package planner

// disposition.go: the B4 disposition linter — the probe-side rule that would
// have caught the G-01 burial: a high-risk probe row (tier 0 or
// assertion_gap >= 3) closed with dismissal vocabulary ("liveness-only",
// "owner can revert", ...) instead of a refutation that runs.
//
// v1 (warning): DispositionReview scans the closed rows and flags the
// offenders for `webv2 brief` and the report's Disposition review section.
// v2 (rejection): checkDismissalGate — wired into MarkAnswered — refuses to
// record such a closure without an exec-backed or invariant-backed ref, or
// an explicit, logged override (probe.dismissal_overridden).

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// DismissalPhrases is the B4 vocabulary table (IMPROVEMENTS B4): the
// dismissive wording that buries a high-risk row. Matched as a
// case-insensitive substring of the closure reason.
var DismissalPhrases = []string{
	"liveness-only",
	"liveness only",
	"owner-revert",
	"owner can revert",
	"not exploitable",
	"never permanently",
	"until the owner",
	"no economic impact",
	"no profit",
}

// DismissalHits scans a reason for dismissal vocabulary (case-insensitive)
// and returns the phrases that hit, in table order ([] when clean).
func DismissalHits(reason string) []string {
	low := strings.ToLower(reason)
	hits := []string{}
	for _, p := range DismissalPhrases {
		if strings.Contains(low, p) {
			hits = append(hits, p)
		}
	}
	return hits
}

// HighRiskRow is the B4 gate predicate: tier 0 (the probe's most serious
// claim) or assertion_gap >= 3 (the row asserts far beyond its evidence).
// A missing tier reads as tier 0 — the linter errs toward caution.
func HighRiskRow(row validation.Value) bool {
	return rowInt(row, "tier") == 0 ||
		rowInt(row, "assertion_gap") >= 3
}

// rowInt reads an integer row field (0 when absent — see HighRiskRow).
func rowInt(row validation.Value, key string) int64 {
	v := validation.ObjAt(row, key)
	switch v.Kind {
	case validation.Int:
		return v.I
	case validation.Flt:
		return int64(v.F)
	}
	return 0
}

// DismissalFlag is one flagged closure: a high-risk row dismissed with
// dismissal vocabulary.
type DismissalFlag struct {
	Priority string
	RowID    string
	Tier     int64
	Gap      int64
	Reason   string
	Phrases  []string
}

// DispositionReview is the B4 v1 scan: every dispositioned probe row in the
// plan whose closure reason uses dismissal vocabulary on a high-risk row.
// Rows that cannot be resolved against the current surface (the surface was
// re-emitted after the closure) are skipped — the risk rank is the
// surface's, not the plan's.
func DispositionReview(campaign *state.Campaign, plan validation.Value) ([]DismissalFlag, error) {
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return nil, err
	}
	flags := []DismissalFlag{}
	for _, p := range listOf(plan, "priorities") {
		prov, hasProv := probeProvenance(p)
		if !hasProv ||
			!inList(validation.ObjStr(p, "status"), ProbeRowDispositioned) {
			continue
		}
		reason := validation.ObjStr(p, "closed_reason")
		if reason == "" {
			continue
		}
		phrases := DismissalHits(reason)
		if len(phrases) == 0 {
			continue
		}
		if surface == nil {
			continue
		}
		row, ok := findRow(*surface, validation.ObjStr(prov, "row_id"))
		if !ok || !HighRiskRow(row) {
			continue
		}
		flags = append(flags, DismissalFlag{
			Priority: validation.ObjStr(p, "id"),
			RowID:    validation.ObjStr(prov, "row_id"),
			Tier:     rowInt(row, "tier"),
			Gap:      rowInt(row, "assertion_gap"),
			Reason:   reason,
			Phrases:  phrases,
		})
	}
	return flags, nil
}

var (
	execIDPattern    = regexp.MustCompile(`^EXEC-[0-9a-f]{10}$`)
	invariantPattern = regexp.MustCompile(`^INV-[0-9]+$`)
)

// refutationBacked is the B4 v2 acceptance: an exec id whose record exists
// on disk, or an invariant id present in the campaign's invariant registry.
// Anything else — a file#L anchor, a finding id, bare prose — is an
// assertion, not a refutation.
func refutationBacked(campaign *state.Campaign, ref string) bool {
	if execIDPattern.MatchString(ref) {
		_, err := os.Stat(filepath.Join(campaign.ExecsDir, ref,
			"exec_record.json"))
		return err == nil
	}
	if invariantPattern.MatchString(ref) {
		return invariantRegistered(campaign, ref)
	}
	return false
}

// checkDismissalGate is the B4 v2 hard gate: a high-risk row (tier 0 or
// assertion_gap >= 3) may not be dispositioned on a reason that uses
// dismissal vocabulary unless the closure rests on a refutation that runs —
// an exec that refutes the row, or an invariant the refutation rests on — or
// an explicit, logged override. It runs inside MarkAnswered so every caller
// (the CLI and orchestrator.ingest) is gated the same way.
func checkDismissalGate(campaign *state.Campaign, priorityID, outcome string,
	prov validation.Value, hasProv bool, opts AnsweredOpts) error {
	return checkDismissalGateInner(campaign, priorityID, outcome, prov,
		hasProv, opts, false)
}

// checkDismissalGateDry is the batch pre-flight form of the gate: it
// validates exactly what checkDismissalGate validates — including that an
// override carries its justification — but records NOTHING, so a refused
// batch leaves zero events behind. The apply pass then runs the recording
// gate via MarkAnswered.
func checkDismissalGateDry(campaign *state.Campaign, priorityID,
	outcome string, prov validation.Value, hasProv bool,
	opts AnsweredOpts) error {
	return checkDismissalGateInner(campaign, priorityID, outcome, prov,
		hasProv, opts, true)
}

// gateSkipNotice is the FIX-3 diagnostic: the one-line notice a gate sets on
// AnsweredOpts.SkipNotice when it stands down because the priority's probe
// row no longer resolves against the current surface (the surface was
// re-emitted after the closure was written). The row id is named, the gate is
// named, and the skip is a fact, not a verdict — resolveAnchor has already
// refused the closure on the same condition, so this is defense in depth for
// the paths that close without it, and the only live reporting path for the
// sweep.
func gateSkipNotice(priorityID, rowID, gate string) string {
	return "notice: priority " + priorityID + " cites probe row " + rowID +
		", which is not in the current surface — the " + gate +
		" gate was skipped for it"
}

// recordOverrideEvent is the ONE recorder for probe.dismissal_overridden:
// row provenance (row_id, tier, assertion_gap), actor, the dismissal phrases
// the closure reason used (empty when the override rides a clean reason), the
// justification and the closure reason itself. dry (the batch pre-flight)
// validates the recording path but records nothing — a refused batch leaves
// zero events behind. Every override arm funnels here, so a closure carries
// exactly one event on every path: the arms dedupe between themselves (the
// LATER gate in runAnsweredGates records on a high-risk row; the sentinel
// arm, which runs first, records on a non-high-risk one and the later arms
// yield to it).
func recordOverrideEvent(campaign *state.Campaign, priorityID string,
	row validation.Value, rowID string, phrases []string, opts AnsweredOpts,
	dry bool) error {
	phrasesV := validation.VArr()
	for _, p := range phrases {
		phrasesV.A = append(phrasesV.A, validation.VStr(p))
	}
	data := validation.VObj(
		kv("row_id", validation.VStr(rowID)),
		kv("tier", validation.VInt(rowInt(row, "tier"))),
		kv("assertion_gap", validation.VInt(rowInt(row, "assertion_gap"))),
		kv("actor", validation.VStr(actorOr(opts.Actor))),
		kv("phrases", phrasesV),
		kv("override_reason", validation.VStr(*opts.OverrideReason)),
		kv("closed_reason", optStr(opts.Reason)),
	)
	if dry {
		// Pre-flight: the override is valid, but recording it is the
		// apply pass's job — a refused batch must leave zero events.
		if opts.OverrideLogged != nil {
			*opts.OverrideLogged = true
		}
		return nil
	}
	if _, err := campaign.Log("probe.dismissal_overridden", &priorityID,
		&data); err != nil {
		return err
	}
	if opts.OverrideLogged != nil {
		*opts.OverrideLogged = true
	}
	return nil
}

func checkDismissalGateInner(campaign *state.Campaign, priorityID,
	outcome string, prov validation.Value, hasProv bool, opts AnsweredOpts,
	dry bool) error {
	if !hasProv || !inList(outcome, ProbeRowDispositioned) {
		return nil
	}
	// FIX-8: a reason-less OVERRIDE still reaches the row — the override is
	// the operator's decision and it is logged as one (with an empty phrase
	// list); a reason-less plain closure is nobody's gate's business.
	if opts.Reason == nil && !opts.OverrideDismissal {
		return nil
	}
	phrases := []string{}
	if opts.Reason != nil {
		phrases = DismissalHits(*opts.Reason)
	}
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return err
	}
	if surface == nil {
		return nil // anchor resolution (when needed) reports the missing surface
	}
	rowID := validation.ObjStr(prov, "row_id")
	row, ok := findRow(*surface, rowID)
	if !ok {
		// FIX-3: the skip is a fact worth one line, not a silent pass — the
		// surface was re-emitted after this closure was written, so the
		// gate's risk rank (the surface's) cannot be computed.
		if opts.SkipNotice != nil {
			*opts.SkipNotice = gateSkipNotice(priorityID, rowID,
				"dismissal")
		}
		return nil
	}
	head := "priority " + priorityID + " (probe row " + rowID +
		", tier " + strconv.FormatInt(rowInt(row, "tier"), 10) +
		", assertion_gap " +
		strconv.FormatInt(rowInt(row, "assertion_gap"), 10) + ")"
	if !HighRiskRow(row) {
		// FIX-8: the override contract does not stop at the high-risk line.
		// An explicit --override-dismissal on any probe row is a decision to
		// bury a check, and it is logged as one — a low-risk row is cheaper
		// to dismiss, not exempt from justifying the dismissal. The override
		// still carries its justification (the same refusal wording), and
		// dedupes with the later recording sites exactly as the high-risk
		// arm's does: this arm only fires when NO later site will record —
		// i.e. when the row is low-risk and the closure carries no reason
		// for the deferred arm's dedupe to key on. The sentinel arm (which
		// runs BEFORE this gate) records non-high-risk sentinel overrides
		// itself, so a sentinel-form row here is already logged.
		if opts.OverrideDismissal {
			if opts.OverrideReason == nil ||
				strings.TrimSpace(*opts.OverrideReason) == "" {
				return errValue("priority " + priorityID + " (probe row " +
					rowID + ", tier " +
					strconv.FormatInt(rowInt(row, "tier"), 10) +
					", assertion_gap " +
					strconv.FormatInt(rowInt(row, "assertion_gap"), 10) +
					"): --override-dismissal needs " +
					"--override-reason — the justification is logged with " +
					"the override (probe.dismissal_overridden)")
			}
			sentinelAhead := validation.ObjStr(row, "own_form") == "sentinel" &&
				inList(outcome, []string{"answered", "not-applicable"})
			if sentinelAhead {
				// the sentinel rule's override arm runs EARLIER in
				// runAnsweredGates and records a non-high-risk sentinel
				// row's override itself — this arm stays silent, so the
				// closure carries exactly one probe.dismissal_overridden.
				return nil
			}
			return recordOverrideEvent(campaign, priorityID, row, rowID,
				phrases, opts, dry)
		}
		return nil
	}
	// v3's citation rule reads the row's own surface entry: what the reason
	// has to name, and what the refusal offers back, are the same list. A row
	// that carries no symbols at all is exempt by construction (see
	// RowSymbols) — the rule exists to make a dismissal checkable, not to make
	// a row unclosable.
	symbols := RowSymbols(row)
	if opts.OverrideDismissal {
		if opts.OverrideReason == nil ||
			strings.TrimSpace(*opts.OverrideReason) == "" {
			return errValue(head + ": --override-dismissal needs " +
				"--override-reason — the justification is logged with the " +
				"override (probe.dismissal_overridden)")
		}
		if validation.ObjStr(row, "own_form") == "sentinel" && opts.Reason == nil &&
			inList(outcome, []string{"answered", "not-applicable"}) {
			// the sentinel rule's override arm (which runs first) recorded
			// this reason-less override itself — see overrideSentinelPasses.
			return nil
		}
		return recordOverrideEvent(campaign, priorityID, row, rowID,
			phrases, opts, dry)
	}
	if opts.Ref != nil && refutationBacked(campaign, *opts.Ref) {
		return nil
	}
	if len(phrases) == 0 {
		// v3 only: nothing dismissive in the wording, but nothing checkable
		// either — the row is being closed on prose that no reader can follow
		// back to the code it is about.
		if namesSymbol(*opts.Reason, symbols) != "" || len(symbols) == 0 {
			return nil
		}
		return errValue(head + ": the closure reason names nothing from the " +
			"row's own surface entry, so there is nothing to check it " +
			"against. A dismissal this close to the money has to be " +
			"falsifiable: quote the code the row is about (" +
			strings.Join(symbols, ", ") + "), or pass a refutation that runs " +
			"— --ref EXEC-<id> (an existing exec record) or --ref INV-<n> (a " +
			"registered invariant) — or override explicitly: " +
			"--override-dismissal --override-reason R")
	}
	return errValue(head + ": the closure reason uses dismissal vocabulary " +
		validation.PyRepr(validation.StrArr(phrases)) + " on a high-risk row (tier 0 " +
		"or assertion_gap >= 3). A dismissal this close to the money needs a " +
		"refutation that runs — --ref EXEC-<id> (an existing exec record) or " +
		"--ref INV-<n> (a registered invariant) — or an explicit, logged " +
		"override: --override-dismissal --override-reason R")
}

// ---------------------------------------------------------------------------
// v3: the structural layer. v2 catches the WORDS a dismissal uses; v3 catches
// the case it generalises over — a high-risk row closed by prose that names
// nothing a reader can check. The row's own surface entry is the citation
// source: its contract, the consumer/function it is about, the base it
// inherits, the siblings it is symmetric to, the forward path it pays into.
// A reason that quotes one of those is falsifiable (go read the function); a
// reason that quotes none of them, and cites no refutation that runs, is the
// G-01 failure with better manners.
//
// The second half of v3 is the converse duty: an id the reason CITES must
// exist. A dismissal that "rests on F-1a2b3c4d5e6f" is either citing a real
// finding or inventing one, and the framework can tell the difference.
// ---------------------------------------------------------------------------

// rowSymbolKeys are the row fields that name something in the tree, in the
// order a refusal message should offer them (most specific first). Only
// strings and string lists are read; a missing field is simply absent.
var rowSymbolKeys = []string{
	"contract", "consumer", "base", "asserter", "custody",
	"concept_keys", "forward", "siblings", "members",
}

// genericSymbols are tokens a row carries that name no code: a custody verb or
// a boolean says nothing a reader can go and look at, so matching one is not a
// citation. Kept deliberately tiny — the point is to avoid a rubber stamp, not
// to second-guess an author's vocabulary.
var genericSymbols = map[string]bool{
	"true": true, "false": true,
	"burns": true, "mints": true, "forwards": true,
}

// RowSymbols is the checkable identity of a surface row: every contract,
// function, concept and sibling the row is about, in row order, deduplicated
// (case-insensitively) and with the empties dropped. A row with no symbols at
// all returns an empty list, and callers must then NOT enforce the citation
// rule — an unclosable row would be worse than an unverified one.
func RowSymbols(row validation.Value) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || len(v) < 3 || genericSymbols[strings.ToLower(v)] {
			return
		}
		key := strings.ToLower(v)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, v)
	}
	for _, key := range rowSymbolKeys {
		v := validation.ObjAt(row, key)
		switch v.Kind {
		case validation.Str:
			add(v.S)
		case validation.Arr:
			for _, e := range v.A {
				switch e.Kind {
				case validation.Str:
					add(e.S)
				case validation.Obj:
					add(validation.ObjStr(e, "contract"))
					add(validation.ObjStr(e, "name"))
				}
			}
		}
	}
	return out
}

// namesSymbol reports which row symbol the reason quotes ("" when none). The
// match is a case-insensitive substring: "L1ReverseCustomGateway" inside prose
// about L1ReverseCustomGateway is the citation we want, and demanding a
// formatting convention would only teach authors to game it.
func namesSymbol(reason string, symbols []string) string {
	low := strings.ToLower(reason)
	for _, sym := range symbols {
		if strings.Contains(low, strings.ToLower(sym)) {
			return sym
		}
	}
	return ""
}

var (
	findingIDPattern = regexp.MustCompile(`\bF-[0-9a-f]{12}\b`)
	execRefPattern   = regexp.MustCompile(`\bEXEC-[0-9a-f]{10}\b`)
	invRefPattern    = regexp.MustCompile(`\bINV-[0-9]+\b`)
)

// ghostCitation is the v3 converse duty: every finding/exec/invariant id the
// reason mentions must exist. It returns the first id that does not ("" when
// every citation resolves), so a dismissal cannot rest on a record that was
// never written — by typo or by invention.
func ghostCitation(campaign *state.Campaign, reason string) (string, error) {
	for _, id := range findingIDPattern.FindAllString(reason, -1) {
		if _, err := os.Stat(filepath.Join(campaign.FindingsDir,
			id+".json")); err != nil {
			return id, nil
		}
	}
	for _, id := range execRefPattern.FindAllString(reason, -1) {
		if _, err := os.Stat(filepath.Join(campaign.ExecsDir, id,
			"exec_record.json")); err != nil {
			return id, nil
		}
	}
	for _, id := range invRefPattern.FindAllString(reason, -1) {
		if !invariantRegistered(campaign, id) {
			return id, nil
		}
	}
	return "", nil
}

// checkCitedRecords is v3's converse duty at the closure seam: whatever the
// reason or the ref CITES must exist. It runs for every closing disposition
// (not only high-risk probe rows) because a citation that resolves to nothing
// is wrong at every tier — and because "rests on F-1a2b3c4d5e6f" is a claim
// the framework can actually check. Refutation-backed refs are covered by the
// same scan (refutationBacked is the positive form of it).
func checkCitedRecords(campaign *state.Campaign, priorityID, outcome string,
	opts AnsweredOpts) error {
	closing := outcome == "answered" || outcome == "not-applicable" ||
		outcome == "deprioritized" || outcome == "blocked"
	if !closing {
		return nil
	}
	fields := []struct {
		what string
		text *string
	}{{"closure reason", opts.Reason}, {"--ref", opts.Ref}}
	for _, f := range fields {
		if f.text == nil {
			continue
		}
		ghost, err := ghostCitation(campaign, *f.text)
		if err != nil {
			return err
		}
		if ghost != "" {
			return errValue("priority " + priorityID + ": the " + f.what +
				" cites " + ghost + ", which does not exist in this " +
				"campaign — a disposition may rest on a real finding, exec " +
				"record or registered invariant, never on a citation that " +
				"was invented or mistyped")
		}
	}
	return nil
}

// invariantRegistered is refutationBacked's invariant half, factored out so
// the citation scan and the refutation check cannot disagree about what
// "registered" means.
func invariantRegistered(campaign *state.Campaign, id string) bool {
	links, err := invariants.LoadLinks(campaign)
	if err != nil {
		return false
	}
	reg := validation.ObjAt(links, "invariants")
	return reg.Kind == validation.Obj && hasKey(reg, id)
}

// ---------------------------------------------------------------------------
// B4 v3: the sentinel-form rule. v2 catches the WORDS; the citation layer
// catches prose that names nothing; this catches the one closure that is
// checkable and still wrong: "the row is safe because an assertion exists"
// when the guard is a zero-check. `stateRoot != bytes32(0)` cannot express the
// truth of the root — every non-zero value passes it — so a closing
// disposition of such a row has to name the value that DOES pass the check.
// ---------------------------------------------------------------------------

// checkPassesValue is FIX-E's always-on half of the --passes rule: whenever
// the flag is supplied — on any priority, any status, sentinel row or not —
// the value is shape-validated through the SAME plausibility floor the
// sentinel gate uses (passesPlausible), so the two paths cannot disagree
// about what a plausible value is. It runs AFTER checkSentinelPassesRow, so
// the sentinel gate's row-symbol refusal keeps firing on the rows it covers;
// this is the backstop on every route that gate stands down. A short value
// is a REFUSAL naming the >= 3 floor, never closePriority's silent drop;
// junk is refused naming the legal shapes. The value is read against the row
// the disposition points at where one resolves (the citation shape needs
// it); elsewhere the literal shapes and the junk lexicon are still enforced.
func checkPassesValue(campaign *state.Campaign, priorityID string,
	prov validation.Value, hasProv bool, opts AnsweredOpts) error {
	if opts.PassesValue == nil {
		return nil
	}
	v := strings.TrimSpace(*opts.PassesValue)
	var row validation.Value
	if hasProv {
		if surface, err := PB().CampaignSurface(campaign); err == nil &&
			surface != nil {
			row, _ = findRow(*surface, validation.ObjStr(prov, "row_id"))
		}
	}
	if passesPlausible(row, v) {
		return nil
	}
	head := "priority " + priorityID + ": --passes " +
		validation.PyReprStr(*opts.PassesValue) + " "
	if len(v) < 3 {
		return errValue(head + "is below the 3-character floor a passing " +
			"value has to clear — a placeholder is not a value the closure " +
			"record can re-check: name the value that passes the row's " +
			"check, or drop --passes")
	}
	return errValue(head + "is not a plausible value for the check — " +
		"either quote something the row's own surface entry names, or give " +
		"a concrete literal the closure record can re-check (a decimal " +
		"integer, a hex number or Ethereum-style address 0x…, " +
		"bytes32(0x…), a boolean, or an honest quoted string) — or drop " +
		"--passes")
}

// checkSentinelPasses is the B4 v3 rule: a closing disposition of a
// sentinel-guarded row (own_form=sentinel) must name the value that passes
// the check. Existence of an assertion is not correctness; the disposition
// has to be falsifiable. FIX-C adds the plausibility floor the flag needed:
// a >= 3-character string is not yet a value — "zzz", "TBD", "n/a" pass the
// length floor and record nothing checkable. The supplied value must either
// (a) name a symbol that exists on the row's own surface entry (the same
// citation muscle the v3 citation rule uses — RowSymbols/namesSymbol), or
// (b) be a concrete, machine-checkable literal: a decimal integer, a hex
// number or Ethereum-style address (0x…), a bytes32(0x…) literal, a boolean,
// or a quoted string literal. A hex literal is trusted as a CLAIMED value:
// the falsifiability comes from it being recorded on the closure and
// re-checkable by any reader, matching the framework's record-not-answer
// philosophy — the gate forces the question onto the record, it never
// pretends to evaluate the answer. The family escape hatch
// (--override-dismissal with --override-reason) stays the only way around
// the rule — see checkSentinelPassesRow.
func checkSentinelPasses(row validation.Value, outcome string,
	opts AnsweredOpts) error {
	if outcome != "answered" && outcome != "not-applicable" {
		return nil
	}
	if validation.ObjStr(row, "own_form") != "sentinel" {
		return nil
	}
	given := opts.PassesValue != nil
	if given && passesPlausible(row, *opts.PassesValue) {
		return nil
	}
	if !given || len(strings.TrimSpace(*opts.PassesValue)) < 3 {
		return errValue("sentinel-guarded probe row " + validation.ObjStr(row, "row_id") +
			": a closing disposition must name the value that passes its check " +
			"(--passes VALUE) — or override explicitly (--override-dismissal " +
			"--override-reason R)")
	}
	// A value was given and cleared the length floor but is neither a row
	// citation nor a concrete literal: refused, naming both legal shapes.
	syms := RowSymbols(row)
	shape := "either quote something the row's own surface entry names"
	if len(syms) > 0 {
		shape += " (" + strings.Join(syms, ", ") + ")"
	} else {
		shape += " — this row names no symbols, so a citation shape is not " +
			"available here"
	}
	return errValue("sentinel-guarded probe row " + validation.ObjStr(row, "row_id") +
		": --passes " + validation.PyReprStr(*opts.PassesValue) + " is not a " +
		"plausible value for the check — " + shape + ", or give a concrete " +
		"literal the closure record can re-check (a decimal integer, a hex " +
		"number or Ethereum-style address 0x…, bytes32(0x…), a boolean, or " +
		"a quoted string) — or override explicitly (--override-dismissal " +
		"--override-reason R)")
}

// junkPassesValues is the FIX-E junk lexicon, shared by both halves of the
// --passes floor: bare junk and the quoted-string arm of the literal
// alternation are held to the same standard, so `"TBD"` cannot smuggle the
// value in under quotes (round-3 chief item 5, problem 1). Whole-value,
// case-insensitive: an honest quoted literal that merely CONTAINS one of
// these words ("3 days of unresolved withdrawals") stays legal.
var junkPassesValues = map[string]bool{
	"tbd": true, "n/a": true, "na": true, "none": true, "unknown": true,
	"whatever": true, "asdf": true, "zzz": true, "xxx": true,
	"foo": true, "bar": true, "baz": true,
}

// passesLiteralRe is the FIX-C literal half of the --passes plausibility
// floor: the concrete, machine-checkable shapes a sentinel value may take
// without naming a row symbol. A literal is trusted as a claimed value (see
// checkSentinelPasses) — recorded, re-checkable, never evaluated here. The
// quoted-string arm is additionally excluded by junkPassesValues (see
// passesPlausible): a quoted junk word is a placeholder, not a value.
var passesLiteralRe = regexp.MustCompile(
	`(?i)^(?:-?[0-9]+|0[xX][0-9a-fA-F]+|bytes32\(0[xX][0-9a-fA-F]{64}\)|` +
		`true|false|"[^"]+"|'[^']+')$`)

// passesPlausible is the --passes floor, the ONE check both consumers share
// (FIX-E problem 2): the sentinel gate's acceptance and the always-on
// validation of a --passes supplied anywhere else must never disagree about
// what a plausible value is. A value is plausible when it names a symbol on
// the row's own surface entry (case-insensitive substring, the namesSymbol
// muscle), is a concrete literal (passesLiteralRe, junk-quoted forms
// excluded), or — on a row that names no symbols at all — is any honest
// literal; the >= 3 length floor is the caller's. A row with no symbols at
// all stays closable through the literal shapes — an unclosable row would be
// worse than an unverified one.
func passesPlausible(row validation.Value, v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 3 {
		return false
	}
	if namesSymbol(v, RowSymbols(row)) != "" {
		return true
	}
	if !passesLiteralRe.MatchString(v) {
		return false
	}
	// The quoted arms pass the regex by shape; a quoted junk word is
	// refused with the bare forms (the lexicon is whole-value, so a quoted
	// sentence that contains a junk word is untouched).
	quoted := len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0]
	if quoted && junkPassesValues[strings.ToLower(v[1:len(v)-1])] {
		return false
	}
	return true
}

// checkSentinelPassesRow is the closure-seam half: it resolves the surface row
// the disposition points at and applies the rule to it. A probe disposition
// whose surface row cannot be resolved (no surface, or the row was re-emitted
// away) is skipped — the anchor path reports that more usefully, and a row
// nobody can look up must never become unclosable. The family escape hatch
// (--override-dismissal) answers a refusal here under the dismissal gate's
// own contract, never as a bare flag: the override carries its justification
// and is recorded as probe.dismissal_overridden (see overrideSentinelPasses).
func checkSentinelPassesRow(campaign *state.Campaign, priorityID,
	outcome string, prov validation.Value, hasProv bool, opts AnsweredOpts,
	dry bool) error {
	if !hasProv || !inList(outcome, []string{"answered", "not-applicable"}) {
		return nil
	}
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return err
	}
	if surface == nil {
		return nil
	}
	row, ok := findRow(*surface, validation.ObjStr(prov, "row_id"))
	if !ok {
		// FIX-3: the skip is announced, not silent (see
		// checkDismissalGateInner).
		if opts.SkipNotice != nil {
			*opts.SkipNotice = gateSkipNotice(priorityID,
				validation.ObjStr(prov, "row_id"), "sentinel-guard")
		}
		return nil
	}
	err = checkSentinelPasses(row, outcome, opts)
	if err == nil || !opts.OverrideDismissal {
		return err
	}
	return overrideSentinelPasses(campaign, priorityID, row,
		validation.ObjStr(prov, "row_id"), opts, dry)
}

// overrideSentinelPasses is the sentinel rule's override arm: the same
// contract checkDismissalGateInner applies on a high-risk row — the override
// carries its own justification, and the decision is recorded as
// probe.dismissal_overridden with the same provenance (row, tier, gap,
// actor, phrases, both reasons). dry (the batch pre-flight) validates the
// justification but records nothing, so a refused batch leaves zero events
// behind. One closure, one override event: on a HIGH-risk row the dismissal
// gate — which runs after this gate in runAnsweredGates, with the same opts
// — records the identical event, so the sentinel arm stays silent there and
// lets it.
func overrideSentinelPasses(campaign *state.Campaign, priorityID string,
	row validation.Value, rowID string, opts AnsweredOpts, dry bool) error {
	head := "priority " + priorityID + " (probe row " + rowID +
		", tier " + strconv.FormatInt(rowInt(row, "tier"), 10) +
		", assertion_gap " +
		strconv.FormatInt(rowInt(row, "assertion_gap"), 10) + ")"
	if opts.OverrideReason == nil ||
		strings.TrimSpace(*opts.OverrideReason) == "" {
		return errValue(head + ": --override-dismissal needs " +
			"--override-reason — the justification is logged with the " +
			"override (probe.dismissal_overridden)")
	}
	if HighRiskRow(row) && opts.Reason != nil {
		// the dismissal gate records the event — see the comment above.
		return nil
	}
	// FIX-8 dedupe, restated: a non-high-risk row is recorded HERE (the
	// dismissal gate's low-risk arm yields to this one for sentinel rows),
	// a high-risk row with a closure reason is recorded by the dismissal
	// gate (which runs after it with the same opts). The phrase list is the
	// closure reason's dismissal vocabulary — empty for a reason-less
	// override.
	phrases := []string{}
	if opts.Reason != nil {
		phrases = DismissalHits(*opts.Reason)
	}
	return recordOverrideEvent(campaign, priorityID, row, rowID,
		phrases, opts, dry)
}

// ---------------------------------------------------------------------------
// FIX-5: the deferred-consequence gate. The operator's G-01 post-mortem: the
// probe asked whether commitBatch verifies prev:state itself and offered
// asserter as a legal anchor — so "the check lives elsewhere" became a
// sanctioned answer shape. But the gold bug lived INSIDE that shape: the
// check exists, it is asserted at the wrong lifecycle stage, and the interim
// window is exploitable. The framework accepted the disposition while it
// contained the tell (the words "unfinalizable") and never asked the operator
// to price that consequence.
//
// The gate: a high-risk row (tier 0 / assertion_gap >= 3 — the dismissal
// gate's own predicate) closed on the asserter anchor — the v1 trigger, the
// one anchor whose value is "asserted elsewhere" by construction — must price
// the window: --finding F-<id> (a filed finding that records it) or --interim
// STATEMENT, a consequence statement that cites the row's own surface entry
// (the v3 citation muscle: prose that names nothing from the row is refused).
// FIX-1 adds the mirror trigger: a high-risk row whose closure REASON uses
// the failure-consequence vocabulary (the sweep's own table,
// DeferredConsequenceTokens) demands the same pricing whatever the anchor —
// a reason that says what happens when the check never runs is the operator
// describing the deferred window, and describing it is not pricing it. The
// family escape hatch (--override-dismissal + --override-reason, logged
// as probe.dismissal_overridden) stays the only way around it.
//
// The second half is the reverse sweep: closures recorded BEFORE this gate
// existed whose reason vocabulary implies a failure consequence are flagged
// by `webv2 deferred` — a report, never a mutation.
// ---------------------------------------------------------------------------

// deferredAnchor is the v1 trigger value: --anchor asserter. The anchor enum
// resolves it to the row's asserter (the function that DOES carry the
// assertion), so a closure anchored on it has, by construction, conceded that
// the row's own consumer does not enforce the check.
const deferredAnchor = "asserter"

// findingRefPattern is the exact shape --finding accepts: one finding id,
// nothing else. ghostCitation extracts ids from prose; --finding IS the
// citation, so it must be the id itself.
var findingRefPattern = regexp.MustCompile(`^F-[0-9a-f]{12}$`)

// checkDeferredConsequence is the FIX-5 row rule: a closing disposition of a
// high-risk row must price the interim window — the stage gap between the
// row's consumer (which runs without the check) and the asserter (which
// finally applies it). Either a filed finding that records the window, or a
// consequence statement citing the row's own surface entry. The trigger that
// got here is passed in (FIX-1): anchorTriggered (the asserter anchor — the
// closure concedes the check is asserted elsewhere) or the reason's
// failure-consequence vocabulary (the closure describes the cost of the
// window it leaves open); the refusal names the trigger it answered. The
// family escape hatch (--override-dismissal with --override-reason) stays
// the only way around it — see overrideDeferredConsequence.
func checkDeferredConsequence(campaign *state.Campaign, head string,
	row validation.Value, opts AnsweredOpts, anchorTriggered bool,
	tokens []string) error {
	syms := RowSymbols(row)
	// (b) first: a filed finding that records the window. A malformed or
	// ghost --finding is answered AS one — the ghost-citation duty outranks
	// the acceptance it rides in on.
	if opts.Finding != nil {
		ref := strings.TrimSpace(*opts.Finding)
		if !findingRefPattern.MatchString(ref) {
			return errValue(head + ": --finding " +
				validation.PyReprStr(*opts.Finding) + " is not a finding id " +
				"(F-<12 hex digits>) — pass the id of a filed finding, or " +
				"--interim STATEMENT, or override explicitly: " +
				"--override-dismissal --override-reason R")
		}
		if _, err := os.Stat(filepath.Join(campaign.FindingsDir,
			ref+".json")); err != nil {
			return errValue(head + ": --finding " + ref + " does not exist " +
				"in this campaign — a disposition may rest on a real filed " +
				"finding, never on a citation that was invented or mistyped. " +
				"File it first, or pass --interim STATEMENT, or override " +
				"explicitly: --override-dismissal --override-reason R")
		}
		return nil
	}
	// (a) the interim statement: the consequence priced in prose, citing the
	// row's own surface entry (the v3 citation muscle). A row that carries no
	// symbols at all is exempt from the citation demand by construction (see
	// RowSymbols) — the rule exists to make the window checkable, not to make
	// the row unclosable; --finding and the logged override stay open either
	// way.
	if opts.Interim != nil {
		if namesSymbol(*opts.Interim, syms) != "" || len(syms) == 0 {
			return nil
		}
		return errValue(head + ": --interim names nothing from the row's own " +
			"surface entry, so the consequence it describes cannot be checked " +
			"against the code. Quote the code the interim window lives in (" +
			strings.Join(syms, ", ") + "), or pass --finding F-<id> " +
			"(a filed finding that records the window), or override " +
			"explicitly: --override-dismissal --override-reason R")
	}
	// neither exit was taken: the consequence goes unpriced. The refusal
	// names the trigger it is answering (FIX-1): the asserter anchor's own
	// concession, or the reason's failure-consequence vocabulary.
	if anchorTriggered {
		where := validation.ObjStr(row, "asserter")
		if where == "" {
			where = "a later lifecycle stage"
		}
		consumer := validation.ObjStr(row, "consumer")
		consumerPhrase := ""
		if consumer != "" {
			consumerPhrase = ", not enforced by the row's own consumer (" +
				consumer + ")"
		}
		symbolsPhrase := ""
		if len(syms) > 0 {
			symbolsPhrase = " — a consequence statement citing the row's own " +
				"surface entry (" + strings.Join(syms, ", ") + ")"
		}
		return errValue(head + ": the closure anchors on asserter — the row's " +
			"check is asserted at " + where + consumerPhrase + ", so the " +
			"enforcement is DEFERRED to a later lifecycle stage and the interim " +
			"window between the two is exactly what the row asks about. Price " +
			"the consequence: --finding F-<id> (a filed finding that records the " +
			"window) or --interim STATEMENT" + symbolsPhrase +
			" — or override explicitly: --override-dismissal --override-reason R")
	}
	symbolsPhrase := ""
	if len(syms) > 0 {
		symbolsPhrase = " — a consequence statement citing the row's own " +
			"surface entry (" + strings.Join(syms, ", ") + ")"
	}
	return errValue(head + ": the closure reason uses the " +
		"failure-consequence vocabulary " + validation.PyRepr(validation.StrArr(tokens)) +
		" on a high-risk row (tier 0 or assertion_gap >= 3) — it describes " +
		"what happens if the row's deferred check never runs, which is " +
		"exactly the interim window this closure leaves open. Price the " +
		"consequence: --finding F-<id> (a filed finding that records the " +
		"window) or --interim STATEMENT" + symbolsPhrase +
		" — or override explicitly: --override-dismissal --override-reason R")
}

// checkConsequenceFlags is FIX-2: the pricing flags are validated ALWAYS —
// any status, any priority, probe row or not. Before this check, --finding
// and --interim only mattered on the rows the deferred-consequence gate
// covers (high-risk, triggered); everywhere else they were inert: recorded
// verbatim on the closure (a ghost id included) or dropped by the shape
// guards in closePriority without a word. A flag that claims to price an
// interim window has to price a real one: the --finding id must be a filed,
// LIVE finding (a terminal one — DISPROVED, OUT_OF_SCOPE, INFORMATIONAL,
// DUPLICATE, SUPERSEDED — records nothing about a window that is still
// open), and an --interim has to be a statement (non-blank, at least a few
// characters). Runs before every gate so the shape is answered as one, and
// the deferred-consequence rule's own (row-scoped, head-prefixed) refusals
// still fire on the rows it covers.
func checkConsequenceFlags(campaign *state.Campaign, priorityID string,
	opts AnsweredOpts) error {
	if opts.Interim != nil &&
		len(strings.TrimSpace(*opts.Interim)) < 3 {
		return errValue("priority " + priorityID + ": --interim " +
			validation.PyReprStr(*opts.Interim) + " is too short to be a " +
			"consequence statement — the interim window it claims to price " +
			"has to be described, not gestured at; write the statement or " +
			"drop the flag")
	}
	if opts.Finding != nil {
		ref := strings.TrimSpace(*opts.Finding)
		if !findingRefPattern.MatchString(ref) {
			return errValue("priority " + priorityID + ": --finding " +
				validation.PyReprStr(*opts.Finding) + " is not a finding id " +
				"(F-<12 hex digits>) — pass the id of a filed finding, or " +
				"drop the flag")
		}
		f, err := findings.LoadFinding(campaign, ref)
		if err != nil {
			return errValue("priority " + priorityID + ": --finding " + ref +
				" does not exist in this campaign — a disposition may rest " +
				"on a real filed finding, never on a citation that was " +
				"invented or mistyped. File it first, or drop the flag")
		}
		if status := validation.ObjStr(f, "status"); status != "" {
			if _, terminal := findings.TERMINAL[status]; terminal {
				return errValue("priority " + priorityID + ": --finding " +
					ref + " names a " + status + " finding — a terminal " +
					"finding records nothing about an interim window that " +
					"is still open. Point at a live finding (one that is " +
					"not DISPROVED, OUT_OF_SCOPE, INFORMATIONAL, DUPLICATE " +
					"or SUPERSEDED), or drop the flag")
			}
		}
	}
	return nil
}

// checkDeferredConsequenceRow is the closure-seam half of FIX-5, shaped like
// checkSentinelPassesRow: it resolves the surface row the disposition points
// at and applies the rule to it. A probe disposition whose surface row cannot
// be resolved (no surface, or the row was re-emitted away) is skipped — a row
// nobody can look up must never become unclosable, and the anchor path above
// already reports a missing surface more usefully. FIX-1 widens the trigger
// to BOTH halves of the same fact: the asserter anchor CONCEDES the row's
// check lives elsewhere (the v1 trigger), and a closure reason that uses the
// failure-consequence vocabulary ADMITS what the deferred window costs — on
// a high-risk row, either one demands the pricing (--finding/--interim) or
// the logged override. The family escape hatch (--override-dismissal) answers
// a refusal here under the dismissal gate's own contract, never as a bare
// flag: the override carries its justification and is recorded as
// probe.dismissal_overridden (see overrideDeferredConsequence — which
// validates it; the dismissal gate records it).
func checkDeferredConsequenceRow(campaign *state.Campaign, priorityID,
	outcome string, prov validation.Value, hasProv bool, opts AnsweredOpts,
	dry bool) error {
	if !hasProv || !inList(outcome, ProbeRowDispositioned) {
		return nil
	}
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return err
	}
	if surface == nil {
		return nil
	}
	rowID := validation.ObjStr(prov, "row_id")
	row, ok := findRow(*surface, rowID)
	if !ok {
		// FIX-3: the skip is announced, not silent (see
		// checkDismissalGateInner).
		if opts.SkipNotice != nil {
			*opts.SkipNotice = gateSkipNotice(priorityID, rowID,
				"deferred-consequence")
		}
		return nil
	}
	if !HighRiskRow(row) {
		return nil
	}
	anchorTriggered := opts.Anchor != nil && *opts.Anchor == deferredAnchor
	tokens := []string{}
	if opts.Reason != nil {
		tokens = DeferredHits(*opts.Reason)
	}
	if !anchorTriggered && len(tokens) == 0 {
		// neither trigger: the closure neither concedes the deferral nor
		// describes its cost
		return nil
	}
	head := "priority " + priorityID + " (probe row " + rowID +
		", tier " + strconv.FormatInt(rowInt(row, "tier"), 10) +
		", assertion_gap " +
		strconv.FormatInt(rowInt(row, "assertion_gap"), 10) + ")"
	err = checkDeferredConsequence(campaign, head, row, opts,
		anchorTriggered, tokens)
	if err == nil || !opts.OverrideDismissal {
		return err
	}
	return overrideDeferredConsequence(campaign, priorityID, row,
		rowID, outcome, opts, dry)
}

// overrideDeferredConsequence is the deferred-consequence rule's override
// arm: the same contract checkDismissalGateInner applies on a high-risk row —
// the override carries its own justification, and the decision is recorded as
// probe.dismissal_overridden with the same provenance (row, tier, gap, actor,
// phrases, both reasons). dry (the batch pre-flight) validates the
// justification but records nothing, so a refused batch leaves zero events
// behind. One closure, one override event: on a high-risk row with a closure
// reason the dismissal gate — which runs after this gate in runAnsweredGates,
// with the same opts — records the identical event, so this arm stays silent
// there and lets it (the dedupe the sentinel rule's override arm uses); on a
// sentinel-form row closed as answered/not-applicable the sentinel arm has
// ALREADY recorded the event (it runs first), so this arm stays silent there
// too.
func overrideDeferredConsequence(campaign *state.Campaign, priorityID string,
	row validation.Value, rowID, outcome string, opts AnsweredOpts,
	dry bool) error {
	head := "priority " + priorityID + " (probe row " + rowID +
		", tier " + strconv.FormatInt(rowInt(row, "tier"), 10) +
		", assertion_gap " +
		strconv.FormatInt(rowInt(row, "assertion_gap"), 10) + ")"
	if opts.OverrideReason == nil ||
		strings.TrimSpace(*opts.OverrideReason) == "" {
		return errValue(head + ": --override-dismissal needs " +
			"--override-reason — the justification is logged with the " +
			"override (probe.dismissal_overridden)")
	}
	// FIX-8: this arm is a VALIDATOR now, not a recorder. The dismissal gate
	// — which runs after it in runAnsweredGates with the same opts, on this
	// same row — records the closure's probe.dismissal_overridden (it fires
	// for any risk level since the FIX-8 low-risk arm, and for a
	// reason-less override since the gate's entry no longer stops on a nil
	// reason). One closure, one event, recorded at the END of the gate
	// chain: no arm upstream of the dismissal gate needs to log, and no arm
	// downstream of it exists. The pre-flight (dry) contract is unchanged:
	// the justification is validated here, the event is recorded by the
	// apply pass's dismissal gate.
	return nil
}

// ---------------------------------------------------------------------------
// FIX-5, second half: the reverse sweep. Closures recorded before the gate
// existed (or through its override) can still carry the tell: a tier-0
// closure whose reason vocabulary implies a failure consequence — the row
// stays unfinalizable, funds strand, the pool freezes — priced as if the
// consequence were someone else's problem. The sweep lists them and demands
// the re-answer (a finding ref or an --interim statement); it REPORTS, it
// never mutates.
// ---------------------------------------------------------------------------

// DeferredConsequenceTokens is the sweep vocabulary: whole-word tokens that,
// in a high-risk closure's reason, describe what happens if the deferred
// check never runs — the exact tell the G-01 disposition carried.
var DeferredConsequenceTokens = []string{
	"unfinalizable", "strand", "stranded", "freeze", "frozen",
	"revert-forever", "permanently revert", "owner-clears", "owner clears",
}

// deferredTokenRes compiles the vocabulary once: whole-word (a token inside a
// larger word is prose, not the tell), case-insensitive, in table order.
var deferredTokenRes = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(DeferredConsequenceTokens))
	for i, tok := range DeferredConsequenceTokens {
		out[i] = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(tok) + `\b`)
	}
	return out
}()

// DeferredHits scans a reason for the sweep vocabulary (whole-word,
// case-insensitive) and returns the tokens that hit, in table order
// ([] when clean).
func DeferredHits(reason string) []string {
	hits := []string{}
	for i, re := range deferredTokenRes {
		if re.MatchString(reason) {
			hits = append(hits, DeferredConsequenceTokens[i])
		}
	}
	return hits
}

// DeferredFlag is one flagged closure of the reverse sweep: a high-risk row
// dispositioned on failure-consequence vocabulary with no interim pricing.
type DeferredFlag struct {
	Priority string
	RowID    string
	Tier     int64
	Gap      int64
	Reason   string
	Tokens   []string
}

// DeferredConsequenceReview is the FIX-5 reverse sweep: every dispositioned
// probe row whose closure reason uses the failure-consequence vocabulary on a
// high-risk row and that records no interim pricing (no interim statement, no
// interim_finding — the two exits the gate now demands). It REPORTS — it
// never mutates: the closures it lists were recorded before the gate existed,
// and the fix is a re-answer, which only the operator can make. Rows that
// cannot be resolved against the current surface (the surface was re-emitted
// after the closure) are NOT silently dropped: they come back as the second
// return value (FIX-3), each as "PRIORITY (probe row ROWID)", so the CLI can
// print the skip — the risk rank is the surface's, not the plan's, but the
// reader decides what that is worth.
func DeferredConsequenceReview(campaign *state.Campaign,
	plan validation.Value) ([]DeferredFlag, []string, error) {
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return nil, nil, err
	}
	flags := []DeferredFlag{}
	skipped := []string{}
	for _, p := range listOf(plan, "priorities") {
		prov, hasProv := probeProvenance(p)
		if !hasProv ||
			!inList(validation.ObjStr(p, "status"), ProbeRowDispositioned) {
			continue
		}
		reason := validation.ObjStr(p, "closed_reason")
		if reason == "" {
			continue
		}
		// already priced: an interim statement or a finding ref recorded on
		// the priority is the fix this sweep asks for
		if hasKey(p, "interim") || hasKey(p, "interim_finding") {
			continue
		}
		tokens := DeferredHits(reason)
		if len(tokens) == 0 {
			continue
		}
		skippedEntry := validation.ObjStr(p, "id") + " (probe row " +
			validation.ObjStr(prov, "row_id") + ")"
		if surface == nil {
			skipped = append(skipped, skippedEntry)
			continue
		}
		row, ok := findRow(*surface, validation.ObjStr(prov, "row_id"))
		if !ok {
			skipped = append(skipped, skippedEntry)
			continue
		}
		if !HighRiskRow(row) {
			continue
		}
		flags = append(flags, DeferredFlag{
			Priority: validation.ObjStr(p, "id"),
			RowID:    validation.ObjStr(prov, "row_id"),
			Tier:     rowInt(row, "tier"),
			Gap:      rowInt(row, "assertion_gap"),
			Reason:   reason,
			Tokens:   tokens,
		})
	}
	return flags, skipped, nil
}
