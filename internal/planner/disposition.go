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
	v := objAt(row, key)
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
			!inList(objStr(p, "status"), ProbeRowDispositioned) {
			continue
		}
		reason := objStr(p, "closed_reason")
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
		row, ok := findRow(*surface, objStr(prov, "row_id"))
		if !ok || !HighRiskRow(row) {
			continue
		}
		flags = append(flags, DismissalFlag{
			Priority: objStr(p, "id"),
			RowID:    objStr(prov, "row_id"),
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

func checkDismissalGateInner(campaign *state.Campaign, priorityID,
	outcome string, prov validation.Value, hasProv bool, opts AnsweredOpts,
	dry bool) error {
	if !hasProv || !inList(outcome, ProbeRowDispositioned) ||
		opts.Reason == nil {
		return nil
	}
	phrases := DismissalHits(*opts.Reason)
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return err
	}
	if surface == nil {
		return nil // anchor resolution (when needed) reports the missing surface
	}
	row, ok := findRow(*surface, objStr(prov, "row_id"))
	if !ok || !HighRiskRow(row) {
		return nil
	}
	// v3's citation rule reads the row's own surface entry: what the reason
	// has to name, and what the refusal offers back, are the same list. A row
	// that carries no symbols at all is exempt by construction (see
	// RowSymbols) — the rule exists to make a dismissal checkable, not to make
	// a row unclosable.
	symbols := RowSymbols(row)
	rowID := objStr(prov, "row_id")
	head := "priority " + priorityID + " (probe row " + rowID +
		", tier " + strconv.FormatInt(rowInt(row, "tier"), 10) +
		", assertion_gap " +
		strconv.FormatInt(rowInt(row, "assertion_gap"), 10) + ")"
	if opts.OverrideDismissal {
		if opts.OverrideReason == nil ||
			strings.TrimSpace(*opts.OverrideReason) == "" {
			return errValue(head + ": --override-dismissal needs " +
				"--override-reason — the justification is logged with the " +
				"override (probe.dismissal_overridden)")
		}
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
			kv("closed_reason", validation.VStr(*opts.Reason)),
		)
		if dry {
			// Pre-flight: the override is valid, but recording it is the
			// apply pass's job — a refused batch must leave zero events.
			if opts.OverrideLogged != nil {
				*opts.OverrideLogged = true
			}
			return nil
		}
		if _, err := campaign.Log("probe.dismissal_overridden",
			&priorityID, &data); err != nil {
			return err
		}
		if opts.OverrideLogged != nil {
			*opts.OverrideLogged = true
		}
		return nil
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
		validation.PyRepr(strArr(phrases)) + " on a high-risk row (tier 0 " +
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
	"concept_keys", "forward", "siblings",
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
		v := objAt(row, key)
		switch v.Kind {
		case validation.Str:
			add(v.S)
		case validation.Arr:
			for _, e := range v.A {
				switch e.Kind {
				case validation.Str:
					add(e.S)
				case validation.Obj:
					add(objStr(e, "contract"))
					add(objStr(e, "name"))
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
	reg := objAt(links, "invariants")
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

// checkSentinelPasses is the B4 v3 rule: a closing disposition of a
// sentinel-guarded row (own_form=sentinel) must name the value that passes
// the check. Existence of an assertion is not correctness; the disposition
// has to be falsifiable. The family escape hatch (--override-dismissal with
// --override-reason) stays the only way around it — see
// checkSentinelPassesRow.
func checkSentinelPasses(row validation.Value, outcome string,
	opts AnsweredOpts) error {
	if outcome != "answered" && outcome != "not-applicable" {
		return nil
	}
	if objStr(row, "own_form") != "sentinel" {
		return nil
	}
	if opts.PassesValue != nil &&
		len(strings.TrimSpace(*opts.PassesValue)) >= 3 {
		return nil
	}
	return errValue("sentinel-guarded probe row " + objStr(row, "row_id") +
		": a closing disposition must name the value that passes its check " +
		"(--passes VALUE) — or override explicitly (--override-dismissal " +
		"--override-reason R)")
}

// checkSentinelPassesRow is the closure-seam half: it resolves the surface row
// the disposition points at and applies the rule to it. A probe disposition
// whose surface row cannot be resolved (no surface, or the row was re-emitted
// away) is skipped — the anchor path reports that more usefully, and a row
// nobody can look up must never become unclosable. An explicit dismissal
// override passes the rule: the logged reason is the record of that decision.
func checkSentinelPassesRow(campaign *state.Campaign, outcome string,
	prov validation.Value, hasProv bool, opts AnsweredOpts) error {
	if !hasProv || !inList(outcome, []string{"answered", "not-applicable"}) {
		return nil
	}
	if opts.OverrideDismissal {
		return nil
	}
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return err
	}
	if surface == nil {
		return nil
	}
	row, ok := findRow(*surface, objStr(prov, "row_id"))
	if !ok {
		return nil
	}
	return checkSentinelPasses(row, outcome, opts)
}
