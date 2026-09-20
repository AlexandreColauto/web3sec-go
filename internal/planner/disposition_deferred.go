// disposition_deferred.go: the FIX-5 deferred-consequence gate — a
// high-risk row closed on the asserter anchor or on failure-consequence
// vocabulary must price the interim window.
package planner

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

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
	if !hasProv || !slices.Contains(ProbeRowDispositioned, outcome) {
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
	// R3-5(i): a closure that links a finding never checked the finding
	// DESCRIBES this row — the report's arm-1 loss is a row closed with a
	// causally wrong reason quoting the row's own identifiers while the
	// linked finding talks about other code. Causal truth is not
	// statically decidable (the repo's own doctrine, and a refusal would
	// fight the FP budget), so this WARNS on the notice channel —
	// mechanically, on symbol overlap — and lets the closure land. It runs
	// BEFORE the high-risk and trigger early-returns so every linked
	// closure is covered, not just deferred-consequence ones.
	if opts.Finding != nil {
		warnUnrelatedFinding(campaign, opts, priorityID, rowID, row)
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

// warnUnrelatedFinding is the R3-5(i) cross-check: the linked finding's
// root_cause mechanism+description must name at least one of the row's own
// surface symbols, or the notice channel carries a line saying the link is
// unverified and pointing at `webv2 anchors` (the mechanical overlap check
// B8 made possible). Everything it cannot judge it stays silent about: a
// malformed or ghost id belongs to the strict gates (they refuse it where
// they run), an empty mechanism is no signal, a symbol-less row has nothing
// to match, and a notice already set this run is APPENDED to, never
// clobbered — two stand-downs in one pass deserve two lines.
func warnUnrelatedFinding(campaign *state.Campaign, opts AnsweredOpts,
	priorityID, rowID string, row validation.Value) {
	if opts.SkipNotice == nil {
		return
	}
	ref := strings.TrimSpace(*opts.Finding)
	if !findingRefPattern.MatchString(ref) {
		return
	}
	raw, err := os.ReadFile(filepath.Join(campaign.FindingsDir, ref+".json"))
	if err != nil {
		return
	}
	f, err := validation.ParseOrdered(raw)
	if err != nil {
		return
	}
	rc := validation.ObjAt(f, "root_cause")
	text := strings.TrimSpace(validation.ObjStr(rc, "mechanism") + " " +
		validation.ObjStr(rc, "description"))
	if text == "" {
		return
	}
	syms := RowSymbols(row)
	if len(syms) == 0 || namesSymbol(text, syms) != "" {
		return
	}
	line := "notice: priority " + priorityID + " closes probe row " + rowID +
		" citing finding " + ref + ", whose mechanism names nothing from " +
		"that row's surface entry (" + strings.Join(syms, ", ") + ") — " +
		"verify the link before leaning on this closure: webv2 anchors " +
		campaign.CampaignID + " <symbol>"
	if *opts.SkipNotice == "" {
		*opts.SkipNotice = line
	} else {
		*opts.SkipNotice += "\n" + line
	}
}
