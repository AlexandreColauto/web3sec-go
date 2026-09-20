// disposition_gate.go: the B4 v2 hard gate — a high-risk row may not be
// closed on dismissal vocabulary without a refutation that runs or an
// explicit, logged override.
package planner

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

var (
	execIDPattern    = regexp.MustCompile(`^EXEC-[0-9a-f]{10}$`)
	invariantPattern = regexp.MustCompile(`^INV-[0-9]+$`)
)

// refutationBacked is the B4 v2 acceptance: an exec id whose record exists
// on disk, or an invariant id present in the campaign's invariant registry.
// Anything else — a file#L anchor, a finding id, bare prose — is an
// assertion, not a refutation.
func refutationBacked(campaign *state.Campaign, ref string) bool {
	backed, _ := refutationRecord(campaign, ref)
	return backed
}

// refutationRecord is the record-returning form (R3-5(ii)): the EXEC half
// reads the exec_record.json whose EXISTENCE refutationBacked was checking,
// so a caller can ask whose finding the run belongs to. Existence is still
// the acceptance — an unreadable record backs the dismissal but attributes
// nothing (the caller sees a null record and applies its own law).
func refutationRecord(campaign *state.Campaign,
	ref string) (bool, validation.Value) {
	if execIDPattern.MatchString(ref) {
		raw, err := os.ReadFile(filepath.Join(campaign.ExecsDir, ref,
			"exec_record.json"))
		if err != nil {
			return false, validation.VNull()
		}
		rec, perr := validation.ParseOrdered(raw)
		if perr != nil {
			return true, validation.VNull()
		}
		return true, rec
	}
	if invariantPattern.MatchString(ref) {
		return invariantRegistered(campaign, ref), validation.VNull()
	}
	return false, validation.VNull()
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
	if !hasProv || !slices.Contains(ProbeRowDispositioned, outcome) {
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
				slices.Contains([]string{"answered", "not-applicable"}, outcome)
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
			slices.Contains([]string{"answered", "not-applicable"}, outcome) {
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
