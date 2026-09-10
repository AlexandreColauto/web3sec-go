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
		links, err := invariants.LoadLinks(campaign)
		if err != nil {
			return false
		}
		reg := objAt(links, "invariants")
		return reg.Kind == validation.Obj && hasKey(reg, ref)
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
	if !hasProv || !inList(outcome, ProbeRowDispositioned) ||
		opts.Reason == nil {
		return nil
	}
	phrases := DismissalHits(*opts.Reason)
	if len(phrases) == 0 {
		return nil
	}
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
	return errValue(head + ": the closure reason uses dismissal vocabulary " +
		validation.PyRepr(strArr(phrases)) + " on a high-risk row (tier 0 " +
		"or assertion_gap >= 3). A dismissal this close to the money needs a " +
		"refutation that runs — --ref EXEC-<id> (an existing exec record) or " +
		"--ref INV-<n> (a registered invariant) — or an explicit, logged " +
		"override: --override-dismissal --override-reason R")
}
