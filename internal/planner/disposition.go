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
package planner

import (
	"slices"
	"strings"
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
			!slices.Contains(ProbeRowDispositioned, validation.ObjStr(p, "status")) {
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
