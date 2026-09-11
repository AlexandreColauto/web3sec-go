// lens_join.go (G17 shared join): the per-lens attribution behind
// LensYield, promoted to exported so the planner's auto-deprioritization
// and the briefing's batting-average render consume the SAME join — one
// source of truth, no second implementation. LensYield itself is built on
// these helpers (its body was refactored onto them, not copied).
package costs

import (
	"os"
	"path/filepath"
	"sort"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ProbeRowLens is the probe-surface join: surface row_id -> lens (L-id).
// Best effort — a missing or stale surface yields an empty map and
// priorities stay unattributed rather than failing the rollup.
func ProbeRowLens(c *state.Campaign) map[string]string {
	rowLens := map[string]string{}
	raw, err := os.ReadFile(
		filepath.Join(c.ArtifactsDir, "probe_surface.json"))
	if err != nil {
		return rowLens
	}
	surface, err := validation.ParseOrdered(raw)
	if err != nil {
		return rowLens
	}
	for _, r := range listOf(surface, "rows") {
		if rid, lens := objStr(r, "row_id"), objStr(r, "lens"); rid != "" &&
			lens != "" {
			rowLens[rid] = lens
		}
	}
	return rowLens
}

// PlanLensIDs is the plan's lens roster: sorted unique lens ids from the
// plan's lenses array (the deterministic L-id order every consumer sorts
// by — plan order is LensIDs order, and sorting pins it).
func PlanLensIDs(plan validation.Value) []string {
	seen := map[string]bool{}
	ids := []string{}
	for _, l := range listOf(plan, "lenses") {
		id := objStr(l, "id")
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// PrioLensBucket attributes one plan priority to its lens bucket: the
// probe provenance (probe.row_id) resolved through the surface join when
// the plan knows that lens, "unattributed" otherwise (unresolvable or
// unknown — never an invented row).
func PrioLensBucket(p validation.Value, rowLens map[string]string,
	known map[string]bool) string {
	lens := ""
	if prov := objAt(p, "probe"); prov.Kind == validation.Obj {
		lens = rowLens[objStr(prov, "row_id")]
	}
	if known[lens] {
		return lens
	}
	return "unattributed"
}

// LensConfirmed is the confirmation bar the per-lens n_confirmed counts:
// critic verdict confirmed AND no CONFIRMED evidence deficit (the report
// precision block's floor intersection — a critic-only confirmation is a
// false-positive suspect, not a billed result).
func LensConfirmed(f validation.Value, c *state.Campaign) bool {
	if objStr(objAt(f, "verification"), "critic_verdict") != "confirmed" {
		return false
	}
	return findings.EvidenceDeficit(f, "CONFIRMED", c) == nil
}
