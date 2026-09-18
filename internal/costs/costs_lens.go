// G13 cost-attribution lens: the per-lens planned/confirmed/cost table with its lenient plan read.
package costs

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// LensYield is the G13 per-lens attribution table: one row per lens in
// the campaign plan, {lens, n_planned, n_confirmed, cost_usd}, plus a
// final "unattributed" bucket for cost rows that carry no lens.
//
// Attribution paths (the repo's only real ones — priorities carry no
// top-level lens field, so this joins what exists):
//   - n_planned: plan priorities whose probe provenance (probe.row_id)
//     resolves to a probe_surface.json row carrying that lens id.
//     Priorities with no resolvable lens count toward "unattributed".
//   - n_confirmed: the subset of those priorities closed as answered
//     whose closed_ref names a finding that clears the full confirmation
//     bar — critic verdict confirmed AND no CONFIRMED evidence deficit
//     (the precision block's floor intersection: a critic-only
//     confirmation is a false-positive suspect, not a billed result).
//   - cost_usd: the sum of cost rows whose row.lens == id. A cost row
//     whose lens the plan does not know bills to "unattributed" rather
//     than inventing a row.
//
// Presence gate: nil (no rows) when zero lens-carrying cost rows exist
// AND the plan carries no lens data — renderers then emit nothing at
// all. Any lens data on either side renders the full table with zeros
// where nothing was observed. Deterministic: plan L-ids ascending,
// "unattributed" last. The per-lens cost rows plus the unattributed
// bucket always sum to the campaign total.
//
// ADVISORY LAW (see YieldReport): this renders and rolls up only — no
// gate, completion check, or policy may consume it.
func LensYield(c *state.Campaign) ([]validation.Value, error) {
	l := &lensYield{c: c}
	if err := l.lensFoldCosts(); err != nil {
		return nil, err
	}
	l.lensLoadPlan()
	if !l.hasLensCosts && len(l.planLens) == 0 {
		return nil, nil
	}
	ids := l.lensIDs()
	if err := l.lensFoldPriorities(ids); err != nil {
		return nil, err
	}
	return l.lensRender(ids), nil
}

// lensYield carries LensYield's attribution state: the per-lens cost
// fold from costs.jsonl, the leniently-read plan and its lens ids, and
// the planned/confirmed counters the render step emits.
type lensYield struct {
	c                *state.Campaign
	lensCost         map[string]float64
	unattributedCost float64
	unattributedRows int
	hasLensCosts     bool
	plan             validation.Value
	planOK           bool
	planLens         []string
	known            map[string]bool
	planned          map[string]int64
	confirmed        map[string]int64
}

// lensFoldCosts loads the cost rows and bills each to its lens; rows
// carrying no lens accumulate in the unattributed bucket.
func (l *lensYield) lensFoldCosts() error {
	costRows, err := LoadCosts(l.c)
	if err != nil {
		return err
	}
	l.lensCost = map[string]float64{}
	for _, e := range costRows {
		lens := validation.ObjStr(e, "lens")
		if lens == "" {
			l.unattributedCost += floatField(e, "amount_usd")
			l.unattributedRows++
			continue
		}
		l.hasLensCosts = true
		l.lensCost[lens] += floatField(e, "amount_usd")
	}
	return nil
}

// lensLoadPlan reads the campaign plan leniently and collects the lens
// ids it plans for (empty when the plan is absent or unparseable).
func (l *lensYield) lensLoadPlan() {
	plan, ok := loadPlanLenient(l.c)
	l.plan, l.planOK = plan, ok
	l.planLens = []string{}
	if ok {
		l.planLens = PlanLensIDs(plan)
	}
}

// lensIDs assembles the table's row order: the plan's lens ids
// ascending; when the plan is absent, the observed cost lens ids sorted.
func (l *lensYield) lensIDs() []string {
	ids := append([]string{}, l.planLens...)
	if !l.planOK {
		for lens := range l.lensCost {
			ids = append(ids, lens)
		}
		sort.Strings(ids)
	}
	return ids
}

// lensFoldPriorities counts, per lens bucket, the plan's priorities and
// the subset closed as answered whose closed_ref names a finding that
// clears the full confirmation bar.
func (l *lensYield) lensFoldPriorities(ids []string) error {
	// The probe-surface join (shared with the planner's G17 gate and the
	// briefing's batting-average render — one source, costs owns it).
	rowLens := ProbeRowLens(l.c)
	l.known = map[string]bool{}
	for _, id := range ids {
		l.known[id] = true
	}
	l.planned = map[string]int64{}
	l.confirmed = map[string]int64{}
	if !l.planOK {
		return nil
	}
	byFinding := map[string]validation.Value{}
	all, err := findings.LoadAllFindings(l.c)
	if err != nil {
		return err
	}
	for _, f := range all {
		byFinding[validation.ObjStr(f, "finding_id")] = f
	}
	for _, p := range listOf(l.plan, "priorities") {
		bucket := PrioLensBucket(p, rowLens, l.known)
		l.planned[bucket]++
		if validation.ObjStr(p, "status") != "answered" {
			continue
		}
		ref := strings.TrimSpace(validation.ObjStr(p, "closed_ref"))
		if !strings.HasPrefix(ref, "F-") {
			continue
		}
		f, ok := byFinding[strings.Fields(ref)[0]]
		if !ok {
			continue
		}
		if !LensConfirmed(f, l.c) {
			continue
		}
		l.confirmed[bucket]++
	}
	return nil
}

// lensRender emits one row per lens id plus, when warranted, the
// unattributed bucket for cost rows that carry no (known) lens.
func (l *lensYield) lensRender(ids []string) []validation.Value {
	out := []validation.Value{}
	for _, id := range ids {
		out = append(out, validation.VObj(
			validation.KV{K: "lens", V: validation.VStr(id)},
			validation.KV{K: "n_planned", V: validation.VInt(l.planned[id])},
			validation.KV{K: "n_confirmed",
				V: validation.VInt(l.confirmed[id])},
			validation.KV{K: "cost_usd",
				V: validation.VFloat(l.lensCost[id])},
		))
	}
	// The unattributed bucket exists for cost rows lacking lens. When the
	// plan is absent there is no other row to bill them to, so any
	// unattributed spend still lands here. Planned-count arm: a priority
	// with no resolvable lens buckets to "unattributed" even when every
	// cost row is lensed — emitting no row there would drop the count.
	if l.unattributedRows > 0 || !l.planOK || l.planned["unattributed"] > 0 {
		out = append(out, validation.VObj(
			validation.KV{K: "lens", V: validation.VStr("unattributed")},
			validation.KV{K: "n_planned",
				V: validation.VInt(l.planned["unattributed"])},
			validation.KV{K: "n_confirmed",
				V: validation.VInt(l.confirmed["unattributed"])},
			validation.KV{K: "cost_usd",
				V: validation.VFloat(l.unattributedCost +
					unbilledLens(l.lensCost, l.known))},
		))
	}
	return out
}

// unbilledLens is the spend on lens ids the plan does not know: operator
// error (a typo'd --lens), billed to "unattributed" rather than dropped.
func unbilledLens(lensCost map[string]float64,
	known map[string]bool) float64 {
	out := 0.0
	for lens, amt := range lensCost {
		if !known[lens] {
			out += amt
		}
	}
	return out
}

// loadPlanLenient reads artifacts/campaign_plan.json without schema
// enforcement: attribution must degrade (unattributed), never fail, on a
// half-written plan. ok=false means absent or unparseable.
func loadPlanLenient(c *state.Campaign) (validation.Value, bool) {
	raw, err := os.ReadFile(
		filepath.Join(c.ArtifactsDir, "campaign_plan.json"))
	if err != nil {
		return validation.VNull(), false
	}
	plan, err := validation.ParseOrdered(raw)
	if err != nil || plan.Kind != validation.Obj {
		return validation.VNull(), false
	}
	return plan, true
}
