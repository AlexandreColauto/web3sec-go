// Package costs is webv2/costs.py: operator-reported costs and cost-adjusted
// discovery yield.
//
// The planner should allocate budget by observed yield, not by a static agent
// list:
//
//	yield = confirmed_security_value / (model_cost + compute_cost + human_review_cost)
//
// Design rules, enforced here:
//
//   - Costs are operator-reported, never inferred. The system only records
//     what it is told, with an actor on every row and a hash-chained log
//     entry per record. It never guesses.
//   - Value is confirmed money: the sum of economic_impact.extractable_usd
//     over CONFIRMED findings. The 1-10 risk score is a band, not a price; it
//     never enters this arithmetic.
//   - Yield is advisory. It ranks trajectories so the planner can learn and
//     allocate budget intelligently. It gates nothing.
package costs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// CostKinds is COST_KINDS.
var CostKinds = []string{"model", "compute", "human-review"}

// costIDSource mints the cost_id: a RAW uuid4 hex[:12], not state.new_id,
// so the WEBV2_UUID pin does not reach it. Tests and the golden suite
// install a deterministic minter through SetCostIDSource.
var costIDSource = newRandomCostID

// SetCostIDSource installs a cost-id minter; nil restores uuid4.
func SetCostIDSource(f func() string) {
	if f == nil {
		f = newRandomCostID
	}
	costIDSource = f
}

func newRandomCostID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("costs: uuid4: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return "COST-" + hex.EncodeToString(b)[:12]
}

func costsPath(c *state.Campaign) string {
	return filepath.Join(c.Dir, "costs.jsonl")
}

// zeroRow is _ZERO / _row: the per-trajectory accumulator in Python's key
// order.
func zeroRow() validation.Value {
	return validation.VObj(
		validation.KV{K: "model", V: validation.VFloat(0)},
		validation.KV{K: "compute", V: validation.VFloat(0)},
		validation.KV{K: "human-review", V: validation.VFloat(0)},
		validation.KV{K: "confirmed_findings", V: validation.VInt(0)},
		validation.KV{K: "confirmed_value_usd", V: validation.VFloat(0)},
	)
}

// RecordOpts is record_cost's keyword arguments.
type RecordOpts struct {
	Kind       string
	AmountUSD  float64
	Trajectory *string
	Stage      *string
	Actor      string
	Note       *string
	FindingID  *string
	// Lens is the G13 cost-attribution lens (L-01, L-02, ...): the check
	// family the spend served. Operator-reported like every other cost
	// field — the writer passes it only where genuinely known (a `cost
	// --lens` invocation); "" means the row carries no lens and the key
	// is absent from the row (omitempty-style), never null.
	Lens string
}

// RecordCost is record_cost: append one operator-reported cost row. Costs
// are never inferred: whatever the operator reports is recorded verbatim,
// attributed to an actor, and anchored in the event log.
func RecordCost(c *state.Campaign, opts RecordOpts) (validation.Value, error) {
	if !contains(CostKinds, opts.Kind) {
		return validation.VNull(), fmt.Errorf(
			"cost kind must be one of %s, got %s", pyTuple(CostKinds),
			validation.PyReprStr(opts.Kind))
	}
	if opts.AmountUSD < 0 {
		return validation.VNull(), fmt.Errorf(
			"amount_usd must be a number >= 0, got %s",
			validation.PythonFloat(opts.AmountUSD))
	}
	if strings.TrimSpace(opts.Actor) == "" {
		return validation.VNull(), fmt.Errorf(
			"cost rows must name their actor (who reports the cost)")
	}
	entry := validation.VObj(
		validation.KV{K: "cost_id", V: validation.VStr(costIDSource())},
		validation.KV{K: "at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "kind", V: validation.VStr(opts.Kind)},
		validation.KV{K: "amount_usd", V: validation.VFloat(opts.AmountUSD)},
		validation.KV{K: "trajectory", V: optStr(opts.Trajectory)},
		validation.KV{K: "stage", V: optStr(opts.Stage)},
		validation.KV{K: "actor", V: validation.VStr(opts.Actor)},
		validation.KV{K: "note", V: optStr(opts.Note)},
		validation.KV{K: "finding_id", V: optStr(opts.FindingID)},
	)
	// The lens rides the row only where the call site genuinely knows it:
	// "" keeps the key absent (never null) so unattributed spend stays
	// distinguishable from mis-attributed spend downstream.
	if opts.Lens != "" {
		entry.O = append(entry.O,
			validation.KV{K: "lens", V: validation.VStr(opts.Lens)})
	}
	// The JSONL split policy: costs.jsonl is written with bare json.dumps
	// (ensure_ascii=True), unlike every other JSONL in the tree.
	// r14: row + cost.recorded event are ONE unit (the projection audit
	// cross-checks both directions); hold the campaign lock across both,
	// exactly like the waiver pair.
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	if err := validation.AppendJsonlAscii(costsPath(c),
		validation.DumpsOrdered(entry, true)); err != nil {
		return validation.VNull(), err
	}
	ref := objStr(entry, "cost_id")
	data := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr(opts.Kind)},
		validation.KV{K: "amount_usd", V: validation.VFloat(opts.AmountUSD)},
		validation.KV{K: "trajectory", V: optStr(opts.Trajectory)},
		validation.KV{K: "actor", V: validation.VStr(opts.Actor)},
	)
	if _, err := c.Log("cost.recorded", &ref, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// LoadCosts is load_costs: every row, in file order.
func LoadCosts(c *state.Campaign) ([]validation.Value, error) {
	raw, err := os.ReadFile(costsPath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []validation.Value
	for i, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v, err := validation.ParseOrdered([]byte(line))
		if err != nil {
			// r15: line-attributed, like every other JSONL in the
			// tree — "invalid character '\xff'" alone sent operators
			// scanning the file by eye.
			return nil, fmt.Errorf("costs.jsonl line %d does not parse (%v)",
				i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// YieldReport is yield_report: per-trajectory cost by kind, confirmed
// findings, confirmed value, and yield = value / total cost (nil when no cost
// was recorded — zero-cost confirmed value is a reporting gap, not infinite
// yield).
func YieldReport(c *state.Campaign) (validation.Value, error) {
	byTraj := []validation.KV{}
	index := map[string]int{}
	row := func(traj string) *validation.Value {
		if i, ok := index[traj]; ok {
			return &byTraj[i].V
		}
		d := zeroRow()
		d.O = append(d.O, validation.KV{K: "trajectory",
			V: validation.VStr(traj)})
		byTraj = append(byTraj, validation.KV{K: traj, V: d})
		index[traj] = len(byTraj) - 1
		return &byTraj[len(byTraj)-1].V
	}
	costs, err := LoadCosts(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, e := range costs {
		traj := objStr(e, "trajectory")
		if traj == "" {
			traj = "unattributed"
		}
		d := row(traj)
		kind := objStr(e, "kind")
		cur := floatField(*d, kind)
		setKey(d, kind, validation.VFloat(cur+floatField(e, "amount_usd")))
	}

	confirmedCount := int64(0)
	confirmedValue := 0.0
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	// G13 cost attribution (advisory-only): the per-confirmed denominators
	// reuse the report precision block's vocabulary verbatim —
	// critic-confirmed is verification.critic_verdict == "confirmed" and
	// evidence-confirmed is a cleared CONFIRMED evidence floor
	// (findings.EvidenceDeficit == nil), both counted over the same live
	// set the precision block ranks (DUPLICATE / OUT_OF_SCOPE /
	// SUPERSEDED excluded). ADVISORY LAW: these quotients render and roll
	// up only — grep the tree and you will find no gate, completion
	// check, or policy consuming cost_per_* or lens_yield anywhere.
	criticConfirmed := int64(0)
	evidenceConfirmed := int64(0)
	for _, f := range all {
		if s := objStr(f, "status"); s == "DUPLICATE" ||
			s == "OUT_OF_SCOPE" || s == "SUPERSEDED" {
			continue
		}
		if objStr(objAt(f, "verification"), "critic_verdict") ==
			"confirmed" {
			criticConfirmed++
		}
		if findings.EvidenceDeficit(f, "CONFIRMED", c) == nil {
			evidenceConfirmed++
		}
	}
	for _, f := range all {
		if objStr(f, "status") != "CONFIRMED" {
			continue
		}
		confirmedCount++
		value := floatField(objAt(f, "economic_impact"), "extractable_usd")
		confirmedValue += value
		traj := objStr(f, "trajectory")
		if traj == "" {
			traj = "unattributed"
		}
		d := row(traj)
		setKey(d, "confirmed_findings", validation.VInt(
			intField(*d, "confirmed_findings")+1))
		setKey(d, "confirmed_value_usd", validation.VFloat(
			floatField(*d, "confirmed_value_usd")+value))
	}

	names := make([]string, 0, len(byTraj))
	for _, kv := range byTraj {
		names = append(names, kv.K)
	}
	sort.Strings(names)
	rows := []validation.Value{}
	totalCost := 0.0
	for _, traj := range names {
		d := *row(traj)
		total := 0.0
		for _, k := range CostKinds {
			total += floatField(d, k)
		}
		setKey(&d, "total_cost_usd", validation.VFloat(total))
		var yieldV validation.Value = validation.VNull()
		if total > 0 {
			yieldV = validation.VFloat(floatField(d, "confirmed_value_usd") / total)
		}
		setKey(&d, "yield_usd_per_usd", yieldV)
		totalCost += total
		rows = append(rows, d)
	}
	var totalYield validation.Value = validation.VNull()
	if totalCost > 0 {
		totalYield = validation.VFloat(confirmedValue / totalCost)
	}
	// sum() over NO rows at all is the INT 0 (Python), so an empty campaign
	// reports totals.total_cost_usd as 0, not 0.0 — the JSON dump shows it.
	var totalCostV validation.Value = validation.VInt(0)
	if len(rows) > 0 {
		totalCostV = validation.VFloat(totalCost)
	}
	// Cost per confirmation is null when the denominator is 0 — zero-cost
	// confirmed value is a reporting gap, never infinity (same rule as
	// yield_usd_per_usd above). Stored full float like cost_usd itself;
	// renderers round to 2 decimals.
	var perCritic, perEvidence validation.Value = validation.VNull(),
		validation.VNull()
	if criticConfirmed > 0 {
		perCritic = validation.VFloat(totalCost / float64(criticConfirmed))
	}
	if evidenceConfirmed > 0 {
		perEvidence = validation.VFloat(totalCost / float64(evidenceConfirmed))
	}
	return validation.VObj(
		validation.KV{K: "trajectories", V: validation.VArr(rows...)},
		validation.KV{K: "totals", V: validation.VObj(
			validation.KV{K: "total_cost_usd", V: totalCostV},
			validation.KV{K: "confirmed_findings",
				V: validation.VInt(confirmedCount)},
			validation.KV{K: "confirmed_value_usd",
				V: validation.VFloat(confirmedValue)},
			validation.KV{K: "yield_usd_per_usd", V: totalYield},
			validation.KV{K: "cost_per_critic_confirmed_usd",
				V: perCritic},
			validation.KV{K: "cost_per_evidence_confirmed_usd",
				V: perEvidence})},
		validation.KV{K: "note", V: validation.VStr("value = confirmed " +
			"extractable_usd (never the 1-10 risk band); costs are " +
			"operator-reported; yield is advisory and gates nothing")},
	), nil
}

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
	costRows, err := LoadCosts(c)
	if err != nil {
		return nil, err
	}
	lensCost := map[string]float64{}
	unattributedCost := 0.0
	unattributedRows := 0
	hasLensCosts := false
	for _, e := range costRows {
		lens := objStr(e, "lens")
		if lens == "" {
			unattributedCost += floatField(e, "amount_usd")
			unattributedRows++
			continue
		}
		hasLensCosts = true
		lensCost[lens] += floatField(e, "amount_usd")
	}
	plan, planOK := loadPlanLenient(c)
	planLens := []string{}
	if planOK {
		planLens = PlanLensIDs(plan)
	}
	if !hasLensCosts && len(planLens) == 0 {
		return nil, nil
	}
	ids := append([]string{}, planLens...)
	if !planOK {
		for lens := range lensCost {
			ids = append(ids, lens)
		}
		sort.Strings(ids)
	}
	// The probe-surface join (shared with the planner's G17 gate and the
	// briefing's batting-average render — one source, costs owns it).
	rowLens := ProbeRowLens(c)
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	planned := map[string]int64{}
	confirmed := map[string]int64{}
	byFinding := map[string]validation.Value{}
	if planOK {
		all, err := findings.LoadAllFindings(c)
		if err != nil {
			return nil, err
		}
		for _, f := range all {
			byFinding[objStr(f, "finding_id")] = f
		}
		for _, p := range listOf(plan, "priorities") {
			bucket := PrioLensBucket(p, rowLens, known)
			planned[bucket]++
			if objStr(p, "status") != "answered" {
				continue
			}
			ref := strings.TrimSpace(objStr(p, "closed_ref"))
			if !strings.HasPrefix(ref, "F-") {
				continue
			}
			f, ok := byFinding[strings.Fields(ref)[0]]
			if !ok {
				continue
			}
			if !LensConfirmed(f, c) {
				continue
			}
			confirmed[bucket]++
		}
	}
	out := []validation.Value{}
	for _, id := range ids {
		out = append(out, validation.VObj(
			validation.KV{K: "lens", V: validation.VStr(id)},
			validation.KV{K: "n_planned", V: validation.VInt(planned[id])},
			validation.KV{K: "n_confirmed",
				V: validation.VInt(confirmed[id])},
			validation.KV{K: "cost_usd",
				V: validation.VFloat(lensCost[id])},
		))
	}
	// The unattributed bucket exists for cost rows lacking lens. When the
	// plan is absent there is no other row to bill them to, so any
	// unattributed spend still lands here. Planned-count arm: a priority
	// with no resolvable lens buckets to "unattributed" even when every
	// cost row is lensed — emitting no row there would drop the count.
	if unattributedRows > 0 || !planOK || planned["unattributed"] > 0 {
		out = append(out, validation.VObj(
			validation.KV{K: "lens", V: validation.VStr("unattributed")},
			validation.KV{K: "n_planned",
				V: validation.VInt(planned["unattributed"])},
			validation.KV{K: "n_confirmed",
				V: validation.VInt(confirmed["unattributed"])},
			validation.KV{K: "cost_usd",
				V: validation.VFloat(unattributedCost +
					unbilledLens(lensCost, known))},
		))
	}
	return out, nil
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

// listOf is plan.get(key, []) for the array shapes the plan and the probe
// surface hold.
func listOf(v validation.Value, key string) []validation.Value {
	l := objAt(v, key)
	if l.Kind == validation.Arr {
		return l.A
	}
	return nil
}

// BudgetStatus is budget_status: cost position against the operator-set
// ceiling (budget.max_total_cost_usd). The ceiling is a DECISION surface,
// not a meter.
func BudgetStatus(c *state.Campaign) (validation.Value, error) {
	// r15: enforcement never prices a damaged mirror. This is a
	// REFUSAL, not a warning — the pipeline that halts here halts on
	// the honest reason, and `audit` names each problem (the sanctioned
	// way back is repair, not a bigger ceiling).
	if probs := CostMirrorProblems(c); len(probs) > 0 {
		return validation.VNull(), fmt.Errorf(
			"cost projection is damaged (%d problem(s), first: %s) — "+
				"spend numbers cannot be trusted and the budget will "+
				"not be evaluated against them; run `webv2 audit` for "+
				"the full list", len(probs), probs[0])
	}
	budget, err := c.Budget()
	if err != nil {
		return validation.VNull(), err
	}
	limit := objAt(budget, "max_total_cost_usd")
	rep, err := YieldReport(c)
	if err != nil {
		return validation.VNull(), err
	}
	// spent keeps yield_report's exact value (int 0 when no rows exist).
	spent := objAt(objAt(rep, "totals"), "total_cost_usd")
	if limit.Kind == validation.Null {
		return validation.VObj(
			validation.KV{K: "limit_usd", V: validation.VNull()},
			validation.KV{K: "spent_usd", V: spent},
			validation.KV{K: "status", V: validation.VStr("no-limit")},
			validation.KV{K: "remaining_usd", V: validation.VNull()},
			validation.KV{K: "note", V: validation.VStr("no " +
				"max_total_cost_usd set — spend is unbounded; set one in " +
				"the campaign budget to halt the pipeline when the " +
				"ceiling is crossed")},
		), nil
	}
	lim := floatField(budget, "max_total_cost_usd")
	remaining := lim - floatField(objAt(rep, "totals"), "total_cost_usd")
	status := "within"
	if remaining < 0 {
		status = "exceeded"
	}
	over := 0.0
	if -remaining > 0 {
		over = -remaining
	}
	return validation.VObj(
		validation.KV{K: "limit_usd", V: validation.VFloat(lim)},
		validation.KV{K: "spent_usd", V: spent},
		validation.KV{K: "status", V: validation.VStr(status)},
		validation.KV{K: "remaining_usd", V: validation.VFloat(remaining)},
		validation.KV{K: "over_by_usd", V: validation.VFloat(over)},
	), nil
}

// AllocationAdvice is allocation_advice: rank trajectories by observed yield
// (highest first; no-cost rows last). Pure advice for the planner.
func AllocationAdvice(c *state.Campaign) ([]validation.Value, error) {
	rep, err := YieldReport(c)
	if err != nil {
		return nil, err
	}
	rows := append([]validation.Value{}, objAt(rep, "trajectories").A...)
	sort.SliceStable(rows, func(i, j int) bool {
		yi, yj := objAt(rows[i], "yield_usd_per_usd"), objAt(rows[j], "yield_usd_per_usd")
		ni, nj := yi.Kind == validation.Null, yj.Kind == validation.Null
		if ni != nj {
			return !ni
		}
		return -floatField(rows[i], "yield_usd_per_usd") <
			-floatField(rows[j], "yield_usd_per_usd")
	})
	advice := []validation.Value{}
	for i, r := range rows {
		y := objAt(r, "yield_usd_per_usd")
		ys := "no cost recorded"
		var yv validation.Value = validation.VNull()
		if y.Kind != validation.Null {
			yv = y
			ys = pyFixed1(floatField(r, "yield_usd_per_usd")) + "x"
		}
		confirmed := intField(r, "confirmed_findings")
		var verdict string
		switch {
		case confirmed == 0:
			verdict = "no confirmed value yet — spend is a bet, watch the " +
				"next pass"
		case y.Kind == validation.Null:
			verdict = "confirmed value with no recorded cost — record the " +
				"costs to make this comparable"
		case i == 0 && len(rows) > 1 && floatField(r, "yield_usd_per_usd") > 0:
			verdict = "highest observed yield — allocate more budget here"
		case i == 0 && floatField(r, "yield_usd_per_usd") == 0:
			verdict = "no positive yield yet — keep spend minimal until a " +
				"confirmation lands"
		default:
			verdict = "observed yield below the leader — allocate " +
				"proportionally"
		}
		advice = append(advice, validation.VObj(
			validation.KV{K: "rank", V: validation.VInt(int64(i + 1))},
			validation.KV{K: "trajectory", V: objAt(r, "trajectory")},
			validation.KV{K: "yield_usd_per_usd", V: yv},
			validation.KV{K: "yield", V: validation.VStr(ys)},
			validation.KV{K: "advice", V: validation.VStr(verdict)},
		))
	}
	return advice, nil
}

// API adapts the costs module to pipeline.CostsAPI (the pipeline halts on
// the ceiling through budget_status).
type API struct{}

// BudgetStatus is costs.budget_status.
func (API) BudgetStatus(c *state.Campaign) (validation.Value, error) {
	return BudgetStatus(c)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// pyTuple is Python's repr of a tuple of strings.
func pyTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	if len(items) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyFixed1 is Python's f"{x:.1f}".
func pyFixed1(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func optStr(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

// floatField is float(v.get(key, 0)) for the number shapes costs.jsonl and
// findings hold (Python's `or 0` treats null/absent as 0).
func floatField(v validation.Value, key string) float64 {
	f := objAt(v, key)
	switch f.Kind {
	case validation.Flt:
		return f.F
	case validation.Int:
		if f.Big != "" {
			out, _ := strconv.ParseFloat(f.Big, 64)
			return out
		}
		return float64(f.I)
	}
	return 0
}

func intField(v validation.Value, key string) int64 {
	f := objAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

// setKey replaces key in place (Python's dict assignment keeps position).
func setKey(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
}

// CostMirrorProblems is the ONE cost-projection law: costs.jsonl rows
// and cost.recorded ledger events must describe the same spend, both
// directions. The audit (sections.Projection) reports these; the
// ENFORCEMENT side (BudgetStatus) refuses to price a campaign over
// them (r15: a ghost row halted pipelines on spend the audit
// simultaneously called forged — the gate and the truth reader each
// trusted their own file). Presence-gated: quiet campaigns and fully
// consistent ones return nothing.
func CostMirrorProblems(c *state.Campaign) []string {
	evts, err := c.Events()
	if err != nil {
		// r17 P2: an UNREADABLE ledger is strictly worse than a damaged
		// mirror — returning nil here priced spend off the rows alone
		// while verify screamed red ("cost: $42.00 spent" on a GARBAGE
		// log). "The ledger verdict belongs to verify" justified
		// silence, not authority to evaluate spend against nothing.
		return []string{"the event ledger is unreadable, so recorded " +
			"costs cannot be cross-checked: " + err.Error()}
	}
	var costEvts []validation.Value
	refs := map[string]bool{}
	for _, e := range evts {
		if objStr(e, "type") == "cost.recorded" {
			costEvts = append(costEvts, e)
			refs[objStr(e, "ref")] = true
		}
	}
	rows, rerr := LoadCosts(c)
	if rerr != nil {
		return []string{fmt.Sprintf("costs.jsonl unreadable: %v", rerr)}
	}
	if len(costEvts) == 0 && len(rows) == 0 {
		return nil
	}
	var out []string
	// r16 P1-1: the law is about SPEND, not id-existence — comparing
	// cost_id strings alone let one appended duplicate-id row double the
	// booked amount (audit PASS while budget priced phantom money) and
	// let an amount rewrite hide under its own id. Per id the ledger and
	// the file must agree on COUNT and on the SUM of amounts (and every
	// kind the id carries): twin stores legitimately repeat an id across
	// rows — uuid4 is per-row but the pinned fixtures prove identity is
	// not the invariant — so equality is aggregated, and that catches
	// inflation, dodging, and edits alike.
	type ledger struct {
		n     int
		sum   float64
		kinds map[string]bool
	}
	byID := map[string]ledger{}
	for _, e := range costEvts {
		id := objStr(e, "ref")
		if id == "" {
			out = append(out, "a cost.recorded event carries no ref — "+
				"spend the ledger cannot attribute")
			continue
		}
		l := byID[id]
		l.n++
		if a := objAt(objAt(e, "data"), "amount_usd"); a.Kind == validation.Flt ||
			a.Kind == validation.Int {
			f, _ := numberValue(a)
			l.sum += f
		}
		if l.kinds == nil {
			l.kinds = map[string]bool{}
		}
		if k := objStr(objAt(e, "data"), "kind"); k != "" {
			l.kinds[k] = true
		}
		byID[id] = l
	}
	count := map[string]int{}
	sum := map[string]float64{}
	kinds := map[string]map[string]bool{}
	for _, r := range rows {
		id := objStr(r, "cost_id")
		if id == "" {
			out = append(out, "costs.jsonl has a row with no cost_id — "+
				"spend that cannot be attributed cannot be audited")
			continue
		}
		count[id]++
		if a := objAt(r, "amount_usd"); a.Kind == validation.Flt ||
			a.Kind == validation.Int {
			f, _ := numberValue(a)
			sum[id] += f
		}
		if kinds[id] == nil {
			kinds[id] = map[string]bool{}
		}
		if k := objStr(r, "kind"); k != "" {
			kinds[id][k] = true
		}
	}
	for id, l := range byID {
		if count[id] == 0 {
			out = append(out, fmt.Sprintf("the ledger records cost %s (%s) "+
				"but costs.jsonl has no row for it", id,
				pyReprValue(validation.VFloat(l.sum))))
			continue
		}
		if count[id] != l.n {
			out = append(out, fmt.Sprintf(
				"costs.jsonl carries %d rows for cost %s but the ledger "+
					"recorded %d — spend was duplicated or events lost",
				count[id], id, l.n))
			continue
		}
		if sum[id] != l.sum {
			out = append(out, fmt.Sprintf(
				"costs.jsonl books $%s under cost %s but the ledger "+
					"events sum to $%s — the recorded amounts were "+
					"edited in the file", format2(sum[id]), id,
				format2(l.sum)))
			continue
		}
		for k := range l.kinds {
			if !kinds[id][k] {
				out = append(out, fmt.Sprintf(
					"the ledger says cost %s was kind %s but no costs.jsonl "+
						"row for it is — the recorded kind was edited", id, k))
			}
		}
	}
	for id := range count {
		if _, ok := byID[id]; !ok {
			out = append(out, fmt.Sprintf("costs.jsonl row(s) for cost %s "+
				"were never recorded in the ledger — ghost spend inflates "+
				"the budget silently; costs are owed through `webv2 cost`, "+
				"not by editing the file", id))
		}
	}
	return out
}

// sameSpend compares ledger vs row numbers the way Python's == would
// across int/float (1 == 1.0), and treats any non-number as unequal to
// a number. Null vs Null is equal (a cost recorded without an amount
// matches a row without one).
func sameSpend(a, b validation.Value) bool {
	if a.Kind == validation.Null && b.Kind == validation.Null {
		return true
	}
	an, aok := numberValue(a)
	bn, bok := numberValue(b)
	if aok && bok {
		return an == bn
	}
	return false
}

func numberValue(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Flt:
		return v.F, true
	case validation.Int:
		return float64(v.I), true
	}
	return 0, false
}

// pyReprValue renders a number for a message (None, 10.0, 4).
func pyReprValue(v validation.Value) string {
	if v.Kind == validation.Null {
		return "None"
	}
	f, ok := numberValue(v)
	if !ok {
		return validation.PyRepr(v)
	}
	if v.Kind == validation.Int {
		return validation.IntText(v)
	}
	return validation.PythonFloat(f)
}

// format2 renders a money figure for messages (2 decimals, plain).
func format2(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}
