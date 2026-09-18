// Yield report: per-trajectory cost/confirmed-value accumulation and the yield arithmetic, plus allocation advice ranked by observed yield.
package costs

import (
	"sort"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// YieldReport is yield_report: per-trajectory cost by kind, confirmed
// findings, confirmed value, and yield = value / total cost (nil when no cost
// was recorded — zero-cost confirmed value is a reporting gap, not infinite
// yield).
func YieldReport(c *state.Campaign) (validation.Value, error) {
	y := &yieldReport{c: c, index: map[string]int{}}
	costs, err := LoadCosts(c)
	if err != nil {
		return validation.VNull(), err
	}
	y.yieldFoldCosts(costs)
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	y.yieldFoldConfirmed(all)
	rows, totalCost := y.yieldRenderRows()
	return y.yieldRenderTotals(rows, totalCost), nil
}

// yieldReport carries the state YieldReport accumulates: byTraj is the
// per-trajectory row list in first-seen order, index maps each trajectory
// to its slot (the dict ordering the report relies on), and the
// confirmation totals feed the totals block.
type yieldReport struct {
	c                 *state.Campaign
	byTraj            []validation.KV
	index             map[string]int
	confirmedCount    int64
	confirmedValue    float64
	criticConfirmed   int64
	evidenceConfirmed int64
}

// yieldRow is _row: the per-trajectory accumulator in Python's key
// order — first touch appends a zero row, later touches return it.
func (y *yieldReport) yieldRow(traj string) *validation.Value {
	if i, ok := y.index[traj]; ok {
		return &y.byTraj[i].V
	}
	d := zeroRow()
	d.O = append(d.O, validation.KV{K: "trajectory",
		V: validation.VStr(traj)})
	y.byTraj = append(y.byTraj, validation.KV{K: traj, V: d})
	y.index[traj] = len(y.byTraj) - 1
	return &y.byTraj[len(y.byTraj)-1].V
}

// yieldFoldCosts adds every cost row's amount to its trajectory's
// accumulator (rows without a trajectory land on "unattributed").
func (y *yieldReport) yieldFoldCosts(costs []validation.Value) {
	for _, e := range costs {
		traj := validation.ObjStr(e, "trajectory")
		if traj == "" {
			traj = "unattributed"
		}
		d := y.yieldRow(traj)
		kind := validation.ObjStr(e, "kind")
		cur := floatField(*d, kind)
		setKey(d, kind, validation.VFloat(cur+floatField(e, "amount_usd")))
	}
}

// yieldFoldConfirmed folds the findings set over the accumulators: first
// the G13 advisory attribution counters, then the confirmed findings and
// their confirmed value.
//
// G13 cost attribution (advisory-only): the per-confirmed denominators
// reuse the report precision block's vocabulary verbatim —
// critic-confirmed is verification.critic_verdict == "confirmed" and
// evidence-confirmed is a cleared CONFIRMED evidence floor
// (findings.EvidenceDeficit == nil), both counted over the same live
// set the precision block ranks (DUPLICATE / OUT_OF_SCOPE /
// SUPERSEDED excluded). ADVISORY LAW: these quotients render and roll
// up only — grep the tree and you will find no gate, completion
// check, or policy consuming cost_per_* or lens_yield anywhere.
func (y *yieldReport) yieldFoldConfirmed(all []validation.Value) {
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" ||
			s == "OUT_OF_SCOPE" || s == "SUPERSEDED" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(f, "verification"), "critic_verdict") ==
			"confirmed" {
			y.criticConfirmed++
		}
		if findings.EvidenceDeficit(f, "CONFIRMED", y.c) == nil {
			y.evidenceConfirmed++
		}
	}
	for _, f := range all {
		if validation.ObjStr(f, "status") != "CONFIRMED" {
			continue
		}
		y.confirmedCount++
		value := floatField(validation.ObjAt(f, "economic_impact"), "extractable_usd")
		y.confirmedValue += value
		traj := validation.ObjStr(f, "trajectory")
		if traj == "" {
			traj = "unattributed"
		}
		d := y.yieldRow(traj)
		setKey(d, "confirmed_findings", validation.VInt(
			intField(*d, "confirmed_findings")+1))
		setKey(d, "confirmed_value_usd", validation.VFloat(
			floatField(*d, "confirmed_value_usd")+value))
	}
}

// yieldRenderRows sorts the trajectories by name and renders one row per
// trajectory: its per-kind total cost and its yield (null when no cost
// was recorded).
func (y *yieldReport) yieldRenderRows() ([]validation.Value, float64) {
	names := make([]string, 0, len(y.byTraj))
	for _, kv := range y.byTraj {
		names = append(names, kv.K)
	}
	sort.Strings(names)
	rows := []validation.Value{}
	totalCost := 0.0
	for _, traj := range names {
		d := *y.yieldRow(traj)
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
	return rows, totalCost
}

// yieldRenderTotals assembles the campaign-level totals block and the
// report's outer object.
func (y *yieldReport) yieldRenderTotals(rows []validation.Value,
	totalCost float64) validation.Value {
	var totalYield validation.Value = validation.VNull()
	if totalCost > 0 {
		totalYield = validation.VFloat(y.confirmedValue / totalCost)
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
	if y.criticConfirmed > 0 {
		perCritic = validation.VFloat(totalCost / float64(y.criticConfirmed))
	}
	if y.evidenceConfirmed > 0 {
		perEvidence = validation.VFloat(totalCost / float64(y.evidenceConfirmed))
	}
	return validation.VObj(
		validation.KV{K: "trajectories", V: validation.VArr(rows...)},
		validation.KV{K: "totals", V: validation.VObj(
			validation.KV{K: "total_cost_usd", V: totalCostV},
			validation.KV{K: "confirmed_findings",
				V: validation.VInt(y.confirmedCount)},
			validation.KV{K: "confirmed_value_usd",
				V: validation.VFloat(y.confirmedValue)},
			validation.KV{K: "yield_usd_per_usd", V: totalYield},
			validation.KV{K: "cost_per_critic_confirmed_usd",
				V: perCritic},
			validation.KV{K: "cost_per_evidence_confirmed_usd",
				V: perEvidence})},
		validation.KV{K: "note", V: validation.VStr("value = confirmed " +
			"extractable_usd (never the 1-10 risk band); costs are " +
			"operator-reported; yield is advisory and gates nothing")},
	)
}

// AllocationAdvice is allocation_advice: rank trajectories by observed yield
// (highest first; no-cost rows last). Pure advice for the planner.
func AllocationAdvice(c *state.Campaign) ([]validation.Value, error) {
	rep, err := YieldReport(c)
	if err != nil {
		return nil, err
	}
	rows := append([]validation.Value{}, validation.ObjAt(rep, "trajectories").A...)
	sort.SliceStable(rows, func(i, j int) bool {
		yi, yj := validation.ObjAt(rows[i], "yield_usd_per_usd"), validation.ObjAt(rows[j], "yield_usd_per_usd")
		ni, nj := yi.Kind == validation.Null, yj.Kind == validation.Null
		if ni != nj {
			return !ni
		}
		return -floatField(rows[i], "yield_usd_per_usd") <
			-floatField(rows[j], "yield_usd_per_usd")
	})
	advice := []validation.Value{}
	for i, r := range rows {
		y := validation.ObjAt(r, "yield_usd_per_usd")
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
			validation.KV{K: "trajectory", V: validation.ObjAt(r, "trajectory")},
			validation.KV{K: "yield_usd_per_usd", V: yv},
			validation.KV{K: "yield", V: validation.VStr(ys)},
			validation.KV{K: "advice", V: validation.VStr(verdict)},
		))
	}
	return advice, nil
}
