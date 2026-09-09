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

// costIDSource mints the cost_id. Python uses a RAW uuid4 (uuid.uuid4().hex
// [:12]), not state.new_id, so the WEBV2_UUID pin does not reach it; the
// cross-twin probe installs a deterministic minter through SetCostIDSource.
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
	// The JSONL split policy: costs.jsonl is written with bare json.dumps
	// (ensure_ascii=True), unlike every other JSONL in the tree.
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
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v, err := validation.ParseOrdered([]byte(line))
		if err != nil {
			return nil, err
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
	return validation.VObj(
		validation.KV{K: "trajectories", V: validation.VArr(rows...)},
		validation.KV{K: "totals", V: validation.VObj(
			validation.KV{K: "total_cost_usd", V: totalCostV},
			validation.KV{K: "confirmed_findings",
				V: validation.VInt(confirmedCount)},
			validation.KV{K: "confirmed_value_usd",
				V: validation.VFloat(confirmedValue)},
			validation.KV{K: "yield_usd_per_usd", V: totalYield})},
		validation.KV{K: "note", V: validation.VStr("value = confirmed " +
			"extractable_usd (never the 1-10 risk band); costs are " +
			"operator-reported; yield is advisory and gates nothing")},
	), nil
}

// BudgetStatus is budget_status: cost position against the operator-set
// ceiling (budget.max_total_cost_usd). The ceiling is a DECISION surface,
// not a meter.
func BudgetStatus(c *state.Campaign) (validation.Value, error) {
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
