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
	"slices"
	"strconv"
	"strings"
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
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: crypto/rand failure is unrecoverable, there is no caller to return to
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
	if !slices.Contains(CostKinds, opts.Kind) {
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
	// r38 P2-2: the unit is only atomic if a REFUSED c.Log restores the
	// row — the pre-r38 code appended first and returned the log error
	// with the row still on disk, so a truncated ledger (mirror longer
	// than the log) left a ghost row that CostMirrorProblems red-lines
	// forever, the budget refuses to price the campaign, doctor heals the
	// mirror but cannot delete a cost row, and the retry appended a
	// SECOND row. state.AppendJsonlAsciiThenLog is the shared r36
	// unwind-on-refusal dance (one implementation, used by learning and
	// the waiver pair too): snapshot -> append -> log -> restore the
	// exact pre-write bytes on refusal.
	ref := validation.ObjStr(entry, "cost_id")
	data := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr(opts.Kind)},
		validation.KV{K: "amount_usd", V: validation.VFloat(opts.AmountUSD)},
		validation.KV{K: "trajectory", V: optStr(opts.Trajectory)},
		validation.KV{K: "actor", V: validation.VStr(opts.Actor)},
	)
	if err := state.AppendJsonlAsciiThenLog(c, costsPath(c),
		validation.DumpsOrdered(entry, true), func() error {
			_, lerr := c.Log("cost.recorded", &ref, &data)
			return lerr
		}); err != nil {
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
		if state.BlankLine(line) {
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

// listOf is plan.get(key, []) for the array shapes the plan and the probe
// surface hold.
func listOf(v validation.Value, key string) []validation.Value {
	l := validation.ObjAt(v, key)
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
	limit := validation.ObjAt(budget, "max_total_cost_usd")
	rep, err := YieldReport(c)
	if err != nil {
		return validation.VNull(), err
	}
	// spent keeps yield_report's exact value (int 0 when no rows exist).
	spent := validation.ObjAt(validation.ObjAt(rep, "totals"), "total_cost_usd")
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
	remaining := lim - floatField(validation.ObjAt(rep, "totals"), "total_cost_usd")
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

// API adapts the costs module to pipeline.CostsAPI (the pipeline halts on
// the ceiling through budget_status).
type API struct{}

// BudgetStatus is costs.budget_status.
func (API) BudgetStatus(c *state.Campaign) (validation.Value, error) {
	return BudgetStatus(c)
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

// floatField is float(v.get(key, 0)) for the number shapes costs.jsonl and
// findings hold (Python's `or 0` treats null/absent as 0).
func floatField(v validation.Value, key string) float64 {
	f := validation.ObjAt(v, key)
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
	f := validation.ObjAt(v, key)
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
