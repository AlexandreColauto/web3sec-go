// costs_test.go ports the costs-targeted tests of tests/test_budget.py and
// tests/test_design_upgrades.py 1:1 (Python wins). The CONFIRMED-finding
// fixture is written straight to disk: yield_report reads the finding FILES,
// and the Python source's gate ceremony (evidence, critic, memory check) is
// the subject of other suites — the arithmetic pinned here is the same.
package costs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func camp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// confirmedFinding writes a CONFIRMED finding with a confirmed value.
func confirmedFinding(t *testing.T, c *state.Campaign, fid, trajectory string,
	usd float64) {
	t.Helper()
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(fid)},
		validation.KV{K: "created_at", V: validation.VStr("2026-01-01T00:00:00+00:00")},
		validation.KV{K: "status", V: validation.VStr("CONFIRMED")},
		validation.KV{K: "trajectory", V: validation.VStr(trajectory)},
		validation.KV{K: "economic_impact", V: validation.VObj(
			validation.KV{K: "extractable_usd", V: validation.VFloat(usd)})},
	)
	path := filepath.Join(c.FindingsDir, fid+".json")
	if err := validation.WriteJson(path, f, ""); err != nil {
		t.Fatal(err)
	}
}

func ptr(s string) *string { return &s }

func TestRecordCostValidatesInputs(t *testing.T) {
	c := camp(t)
	if _, err := RecordCost(c, RecordOpts{Kind: "vibes", AmountUSD: 1,
		Actor: "op"}); err == nil ||
		!strings.Contains(err.Error(), "kind") {
		t.Fatalf("bad kind: err = %v, want a 'kind' ValueError", err)
	}
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: -1,
		Actor: "op"}); err == nil ||
		!strings.Contains(err.Error(), "amount") {
		t.Fatalf("negative amount: err = %v, want an 'amount' ValueError", err)
	}
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 1,
		Actor: "  "}); err == nil || !strings.Contains(err.Error(), "actor") {
		t.Fatalf("blank actor: err = %v, want an 'actor' ValueError", err)
	}
	// nothing was written by a rejected row
	if rows, err := LoadCosts(c); err != nil || len(rows) != 0 {
		t.Fatalf("costs.jsonl rows = %d, err = %v, want 0", len(rows), err)
	}
}

func TestYieldReportAndAllocationAdvice(t *testing.T) {
	c := camp(t)
	confirmedFinding(t, c, "F-econ000001", "economic", 100_000)
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 30,
		Trajectory: ptr("economic"), Actor: "operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordCost(c, RecordOpts{Kind: "compute", AmountUSD: 10,
		Trajectory: ptr("economic"), Actor: "operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordCost(c, RecordOpts{Kind: "human-review", AmountUSD: 40,
		Trajectory: ptr("economic"), Actor: "operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 200,
		Trajectory: ptr("static"), Actor: "operator"}); err != nil {
		t.Fatal(err)
	}
	rep, err := YieldReport(c)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]validation.Value{}
	for _, r := range validation.ObjAt(rep, "trajectories").A {
		rows[validation.ObjStr(r, "trajectory")] = r
	}
	eco := rows["economic"]
	if got := floatField(eco, "total_cost_usd"); got != 80 {
		t.Errorf("economic total_cost_usd = %v, want 80", got)
	}
	if got := intField(eco, "confirmed_findings"); got != 1 {
		t.Errorf("economic confirmed_findings = %d, want 1", got)
	}
	if got := floatField(eco, "confirmed_value_usd"); got != 100_000 {
		t.Errorf("economic confirmed_value_usd = %v, want 100000", got)
	}
	if got := floatField(eco, "yield_usd_per_usd"); got != 100_000.0/80.0 {
		t.Errorf("economic yield = %v, want %v", got, 100_000.0/80.0)
	}
	st := rows["static"]
	if got := floatField(st, "confirmed_value_usd"); got != 0 {
		t.Errorf("static confirmed_value_usd = %v, want 0", got)
	}
	if got := floatField(st, "yield_usd_per_usd"); got != 0 {
		t.Errorf("static yield = %v, want 0.0", got)
	}
	if got := intField(validation.ObjAt(rep, "totals"), "confirmed_findings"); got != 1 {
		t.Errorf("totals confirmed_findings = %d, want 1", got)
	}
	advice, err := AllocationAdvice(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 2 {
		t.Fatalf("advice rows = %d, want 2", len(advice))
	}
	if got := validation.ObjStr(advice[0], "trajectory"); got != "economic" {
		t.Errorf("advice[0] = %q, want economic", got)
	}
	if got := validation.ObjStr(advice[0], "advice"); !strings.Contains(got, "more budget") {
		t.Errorf("advice[0] = %q, want the more-budget verdict", got)
	}
}

func TestZeroCostIsAReportingGapNotInfiniteYield(t *testing.T) {
	c := camp(t)
	confirmedFinding(t, c, "F-hist000001", "historical", 50_000)
	rep, err := YieldReport(c)
	if err != nil {
		t.Fatal(err)
	}
	var row validation.Value
	for _, r := range validation.ObjAt(rep, "trajectories").A {
		if validation.ObjStr(r, "trajectory") == "historical" {
			row = r
		}
	}
	if y := validation.ObjAt(row, "yield_usd_per_usd"); y.Kind != validation.Null {
		t.Fatalf("yield = %s, want null (not inf, not 0)",
			validation.DumpIndented(y))
	}
	if got := floatField(row, "confirmed_value_usd"); got != 50_000 {
		t.Errorf("confirmed_value_usd = %v, want 50000", got)
	}
}

func TestNoLimitIsExplicit(t *testing.T) {
	c := camp(t)
	st, err := BudgetStatus(c)
	if err != nil {
		t.Fatal(err)
	}
	// sum() over no trajectory rows at all is the INT 0, not 0.0.
	if spent := validation.ObjAt(st, "spent_usd"); spent.Kind != validation.Int ||
		spent.I != 0 {
		t.Errorf("spent_usd = %s, want int 0",
			validation.DumpIndented(spent))
	}
	if got := validation.ObjStr(st, "status"); got != "no-limit" {
		t.Errorf("status = %q, want no-limit", got)
	}
	if validation.ObjAt(st, "limit_usd").Kind != validation.Null {
		t.Errorf("limit_usd = %s, want null",
			validation.DumpIndented(validation.ObjAt(st, "limit_usd")))
	}
	if !strings.Contains(validation.ObjStr(st, "note"), "unbounded") {
		t.Errorf("note = %q, want unbounded", validation.ObjStr(st, "note"))
	}
}

func TestWithinAndExceeded(t *testing.T) {
	c := camp(t)
	lim := validation.VFloat(100)
	if _, err := c.SetCostCeiling(&lim, "lead"); err != nil {
		t.Fatal(err)
	}
	st, err := BudgetStatus(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(st, "status"); got != "within" {
		t.Errorf("status = %q, want within", got)
	}
	if got := floatField(st, "remaining_usd"); got != 100 {
		t.Errorf("remaining = %v, want 100", got)
	}
	// record spend past the ceiling
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 250,
		Trajectory: ptr("code"), Actor: "harness"}); err != nil {
		t.Fatal(err)
	}
	st, err = BudgetStatus(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(st, "status"); got != "exceeded" {
		t.Errorf("status = %q, want exceeded", got)
	}
	if floatField(st, "over_by_usd") <= 0 {
		t.Errorf("over_by_usd = %v, want > 0", floatField(st, "over_by_usd"))
	}
}

func TestClearCeilingReturnsToNoLimit(t *testing.T) {
	c := camp(t)
	lim := validation.VFloat(50)
	if _, err := c.SetCostCeiling(&lim, "lead"); err != nil {
		t.Fatal(err)
	}
	st, err := BudgetStatus(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(st, "status"); got != "within" {
		t.Errorf("status = %q, want within", got)
	}
	if _, err := c.SetCostCeiling(nil, "lead"); err != nil {
		t.Fatal(err)
	}
	st, err = BudgetStatus(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(st, "status"); got != "no-limit" {
		t.Errorf("status = %q, want no-limit after clearing", got)
	}
}

// TestBudgetRefusesADamagedMirror pins r15 P1-1: the enforcing gate
// read ONLY costs.jsonl while the audit read both — a ghost row halted
// pipelines on spend the tool itself called forged. Enforcement now
// refuses over the same cross-check until it is repaired.
func TestBudgetRefusesADamagedMirror(t *testing.T) {
	c := camp(t)
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 1.0,
		Actor: "op"}); err != nil {
		t.Fatal(err)
	}
	good, err := BudgetStatus(c)
	if err != nil {
		t.Fatalf("healthy mirror must price: %v", err)
	}
	_ = good
	// Ghost row through the raw file (no event):
	f := filepath.Join(c.Dir, "costs.jsonl")
	raw, _ := os.ReadFile(f)
	if err := os.WriteFile(f, append(raw, []byte(
		`{"cost_id": "COST-ghost000001", "at": "2026-01-01T00:00:00+00:00", "kind": "model", "amount_usd": 999999.0, "actor": "ghost"}`+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BudgetStatus(c); err == nil {
		t.Fatal("budget priced a forged mirror")
	} else if !strings.Contains(err.Error(), "COST-ghost000001") {
		t.Fatalf("refusal must name a problem: %v", err)
	}
}

// TestCostMirrorComparesSpendNotJustIds pins r16 P1-1: the first cut
// of the mirror law matched cost_id strings only — appending a second
// row under an EXISTING id doubled booked spend ($15 -> $1,014, budget
// EXCEEDED, audit PASS), and rewriting a row's amount hid inside its
// own id. The law now compares count AND amount AND kind per id.
func TestCostMirrorComparesSpendNotJustIds(t *testing.T) {
	c := camp(t)
	id := ""
	if ev, err := RecordCost(c, RecordOpts{Kind: "model",
		AmountUSD: 15.0, Actor: "op"}); err != nil {
		t.Fatal(err)
	} else {
		id = validation.ObjStr(ev, "cost_id")
	}
	f := filepath.Join(c.Dir, "costs.jsonl")
	raw, _ := os.ReadFile(f)
	// Duplicate id, inflated amount:
	if err := os.WriteFile(f, append(raw, []byte(
		`{"cost_id": "`+id+`", "at": "2026-01-01T00:00:00+00:00", "kind": "model", "amount_usd": 999.0, "actor": "op"}`+"\n")...),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BudgetStatus(c); err == nil ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicated cost row must refuse the gate: %v", err)
	}
	// Back to one row, but with the AMOUNT edited:
	if err := os.WriteFile(f, []byte(
		`{"cost_id": "`+id+`", "at": "2026-01-01T00:00:00+00:00", "kind": "model", "amount_usd": 0.01, "actor": "op"}`+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	probs := CostMirrorProblems(c)
	found := false
	for _, p := range probs {
		if strings.Contains(p, "edited in the file") &&
			strings.Contains(p, "0.01") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an amount rewrite must burn naming both numbers: %v", probs)
	}
}

// TestBudgetRefusesAnUnreadableLedger pins r17 P2#4: the mirror helper
// once returned "no problems" when the ledger could not be read at all,
// so `budget` priced spend off costs.jsonl alone while verify screamed.
func TestBudgetRefusesAnUnreadableLedger(t *testing.T) {
	c := camp(t)
	if _, err := RecordCost(c, RecordOpts{Kind: "model",
		AmountUSD: 42.0, Actor: "op"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "events.jsonl"),
		[]byte("GARBAGE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BudgetStatus(c); err == nil ||
		!strings.Contains(err.Error(), "cannot be cross-checked") {
		t.Fatalf("spend over an unreadable ledger must refuse: %v", err)
	}
}
