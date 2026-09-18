package state

// T35 testmap re-triage: 1:1 ports of the deferred test_budget.py and
// test_budget_discovery.py rows whose production behavior lives in
// internal/state (set_discovery_budget / set_cost_ceiling). The CLI half of
// those files is pinned by internal/cli/cmd_budget_test.go.

import (
	"testing"

	"websec/internal/validation"
)

// TestSetDiscoveryBudgetUpdatesAndLogs ports
// test_set_discovery_budget_updates_and_logs: the new ceiling lands in the
// budget block and one budget.discovery_set event carries old/new/actor.
func TestSetDiscoveryBudgetUpdatesAndLogs(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "bud", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetDiscoveryBudget(800, "op"); err != nil {
		t.Fatal(err)
	}
	b, err := c.Budget()
	if err != nil {
		t.Fatal(err)
	}
	if got := objVal(b, "max_discovery_findings"); got.Kind != validation.Int ||
		got.I != 800 {
		t.Fatalf("max_discovery_findings = %+v, want 800", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, e := range events {
		if validation.ObjStr(e, "type") != "budget.discovery_set" {
			continue
		}
		found++
		d := objVal(e, "data")
		old, new_, actor := objVal(d, "old"), objVal(d, "new"),
			objVal(d, "actor")
		if old.Kind != validation.Int || old.I != 400 {
			t.Errorf("old = %+v, want 400", old)
		}
		if new_.Kind != validation.Int || new_.I != 800 {
			t.Errorf("new = %+v, want 800", new_)
		}
		if actor.Kind != validation.Str || actor.S != "op" {
			t.Errorf("actor = %+v, want op", actor)
		}
		if got := keyNames(d); len(got) != 3 {
			t.Errorf("data keys = %v, want exactly old/new/actor", got)
		}
	}
	if found != 1 {
		t.Fatalf("budget.discovery_set events = %d, want 1", found)
	}
}

// TestSetDiscoveryBudgetRejectsNonpositive ports
// test_set_discovery_budget_rejects_nonpositive. Python also probes True
// (a bool is an int there); Go's int64 cannot be a bool, the < 1 guard is
// the exact analogue.
func TestSetDiscoveryBudgetRejectsNonpositive(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "bud2", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int64{0, -1} {
		_, err := c.SetDiscoveryBudget(bad, "op")
		if err == nil {
			t.Fatalf("SetDiscoveryBudget(%d) must error", bad)
		}
		if err.Error() != "max_discovery_findings must be a positive integer" {
			t.Errorf("message = %q", err.Error())
		}
	}
	b, err := c.Budget()
	if err != nil {
		t.Fatal(err)
	}
	if got := objVal(b, "max_discovery_findings"); got.I != 400 {
		t.Errorf("budget changed on rejection: %+v", got)
	}
	events, _ := c.Events()
	for _, e := range events {
		if validation.ObjStr(e, "type") == "budget.discovery_set" {
			t.Error("rejected set must not log")
		}
	}
}

// TestCeilingChangeIsLogged ports test_ceiling_change_is_logged: every
// ceiling change is its own actor-attributed budget.limit_set event.
func TestCeilingChangeIsLogged(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "ceil", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []float64{500.0, 300.0} {
		val := validation.VFloat(v)
		if _, err := c.SetCostCeiling(&val, "lead"); err != nil {
			t.Fatal(err)
		}
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var got []validation.Value
	for _, e := range events {
		if validation.ObjStr(e, "type") == "budget.limit_set" {
			got = append(got, objVal(e, "data"))
		}
	}
	if len(got) != 2 {
		t.Fatalf("budget.limit_set events = %d, want 2", len(got))
	}
	if v := objVal(got[0], "new"); v.Kind != validation.Flt || v.F != 500.0 {
		t.Errorf("event0 new = %+v, want 500.0", v)
	}
	if v := objVal(got[1], "old"); v.Kind != validation.Flt || v.F != 500.0 {
		t.Errorf("event1 old = %+v, want 500.0", v)
	}
	if v := objVal(got[1], "new"); v.Kind != validation.Flt || v.F != 300.0 {
		t.Errorf("event1 new = %+v, want 300.0", v)
	}
}

// TestStateSchemaAcceptsCeiling ports test_state_schema_accepts_ceiling:
// the ceiling is a real state field, not a side file.
func TestStateSchemaAcceptsCeiling(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "ceil2", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	val := validation.VFloat(123.45)
	if _, err := c.SetCostCeiling(&val, "op"); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	got := objVal(objVal(st, "budget"), "max_total_cost_usd")
	if got.Kind != validation.Flt || got.F != 123.45 {
		t.Fatalf("budget.max_total_cost_usd = %+v, want 123.45", got)
	}
}
