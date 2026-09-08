package state

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestPhaseTransitionsRecorded: history entries, no-op on same phase,
// unknown phase rejected with the exact message.
func TestPhaseTransitionsRecorded(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	if err := c.SetPhase("SNAPSHOT", "test"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPhase("STRUCTURAL_INDEX", "test"); err != nil {
		t.Fatal(err)
	}
	st, _ := c.State()
	if got := objStr(st, "phase"); got != "STRUCTURAL_INDEX" {
		t.Errorf("phase: %q", got)
	}
	hist := objVal(st, "phase_history")
	var tos []string
	for _, h := range hist.A {
		tos = append(tos, objStr(h, "to"))
	}
	if len(tos) != 2 || tos[0] != "SNAPSHOT" || tos[1] != "STRUCTURAL_INDEX" {
		t.Errorf("history to: %v", tos)
	}
	// history entry key order
	h0 := hist.A[0]
	var keys []string
	for _, kv := range h0.O {
		keys = append(keys, kv.K)
	}
	want := []string{"at", "from", "to", "reason"}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("history key %d: %q want %q", i, keys[i], want[i])
		}
	}
	if err := c.SetPhase("NOT_A_PHASE", "x"); err == nil {
		t.Fatal("unknown phase must error")
	} else if err.Error() != "unknown phase 'NOT_A_PHASE'" {
		t.Errorf("unknown phase message: %q", err.Error())
	}
	// same phase is a no-op
	if err := c.SetPhase("STRUCTURAL_INDEX", "again"); err != nil {
		t.Fatal(err)
	}
	st, _ = c.State()
	if v := objVal(st, "phase_history"); len(v.A) != 2 {
		t.Errorf("no-op added history: %d", len(v.A))
	}
}

// TestPhaseTransitionEvent: the log carries phase.transition with the
// exact ref/data.
func TestPhaseTransitionEvent(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	if err := c.SetPhase("SNAPSHOT", "because"); err != nil {
		t.Fatal(err)
	}
	events, _ := c.Events()
	last := events[len(events)-1]
	if got := objStr(last, "type"); got != "phase.transition" {
		t.Errorf("type: %q", got)
	}
	if got := objStr(last, "ref"); got != "SNAPSHOT" {
		t.Errorf("ref: %q", got)
	}
	data := objVal(last, "data")
	if got := objStr(data, "from"); got != "SCOPE" {
		t.Errorf("data.from: %q", got)
	}
	if got := objStr(data, "reason"); got != "because" {
		t.Errorf("data.reason: %q", got)
	}
}

// TestHalt: halt_reason set + phase HALTED with a history entry.
func TestHalt(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	if err := c.Halt("budget exhausted"); err != nil {
		t.Fatal(err)
	}
	st, _ := c.State()
	if got := objStr(st, "halt_reason"); got != "budget exhausted" {
		t.Errorf("halt_reason: %q", got)
	}
	if got := objStr(st, "phase"); got != "HALTED" {
		t.Errorf("phase: %q", got)
	}
	hist := objVal(st, "phase_history")
	last := hist.A[len(hist.A)-1]
	if got := objStr(last, "to"); got != "HALTED" {
		t.Errorf("history to: %q", got)
	}
}

// TestComplete: validation, projection fields, event, phase transition.
func TestComplete(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})

	if _, err := c.Complete("  ", "long enough reason"); err == nil {
		t.Fatal("empty actor must error")
	} else if err.Error() != "complete requires a named actor" {
		t.Errorf("actor message: %q", err.Error())
	}
	if _, err := c.Complete("op", "short"); err == nil {
		t.Fatal("short reason must error")
	} else if err.Error() != "complete requires a written reason (>= 10 chars): what was closed and why the pass is done" {
		t.Errorf("reason message: %q", err.Error())
	}

	if _, err := c.Complete("op", "  all findings reviewed and closed  "); err != nil {
		t.Fatal(err)
	}
	st, _ := c.State()
	if got := objStr(st, "completed_by"); got != "op" {
		t.Errorf("completed_by: %q", got)
	}
	if got := objStr(st, "completed_reason"); got != "all findings reviewed and closed" {
		t.Errorf("completed_reason (must be stripped): %q", got)
	}
	if got := objStr(st, "phase"); got != "COMPLETE" {
		t.Errorf("phase: %q", got)
	}
	hist := objVal(st, "phase_history")
	last := hist.A[len(hist.A)-1]
	if got := objStr(last, "reason"); got != "op: all findings reviewed and closed" {
		t.Errorf("history reason: %q", got)
	}
	// last event is the phase.transition to COMPLETE; the decision
	// event (campaign.completed) is the one before it
	events, _ := c.Events()
	ev := events[len(events)-2]
	if got := objStr(ev, "type"); got != "campaign.completed" {
		t.Errorf("event type: %q", got)
	}
	if got := objStr(ev, "ref"); got != c.CampaignID {
		t.Errorf("event ref: %q", got)
	}
	data := objVal(ev, "data")
	if got := objStr(data, "actor"); got != "op" {
		t.Errorf("data.actor: %q", got)
	}
	// completed_* keys appended after floor_policy (insertion order)
	var keyOrder []string
	for _, kv := range st.O {
		keyOrder = append(keyOrder, kv.K)
	}
	fi, ci := -1, -1
	for i, k := range keyOrder {
		if k == "floor_policy" {
			fi = i
		}
		if k == "completed_by" {
			ci = i
		}
	}
	if fi < 0 || ci <= fi {
		t.Errorf("completed_by must follow floor_policy: %v", keyOrder)
	}
}

// TestBudgetConsumption: consume increments; setDiscoveryBudget
// validates and logs; setCostCeiling sets/clears and logs.
func TestBudgetConsumption(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	b, _ := c.Budget()
	if v := objVal(b, "discovery_findings_so_far"); v.Kind != validation.Int || v.I != 0 {
		t.Errorf("initial: %+v", v)
	}
	if err := c.ConsumeDiscoverySlot(); err != nil {
		t.Fatal(err)
	}
	b, _ = c.Budget()
	if v := objVal(b, "discovery_findings_so_far"); v.I != 1 {
		t.Errorf("after consume: %+v", v)
	}

	if _, err := c.SetDiscoveryBudget(400, "op"); err != nil {
		t.Fatal(err)
	}
	b, _ = c.Budget()
	if v := objVal(b, "max_discovery_findings"); v.I != 400 {
		t.Errorf("discovery: %+v", v)
	}
	if _, err := c.SetDiscoveryBudget(0, "op"); err == nil {
		t.Fatal("zero must error")
	} else if err.Error() != "max_discovery_findings must be a positive integer" {
		t.Errorf("message: %q", err.Error())
	}
	if _, err := c.SetDiscoveryBudget(-3, "op"); err == nil {
		t.Fatal("negative must error")
	}

	// budget.discovery_set event with old/new/actor
	// the state mirror preserves the data insertion order (the log
	// line is sorted by design)
	st, _ := c.State()
	var found bool
	for _, e := range objVal(st, "events").A {
		if objStr(e, "type") == "budget.discovery_set" {
			found = true
			d := objVal(e, "data")
			var dk []string
			for _, kv := range d.O {
				dk = append(dk, kv.K)
			}
			if len(dk) != 3 || dk[0] != "old" || dk[1] != "new" || dk[2] != "actor" {
				t.Errorf("data key order: %v", dk)
			}
			if v := objVal(d, "old"); v.I != 400 {
				t.Errorf("old: %+v", v)
			}
			if v := objVal(d, "new"); v.I != 400 {
				t.Errorf("new: %+v", v)
			}
			if got := objStr(d, "actor"); got != "op" {
				t.Errorf("actor: %q", got)
			}
		}
	}
	if !found {
		t.Error("budget.discovery_set event missing")
	}

	// cost ceiling: set then clear
	ceil := validation.VFloat(100.0)
	if _, err := c.SetCostCeiling(&ceil, "op"); err != nil {
		t.Fatal(err)
	}
	b, _ = c.Budget()
	if v := objVal(b, "max_total_cost_usd"); v.Kind != validation.Flt || v.F != 100.0 {
		t.Errorf("ceiling: %+v", v)
	}
	// appended after discovery_findings_so_far
	var bk []string
	for _, kv := range b.O {
		bk = append(bk, kv.K)
	}
	if len(bk) != 7 || bk[6] != "max_total_cost_usd" {
		t.Errorf("budget key order: %v", bk)
	}
	if _, err := c.SetCostCeiling(nil, "op"); err != nil {
		t.Fatal(err)
	}
	b, _ = c.Budget()
	if v := objVal(b, "max_total_cost_usd"); v.Kind != validation.Null {
		t.Errorf("cleared: %+v", v)
	}
	events, _ := c.Events()
	last := events[len(events)-1]
	if objStr(last, "type") != "budget.limit_set" {
		t.Errorf("event: %q", objStr(last, "type"))
	}
	d := objVal(last, "data")
	if v := objVal(d, "new"); v.Kind != validation.Null {
		t.Errorf("new (clear): %+v", v)
	}
	if v := objVal(d, "old"); v.Kind != validation.Flt || v.F != 100.0 {
		t.Errorf("old: %+v", v)
	}
}

// TestPhasesConstant: the 19 phase names in exact order.
func TestPhasesConstant(t *testing.T) {
	want := []string{
		"SCOPE", "SNAPSHOT", "STRUCTURAL_INDEX", "PROTOCOL_INTELLIGENCE",
		"CAMPAIGN_PLANNING", "DISCOVERY", "CANDIDATE_INTEL", "HOSTILE_REVIEW",
		"REPRODUCTION", "CHAINING", "MAXIMAL_EXPLOITATION",
		"INDEPENDENT_VERIFICATION", "RISK_CALIBRATION", "MAINNET_FORK_POC",
		"BOUNTY_GATE", "REPORTING", "LEARNING", "HALTED", "COMPLETE",
	}
	if len(Phases) != len(want) {
		t.Fatalf("phase count: %d", len(Phases))
	}
	for i := range want {
		if Phases[i] != want[i] {
			t.Errorf("phase %d: %q want %q", i, Phases[i], want[i])
		}
	}
	if !strings.Contains(strings.Join(Phases, ","), "BOUNTY_GATE") {
		t.Error("sanity")
	}
}
