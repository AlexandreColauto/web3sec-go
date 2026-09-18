// task12_orchestrator_test.go — the Task 12 acceptance test through the real
// Plan verb: the returned work_queue must order the consensus-critical
// contract above the alphabetically-first untouched low-risk one.
//
// The fixture is an operator-authored plan (so the plan is the contract and
// Plan writes it), plus the model the score reads.
package orchestrator

import (
	"path/filepath"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// task12Plan is the two-row plan: Q-001 names the alphabetically first file
// (Alpha, untouched, no invariant), Q-002 names the consensus-critical one
// (Rollup, untouched, critical invariant).
const task12Plan = `{
 "campaign_id": "C-task12",
 "created_at": "2026-09-17T00:00:00Z",
 "priorities": [
  {"id": "Q-001", "question": "sweep the peripheral Alpha contract for drift",
   "risk": 0.6, "components": ["Alpha"], "trajectories": ["code"],
   "status": "open", "budget_class": "cheap"},
  {"id": "Q-002", "question": "test the critical Rollup invariant end to end",
   "risk": 0.6, "components": ["Rollup"], "invariant_ids": ["INV-001"],
   "trajectories": ["code"], "status": "open", "budget_class": "cheap"}
 ]
}`

// task12Model is the scoring model: Rollup carries the critical invariant.
const task12Model = `{
 "protocol_id": "task12",
 "name": "Task 12",
 "snapshot_id": "unpinned",
 "contracts": [
  {"name": "Alpha", "path": "src/Alpha.sol", "in_scope": true},
  {"name": "Rollup", "path": "src/Rollup.sol", "in_scope": true}
 ],
 "invariants": [
  {"id": "INV-001", "statement": "only the sequencer may propose a root",
   "applies_to": ["Rollup"], "severity_if_broken": "critical"}
 ]
}`

// TestPlanQueueOrdersByAdditiveRisk pins the operator-visible ordering: the
// consensus-critical untouched contract leads, deterministically. The model is
// the campaign's own artifact (the shape every real campaign has), so the
// write path and the read-back path score against the same signals.
func TestPlanQueueOrdersByAdditiveRisk(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Task 12 Program", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), portJSON(t, task12Model), ""); err != nil {
		t.Fatalf("write model: %v", err)
	}
	o := New(c)
	planned, err := o.Plan(portJSON(t, task12Plan), validation.VNull(), false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	queue := listAt(planned, "work_queue")
	if len(queue) < 2 {
		t.Fatalf("queue too short: %s",
			validation.CanonCompact(validation.VArr(queue...)))
	}
	if got := strAt(queue[0], "priority_id"); got != "Q-002" {
		t.Fatalf("first queue row = %s, want Q-002 (consensus-critical, "+
			"untouched): %s", got,
			validation.CanonCompact(validation.VArr(queue...)))
	}
	// deterministic: a second read of the same plan on disk agrees
	again, err := o.Plan(validation.VNull(), validation.VNull(), false)
	if err != nil {
		t.Fatalf("plan read-only: %v", err)
	}
	againQueue := listAt(again, "work_queue")
	if len(againQueue) != len(queue) {
		t.Fatalf("queue length drifted: %d vs %d", len(againQueue), len(queue))
	}
	for i := range queue {
		if a, b := validation.CanonCompact(queue[i]),
			validation.CanonCompact(againQueue[i]); a != b {
			t.Fatalf("queue row %d drifted: %s vs %s", i, a, b)
		}
	}
}
