// task12_queue_scoring_test.go — plan §Task 12 (2026-09-17-trust-boundary-
// hardening.md): cockpit priority is risk × untouched, not alphabetical.
//
// Law: the ordering weight inside a slot is ADDITIVE —
//
//	Score = (untouchedCount * W1) + (severityScore * W2) + (openQuestionCount * W3)
//
// named constants, ties broken alphabetically, NEVER multiplicative: a product
// zeroes out a critical consensus contract that happens to carry no open
// question and drops it below alphabetical entries.
package planner

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// task12Model is the scoring fixture: Alpha and Zeta are covered (the ledger
// says so), Rollup and Aardvark are untouched. INV-001 is critical and applies
// to Rollup and Zeta.
const task12Model = `{
 "contracts": [
  {"name": "Aardvark", "path": "src/Aardvark.sol", "in_scope": true},
  {"name": "Alpha", "path": "src/Alpha.sol", "in_scope": true},
  {"name": "Rollup", "path": "src/Rollup.sol", "in_scope": true},
  {"name": "Zeta", "path": "src/Zeta.sol", "in_scope": true}
 ],
 "invariants": [
  {"id": "INV-001", "statement": "only the sequencer may propose a root",
   "applies_to": ["Rollup", "Zeta"], "severity_if_broken": "critical"}
 ]
}`

// task12Coverage marks Aardvark and Zeta as swept — the touched pair. Alpha
// and Rollup have no row, so they are untouched.
const task12Coverage = `{
 "campaign_id": "C-task12",
 "snapshot_id": "unpinned",
 "updated_at": "2026-09-17T00:00:00Z",
 "contracts": [
  {"path": "src/Aardvark.sol", "status": "swept",
   "trajectory_counts": {"code": 1}},
  {"path": "src/Zeta.sol", "status": "swept",
   "trajectory_counts": {"code": 1}}
 ],
 "surfaces": {}, "funnel": {}, "gaps": [], "summary": {}
}`

// task12Campaign is a campaign carrying the coverage ledger above.
func task12Campaign(t *testing.T) *state.Campaign {
	t.Helper()
	camp := newCampaign(t, "wqscore")
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"coverage.json"), jsonValue(t, task12Coverage), ""); err != nil {
		t.Fatalf("write coverage: %v", err)
	}
	return camp
}

// task12IDs is the queue's priority_id order.
func task12IDs(queue []validation.Value) []string {
	out := make([]string, 0, len(queue))
	for _, row := range queue {
		out = append(out, objStr(row, "priority_id"))
	}
	return out
}

// TestQueueAdditiveRiskOrdering is the Task 12 witness: the alphabetically
// first untouched low-risk file loses to the consensus-critical contract, and
// the order is identical across runs.
func TestQueueAdditiveRiskOrdering(t *testing.T) {
	camp := task12Campaign(t)
	plan := jsonValue(t, `{"priorities":[
	 {"id":"Q-001","question":"sweep the peripheral Alpha contract for drift",
	  "risk":0.6,"components":["Alpha"],"trajectories":["code"],
	  "status":"open","budget_class":"cheap"},
	 {"id":"Q-002","question":"test the critical Rollup invariant end to end",
	  "risk":0.6,"components":["Rollup"],"invariant_ids":["INV-001"],
	  "trajectories":["code"],"status":"open","budget_class":"cheap"}]}`)
	model := jsonValue(t, task12Model)
	queue, err := WorkQueue(camp, plan, model, false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	got := task12IDs(queue)
	if len(got) != 2 || got[0] != "Q-002" {
		t.Fatalf("queue order = %v, want Q-002 (consensus-critical, "+
			"untouched) first: %s", got,
			validation.CanonCompact(validation.VArr(queue...)))
	}
	// deterministic across runs (no map-order leak into the comparator)
	for i := 0; i < 25; i++ {
		again, err := WorkQueue(camp, plan, model, false)
		if err != nil {
			t.Fatalf("work_queue run %d: %v", i, err)
		}
		if now := task12IDs(again); strings.Join(now, ",") != strings.Join(got, ",") {
			t.Fatalf("run %d order = %v, want %v", i, now, got)
		}
	}
}

// TestQueueScoreIsAdditiveNotMultiplicative pins the law's rationale: a
// critical contract that is already covered carries zero untouched count and
// zero open questions, so a MULTIPLICATIVE score would zero it out and drop it
// below an alphabetical zero-signal entry. Additive keeps its severity.
func TestQueueScoreIsAdditiveNotMultiplicative(t *testing.T) {
	camp := task12Campaign(t)
	plan := jsonValue(t, `{"priorities":[
	 {"id":"Q-001","question":"re-sweep the covered Aardvark contract for drift",
	  "risk":0.6,"components":["Aardvark"],"trajectories":["code"],
	  "status":"open","budget_class":"cheap"},
	 {"id":"Q-002","question":"re-test the covered Zeta critical invariant",
	  "risk":0.6,"components":["Zeta"],"invariant_ids":["INV-001"],
	  "trajectories":["code"],"status":"open","budget_class":"cheap"}]}`)
	model := jsonValue(t, task12Model)
	queue, err := WorkQueue(camp, plan, model, false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	if got := task12IDs(queue); len(got) != 2 || got[0] != "Q-002" {
		t.Fatalf("queue order = %v — a zero-untouched, zero-question "+
			"critical contract must still outrank a zero-signal one "+
			"(additive, never multiplicative)", got)
	}
}
