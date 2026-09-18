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

// task12OpenQModel is the F5 fixture (critic round 1): ONE unresolved open
// question whose `blocks` list names TWO components of the same row (Rollup and
// Zeta, both in scope; the coverage ledger above marks Zeta swept and Rollup
// untouched).
const task12OpenQModel = `{
 "contracts": [
  {"name": "Aardvark", "path": "src/Aardvark.sol", "in_scope": true},
  {"name": "Alpha", "path": "src/Alpha.sol", "in_scope": true},
  {"name": "Rollup", "path": "src/Rollup.sol", "in_scope": true},
  {"name": "Zeta", "path": "src/Zeta.sol", "in_scope": true}
 ],
 "invariants": [
  {"id": "INV-001", "statement": "only the sequencer may propose a root",
   "applies_to": ["Rollup", "Zeta"], "severity_if_broken": "critical"}
 ],
 "open_questions": [
  {"question": "does the rollup root follow the sequencer?",
   "blocks": ["Rollup", "Zeta"]}
 ]
}`

// TestQueueOpenQuestionCountedOncePerRow is the F5 witness: `openQuestionCount`
// is DISTINCT QUESTIONS PER ROW, not (question, component) pairs. One question
// naming two components of the same row contributes W3 once — the same as one
// question naming one component — so a row cannot buy rank by how many of its
// components a single question happens to name. Direction, documented: the
// count-once rule can only LOWER a row's weight relative to summing per
// component, so no row is ever promoted by it; that is the conservative
// direction for a cockpit that must not inflate a duplicated signal.
func TestQueueOpenQuestionCountedOncePerRow(t *testing.T) {
	camp := task12Campaign(t)
	model := jsonValue(t, task12OpenQModel)
	sig, err := buildQueueSignals(camp, model)
	if err != nil {
		t.Fatalf("buildQueueSignals: %v", err)
	}
	two := jsonValue(t, `{"priority_id":"Q-002","question":"two-component spelling",
	 "components":["Rollup","Zeta"],"invariant_ids":[]}`)
	if got := sig.scoreRow(two).openQ; got != 1 {
		t.Fatalf("one question naming TWO components of one row scored "+
			"openQ=%d, want 1 (counted once per row)", got)
	}
	one := jsonValue(t, `{"priority_id":"Q-001","question":"one-component spelling",
	 "components":["Rollup"],"invariant_ids":[]}`)
	if got := sig.scoreRow(one).openQ; got != 1 {
		t.Fatalf("one question naming ONE component scored openQ=%d, want 1", got)
	}
	// The other two score parts are untouched by the count-once rule.
	if got := sig.scoreRow(two); got.untouched != 1 || got.severity != 3 {
		t.Fatalf("two-component row = %+v, want untouched=1 severity=3", got)
	}
	if a, b := sig.scoreRow(one).weight(), sig.scoreRow(two).weight(); a != b {
		t.Fatalf("weights differ (%v vs %v) — one question must not weigh "+
			"more for naming two components of the same row", a, b)
	}
}

// TestQueueMultiComponentQuestionDoesNotInflateRank drives the same fixture
// through the real WorkQueue: two rows with identical untouched/severity
// signals, one spelled with a single component and one with two components the
// single question names. Before the F5 fix the two-component row collected W3
// twice and led; now the rows tie and fall back to alphabetical order.
func TestQueueMultiComponentQuestionDoesNotInflateRank(t *testing.T) {
	camp := task12Campaign(t)
	model := jsonValue(t, task12OpenQModel)
	plan := jsonValue(t, `{"priorities":[
	 {"id":"Q-001","question":"the one-component spelling","risk":0.6,
	  "components":["Rollup"],"trajectories":["code"],
	  "status":"open","budget_class":"cheap"},
	 {"id":"Q-002","question":"the two-component spelling","risk":0.6,
	  "components":["Rollup","Zeta"],"trajectories":["code"],
	  "status":"open","budget_class":"cheap"}]}`)
	queue, err := WorkQueue(camp, plan, model, false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	got := task12IDs(queue)
	if len(got) != 2 || got[0] != "Q-001" {
		t.Fatalf("queue order = %v — a row whose single open question names "+
			"two components must not outrank the one-component spelling of "+
			"the same question (counted once per row)", got)
	}
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
