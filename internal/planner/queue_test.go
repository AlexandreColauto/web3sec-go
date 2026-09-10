package planner

import (
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestWorkQueueOracle pins the ordered queue for the rich plan: answered and
// deprioritized rows are dropped, slots come from decision_rule and the sort
// is (slot order, -risk).
func TestWorkQueueOracle(t *testing.T) {
	root := oracles(t)
	wq := at(t, root, "work_queue")
	camp := newCampaign(t, "wq")
	queue, err := WorkQueue(camp, objAt(wq, "plan"), objAt(wq, "model"), false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	requireJSON(t, "queue", validation.VArr(queue...), objAt(wq, "queue"))
	for _, row := range queue {
		if objStr(row, "slot") == "" {
			t.Fatalf("queue row without a slot: %v", validation.CanonCompact(row))
		}
	}
}

// TestWorkQueueHintsEmpty pins include_hints=True with an empty hint store:
// byte-identical to the default queue.
func TestWorkQueueHintsEmpty(t *testing.T) {
	root := oracles(t)
	wq := at(t, root, "work_queue")
	camp := newCampaign(t, "wqh")
	queue, err := WorkQueue(camp, objAt(wq, "plan"), objAt(wq, "model"), true)
	if err != nil {
		t.Fatalf("work_queue hints: %v", err)
	}
	requireJSON(t, "queue_hints", validation.VArr(queue...),
		objAt(wq, "queue_hints"))
	requireJSON(t, "queue_hints == queue", validation.VArr(queue...),
		objAt(wq, "queue"))
}

// TestWorkQueueHintRows pins the seam: an installed hint loader contributes
// tagged rows with the documented risk/cost/slot and no components.
func TestWorkQueueHintRows(t *testing.T) {
	camp := newCampaign(t, "wqh2")
	prev := loadPlannerHintsFunc
	SetLoadPlannerHints(func(*state.Campaign) ([]PlannerHint, error) {
		return []PlannerHint{{HintID: "H-01", Content: "check the cursor"}}, nil
	})
	t.Cleanup(func() { SetLoadPlannerHints(prev) })
	plan := jsonValue(t, `{"priorities":[{"id":"Q-001","question":"q","risk":0.2,
		"trajectories":["A-code"],"status":"open"}]}`)
	queue, err := WorkQueue(camp, plan, validation.VObj(), true)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	if len(queue) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(queue))
	}
	hint := queue[0]
	requireJSON(t, "hint id", objAt(hint, "priority_id"), validation.VStr("H-01"))
	requireJSON(t, "hint source", objAt(hint, "source"),
		validation.VStr("hint:H-01"))
	requireJSON(t, "hint slot", objAt(hint, "slot"), validation.VStr("next"))
	requireJSON(t, "hint components", objAt(hint, "components"),
		validation.VArr())
}

// TestWorkQueueRankingOracle pins the queue for the structural ranking model.
func TestWorkQueueRankingOracle(t *testing.T) {
	root := oracles(t)
	wq := at(t, root, "work_queue")
	model, err := validation.ReadJson("testdata/ranking_model.json")
	if err != nil {
		t.Fatalf("read ranking model: %v", err)
	}
	camp := newCampaign(t, "wqr")
	queue, err := WorkQueue(camp, at(t, root, "default_plan", "ranking"), model,
		false)
	if err != nil {
		t.Fatalf("work_queue ranking: %v", err)
	}
	requireJSON(t, "ranking queue", validation.VArr(queue...),
		objAt(wq, "ranking_queue"))
}

// TestWorkQueueSkipsTerminalStatuses pins the status filter and the stability
// of the sort for equal (slot, risk) rows.
func TestWorkQueueSkipsTerminalStatuses(t *testing.T) {
	camp := newCampaign(t, "wqs")
	plan := jsonValue(t, `{"priorities":[
		{"id":"Q-001","question":"a","risk":0.9,"trajectories":["A-code"],
		 "status":"answered","budget_class":"cheap"},
		{"id":"Q-002","question":"b","risk":0.9,"trajectories":["A-code"],
		 "status":"deprioritized","budget_class":"cheap"},
		{"id":"Q-003","question":"c","risk":0.5,"trajectories":["B-economic"],
		 "status":"open","budget_class":"cheap"},
		{"id":"Q-004","question":"d","risk":0.5,"trajectories":["C-state-machine"],
		 "status":"open","budget_class":"cheap"}]}`)
	queue, err := WorkQueue(camp, plan, validation.VObj(), false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	if len(queue) != 2 {
		t.Fatalf("expected 2 live rows, got %d", len(queue))
	}
	requireJSON(t, "first live row", objAt(queue[0], "priority_id"),
		validation.VStr("Q-003"))
	requireJSON(t, "second live row", objAt(queue[1], "priority_id"),
		validation.VStr("Q-004"))
	requireJSON(t, "trajectory enum", objAt(queue[0], "trajectories"),
		jsonValue(t, `["economic"]`))
}

// TestWorkQueueSkipsNotApplicable pins feedback-triage A1: a priority closed
// as not-applicable (a legitimate closing disposition per planner.gates) must
// not re-enter the work queue — before the fix it re-queued forever and the
// discovery completion proof could never complete.
func TestWorkQueueSkipsNotApplicable(t *testing.T) {
	camp := newCampaign(t, "wqna")
	plan := jsonValue(t, `{"priorities":[
		{"id":"Q-001","question":"a","risk":0.9,"trajectories":["A-code"],
		 "status":"not-applicable","budget_class":"cheap"},
		{"id":"Q-002","question":"b","risk":0.4,"trajectories":["A-code"],
		 "status":"open","budget_class":"cheap"}]}`)
	queue, err := WorkQueue(camp, plan, validation.VObj(), false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	if len(queue) != 1 {
		t.Fatalf("expected 1 live row (not-applicable dropped), got %d",
			len(queue))
	}
	requireJSON(t, "live row", objAt(queue[0], "priority_id"),
		validation.VStr("Q-002"))
}
