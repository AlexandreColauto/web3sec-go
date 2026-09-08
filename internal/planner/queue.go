package planner

import (
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// DecisionRule is decision_rule: high prior + cheap validation = investigate
// now. High prior + expensive validation + weak reachability = deprioritize.
// Returns the queue slot class: 'now' | 'next' | 'batch' | 'park'. The
// reachability tail is Python's `reachability="unknown"` default.
func DecisionRule(prior float64, cost string, reachability ...string) string {
	reach := "unknown"
	if len(reachability) > 0 {
		reach = reachability[0]
	}
	if prior >= 0.75 && cost == "cheap" {
		return "now"
	}
	if prior >= 0.75 && reach == "demonstrated" {
		return "now"
	}
	if prior >= 0.6 {
		if cost != "expensive" {
			return "next"
		}
		return "batch"
	}
	if prior >= 0.4 {
		if cost == "cheap" {
			return "batch"
		}
		return "park"
	}
	return "park"
}

// PlannerHint is one learning.load_planner_hints row (kind="priority"): the
// planner only reads hint_id and content.
type PlannerHint struct {
	HintID  string
	Content string
}

// loadPlannerHintsFunc is the learning.load_planner_hints seam (learning is
// unported). Feature absent: no hints, so include_hints=True is a no-op —
// byte-identical to Python with an empty hint store.
var loadPlannerHintsFunc = func(*state.Campaign) ([]PlannerHint, error) {
	return nil, nil
}

// SetLoadPlannerHints wires learning.load_planner_hints(campaign,
// kind="priority").
func SetLoadPlannerHints(f func(*state.Campaign) ([]PlannerHint, error)) {
	if f == nil {
		panic("planner: nil planner-hint loader")
	}
	loadPlannerHintsFunc = f
}

// WorkQueue is work_queue: the ordered, bounded work list for the
// orchestrator — each priority annotated with prior risk, validation cost,
// and queue slot.
//
// includeHints folds in the reflection-derived planner hints
// (learning.planner_hint, kind='priority') — the loop closure run 1 left open:
// reflection said things, the planner never heard them. Hint rows are tagged
// `source: hint:<hint_id>` so the operator can see which queue rows came from
// the campaign's own after-action learning. The discovery COMPLETION PROOF
// calls this with the default (false): hints steer, they do not block stage
// completion.
func WorkQueue(campaign *state.Campaign, plan, model validation.Value,
	includeHints bool) ([]validation.Value, error) {
	out := []validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		if st := objStr(p, "status"); st == "answered" || st == "deprioritized" {
			continue
		}
		cost := objStr(p, "budget_class")
		if cost == "" {
			cost = "standard"
		}
		risk := numAt(p, "risk")
		trajs := []string{}
		for _, t := range listOf(p, "trajectories") {
			trajs = append(trajs, enumTrajectory(pyStr(t)))
		}
		out = append(out, validation.VObj(
			kv("priority_id", objAt(p, "id")),
			kv("question", objAt(p, "question")),
			kv("risk", objAt(p, "risk")),
			kv("cost", validation.VStr(cost)),
			kv("slot", validation.VStr(DecisionRule(risk, cost))),
			kv("trajectories", strArr(trajs)),
			kv("components", keyOrEmpty(p, "components")),
			kv("invariant_ids", keyOrEmpty(p, "invariant_ids")),
			kv("required_context", keyOrEmpty(p, "required_context")),
		))
	}
	if includeHints {
		hints, err := loadPlannerHintsFunc(campaign)
		if err != nil {
			return nil, err
		}
		for _, h := range hints {
			out = append(out, validation.VObj(
				kv("priority_id", validation.VStr(h.HintID)),
				kv("question", validation.VStr("from reflection ("+h.HintID+
					"): "+h.Content)),
				kv("risk", validation.VFloat(0.7)),
				kv("cost", validation.VStr("standard")),
				kv("slot", validation.VStr(DecisionRule(0.7, "standard"))),
				kv("trajectories", strArr([]string{"code"})),
				kv("components", validation.VArr()),
				kv("invariant_ids", validation.VArr()),
				kv("required_context", validation.VArr()),
				kv("source", validation.VStr("hint:"+h.HintID)),
			))
		}
	}
	order := map[string]int{"now": 0, "next": 1, "batch": 2, "park": 3}
	sort.SliceStable(out, func(i, j int) bool {
		si := order[objStr(out[i], "slot")]
		sj := order[objStr(out[j], "slot")]
		if si != sj {
			return si < sj
		}
		return numAt(out[i], "risk") > numAt(out[j], "risk")
	})
	return out, nil
}

// enumTrajectory is TRAJECTORY_TO_ENUM.get(t, "code").
func enumTrajectory(t string) string {
	if e, ok := TrajectoryToEnum[t]; ok {
		return e
	}
	return "code"
}

// keyOrEmpty is `p.get(key, [])` — the default applies only when the key is
// ABSENT, so an explicit null passes through (Python does the same).
func keyOrEmpty(p validation.Value, key string) validation.Value {
	got, ok := fieldAt(p, key)
	if !ok {
		return validation.VArr()
	}
	return got
}

// numAt is a numeric field as float64 (0 when absent/non-numeric).
func numAt(v validation.Value, key string) float64 {
	got := objAt(v, key)
	switch got.Kind {
	case validation.Flt:
		return got.F
	case validation.Int:
		return float64(got.I)
	}
	return 0
}
