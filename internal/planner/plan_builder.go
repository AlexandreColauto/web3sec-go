// plan_builder.go: the `add` closure of default_plan_from_model and the
// deterministic bootstrap of a plan from the protocol model.
package planner

import (
	"websec/internal/invariants"
	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

// planBuilder is the `add` closure of default_plan_from_model: one Q-%03d
// priority per call, keys in the Python dict's order.
type planBuilder struct {
	priorities []validation.Value
	qi         int
}

// addOpts is the optional tail of add (Python: invariant_ids=None,
// stages=None, budget="standard").
type addOpts struct {
	invariantIDs []string
	stages       []string
	budget       string
}

// add builds one priority: one Q-%03d row per call, keys in the Python dict's
// order. src is the source row the question was derived from (validation.VNull
// for the static/aggregate questions); when it names a CANONICAL bug_class the
// row is stamped onto the priority, so the diversity clause counts a class the
// model actually asserted. A non-canonical source class is dropped rather than
// copied — SavePlan would reject the plan the builder just produced.
func (b *planBuilder) add(src validation.Value, question string, risk float64,
	components, trajectories []string, opts addOpts) {
	b.qi++
	b.addWithID(qid(b.qi), src, question, risk, components, trajectories, opts)
}

// addWithID is add with an explicit id: the adversarial-lifecycle rows carry
// positional LC-%03d ids (their stable handle is the machine NAME), every
// other row keeps the Q-%03d stream.
func (b *planBuilder) addWithID(id string, src validation.Value, question string,
	risk float64, components, trajectories []string, opts addOpts) {
	budget := opts.budget
	if budget == "" {
		budget = "standard"
	}
	inv := opts.invariantIDs
	if inv == nil {
		inv = []string{}
	}
	stages := opts.stages
	if stages == nil {
		stages = []string{}
	}
	prio := validation.VObj(
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr(question)),
		kv("risk", validation.VFloat(risk)),
		kv("components", validation.StrArr(components)),
		kv("invariant_ids", validation.StrArr(inv)),
		kv("required_context", validation.StrArr([]string{"structural_index",
			"protocol_model"})),
		kv("trajectories", validation.StrArr(trajectories)),
		kv("recommended_stages", validation.StrArr(stages)),
		kv("budget_class", validation.VStr(budget)),
		kv("status", validation.VStr("open")),
	)
	if bc := validation.ObjAt(src, "bug_class"); bc.Kind == validation.Str &&
		isCanonicalClass(bc.S) {
		prio.O = validation.SetOrAppend(prio.O, "bug_class", bc)
	}
	b.priorities = append(b.priorities, prio)
}

// qid is f"Q-{n:03d}".
func qid(n int) string {
	return "Q-" + pad3(n)
}

// pad3 is f"{n:03d}".
func pad3(n int) string {
	s := itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

// DefaultPlanFromModel is default_plan_from_model: bootstrap a plan
// deterministically from the protocol model + risk heuristics. The LLM
// planner then refines priorities/questions — this exists so the pipeline
// runs even before the planner stage is executed.
func DefaultPlanFromModel(campaign *state.Campaign,
	model validation.Value) (validation.Value, error) {
	b := &planBuilder{}
	bootstrapPrivileged(b, campaign, model)
	uncovered, err := invariants.UncoveredCritical(campaign, model)
	if err != nil {
		return validation.VNull(), err
	}
	bootstrapUncovered(b, uncovered)
	b.add(validation.VNull(), "Which known exploit patterns apply to this "+
		"protocol's design (history mining)?", 0.6, []string{},
		[]string{"historical"}, addOpts{budget: "cheap"})
	risky := protocolgraph.ExternalAssets(model)
	if len(risky) > 0 {
		bootstrapRisky(b, risky)
	}
	bootstrapRoles(b, model)
	// Task 10: the model's OWN open questions compile into the queue. Last,
	// so every pre-existing question keeps its Q-number byte-for-byte.
	bootstrapOpenQuestions(b, model)
	// Task 2 (defect 4): the model's own adversarial lifecycle machines mint
	// into the same queue, through the same scoring path. Last again, so every
	// pre-existing question keeps its Q-number byte-for-byte.
	if err := bootstrapLifecycleSurfaces(b, campaign, model); err != nil {
		return validation.VNull(), err
	}
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(campaign.CampaignID)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("snapshot_id", validation.VStr(snapshotIDOrUnpinned(campaign))),
		kv("strategy_note", validation.VStr("bootstrapped deterministically "+
			"from protocol model; refine via the planner stage")),
		kv("priorities", validation.VArr(b.priorities...)),
		kv("trajectory_matrix", validation.VObj(TrajectoryContracts...)),
		kv("coverage_targets", coverageTargets(model)),
	)
	_, plan = SeedLenses(plan, model)
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}
