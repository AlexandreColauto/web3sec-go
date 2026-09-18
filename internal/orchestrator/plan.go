// plan.go: phase 5 (CAMPAIGN_PLANNING) — the plan is the campaign's CONTRACT.
package orchestrator

import (
	"errors"
	"path/filepath"

	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/planner"
	"websec/internal/validation"
)

// classFloorOrder is CLASS_CONFIRM_FLOOR's insertion order. plan_reachability
// walks the Python dict in that order and the resulting
// classes_at_e5_plus object keeps it, so the Go map's random order cannot be
// used (a test asserts this list is exactly the map's key set).
var classFloorOrder = []string{
	"access-control", "signature-replay", "upgrade-initializer",
	"authorization", "reentrancy", "logic-error", "dos-griefing",
	"token-integration", "share-price-accounting", "oracle-manipulation",
	"flash-loan", "share-price-inflation", "economic-invariant",
	"liquidation-logic", "bridge-message", "cross-chain-replay",
}

// Plan is plan(). A plan on disk is the campaign's CONTRACT: with a plan on
// disk and rebuild=false it computes the view from the file and writes
// NOTHING — no save, no artifact refresh, no stage/phase mutation. Passing a
// plan for an existing campaign without rebuild=true is a would-be clobber and
// raises. Regeneration is explicit (rebuild=true), and the outgoing plan is
// archived BEFORE the new one is written.
//
// plan and model are validation.VNull() for Python's None.
func (o *Orchestrator) Plan(plan, model validation.Value,
	rebuild bool) (validation.Value, error) {
	planPath := filepath.Join(o.C.ArtifactsDir, "campaign_plan.json")
	existing := fileExists(planPath)
	if existing && !rebuild {
		return o.planReadOnly(plan, model, planPath)
	}
	resolved, err := o.resolvePlan(plan, model)
	if err != nil {
		return validation.VNull(), err
	}
	return o.writePlan(resolved, planPath, existing, model)
}

// planReadOnly computes the view from the plan on disk and writes NOTHING.
func (o *Orchestrator) planReadOnly(plan, model validation.Value,
	planPath string) (validation.Value, error) {
	if plan.Kind != validation.Null {
		return validation.VNull(), orchestrationError("a campaign plan " +
			"already exists at " + planPath + " — loading another one would " +
			"clobber the campaign's contract; add --rebuild to regenerate " +
			"(the current plan is archived)")
	}
	current, err := validation.ReadJson(planPath)
	if err != nil {
		return validation.VNull(), err
	}
	// include_hints: the campaign's own reflection feeds the queue — the
	// loop run 1 left open (reflection written, never consumed).
	queueModel, err := o.planQueueModel(model)
	if err != nil {
		return validation.VNull(), err
	}
	queue, err := planner.WorkQueue(o.C, current, queueModel, true)
	if err != nil {
		return validation.VNull(), err
	}
	reach, err := o.PlanReachability()
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kvOf("plan", current),
		kvOf("work_queue", valueArr(queue)),
		kvOf("reachability", reach),
		kvOf("read_only", validation.VBool(true)),
	), nil
}

// planQueueModel is the model the work queue is scored against: the caller's
// own model when one was supplied, else the campaign's protocol_model.json.
// The queue's risk weighting (Task 12) reads contracts, invariants and open
// questions, so a plan read back without a model argument must not silently
// score every row at zero — the campaign's model is on disk, and it is the
// same one the plan was built from. Absent model = an empty object (no
// signals); a model that EXISTS but cannot be read is an error, never a
// silent zero.
func (o *Orchestrator) planQueueModel(model validation.Value) (validation.Value,
	error) {
	if model.Kind != validation.Null {
		return model, nil
	}
	pm := filepath.Join(o.C.ArtifactsDir, "protocol_model.json")
	if !fileExists(pm) {
		return orEmptyObj(model), nil
	}
	loaded, err := validation.ReadJson(pm)
	if err != nil {
		return validation.VNull(), err
	}
	return loaded, nil
}

// resolvePlan is the incoming-plan half: an explicit plan, or the one derived
// from the loaded protocol model.
func (o *Orchestrator) resolvePlan(plan, model validation.Value) (
	validation.Value, error) {
	if plan.Kind != validation.Null {
		return plan, nil
	}
	if model.Kind == validation.Null {
		pm := filepath.Join(o.C.ArtifactsDir, "protocol_model.json")
		if fileExists(pm) {
			loaded, err := validation.ReadJson(pm)
			if err != nil {
				return validation.VNull(), err
			}
			model = loaded
		}
	}
	if model.Kind == validation.Null {
		return validation.VNull(), orchestrationError(
			"provide a plan or load a protocol model first")
	}
	return planner.DefaultPlanFromModel(o.C, model)
}

// writePlan is the mutating half: validate, archive the outgoing plan, save,
// and record the reachability warning and stage/phase moves.
func (o *Orchestrator) writePlan(plan validation.Value, planPath string,
	existing bool, model validation.Value) (validation.Value, error) {
	// Prove the incoming plan is writable BEFORE retiring the outgoing one: a
	// rebuild that fails validation must not leave an archive of a plan that
	// is still live.
	plan, err := planner.ValidatePlan(o.C, plan)
	if err != nil {
		return validation.VNull(), err
	}
	if existing {
		if _, err := planner.ArchivePlan(o.C, planner.ArchiveOpts{
			Path: planPath,
			Reason: "plan rebuilt (--rebuild); the outgoing plan is the " +
				"superseded contract"}); err != nil {
			return validation.VNull(), err
		}
	}
	if _, err := planner.SavePlan(o.C, plan); err != nil {
		return validation.VNull(), err
	}
	queueModel, err := o.planQueueModel(model)
	if err != nil {
		return validation.VNull(), err
	}
	queue, err := planner.WorkQueue(o.C, plan, queueModel, true)
	if err != nil {
		return validation.VNull(), err
	}
	reach, err := o.PlanReachability()
	if err != nil {
		return validation.VNull(), err
	}
	if err := o.logReachability(reach); err != nil {
		return validation.VNull(), err
	}
	note := itoa(len(queue)) + " queued priorities"
	if err := o.C.SetStage("campaign-planning", "needs-model",
		validation.VStr(note), nil); err != nil {
		return validation.VNull(), err
	}
	if err := o.C.SetPhase("DISCOVERY", "plan ready"); err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kvOf("plan", plan),
		kvOf("work_queue", valueArr(queue)),
		kvOf("reachability", reach),
		kvOf("read_only", validation.VBool(false)),
	), nil
}

// logReachability records the plan.reachability event when E5/E6 are blocked.
func (o *Orchestrator) logReachability(reach validation.Value) error {
	if !pyTruthyBigNonEmpty(objAt(reach, "e5")) && !pyTruthyBigNonEmpty(objAt(reach, "e6")) {
		return nil
	}
	data := validation.VObj(
		kvOf("e5", objAt(reach, "e5")),
		kvOf("e6", objAt(reach, "e6")),
		kvOf("classes_at_e5_plus", objAt(reach, "classes_at_e5_plus")),
	)
	_, err := o.C.Log("plan.reachability", nil, &data)
	return err
}

// PlanReachability is plan_reachability(): the plan-time structural warning —
// which evidence levels are unreachable in THIS campaign right now (no
// deployment/chain pin, no FORK_RPC_URL) and which classes' CONFIRMED floors
// they block.
func (o *Orchestrator) PlanReachability() (validation.Value, error) {
	e5, err := findings.ReachabilityDiagnostic(o.C, "E5", nil)
	if err != nil {
		return validation.VNull(), err
	}
	e6, err := findings.ReachabilityDiagnostic(o.C, "E6", nil)
	if err != nil {
		return validation.VNull(), err
	}
	e5Index, err := findings.LevelIndex("E5")
	if err != nil {
		return validation.VNull(), err
	}
	affected := []validation.KV{}
	for _, class := range classFloorOrder {
		eff, ok := findings.CLASS_CONFIRM_FLOOR[class]
		if !ok {
			return validation.VNull(), errors.New(
				"unknown bug class in the CONFIRMED floor table: " + class)
		}
		override, err := floors.FloorOverride(o.C, class)
		if err != nil {
			return validation.VNull(), err
		}
		if override != nil && *override != "" {
			eff = *override
		}
		idx, err := findings.LevelIndex(eff)
		if err != nil {
			return validation.VNull(), err
		}
		if idx >= e5Index {
			affected = append(affected, kvOf(class, validation.VStr(eff)))
		}
	}
	note := "no structural blockers detected"
	if len(e5) > 0 || len(e6) > 0 {
		note = "classes whose CONFIRMED floor is E5/E6 cannot reach " +
			"confirmation while the prerequisites above are missing"
	}
	return validation.VObj(
		kvOf("e5", strArr(e5)),
		kvOf("e6", strArr(e6)),
		kvOf("classes_at_e5_plus", validation.VObj(affected...)),
		kvOf("note", validation.VStr(note)),
	), nil
}
