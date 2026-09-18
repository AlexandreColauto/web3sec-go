package findings

import (
	"fmt"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- planner / taxonomy seams (their tasks own the real modules). The
// ---- defaults keep the finding-side logic honest without them: no model
// ---- means no family tokens, and the adjacent-property guard stays armed
// ---- with the Python message.

// plannerModelOrEmptyFunc is planner._model_or_empty: the protocol model, or
// an empty object when it is absent/unreadable.
var plannerModelOrEmptyFunc = func(*state.Campaign) validation.Value {
	return validation.VObj()
}

// SetPlannerModelOrEmpty wires planner._model_or_empty.
func SetPlannerModelOrEmpty(f func(*state.Campaign) validation.Value) {
	if f == nil {
		panic("findings: nil planner model loader")
	}
	plannerModelOrEmptyFunc = f
}

// plannerFamiliesForFindingFunc is planner.families_for_finding.
var plannerFamiliesForFindingFunc = func(model, finding validation.Value) map[string]struct{} {
	return map[string]struct{}{}
}

// SetPlannerFamiliesForFinding wires planner.families_for_finding.
func SetPlannerFamiliesForFinding(f func(validation.Value, validation.Value) map[string]struct{}) {
	if f == nil {
		panic("findings: nil planner families resolver")
	}
	plannerFamiliesForFindingFunc = f
}

// adjacentRequiredMsg is planner.ADJACENT_REQUIRED_MSG.
var adjacentRequiredMsg = "DISPROVED on a lifecycle finding must name the " +
	"adjacent unchecked property (--adjacent '...') or attest it clear " +
	"(--adjacent-clear --reason R)"

// SetAdjacentRequiredMsg wires planner.ADJACENT_REQUIRED_MSG.
func SetAdjacentRequiredMsg(msg string) {
	if msg == "" {
		panic("findings: empty adjacent-required message")
	}
	adjacentRequiredMsg = msg
}

// plannerLoadPlanReadonlyFunc is planner.load_plan_readonly.
var plannerLoadPlanReadonlyFunc = func(*state.Campaign) (validation.Value, error) {
	return validation.VNull(), fmt.Errorf("no campaign plan")
}

// SetPlannerLoadPlanReadonly wires planner.load_plan_readonly.
func SetPlannerLoadPlanReadonly(f func(*state.Campaign) (validation.Value, error)) {
	if f == nil {
		panic("findings: nil plan loader")
	}
	plannerLoadPlanReadonlyFunc = f
}

// plannerSavePlanFunc is planner.save_plan.
var plannerSavePlanFunc = func(*state.Campaign, validation.Value) error { return nil }

// SetPlannerSavePlan wires planner.save_plan.
func SetPlannerSavePlan(f func(*state.Campaign, validation.Value) error) {
	if f == nil {
		panic("findings: nil plan saver")
	}
	plannerSavePlanFunc = f
}

// plannerSiblingRescanFunc is planner.sibling_rescan.
var plannerSiblingRescanFunc = func(*state.Campaign, validation.Value,
	string, bool, string, string) error {
	return nil
}

// SetPlannerSiblingRescan wires planner.sibling_rescan.
func SetPlannerSiblingRescan(f func(*state.Campaign, validation.Value, string,
	bool, string, string) error) {
	if f == nil {
		panic("findings: nil sibling rescan")
	}
	plannerSiblingRescanFunc = f
}

// taxonomyKnownClassesFunc is taxonomy.known_classes: the canonical class
// vocabulary save_plan hard-validates against.
var taxonomyKnownClassesFunc = func() map[string]struct{} {
	return map[string]struct{}{}
}

// SetTaxonomyKnownClasses wires taxonomy.known_classes.
func SetTaxonomyKnownClasses(f func() map[string]struct{}) {
	if f == nil {
		panic("findings: nil taxonomy class set")
	}
	taxonomyKnownClassesFunc = f
}
