package planner

import (
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// init wires the planner's seams into the findings module. Both packages are
// imported by the CLI, so the wiring is done here rather than in main: the
// planner is the owner of these functions, and a missing wire would silently
// degrade findings' DISPROVED sibling guard to a no-op.
func init() {
	findings.SetPlannerModelOrEmpty(ModelOrEmpty)
	findings.SetPlannerFamiliesForFinding(FamiliesForFinding)
	findings.SetAdjacentRequiredMsg(AdjacentRequiredMsg)
	findings.SetPlannerLoadPlanReadonly(LoadPlanReadonly)
	findings.SetPlannerSavePlan(savePlanSeam)
	findings.SetPlannerSiblingRescan(siblingRescanSeam)
	findings.SetTaxonomyKnownClasses(taxonomy.KnownClasses)
}

// savePlanSeam adapts save_plan to findings' error-only seam.
func savePlanSeam(campaign *state.Campaign, plan validation.Value) error {
	_, err := SavePlan(campaign, plan)
	return err
}

// siblingRescanSeam adapts sibling_rescan to findings' positional seam: an
// empty adjacent is Python's None, an empty reason is Python's None.
func siblingRescanSeam(campaign *state.Campaign, finding validation.Value,
	adjacent string, clear bool, reason, actor string) error {
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	_, err := SiblingRescan(campaign, finding, SiblingOpts{Adjacent: adjacent,
		Clear: clear, Reason: reasonPtr, Actor: actor})
	return err
}
