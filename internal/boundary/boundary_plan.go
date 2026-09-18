package boundary

import (
	"fmt"
	"sort"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// validatePlanKinds is the hypothesis/plan cross-field block.
func validatePlanKinds(kind string, payload validation.Value,
	campaign *state.Campaign) error {
	stepsKey := "initial_plan"
	if kind == "plan" {
		stepsKey = "steps"
	}
	tools := map[string]bool{}
	if steps := validation.ObjAt(payload, stepsKey); steps.Kind == validation.Arr {
		for _, s := range steps.A {
			if s.Kind == validation.Obj {
				tools[validation.ObjStr(s, "tool_id")] = true
			}
		}
	}
	unknown := []string{}
	for t := range tools {
		if !inRegistry(t) {
			unknown = append(unknown, t)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"%s plan cites tool ids not in the registry: %s (registry: %s)",
			kind, validation.PyListRepr(unknown), validation.PyListRepr(ToolRegistry()))}
	}
	if campaign == nil {
		return nil
	}
	if kind == "plan" {
		fid := validation.ObjStr(payload, "finding_id")
		if _, err := findings.LoadFinding(campaign, fid); err != nil {
			return &BoundaryError{Msg: fmt.Sprintf(
				"plan references unknown finding %s", validation.PyReprStr(fid))}
		}
		return nil
	}
	// r44c: the id set is a READ of the memory store. A store that cannot be
	// listed refuses here — as a plain error, NOT a BoundaryError: "unknown
	// memory row" would accuse the model's payload of a defect the store read
	// never established. The caller must surface the refusal as the
	// infrastructure failure it is rather than re-requesting the model.
	known, err := campaignMemoryIDs(campaign)
	if err != nil {
		return err
	}
	if d := validation.ObjAt(payload, "differs_from_memory"); d.Kind == validation.Arr {
		for _, item := range d.A {
			if item.Kind != validation.Obj {
				continue
			}
			mid := validation.ObjStr(item, "memory_id")
			if !known[mid] {
				return &BoundaryError{Msg: fmt.Sprintf(
					"hypothesis override names unknown memory row %s — an "+
						"override must name a real surfacable prior",
					validation.PyReprStr(mid))}
			}
		}
	}
	return nil
}
