package planner

import (
	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

// TrackedSurfacesSection is the G9 plan-view block: the model's
// tracked-but-opaque component surfaces listed as tracked surfaces — one
// line per component (`- <kind> <path|url>:
// <in_scope|out-of-scope><, paid>`, via protocolgraph.ComponentSurfaceLines).
//
// Presence-gated (the additive convention): nil unless the model carries a
// non-empty `components` list, so a component-free plan view gains no
// bytes. Pure function, no IO, no campaign handle (the Task 2
// AssumptionTable pattern): the plan view loads the model and gates on
// len. Findings may anchor on these surfaces; structidx never indexes
// them.
func TrackedSurfacesSection(model validation.Value) []string {
	lines := protocolgraph.ComponentSurfaceLines(model)
	if len(lines) == 0 {
		return nil
	}
	out := []string{"tracked-but-opaque surfaces (findings only — " +
		"structidx never indexes these):"}
	out = append(out, lines...)
	return out
}
