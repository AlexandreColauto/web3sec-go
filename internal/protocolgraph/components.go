// components.go: G9 opaque-surface projection — one display line per
// protocol-model component.
//
// A component is a tracked-but-opaque surface: findings may anchor on it,
// but structidx never indexes it (the solidity parser only reads .sol, so
// there is nothing to exclude — the law holds by construction and the
// e2e test pins it). This projection is the single source of the display
// format `- <kind> <path|url>: <in_scope|out-of-scope><, paid>` consumed
// by the briefing block, the report block and the plan view, so the three
// can never drift apart.
//
// Pure function, no IO, no campaign handle (the Task 2 AssumptionTable
// pattern): the renderers own presence-gating (no components key or an
// empty list renders nothing).
package protocolgraph

import (
	"websec/internal/validation"
)

// ComponentSurfaceLines is the per-component display projection: one line
// per entry of the model's `components[]` (Task 1 shape, verbatim field
// names):
//
//   - <kind> <path|url>: <in_scope|out-of-scope><, paid>
//
// The locator prefers `path` over `url` (a component may carry either);
// both absent renders "?". Scope reads the `in_scope` flag verbatim; the
// `, paid` suffix rides `paid_for`. A model with no `components` key (or
// a non-list) yields nil, so callers gate on len(lines) > 0.
func ComponentSurfaceLines(model validation.Value) []string {
	comps := objAt(model, "components")
	if comps.Kind != validation.Arr {
		return nil
	}
	out := []string{}
	for _, c := range comps.A {
		if c.Kind != validation.Obj {
			continue
		}
		kind := objAt(c, "kind")
		name := "?"
		if kind.Kind == validation.Str && kind.S != "" {
			name = kind.S
		}
		loc := "?"
		if p := objAt(c, "path"); p.Kind == validation.Str && p.S != "" {
			loc = p.S
		} else if u := objAt(c, "url"); u.Kind == validation.Str &&
			u.S != "" {
			loc = u.S
		}
		scope := "out-of-scope"
		if pyTruthy(objAt(c, "in_scope")) {
			scope = "in_scope"
		}
		line := "- " + name + " " + loc + ": " + scope
		if pyTruthy(objAt(c, "paid_for")) {
			line += ", paid"
		}
		out = append(out, line)
	}
	return out
}
