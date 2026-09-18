package cli

// cmd_answered_helpers: the probe-closure report and the small
// plan-entry helpers shared by the answered routes (moved verbatim from
// cmd_answered.go).
import (
	"fmt"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// printProbeClosure is cli.py's _print_probe_closure: the probe clause of a
// lens as a sentence with counts (only_closed=True). With the probes module
// unported there is no surface, so divergence_status emits no probe entry and
// this prints nothing — exactly what Python prints for a campaign with no
// probe artifact.
func printProbeClosure(c *state.Campaign, plan validation.Value,
	lensNames map[string]struct{}, stdout interface{ Write([]byte) (int, error) }) {
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		return
	}
	for _, entry := range t14List(div, "lenses").A {
		probe := validation.ObjAt(entry, "probe")
		if probe.Kind != validation.Obj || !t14Truthy(validation.ObjAt(probe, "message")) {
			continue
		}
		if lensNames != nil {
			_, a := lensNames[validation.ObjStr(entry, "lens")]
			_, b := lensNames[validation.ObjStr(entry, "id")]
			if !a && !b {
				continue
			}
		}
		if !t14Truthy(validation.ObjAt(probe, "closed")) {
			continue
		}
		fmt.Fprintf(stdout, "%s\n", validation.ObjStr(probe, "message"))
	}
}

// t14FindByID is next((x for x in items if x["id"] == id), None).
func t14FindByID(items validation.Value, id string) (validation.Value, bool) {
	for _, it := range items.A {
		if validation.ObjStr(it, "id") == id {
			return it, true
		}
	}
	return validation.VNull(), false
}

// t14Strings renders a list value as Go strings.
func t14Strings(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, it := range v.A {
		out = append(out, scalarStr(it))
	}
	return out
}

// t14InList is `x in items`.
func t14InList(x string, items []string) bool {
	for _, it := range items {
		if it == x {
			return true
		}
	}
	return false
}
