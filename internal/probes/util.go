package probes

import (
	"fmt"
	"sort"

	"websec/internal/validation"
)

// errf is a formatted error (the Python module's ValueError/ProbeError).
func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }

// sprintf is fmt.Sprintf under the Python-module naming.
func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

// contractPaths is _contract_paths: contract name -> source path, first
// definition wins (sorted by node id).
func contractPaths(index validation.Value) map[string]string {
	out := map[string]string{}
	nodes := append([]validation.Value(nil), vList(index, "nodes")...)
	sort.SliceStable(nodes, func(i, j int) bool {
		return pyStr(vGet(nodes[i], "id")) < pyStr(vGet(nodes[j], "id"))
	})
	for _, n := range nodes {
		if n.Kind != validation.Obj {
			continue
		}
		switch vStr(n, "kind") {
		case "contract", "interface", "library":
		default:
			continue
		}
		name := vStr(n, "name")
		if name == "" {
			continue
		}
		if _, seen := out[name]; seen {
			continue
		}
		path := vGet(n, "path")
		if vTruthy(path) {
			out[name] = pyStr(path)
		} else {
			out[name] = name
		}
	}
	return out
}
