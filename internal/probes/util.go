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
		// Only map contracts that have a real source path. A node without a
		// path can't anchor to a file, so omit it (mapping name->name here
		// would make the resolver emit a bogus "Name#L" citation).
		if vTruthy(path) {
			out[name] = pyStr(path)
		}
	}
	return out
}

// resolveAnchorToken maps a contract name to an anchor file token.
//
// With an index (hasIndex), a contract that is not resolvable to a real path
// resolves to NOTHING (ok=false) — the caller must skip it rather than
// fabricate a "Name#L" citation that names no file. Without an index there is
// nothing to check against, so the bare name (or "?" when empty) is the best
// available token.
func resolveAnchorToken(paths map[string]string, hasIndex bool, contractStr string) (string, bool) {
	if token, ok := paths[contractStr]; ok {
		return token, true
	}
	if hasIndex {
		return "", false
	}
	if contractStr != "" {
		return contractStr, true
	}
	return "?", true
}
