// reachability.go: T0 static reachability and its seam to
// webv2.structural_index.
//
// structural_index (P3) is not ported in this wave, so its two queries arrive
// through StructuralIndexAPI. The DEFAULT answers are the fail-closed ones —
// no unguarded entry points, no path — which means an unwired index can
// never mint E2 reachability evidence on a guess. When internal/structural
// lands it installs the real queries through SetStructuralIndex.
package reproduction

import (
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// StructuralIndexAPI is the structural_index surface reproduction needs.
type StructuralIndexAPI struct {
	// UnguardedEntryPoints is si.unguarded_entry_points.
	UnguardedEntryPoints func(index validation.Value) []validation.Value
	// PathExists is si.path_exists: the node-id path, or false for Python's
	// None.
	PathExists func(index validation.Value, src, dst string) ([]string, bool)
}

var structuralIndex = StructuralIndexAPI{
	UnguardedEntryPoints: func(validation.Value) []validation.Value { return nil },
	PathExists:           func(validation.Value, string, string) ([]string, bool) { return nil, false },
}

// SetStructuralIndex installs the structural_index queries; the zero value
// restores the fail-closed defaults.
func SetStructuralIndex(api StructuralIndexAPI) {
	if api.UnguardedEntryPoints == nil {
		api.UnguardedEntryPoints = func(validation.Value) []validation.Value {
			return nil
		}
	}
	if api.PathExists == nil {
		api.PathExists = func(validation.Value, string, string) ([]string, bool) {
			return nil, false
		}
	}
	structuralIndex = api
}

// StaticReachability is static_reachability: T0 — is the affected function
// reachable from an unguarded entry point? Deterministic, instant, and
// raises the evidence floor to E2 when true.
func StaticReachability(c *state.Campaign, findingID string,
	index validation.Value) (validation.Value, error) {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	targetFn := ""
	if affected := validation.ObjAt(f, "affected"); affected.Kind == validation.Arr &&
		len(affected.A) > 0 {
		targetFn = validation.ObjStr(affected.A[0], "function")
	}
	if targetFn == "" {
		return validation.VObj(
			validation.KV{K: "reachable", V: validation.VBool(false)},
			validation.KV{K: "reason", V: validation.VStr(
				"no function recorded on finding")},
		), nil
	}
	var fnNodes []validation.Value
	for _, n := range validation.ObjAt(index, "nodes").A {
		if validation.ObjStr(n, "kind") == "function" && validation.ObjStr(n, "name") == targetFn {
			fnNodes = append(fnNodes, n)
		}
	}
	if len(fnNodes) == 0 {
		return validation.VObj(
			validation.KV{K: "reachable", V: validation.VBool(false)},
			validation.KV{K: "reason", V: validation.VStr(
				"function " + validation.PyReprStr(targetFn) + " not in index")},
		), nil
	}
	reachable := false
	var witness []string
	for _, entry := range structuralIndex.UnguardedEntryPoints(index) {
		for _, fn := range fnNodes {
			entryID, fnID := validation.ObjStr(entry, "id"), validation.ObjStr(fn, "id")
			var p []string
			var ok bool
			if entryID == fnID {
				p, ok = []string{fnID}, true
			} else {
				p, ok = structuralIndex.PathExists(index, entryID, fnID)
			}
			if ok {
				reachable, witness = true, p
				break
			}
		}
		if reachable {
			break
		}
	}
	if truthy(validation.ObjAt(fnNodes[0], "is_entry_point")) &&
		!truthy(validation.ObjAt(fnNodes[0], "guarded_by")) {
		reachable = true
		witness = []string{validation.ObjStr(fnNodes[0], "id")}
	}
	reason := "no path from unguarded entry point"
	if reachable {
		reason = "path from unguarded entry point"
	}
	var witnessV validation.Value = validation.VNull()
	if witness != nil {
		items := make([]validation.Value, 0, len(witness))
		for _, id := range witness {
			items = append(items, validation.VStr(id))
		}
		witnessV = validation.VArr(items...)
	}
	result := validation.VObj(
		validation.KV{K: "reachable", V: validation.VBool(reachable)},
		validation.KV{K: "witness", V: witnessV},
		validation.KV{K: "reason", V: validation.VStr(reason)},
	)
	if reachable {
		item := validation.VObj(
			validation.KV{K: "evidence_id", V: validation.VStr("EV-" + shortID(8))},
			validation.KV{K: "level", V: validation.VStr("E2")},
			validation.KV{K: "type", V: validation.VStr("reachability")},
			validation.KV{K: "description", V: validation.VStr(
				"T0 static reachability: " + reason)},
			validation.KV{K: "produced_at", V: validation.VStr(state.NowIso())},
			validation.KV{K: "snapshot_id", V: validation.ObjAt(validation.ObjAt(f, "snapshot_ids"),
				"source")},
		)
		if _, err := findings.AddEvidence(c, findingID, item); err != nil {
			return validation.VNull(), err
		}
	}
	return result, nil
}

// truthy is Python truthiness for the JSON scalars an index node holds.
func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	default:
		return false
	}
}
