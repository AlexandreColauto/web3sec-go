// enforcement_value.go: value accessors and serializers shared by the enforcement table.

package structidx

import (
	"fmt"
	"strings"
	"websec/internal/validation"
)

// enfGuardsOf is the containing function's assertions, each marked with
// whether it is about the queried variable (its concept keys intersect).
func enfGuardsOf(n validation.Value, conceptKey string) []enfGuard {
	out := []enfGuard{}
	for _, g := range listOf(validation.ObjAt(n, "guards")) {
		rec := enfGuard{
			line:  intAt(g, "line"),
			class: intAt(g, "class"),
			text:  validation.ObjStr(g, "text"),
		}
		rec.about = hasConceptKey(strList(validation.ObjAt(g, "concept_keys")), conceptKey)
		out = append(out, rec)
	}
	return out
}

// useLine is the first statement-level use of the wanted keys with the given
// kind (the precise line of a write or read of the variable).
func useLine(n validation.Value, conceptKey, kind string) (int64, bool) {
	for _, u := range usesOf(n) {
		if validation.ObjStr(u, "kind") != kind {
			continue
		}
		if hasConceptKey(strList(validation.ObjAt(u, "concept_keys")), conceptKey) {
			return intAt(u, "line"), true
		}
	}
	return 0, false
}

func usesOf(n validation.Value) []validation.Value { return listOf(validation.ObjAt(n, "uses")) }

func listOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

func listHas(v validation.Value, want string) bool {
	for _, e := range strList(v) {
		if e == want {
			return true
		}
	}
	return false
}

// conceptKeyOf is the maximal concept key of a name or expression: the
// index's own tokenizer (splitIdent, which already applies the synonym fold
// and drops stopwords) joined by ":" — the exact string the index records for
// an expression that IS that name. ConceptKeys sorts its output, so the
// maximal key has to be rebuilt here rather than taken from the tail.
func conceptKeyOf(expr string) string {
	// splitIdent splits only on '_' and camelCase boundaries, so a name typed
	// the way an operator writes it ("prev-state root", "prev.state.root") is
	// first folded onto that one separator.
	clean := []byte(expr)
	for i, b := range clean {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z',
			b >= '0' && b <= '9':
		default:
			clean[i] = '_'
		}
	}
	return strings.Join(splitIdent(string(clean)), ":")
}

// hasConceptKey reports whether a recorded key list carries the wanted key. A
// partial token overlap is deliberately NOT a match: `storedHash` folds to
// "stored:root", and matching on the bare "root" token would sweep in every
// unrelated stateRoot expression in the index.
func hasConceptKey(keys []string, want string) bool {
	if want == "" {
		return false
	}
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

func boolAt(v validation.Value, key string) bool {
	x := validation.ObjAt(v, key)
	return x.Kind == validation.Bool && x.B
}

func intAt(v validation.Value, key string) int64 {
	x := validation.ObjAt(v, key)
	if x.Kind != validation.Int {
		return 0
	}
	return x.I
}

func objLineOf(n validation.Value) int64 { return intAt(n, "line") }

func intText(n int64) string { return fmt.Sprintf("%d", n) }

// splitNodeID splits an index node id (`path#Contract.func`, or
// `path#Contract` for a contract) into its contract and function names.
func splitNodeID(id string) (contract, function string) {
	rest := id
	if i := strings.LastIndex(id, "#"); i >= 0 {
		rest = id[i+1:]
	}
	if i := strings.LastIndex(rest, "."); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// enfSiteValues renders the sites (and their guards) as JSON values.
func enfSiteValues(sites []enfSite) []validation.Value {
	out := make([]validation.Value, 0, len(sites))
	for _, s := range sites {
		guards := make([]validation.Value, 0, len(s.guards))
		for _, g := range s.guards {
			guards = append(guards, validation.VObj(
				validation.KV{K: "line", V: validation.VInt(g.line)},
				validation.KV{K: "class", V: validation.VInt(g.class)},
				validation.KV{K: "text", V: validation.VStr(g.text)},
				validation.KV{K: "about_variable", V: validation.VBool(g.about)}))
		}
		var depth validation.Value
		if s.hasDepth {
			depth = validation.VInt(int64(s.depth))
		} else {
			depth = validation.VNull()
		}
		out = append(out, validation.VObj(
			validation.KV{K: "contract", V: validation.VStr(s.contract)},
			validation.KV{K: "function", V: validation.VStr(s.function)},
			validation.KV{K: "function_id", V: validation.VStr(s.id)},
			validation.KV{K: "kind", V: validation.VStr(s.kind)},
			validation.KV{K: "line", V: validation.VInt(s.line)},
			validation.KV{K: "granularity", V: validation.VStr(s.gran)},
			validation.KV{K: "is_entry_point", V: validation.VBool(s.entry)},
			validation.KV{K: "depth", V: depth},
			validation.KV{K: "guarded", V: validation.VBool(s.guarded)},
			validation.KV{K: "guards", V: validation.VArr(guards...)}))
	}
	return out
}

// enfSiteRef is the compact site identity used inside a stage pair.
func enfSiteRef(s enfSite) validation.Value {
	return validation.VObj(
		validation.KV{K: "contract", V: validation.VStr(s.contract)},
		validation.KV{K: "function", V: validation.VStr(s.function)},
		validation.KV{K: "line", V: validation.VInt(s.line)},
		validation.KV{K: "kind", V: validation.VStr(s.kind)})
}
