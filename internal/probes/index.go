package probes

import (
	"sort"
	"strconv"

	"websec/internal/validation"
)

// contractNodes is _contract_nodes(index): contract/interface/library nodes,
// sorted by id.
func contractNodes(index validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, n := range vList(index, "nodes") {
		if n.Kind != validation.Obj {
			continue
		}
		switch vStr(n, "kind") {
		case "contract", "interface", "library":
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return vStr(out[i], "id") < vStr(out[j], "id")
	})
	return out
}

// functionNodes is _function_nodes(index): node id -> function node.
func functionNodes(index validation.Value) map[string]validation.Value {
	out := map[string]validation.Value{}
	for _, n := range vList(index, "nodes") {
		if n.Kind == validation.Obj && vStr(n, "kind") == "function" {
			out[vStr(n, "id")] = n
		}
	}
	return out
}

// nodeID is _node_id(entry): path#defining_contract.name.
func nodeID(entry validation.Value) string {
	return vStr(entry, "path") + "#" + vStr(entry, "defining_contract") +
		"." + vStr(entry, "name")
}

// rawRow is _raw: one raw candidate — the internal grouping slots plus the
// probe's public fields. `consumer`/`consumer_line` are the public names of
// the function slot.
func rawRow(contract, function string, line int, concept string, tier int,
	gate string, gap int, sortName string, extra ...validation.KV) validation.Value {
	out := validation.VObj(
		validation.KV{K: "contract", V: validation.VStr(contract)},
		validation.KV{K: "function", V: validation.VStr(function)},
		validation.KV{K: "line", V: validation.VInt(int64(line))},
		validation.KV{K: "concept", V: validation.VStr(concept)},
		validation.KV{K: "tier", V: validation.VInt(int64(tier))},
		validation.KV{K: "gate", V: validation.VStr(gate)},
		validation.KV{K: "assertion_gap", V: validation.VInt(int64(gap))},
		validation.KV{K: "sort_name", V: validation.VStr(sortName)},
		validation.KV{K: "consumer", V: validation.VStr(function)},
		validation.KV{K: "consumer_line", V: validation.VInt(int64(line))},
	)
	for _, kv := range extra {
		vSet(&out, kv.K, kv.V)
	}
	return out
}

// kv is a key/value constructor.
func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// itoa is str(n) for a non-negative int.
func itoa(n int) string { return strconv.Itoa(n) }

// blindEntry builds one `blind[]` entry in Python's key order.
func blindEntry(kind, key string, near validation.Value, rest ...validation.KV) validation.Value {
	out := validation.VObj(
		kv("kind", validation.VStr(kind)),
		kv("key", validation.VStr(key)),
		kv("near", near),
	)
	for _, pair := range rest {
		vSet(&out, pair.K, pair.V)
	}
	return out
}

// nodeModifiers is node.get("modifiers") as a string list.
func nodeModifiers(node validation.Value) []string { return vStrList(node, "modifiers") }

// guardClass is g.get("class", 0).
func guardClass(g validation.Value) int {
	if vHas(g, "class") {
		return vInt(g, "class")
	}
	return 0
}

// usesOf is entry.get("uses") or [].
func usesOf(entry validation.Value) []validation.Value { return vObjList(entry, "uses") }

// guardsOf is entry.get("guards") or [].
func guardsOf(entry validation.Value) []validation.Value { return vObjList(entry, "guards") }

// sortedUsesConcepts is sorted({k for u in uses for k in u.concept_keys}).
func sortedUsesConcepts(uses []validation.Value) []string {
	set := map[string]struct{}{}
	for _, u := range uses {
		for _, k := range vStrList(u, "concept_keys") {
			set[k] = struct{}{}
		}
	}
	return sortedStrSet(set)
}

// sortBlindFields sorts `blind[]` by the given keys, each read as
// `str(b.get(k) or "")` (probe 1 keys on the citation, the others on kind).
func sortBlindFields(blind []validation.Value, fields ...string) {
	sort.SliceStable(blind, func(i, j int) bool {
		for _, f := range fields {
			a, b := blindStr(blind[i], f), blindStr(blind[j], f)
			if a != b {
				return a < b
			}
		}
		return false
	})
}

// blindStr is str(b.get(field) or "").
func blindStr(b validation.Value, field string) string {
	if v := vGet(b, field); vTruthy(v) {
		return pyStr(v)
	}
	return ""
}

// blindNear is str(b.get("near") or "").
func blindNear(b validation.Value) string {
	if n := vGet(b, "near"); vTruthy(n) {
		return pyStr(n)
	}
	return ""
}

// blindField is str(b.get(field) or "").
func blindField(field string) func(validation.Value) string {
	return func(b validation.Value) string {
		if v := vGet(b, field); vTruthy(v) {
			return pyStr(v)
		}
		return ""
	}
}

// limit50 is blind[:50].
func limit50(items []validation.Value) []validation.Value {
	if len(items) > 50 {
		return items[:50]
	}
	return items
}
