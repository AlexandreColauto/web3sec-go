// dedup_value_helpers.go: the local Value helpers split out of dedup.go —
// deep get/set, signature lookup, signature grouping and list conversions.
package dedup

import (
	"websec/internal/validation"
)

// ---- local Value helpers (findings' equivalents are unexported) -------------

// getDeep is a chain of dict.get: Null as soon as a step is missing or is not
// an object (Python's (d.get(k1) or {}).get(k2)).
func getDeep(root validation.Value, keys ...string) validation.Value {
	cur := root
	for _, k := range keys {
		if cur.Kind != validation.Obj {
			return validation.VNull()
		}
		cur = validation.ObjAt(cur, k)
	}
	return cur
}

// setDeep is Python's d.setdefault(k1, {})[k2] = v chain: missing
// intermediate objects are created, an existing key keeps its position.
func setDeep(root validation.Value, v validation.Value, keys ...string) validation.Value {
	if len(keys) == 0 {
		return v
	}
	child := validation.VObj()
	for _, kv := range root.O {
		if kv.K == keys[0] && kv.V.Kind == validation.Obj {
			child = kv.V
			break
		}
	}
	child = setDeep(child, v, keys[1:]...)
	root.O = validation.SetOrAppend(root.O, keys[0], child)
	return root
}

// sigAt is (f.get("dedup") or {}).get(key) when truthy: the signature string,
// or "" for a falsy value (absent, null, empty).
func sigAt(f validation.Value, key string) string {
	if v := getDeep(f, "dedup", key); v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// groupBySig buckets findings by one dedup signature, preserving the first
// appearance order of each signature (Python dict iteration order).
func groupBySig(live []validation.Value, key string, exclude map[string]bool) []sigGroup {
	var groups []sigGroup
	index := map[string]int{}
	for _, f := range live {
		sig := sigAt(f, key)
		if sig == "" {
			continue
		}
		if exclude != nil && exclude[validation.ObjStr(f, "finding_id")] {
			continue
		}
		i, ok := index[sig]
		if !ok {
			i = len(groups)
			index[sig] = i
			groups = append(groups, sigGroup{sig: sig})
		}
		groups[i].members = append(groups[i].members, f)
	}
	return groups
}

// valueStrings is the string elements of a list value (finding ids; a
// non-list or non-string element cannot pass the finding schema).
func valueStrings(v validation.Value) []string {
	if v.Kind != validation.Arr {
		return nil
	}
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

// strArray builds a JSON array value from strings.
func strArray(items []string) validation.Value {
	arr := validation.VArr()
	for _, s := range items {
		arr.A = append(arr.A, validation.VStr(s))
	}
	return arr
}

// containsStr is Python's `x in list`.
