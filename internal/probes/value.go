// Package probes is the port of webv2/probes.py (2,192 lines): the six
// structural probes that turn a structural index + protocol model into the
// candidate surface. A row is an OBLIGATION TO LOOK — it sets no finding
// status, mints no hypothesis and costs no FP budget.
//
// Rows are ordered validation.Value objects (Python dicts), because the
// surface is written to JSON with insertion-order keys and hashed with
// canonical JSON; the helpers here are the dict operations the Python module
// performs.
package probes

import (
	"sort"
	"strings"
	"unicode"

	"websec/internal/validation"
)

// vGet is v.get(key): a missing key (or non-object) is None.
func vGet(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V
		}
	}
	return validation.VNull()
}

// vHas is `key in v`.
func vHas(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return true
		}
	}
	return false
}

// vSet is `v[key] = value` on an ordered dict: an existing key keeps its
// position, a new key is appended.
func vSet(v *validation.Value, key string, val validation.Value) {
	if v.Kind != validation.Obj {
		*v = validation.VObj()
	}
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
}

// vDel is `v.pop(key, None)`.
func vDel(v *validation.Value, key string) {
	if v.Kind != validation.Obj {
		return
	}
	for i := range v.O {
		if v.O[i].K == key {
			v.O = append(v.O[:i:i], v.O[i+1:]...)
			return
		}
	}
}

// vStr is v.get(key) as a string ("" when absent or non-string).
func vStr(v validation.Value, key string) string {
	got := vGet(v, key)
	if got.Kind == validation.Str {
		return got.S
	}
	return ""
}

// vInt is v.get(key) as an int (0 when absent or non-numeric).
func vInt(v validation.Value, key string) int {
	got := vGet(v, key)
	if got.Kind == validation.Int {
		if got.Big != "" {
			return 0
		}
		return int(got.I)
	}
	return 0
}

// vBool is v.get(key) as a bool (false when absent or non-bool).
func vBool(v validation.Value, key string) bool {
	got := vGet(v, key)
	return got.Kind == validation.Bool && got.B
}

// vList is `v.get(key) or []`.
func vList(v validation.Value, key string) []validation.Value {
	got := vGet(v, key)
	if got.Kind != validation.Arr {
		return nil
	}
	return got.A
}

// vStrList is `v.get(key) or []` as strings.
func vStrList(v validation.Value, key string) []string {
	items := vList(v, key)
	if items == nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it.Kind == validation.Str {
			out = append(out, it.S)
		}
	}
	return out
}

// vStrSet is set(v.get(key) or []).
func vStrSet(v validation.Value, key string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range vStrList(v, key) {
		out[s] = struct{}{}
	}
	return out
}

// vObjList is the object elements of `v.get(key) or []`.
func vObjList(v validation.Value, key string) []validation.Value {
	items := vList(v, key)
	out := make([]validation.Value, 0, len(items))
	for _, it := range items {
		if it.Kind == validation.Obj {
			out = append(out, it)
		}
	}
	return out
}

// vTruthy is Python truthiness over JSON-shaped values.
func vTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.Big != "" || v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// pyStr is str(v) for the JSON-shaped subset.
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	}
	return validation.PyRepr(v)
}

// intArr is a JSON array of ints.
func intArr(items []int) validation.Value {
	out := make([]validation.Value, len(items))
	for i, n := range items {
		out[i] = validation.VInt(int64(n))
	}
	return validation.VArr(out...)
}

// sortedKeys is sorted(map).
func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedStrSet is sorted(set).
func sortedStrSet(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedStrings is Python's sorted() over a copy of the slice.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// strip is Python str.strip(): the Unicode whitespace property plus the four
// ASCII information separators Python also treats as whitespace.
func strip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		if r >= 0x1c && r <= 0x1f {
			return true
		}
		return unicode.IsSpace(r)
	})
}
