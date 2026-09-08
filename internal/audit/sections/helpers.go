// Shared helpers for the audit section producers.
package sections

import (
	"sort"

	"websec/internal/validation"
)

// objAt is the object field lookup (Null when absent/non-object).
func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// objStr is the string field lookup ("" when absent/non-string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Str {
			return kv.V.S
		}
	}
	return ""
}

// mapStrSet builds a set from an array of string values (Python
// {e.get("ref") for e in events if ...}).
func mapStrSet(v validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range v.A {
		if item.Kind == validation.Str {
			out[item.S] = struct{}{}
		}
	}
	return out
}

// KV is the keyed KV constructor for section producers (audit no longer
// owns this: the sections package must not import the audit package so
// that audit and its in-package tests can depend on sections without an
// audit<->sections import cycle).
func KV(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// pyTruthy is Python truthiness for a decoded JSON value (None/False/0/""/
// []/{} are falsy; every other value is truthy).
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		if v.Big != "" {
			return v.Big != "0"
		}
		return v.I != 0
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

// pyStrValue is Python str(v): a string renders raw, everything else
// renders exactly like repr(v) (str and repr agree outside str).
func pyStrValue(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

// pyTypeName is Python type(v).__name__ for a decoded JSON value (used by
// the attribute-error mirror in the baselines section).
func pyTypeName(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "NoneType"
	case validation.Bool:
		return "bool"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Obj:
		return "dict"
	}
	return "object"
}

// strArrOf converts a []string to a JSON array of strings.
func strArrOf(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// strListOf is Python list(iterable-of-str) for a decoded array: non-string
// items are dropped (callers only use it on string lists).
func strListOf(v validation.Value) []string {
	var out []string
	for _, item := range v.A {
		if item.Kind == validation.Str {
			out = append(out, item.S)
		}
	}
	return out
}

// orEmptyObj is Python `x or {}`: a falsy value (None, {}, [], "", 0) folds
// to an empty object, a truthy one passes through.
func orEmptyObj(v validation.Value) validation.Value {
	if !pyTruthy(v) {
		return validation.VObj()
	}
	return v
}

// listOf is Python `x or []`: a falsy value folds to an empty array.
func listOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr || len(v.A) == 0 {
		return nil
	}
	return v.A
}

// sortedObjKeys is Python sorted(dict): the object's keys, ascending.
func sortedObjKeys(v validation.Value) []string {
	out := make([]string, 0, len(v.O))
	for _, kv := range v.O {
		out = append(out, kv.K)
	}
	sort.Strings(out)
	return out
}

// headStrs is Python `lst[:n]`.
func headStrs(items []string, n int) []string {
	if len(items) > n {
		return items[:n]
	}
	return items
}
