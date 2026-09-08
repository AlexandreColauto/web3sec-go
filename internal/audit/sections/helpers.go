// Shared helpers for the audit section producers.
package sections

import "websec/internal/validation"

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
