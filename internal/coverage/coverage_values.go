// coverage_values.go: Python value helpers — dict membership, indexing with
// KeyError text, defaulted reads.
package coverage

import (
	"fmt"

	"websec/internal/validation"
)

// ---- Python value helpers ------------------------------------------------

// kv is the vet-clean keyed KV constructor.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// lookup is the `key in dict` + indexing pair: found reports whether the key
// is PRESENT (a present null is not the same as an absent key).
func lookup(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V, true
		}
	}
	return validation.VNull(), false
}

// reqKey is dict[key]: the value, or Python's str(KeyError(key)) when the key
// is absent (the repr of the key name — what the CLI prints).
func reqKey(v validation.Value, key string) (validation.Value, error) {
	val, ok := lookup(v, key)
	if !ok {
		return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(key))
	}
	return val, nil
}

// listField is dict.get(key, []): the array's elements, empty when the key is
// absent or the value is not an array.
func listField(v validation.Value, key string) []validation.Value {
	return validation.ObjAt(v, key).A
}

// getOr is dict.get(key, default): the default only when the key is ABSENT.
func getOr(v validation.Value, key string, def validation.Value) validation.Value {
	if val, ok := lookup(v, key); ok {
		return val
	}
	return def
}
