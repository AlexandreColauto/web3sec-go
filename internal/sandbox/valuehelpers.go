// valuehelpers.go: small validation.Value helpers shared by the exec flows.
package sandbox

import (
	"sort"
	"websec/internal/validation"
)

// --- small value helpers ---------------------------------------------------

func truthy(v validation.Value, key string) bool {
	f := validation.ObjAt(v, key)
	return f.Kind == validation.Bool && f.B
}

func optStrValue(p *string) validation.Value {
	if p == nil {
		return validation.VNull()
	}
	return validation.VStr(*p)
}

func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := validation.Value{Kind: validation.Obj, O: append(
		[]validation.KV(nil), v.O...)}
	for i := range out.O {
		if out.O[i].K == key {
			out.O[i].V = val
			return out
		}
	}
	out.O = append(out.O, validation.KV{K: key, V: val})
	return out
}

// pyListRepr renders Python's repr of a list of strings ("['a', 'b']").
func pyListRepr(v validation.Value) string {
	items := make([]validation.Value, 0, len(v.A))
	items = append(items, v.A...)
	return validation.PyRepr(validation.VArr(items...))
}

func envKeyValues(env []EnvVar) []validation.Value {
	keys := make([]string, 0, len(env))
	for _, e := range env {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return envKeyValues2(keys)
}

func envKeyValues2(keys []string) []validation.Value {
	out := make([]validation.Value, 0, len(keys))
	for _, k := range keys {
		out = append(out, validation.VStr(k))
	}
	return out
}
