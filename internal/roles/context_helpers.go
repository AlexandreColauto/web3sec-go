// context_helpers.go: the small shared Value helpers split out of context.go
// — or-empty projections, key removal, character-safe truncation.
package roles

import (
	"websec/internal/validation"
)

// ---- small shared helpers -------------------------------------------------

func orEmpty(v validation.Value, key string) validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Arr {
		return x
	}
	return validation.VArr()
}

func orEmptyObj(v validation.Value, key string) validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Obj {
		return x
	}
	return validation.VObj()
}

func removeKey(v validation.Value, key string) validation.Value {
	out := validation.VObj()
	for _, kv := range v.O {
		if kv.K != key {
			out.O = append(out.O, kv)
		}
	}
	return out
}

// truncate is Python's `s[:n]`: a CHARACTER slice, not a byte slice. The
// reference clips pattern/evidence_summary with `[:300]`/`[:200]`, so a
// multi-byte rune straddling the budget must not shorten the cut (the same
// rule roles.truncatedMarker documents for _bounded_json).
func truncate(s string, n int) string {
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func defaultedInt(v validation.Value, def int64) validation.Value {
	if v.Kind == validation.Int {
		return v
	}
	return validation.VInt(def)
}

func sameScalar(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I
	case validation.Null:
		return true
	}
	return false
}
