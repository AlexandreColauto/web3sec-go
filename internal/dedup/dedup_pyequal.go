// dedup_pyequal.go: Python value-comparison semantics split out of dedup.go
// — same-spot tests and Python == over decoded JSON values.
package dedup

import (
	"math/big"
	"websec/internal/validation"
)

// sameSpot is the tier-2 same_spot test: the first affected path AND function
// match ((f.get("affected") or [{}])[0] on both sides).
func sameSpot(dup, keep validation.Value) bool {
	dupFirst, keepFirst := firstAffected(dup), firstAffected(keep)
	return pyEqual(validation.ObjAt(dupFirst, "path"), validation.ObjAt(keepFirst, "path")) &&
		pyEqual(validation.ObjAt(dupFirst, "function"), validation.ObjAt(keepFirst, "function"))
}

// firstAffected is (f.get("affected") or [{}])[0]: the first affected entry,
// or an empty object when affected is missing or empty (both fields then
// compare as Python None).
func firstAffected(f validation.Value) validation.Value {
	arr := validation.ObjAt(f, "affected")
	if arr.Kind == validation.Arr && len(arr.A) > 0 {
		return arr.A[0]
	}
	return validation.VObj()
}

// pyEqual is Python == on two decoded JSON values: numbers compare across
// int/float, containers element-wise, objects key-insensitively to order.
func pyEqual(a, b validation.Value) bool {
	if isNum(a) && isNum(b) {
		return ratOf(a).Cmp(ratOf(b)) == 0
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	case validation.Str:
		return a.S == b.S
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !pyEqual(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, kv := range a.O {
			if !pyEqual(kv.V, validation.ObjAt(b, kv.K)) {
				return false
			}
		}
		return true
	}
	return false
}

// isNum reports whether v is an int or a float (Python's numeric kinds).
func isNum(v validation.Value) bool {
	return v.Kind == validation.Int || v.Kind == validation.Flt
}

// ratOf is the exact rational value of a number (big ints included).
func ratOf(v validation.Value) *big.Rat {
	if v.Kind == validation.Flt {
		return new(big.Rat).SetFloat64(v.F)
	}
	text := validation.IntText(v)
	if r, ok := new(big.Rat).SetString(text); ok {
		return r
	}
	return new(big.Rat)
}

// pyStrip is Python's str.strip() with no argument: trim str.isspace()
// characters from both ends.

// pySpace is Py_UNICODE_ISSPACE: the Unicode White_Space property plus the
// ASCII file separators U+001C-U+001F (Python's str.isspace() says true
// there, unicode.IsSpace does not).
