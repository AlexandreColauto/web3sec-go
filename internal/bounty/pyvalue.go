// Python value emulation (str/int/float/slice semantics) shared by the
// policy engine and the gate checks.

package bounty

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"strconv"

	"websec/internal/validation"
)

// pyLower is str.lower() under the Python default locale — the same emulation
// findings uses (a plain strings.ToLower is not Python's case mapping).
var pyLower = cases.Lower(language.Und)

// fieldAt is (key in obj, obj[key]): the present-but-null case is distinct
// from the absent case.
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// getDefault is obj.get(key, def): the value when the key is present (a
// present null is NOT replaced), def when it is absent.
func getDefault(v validation.Value, key string, def validation.Value) validation.Value {
	if got, ok := fieldAt(v, key); ok {
		return got
	}
	return def
}

// pyTruthyBigNonEmpty is a DIVERGENT pyTruthy variant (Wave J Task 7), NOT the
// canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except that an Int with any non-empty Big
// text is truthy — including Big == "0", which validation.PyTruthy (and
// CPython) reads falsy. The divergence is reachable only for Values that
// violate jval's invariant that Big is set only when the integer does not fit
// int64.
func pyTruthyBigNonEmpty(v validation.Value) bool {
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

// pyStrAny is f-string interpolation of a value: str(v). A string is itself;
// everything else is the Python repr (which equals str for null, bool,
// numbers, lists and dicts).

// pyFloat is isinstance(v, (int, float)) as a float64 (bool included, as in
// Python; a big int is parsed best-effort).
func pyFloat(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return 0, false
			}
			return f, true
		}
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	case validation.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// pyListRepr renders a list of strings in Python's list-literal form
// (["a", "b"] with repr quoting), which is what an f-string prints.

// headRunes is s[:n] — a Python slice counts characters (runes).
func headRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
