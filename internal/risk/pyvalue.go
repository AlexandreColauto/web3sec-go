// Risk — Python-value helpers: field access, numeric coercion and money formatting shared by the risk passes (split from risk.go; pure structural move).

package risk

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"math/big"
	"unicode/utf8"
	"websec/internal/validation"
)

// fieldAt is d.get(key) with presence: (value, true) also for a present null.
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// orObj is Python's `v or {}` for the object fields read by the banding
// helpers: a missing/null/falsy value reads as an empty object.
func orObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// orStr is Python's `v or ""` for the text fields.
func orStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// isNoneField is `d.get(key) is None`: absent or present-null.
func isNoneField(v validation.Value, key string) bool {
	got, ok := fieldAt(v, key)
	return !ok || got.Kind == validation.Null
}

// snapshotSource is f.get("snapshot_ids", {}).get("source").
func snapshotSource(f validation.Value) validation.Value {
	return validation.ObjAt(orObj(validation.ObjAt(f, "snapshot_ids")), "source")
}

// idTail is new_id(prefix, n).split("-")[1].
func idTail(id string) string {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// ensureObjField is dict.setdefault(key, {}): the index of key in o, with an
// empty object appended when absent. A present non-object value reproduces
// Python's TypeError on the following item assignment.
func ensureObjField(o *[]validation.KV, key string) (int, error) {
	for i := range *o {
		if (*o)[i].K == key {
			if (*o)[i].V.Kind != validation.Obj {
				return 0, fmt.Errorf("'%s' object does not support item "+
					"assignment", pyTypeName((*o)[i].V))
			}
			return i, nil
		}
	}
	*o = append(*o, validation.KV{K: key, V: validation.VObj()})
	return len(*o) - 1, nil
}

// setFloatField is d[key] = float(v), skipped for Python None.
func setFloatField(o *[]validation.KV, key string, v validation.Value) error {
	if v.Kind == validation.Null {
		return nil
	}
	f, err := asFloat(v)
	if err != nil {
		return err
	}
	*o = validation.SetOrAppend(*o, key, validation.VFloat(f))
	return nil
}

// popKey is dict.pop(key, None): drop the key, keeping the order of the rest.
func popKey(o []validation.KV, key string) []validation.KV {
	for i := range o {
		if o[i].K == key {
			return append(o[:i:i], o[i+1:]...)
		}
	}
	return o
}

// optNum is Python Optional[float] as a Value.
func optNum(f *float64) validation.Value {
	if f == nil {
		return validation.VNull()
	}
	return validation.VFloat(*f)
}

// optNumAt is (obj.get(key) or 0) as a float, plus "the key was present and
// not None". Falsy scalars (0, 0.0, "", false) read as 0.
func optNumAt(obj validation.Value, key string) (float64, bool, error) {
	v, ok := fieldAt(obj, key)
	if !ok || v.Kind == validation.Null {
		return 0, false, nil
	}
	if !pyTruthyBigNonEmpty(v) {
		return 0, true, nil
	}
	f, err := asFloat(v)
	if err != nil {
		return 0, true, err
	}
	return f, true, nil
}

// numOrZero is `v or 0` as a float for the comparison helpers.
func numOrZero(v validation.Value) float64 {
	if !pyTruthyBigNonEmpty(v) {
		return 0
	}
	f, err := asFloat(v)
	if err != nil {
		return 0 // schema-typed number; Python would raise TypeError
	}
	return f
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

// pyLen is Python len(v) for the sequence kinds (str counts code points).
func pyLen(v validation.Value) int {
	switch v.Kind {
	case validation.Arr:
		return len(v.A)
	case validation.Obj:
		return len(v.O)
	case validation.Str:
		return utf8.RuneCountInString(v.S)
	}
	return 0
}

// pyStr is Python str(v) for the JSON scalar kinds.

// pyTypeName is type(v).__name__ for the JSON kinds.
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

// asFloat is Python float(v) for the JSON scalar kinds; the error text
// mirrors CPython's ValueError / TypeError wording.
func asFloat(v validation.Value) (float64, error) {
	switch v.Kind {
	case validation.Flt:
		return v.F, nil
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return 0, fmt.Errorf("int too large to convert to float")
			}
			return f, nil
		}
		return float64(v.I), nil
	case validation.Bool:
		if v.B {
			return 1, nil
		}
		return 0, nil
	case validation.Str:
		f, err := strconv.ParseFloat(validation.PyStrip(v.S), 64)
		if err != nil {
			return 0, fmt.Errorf("could not convert string to float: %s",
				validation.PyReprStr(v.S))
		}
		return f, nil
	}
	return 0, fmt.Errorf("float() argument must be a string or a real "+
		"number, not '%s'", pyTypeName(v))
}

// pyUsd0f is Python's f"{x:,.0f}": thousands-grouped, zero decimals,
// round-half-even on the exact binary value (so 0.5 -> "0", 99_999.5 ->
// "100,000"), with CPython's nan/inf spellings and a signed "-0".
func pyUsd0f(x float64) string {
	switch {
	case math.IsNaN(x):
		return "nan"
	case math.IsInf(x, 1):
		return "inf"
	case math.IsInf(x, -1):
		return "-inf"
	}
	r := validation.PythonRound(x, 0)
	neg := math.Signbit(r)
	if r == 0 {
		if neg {
			return "-0"
		}
		return "0"
	}
	i, _ := new(big.Float).SetFloat64(math.Abs(r)).Int(nil)
	digits := groupThousands(i.String())
	if neg {
		return "-" + digits
	}
	return digits
}

// groupThousands inserts "," every three digits from the right.
func groupThousands(digits string) string {
	if len(digits) <= 3 {
		return digits
	}
	var b strings.Builder
	lead := len(digits) % 3
	if lead > 0 {
		b.WriteString(digits[:lead])
	}
	for i := lead; i < len(digits); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[i : i+3])
	}
	return b.String()
}

// pyStrip is Python's str.strip() with no argument: trim str.isspace()
// characters from both ends.

// pySpace is Py_UNICODE_ISSPACE: the Unicode White_Space property plus the
// ASCII file separators U+001C-U+001F (Python's str.isspace() says true
// there, unicode.IsSpace does not).
