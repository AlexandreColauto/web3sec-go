// helpers.go: the small Python-shaped accessors briefing shares with the
// rest of the port (each package keeps its own copy, like the Python
// modules keep their own imports).
package briefing

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func setKey(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
}

func objBool(v validation.Value, key string) bool {
	f := validation.ObjAt(v, key)
	return f.Kind == validation.Bool && f.B
}

func listAt(v validation.Value, key string) []validation.Value {
	f := validation.ObjAt(v, key)
	if f.Kind != validation.Arr {
		return nil
	}
	return f.A
}

func intField(v validation.Value, key string) int64 {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

func floatOf(v validation.Value) float64 {
	switch v.Kind {
	case validation.Int:
		return float64(v.I)
	case validation.Flt:
		return v.F
	case validation.Bool:
		if v.B {
			return 1
		}
	}
	return 0
}

func intPtr(v validation.Value) *int64 {
	if v.Kind != validation.Int {
		return nil
	}
	out := v.I
	return &out
}

// pyTruthyInt64Only is a DIVERGENT pyTruthy variant (Wave J Task 7), NOT the
// canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except that an Int reads only the int64
// field I and ignores Big — so an integer that overflowed int64 (Big set,
// I == 0) reads FALSE where validation.PyTruthy reads it true.
func pyTruthyInt64Only(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
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

func strListOf(v validation.Value) []string {
	if v.Kind != validation.Arr {
		return nil
	}
	out := []string{}
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		} else {
			out = append(out, validation.PyRepr(e))
		}
	}
	return out
}

func subsetOf(sub, super []string) bool {
	set := map[string]bool{}
	for _, s := range super {
		set[s] = true
	}
	for _, s := range sub {
		if !set[s] {
			return false
		}
	}
	return true
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func pyListRepr(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func nullableStrEqual(v validation.Value, s *string) bool {
	if v.Kind == validation.Null || s == nil {
		return v.Kind == validation.Null && s == nil
	}
	return v.Kind == validation.Str && v.S == *s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptrOrNull(v *validation.Value) validation.Value {
	if v == nil {
		return validation.VNull()
	}
	return *v
}

func orQuestion(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func valueText(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// pyCommaFloat is Python's f"{v:,.2f}" / f"{v:,.0f}" — thousands separators,
// fixed decimals, banker's-free rounding (FormatFloat rounds half away from
// zero; the call sites only ever render money already rounded).
func pyCommaFloat(v float64, decimals int) string {
	s := strconv.FormatFloat(v, 'f', decimals, 64)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart := s
	frac := ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i:]
	}
	var b strings.Builder
	for i, c := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	out := b.String() + frac
	if neg {
		out = "-" + out
	}
	return out
}

var _ = fmt.Sprintf

func objInt(v validation.Value, key string) int64 {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}
