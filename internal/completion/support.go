// support.go: the value/file helpers shared by the completion proofs. The
// semantics are Python's, not Go's: falsiness, character slices, str.strip()
// and splitlines() all follow CPython so the proof text is byte-identical.
package completion

import (
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"websec/internal/state"
	"websec/internal/validation"
)

// kv is validation.KV{K: k, V: v} (non-test files cannot use the test kv()).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// objAt is v.get(key) for the object case (Null when absent/not an object).
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// fieldAt is (key in v, v[key]): present-but-null stays distinct.
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

// objStr is v.get(key) when it is a string ("" otherwise).
func objStr(v validation.Value, key string) string {
	f, ok := fieldAt(v, key)
	if !ok || f.Kind != validation.Str {
		return ""
	}
	return f.S
}

// listAt is v.get(key) when it is a list ([]Value otherwise).
func listAt(v validation.Value, key string) []validation.Value {
	f, ok := fieldAt(v, key)
	if !ok || f.Kind != validation.Arr {
		return nil
	}
	return f.A
}

// orEmpty is Python's `x or {}`: a falsy value becomes the empty object.
func orEmpty(v validation.Value) validation.Value {
	if !pyTruthyBigNonEmpty(v) {
		return validation.VObj()
	}
	return v
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

// strArr builds the list Value of strings (`[]` when empty, never null).
func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// strList reads a list Value as strings (non-strings become "").
func strList(v validation.Value) []string {
	if v.Kind != validation.Arr {
		return nil
	}
	out := make([]string, len(v.A))
	for i, e := range v.A {
		out[i] = e.S
	}
	return out
}

// headRunes is s[:n] — a Python slice counts characters, not bytes.
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

// pyStrip is str.strip(): CPython whitespace, which (unlike
// unicode.IsSpace) also includes the C0 separators \x1c-\x1f.
func pyStrip(s string) string {
	return strings.TrimFunc(s, isPySpace)
}

func isPySpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0:
		return true
	}
	// Zs / Zl / Zp are whitespace in Python too.
	return r == 0x1680 || r == 0x2028 || r == 0x2029 || r == 0x202f ||
		r == 0x205f || r == 0x3000 || (r >= 0x2000 && r <= 0x200a)
}

// pyStrAny is f-string interpolation of a value: str(v). A string is
// itself; every other value is its Python repr.
func pyStrAny(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

// kindName is the Python type name of a value ("list"/"dict"/"NoneType"),
// used for the unhashable-key TypeError text.
func kindName(v validation.Value) string {
	switch v.Kind {
	case validation.Arr:
		return "list"
	case validation.Obj:
		return "dict"
	case validation.Str:
		return "str"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Bool:
		return "bool"
	}
	return "NoneType"
}

// pyLen is len(str): CPython counts characters.
func pyLen(s string) int { return utf8.RuneCountInString(s) }

// fileExists is path.exists() for a regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// dirExists is path.exists() for a directory.
func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// nowIso is now_iso (state's is unexported; snapshot and findings carry the
// same copy). The WEBV2_NOW golden-suite clock pin is honored identically.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return now.Format("2006-01-02T15:04:05") + "." +
		pad6(now.Nanosecond()/1000) + "+00:00"
}

func pad6(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

// campaignDir is campaign.dir (state.Campaign keeps it as a field).
func campaignDir(c *state.Campaign) string { return c.Dir }
