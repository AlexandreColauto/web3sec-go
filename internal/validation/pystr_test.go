package validation

import (
	"strings"
	"testing"
)

// TestPyStrMatchesTheSpelledOutClones is the proof that folding the pyStr
// family was safe. The clones either wrote the minimal form — which is this
// implementation verbatim — or spelled the scalar cases out by hand. Those
// spelled-out cases are asserted here against PyStr for every kind, so if
// PyRepr ever stops returning None/True/False/IntText/PythonFloat for a
// scalar, this test fails instead of a golden drifting silently.
func TestPyStrMatchesTheSpelledOutClones(t *testing.T) {
	spelled := func(v Value) string {
		switch v.Kind {
		case Null:
			return "None"
		case Bool:
			if v.B {
				return "True"
			}
			return "False"
		case Int:
			return IntText(v)
		case Flt:
			return PythonFloat(v.F)
		case Str:
			return v.S
		}
		return PyRepr(v)
	}
	values := []Value{
		VNull(), VBool(true), VBool(false), VInt(0), VInt(-7), VFloat(1.5), VFloat(0),
		VStr(""), VStr("text"), VArr(VStr("a"), VInt(1)), VObj(KV{K: "k", V: VStr("v")}),
	}
	for _, v := range values {
		if got, want := PyStr(v), spelled(v); got != want {
			t.Errorf("PyStr(kind=%v) = %q, spelled-out clone = %q", v.Kind, got, want)
		}
	}
	// The defining property: a string is itself, not its repr.
	if got := PyStr(VStr("text")); got != "text" {
		t.Errorf("PyStr of a string must be unquoted, got %q", got)
	}
	if got := PyRepr(VStr("text")); got != `'text'` {
		t.Errorf("PyRepr of a string must be quoted, got %q", got)
	}
}

// TestPyListReprAndStripMatchTheClones covers the other two families,
// including the PyRepr(StrArr(...)) spelling that had to agree with the
// manual join.
func TestPyListReprAndStripMatchTheClones(t *testing.T) {
	manual := func(items []string) string {
		parts := make([]string, 0, len(items))
		for _, s := range items {
			parts = append(parts, PyReprStr(s))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	for _, items := range [][]string{nil, {}, {"a"}, {"a", "b,c"}, {""}} {
		if got, want := PyListRepr(items), manual(items); got != want {
			t.Errorf("PyListRepr(%q) = %q, manual = %q", items, got, want)
		}
		if got, want := PyListRepr(items), PyRepr(StrArr(items)); got != want {
			t.Errorf("PyListRepr(%q) = %q, PyRepr(StrArr(...)) = %q", items, got, want)
		}
	}
	// str.strip(): Python's whitespace set, which includes U+001C..U+001F.
	for _, tc := range []struct{ in, want string }{
		{"  x  ", "x"}, {"\t\nx\r", "x"}, {"\x1cx\x1f", "x"}, {"x", "x"}, {"", ""},
		{"\u00a0x\u00a0", "x"},
	} {
		if got := PyStrip(tc.in); got != tc.want {
			t.Errorf("PyStrip(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The predicate: unicode.IsSpace plus the C1 separators.
	for _, tc := range []struct {
		r    rune
		want bool
	}{{' ', true}, {'\t', true}, {'\u00a0', true}, {'\u0085', true},
		{0x1c, true}, {0x1f, true}, {'x', false}, {0x200b, false}, {0x1b, false}} {
		if got := PyIsSpace(tc.r); got != tc.want {
			t.Errorf("PyIsSpace(%U) = %v, want %v", tc.r, got, tc.want)
		}
	}
}
