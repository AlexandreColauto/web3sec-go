// pystr.go: the Python-semantics string helpers that ~27 packages re-inlined.
//
// These sit next to PyRepr/PythonFloat/Canon because they are the same kind of
// thing: a formatter whose exact bytes are part of the frozen output surface.
// Each one below is byte-identical to every clone it replaced — the clones
// differed only in spelling (a spelled-out scalar switch versus the minimal
// form) or in naming the whitespace predicate differently.

package validation

import (
	"strings"
	"unicode"
)

// PyStr is Python's str(v): a string is itself, every other kind is its Python
// repr. The spelled-out clones listed Null/Bool/Int/Flt by hand, which is
// exactly what PyRepr returns for those kinds, so the minimal form is the same
// function. Clones that fell through to CanonCompact are NOT this function and
// were left alone: that renders compact canonical JSON, not a Python repr.
func PyStr(v Value) string {
	if v.Kind == Str {
		return v.S
	}
	return PyRepr(v)
}

// PyListRepr is repr() of a list of strings: "[" + repr each + "]".
func PyListRepr(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = PyReprStr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// PyStrip is str.strip() with Python's whitespace set.
func PyStrip(s string) string {
	return strings.TrimFunc(s, PyIsSpace)
}

// PyIsSpace is Python's whitespace test: Go's unicode.IsSpace (which already
// covers U+0085, U+00A0 and the Zs/Zl/Zp set one clone listed by hand) plus the
// four C1 separators U+001C..U+001F, which Python counts as whitespace and Go
// does not.
func PyIsSpace(r rune) bool {
	if r >= 0x1c && r <= 0x1f {
		return true
	}
	return unicode.IsSpace(r)
}
