package validation

import (
	"math"
	"testing"
)

// TestPyReprString pins CPython 3.14 str repr: quote selection and the
// escape table (\\, active quote, \n \t \r named; \xNN / \uNNNN /
// \UNNNNNNNN for non-printables; printable non-ASCII raw).
func TestPyReprString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`a'b`, `"a'b"`},
		{`a"b`, `'a"b'`},
		{`a'b"c`, `'a\'b"c'`},
		{"", `''`},
		{"tab\there", `'tab\there'`},
		{"nl\nhere", `'nl\nhere'`},
		{"cr\rhere", `'cr\rhere'`},
		{"bs\bhere", `'bs\x08here'`},
		{"ff\fhere", `'ff\x0chere'`},
		{"vt\vhere", `'vt\x0bhere'`},
		{"nul\x00here", `'nul\x00here'`},
		{"del\x7fhere", `'del\x7fhere'`},
		{"ctrl\x01here", `'ctrl\x01here'`},
		{"nbs\u00a0x", `'nbs\xa0x'`},
		{"copy©x", `'copy©x'`},
		{"y\u00ffx", `'yÿx'`},
		{"ls\u2028x", `'ls\u2028x'`},
		{"ps\u2029x", `'ps\u2029x'`},
		{"ar\u0627\u0644\u0639", `'arالع'`},
		{"em\U0001f600x", "'em\U0001f600x'"},
		{"back\\slash", `'back\\slash'`},
		{"~!@#$%^&*()_+{}|:;<>,.?/", `'~!@#$%^&*()_+{}|:;<>,.?/'`},
		{"'only-double", `"'only-double"`},
		{`"only-single`, `'"only-single'`},
		{"both'and\"", `'both\'and"'`},
	}
	for _, c := range cases {
		if got := PyReprStr(c.in); got != c.want {
			t.Errorf("PyReprStr(%q):\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// TestPyReprScalars pins the non-string forms.
func TestPyReprScalars(t *testing.T) {
	cases := []struct {
		v    Value
		want string
	}{
		{VNull(), "None"},
		{VBool(true), "True"},
		{VBool(false), "False"},
		{VInt(0), "0"},
		{VInt(-42), "-42"},
		{VFloat(1.0), "1.0"},
		{VFloat(3.14), "3.14"},
		{VFloat(math.Copysign(0, -1)), "-0.0"},
		{VArr(VInt(1), VStr("a")), "[1, 'a']"},
		{VArr(), "[]"},
		{VObj(KV{K: "k", V: VInt(1)}), `{'k': 1}`},
		{VObj(), "{}"},
		{VObj(KV{K: "a", V: VNull()}, KV{K: "b", V: VBool(true)}), `{'a': None, 'b': True}`},
	}
	for _, c := range cases {
		if got := PyRepr(c.v); got != c.want {
			t.Errorf("PyRepr(%v):\n got %q\nwant %q", c.v, got, c.want)
		}
	}
}

// TestPyReprTuple pins the tuple repr used in the unknown-schema error.
func TestPyReprTuple(t *testing.T) {
	if got := pyReprTuple([]string{"a", "b"}); got != "('a', 'b')" {
		t.Errorf("got %q", got)
	}
	if got := pyReprTuple(nil); got != "()" {
		t.Errorf("got %q", got)
	}
}
