package chainengine

// The leanness merge (wave F, 2026-09-10): the local json.dumps twin
// (spaced separators ", " / ": ", insertion order, ensure_ascii=True — the
// encoding of dedup_meta's members/capability_links/terminal fields) was
// deleted from values.go in favor of validation.CanonSpaced. The reference
// implementation below IS the deleted code, kept as the permanent
// equivalence proof: if the canonical encoder ever drifts from the bytes
// these fields recorded, this test fails before any campaign does.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/validation"
)

// pyJSONDump is json.dumps(v) with the default separators (", " / ": "),
// insertion order and ensure_ascii=True — the encoding of dedup_meta's
// members/capability_links/terminal fields.
func legacyJSONDump(v validation.Value) string {
	var b strings.Builder
	legacyWriteDump(&b, v)
	return b.String()
}

func legacyWriteDump(b *strings.Builder, v validation.Value) {
	switch v.Kind {
	case validation.Null:
		b.WriteString("null")
	case validation.Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case validation.Int:
		b.WriteString(validation.IntText(v))
	case validation.Flt:
		b.WriteString(validation.PythonFloat(v.F))
	case validation.Str:
		legacyWriteDumpStr(b, v.S)
	case validation.Arr:
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(", ")
			}
			legacyWriteDump(b, e)
		}
		b.WriteByte(']')
	case validation.Obj:
		b.WriteByte('{')
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(", ")
			}
			legacyWriteDumpStr(b, kv.K)
			b.WriteString(": ")
			legacyWriteDump(b, kv.V)
		}
		b.WriteByte('}')
	}
}

// writeDumpStr is json.dumps' ensure_ascii=True string escaping.
func legacyWriteDumpStr(b *strings.Builder, s string) {
	const hexd = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r < 0x20 || r == 0x7f:
			b.WriteString("\\u00")
			b.WriteByte(hexd[(r>>4)&0xf])
			b.WriteByte(hexd[r&0xf])
		case r <= 0x7e:
			b.WriteRune(r)
		default:
			if r > 0xffff {
				r2 := r - 0x10000
				validation.WriteU4(b, 0xd800+rune(r2>>10&0x3ff))
				validation.WriteU4(b, 0xdc00+rune(r2&0x3ff))
			} else {
				validation.WriteU4(b, r)
			}
		}
		i += size
	}
	b.WriteByte('"')
}

// ---- the equivalence proof ------------------------------------------------

func dumpSamples() []validation.Value {
	out := []validation.Value{
		validation.VObj(validation.KV{K: "a", V: validation.VInt(1)},
			validation.KV{K: "b", V: validation.VStr("x")}),
		validation.VObj(),
		validation.VArr(validation.VInt(1), validation.VNull(), validation.VBool(true)),
		validation.VObj(validation.KV{K: "k", V: validation.VFloat(1.5)}),
		validation.VObj(validation.KV{K: "k", V: validation.VBigInt("12345678901234567890")}),
		validation.VObj(validation.KV{K: "nested", V: validation.VObj(
			validation.KV{K: "arr", V: validation.VArr(
				validation.VStr("q\""), validation.VFloat(1e21))})}),
		validation.VFloat(1e300), validation.VFloat(-0.0),
		validation.VStr("tab\tnewline\ncarriage\r backspace\b form\f quote\" backslash\\"),
	}
	for cp := rune(0); cp <= 0xFFFF; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF {
			continue
		}
		s := string(cp)
		out = append(out,
			validation.VStr(s),
			validation.VObj(validation.KV{K: s, V: validation.VStr("x" + s + "y")}),
			validation.VArr(validation.VStr("a\""+s+"\\"), validation.VInt(7)),
		)
	}
	for _, cp := range []rune{0x10000, 0x1F600, 0x10FFFF} {
		out = append(out, validation.VStr(string(rune(0x1F600))+string(cp)))
	}
	return out
}

func TestLegacyDumpEquivalence(t *testing.T) {
	n := 0
	for _, v := range dumpSamples() {
		a := legacyJSONDump(v)
		c := validation.CanonSpaced(v)
		if a != c {
			t.Fatalf("encoders drifted at sample %d:\n  legacy=%q\n  canon =%q", n, a, c)
		}
		n++
	}
	t.Logf("%d sampled values encode identically", n)
}
