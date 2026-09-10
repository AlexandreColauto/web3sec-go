package cli

// The leanness merge (wave F, 2026-09-10): the local json.dumps(indent=2,
// ensure_ascii=True) pretty-printer (CLI --json rendering) was deleted from
// cli.go in favor of validation.DumpIndentedASCII. The reference below IS
// the deleted code; TestLegacyPrettyEquivalence proves the two encoders
// agree on every BMP codepoint and every shape the CLI renders.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/validation"
)

// --- prettyASCII: json.dumps(v, indent=2) byte-exact ----------------------
// Insertion order, 2-space indent, ensure_ascii=True escaping (CPython
// indent mode uses item separator ',' + newline and key separator ': ').

func legacyPrettyASCII(v validation.Value) string {
	var b strings.Builder
	legacyWritePretty(&b, v, 0)
	return b.String()
}

func legacyWritePretty(b *strings.Builder, v validation.Value, depth int) {
	pad := strings.Repeat("  ", depth)
	inner := pad + "  "
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
		b.WriteByte('"')
		legacyWriteASCIIEscape(b, v.S)
		b.WriteByte('"')
	case validation.Arr:
		if len(v.A) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			legacyWritePretty(b, e, depth+1)
		}
		b.WriteString("\n" + pad + "]")
	case validation.Obj:
		if len(v.O) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			b.WriteByte('"')
			legacyWriteASCIIEscape(b, kv.K)
			b.WriteString("\": ")
			legacyWritePretty(b, kv.V, depth+1)
		}
		b.WriteString("\n" + pad + "}")
	}
}

const hexd = "0123456789abcdef"

// writeASCIIEscape is CPython ensure_ascii=True string escaping (matches
// validation's canonical escaper; DEL 0x7f is escaped, unlike the raw
// indented dump).
func legacyWriteASCIIEscape(b *strings.Builder, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			validation.WriteU4(b, r)
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
}

func prettySamples() []validation.Value {
	out := []validation.Value{
		validation.VObj(validation.KV{K: "a", V: validation.VInt(1)}),
		validation.VObj(), validation.VArr(),
		validation.VArr(validation.VObj(validation.KV{K: "x", V: validation.VStr("é")})),
		validation.VFloat(1.5), validation.VBigInt("99999999999999999999"),
		validation.VBool(true), validation.VNull(),
		validation.VObj(validation.KV{K: "n", V: validation.VObj(
			validation.KV{K: "arr", V: validation.VArr(validation.VStr("q\""),
				validation.VFloat(1e21))})}),
	}
	for cp := rune(0); cp <= 0xFFFF; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF {
			continue
		}
		s := string(cp)
		out = append(out,
			validation.VStr("x"+s+"y"),
			validation.VObj(validation.KV{K: s, V: validation.VNull()}),
			validation.VArr(validation.VStr("a\""+s+"\\")),
		)
	}
	for _, cp := range []rune{0x10000, 0x1F600, 0x10FFFF} {
		out = append(out, validation.VStr(string(rune(0x1F600))+string(cp)))
	}
	return out
}

func TestLegacyPrettyEquivalence(t *testing.T) {
	n := 0
	for _, v := range prettySamples() {
		if legacyPrettyASCII(v) != validation.DumpIndentedASCII(v) {
			t.Fatalf("encoders drifted at sample %d:\n  legacy=%q\n  canon =%q",
				n, legacyPrettyASCII(v), validation.DumpIndentedASCII(v))
		}
		n++
	}
	t.Logf("%d sampled values encode identically", n)
}

var _ = strings.Repeat
