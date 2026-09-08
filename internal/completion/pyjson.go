// pyjson.go: the two CPython string routines the waivers log and the report
// stamp parser depend on — json.dumps(row, ensure_ascii=False) and
// str.splitlines().
package completion

import (
	"strings"

	"websec/internal/validation"
)

// pyJSONDumps is json.dumps(v, ensure_ascii=False): insertion order, the
// default ", " / ": " separators, raw non-ASCII, CPython's repr floats.
// (validation.CanonSpaced sorts keys and escapes non-ASCII — the events log
// wants that; the waivers log does not.)
func pyJSONDumps(v validation.Value) string {
	var b strings.Builder
	writePyJSON(&b, v)
	return b.String()
}

func writePyJSON(b *strings.Builder, v validation.Value) {
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
		writeRawEscaped(b, v.S)
		b.WriteByte('"')
	case validation.Arr:
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(", ")
			}
			writePyJSON(b, e)
		}
		b.WriteByte(']')
	case validation.Obj:
		b.WriteByte('{')
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteByte('"')
			writeRawEscaped(b, kv.K)
			b.WriteString("\": ")
			writePyJSON(b, kv.V)
		}
		b.WriteByte('}')
	}
}

// writeRawEscaped is json.dumps(ensure_ascii=False) string escaping: named
// escapes for " \ \b \f \n \r \t, \uXXXX for the remaining control
// characters; 0x7f and every non-ASCII rune stay raw.
func writeRawEscaped(b *strings.Builder, s string) {
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString("\\u00")
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
				continue
			}
			b.WriteRune(r)
		}
	}
}

// pySplitLines is str.splitlines(): the line boundaries are \n, \r, \r\n,
// \v, \f, \x1c-\x1e, \x85, U+2028 and U+2029, and a trailing boundary does
// not add an empty final line.
func pySplitLines(text string) []string {
	out := []string{}
	start := 0
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if !isLineBoundary(r) {
			continue
		}
		out = append(out, string(runes[start:i]))
		if r == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(runes) {
		out = append(out, string(runes[start:]))
	}
	return out
}

func isLineBoundary(r rune) bool {
	switch r {
	case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}
