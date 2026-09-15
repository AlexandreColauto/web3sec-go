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
// characters; 0x7f and every other non-ASCII rune stay raw — with the three
// documented exceptions below.
//
// r40c P2-3: 0x85 (NEL), U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH
// SEPARATOR) are escaped as well, and that is a deliberate deviation from
// json.dumps(ensure_ascii=False). The bytes pyJSONDumps produces land in
// waivers.jsonl, a LINE-framed JSONL file, and those three runes are raw in
// CPython's output while str.splitlines() counts each of them a LINE
// BOUNDARY. So the writer could emit a row that the framing turns into two:
// the first fragment stopped mid-string and every splitlines reader died on
// it with a bare JSON error, while verify's "\n"-only reader saw one clean
// row — the two readers disagreed about the same bytes and the waiver was
// recorded, reported as success, and never consulted. "\uXXXX" is the SAME
// string value to every JSON reader (Go's encoding/json and CPython's
// json.loads decode it identically), so escaping changes nothing any
// consumer of the value sees; it only keeps one row on one physical line
// under BOTH framings. The other splitlines boundaries (\n, \r, \v, \f,
// \x1c-\x1e) are already < 0x20 and escaped above, so these three were the
// only raw survivors; 0x7f and every other non-ASCII rune — the em-dash the
// golden replay pins — stay raw.
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
			if r < 0x20 || r == 0x85 || r == 0x2028 || r == 0x2029 {
				writeUnicodeEscape(b, r)
				continue
			}
			b.WriteRune(r)
		}
	}
}

// writeUnicodeEscape writes CPython's json \uXXXX escape form (lower-case
// hex, four digits) for one rune.
func writeUnicodeEscape(b *strings.Builder, r rune) {
	const hex = "0123456789abcdef"
	b.WriteString("\\u")
	b.WriteByte(hex[(r>>12)&0xf])
	b.WriteByte(hex[(r>>8)&0xf])
	b.WriteByte(hex[(r>>4)&0xf])
	b.WriteByte(hex[r&0xf])
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
