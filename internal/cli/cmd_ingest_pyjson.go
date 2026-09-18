package cli

// cmd_ingest_pyjson: the CPython-compatible JSON error scanner — a
// faithful port of json/decoder.py + json/scanner.py so the CLI's JSON
// error lines match Python's byte for byte (moved verbatim from
// cmd_ingest.go).
import (
	"fmt"
	"regexp"
	"strings"
)

// ---- schema-walked enum legend (validation.schema_enum_legend) ------------

// ---- CPython-compatible JSON error text -----------------------------------

// t14PyJSONError reproduces CPython's json.JSONDecodeError text for doc, or
// "" when doc decodes. Go's encoding/json reports a different shape ("invalid
// character 'b' looking for beginning of object key string"); the CLI's
// error lines are Python's, so the scanner below is a faithful port of
// json/decoder.py + json/scanner.py (positions are code points).
func t14PyJSONError(doc string) string {
	runes := []rune(doc)
	pos, msg := t14PyJSONDecode(runes)
	if msg == "" {
		return ""
	}
	if pos > len(runes) {
		pos = len(runes)
	}
	head := string(runes[:pos])
	line := 1 + strings.Count(head, "\n")
	col := pos - strings.LastIndex(head, "\n")
	return fmt.Sprintf("%s: line %d column %d (char %d)", msg, line, col, pos)
}

// t14PyJErr is CPython's JSONDecodeError payload (message + position).
type t14PyJErr struct {
	msg string
	pos int
}

// t14PyJSONDecode is JSONDecoder.decode: leading whitespace, one value, then
// trailing whitespace only.
func t14PyJSONDecode(s []rune) (int, string) {
	end, jerr := t14PyScanOnce(s, t14SkipWS(s, 0))
	if jerr != nil {
		return jerr.pos, jerr.msg
	}
	end = t14SkipWS(s, end)
	if end != len(s) {
		return end, "Extra data"
	}
	return 0, ""
}

// t14PyScanOnce is scanner._scan_once: the value at idx, or StopIteration(idx)
// as "Expecting value".
func t14PyScanOnce(s []rune, idx int) (int, *t14PyJErr) {
	if idx >= len(s) {
		return 0, &t14PyJErr{msg: "Expecting value", pos: idx}
	}
	switch {
	case s[idx] == '"':
		return t14PyScanString(s, idx+1)
	case s[idx] == '{':
		return t14PyObject(s, idx+1)
	case s[idx] == '[':
		return t14PyArray(s, idx+1)
	case s[idx] == 'n' && t14Runes(s, idx, idx+4) == "null":
		return idx + 4, nil
	case s[idx] == 't' && t14Runes(s, idx, idx+4) == "true":
		return idx + 4, nil
	case s[idx] == 'f' && t14Runes(s, idx, idx+5) == "false":
		return idx + 5, nil
	case s[idx] == 'N' && t14Runes(s, idx, idx+3) == "NaN":
		return idx + 3, nil
	case s[idx] == 'I' && t14Runes(s, idx, idx+8) == "Infinity":
		return idx + 8, nil
	case s[idx] == '-' && t14Runes(s, idx, idx+9) == "-Infinity":
		return idx + 9, nil
	}
	if loc := t14NumberRe.FindStringIndex(string(s[idx:])); loc != nil {
		return idx + len([]rune(string(s[idx:])[:loc[1]])), nil
	}
	return 0, &t14PyJErr{msg: "Expecting value", pos: idx}
}

// t14NumberRe is json.scanner.NUMBER_RE (anchored at the scan position).
var t14NumberRe = regexp.MustCompile(
	`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?`)

// t14PyObject is decoder.JSONObject.
func t14PyObject(s []rune, end int) (int, *t14PyJErr) {
	nextchar := t14At(s, end)
	if nextchar != '"' {
		if t14IsWS(nextchar) {
			end = t14SkipWS(s, end)
			nextchar = t14At(s, end)
		}
		if nextchar == '}' {
			return end + 1, nil
		}
		if nextchar != '"' {
			return 0, &t14PyJErr{msg: "Expecting property name enclosed in " +
				"double quotes", pos: end}
		}
	}
	end++
	for {
		var jerr *t14PyJErr
		if end, jerr = t14PyScanString(s, end); jerr != nil {
			return 0, jerr
		}
		if t14At(s, end) != ':' {
			end = t14SkipWS(s, end)
			if t14At(s, end) != ':' {
				return 0, &t14PyJErr{msg: "Expecting ':' delimiter", pos: end}
			}
		}
		end++
		if end < len(s) && t14IsWS(s[end]) {
			end++
			if end < len(s) && t14IsWS(s[end]) {
				end = t14SkipWS(s, end+1)
			}
		}
		if end, jerr = t14PyScanOnce(s, end); jerr != nil {
			return 0, jerr
		}
		nextchar = t14At(s, end)
		if t14IsWS(nextchar) {
			end = t14SkipWS(s, end)
			nextchar = t14At(s, end)
		}
		end++
		if nextchar == '}' {
			return end, nil
		}
		if nextchar != ',' {
			return 0, &t14PyJErr{msg: "Expecting ',' delimiter", pos: end - 1}
		}
		commaIdx := end - 1
		end = t14SkipWS(s, end)
		nextchar = t14At(s, end)
		end++
		if nextchar != '"' {
			if nextchar == '}' {
				return 0, &t14PyJErr{msg: "Illegal trailing comma before " +
					"end of object", pos: commaIdx}
			}
			return 0, &t14PyJErr{msg: "Expecting property name enclosed in " +
				"double quotes", pos: end - 1}
		}
	}
}

// t14PyArray is decoder.JSONArray.
func t14PyArray(s []rune, end int) (int, *t14PyJErr) {
	nextchar := t14At(s, end)
	if t14IsWS(nextchar) {
		end = t14SkipWS(s, end)
		nextchar = t14At(s, end)
	}
	if nextchar == ']' {
		return end + 1, nil
	}
	for {
		var jerr *t14PyJErr
		if end, jerr = t14PyScanOnce(s, end); jerr != nil {
			return 0, jerr
		}
		nextchar = t14At(s, end)
		if t14IsWS(nextchar) {
			end = t14SkipWS(s, end)
			nextchar = t14At(s, end)
		}
		end++
		if nextchar == ']' {
			return end, nil
		}
		if nextchar != ',' {
			return 0, &t14PyJErr{msg: "Expecting ',' delimiter", pos: end - 1}
		}
		commaIdx := end - 1
		if end < len(s) && t14IsWS(s[end]) {
			end++
			if end < len(s) && t14IsWS(s[end]) {
				end = t14SkipWS(s, end+1)
			}
		}
		nextchar = t14At(s, end)
		if nextchar == ']' {
			return 0, &t14PyJErr{msg: "Illegal trailing comma before end " +
				"of array", pos: commaIdx}
		}
	}
}

// t14PyScanString is decoder.py_scanstring (end is the index after the
// opening quote).
func t14PyScanString(s []rune, end int) (int, *t14PyJErr) {
	begin := end - 1
	for {
		i := end
		for i < len(s) && s[i] != '"' && s[i] != '\\' && s[i] >= 0x20 {
			i++
		}
		if i >= len(s) {
			return 0, &t14PyJErr{msg: "Unterminated string starting at",
				pos: begin}
		}
		terminator := s[i]
		end = i + 1
		if terminator == '"' {
			return end, nil
		}
		if terminator != '\\' {
			// the C scanner (what json.loads uses) omits py_scanstring's
			// {!r} of the offending character
			return 0, &t14PyJErr{msg: "Invalid control character at",
				pos: end - 1}
		}
		if end >= len(s) {
			return 0, &t14PyJErr{msg: "Unterminated string starting at",
				pos: begin}
		}
		esc := s[end]
		if esc != 'u' {
			if !strings.ContainsRune("\"\\/bfnrt", esc) {
				// the C scanner points at the backslash, not the escape
				return 0, &t14PyJErr{msg: "Invalid \\escape", pos: end - 1}
			}
			end++
			continue
		}
		uni, jerr := t14DecodeUXXXX(s, end)
		if jerr != nil {
			return 0, jerr
		}
		end += 5
		if uni >= 0xd800 && uni <= 0xdbff && t14Runes(s, end, end+2) == "\\u" {
			uni2, jerr2 := t14DecodeUXXXX(s, end+1)
			if jerr2 != nil {
				return 0, jerr2
			}
			if uni2 >= 0xdc00 && uni2 <= 0xdfff {
				end += 6
			}
		}
	}
}

// t14DecodeUXXXX is decoder._decode_uXXXX (pos is the index of the "u").
func t14DecodeUXXXX(s []rune, pos int) (int, *t14PyJErr) {
	if pos+5 <= len(s) {
		v := 0
		ok := true
		for _, r := range s[pos+1 : pos+5] {
			d, good := t14HexVal(r)
			if !good {
				ok = false
				break
			}
			v = v*16 + d
		}
		if ok {
			return v, nil
		}
	}
	return 0, &t14PyJErr{msg: "Invalid \\uXXXX escape", pos: pos}
}

// t14HexVal is one hex digit.
func t14HexVal(r rune) (int, bool) {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0'), true
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10, true
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10, true
	}
	return 0, false
}

// t14At is s[i:i+1] ("" out of range).
func t14At(s []rune, i int) rune {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

// t14Runes is s[a:b] as a string (clamped).
func t14Runes(s []rune, a, b int) string {
	if a < 0 {
		a = 0
	}
	if b > len(s) {
		b = len(s)
	}
	if a >= b {
		return ""
	}
	return string(s[a:b])
}

// t14IsWS is `c in " \t\n\r"`.
func t14IsWS(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// t14SkipWS is WHITESPACE.match(s, i).end().
func t14SkipWS(s []rune, i int) int {
	for i < len(s) && t14IsWS(s[i]) {
		i++
	}
	return i
}
