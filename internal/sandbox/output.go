// output.go: exec_output — the captured-output reader behind the forge
// meaningfulness gate (webv2.sandbox.exec_output).
package sandbox

import (
	"os"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// ExecOutput is exec_output: the captured stdout+stderr of an exec record,
// read back from disk. Missing or unreadable logs read as empty, so a run
// that cannot show its output fails closed at the evidence gate instead of
// minting on silence.
func ExecOutput(rec validation.Value) string {
	var b strings.Builder
	for _, key := range []string{"stdout_path", "stderr_path"} {
		p := objStr(rec, key)
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			// Python's Path.is_file() is stat.S_ISREG: a directory, FIFO
			// or socket is skipped (never opened).
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			// Fail closed: Python's read_text would raise on an unreadable
			// regular file; the gate treats unreadable as empty.
			continue
		}
		b.WriteString(pyTextReplace(raw))
	}
	return b.String()
}

// pyTextReplace is Path.read_text(encoding="utf-8", errors="replace"): a
// UTF-8 decode with CPython's maximal-subpart replacement of ill-formed
// sequences, plus universal-newline translation (\r\n and lone \r -> \n).
func pyTextReplace(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		r, size := decodeUTF8Replace(raw[i:])
		i += size
		if r == '\r' {
			if i < len(raw) && raw[i] == '\n' {
				i++ // \r\n is one newline
			}
			b.WriteByte('\n')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decodeUTF8Replace decodes the first UTF-8 sequence of s, or reports
// utf8.RuneError with the length of the ill-formed sequence's maximal
// subpart (the bytes CPython consumes for one U+FFFD). A valid start byte
// followed by a bad continuation consumes only the valid prefix, so the bad
// byte is re-examined as a new sequence.
func decodeUTF8Replace(s []byte) (rune, int) {
	b0 := s[0]
	if b0 < 0x80 {
		return rune(b0), 1
	}
	need := 0
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case b0 >= 0xc2 && b0 <= 0xdf:
		need = 2
	case b0 == 0xe0:
		need, lo = 3, 0xa0
	case b0 >= 0xe1 && b0 <= 0xec:
		need = 3
	case b0 == 0xed:
		need, hi = 3, 0x9f
	case b0 >= 0xee && b0 <= 0xef:
		need = 3
	case b0 == 0xf0:
		need, lo = 4, 0x90
	case b0 >= 0xf1 && b0 <= 0xf3:
		need = 4
	case b0 == 0xf4:
		need, hi = 4, 0x8f
	default:
		// 0x80-0xc1 and 0xf5-0xff can never start a sequence.
		return utf8.RuneError, 1
	}
	n := 1
	for n < need && n < len(s) {
		c := s[n]
		if n == 1 {
			if c < lo || c > hi {
				break
			}
		} else if c < 0x80 || c > 0xbf {
			break
		}
		n++
	}
	if n < need {
		return utf8.RuneError, n
	}
	switch need {
	case 2:
		return rune(b0&0x1f)<<6 | rune(s[1]&0x3f), 2
	case 3:
		return rune(b0&0x0f)<<12 | rune(s[1]&0x3f)<<6 | rune(s[2]&0x3f), 3
	default:
		return rune(b0&0x07)<<18 | rune(s[1]&0x3f)<<12 | rune(s[2]&0x3f)<<6 | rune(s[3]&0x3f), 4
	}
}
