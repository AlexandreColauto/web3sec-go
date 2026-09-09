package state

import (
	"unicode/utf8"

	"websec/internal/validation"
)

// NOTE_CAP bounds a stage note. The state file is re-read and re-written
// by EVERY CLI command, so a note is an operator-visible summary, never a
// data payload. One run inlined a 2 GB structural index into a note
// (campaign_state.json grew to 1.7 GB and every command paid for it). The
// full content belongs in a registered artifact.
const NOTE_CAP = 4096

// CapNote is cap_note, exported for doctor's note repair: webv2.doctor
// caps stage/artifact notes in the projection with exactly this function.
func CapNote(note validation.Value) string { return capNote(note) }

// capNote is Python's cap_note: null -> ""; strings pass through capped;
// other values are serialized (sorted, ensure_ascii) so a handler return
// value can never smuggle a payload into the state file. Truncation is
// marked so the operator sees the note was cut. Lengths are codepoints
// (Python str semantics), not bytes.
//
// Deviation: the Python fallback json.dumps(..., default=str) /
// str(note) on TypeError/ValueError has no Go analogue - a Value is
// always serializable, so the sorted canonical form always succeeds.
func capNote(note validation.Value) string {
	if note.Kind == validation.Null {
		return ""
	}
	var s string
	if note.Kind == validation.Str {
		s = note.S
	} else {
		s = validation.CanonSpaced(note)
	}
	n := utf8.RuneCountInString(s)
	if n <= NOTE_CAP {
		return s
	}
	var b []byte
	for i := 0; i < NOTE_CAP; i++ {
		_, size := utf8.DecodeRuneInString(s[len(b):])
		b = append(b, s[len(b):len(b)+size]...)
	}
	return string(b) + truncationMarker(n-NOTE_CAP)
}

// truncationMarker is the exact Python suffix (space + U+2026 ellipsis,
// U+2014 em dash inside).
func truncationMarker(n int) string {
	return " \u2026[truncated " + itoa(n) + " chars \u2014 " +
		"full content must live in an artifact, not a stage note]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
