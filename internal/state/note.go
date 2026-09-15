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
//
// It is a MAXIMUM LENGTH, truncation marker included: capNote never returns
// more than NOTE_CAP codepoints, so any consumer may treat "len(note) <=
// NOTE_CAP" as "this note is already capped".
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
// r36b P2 deviation from the Python original: Python kept NOTE_CAP body
// codepoints and THEN appended the ~80-rune marker, so its own output was
// always LONGER than the cap it claims. That made every "len(note) >
// NOTE_CAP" test a permanent falsehood (doctor's repair re-capped the note
// run after run: 4,179 -> 4,176 -> "4,176 -> 4,176" forever, and the note
// never got inside the cap). Here the marker is counted INSIDE the cap: the
// body is shortened until body+marker fits, and the marker's dropped-count
// is the true number of dropped codepoints, so the result is at most
// NOTE_CAP codepoints and is a fixed point of itself (capping a capped note
// is a no-op — that is what makes doctor converge).
//
// If the marker alone cannot fit inside the cap, the marker is returned
// truncated to the cap. That branch needs the dropped-count's OWN digits to
// exceed NOTE_CAP (a note of more than 10^(NOTE_CAP-~90) codepoints, which
// cannot exist in memory), and the choice is deliberate: the cap is the
// invariant every caller reasons about, so the disclosure is shortened
// rather than the cap exceeded.
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
	// The marker's width depends on the dropped count, which depends on the
	// body width, so the fit is solved by iteration. keep strictly decreases
	// (the marker is never empty), so this ends in a few rounds.
	keep := NOTE_CAP
	for {
		marker := truncationMarker(n - keep)
		if keep+utf8.RuneCountInString(marker) <= NOTE_CAP {
			return truncateRunes(s, keep) + marker
		}
		keep = NOTE_CAP - utf8.RuneCountInString(marker)
		if keep <= 0 {
			return truncateRunes(truncationMarker(n), NOTE_CAP)
		}
	}
}

// truncateRunes cuts s to its first keep codepoints and never mid-rune. The
// cap is in codepoints, so a byte slice would both over-count a non-ASCII
// note and split a rune.
func truncateRunes(s string, keep int) string {
	if keep <= 0 {
		return ""
	}
	n := 0
	for i := range s {
		if n == keep {
			return s[:i]
		}
		n++
	}
	return s
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
