package state

// zz_r36b_test.go — R36B P2 (auditor repro): capNote's output must fit INSIDE
// the cap it claims, marker included, and capNote must be a fixed point of
// itself.
//
// Pre-fix, capNote kept NOTE_CAP runes of the body and THEN appended the
// ~80-rune marker, so its own output was always LONGER than NOTE_CAP. doctor's
// repair test ("len(note) > NOTE_CAP") was therefore permanently true: every
// run reported a truncation, rewrote campaign_state.json and left the note at
// 4,176 runes. The repair never converged — eight runs, eight identical
// reports, the note still over the cap and the "all stage notes within the
// cap" line unreachable.
//
// The contract these tests pin:
//   - RuneCount(capNote(x)) <= NOTE_CAP, always (the marker is part of the cap);
//   - the cut lands on a rune boundary (the cap counts codepoints, never bytes);
//   - the marker's dropped-count is the TRUE number of dropped runes;
//   - capNote(capNote(x)) == capNote(x), so a second doctor run has nothing
//     left to repair (convergence).

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/validation"
)

// r36bMarkerOpen/r36bMarkerClose bracket the dropped-count inside the marker.
const (
	r36bMarkerOpen  = " \u2026[truncated "
	r36bMarkerClose = " chars \u2014"
)

// r36bDropped reads N out of the APPENDED marker (" …[truncated N chars —").
// LastIndex, not Index: a note may itself contain marker-shaped text, and the
// appended marker is always the last one.
func r36bDropped(t *testing.T, capped string) int {
	t.Helper()
	i := strings.LastIndex(capped, r36bMarkerOpen)
	if i < 0 {
		t.Fatalf("no truncation marker in a %d-rune note", utf8.RuneCountInString(capped))
	}
	rest := capped[i+len(r36bMarkerOpen):]
	j := strings.Index(rest, r36bMarkerClose)
	if j < 0 {
		t.Fatalf("malformed marker: %q", rest)
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		t.Fatalf("marker count %q: %v", rest[:j], err)
	}
	return n
}

// r36bBodyRunes is the number of body runes in front of the appended marker.
func r36bBodyRunes(t *testing.T, capped string) int {
	t.Helper()
	i := strings.LastIndex(capped, r36bMarkerOpen)
	if i < 0 {
		t.Fatalf("no truncation marker in the capped note")
	}
	return utf8.RuneCountInString(capped[:i])
}

// TestR36BCapNoteWithinTheCapOnEveryBoundary: the cap is a LIMIT, not a
// prefix length — at, just under, one over, and far over it.
func TestR36BCapNoteWithinTheCapOnEveryBoundary(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"one rune", 1},
		{"one below the cap", NOTE_CAP - 1},
		{"exactly the cap", NOTE_CAP},
		{"cap+1", NOTE_CAP + 1},
		{"cap+4", NOTE_CAP + 4},
		{"cap+90", NOTE_CAP + 90},
		{"the repro's 100000", 100_000},
		{"a million", 1_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.Repeat("a", tc.n)
			got := capNote(validation.VStr(in))
			if tc.n <= NOTE_CAP {
				if got != in {
					t.Errorf("a %d-rune note (<= cap) changed: %d runes out",
						tc.n, utf8.RuneCountInString(got))
				}
				return
			}
			n := utf8.RuneCountInString(got)
			if n > NOTE_CAP {
				t.Errorf("capNote(%d runes) = %d runes, want <= NOTE_CAP (%d): "+
					"the marker is part of the cap it claims", tc.n, n, NOTE_CAP)
			}
			if !strings.Contains(got, "[truncated ") {
				t.Errorf("capNote(%d) dropped the truncation marker", tc.n)
			}
			// The disclosure number must be TRUE: body + dropped == input.
			body := r36bBodyRunes(t, got)
			if dropped := r36bDropped(t, got); body+dropped != tc.n {
				t.Errorf("marker says %d dropped and kept %d runes, want them "+
					"to sum to the input's %d", dropped, body, tc.n)
			}
			if !strings.HasPrefix(got, in[:body]) {
				t.Errorf("the capped body is not the input's prefix")
			}
		})
	}
}

// TestR36BCapNoteIsAFixedPoint: re-capping a capped note must be a no-op.
// Pre-fix it was not (4096+'a' + marker -> 4179, re-capped to 4176, re-capped
// to 4176 forever), which is exactly why doctor's repair could never converge.
func TestR36BCapNoteIsAFixedPoint(t *testing.T) {
	for _, n := range []int{NOTE_CAP + 1, NOTE_CAP + 4, 10_000, 100_000} {
		once := capNote(validation.VStr(strings.Repeat("a", n)))
		twice := capNote(validation.VStr(once))
		if twice != once {
			t.Errorf("capNote is not a fixed point at n=%d: once = %d runes, "+
				"twice = %d runes — doctor would report this note forever",
				n, utf8.RuneCountInString(once), utf8.RuneCountInString(twice))
		}
	}
	// The SHAPE the pre-fix code wrote to disk (cap-sized body + marker) must
	// not be a fixed point either, or a campaign poisoned before the fix
	// stays over the cap forever.
	poisoned := strings.Repeat("a", NOTE_CAP) + truncationMarker(95904)
	if n := utf8.RuneCountInString(poisoned); n <= NOTE_CAP {
		t.Fatalf("fixture: poisoned note is %d runes, must be over the cap", n)
	}
	if got := capNote(validation.VStr(poisoned)); got == poisoned {
		t.Errorf("the pre-fix output is a fixed point of the new capNote: the "+
			"note stays at %d runes, still over the cap",
			utf8.RuneCountInString(poisoned))
	}
}

// TestR36BCapNoteCutsOnRuneBoundaries: the cap is in codepoints (Python str
// semantics). A byte-wise cut would both over-count the cap for non-ASCII
// notes and split a rune.
func TestR36BCapNoteCutsOnRuneBoundaries(t *testing.T) {
	cases := []struct {
		name string
		unit string
	}{
		{"2-byte runes", "\u00e9"},            // é
		{"4-byte runes", "\U0001f642"},        // 🙂
		{"mixed widths", "a\u00e9\U0001f642"}, // 1+2+4 bytes
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.Repeat(tc.unit, NOTE_CAP+1)
			got := capNote(validation.VStr(in))
			if !utf8.ValidString(got) {
				t.Errorf("output is not valid UTF-8: a rune was cut mid-sequence")
			}
			if strings.ContainsRune(got, utf8.RuneError) {
				t.Errorf("output contains U+FFFD — the cut split a rune")
			}
			n := utf8.RuneCountInString(got)
			if n > NOTE_CAP {
				t.Errorf("capNote = %d runes, want <= NOTE_CAP (%d)", n, NOTE_CAP)
			}
			if len(got) <= NOTE_CAP {
				t.Errorf("output is %d bytes, want > %d: the cap must be "+
					"counted in runes, not bytes", len(got), NOTE_CAP)
			}
			body := got[:strings.LastIndex(got, r36bMarkerOpen)]
			if !strings.HasPrefix(in, body) {
				t.Errorf("the capped body is not the input's prefix")
			}
			if r36bBodyRunes(t, got)%utf8.RuneCountInString(tc.unit) != 0 {
				t.Errorf("the body is not a whole number of %q units — the cut "+
					"is not on a rune boundary", tc.unit)
			}
			if dropped := r36bDropped(t, got); utf8.RuneCountInString(body)+dropped !=
				utf8.RuneCountInString(in) {
				t.Errorf("marker dropped-count is not the true rune count")
			}
		})
	}
}

// TestR36BCapNoteEmptyAndMarkerOnlyInputs: the degenerate inputs the cap
// function meets in the wild (an empty note; a note that is only the marker
// text the tool itself writes).
func TestR36BCapNoteEmptyAndMarkerOnlyInputs(t *testing.T) {
	if got := capNote(validation.VStr("")); got != "" {
		t.Errorf("empty note -> %q, want \"\"", got)
	}
	marker := truncationMarker(7)
	if n := utf8.RuneCountInString(marker); n >= NOTE_CAP {
		t.Fatalf("fixture: the marker is %d runes and must fit inside the cap", n)
	}
	if got := capNote(validation.VStr(marker)); got != marker {
		t.Errorf("a note that IS the marker (within the cap) was rewritten: "+
			"%d -> %d runes", utf8.RuneCountInString(marker),
			utf8.RuneCountInString(got))
	}
	// Marker-dominated text over the cap: the re-cap must still fit, and the
	// marker it appends must report the true drop against the whole input.
	over := strings.Repeat(marker, 100)
	if utf8.RuneCountInString(over) <= NOTE_CAP {
		t.Fatalf("fixture: marker text is only %d runes",
			utf8.RuneCountInString(over))
	}
	got := capNote(validation.VStr(over))
	if n := utf8.RuneCountInString(got); n > NOTE_CAP {
		t.Errorf("marker-dominated note -> %d runes, want <= NOTE_CAP (%d)",
			n, NOTE_CAP)
	}
	if body := r36bBodyRunes(t, got); body+r36bDropped(t, got) !=
		utf8.RuneCountInString(over) {
		t.Errorf("marker-dominated note: body + dropped != %d runes",
			utf8.RuneCountInString(over))
	}
}
