package learning

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"websec/internal/state"
	"websec/internal/validation"
)

// Negative-mode memory retrieval: local lookup of memory candidates whose
// pattern shares a keyword with the query. Split from learning.go (same package).

// negativeStatuses is the status set negative_memory_lookup scans.
var negativeStatuses = []string{"DISPROVED", "INTENDED_BEHAVIOR",
	"NON-ECONOMIC", "TEST-HARNESS-ONLY", "UNREACHABLE"}

// NegativeMemoryLookup is negative_memory_lookup: local negative-mode
// retrieval — memory candidates whose pattern shares a keyword with the
// query.
func NegativeMemoryLookup(c *state.Campaign, patternText string) ([]validation.Value, error) {
	words := map[string]struct{}{}
	for _, w := range ReSplit(patternText) {
		// Runes, not bytes: sharedmem's keyword filter (the other half of this
		// retrieval) counts runes, so a non-ASCII keyword used to be eligible
		// in one path and not the other.
		if utf8.RuneCountInString(w) > 3 {
			words[w] = struct{}{}
		}
	}
	rows, err := AllMemory(c)
	if err != nil {
		return nil, err
	}
	hits := []validation.Value{}
	for _, m := range rows {
		if !slices.Contains(negativeStatuses, validation.ObjStr(m, "status")) {
			continue
		}
		neg := validation.ObjAt(m, "negative_mode")
		text := strings.ToLower(validation.ObjStr(m, "pattern") + " " +
			validation.ObjStr(neg, "why_safe"))
		for _, w := range ReSplit(text) {
			if _, ok := words[w]; ok {
				hits = append(hits, m)
				break
			}
		}
	}
	return hits, nil
}

// ReSplit is Python's re.split(r"\W+", s.lower()) over word runs (\w is
// Unicode-aware in Python: letters, numbers and underscore).
func ReSplit(s string) []string {
	out := []string{}
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}
