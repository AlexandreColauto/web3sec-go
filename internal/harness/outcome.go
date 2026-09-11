// outcome.go: G8 outcome mapping (Task 18) — MapRun turns raw runner
// stdout into a rung (counterexample | proved-bounded | inconclusive) plus
// a one-line summary. Pure: no I/O, no attribution, no registry writes.
//
// Fail-open-to-inconclusive law: a run that proves nothing must never
// promote OR demote, so every unmapped shape — empty output, mixed/noisy
// logs, contradictory signals — lands inconclusive, and proved-bounded
// additionally requires explicit bounded evidence (a k=<n> marker or the
// bounded flag text). Timeout always wins over output text: a killed run's
// bytes are partial by definition, so even a "Status: fail" fragment in
// them maps to inconclusive, never to a rung.
//
// Attribution (which EXEC belongs to which invariant) lives in
// `verify --harness-result`, never here: a stray halmos run must never be
// attributed to an invariant by guesswork.
package harness

import (
	"fmt"
	"regexp"
	"strings"
)

// Rung values for verification.harness.rung.
const (
	RungCounterexample = "counterexample"
	RungProvedBounded  = "proved-bounded"
	RungInconclusive   = "inconclusive"
)

// maxExcerpt is the brief's ≤120-char cap on counterexample excerpts.
const maxExcerpt = 120

// kMarker finds halmos's bounded marker ("k=100", "k = 100").
var kMarker = regexp.MustCompile(`k\s*=\s*(\d+)`)

// MapRun maps raw runner output to (rung, summary). kind selects the
// branch; timedOut forces inconclusive ("timeout after <k>s" — k is the
// caller-passed bound, never read from the wall); k is the bound the
// runner was invoked with (forge-fuzz proved-bounded carries it as
// bounded_k; halmos prefers a parsed k=<n> marker — see BoundK).
func MapRun(kind Kind, out []byte, timedOut bool, k int) (rung string,
	summary string) {
	text := string(out)
	if timedOut {
		return RungInconclusive, fmt.Sprintf("timeout after %ds", k)
	}
	switch kind {
	case Halmos:
		return mapHalmos(text, k)
	case ForgeFuzz:
		return mapForgeFuzz(text, k)
	default:
		return RungInconclusive,
			fmt.Sprintf("inconclusive (unknown harness kind %q)",
				string(kind))
	}
}

// mapHalmos is the halmos branch: "Status: fail" plus a model/
// Counterexample block => counterexample (first block line, ≤120 chars);
// a success line ("Status: passed" / "Successfully proved") plus bounded
// evidence (k=<n> marker or the --loop bounded flag) => proved-bounded;
// anything else => inconclusive (never promote on partial text).
func mapHalmos(text string, k int) (string, string) {
	if hasStatusWord(text, "fail") {
		if line, ok := counterexampleLine(text); ok {
			return RungCounterexample,
				"counterexample: " + truncateRunes(line, maxExcerpt)
		}
		return RungInconclusive, "inconclusive (exit output unmapped)"
	}
	if hasStatusWord(text, "passed") || strings.Contains(text,
		"Successfully proved") {
		if _, ok := parseK(text); ok || hasBoundedFlag(text) {
			return RungProvedBounded,
				fmt.Sprintf("proved bounded (k=%d)",
					BoundK(Halmos, []byte(text), k))
		}
		return RungInconclusive, "inconclusive (exit output unmapped)"
	}
	return RungInconclusive, "inconclusive (exit output unmapped)"
}

// mapForgeFuzz is the forge-fuzz branch: a FAIL line with fuzz/seed
// context => counterexample (the seed line when present, else the FAIL
// line); a "---"/Suite-result summary line reading "1 passed" with
// "0 failed" and no FAIL line anywhere => proved-bounded (bounded_k is
// the k param); timed-out and everything else => inconclusive.
func mapForgeFuzz(text string, k int) (string, string) {
	failLine, hasFail := firstLineContaining(text, "FAIL")
	ctx := strings.Contains(strings.ToLower(text), "fuzz") ||
		strings.Contains(strings.ToLower(text), "seed")
	if hasFail && ctx {
		if seed, ok := firstLineContainingFold(text, "seed"); ok {
			return RungCounterexample,
				"counterexample: " + truncateRunes(seed, maxExcerpt)
		}
		return RungCounterexample,
			"counterexample: " + truncateRunes(failLine, maxExcerpt)
	}
	if !hasFail && forgePassSummary(text) {
		return RungProvedBounded, fmt.Sprintf("proved bounded (k=%d)", k)
	}
	return RungInconclusive, "inconclusive (exit output unmapped)"
}

// BoundK is the bounded_k for a proved-bounded rung: halmos prefers the
// first k=<n> marker in the output, otherwise (and always for forge-fuzz,
// whose runs count rides the invocation) the k the runner was invoked
// with. Only meaningful when MapRun returned proved-bounded; callers must
// not consult it for other rungs (their bounded_k is null).
func BoundK(kind Kind, out []byte, k int) int {
	if kind == Halmos {
		if n, ok := parseK(string(out)); ok {
			return n
		}
	}
	return k
}

// parseK reads the first k=<n> marker. ok=false when absent or unparsable
// (callers fall back to the invocation k).
func parseK(text string) (n int, ok bool) {
	m := kMarker.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	n, err := atoiClamped(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// hasBoundedFlag is the bounded-flag-text half of halmos's bounded
// evidence: the --loop flag the bounded recipe passes. (A bare success
// line with no bound evidence is partial text and must not promote.)
func hasBoundedFlag(text string) bool {
	return strings.Contains(text, "--loop")
}

// hasStatusWord matches halmos's "Status: <word>" with a word boundary
// past the word, so "Status: failure"/"Status: failed" do not read as
// "Status: fail".
func hasStatusWord(text, word string) bool {
	needle := "Status: " + word
	for i := 0; i+len(needle) <= len(text); i++ {
		if !strings.HasPrefix(text[i:], needle) {
			continue
		}
		rest := text[i+len(needle):]
		if rest == "" || !isASCIILetter(rest[0]) {
			return true
		}
	}
	return false
}

// modelAssign names a model-value line: "model" as a word followed by a
// ":" or, within a short window, a "=" (an assignment). The window keeps
// prose like "before model construction" (no binding in sight) from
// reading as a model block.
var modelAssign = regexp.MustCompile(`(?i)\bmodel\b\s*[:=]|\bmodel\b[^:=]{0,40}=`)

// counterexampleLine is the halmos counterexample-block excerpt: the first
// block line carrying a value (an "=" binding — the model's symbolic
// values, e.g. a getSymbolicAddress line), falling back to the block
// header itself ("Counterexample:") when the block names no values. The
// "Status: fail" line itself never counts (it names no values).
func counterexampleLine(text string) (string, bool) {
	var lines []string
	blockAt := -1
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "Status:") {
			continue
		}
		lines = append(lines, t)
		if blockAt < 0 && (strings.Contains(t, "Counterexample") ||
			modelAssign.MatchString(t)) {
			blockAt = len(lines) - 1
		}
	}
	if blockAt < 0 {
		return "", false
	}
	for _, t := range lines[blockAt:] {
		if strings.Contains(t, "=") {
			return t, true
		}
	}
	return lines[blockAt], true
}

// forgePassSummary is the proved half's summary line: "1 passed" with
// "0 failed" on a forge summary line (a "---" rule or the Suite result
// line). Callers additionally require no FAIL line anywhere, so a mixed
// log with both can never promote.
//
// H9: BOTH markers are matched on the SAME line. The Suite-result test used
// to scan the whole text, so a "1 passed; 0 failed" line from one suite
// promoted the run whenever the words "Suite result" appeared anywhere else
// in the log — a run whose suites never agreed could read as proved. The
// summary line is the claim; a claim is one line.
func forgePassSummary(text string) bool {
	for _, ln := range strings.Split(text, "\n") {
		if !strings.Contains(ln, "1 passed") ||
			!strings.Contains(ln, "0 failed") {
			continue
		}
		if strings.Contains(ln, "---") {
			return true
		}
		if strings.Contains(ln, "Suite result") {
			return true
		}
	}
	return false
}

// firstLineContaining is the first trimmed non-empty line containing sub
// (case-sensitive: forge's FAIL marker is uppercase; lowercase "failed"
// in a pass summary must not match).
func firstLineContaining(text, sub string) (string, bool) {
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t != "" && strings.Contains(t, sub) {
			return t, true
		}
	}
	return "", false
}

// firstLineContainingFold is firstLineContaining case-insensitive (for
// "seed:"/"Seed" lines, whose casing varies across forge versions).
func firstLineContainingFold(text, sub string) (string, bool) {
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t != "" && strings.Contains(strings.ToLower(t),
			strings.ToLower(sub)) {
			return t, true
		}
	}
	return "", false
}

// truncateRunes caps s at n runes (the brief's "chars" are runes, not
// bytes — a symbolic address excerpt must never split mid-rune).
func truncateRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// atoiClamped is Atoi rejecting empty input (regexp already guarantees
// digits; the clamp guards absurd widths from shifting int range).
func atoiClamped(s string) (int, error) {
	n := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("harness: bad k marker %q", s)
		}
		n = n*10 + int(c-'0')
		if n > 1<<62 {
			return 0, fmt.Errorf("harness: k marker %q overflows", s)
		}
	}
	return n, nil
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
