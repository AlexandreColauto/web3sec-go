package harness

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// maxConstruct caps the construct a floor summary names, and oneLine
// forces it onto ONE line: a summary is a line, so a construct carrying a
// newline must not be able to forge a second one.
const maxConstruct = 60

// oneLine collapses s onto one line (control characters and newlines
// become spaces) and caps it at n runes.
func oneLine(s string, n int) string {
	return truncateRunes(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s), n)
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

// atoiClamped reads the digits of a k=<n> marker. The regexp already
// guarantees digits, so the only error is a non-digit byte (kept as a
// guard). The FULL int64 range is accepted (r31 F2: MaxInt64 was read as
// an overflow and the marker silently discarded); a wider value is a legal
// Python int that this parse cannot hold, so it saturates to BoundCapped
// rather than erroring — the run stated a bound, and dropping the marker
// would let the summary fall back to a number the output never named.
func atoiClamped(s string) (int, error) {
	n := uint64(0)
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("harness: bad k marker %q", s)
		}
		d := uint64(c - '0')
		if n > (uint64(math.MaxInt64)-d)/10 {
			return BoundCapped, nil
		}
		n = n*10 + d
	}
	return int(n), nil
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
