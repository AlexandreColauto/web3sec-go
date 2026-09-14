// outcome.go: G8 outcome mapping (Task 18) — MapRun turns raw runner
// stdout into a rung (counterexample | proved-bounded | inconclusive) plus
// a one-line summary. Pure: no I/O, no attribution, no registry writes.
// The third kind, MiniCertora, emits JSON-lines verdicts instead of
// prose: MapMinicertora (minicertora.go) maps those under the same rung
// vocabulary and inherits both laws below.
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

// BoundDegenerate is the bound a STATED-but-degenerate flag carries.
// The tools themselves refuse such invocations — halmos rejects
// --loop 0, forge rejects --fuzz-runs 0, and the miniprover twin's
// VerifierFlags.__post_init__ raises for loop_bound < 1 — so a record
// claiming a clean run under one describes something no tool can have
// executed. It is NOT "unstated" (0): that would let a k=0 rider print
// as a stated bound, and "proved bounded over zero executions" is a
// proof about nothing. MapRun therefore floors the WHOLE run (r26 F3:
// the r25 <1 floor lived only on the autoprove report path, while the
// real exec path still blessed `proved-bounded (forge-fuzz, k=0)`).
const BoundDegenerate = -1

// MapRun maps raw runner output to (rung, summary). kind selects the
// branch; timedOut forces inconclusive ("timeout after <k>s" — k is the
// caller-passed bound, never read from the wall); k is the bound the
// runner was invoked with (forge-fuzz proved-bounded carries it as
// bounded_k; halmos prefers a parsed k=<n> marker — see BoundK). A
// DEGENERATE stated bound (BoundDegenerate) floors the run whatever the
// output says: no rung rides a bound no tool would have executed under.
func MapRun(kind Kind, out []byte, timedOut bool, k int) (rung string,
	summary string) {
	text := string(out)
	if timedOut {
		return RungInconclusive, fmt.Sprintf("timeout after %ds", k)
	}
	if k == BoundDegenerate {
		return RungInconclusive,
			"inconclusive (degenerate-bound: the invocation states no " +
				"bound >= 1)"
	}
	if k == BoundDegenerate {
		return RungInconclusive,
			"inconclusive (degenerate-bound: the invocation states no " +
				"bound >= 1)"
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
		if n, ok := parseK(text); ok {
			// A marker that PARSES is not automatically evidence:
			// "k = 0" is the same degenerate statement the flag form
			// carries, and a blessing over zero iterations is a proof
			// about nothing (r26 F3).
			if n == BoundDegenerate {
				return RungInconclusive,
					"inconclusive (degenerate-bound: the run states " +
						"no bound >= 1)"
			}
			return RungProvedBounded,
				fmt.Sprintf("proved bounded (k=%d)", n)
		}
		if hasBoundedFlag(text) {
			n := BoundK(Halmos, []byte(text), k)
			if n < 1 {
				return RungProvedBounded,
					"proved bounded (bound UNSTATED)"
			}
			return RungProvedBounded,
				fmt.Sprintf("proved bounded (k=%d)", n)
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
		// r26 F3 mirror: forge's runs count rides the invocation, so an
		// invocation that named none states no bound — the summary must
		// say so rather than print a "k=0" nobody stated (F11's law:
		// a null bound renders UNSTATED).
		if k < 1 {
			return RungProvedBounded, "proved bounded (bound UNSTATED)"
		}
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
			// The output SPOKE: a degenerate marker is a statement
			// that no usable bound was proven, so it must not fall
			// back to the invocation (r26 F3) — the run is floored
			// anyway, and 0 here reads as UNSTATED, never as a bound.
			if n == BoundDegenerate {
				return 0
			}
			return n
		}
	}
	if k < 1 {
		return 0
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
	if n < 1 {
		// Parsed, but degenerate: the marker states a bound below 1.
		return BoundDegenerate, true
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

// TimedOutBit is the MapRun timedOut bit derived from a recorded
// exit_status: -1 covers both "the timeout killed it" and "it never
// started"; 128+N is the shell's signal-death convention. Either way
// the run did not COMPLETE, so its bytes map to inconclusive, never to
// a rung (cli.harnessTimedOut delegates here — one law, one home).
func TimedOutBit(exitStatus int) bool {
	return exitStatus == -1 || exitStatus >= 128
}

// InvocationBound parses the bound flag out of an exec command string:
// halmos's --loop N, forge's --fuzz-runs N (both `--flag N` and
// `--flag=N`), minicertora's --loop-bound N. 0 = unstated: the number
// only feeds display text, never a rung. (cli.boundFlagRe delegates
// here.)
//
// r28 F1: the parse is CLICK-SHAPED, because the twin's CLI is a click
// option (`@click.option("--loop-bound", type=int, default=4)`) and click
// binds a repeated option LAST-WINS (ctx.params["loop_bound"] is the final
// occurrence). Reading the FIRST match called
// `miniprover run --loop-bound 4 --loop-bound 0` a k=4 proof — but the twin
// parses 0 there, VerifierFlags.__post_init__ raises for loop_bound < 1,
// and no tool output can exist under that command at all, so the first
// match was evidence for a run the twin refuses to make. LAST occurrence
// decides, exactly as click does: a degenerate flag last floors the whole
// invocation even after an honest one, while a degenerate flag followed by
// an honest one does not floor.
//
// The token may carry a sign (click's type=int accepts `-1`, in both the
// `--flag -1` and `--flag=-1` forms), and the twin then RAISES — so a
// negative is a STATED degenerate bound, never "unstated". A negative whose
// digits overflow int is degenerate by its sign alone (flooring is the
// honest direction) while an overflowing POSITIVE keeps the old guard's
// reading, UNSTATED.
func InvocationBound(command string) int {
	ms := boundFlagRe.FindAllStringSubmatch(command, -1)
	if len(ms) == 0 {
		return 0
	}
	tok := ms[len(ms)-1][1]
	neg := strings.HasPrefix(tok, "-")
	if neg {
		tok = tok[1:]
	}
	n := 0
	for _, c := range []byte(tok) {
		if n > (1<<62)/10 {
			// The next digit would leave int range: report the
			// statement the guard always did (UNSTATED for an
			// absurd width), never a wrapped number.
			if neg {
				return BoundDegenerate
			}
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if n > 1<<62 {
		if neg {
			return BoundDegenerate
		}
		return 0
	}
	if neg {
		n = -n
	}
	if n < 1 {
		// STATED and degenerate ("--loop 0", "--fuzz-runs=0",
		// "--loop-bound -1"): not unstated, and not a bound any tool
		// would have run under.
		return BoundDegenerate
	}
	return n
}

// boundFlagRe finds every bound-flag occurrence with its signed token.
// The flag text is anchored so a lookalike inside another word
// ("--loop-boundx 4") matches nothing: after `--loop`/`--loop-bound` /
// `--fuzz-runs` the regex demands the `=` or the space and then the
// digits, so a trailing letter fails the whole alternative.
var boundFlagRe = regexp.MustCompile(
	`--(?:loop(?:-bound)?|fuzz-runs)[= ](-?\d+)`)
