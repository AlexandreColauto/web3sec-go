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
	"math"
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
// branch; timedOut forces inconclusive ("inconclusive (timeout)"); k is
// the bound the runner was invoked with (forge-fuzz proved-bounded carries
// it as bounded_k; halmos prefers a parsed k=<n> marker — see BoundK). Any
// FLOORING bound (BoundFloors: a stated bound below 1, a value the tool's
// own parser refuses, or a command the invocation parse could not read at
// all) floors the run whatever the output says AND whatever the timeout
// says: no rung rides a bound no tool would have executed under.
//
// The optional unreadable argument is InvocationBoundReason's construct
// detail, so a caller that holds the command can make the stored floor
// name WHY the invocation could not be read ("invocation-unreadable:
// unmatched single quote") instead of only the class. Leaving it out is
// honest too: the summary then says the command could not be lexed
// faithfully, without pretending to a detail it was not given. Either
// way the summary keeps the "degenerate-bound" prefix disposition.go
// classifies as EscalateBound — a second wording class in that position
// would silently drop the advice (r29 F4).
//
// r32 F3: the timeout arm used to run BEFORE the floor test and print the
// BOUND as a duration ("timeout after 4s" for a run invoked with
// --fuzz-runs 4, "timeout after -1s" for --fuzz-runs 0), so a killed run
// both escaped the floor and stated a number that was never a number of
// seconds. Now the FLOOR decides first (same predicate, same class), and
// the timeout summary carries NO number at all: this call site has no
// record and therefore no elapsed wall-clock to report, and substituting
// the bound is exactly the lie. A caller that can read real seconds must
// render them itself rather than hand MapRun a bound to print.
func MapRun(kind Kind, out []byte, timedOut bool, k int,
	unreadable ...string) (rung string, summary string) {
	text := string(out)
	if timedOut {
		if BoundFloors(k) {
			return RungInconclusive, boundFloorSummary(k, unreadable...)
		}
		return RungInconclusive, "inconclusive (timeout)"
	}
	if BoundFloors(k) {
		return RungInconclusive, boundFloorSummary(k, unreadable...)
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
				fmt.Sprintf("proved bounded (%s)", boundClause(n))
		}
		if hasBoundedFlag(text) {
			// No k=<n> marker parsed, so the invocation's own bound is
			// what this run ran under. Render IT rather than the
			// saturated slot BoundK records, so a capped invocation
			// (-3) still reads as a LOWER bound instead of printing
			// the stand-in as an exact number (r31 F2).
			if k < 1 && k != BoundCapped {
				return RungProvedBounded,
					"proved bounded (bound UNSTATED)"
			}
			return RungProvedBounded,
				fmt.Sprintf("proved bounded (%s)", boundClause(k))
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
		// a null bound renders UNSTATED). BoundCapped is the exception
		// (r31 F2): it is a STATED bound too wide for int64, so it
		// renders as a lower bound instead of "unstated".
		if k < 1 && k != BoundCapped {
			return RungProvedBounded, "proved bounded (bound UNSTATED)"
		}
		return RungProvedBounded,
			fmt.Sprintf("proved bounded (%s)", boundClause(k))
	}
	return RungInconclusive, "inconclusive (exit output unmapped)"
}

// BoundK is the bounded_k for a proved-bounded rung: halmos prefers the
// first k=<n> marker in the output, otherwise (and always for forge-fuzz,
// whose runs count rides the invocation) the k the runner was invoked
// with. Only meaningful when MapRun returned proved-bounded; callers must
// not consult it for other rungs (their bounded_k is null).
//
// A capped bound (BoundCapped, r31 F2) saturates to MaxInt64 rather than
// returning 0: the slot must record the STATED bound as the largest number
// this ledger can hold, never null. The summary wording (boundText) is what
// says the recorded number is a lower bound; the slot keeps the same
// saturating stand-in the cli's own Python-int reader uses.
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
			return saturate(n)
		}
	}
	if k == BoundCapped {
		return math.MaxInt64
	}
	if k < 1 {
		return 0
	}
	return k
}

// saturate maps a parsed bound onto the int64 slot: everything but
// BoundCapped is already a number in range.
func saturate(k int) int {
	if k == BoundCapped {
		return math.MaxInt64
	}
	return k
}

// parseK reads the first k=<n> marker. ok=false when absent or unparsable
// (callers fall back to the invocation k). A marker is a Python int, so
// the whole int64 range parses exactly and a WIDER marker parses to
// BoundCapped — the run did state a bound, and the summary must say it is
// a lower bound instead of calling it unstated (r31 F2).
func parseK(text string) (n int, ok bool) {
	m := kMarker.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	n, err := atoiClamped(m[1])
	if err != nil {
		return 0, false
	}
	if n == BoundCapped {
		return BoundCapped, true
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

// TimedOutBit is the MapRun timedOut bit derived from a recorded
// exit_status: -1 covers both "the timeout killed it" and "it never
// started"; 128+N is the shell's signal-death convention. Either way
// the run did not COMPLETE, so its bytes map to inconclusive, never to
// a rung (cli.harnessTimedOut delegates here — one law, one home).
func TimedOutBit(exitStatus int) bool {
	return exitStatus == -1 || exitStatus >= 128
}
