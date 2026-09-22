// Package sandbox ports the output-integrity slice of webv2.sandbox: the
// E4-capable profile set and the foundry-output meaningfulness gate that
// keeps a "reproduction" from being minted on a run that proved nothing.
//
// The policy/dispatch half (policy_check, Sandbox.run, register_exec,
// load_exec) lands with the sandbox phase (P2); this package ships only the
// pure verdict functions the evidence gates call.
package sandbox

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"websec/internal/validation"
)

// E4_PROFILES is E4_PROFILES: only these profiles can back E4+ execution
// evidence. host-readonly is deliberately excluded — it executes on the
// host and enforces nothing but its own pattern tripwires.
var E4_PROFILES = map[string]struct{}{
	"docker-networkless": {},
	"docker-gvisor":      {},
	"vm-snapshot":        {},
	"fork-runner":        {},
}

// ranRe and failRe are forge_test_summary's counters. Python's \d matches
// any Unicode decimal digit, so [\p{Nd}]+ is the exact equivalent (RE2's
// \d is ASCII-only).
var (
	ranRe  = regexp.MustCompile(`ran ([\p{Nd}]+) tests?`)
	failRe = regexp.MustCompile(`([\p{Nd}]+) failed`)
)

// ForgeSummary is forge_test_summary's dict: tri-state counters (nil means
// "not printed"; the caller decides the verdict) plus the marker flags.
type ForgeSummary struct {
	Ran           *int64
	Failed        *int64
	NoTests       bool
	HasFailMarker bool
	HasPassMarker bool
}

// ForgeTestSummary is forge_test_summary: parse a foundry test output into
// machine-readable verdict parts.
//
// Foundry prints variants like "Ran 1 test suite in 5.2ms (test suite
// successful)" / "Ran 1 test in 3ms (1 test successful)" and "Suite result:
// ok. 1 passed; 0 failed; ..."; the failure modes are "No tests found ..."
// and "(test suite failed)" with a "[FAIL]" line. Not every invocation
// prints counters (bare "PASS:" markers from custom harnesses), so the
// parts stay tri-state: nil means "not printed".
func ForgeTestSummary(text string) ForgeSummary {
	tl := strings.ToLower(text)
	s := ForgeSummary{}
	if m := ranRe.FindStringSubmatch(tl); m != nil {
		n := pyIntDigits(m[1])
		s.Ran = &n
	}
	if m := failRe.FindStringSubmatch(tl); m != nil {
		n := pyIntDigits(m[1])
		s.Failed = &n
	}
	s.NoTests = strings.Contains(tl, "no tests found") || (s.Ran != nil && *s.Ran == 0)
	s.HasFailMarker = strings.Contains(tl, "[fail]")
	// Only EXPLICIT pass markers count. The bare-word `\bpass\b` clause
	// used to be here in Python: any prose containing the word ("the
	// exploit pass could not be loaded", "no tests pass") marked a run as
	// passing — a forge run that matched zero tests could then carry E4+
	// evidence off a failed match.
	s.HasPassMarker = strings.Contains(tl, "[pass]") ||
		strings.Contains(tl, "pass: ") ||
		strings.Contains(tl, "test suite successful") ||
		strings.Contains(tl, "suite result: ok")
	return s
}

// LooksLikeForgeTest is looks_like_forge_test: does this command invoke a
// foundry/forge toolchain binary?
//
// Python's \b is Unicode-aware (a word char is alphanumeric or "_"), while
// RE2's \b is ASCII-only, so the boundary test is spelled out here.
func LooksLikeForgeTest(command string) bool {
	rs := []rune(strings.ToLower(command))
	for _, word := range []string{"forge", "foundry"} {
		w := []rune(word)
		for i := 0; i+len(w) <= len(rs); i++ {
			if string(rs[i:i+len(w)]) != word {
				continue
			}
			if !isPyWord(rs, i-1) && !isPyWord(rs, i+len(w)) {
				return true
			}
		}
	}
	return false
}

// isPyWord reports whether the rune at i is a Python \w character: letters,
// numbers, or "_" (str.isalnum()). Out-of-range indexes are non-word.
func isPyWord(rs []rune, i int) bool {
	if i < 0 || i >= len(rs) {
		return false
	}
	r := rs[i]
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// ExecOutputProblem is exec_output_problem: why an exec's captured output
// cannot back E4+ evidence, or nil.
//
// Exit status and emptiness are checked by the caller; this adds
// MEANINGFULNESS: a forge run that matched zero tests ("No tests found",
// "Ran 0 tests") or whose suite failed is not a reproduction — a test
// command that ran and printed nothing new proved nothing, and minting
// evidence on it was the exact shortcut this framework exists to close.
// Non-forge commands are out of scope here (their output format is
// unconstrained); the caller's exit-0 + non-empty checks apply.
func ExecOutputProblem(rec validation.Value) *string {
	if !commandIsForgeLike(rec) {
		return nil
	}
	s := ForgeTestSummary(ExecOutput(rec))
	if s.NoTests {
		return problem("forge output shows no tests were run (ran=%s); "+
			"'No tests found' is not a reproduction — check the "+
			"--match-test filter / test path and re-run", pyReprOptInt(s.Ran))
	}
	// v16 §5.3: under expected_outcome "fail" a failing suite is the
	// EXPECTED shape — the whole point of an absent-guard reproduction —
	// so that refusal only applies to records expecting (or, as always,
	// not declaring anything, which reads as) "pass". The NoTests branch
	// above and the no-counters branch below stay UNCONDITIONAL: a run
	// that matched nothing proves nothing under either expectation.
	if ExecExpectedOutcome(rec) == EXPECT_PASS && hasFailingSuite(s) {
		return problem("forge output shows a failing suite "+
			"(ran=%s, failed=%s, fail_marker=%s) — a failing test is "+
			"not a passing reproduction",
			pyReprOptInt(s.Ran), pyReprOptInt(s.Failed), pyReprBool(s.HasFailMarker))
	}
	if s.Ran == nil && s.Failed == nil && !s.HasPassMarker {
		return problem("forge output has no test counters and no PASS marker — " +
			"cannot verify a test actually ran and passed; capture the " +
			"full forge output and re-run")
	}
	return nil
}

// hasFailingSuite is the suite-failure verdict of the summary: a [FAIL]
// marker or a positive failed counter (extracted so ExecOutputProblem's
// own complexity stays under the house cap).
func hasFailingSuite(s ForgeSummary) bool {
	return s.HasFailMarker || (s.Failed != nil && *s.Failed > 0)
}

// problem renders one Python f-string message and returns its pointer.
func problem(format string, args ...any) *string {
	out := fmt.Sprintf(format, args...)
	return &out
}

// pyReprOptInt renders Python's repr of an int-or-None (an f-string
// interpolation of a tri-state counter).
func pyReprOptInt(v *int64) string {
	if v == nil {
		return "None"
	}
	return strconv.FormatInt(*v, 10)
}

// pyReprBool renders Python's repr of a bool (f-string interpolation).
func pyReprBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// pyIntDigits converts a run of Unicode decimal digits the way Python's
// int() does. Python ints are unbounded; a counter past int64 saturates
// (forge output cannot produce one).
func pyIntDigits(s string) int64 {
	var n int64
	for _, r := range s {
		d, ok := pyDigitValue(r)
		if !ok {
			continue
		}
		if n > (math.MaxInt64-d)/10 {
			return math.MaxInt64
		}
		n = n*10 + d
	}
	return n
}

// pyDigitValue returns the decimal value of a Unicode Nd rune (0-9).
func pyDigitValue(r rune) (int64, bool) {
	for _, rg := range unicode.Nd.R16 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return int64(r-rune(rg.Lo)) / int64(rg.Stride), true
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return int64(r-rune(rg.Lo)) / int64(rg.Stride), true
		}
	}
	return 0, false
}

// commandIsForgeLike is looks_like_forge_test(rec.get("command", "")).
//
// Deviation: a non-string command (a hostile exec_record.json) is treated
// as forge-like so the meaningfulness gate still runs. Python's
// (command or "").lower() raises AttributeError there — it never skips the
// check — and skipping it is the fail-open direction this module exists to
// close.
func commandIsForgeLike(rec validation.Value) bool {
	for _, kv := range rec.O {
		if kv.K != "command" {
			continue
		}
		if kv.V.Kind != validation.Str {
			return kv.V.Kind != validation.Null
		}
		return LooksLikeForgeTest(kv.V.S)
	}
	return false
}
