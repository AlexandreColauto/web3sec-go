package harness

// outcome_test.go (Task 18): MapRun's branch table — each rung × both
// kinds, plus the noisy/mixed log that must land inconclusive. Fixtures
// are fabricated 10-15-line halmos / forge stdout excerpts shaped after
// the markers MapRun reads (status lines, counterexample blocks, k
// markers, fuzz seeds, Suite-result summaries).

import (
	"strings"
	"testing"
)

// halmosFail is a halmos counterexample run: "Status: fail" plus a
// Counterexample block with a symbolic-address model line.
const halmosFail = `halmos 0.3.3 --root . --match-contract InvInvariantHalmos
[⠋] Compiling...
[⠋] Compiling 2 files with Solc 0.8.33
[⠊] Solc 0.8.33 finished in 412ms
Running 1 test for test/Inv.t.sol:InvInvariantHalmos
[⠋] check_inv_1() (runs: 0, calls: 0, reverts: 0)
Status: fail
Counterexample:
  getSymbolicAddress(symAddr1) = 0x000000000000000000000000dEaDbEef0123456789abcdef0123456789ab
  symUint256_0 = 115792089237316195423570985008687907853269984665640564039457584007913129639935
Trace: [9773, 9774]
`

// halmosProvedK is a bounded halmos proof: success line plus a k=<n>
// marker (bounded_k must parse to 100, not the passed-in k).
const halmosProvedK = `halmos 0.3.3 --root . --match-contract InvInvariantHalmos
[⠋] Compiling...
[⠋] Compiling 2 files with Solc 0.8.33
[⠊] Solc 0.8.33 finished in 388ms
Running 1 test for test/Inv.t.sol:InvInvariantHalmos
[⠋] check_inv_1() (runs: 0, calls: 0, reverts: 0)
Status: passed [k=100, paths: 214]
Successfully proved 1 property with bound k=100
Time: 12.44s
Ran 1 test: 1 passed, 0 failed
`

// halmosProvedFlag is a bounded halmos proof via the bounded flag text
// (--loop) with no k=<n> marker: bounded_k falls back to the passed k.
const halmosProvedFlag = `halmos 0.3.3 --root . --loop 50 --match-contract InvInvariantHalmos
[⠋] Compiling...
[⠋] Compiling 2 files with Solc 0.8.33
[⠊] Solc 0.8.33 finished in 301ms
Running 1 test for test/Inv.t.sol:InvInvariantHalmos
[⠋] check_inv_1() (runs: 0, calls: 0, reverts: 0)
Status: passed
Successfully proved 1 property
Time: 4.02s
Ran 1 test: 1 passed, 0 failed
`

// halmosPassUnbounded is success text with NO bounded evidence: partial
// text must never promote, so this lands inconclusive.
const halmosPassUnbounded = `halmos 0.3.3 --root . --match-contract InvInvariantHalmos
[⠋] Compiling...
[⠋] Compiling 2 files with Solc 0.8.33
Running 1 test for test/Inv.t.sol:InvInvariantHalmos
Status: passed
Time: 1.11s
`

// halmosFailBare is "Status: fail" with no counterexample block (the
// solver died before printing a model): inconclusive, not counterexample.
const halmosFailBare = `halmos 0.3.3 --root . --match-contract InvInvariantHalmos
[⠋] Compiling...
Running 1 test for test/Inv.t.sol:InvInvariantHalmos
Status: fail
[solver error: out of memory before model construction]
Time: 300.01s
`

// forgeFail is a forge-fuzz counterexample: FAIL line plus a seed line.
const forgeFail = `Compiling 2 files with Solc 0.8.33
Solc 0.8.33 finished in 377ms
Ran 1 test for test/Inv.t.sol:InvInvariantFuzz
[FAIL: fuzz_inv_1(uint256)] (runs: 37, calls: 112, reverts: 4)
Suite result: FAILED. 0 passed; 1 failed; 0 skipped
Failing tests:
Encountered 1 failing test in test/Inv.t.sol:InvInvariantFuzz
[FAIL: fuzz_inv_1(uint256)] (runs: 37, calls: 112, reverts: 4)

fuzz test seed: 88421337 counterexample args: [11579208923731619542357098500868790785326998466564056403945758400791312963]
Traces:
  [112] InvInvariantFuzz::fuzz_inv_1(11579208923731619542357098500868790785326998466564056403945758400791312963)
`

// forgePass is a forge-fuzz bounded proof: Suite-result summary with
// "1 passed" and "0 failed", no FAIL line anywhere.
const forgePass = `Compiling 2 files with Solc 0.8.33
Solc 0.8.33 finished in 365ms
Ran 1 test for test/Inv.t.sol:InvInvariantFuzz
[PASS] fuzz_inv_1(uint256) (runs: 256, calls: 1024, reverts: 31)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 9.81ms
---
Ran 1 test suite: 1 passed; 0 failed; 0 skipped
`

// forgeNoisy is the mixed log that must land inconclusive: a FAIL line
// with no fuzz/seed context plus a pass-looking summary (contradictory
// signals from interleaved runs — never promote, never demote).
const forgeNoisy = `Compiling 2 files with Solc 0.8.33
[FAIL] flaky harness compile warning: previous run left stale output
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.11ms
note: rerun with --ffi to reproduce the stale-cache failure above
`

// forgeCrossLineSummary is the H9 shape: a counts line ("1 passed; 0 failed")
// with no summary marker of its own, plus the words "Suite result" on a
// DIFFERENT line. Whole-text matching promoted this run; the summary is the
// line that carries the claim, so per-line matching must not.
const forgeCrossLineSummary = `Suite result: ok.
Ran 1 test for test/Inv.t.sol:InvInvariantFuzz
[PASS] fuzz_inv_1(uint256) (runs: 256, calls: 1024, reverts: 31)
1 passed; 0 failed; 0 skipped
`

// halmosNoisy is the halmos mixed log: the word "failure" (not the
// "Status: fail" marker) plus "model" used as a verb — inconclusive.
const halmosNoisy = `halmos 0.3.3 --root . --match-contract InvInvariantHalmos
Running 1 test for test/Inv.t.sol:InvInvariantHalmos
note: earlier compilation failure was remodeled into the fresh scaffold
Status: unknown (solver heartbeat lost)
Time: 300.01s
`

func TestMapRunTable(t *testing.T) {
	cases := []struct {
		name       string
		kind       Kind
		out        string
		timedOut   bool
		k          int
		wantRung   string
		wantSubstr string // required summary fragment ("" skips)
		wantBoundK int    // checked only when wantRung is proved-bounded
	}{
		{"halmos counterexample", Halmos, halmosFail, false, 100,
			RungCounterexample, "counterexample: ", 0},
		{"halmos proved with k marker", Halmos, halmosProvedK, false, 7,
			RungProvedBounded, "k=100", 100},
		{"halmos proved via bounded flag", Halmos, halmosProvedFlag,
			false, 50, RungProvedBounded, "k=50", 50},
		{"halmos unbounded pass is inconclusive", Halmos,
			halmosPassUnbounded, false, 100, RungInconclusive,
			"inconclusive (exit output unmapped)", 0},
		{"halmos bare fail is inconclusive", Halmos, halmosFailBare,
			false, 100, RungInconclusive,
			"inconclusive (exit output unmapped)", 0},
		{"halmos timeout wins over output", Halmos, halmosFail, true,
			300, RungInconclusive, "timeout after 300s", 0},
		{"halmos empty is inconclusive", Halmos, "", false, 100,
			RungInconclusive, "inconclusive (exit output unmapped)", 0},
		{"halmos noisy log is inconclusive", Halmos, halmosNoisy, false,
			100, RungInconclusive, "inconclusive (exit output unmapped)", 0},
		{"forge counterexample with seed", ForgeFuzz, forgeFail, false,
			256, RungCounterexample, "88421337", 0},
		{"forge proved bounded", ForgeFuzz, forgePass, false, 256,
			RungProvedBounded, "k=256", 256},
		{"forge timeout", ForgeFuzz, forgePass, true, 256,
			RungInconclusive, "timeout after 256s", 0},
		{"forge empty is inconclusive", ForgeFuzz, "", false, 256,
			RungInconclusive, "inconclusive (exit output unmapped)", 0},
		{"forge noisy log is inconclusive", ForgeFuzz, forgeNoisy,
			false, 256, RungInconclusive,
			"inconclusive (exit output unmapped)", 0},
		{"forge cross-line Suite result is inconclusive", ForgeFuzz,
			forgeCrossLineSummary, false, 256, RungInconclusive,
			"inconclusive (exit output unmapped)", 0},
		{"unknown kind is inconclusive", Kind("mythril"), halmosFail,
			false, 100, RungInconclusive, "inconclusive", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rung, summary := MapRun(tc.kind, []byte(tc.out),
				tc.timedOut, tc.k)
			if rung != tc.wantRung {
				t.Fatalf("rung = %q, want %q (summary %q)",
					rung, tc.wantRung, summary)
			}
			if tc.wantSubstr != "" &&
				!strings.Contains(summary, tc.wantSubstr) {
				t.Fatalf("summary %q lacks %q", summary,
					tc.wantSubstr)
			}
			if tc.wantRung == RungProvedBounded {
				if got := BoundK(tc.kind, []byte(tc.out), tc.k); got !=
					tc.wantBoundK {
					t.Fatalf("BoundK = %d, want %d", got,
						tc.wantBoundK)
				}
			}
		})
	}
}

// TestMapRunCounterexampleExcerptCap pins the brief's ≤120-char excerpt:
// the first model line is far longer than the cap.
func TestMapRunCounterexampleExcerptCap(t *testing.T) {
	_, summary := MapRun(Halmos, []byte(halmosFail), false, 100)
	excerpt := strings.TrimPrefix(summary, "counterexample: ")
	if len([]rune(excerpt)) > 120 {
		t.Fatalf("excerpt is %d runes, want <= 120: %q",
			len([]rune(excerpt)), excerpt)
	}
	if !strings.Contains(excerpt, "getSymbolicAddress") {
		t.Fatalf("excerpt must be the first model line, got %q", excerpt)
	}
}

// TestMapRunForgeSeedPreferredOverFailLine pins the seed preference: the
// summary carries the seed line, not the FAIL line.
func TestMapRunForgeSeedPreferredOverFailLine(t *testing.T) {
	_, summary := MapRun(ForgeFuzz, []byte(forgeFail), false, 256)
	if !strings.Contains(strings.ToLower(summary), "seed") {
		t.Fatalf("summary must carry the seed line, got %q", summary)
	}
}

// TestForgePassSummaryIsPerLine (H9) is the direct law the table row above
// exercises through MapRun: a counts line promotes only when the summary
// marker ("---" or "Suite result") sits on that SAME line.
func TestForgePassSummaryIsPerLine(t *testing.T) {
	if forgePassSummary(forgeCrossLineSummary) {
		t.Fatal("a counts line promoted a run whose \"Suite result\" marker " +
			"sits on another line")
	}
	if !forgePassSummary(forgePass) {
		t.Fatal("the real forge pass log must still promote")
	}
	// The other pre-existing summary form: a "---" rule ON the counts line.
	// (H9 only tightened the Suite-result half; this shape behaved the same
	// before and after.)
	if !forgePassSummary("--- 1 passed; 0 failed; 0 skipped\n") {
		t.Fatal("the \"---\" summary form must still promote")
	}
}

// TestDegenerateBoundFloorsTheRun pins r26 F3: a STATED bound below 1 is
// not "unstated" and not a blessing — the tools themselves refuse such
// invocations (halmos --loop 0, forge --fuzz-runs 0, the twin's
// VerifierFlags raising for loop_bound < 1), so a record claiming a
// clean run under one describes a run no tool can have executed.
func TestDegenerateBoundFloorsTheRun(t *testing.T) {
	if got := InvocationBound("forge test --fuzz-runs 0"); got != BoundDegenerate {
		t.Fatalf("--fuzz-runs 0 = %d, want BoundDegenerate", got)
	}
	if got := InvocationBound("halmos check --loop=0"); got != BoundDegenerate {
		t.Fatalf("--loop=0 = %d, want BoundDegenerate", got)
	}
	if got := InvocationBound("forge test"); got != 0 {
		t.Fatalf("no flag must stay UNSTATED (0), got %d", got)
	}
	rung, summary := MapRun(ForgeFuzz, []byte(forgePass), false,
		BoundDegenerate)
	if rung != RungInconclusive || !strings.Contains(summary,
		"degenerate-bound") {
		t.Fatalf("forge --fuzz-runs 0 must floor: %q %q", rung, summary)
	}
	// The marker form carries the same statement: "k = 0" is not evidence.
	rung, summary = MapRun(Halmos, []byte(halmosStatusPassedK0), false, 100)
	if rung != RungInconclusive || !strings.Contains(summary,
		"degenerate-bound") {
		t.Fatalf("halmos k=0 marker must floor: %q %q", rung, summary)
	}
	// ...and BoundK must never hand a degenerate marker out as a bound.
	if got := BoundK(Halmos, []byte(halmosStatusPassedK0), 100); got != 0 {
		t.Fatalf("degenerate marker must not become a bound: %d", got)
	}
	// Honest bounds are untouched: marker wins, flag fallback keeps k.
	rung, _ = MapRun(Halmos, []byte(halmosProvedK), false, 100)
	if rung != RungProvedBounded {
		t.Fatalf("an honest k marker must still prove: %q", rung)
	}
	rung, _ = MapRun(ForgeFuzz, []byte(forgePass), false, 256)
	if rung != RungProvedBounded {
		t.Fatalf("an honest forge run must still prove: %q", rung)
	}
}

const halmosStatusPassedK0 = `halmos 0.3.3 --root . --match-contract InvInvariantHalmos
Status: passed [k=0, paths: 1]
Successfully proved 1 property with bound k=0
`

// TestInvocationBoundIsClickShaped pins r28 F1: InvocationBound parses the
// invocation the way the twin's click CLI binds it. Verified against the
// twin's own parser (miniprover/.venv, click 8.x):
//
//	['--loop-bound','4','--loop-bound','0'] -> 0    (and VerifierFlags raises)
//	['--loop-bound','0','--loop-bound','4'] -> 4
//	['--loop-bound','-1'] / ['--loop-bound=-1'] -> -1 (raises for < 1)
//	['--loop-bound','00'] -> 0 (raises)   ['--loop-bound','1'] -> 1
//	[] -> 4 (the default)                 ['--loop-boundx','4'] -> error
//
// So the LAST occurrence decides (click's last-wins), a signed token is a
// real value, and anything < 1 is a STATED degenerate bound — the run can
// be mapped to nothing, because the twin never ran it.
func TestInvocationBoundIsClickShaped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    int
	}{
		// last-wins: the flag that decides is the one click would
		// have bound to loop_bound.
		{"last degenerate floors", "miniprover run --loop-bound 4 " +
			"--loop-bound 0", BoundDegenerate},
		{"last honest does not floor", "miniprover run --loop-bound 0 " +
			"--loop-bound 4", 4},
		{"halmos last degenerate floors", "halmos check --loop 100 " +
			"--loop 0", BoundDegenerate},
		{"forge last honest wins", "forge test --fuzz-runs 0 " +
			"--fuzz-runs 256", 256},
		// signed tokens: both forms click's type=int accepts.
		{"negative space form", "--loop-bound -1", BoundDegenerate},
		{"negative equals form", "--loop-bound=-1", BoundDegenerate},
		{"negative fuzz-runs", "forge test --fuzz-runs -3",
			BoundDegenerate},
		// zero spellings are the same statement.
		{"zero-padded zero", "--loop-bound 00", BoundDegenerate},
		{"plain zero", "forge test --fuzz-runs 0", BoundDegenerate},
		// honest statements are untouched, in both forms.
		{"one", "--loop-bound 1", 1},
		{"space form", "--loop-bound 8", 8},
		{"equals form", "--loop-bound=8", 8},
		{"halmos loop", "halmos check --loop 100", 100},
		{"forge fuzz-runs", "forge test --fuzz-runs 200", 200},
		// no flag at all.
		{"no flag", "forge test --match-test inv_1", 0},
		// a lookalike inside another word names no flag.
		{"lookalike suffix", "--loop-boundx 4", 0},
		{"lookalike halmos", "--loopx 5", 0},
		// absurd widths keep the guard's reading (UNSTATED), never a
		// wrapped number.
		{"absurd positive", "--loop-bound 99999999999999999999999999", 0},
		{"absurd negative", "--loop-bound -99999999999999999999999999",
			BoundDegenerate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InvocationBound(tc.command); got != tc.want {
				t.Fatalf("InvocationBound(%q) = %d, want %d",
					tc.command, got, tc.want)
			}
		})
	}
}

// TestInvocationBoundFloorsTheWholeInvocation is the rung-level half of
// r28 F1: the auditor's exact repro command must floor the run through the
// same code path the bind uses, with NO rung riding it.
func TestInvocationBoundFloorsTheWholeInvocation(t *testing.T) {
	cmd := "miniprover run --loop-bound 4 --loop-bound 0"
	k := InvocationBound(cmd)
	if k != BoundDegenerate {
		t.Fatalf("InvocationBound(%q) = %d, want BoundDegenerate", cmd, k)
	}
	rung, summary := MapRun(ForgeFuzz, []byte(forgePass), false, k)
	if rung != RungInconclusive || !strings.Contains(summary,
		"degenerate-bound") {
		t.Fatalf("the auditor's repro must floor: %q %q", rung, summary)
	}
	// The mirrored direction: an honest LAST flag keeps its bound.
	if got := InvocationBound("miniprover run --loop-bound 0 " +
		"--loop-bound 4"); got != 4 {
		t.Fatalf("an honest last flag must not floor: %d", got)
	}
}

// TestR29UnreadableBoundFloorsTheWholeInvocation is the rung-level half of
// r29 F4: an invocation the parse could not READ (not a stated value it
// refuses — a construct whose argv is not derivable) floors through the
// same mapper, exactly like a degenerate bound, and its summary keeps the
// "degenerate-bound" vocabulary disposition.go classifies while naming the
// construct that stopped the parse. The fuller shell/click table lives in
// zz_r29a_parse_test.go.
func TestR29UnreadableBoundFloorsTheWholeInvocation(t *testing.T) {
	const cmd = "miniprover run --loop-bound '4" // unmatched single quote
	k, why := InvocationBoundReason(cmd)
	if k != BoundUnreadable || why == "" {
		t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want "+
			"BoundUnreadable with a construct", cmd, k, why)
	}
	if got := InvocationBound(cmd); got != BoundUnreadable {
		t.Fatalf("InvocationBound(%q) = %d, want BoundUnreadable", cmd, got)
	}
	// The output that WOULD prove under an honest bound must not promote:
	// the invocation it claims to come from cannot be executed at all.
	rung, summary := MapRun(ForgeFuzz, []byte(forgePass), false, k, why)
	if rung == RungProvedBounded {
		t.Fatalf("no rung may ride an unreadable invocation: %q %q",
			rung, summary)
	}
	if !strings.Contains(summary, "degenerate-bound") ||
		!strings.Contains(summary, "invocation-unreadable: "+why) {
		t.Fatalf("the floor must keep the vocabulary and name the "+
			"construct: %q", summary)
	}
	if got := BoundK(ForgeFuzz, []byte(forgePass), k); got != 0 {
		t.Fatalf("an unreadable invocation states no bound: %d", got)
	}
	// The degenerate half keeps r28's wording verbatim.
	_, deg := MapRun(ForgeFuzz, []byte(forgePass), false, BoundDegenerate)
	if deg != "inconclusive (degenerate-bound: the invocation states "+
		"no bound >= 1)" {
		t.Fatalf("degenerate wording changed: %q", deg)
	}
	// BoundK never hands a flooring value out as a bound: with no marker
	// in the output, the invocation's own (unreadable) value cannot
	// become a k. (A marker in the output is the output's own statement
	// and still wins — BoundK is only consulted for proved-bounded, which
	// an unreadable invocation never reaches.)
	if got := BoundK(Halmos, []byte(halmosPassUnbounded),
		BoundUnreadable); got != 0 {
		t.Fatalf("an unreadable invocation must not become a k: %d", got)
	}
}
