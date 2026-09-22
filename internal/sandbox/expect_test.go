package sandbox

// v16 P1-10a §5.3: the two expectation keys and ExecOutputProblem's forge
// branch under them. The load-bearing property is the ABSENT case: a record
// with no expected_outcome takes exactly today's verdict, byte for byte,
// while expected_outcome "fail" makes a failing suite the EXPECTED shape —
// and the NoTests / no-counters verdicts stay unconditional under BOTH
// expectations (a run that matched nothing proves nothing).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// withExpect stamps expectation keys onto an in-memory exec record (the
// hand-built execRec shape carries no other keys; nothing here reads the
// record file).
func withExpect(rec validation.Value, outcome, sig string) validation.Value {
	rec.O = append(rec.O,
		validation.KV{K: "expected_outcome", V: validation.VStr(outcome)})
	if sig != "" {
		rec.O = append(rec.O,
			validation.KV{K: "expected_failure", V: validation.VStr(sig)})
	}
	return rec
}

// noCountersProblem is the pre-change no-counters refusal, byte for byte —
// the branch D3 touches.
const noCountersProblem = "forge output has no test counters and no PASS marker — " +
	"cannot verify a test actually ran and passed; capture the full " +
	"forge output and re-run"

// outputProblemCase is one row of the expectation tables below: want ""
// means admitted (nil problem), anything else is byte-exact.
type outputProblemCase struct {
	name string
	rec  validation.Value
	want string
}

// runOutputProblemCases runs the rows (extracted for the funlen cap).
func runOutputProblemCases(t *testing.T, cases []outputProblemCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prob := ExecOutputProblem(c.rec)
			if c.want == "" {
				if prob != nil {
					t.Fatalf("the output must be admitted here; got "+
						"problem %q", *prob)
				}
				return
			}
			if prob == nil {
				t.Fatalf("want problem %q, got nil", c.want)
			}
			if *prob != c.want {
				t.Fatalf("problem drifted byte-for-byte:\n got %q\nwant %q",
					*prob, c.want)
			}
		})
	}
}

// The failing-suite verdict: absent and explicit "pass" refuse with the
// EXACT pre-change message; "fail" admits it (the branch is the only one
// the expectation gates).
func TestExecOutputProblemFailingSuiteExpectation(t *testing.T) {
	const failing = "Ran 5 tests for test/DebtManager.t.sol\n" +
		"[FAIL] testFakeMarket()\n" +
		"Suite result: FAILED. 0 passed; 5 failed; 0 skipped; 0 pending"
	const want = "forge output shows a failing suite (ran=5, failed=5, " +
		"fail_marker=True) — a failing test is not a passing reproduction"
	runOutputProblemCases(t, []outputProblemCase{
		{"absent expectation", execRec(t, "forge test", failing), want},
		{"explicit pass", withExpect(
			execRec(t, "forge test", failing), EXPECT_PASS, ""), want},
		{"fail admits the expected shape", withExpect(
			execRec(t, "forge test", failing), EXPECT_FAIL, "testFakeMarket"), ""},
	})
}

// The UNCONDITIONAL verdicts: a run that matched nothing refuses under
// either expectation — NoTests, and the no-counters branch when NOTHING
// (no counter, no PASS marker, no [FAIL] marker) proves a run happened.
func TestExecOutputProblemUnconditionalUnderFail(t *testing.T) {
	runOutputProblemCases(t, []outputProblemCase{
		{"no tests under fail",
			withExpect(execRec(t, "forge test", "No tests found in test\nRan 0 tests"),
				EXPECT_FAIL, "MarketNotListed"),
			"forge output shows no tests were run (ran=0); 'No tests found' " +
				"is not a reproduction — check the --match-test filter / " +
				"test path and re-run"},
		{"no counters and no marker under fail",
			withExpect(execRec(t, "forge test", "market not listed"),
				EXPECT_FAIL, "MarketNotListed"), noCountersProblem},
	})
}

// D3 (adversarial review): under EXPECT_FAIL a [FAIL] marker is itself the
// proof that a run happened, so the no-counters branch must not demand a
// PASS marker from a run expected to fail. The branch keeps its exact bytes
// — and its unconditional force — under EXPECT_PASS and when absent.
func TestExecOutputProblemFailMarkerProvesRun(t *testing.T) {
	const marked = "[FAIL] testFakeMarket() MarketNotListed not raised"
	const bare = "market not listed"
	runOutputProblemCases(t, []outputProblemCase{
		{"fail + [FAIL] marker, no counters -> admitted",
			withExpect(execRec(t, "forge test", marked), EXPECT_FAIL,
				"MarketNotListed"), ""},
		{"pass + no counters, no marker -> the exact old bytes",
			withExpect(execRec(t, "forge test", bare), EXPECT_PASS, ""),
			noCountersProblem},
		{"absent + no counters, no marker -> the exact old bytes",
			execRec(t, "forge test", bare), noCountersProblem},
		{"fail + no counters, no marker -> still refused",
			withExpect(execRec(t, "forge test", bare), EXPECT_FAIL,
				"MarketNotListed"), noCountersProblem},
	})
}

// D1 (adversarial review): the marker split. A forge-like command needs the
// per-test [FAIL token — the suite summary line never carries it — while an
// arbitrary harness keeps the plain FAIL substring (no better marker
// exists there). The separator after the token is deliberately unpinned.
func TestFailureSignatureOnFailLineMarkers(t *testing.T) {
	const sig = "MarketNotListed"
	cases := []struct {
		name, command, stdout string
		want                  bool
	}{
		{"forge: suite summary is not a per-test failure", "forge test",
			"Suite result: FAILED. 0 passed; 5 failed", false},
		{"forge: [FAIL: rendering", "forge test",
			"[FAIL: MarketNotListed not raised] testX()", true},
		{"forge: [FAIL. Reason: rendering", "forge test",
			"[FAIL. Reason: MarketNotListed not raised] testX()", true},
		{"forge: bare FAIL line without the token", "forge test",
			"FAIL MarketNotListed not raised", false},
		{"non-forge: plain FAIL substring", "python harness.py",
			"FAIL MarketNotListed not raised", true},
		{"non-forge: summary-only FAILED names nothing", "python harness.py",
			"Suite result: FAILED. 0 passed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FailureSignatureOnFailLine(
				execRec(t, c.command, c.stdout), sig)
			if got != c.want {
				t.Fatalf("FailureSignatureOnFailLine = %v, want %v", got, c.want)
			}
		})
	}
}

// The readers: absent means pass; only an explicit "fail" buys the fail
// path; a tampered value never unlocks it.
func TestExecExpectationReaders(t *testing.T) {
	absent := execRec(t, "forge test", "x")
	if got := ExecExpectedOutcome(absent); got != EXPECT_PASS {
		t.Errorf("absent expected_outcome reads %q, want %q (the "+
			"backward-compatibility law)", got, EXPECT_PASS)
	}
	junk := withExpect(execRec(t, "forge test", "x"), "banana", "")
	if got := ExecExpectedOutcome(junk); got != EXPECT_PASS {
		t.Errorf("junk expected_outcome reads %q, want %q (a tampered "+
			"value must never unlock the fail path)", got, EXPECT_PASS)
	}
	fail := withExpect(execRec(t, "forge test", "x"), EXPECT_FAIL, "sig")
	if got := ExecExpectedOutcome(fail); got != EXPECT_FAIL {
		t.Errorf("explicit fail reads %q, want %q", got, EXPECT_FAIL)
	}
	if got := ExecExpectedFailure(fail); got != "sig" {
		t.Errorf("ExecExpectedFailure = %q, want %q", got, "sig")
	}
	if got := ExecExpectedFailure(absent); got != "" {
		t.Errorf("absent expected_failure reads %q, want \"\"", got)
	}
	// the stamp helper keeps legacy records byte-for-byte: no keys, no drift
	if got := strings.Contains(validation.DumpIndentedASCII(absent),
		"expected_"); got {
		t.Error("a legacy record must carry no expectation keys at all")
	}
}

// newHostExpectSandbox is a fresh host-readonly sandbox on a fresh
// campaign — the run-record tests below each need their own ledger.
func newHostExpectSandbox(t *testing.T) *Sandbox {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Expect Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

// TestRunRecordCarriesDeclaredExpectation pins the WRITE half of the
// declaration: both keys land in the record's FIRST write — before the
// payload runs. The payload here reads the record as seen from INSIDE the
// run and copies it out, so a regression that stamped the expectation after
// execution would leave the snapshot keyless (and this test would fail); the
// original final-record assertions are kept on top of that.
func TestRunRecordCarriesDeclaredExpectation(t *testing.T) {
	sb := newHostExpectSandbox(t)
	snap := filepath.Join(t.TempDir(), "seen-record.json")
	cmd := `cat "$WEBV2_TEST_EXECS"/*/exec_record.json > "$WEBV2_TEST_SNAP"`
	rec, err := sb.Run(cmd, RunOpts{Timeout: 30,
		Expect: EXPECT_FAIL, ExpectFailure: "MissingGuard",
		Env: []EnvVar{
			{Key: "WEBV2_TEST_EXECS", Value: sb.Campaign.ExecsDir},
			{Key: "WEBV2_TEST_SNAP", Value: snap},
		}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	assertExpectationSeenInsideRun(t, snap)
	assertFinalExpectation(t, rec)
}

// assertExpectationSeenInsideRun is the load-bearing half: the snapshot the
// PAYLOAD wrote must already carry both keys, and must still be the
// pre-execution write (exit_status null) — after the run it is an integer.
func assertExpectationSeenInsideRun(t *testing.T, snap string) {
	t.Helper()
	seen, err := validation.ReadJson(snap)
	if err != nil {
		t.Fatalf("the payload did not capture the record it ran under: %v", err)
	}
	if got := validation.ObjStr(seen, "expected_outcome"); got != EXPECT_FAIL {
		t.Errorf("record seen INSIDE the run has expected_outcome = %q, "+
			"want %q (the declaration must precede the payload)", got,
			EXPECT_FAIL)
	}
	if got := validation.ObjStr(seen, "expected_failure"); got != "MissingGuard" {
		t.Errorf("record seen INSIDE the run has expected_failure = %q, "+
			"want %q", got, "MissingGuard")
	}
	if exit := validation.ObjAt(seen, "exit_status"); exit.Kind != validation.Null {
		t.Errorf("the snapshot must be the PRE-execution write "+
			"(exit_status null); got %s", validation.PyRepr(exit))
	}
}

// assertFinalExpectation is the original final-record assertion, unchanged.
func assertFinalExpectation(t *testing.T, rec validation.Value) {
	t.Helper()
	if got := validation.ObjStr(rec, "expected_outcome"); got != EXPECT_FAIL {
		t.Errorf("record expected_outcome = %q, want %q (declared before "+
			"the run, in the record's first write)", got, EXPECT_FAIL)
	}
	if got := validation.ObjStr(rec, "expected_failure"); got != "MissingGuard" {
		t.Errorf("record expected_failure = %q, want %q", got, "MissingGuard")
	}
}

// TestRunRecordWithoutDeclarationIsKeyless pins the load-bearing backward
// law: an undeclared run writes NO expectation keys (legacy shape).
func TestRunRecordWithoutDeclarationIsKeyless(t *testing.T) {
	sb := newHostExpectSandbox(t)
	rec, err := sb.Run("echo plain", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, key := range []string{"expected_outcome", "expected_failure"} {
		for _, kv := range rec.O {
			if kv.K == key {
				t.Errorf("an undeclared run must write no %s key", key)
			}
		}
	}
}

// TestRunRecordContradictionRefusedAtWrite: a contradictory RunOpts pair is
// refused by the SCHEMA on the pre-run write (validation.WriteJson validates
// against sandbox_execution; no extra Validate call exists on this path by
// design) — the write happens before execution, so the payload never runs.
// The side-effect marker proves that: if the refusal ever moved after
// execute(), the marker file would exist.
func TestRunRecordContradictionRefusedAtWrite(t *testing.T) {
	sb := newHostExpectSandbox(t)
	marker := filepath.Join(t.TempDir(), "payload-ran")
	_, err := sb.Run(`touch "$WEBV2_TEST_MARKER"`, RunOpts{Timeout: 30,
		Expect: EXPECT_PASS, ExpectFailure: "sig",
		Env: []EnvVar{{Key: "WEBV2_TEST_MARKER", Value: marker}}})
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("a contradictory declaration must be refused by the "+
			"schema on the record write; got: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the payload RAN despite the pre-run write being refused — " +
			"the refusal must happen before execution")
	}
}
