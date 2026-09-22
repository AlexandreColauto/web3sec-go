package sandbox

// v16 P1-10a §5.3: the two expectation keys and ExecOutputProblem's forge
// branch under them. The load-bearing property is the ABSENT case: a record
// with no expected_outcome takes exactly today's verdict, byte for byte,
// while expected_outcome "fail" makes a failing suite the EXPECTED shape —
// and the NoTests / no-counters verdicts stay unconditional under BOTH
// expectations (a run that matched nothing proves nothing).

import (
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

// The failing-suite verdict: absent and explicit "pass" refuse with the
// EXACT pre-change message; "fail" admits it (the branch is the only one
// the expectation gates).
func TestExecOutputProblemFailingSuiteExpectation(t *testing.T) {
	const failing = "Ran 5 tests for test/DebtManager.t.sol\n" +
		"[FAIL] testFakeMarket()\n" +
		"Suite result: FAILED. 0 passed; 5 failed; 0 skipped; 0 pending"
	const want = "forge output shows a failing suite (ran=5, failed=5, " +
		"fail_marker=True) — a failing test is not a passing reproduction"
	cases := []struct {
		name string
		rec  validation.Value
		want string // "" = admitted (nil problem)
	}{
		{"absent expectation", execRec(t, "forge test", failing), want},
		{"explicit pass", withExpect(
			execRec(t, "forge test", failing), EXPECT_PASS, ""), want},
		{"fail admits the expected shape", withExpect(
			execRec(t, "forge test", failing), EXPECT_FAIL, "testFakeMarket"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runFailingSuiteCase(t, c)
		})
	}
}

// runFailingSuiteCase is one subtest body (extracted for the funlen cap).
func runFailingSuiteCase(t *testing.T, c struct {
	name string
	rec  validation.Value
	want string
}) {
	t.Helper()
	prob := ExecOutputProblem(c.rec)
	if c.want == "" {
		if prob != nil {
			t.Fatalf("under 'fail' a failing suite is the expected "+
				"shape; got problem %q", *prob)
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
}

// The two UNCONDITIONAL verdicts: a run that matched nothing refuses under
// either expectation — NoTests and the no-counters branch.
func TestExecOutputProblemUnconditionalUnderFail(t *testing.T) {
	cases := []struct {
		name, stdout, want string
	}{
		{"no tests under fail",
			"No tests found in test\nRan 0 tests",
			"forge output shows no tests were run (ran=0); 'No tests found' " +
				"is not a reproduction — check the --match-test filter / " +
				"test path and re-run"},
		{"no counters under fail",
			"[FAIL] testFakeMarket() MarketNotListed not raised",
			"forge output has no test counters and no PASS marker — cannot " +
				"verify a test actually ran and passed; capture the full " +
				"forge output and re-run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := withExpect(execRec(t, "forge test", c.stdout),
				EXPECT_FAIL, "MarketNotListed")
			prob := ExecOutputProblem(rec)
			if prob == nil {
				t.Fatal("a run that matched nothing proves nothing under " +
					"either expectation; got nil")
			}
			if *prob != c.want {
				t.Fatalf("problem = %q\nwant      %q", *prob, c.want)
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
// payload runs.
func TestRunRecordCarriesDeclaredExpectation(t *testing.T) {
	sb := newHostExpectSandbox(t)
	rec, err := sb.Run("echo declared", RunOpts{Timeout: 30,
		Expect: EXPECT_FAIL, ExpectFailure: "MissingGuard"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
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
func TestRunRecordContradictionRefusedAtWrite(t *testing.T) {
	sb := newHostExpectSandbox(t)
	_, err := sb.Run("echo should-not-run", RunOpts{Timeout: 30,
		Expect: EXPECT_PASS, ExpectFailure: "sig"})
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("a contradictory declaration must be refused by the "+
			"schema on the record write; got: %v", err)
	}
}
