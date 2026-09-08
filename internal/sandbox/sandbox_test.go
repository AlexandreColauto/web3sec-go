package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// execRec builds the exec-record shape register_exec writes (command plus
// the captured-output paths); the sandbox phase owns the real writer, so
// the tests mint the record directly.
func execRec(t *testing.T, command, stdout string) validation.Value {
	t.Helper()
	return recWithCommand(t, validation.VStr(command), stdout)
}

// recWithCommand is execRec with a raw command Value, for the hostile-input
// cases.
func recWithCommand(t *testing.T, command validation.Value, stdout string) validation.Value {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdout.txt")
	if err := os.WriteFile(p, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	return validation.VObj(
		kv("command", command),
		kv("stdout_path", validation.VStr(p)),
	)
}

// Port of tests/test_evidence_integrity.py::test_forge_test_summary_parses_counters.
func TestForgeTestSummaryParsesCounters(t *testing.T) {
	s := ForgeTestSummary("Ran 3 tests for test/poc.t.sol\n[PASS] a\n[PASS] b\n[FAIL] c")
	if s.Ran == nil || *s.Ran != 3 {
		t.Errorf("ran = %v, want 3", pyReprOptInt(s.Ran))
	}
	if !s.HasPassMarker {
		t.Error("has_pass_marker = false, want true")
	}
	if !s.HasFailMarker {
		t.Error("has_fail_marker = false, want true")
	}
	if s.NoTests {
		t.Error("no_tests = true, want false")
	}
}

// Port of tests/test_review_fixes.py::test_b3_bare_pass_word_is_not_a_forge_marker:
// only EXPLICIT pass markers count.
func TestForgeTestSummaryPassMarkerIsExplicit(t *testing.T) {
	if ForgeTestSummary("the exploit pass could not be loaded").HasPassMarker {
		t.Error("prose containing 'pass' must not be a pass marker")
	}
	s := ForgeTestSummary("Ran 0 tests, no tests pass")
	if s.HasPassMarker {
		t.Error("'no tests pass' must not be a pass marker")
	}
	if !s.NoTests || s.Ran == nil || *s.Ran != 0 {
		t.Errorf("no_tests/ran = %v/%v, want true/0", s.NoTests, pyReprOptInt(s.Ran))
	}
	for _, text := range []string{
		"PASS: poc\n",
		"[PASS] poc",
		"Ran 1 test suite in 5.2ms (test suite successful)",
		"Suite result: ok. 1 passed; 0 failed; 0 skipped; 0 pending",
	} {
		if !ForgeTestSummary(text).HasPassMarker {
			t.Errorf("explicit pass marker not detected in %q", text)
		}
	}
}

// Port of tests/test_evidence_integrity.py::test_forge_no_tests_is_a_problem.
func TestForgeNoTestsIsAProblem(t *testing.T) {
	rec := execRec(t, "forge test --match-test test_exploit",
		"No tests found in test\nRan 0 tests")
	prob := ExecOutputProblem(rec)
	if prob == nil {
		t.Fatal("exec_output_problem = nil, want a problem")
	}
	want := "forge output shows no tests were run (ran=0); 'No tests found' is not a " +
		"reproduction — check the --match-test filter / test path and re-run"
	if *prob != want {
		t.Errorf("problem = %q\nwant      %q", *prob, want)
	}
}

// Port of tests/test_evidence_integrity.py::test_forge_passing_output_is_not_a_problem.
// The first case is the conftest sandboxed_exec fixture (bare PASS marker,
// no counters); the second is real foundry passing output with counters.
func TestForgePassingOutputIsNotAProblem(t *testing.T) {
	rec := execRec(t, "forge test --match-test test_exploit", "PASS: test_exploit\n")
	if prob := ExecOutputProblem(rec); prob != nil {
		t.Errorf("bare PASS marker flagged: %q", *prob)
	}
	rec2 := execRec(t, "forge test --match-test poc",
		"Ran 1 test for test/poc.t.sol\n[PASS] poc\n")
	if prob := ExecOutputProblem(rec2); prob != nil {
		t.Errorf("passing forge output flagged: %q", *prob)
	}
}

// Port of tests/test_evidence_integrity.py::test_exec_output_problem_null_for_non_forge.
func TestExecOutputProblemNullForNonForge(t *testing.T) {
	rec := execRec(t, "python3 exploit.py", "drained 1234 wei")
	if prob := ExecOutputProblem(rec); prob != nil {
		t.Errorf("non-forge command flagged: %q", *prob)
	}
	// a non-string command in a hostile exec_record.json must not skip the
	// gate (Python raises AttributeError there; we fail closed)
	hostile := recWithCommand(t, validation.VInt(1), "")
	if prob := ExecOutputProblem(hostile); prob == nil {
		t.Error("non-string command must not bypass the forge gate")
	}
	nullCmd := recWithCommand(t, validation.VNull(), "")
	if prob := ExecOutputProblem(nullCmd); prob != nil {
		t.Errorf("null command flagged: %q", *prob)
	}
}

// The remaining verdicts of exec_output_problem, byte-exact.
func TestExecOutputProblemVerdicts(t *testing.T) {
	checks := []struct {
		command, stdout, want string
	}{
		{"forge test", "",
			"forge output has no test counters and no PASS marker — cannot verify a test " +
				"actually ran and passed; capture the full forge output and re-run"},
		{"forge test", "[FAIL] x",
			"forge output shows a failing suite (ran=None, failed=None, fail_marker=True) " +
				"— a failing test is not a passing reproduction"},
		{"forge test", "Ran 2 tests\n1 failed\n[PASS] x",
			"forge output shows a failing suite (ran=2, failed=1, fail_marker=False) " +
				"— a failing test is not a passing reproduction"},
		{"forge test", "Ran 0 tests\n[PASS] x",
			"forge output shows no tests were run (ran=0); 'No tests found' is not a " +
				"reproduction — check the --match-test filter / test path and re-run"},
		{"forge test", "Suite result: ok. 1 passed; 0 failed; 0 skipped", ""},
		{"foundry test", "Ran 1 test\n[PASS] a", ""},
	}
	for _, c := range checks {
		prob := ExecOutputProblem(execRec(t, c.command, c.stdout))
		if c.want == "" {
			if prob != nil {
				t.Errorf("%q -> %q, want nil", c.stdout, *prob)
			}
			continue
		}
		if prob == nil || *prob != c.want {
			t.Errorf("%q -> %v\nwant %q", c.stdout, prob, c.want)
		}
	}
}

// looks_like_forge_test: word boundaries, case-insensitive.
func TestLooksLikeForgeTest(t *testing.T) {
	yes := []string{"forge test", "FORGE TEST", "foundry test", "cd x && forge test",
		"café forge", "a-foundry-b"}
	no := []string{"", "forgetest", "forged", "foundrys", "python3 exploit.py"}
	for _, c := range yes {
		if !LooksLikeForgeTest(c) {
			t.Errorf("LooksLikeForgeTest(%q) = false, want true", c)
		}
	}
	for _, c := range no {
		if LooksLikeForgeTest(c) {
			t.Errorf("LooksLikeForgeTest(%q) = true, want false", c)
		}
	}
}

// exec_output concatenates stdout then stderr and fails closed on anything
// that is not a readable regular file.
func TestExecOutputReadsStdoutThenStderr(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	errp := filepath.Join(dir, "err.txt")
	if err := os.WriteFile(out, []byte("out"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errp, []byte("err"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kv("stdout_path", validation.VStr(out)),
		kv("stderr_path", validation.VStr(errp)),
	)
	if got := ExecOutput(rec); got != "outerr" {
		t.Errorf("ExecOutput = %q, want %q", got, "outerr")
	}
	// missing / empty / directory paths read as empty
	rec = validation.VObj(
		kv("stdout_path", validation.VStr(filepath.Join(dir, "nope"))),
		kv("stderr_path", validation.VStr(dir)),
	)
	if got := ExecOutput(rec); got != "" {
		t.Errorf("ExecOutput = %q, want empty", got)
	}
	if got := ExecOutput(validation.VObj()); got != "" {
		t.Errorf("ExecOutput(empty rec) = %q, want empty", got)
	}
}

// exec_output's reader is read_text(encoding="utf-8", errors="replace"):
// universal newlines and CPython's maximal-subpart U+FFFD replacement.
// Vectors measured against the Python twin (web3sec-final).
func TestExecOutputReplaceDecoding(t *testing.T) {
	raw := "a\r\nb\rc\n\xe2\x82\x41 \xed\xa0\x80 \xc0\x80 \xf0\x9f\x92 \xff"
	want := "a\nb\nc\n\ufffdA \ufffd\ufffd\ufffd \ufffd\ufffd \ufffd \ufffd"
	p := filepath.Join(t.TempDir(), "stdout.bin")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(kv("stdout_path", validation.VStr(p)))
	if got := ExecOutput(rec); got != want {
		t.Errorf("ExecOutput = %q\nwant           %q", got, want)
	}
}
