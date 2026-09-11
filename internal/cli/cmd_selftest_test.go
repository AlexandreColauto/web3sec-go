package cli

// cmd_selftest_test: the port of web3sec-final/verify.py's contract.
//
// Covered here:
//   * fast mode is green and its output SHAPE matches verify.py's
//     (header, 60-char rule, `[PASS] <name padded to 12> <detail>`, footer,
//     exit code) with the documented Go check-name mapping;
//   * --full appends the suite check and its exit code follows the suite;
//   * a forced-failure check makes the command exit 1 with the Python
//     footer ("N check(s) FAILED");
//   * a released binary (no module tree) reports the suite location instead
//     of failing.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// selftestOut runs the command in-process and returns (exit, output).
func selftestOut(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	code := Run(append([]string{"selftest"}, args...), &buf, &buf)
	return code, buf.String()
}

// verifyLineRe is verify.py's per-check line shape.
var verifyLineRe = regexp.MustCompile(`^\[(PASS|FAIL)\] (\S+) +(\S.*)?$`)

// TestSelftestFastModeMatchesVerifyShape: fast mode is green, prints the
// three checks in verify.py's order, and every line obeys the shared shape.
func TestSelftestFastModeMatchesVerifyShape(t *testing.T) {
	code, out := selftestOut(t)
	if code != 0 {
		t.Fatalf("selftest exit = %d, want 0\n%s", code, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 7 {
		t.Fatalf("want 7 lines (header, rule, 3 checks, rule, footer), got %d:\n%s",
			len(lines), out)
	}
	if lines[0] != "web3sec-go self-check (fast — pass --full for the go test suite)" {
		t.Errorf("header = %q", lines[0])
	}
	if lines[1] != selftestRule || lines[5] != selftestRule {
		t.Errorf("rules wrong: %q / %q", lines[1], lines[5])
	}
	if lines[6] != "ALL PASS" {
		t.Errorf("footer = %q", lines[6])
	}
	// The Python names -> Go names mapping (documented in cmd_selftest.go).
	want := []string{"build-sweep", "walkthrough", "cli-audit"}
	for i, name := range want {
		m := verifyLineRe.FindStringSubmatch(lines[2+i])
		if m == nil {
			t.Fatalf("line %d does not match verify.py shape: %q", 3+i, lines[2+i])
		}
		if m[1] != "PASS" || m[2] != name {
			t.Errorf("check %d = [%s] %s, want [PASS] %s", i, m[1], m[2], name)
		}
	}
	// Python's detail[:120] clip.
	for _, ln := range lines[2:5] {
		if len([]rune(ln)) > 120+len("[PASS] ")+13 {
			t.Errorf("line not clipped to 120 detail runes: %q", ln)
		}
	}
	// The walkthrough detail mirrors Python's terminal line.
	if !strings.Contains(lines[3], "done. campaign kept at ") {
		t.Errorf("walkthrough detail = %q", lines[3])
	}
	if !strings.Contains(lines[4], "audit PASS") {
		t.Errorf("cli-audit detail = %q", lines[4])
	}
}

// TestSelftestFullPlanAddsGoTest: --full appends the suite check and the
// eval-suite self-score proof, in that order.
func TestSelftestFullPlanAddsGoTest(t *testing.T) {
	fast := selftestPlan(false)
	full := selftestPlan(true)
	if len(fast) != 3 || len(full) != 5 {
		t.Fatalf("plan sizes = %d / %d, want 3 / 5", len(fast), len(full))
	}
	if full[3].name != "go-test" {
		t.Errorf("--full check 3 = %q, want go-test", full[3].name)
	}
	if full[4].name != "evalsuite-selfcheck" {
		t.Errorf("--full check 4 = %q, want evalsuite-selfcheck", full[4].name)
	}
	for i := range fast {
		if fast[i].name != full[i].name {
			t.Errorf("check %d differs: %q vs %q", i, fast[i].name, full[i].name)
		}
	}
}

// TestSelftestEvalsuiteSelfcheck: the step proves the scorer against the
// gold suite itself (19/19, FP 0) and prints the pinned ok line — scorer
// semantics, not a detector claim.
func TestSelftestEvalsuiteSelfcheck(t *testing.T) {
	ok, detail := checkEvalsuiteSelfcheck()
	if !ok {
		t.Fatalf("checkEvalsuiteSelfcheck = false (%s)", detail)
	}
	want := "ok: gold suite self-scores 19/19 (95% CI 83.2–100.0%) — " +
		"scorer semantics proven, NOT a detector claim"
	if detail != want {
		t.Fatalf("detail = %q\nwant %q", detail, want)
	}
}

// TestSelftestForcedFailureExitsOne: a failing check yields exit 1 and the
// Python footer. The seam is the plan var, never production behavior.
func TestSelftestForcedFailureExitsOne(t *testing.T) {
	orig := selftestPlan
	defer func() { selftestPlan = orig }()
	selftestPlan = func(bool) []selftestCheck {
		return []selftestCheck{
			{"build-sweep", func() (bool, string) { return true, "ok" }},
			{"walkthrough", func() (bool, string) { return false, "forced failure" }},
		}
	}
	code, out := selftestOut(t)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "[FAIL] walkthrough  forced failure") {
		t.Errorf("missing FAIL line:\n%s", out)
	}
	if !strings.Contains(out, "1 check(s) FAILED") {
		t.Errorf("missing footer:\n%s", out)
	}
}

// TestSelftestGoTestReleasedBinary: outside a module tree the suite check
// reports the location and passes (the Python twin needs the source tree
// for --full as well).
func TestSelftestGoTestReleasedBinary(t *testing.T) {
	t.Chdir(t.TempDir())
	ok, detail := checkGoTest()
	if !ok {
		t.Fatalf("checkGoTest = false (%s), want true for a released binary", detail)
	}
	if !strings.Contains(detail, "go test ./... -count=1") {
		t.Errorf("detail does not name the suite: %q", detail)
	}
}

// TestSelftestGoTestExitCode: in a module tree the check follows the
// suite's verdict — green passes, a failing test fails. A throwaway module
// named `websec` keeps findGoModuleRoot honest without touching the real
// tree.
func TestSelftestGoTestExitCode(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module websec\n\ngo 1.26\n")
	writeFile(t, filepath.Join(dir, "lib.go"), "package lib\n\nfunc One() int { return 1 }\n")
	writeFile(t, filepath.Join(dir, "lib_test.go"),
		"package lib\n\nimport \"testing\"\n\nfunc TestOne(t *testing.T) {\n\tif One() != 1 { t.Fatal(\"no\") }\n}\n")
	t.Chdir(dir)
	if ok, detail := checkGoTest(); !ok {
		t.Fatalf("green suite: checkGoTest = false (%s)", detail)
	}
	writeFile(t, filepath.Join(dir, "lib_test.go"),
		"package lib\n\nimport \"testing\"\n\nfunc TestOne(t *testing.T) {\n\tt.Fatal(\"red\")\n}\n")
	if ok, _ := checkGoTest(); ok {
		t.Fatal("red suite: checkGoTest = true, want false")
	}
}

// TestSelftestBuildSweepInModule: from the real tree the sweep runs
// `go build ./...` and still passes.
func TestSelftestBuildSweepInModule(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if findGoModuleRoot() == "" {
		t.Skipf("not in the module tree (%s)", wd)
	}
	ok, detail := checkBuildSweep()
	if !ok {
		t.Fatalf("checkBuildSweep = false (%s)", detail)
	}
	if !strings.Contains(detail, "go build ./... ok") {
		t.Errorf("detail lacks the build sweep: %q", detail)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSelftestRejectsUnknownFlag: the Python twin ignored unknown argv
// because it only tested membership; the port kept that, so `selftest --ful`
// ran the fast plan and printed PASS — which reads as "the suite is green".
func TestSelftestRejectsUnknownFlag(t *testing.T) {
	code, out, errS := run(t, "--root", mkroot(t), "selftest", "--ful")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "unrecognized arguments: --ful") {
		t.Errorf("stderr = %q, want the unrecognized-arguments message", errS)
	}
	if strings.Contains(out, "PASS") {
		t.Errorf("stdout = %q: a refused run must not print results", out)
	}
}
