package trajectory

// R43B (P3-2) at the per-event finding probe: it folded EVERY os.Stat error
// into "names a finding that does not exist". An unstattable path (EACCES,
// ENAMETOOLONG, EIO) is not an absent finding — the reader has no evidence
// about it, so it says so and judges nothing else. Both answers are
// fail-closed (a problem, never a pass); the defect is the misattribution.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

const r43bAbsentFindingID = "F-000000000000"

// r43bLongFindingID is a syntactically valid F- reference whose file name
// exceeds NAME_MAX: os.Stat answers ENAMETOOLONG — a read failure, never
// ENOENT — so the probe cannot call the finding absent. Unlike a chmod-based
// probe it holds for root too.
func r43bLongFindingID() string {
	return "F-" + strings.Repeat("x", 300)
}

// r43bRefCampaign logs one model.rejected whose ref names fid (the shape
// TestDanglingRefFlagged uses) and returns the campaign.
func r43bRefCampaign(t *testing.T, fid string) *state.Campaign {
	t.Helper()
	c := newCamp(t)
	pin(t, c)
	if _, err := RecordModelEvent(c, "model.rejected", validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("kind", validation.VStr("hypothesis")),
		kv("error", validation.VStr("hypothesis contract failure at <root>: "+
			"assumptions missing")),
		kv("payload_sha256", validation.VStr(strings.Repeat("c", 64)))),
		&fid); err != nil {
		t.Fatal(err)
	}
	return c
}

// r43bProblems verifies the campaign and returns the problem strings.
func r43bProblems(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatalf("VerifyTrajectory: %v", err)
	}
	if objAt(report, "ok").B {
		t.Fatalf("ok = true, want false; problems %v", objAt(report, "problems"))
	}
	problems := []string{}
	for _, p := range objAt(report, "problems").A {
		problems = append(problems, scalarText(p))
	}
	return problems
}

func r43bJoined(problems []string) string {
	return strings.Join(problems, "\n")
}

// TestR43bUnstattableRefIsAReadFailureNotAnAbsentFinding is the misattribution:
// the ref's file name cannot be stat'ed at all, and the report must name the
// read failure and the path instead of asserting the finding does not exist.
func TestR43bUnstattableRefIsAReadFailureNotAnAbsentFinding(t *testing.T) {
	fid := r43bLongFindingID()
	c := r43bRefCampaign(t, fid)
	path := findings.FindingPath(c, fid)
	if _, err := os.Stat(path); err == nil || os.IsNotExist(err) {
		t.Fatalf("probe precondition: os.Stat(%s) = %v, want a non-NotExist "+
			"failure", path, err)
	}
	joined := r43bJoined(r43bProblems(t, c))
	t.Logf("ref %s -> %s", fid, joined)
	if strings.Contains(joined, "does not exist") {
		t.Errorf("an unstattable finding was reported as absent:\n%s", joined)
	}
	if !strings.Contains(joined, fid) {
		t.Errorf("the report does not name the finding %s:\n%s", fid, joined)
	}
	if !strings.Contains(joined, path) {
		t.Errorf("the report does not name the path %s:\n%s", path, joined)
	}
	if !strings.Contains(joined, "cannot be read") {
		t.Errorf("the report does not name the read failure:\n%s", joined)
	}
}

// TestR43bUnsearchableFindingsDirIsAReadFailure is the realistic half: the
// findings/ directory exists but cannot be searched, so EACCES reaches the
// probe. Skipped where the process can stat through mode 000 (root).
func TestR43bUnsearchableFindingsDirIsAReadFailure(t *testing.T) {
	fid := "F-0000000000ab"
	c := r43bRefCampaign(t, fid)
	path := findings.FindingPath(c, fid)
	if err := os.Chmod(c.FindingsDir, 0o000); err != nil {
		t.Skipf("chmod 000 %s: %v", c.FindingsDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(c.FindingsDir, 0o755) })
	if _, err := os.Stat(path); err == nil || os.IsNotExist(err) {
		t.Skipf("an unsearchable findings/ stays stat-able here (root?): %v", err)
	}
	joined := r43bJoined(r43bProblems(t, c))
	if strings.Contains(joined, "does not exist") {
		t.Errorf("an unsearchable finding was reported as absent:\n%s", joined)
	}
	if !strings.Contains(joined, "cannot be read") {
		t.Errorf("the report does not name the read failure:\n%s", joined)
	}
}

// TestR43bAbsentRefStillSaysTheFindingDoesNotExist is the control: the
// NotExist answer is a fact about a path the probe DID read, and it must keep
// its own wording — the fix distinguishes the classes, it does not flatten
// everything into a refusal.
func TestR43bAbsentRefStillSaysTheFindingDoesNotExist(t *testing.T) {
	c := r43bRefCampaign(t, r43bAbsentFindingID)
	joined := r43bJoined(r43bProblems(t, c))
	if !strings.Contains(joined, "names a finding that does not exist") {
		t.Errorf("an absent finding is no longer named absent:\n%s", joined)
	}
	if strings.Contains(joined, "cannot be read") {
		t.Errorf("an absent finding was reported as a read failure:\n%s", joined)
	}
}
