package reproduction

// Task 8 (G11) tests — PostPatchVerdict: the post-patch verdict table over
// real exec-record fixtures (RegisterExec, the production ledger seeder —
// the same builder the harness path's exec-dir seeder covers), the
// no-baseline case, unknown ids, and the fail-open pins (pure reads: the
// finding file is byte-identical after the call; status never moves).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ppExec registers one EXEC record with explicit stdout/exit and returns
// its id.
func ppExec(t *testing.T, c *state.Campaign, stdout string,
	exit int) string {
	t.Helper()
	rec := registerExec(t, c, "docker-networkless",
		"forge test --match-test test_exploit", stdout, "pytest-harness",
		exit, "")
	return validation.ObjStr(rec, "exec_id")
}

// ppFinding ingests a hypothesis and returns its id.
func ppFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	return ingest(t, c, hypoPayload("logic-error"), "integration", "")
}

// ppCite appends one minted-style evidence item citing execID (the
// MintReproEvidence evidence-item shape, minus the gates — PostPatchVerdict
// only reads).
func ppCite(t *testing.T, c *state.Campaign, fid, execID string) {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ev := validation.ObjAt(f, "evidence")
	if ev.Kind != validation.Arr {
		ev = validation.VArr()
	}
	ev.A = append(ev.A, validation.VObj(
		kv("evidence_id", validation.VStr("EV-ppbaseline")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("artifact_id", validation.VStr(execID)),
		kv("description", validation.VStr("baseline reproduction of the bug")),
		kv("command", validation.VStr("forge test --match-test test_exploit")),
		kv("sandbox_profile", validation.VStr("docker-networkless"))))
	f = setKey(f, "evidence", ev)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
}

// ppSetup seeds a campaign + finding + cited baseline exec and returns all
// three ids.
func ppSetup(t *testing.T, baseStdout string, baseExit int) (*state.Campaign,
	string, string) {
	t.Helper()
	c := newCampaign(t, "Acme Program")
	fid := ppFinding(t, c)
	base := ppExec(t, c, baseStdout, baseExit)
	ppCite(t, c, fid, base)
	return c, fid, base
}

// ppFileBytes snapshots the finding file for the writes-nothing pin.
func ppFileBytes(t *testing.T, c *state.Campaign, fid string) []byte {
	t.Helper()
	raw, err := os.ReadFile(findings.FindingPath(c, fid))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPostPatchStillReproducible(t *testing.T) {
	c, fid, base := ppSetup(t, "PASS: test_exploit\n", 0)
	next := ppExec(t, c, "PASS: test_exploit\n", 0)
	before := ppFileBytes(t, c, fid)
	verdict, detail, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "still_reproducible" {
		t.Fatalf("verdict = %q, want still_reproducible", verdict)
	}
	if !strings.Contains(detail, base) || !strings.Contains(detail, next) {
		t.Fatalf("detail %q must name both execs", detail)
	}
	if after := ppFileBytes(t, c, fid); string(after) != string(before) {
		t.Fatal("PostPatchVerdict wrote to the finding file")
	}
}

func TestPostPatchFixed(t *testing.T) {
	c, fid, _ := ppSetup(t, "PASS: test_exploit\n", 0)
	next := ppExec(t, c, "FAIL: test_exploit\n", 1)
	verdict, detail, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "fixed" {
		t.Fatalf("verdict = %q, want fixed", verdict)
	}
	if detail == "" {
		t.Fatal("detail must be non-empty")
	}
}

func TestPostPatchIndeterminateDifferentStdout(t *testing.T) {
	c, fid, _ := ppSetup(t, "PASS: test_exploit\n", 0)
	next := ppExec(t, c, "PASS: test_exploit (patched output)\n", 0)
	verdict, _, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "indeterminate" {
		t.Fatalf("verdict = %q, want indeterminate", verdict)
	}
}

func TestPostPatchIndeterminateOriginalNonZero(t *testing.T) {
	c, fid, _ := ppSetup(t, "FAIL: test_exploit\n", 1)
	next := ppExec(t, c, "FAIL: test_exploit\n", 1)
	verdict, _, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "indeterminate" {
		t.Fatalf("verdict = %q, want indeterminate", verdict)
	}
}

func TestPostPatchNoBaseline(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := ppFinding(t, c)
	next := ppExec(t, c, "PASS: test_exploit\n", 0)
	verdict, detail, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "indeterminate" {
		t.Fatalf("verdict = %q, want indeterminate", verdict)
	}
	if detail != "no baseline repro exec on the finding" {
		t.Fatalf("detail = %q", detail)
	}
}

func TestPostPatchMissingStdoutFile(t *testing.T) {
	c, fid, _ := ppSetup(t, "PASS: test_exploit\n", 0)
	next := ppExec(t, c, "PASS: test_exploit\n", 0)
	if err := os.Remove(filepath.Join(c.ExecsDir, next,
		"stdout.log")); err != nil {
		t.Fatal(err)
	}
	verdict, detail, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "indeterminate" {
		t.Fatalf("verdict = %q, want indeterminate", verdict)
	}
	if !strings.Contains(detail, next) {
		t.Fatalf("detail %q must name the exec", detail)
	}
}

func TestPostPatchTimeoutMarker(t *testing.T) {
	c, fid, _ := ppSetup(t, "PASS: test_exploit\n", 0)
	next := ppExec(t, c, "", -1)
	verdict, _, err := PostPatchVerdict(c, fid, next)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if verdict != "indeterminate" {
		t.Fatalf("verdict = %q, want indeterminate (timeout marker)", verdict)
	}
}

func TestPostPatchUnknownFinding(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	next := ppExec(t, c, "PASS: test_exploit\n", 0)
	_, _, err := PostPatchVerdict(c, "F-doesnotexist", next)
	if err == nil {
		t.Fatal("want an error for an unknown finding")
	}
	if !strings.Contains(err.Error(), "F-doesnotexist") {
		t.Fatalf("error %q must name the finding", err)
	}
}

func TestPostPatchUnknownExec(t *testing.T) {
	c, fid, _ := ppSetup(t, "PASS: test_exploit\n", 0)
	_, _, err := PostPatchVerdict(c, fid, "EXEC-nope")
	if err == nil {
		t.Fatal("want an error for an unknown exec")
	}
	if !strings.Contains(err.Error(), "EXEC-nope") {
		t.Fatalf("error %q must name the exec", err)
	}
}

func TestPostPatchNoBaselineBeforeExecLoad(t *testing.T) {
	// Order pin: the no-baseline check runs before the new-exec load,
	// so an unknown --exec on a baseline-less finding is indeterminate
	// (fail-open), not an unknown-exec error.
	c := newCampaign(t, "Acme Program")
	fid := ppFinding(t, c)
	verdict, detail, err := PostPatchVerdict(c, fid, "EXEC-nope")
	if err != nil {
		t.Fatalf("verdict: %v (no-baseline must win over unknown exec)", err)
	}
	if verdict != PostPatchIndeterminate {
		t.Fatalf("verdict = %q, want indeterminate", verdict)
	}
	if detail != NoBaselineDetail {
		t.Fatalf("detail = %q, want %q", detail, NoBaselineDetail)
	}
}

func TestPostPatchStatusUntouched(t *testing.T) {
	c, fid, _ := ppSetup(t, "PASS: test_exploit\n", 0)
	next := ppExec(t, c, "FAIL: test_exploit\n", 1)
	before, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PostPatchVerdict(c, fid, next); err != nil {
		t.Fatal(err)
	}
	after, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(before, "status") != validation.ObjStr(after, "status") {
		t.Fatalf("status moved %q -> %q", validation.ObjStr(before, "status"),
			validation.ObjStr(after, "status"))
	}
}
