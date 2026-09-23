package sandbox

// v1.6 — failure_class: the classifier's verdict is ARCHIVED on the exec
// event, beside the record anchor, so a later reader recovers what was decided
// instead of re-running ClassifyFailure over the captured output
// (exec_failure_class.go). Both writers must stamp it, it is unconditional,
// and the load-bearing test is the last one: the key rides the EVENT, never
// the record, so the record's anchor digest must not move.

import (
	"testing"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// hostSandbox is a host-readonly sandbox plus the campaign it logs into.
func hostSandbox(t *testing.T, program string) (*Sandbox, *state.Campaign) {
	t.Helper()
	c := newCampaign(t, program)
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	return sb, c
}

// fakeProc pins the process result for the duration of a test, so the
// captured output the classifier reads is fixed and no shell runs.
func fakeProc(t *testing.T, res ProcResult) {
	t.Helper()
	withProc(t, func([]string, string, []string,
		time.Duration) (ProcResult, error) {
		return res, nil
	})
}

// archivedFailureClass reads the failure_class a carrier event archived for
// execID, plus whether the key is there at all.
func archivedFailureClass(t *testing.T, c *state.Campaign, typ,
	execID string) (string, bool) {
	t.Helper()
	data := validation.ObjAt(carrierEvent(t, c, typ, execID), "data")
	if !validation.HasKey(data, KeyFailureClass) {
		return "", false
	}
	return validation.ObjStr(data, KeyFailureClass), true
}

// assertArchivedClass is the shared assertion: the key is present, its value
// is EXACTLY what the real classifier reports for the record on disk (never a
// hardcoded class, so the archived verdict cannot drift from the
// implementation), and a FAILED exec never archives "none" (the classifier
// reserves that word for exit 0).
func assertArchivedClass(t *testing.T, c *state.Campaign, typ, execID string,
	wantFailed bool) {
	t.Helper()
	rec, err := LoadExec(c, execID)
	if err != nil {
		t.Fatal(err)
	}
	want := validation.ObjStr(ClassifyFailure(rec), "class")
	got, present := archivedFailureClass(t, c, typ, execID)
	if !present {
		t.Fatalf("the %s event for %s carries no %s key", typ, execID,
			KeyFailureClass)
	}
	if got != want {
		t.Fatalf("archived %s = %q, want the classifier's %q for the "+
			"record on disk", KeyFailureClass, got, want)
	}
	if wantFailed && got == "none" {
		t.Fatalf("a FAILED exec archived %s = none; the classifier "+
			"reserves none for exit 0", KeyFailureClass)
	}
}

// assertNoFailureClassKey refuses the misplacement this change exists to
// avoid: the key on the RECORD, which is what the anchor digests. The record
// schema is closed, so it is checked too.
func assertNoFailureClassKey(t *testing.T, rec validation.Value) {
	t.Helper()
	for _, kv := range rec.O {
		if kv.K == KeyFailureClass {
			t.Fatalf("%s landed ON the exec record; the record is the "+
				"thing the anchor verifies — the verdict belongs on the "+
				"ledger side", KeyFailureClass)
		}
	}
	if err := validation.Validate(rec, "sandbox_execution", 1); err != nil {
		t.Fatalf("the record no longer validates against the closed "+
			"sandbox_execution schema: %v", err)
	}
}

// TestRunArchivesTheFailureClassOnTheExecEvent: a FAILING exec's sandbox.exec
// event carries the class the real classifier reports for that record.
func TestRunArchivesTheFailureClassOnTheExecEvent(t *testing.T) {
	sb, c := hostSandbox(t, "failure-class-run")
	fakeProc(t, ProcResult{ReturnCode: 1,
		Stderr: "Assertion failed: x != y\n"})
	rec, err := sb.Run("forge test", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	assertArchivedClass(t, c, "sandbox.exec",
		validation.ObjStr(rec, "exec_id"), true)
}

// TestRunArchivesNoneForASuccessfulExec: the key is ALWAYS emitted — exit 0
// archives the classifier's own word for "nothing to classify", so a reader
// never has to tell absent from null.
func TestRunArchivesNoneForASuccessfulExec(t *testing.T) {
	sb, c := hostSandbox(t, "failure-class-none")
	fakeProc(t, ProcResult{ReturnCode: 0, Stdout: "all good\n"})
	rec, err := sb.Run("echo ok", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	assertArchivedClass(t, c, "sandbox.exec", execID, false)
	if got, _ := archivedFailureClass(t, c, "sandbox.exec", execID); got != "none" {
		t.Fatalf("a SUCCESSFUL exec archived %s = %q, want %q",
			KeyFailureClass, got, "none")
	}
}

// TestRegisterExecArchivesTheFailureClass: the externally-reported writer
// stamps the same key on sandbox.exec.registered — for a failing and for a
// successful registration, because the key is unconditional.
func TestRegisterExecArchivesTheFailureClass(t *testing.T) {
	c := newCampaign(t, "failure-class-register")
	failed, err := RegisterExec(c, RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		ReportedBy: "operator", ExitStatus: 1,
		StdoutText: "[FAIL] test_x\nAssertion failed: x != y\n"})
	if err != nil {
		t.Fatal(err)
	}
	assertArchivedClass(t, c, "sandbox.exec.registered",
		validation.ObjStr(failed, "exec_id"), true)
	passed, err := RegisterExec(c, RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_y",
		ReportedBy: "operator", ExitStatus: 0, StdoutText: "[PASS] test_y\n"})
	if err != nil {
		t.Fatal(err)
	}
	assertArchivedClass(t, c, "sandbox.exec.registered",
		validation.ObjStr(passed, "exec_id"), false)
}

// TestTheFailureClassIsOnTheEventNotTheRecord is the load-bearing one. The
// anchor digest covers the exec RECORD, so failure_class must ride the EVENT:
// if it were stamped on the record instead, the digest the event carries
// would no longer be the record's and every anchored carrier would read as
// edited. The digest is shown to be sensitive to exactly that misplacement,
// so this test cannot pass vacuously.
func TestTheFailureClassIsOnTheEventNotTheRecord(t *testing.T) {
	sb, c := hostSandbox(t, "failure-class-anchor")
	fakeProc(t, ProcResult{ReturnCode: 1, Stderr: "Assertion failed\n"})
	rec, err := sb.Run("forge test", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	onDisk, err := LoadExec(c, execID)
	if err != nil {
		t.Fatal(err)
	}
	assertNoFailureClassKey(t, onDisk)
	assertAnchoredEvent(t, c, "sandbox.exec", execID)
	class, present := archivedFailureClass(t, c, "sandbox.exec", execID)
	if !present || class == "" {
		t.Fatalf("the event archived no usable %s: (%q, %v)",
			KeyFailureClass, class, present)
	}
	moved := setKey(onDisk, KeyFailureClass, validation.VStr(class))
	if ExecRecordDigest(moved) == ExecRecordDigest(onDisk) {
		t.Fatalf("adding %s to the record left the anchor digest "+
			"unchanged — the anchor would not notice the misplacement "+
			"this test exists to catch", KeyFailureClass)
	}
}

// TestTheArchivedClassComesFromTheSwappableClassifier proves the writer
// CONSULTS ClassifyFailure instead of stamping a verdict of its own. Every
// other fixture's output classifies as logic or none — exactly the two values
// a regression hardcoding `exit == 0 ? "none" : "logic"` would produce — so a
// stub installed through the seam reports a class ("stub") no real branch can
// return and only a genuine call can reproduce. SetClassifyFailure is
// package-global state, so this test is NOT parallel and restores the default
// in t.Cleanup (the convention at envseam_test.go:236).
func TestTheArchivedClassComesFromTheSwappableClassifier(t *testing.T) {
	SetClassifyFailure(func(validation.Value) validation.Value {
		return validation.VObj(
			validation.KV{K: "class", V: validation.VStr("stub")})
	})
	t.Cleanup(func() { SetClassifyFailure(nil) })
	sb, c := hostSandbox(t, "failure-class-stub")
	fakeProc(t, ProcResult{ReturnCode: 1,
		Stderr: "Assertion failed: x != y\n"})
	rec, err := sb.Run("forge test", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	got, present := archivedFailureClass(t, c, "sandbox.exec",
		validation.ObjStr(rec, "exec_id"))
	if !present {
		t.Fatalf("the sandbox.exec event carries no %s key", KeyFailureClass)
	}
	if got != "stub" {
		t.Fatalf("archived %s = %q, want the installed classifier's %q — "+
			"the writer stamped a verdict of its own instead of consulting "+
			"ClassifyFailure", KeyFailureClass, got, "stub")
	}
}

// TestTheArchivedClassIsEmptyWhenTheClassifierNamesNoClass pins the defensive
// branch: a classifier returning an object with NO "class" key archives the
// key PRESENT with the empty string, never an invented verdict. "" is outside
// the classifier's vocabulary (none/logic/setup/environment/unknown), so every
// class-gated consumer fails closed on it.
func TestTheArchivedClassIsEmptyWhenTheClassifierNamesNoClass(t *testing.T) {
	SetClassifyFailure(func(validation.Value) validation.Value {
		return validation.VObj()
	})
	t.Cleanup(func() { SetClassifyFailure(nil) })
	sb, c := hostSandbox(t, "failure-class-noclass")
	fakeProc(t, ProcResult{ReturnCode: 1, Stderr: "Assertion failed\n"})
	rec, err := sb.Run("forge test", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	got, present := archivedFailureClass(t, c, "sandbox.exec",
		validation.ObjStr(rec, "exec_id"))
	if !present {
		t.Fatalf("the sandbox.exec event carries no %s key: the key must "+
			"be present with an empty value, not absent", KeyFailureClass)
	}
	if got != "" {
		t.Fatalf("archived %s = %q, want \"\" — the helper must not invent "+
			"a verdict when the classifier names no class", KeyFailureClass,
			got)
	}
}

// TestTheArchivedClassMatchesTheRealClassifierForAnEnvironmentCapture is the
// second, independent D1 guard: a capture the REAL classifier routes to a
// class other than logic/none — a dead docker daemon is environment — archives
// that class, so the archived value cannot be a two-valued stand-in.
func TestTheArchivedClassMatchesTheRealClassifierForAnEnvironmentCapture(
	t *testing.T) {
	sb, c := hostSandbox(t, "failure-class-environment")
	fakeProc(t, ProcResult{ReturnCode: 1,
		Stderr: "Cannot connect to the Docker daemon at " +
			"unix:///var/run/docker.sock. Is the docker daemon running?\n"})
	rec, err := sb.Run("forge test", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	got, present := archivedFailureClass(t, c, "sandbox.exec", execID)
	if !present {
		t.Fatalf("the sandbox.exec event carries no %s key", KeyFailureClass)
	}
	if got != "environment" {
		t.Fatalf("archived %s = %q, want %q for a dead-docker capture",
			KeyFailureClass, got, "environment")
	}
	assertArchivedClass(t, c, "sandbox.exec", execID, true)
}
