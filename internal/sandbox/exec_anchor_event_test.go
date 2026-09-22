package sandbox

// v1.6 — the exec-record anchor: both writers stamp it, and the digest is
// root-independent.
//
// The anchor rides the event each writer already appends, so the ledger law is
// unchanged (one hash-chained event per mutation, no second write): the record
// is on disk immediately before the Log call, so the digest can be added to
// that same event's data with no ordering problem.

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// carrierEvent is the first event of the given type whose ref is execID.
func carrierEvent(t *testing.T, c *state.Campaign, typ, execID string) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == typ &&
			validation.ObjStr(ev, "ref") == execID {
			return ev
		}
	}
	t.Fatalf("no %s event for %s", typ, execID)
	return validation.VNull()
}

// assertAnchoredEvent pins the event's anchor against the record on disk: the
// digest recomputes, the label is the pinned literal, and the verifier agrees.
func assertAnchoredEvent(t *testing.T, c *state.Campaign, typ, execID string) {
	t.Helper()
	rec, err := LoadExec(c, execID)
	if err != nil {
		t.Fatal(err)
	}
	ev := carrierEvent(t, c, typ, execID)
	digest, alg, present := EventAnchor(ev)
	if !present {
		t.Fatalf("the %s event for %s carries no anchor key", typ, execID)
	}
	if alg != ExecRecordAnchorAlg {
		t.Fatalf("alg = %q, want %q", alg, ExecRecordAnchorAlg)
	}
	if want := ExecRecordDigest(rec); digest != want {
		t.Fatalf("event digest = %s, want the record's %s", digest, want)
	}
	if err := VerifyExecRecordAnchor(c, execID, rec); err != nil {
		t.Fatalf("the mint-side verifier refused its own writer: %v", err)
	}
}

func TestRunStampsTheRecordAnchorOnTheExecEvent(t *testing.T) {
	c := newCampaign(t, "anchor-run")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo ANCHOR", RunOpts{Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	assertAnchoredEvent(t, c, "sandbox.exec", validation.ObjStr(rec, "exec_id"))
}

func TestRegisterExecStampsTheRecordAnchorOnTheRegisteredEvent(t *testing.T) {
	c := newCampaign(t, "anchor-register")
	rec, err := RegisterExec(c, RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		ReportedBy: "operator", ExitStatus: 1, StdoutText: "[FAIL] test_x\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertAnchoredEvent(t, c, "sandbox.exec.registered",
		validation.ObjStr(rec, "exec_id"))
}

func TestTheAnchorSurvivesACampaignCopy(t *testing.T) {
	c := newCampaign(t, "anchor-copy")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo ANCHOR", RunOpts{Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")

	// The digest covers the record's CONTENT, not its path, so a campaign
	// copied to another root keeps its anchors — which is what
	// scripts/verify-full.sh step 9 requires of the committed fixture.
	c2, err := state.Init(t.TempDir(), "anchor-copy-2",
		state.InitOpts{CampaignID: c.CampaignID})
	if err != nil {
		t.Fatal(err)
	}
	copyCampaignExec(t, c, c2, execID)

	moved, err := LoadExec(c2, execID)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecRecordAnchor(c2, execID, moved); err != nil {
		t.Fatalf("the anchor did not survive the copy: %v", err)
	}
	digest, alg, present := EventAnchor(carrierEvent(t, c2, "sandbox.exec", execID))
	if !present || digest != ExecRecordDigest(moved) || alg != ExecRecordAnchorAlg {
		t.Fatalf("copied event anchor = (%q, %q, %v), want (%q, %q, true)",
			digest, alg, present, ExecRecordDigest(moved), ExecRecordAnchorAlg)
	}
}

// copyCampaignExec copies one exec dir and the whole ledger into another
// campaign root.
func copyCampaignExec(t *testing.T, from, to *state.Campaign, execID string) {
	t.Helper()
	copyTree(t, filepath.Join(from.ExecsDir, execID),
		filepath.Join(to.ExecsDir, execID))
	copyFile(t, from.EventsPath, to.EventsPath)
}

// copyTree copies a directory one level deep (the exec dir: record + logs).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		copyFile(t, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()))
	}
}

// copyFile copies one regular file, creating its parent.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
