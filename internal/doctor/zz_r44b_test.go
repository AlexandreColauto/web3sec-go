// zz_r44b_test.go pins R44B P3-a at doctor's snapshot scope: the stat of the
// active pin's directory folded EVERY error into exists:false + "snapshot <id>
// directory missing". With `chmod 000 <c>/snapshots/` the directory is there
// but unreadable (stat needs +x on the parent), so doctor's human and JSON
// surfaces both said MISSING — a claim about ABSENCE drawn from a READ
// failure. Doctor's exit 0 is documented precedent (the bill discloses, it
// does not fail), so the lie was the REASON; the note must now say the store
// could not be read, naming the errno, while a genuinely missing pin keeps the
// r37b shape the CLI's MISSING branch renders.
package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// r44bPin pins one real source tree; returns the snapshot id and its dir.
func r44bPin(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	target := filepath.Join(c.Root, "t")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "app.py"), "x = 1\n")
	pinned, err := snapshot.PinSourceSnapshot(c, target, nil, nil)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	sid := validation.ObjStr(pinned, "snapshot_id")
	if sid == "" {
		t.Fatal("pin returned no snapshot id")
	}
	return sid, filepath.Join(c.Dir, "snapshots", sid)
}

func TestR44bSnapshotScopeReadFailureIsNotMissing(t *testing.T) {
	c := newCampaign(t, "r44b1")
	sid, snapDir := r44bPin(t, c)
	snapsRoot := filepath.Join(c.Dir, "snapshots")

	// BEFORE: the pin is present and scoped (no exists/read_error keys).
	before, err := SnapshotScope(c)
	if err != nil {
		t.Fatalf("green campaign refused: %v", err)
	}
	if intField(before, "files") <= 0 {
		t.Fatalf("BEFORE files = %d, want > 0", intField(before, "files"))
	}
	if ex := validation.ObjAt(before, "exists"); ex.Kind != validation.Null {
		t.Fatalf("BEFORE exists = %s, want the absent key",
			validation.DumpIndented(ex))
	}

	if err := os.Chmod(snapsRoot, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(snapsRoot, 0o755) })
	if _, serr := os.Stat(snapDir); serr == nil ||
		os.IsNotExist(serr) {
		t.Skip("cannot make the store unreadable here (running as root?)")
	}

	// AFTER: the REASON is the read failure, not a missing directory.
	res, err := SnapshotScope(c)
	if err != nil {
		t.Fatalf("doctor discloses a pin-store read failure; it does not "+
			"fail the run (rc 0 is documented precedent): %v", err)
	}
	if got := validation.ObjStr(res, "active_snapshot"); got != sid {
		t.Fatalf("active_snapshot = %q, want %q", got, sid)
	}
	if ex := validation.ObjAt(res, "exists"); ex.Kind != validation.Bool || ex.B {
		t.Fatalf("exists = %s, want false (existence was not established)",
			validation.DumpIndented(ex))
	}
	readErr := validation.ObjStr(res, "read_error")
	if readErr == "" {
		t.Fatalf("no read_error key: %s", validation.DumpsOrdered(res, false))
	}
	note := validation.ObjStr(res, "note")
	for _, want := range []string{"could not be read", "permission denied",
		snapDir} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q must carry %q", note, want)
		}
	}
	if strings.Contains(note, "directory missing") {
		t.Errorf("a read failure must not be reported as a missing "+
			"directory: %q", note)
	}
	// The human view prints "snapshot <id>: MISSING — <note>"; the note is
	// the only reason text it renders, so the read failure must be the
	// sentence it carries (r37b's human-surface contract).
	if validation.ObjStr(res, "note") == "snapshot "+sid+" directory missing" {
		t.Fatal("the read-failure note is the missing-pin note")
	}
}

func TestR44bSnapshotScopeGenuinelyMissingPinKeepsTheMissingShape(t *testing.T) {
	c := newCampaign(t, "r44b2")
	sid, snapDir := r44bPin(t, c)
	if err := os.RemoveAll(snapDir); err != nil {
		t.Fatal(err)
	}
	res, err := SnapshotScope(c)
	if err != nil {
		t.Fatalf("a missing pin is a disclosed shape, not a failure: %v", err)
	}
	if ex := validation.ObjAt(res, "exists"); ex.Kind != validation.Bool || ex.B {
		t.Fatalf("exists = %s, want false", validation.DumpIndented(ex))
	}
	if re := validation.ObjAt(res, "read_error"); re.Kind != validation.Null {
		t.Fatalf("an absent pin has no read_error: %s",
			validation.DumpIndented(re))
	}
	if note := validation.ObjStr(res, "note"); note != "snapshot "+sid+" directory missing" {
		t.Fatalf("note = %q, want the r37b missing-pin sentence", note)
	}
}

// TestR44bSnapshotScopeUnreadablePinDirRefuses: the store root is fine but
// the pin dir cannot be searched, so neither its manifest nor its file list
// can be read. The scope report has no count to offer — it must refuse (rc 1
// through the CLI) rather than bill a clean, empty-looking pin.
func TestR44bSnapshotScopeUnreadablePinDirRefuses(t *testing.T) {
	c := newCampaign(t, "r44b5")
	_, snapDir := r44bPin(t, c)
	if err := os.Chmod(snapDir, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(snapDir, 0o755) })
	if _, serr := os.Stat(filepath.Join(snapDir, "snapshot.json")); serr == nil {
		t.Skip("cannot make a pin dir unsearchable here (running as root?)")
	}
	res, err := SnapshotScope(c)
	if err == nil {
		t.Fatalf("an unreadable pin dir billed clean: %s",
			validation.DumpsOrdered(res, false))
	}
}

// The honest shapes: no pin at all, and a pin still in place.
func TestR44bSnapshotScopeUnpinnedAndHealthyStayGreen(t *testing.T) {
	unpinned := newCampaign(t, "r44b3")
	res, err := SnapshotScope(unpinned)
	if err != nil {
		t.Fatalf("an unpinned campaign: %v", err)
	}
	if s := validation.ObjAt(res, "active_snapshot"); s.Kind != validation.Null {
		t.Fatalf("active_snapshot = %s, want null",
			validation.DumpIndented(s))
	}
	if note := validation.ObjStr(res, "note"); !strings.Contains(note, "no snapshot pinned") {
		t.Fatalf("note = %q", note)
	}
	if re := validation.ObjAt(res, "read_error"); re.Kind != validation.Null {
		t.Fatalf("an unpinned campaign has no read_error: %s",
			validation.DumpIndented(re))
	}

	healthy := newCampaign(t, "r44b4")
	_, _ = r44bPin(t, healthy)
	res, err = SnapshotScope(healthy)
	if err != nil {
		t.Fatalf("a healthy pin: %v", err)
	}
	if intField(res, "files") <= 0 {
		t.Fatalf("files = %d, want > 0", intField(res, "files"))
	}
	if re := validation.ObjAt(res, "read_error"); re.Kind != validation.Null {
		t.Fatalf("a readable store has no read_error: %s",
			validation.DumpIndented(re))
	}
}
