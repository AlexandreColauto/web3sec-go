package sequencepoc

// r45b pins for the fork-target pin reader. Before this round
// SnapshotHasForkTarget documented itself as "Total: no active snapshot /
// unreadable pin -> false, never raises" — which folded EACCES/ENOTDIR/EISDIR
// on the ACTIVE pin manifest into the FACT "no fork target", and its consumer
// then discharged the audit row, the CONFIRMED gate's sequence-coverage
// clause and the fork-PoC evidence floor with "on-chain sequence coverage is
// not required".
//
// These tests pin the r44 pinnedCompiler shape at this site:
//
//   - no active snapshot / no pin manifest (ENOENT) -> (false, nil): a FACT;
//   - deployment or chain pin -> (true, nil): unchanged;
//   - any other stat/read failure -> a REFUSAL naming the path and the errno;
//   - the wired bool predicate is FAIL-CLOSED on a refusal (true — never
//     "not required"), and OnchainSequenceRequiredErr carries the refusal to
//     error-aware callers.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
)

// r45bPinPath is the ACTIVE snapshot's pin manifest path.
func r45bPinPath(t *testing.T, c *state.Campaign) string {
	t.Helper()
	return filepath.Join(c.Dir, "snapshots", sid(t, c), "snapshot.json")
}

// r45bHide makes a file unreadable (EACCES) for the duration of the test.
// Skipped as root, where mode bits do not deny the read.
func r45bHide(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny the read")
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
}

// TestR45bAbsentPinIsAFactNotARefusal is the honest-shape half: no active
// snapshot and no pin manifest are FACTS, and they must stay (false, nil).
func TestR45bAbsentPinIsAFactNotARefusal(t *testing.T) {
	c := testCampaign(t) // no snapshot at all
	has, err := SnapshotHasForkTarget(c)
	if err != nil {
		t.Fatalf("no active snapshot is a fact, not a refusal: %v", err)
	}
	if has {
		t.Fatal("no active snapshot: false")
	}

	c = pinGateCampaign(t)
	if err := os.Remove(r45bPinPath(t, c)); err != nil {
		t.Fatal(err)
	}
	has, err = SnapshotHasForkTarget(c)
	if err != nil {
		t.Fatalf("ENOENT on the pin manifest is a fact, not a refusal: %v", err)
	}
	if has {
		t.Fatal("absent pin manifest: false")
	}
	if OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("absent pin manifest: the on-chain demand must not fire")
	}
}

// TestR45bReadablePinShapesStayIdentical is the other honest-shape half: a
// source-only pin, a deployment pin and a chain pin read exactly as before.
func TestR45bReadablePinShapesStayIdentical(t *testing.T) {
	c := pinGateCampaign(t) // source-only
	has, err := SnapshotHasForkTarget(c)
	if err != nil {
		t.Fatalf("readable source-only pin: %v", err)
	}
	if has {
		t.Fatal("source-only pin has no fork target")
	}
	if OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("source-only pin: not on-chain required")
	}

	dep := mustParse(t, `{"network": "ethereum", "contracts": [
      {"name": "Vault", "address": "0x`+repeat("1", 40)+`"}]}`)
	if _, err := snapshot.AttachDeploymentPin(c, sid(t, c), dep); err != nil {
		t.Fatal(err)
	}
	has, err = SnapshotHasForkTarget(c)
	if err != nil {
		t.Fatalf("readable deployment pin: %v", err)
	}
	if !has {
		t.Fatal("deployment pin must count as a fork target")
	}
	req, err := OnchainSequenceRequiredErr(c, multiStep(t))
	if err != nil {
		t.Fatalf("readable deployment pin must not refuse: %v", err)
	}
	if !req || !OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("deployment pin + multi-step must be on-chain required")
	}
	if OnchainSequenceRequired(c, singleStep(t)) {
		t.Fatal("single-step finding stays not-required")
	}
}

// TestR45bUnreadablePinIsRefusalNotNoForkTarget is THE pin: chmod 000 on the
// active pin manifest. The old code answered false ("no fork target"); the
// answer must now be a refusal naming the path and the errno, and the wired
// bool predicate must never discharge the demand.
func TestR45bUnreadablePinIsRefusalNotNoForkTarget(t *testing.T) {
	c := pinGateCampaign(t)
	pin := r45bPinPath(t, c)
	r45bHide(t, pin)

	has, err := SnapshotHasForkTarget(c)
	if err == nil {
		t.Fatal("EACCES on the active pin manifest was folded into a " +
			"fork-target answer instead of a refusal")
	}
	if has {
		t.Fatal("a pin the tool could not read is not a fork target")
	}
	msg := err.Error()
	if !strings.Contains(msg, pin) {
		t.Errorf("the refusal must name the path %s: %q", pin, msg)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Errorf("the refusal must name the errno (permission denied): %q", msg)
	}

	// The wired seam contract is a bare bool: on a refusal it must be
	// FAIL-CLOSED — "required", never the old silent "not required".
	if !OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("an unreadable pin must not answer 'not required'")
	}
	// The error-carrying form hands the refusal to the CONFIRMED gate.
	if _, err := OnchainSequenceRequiredErr(c, multiStep(t)); err == nil {
		t.Fatal("OnchainSequenceRequiredErr must carry the refusal")
	}
	// The shape gate still comes first: a single-step finding is not
	// sequence-required whatever the pin says, so no refusal is owed.
	if OnchainSequenceRequired(c, singleStep(t)) {
		t.Fatal("single-step finding must stay not-required")
	}
	if req, err := OnchainSequenceRequiredErr(c, singleStep(t)); err != nil ||
		req {
		t.Fatalf("single-step finding: (%v, %v), want (false, nil)", req, err)
	}
}

// TestR45bPinPathENOTDIRIsRefusal pins a non-EACCES read failure (ENOTDIR):
// the manifest's parent is a regular file, so the stat itself fails with an
// errno that must be named, not folded into "no fork target".
func TestR45bPinPathENOTDIRIsRefusal(t *testing.T) {
	c := pinGateCampaign(t)
	pin := r45bPinPath(t, c)
	dir := filepath.Dir(pin)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	has, err := SnapshotHasForkTarget(c)
	if err == nil || has {
		t.Fatalf("ENOTDIR on the pin manifest: (has=%v, err=%v), want a refusal",
			has, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, pin) || !strings.Contains(msg, "not a directory") {
		t.Errorf("the refusal must name the path %s and the errno: %q", pin, msg)
	}
	if !OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("a pin path the tool could not stat must not answer 'not required'")
	}
}

// TestR45bPinPathIsADirectoryIsRefusal pins the EISDIR class: the manifest
// path exists but is a directory, which is a broken pin, not an absent one.
func TestR45bPinPathIsADirectoryIsRefusal(t *testing.T) {
	c := pinGateCampaign(t)
	pin := r45bPinPath(t, c)
	if err := os.Remove(pin); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pin, 0o755); err != nil {
		t.Fatal(err)
	}

	has, err := SnapshotHasForkTarget(c)
	if err == nil || has {
		t.Fatalf("a directory at the pin path: (has=%v, err=%v), want a refusal",
			has, err)
	}
	if msg := err.Error(); !strings.Contains(msg, pin) ||
		!strings.Contains(msg, "directory") {
		t.Errorf("the refusal must name the path %s and say directory: %q",
			pin, msg)
	}
	if _, err := OnchainSequenceRequiredErr(c, multiStep(t)); err == nil {
		t.Fatal("the refusal must reach the error-carrying predicate")
	}
	if !OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("a directory pin must not answer 'not required'")
	}
}
