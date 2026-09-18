package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// TestSnapshotsGhostActivePinNamesIt pins r4 issue 3: corrupt content was
// always caught; a MISSING directory behind the projection's active pin is
// now the same class of problem.
func TestSnapshotsGhostActivePinNamesIt(t *testing.T) {
	c, err := state.Init(t.TempDir(), "GhostPinTarget", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Fresh campaign: no snapshots dir at all and no active pin: silent.
	rep, err := Snapshots(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(rep, "ok").B {
		t.Fatalf("unpinned campaign must be clean: %s",
			validation.DumpsOrdered(rep, false))
	}
	// Pin for real, then rm -rf the store (the critic's probe).
	fake := "unused"
	// A real pin — then the directory disappears while the projection
	// keeps naming it.
	tgt := t.TempDir()
	if err := os.WriteFile(filepath.Join(tgt, "V.sol"),
		[]byte("contract V {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.PinSourceSnapshot(c, tgt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fake = validation.ObjStr(snap, "snapshot_id")
	if err := os.RemoveAll(filepath.Join(c.Dir, "snapshots", fake)); err != nil {
		t.Fatal(err)
	}
	rep, err = Snapshots(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(rep, false)
	if validation.ObjAt(rep, "ok").B || !strings.Contains(body, fake) ||
		!strings.Contains(body, "does not exist") {
		t.Fatalf("ghost pin must fail the section: %s", body)
	}
	// Restoring the dir (empty manifest-less dir still reports its own
	// problem, but no longer the ghost one) — full honesty both ways.
	if _, err := snapshot.PinSourceSnapshot(c, tgt, nil, nil); err != nil {
		t.Fatalf("re-pin: %v", err)
	}
	rep, err = Snapshots(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(validation.DumpsOrdered(rep, false), "does not exist") {
		t.Fatal("ghost complaint must clear once the dir exists")
	}
}

// TestSnapshotsGhostInactiveRowNamesIt pins r12 issue 3: the section's
// own message says "the ledger pins are ghosts", yet only the ACTIVE pin
// was existence-checked — a campaign with rows [A, B], active B, and A's
// directory deleted audited [snapshots]=0 while brief and learning still
// trust row A.
func TestSnapshotsGhostInactiveRowNamesIt(t *testing.T) {
	c, err := state.Init(t.TempDir(), "GhostRowTarget", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	t1 := t.TempDir()
	if err := os.WriteFile(filepath.Join(t1, "V.sol"),
		[]byte("contract V {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.PinSourceSnapshot(c, t1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstID := validation.ObjStr(first, "snapshot_id")
	t2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(t2, "W.sol"),
		[]byte("contract W {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := snapshot.PinSourceSnapshot(c, t2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondID := validation.ObjStr(second, "snapshot_id")
	if firstID == secondID {
		t.Fatal("two distinct trees must pin distinctly")
	}
	// ACTIVE is the second; delete only the INACTIVE row's dir.
	if err := os.RemoveAll(filepath.Join(c.Dir, "snapshots", firstID)); err != nil {
		t.Fatal(err)
	}
	rep, err := Snapshots(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(rep, false)
	if validation.ObjAt(rep, "ok").B || !strings.Contains(body, firstID) {
		t.Fatalf("inactive ghost row must fail the section: %s", body)
	}
	// The active row alone (dir back absent for BOTH) was already red;
	// restoring the first dir clears only the new complaint.
	if err := os.WriteFile(filepath.Join(t1, "V.sol"),
		[]byte("contract V {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Recreate a valid dir the sanctioned way: re-pin the first content
	// (the empty shell above is what the pin's existence check refuses —
	// remove it first).
	if err := os.RemoveAll(filepath.Join(c.Dir, "snapshots", firstID)); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, t1, nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err = Snapshots(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(rep, "ok").B {
		t.Fatalf("restored store must clear the row ghost: %s",
			validation.DumpsOrdered(rep, false))
	}
}
