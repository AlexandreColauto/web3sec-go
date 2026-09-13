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
	if !objAt(rep, "ok").B {
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
	fake = objStr(snap, "snapshot_id")
	if err := os.RemoveAll(filepath.Join(c.Dir, "snapshots", fake)); err != nil {
		t.Fatal(err)
	}
	rep, err = Snapshots(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(rep, false)
	if objAt(rep, "ok").B || !strings.Contains(body, fake) ||
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
