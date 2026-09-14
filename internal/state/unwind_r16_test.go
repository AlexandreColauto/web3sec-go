package state

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// TestLedgerRefusalUndoesTheCeiling pins r16 P1-2: the no-half-landing
// guarantee is now the UNWIND discipline, not just one pre-check — the
// state package's own save-then-log methods (ceiling, stage, artifact
// register/prune, phase, halt, complete) restore the exact pre-write
// bytes when the Log refuses. Half-landed decisions were invisible
// except as permanent audit red that doctor then laundered.
func TestLedgerRefusalUndoesTheCeiling(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Unwind Program", InitOpts{CampaignID: "C-unwind0001"})
	if err != nil {
		t.Fatal(err)
	}
	v := validation.VFloat(42.0)
	if _, err := c.SetCostCeiling(&v, "op"); err != nil {
		t.Fatal(err)
	}
	// Sabotage the ledger OUTSIDE the tool (torn head): every Log fails.
	if err := os.WriteFile(c.EventsPath, []byte("GARBAGE"), 0o644); err != nil {
		t.Fatal(err)
	}
	v2 := validation.VFloat(50.0)
	if _, err := c.SetCostCeiling(&v2, "op"); err == nil {
		t.Fatal("ceiling set accepted a dead ledger")
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	ceil := objAt(objAt(st, "budget"), "max_total_cost_usd")
	if ceil.Kind != validation.Flt || ceil.F != 42.0 {
		t.Fatalf("refused set left the ceiling half-landed at %v — "+
			"the unwind must restore 42.0", ceil)
	}
}

// TestUnwindOnStageAndArtifact covers the same law on the other doors.
func TestUnwindOnStageAndArtifact(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Unwind Program", InitOpts{CampaignID: "C-unwind0002"})
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(c.ArtifactsDir, "model.json")
	if err := os.WriteFile(art, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("protocol-model", art, "initial", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.EventsPath, []byte("GARBAGE"), 0o644); err != nil {
		t.Fatal(err)
	}
	art2 := filepath.Join(c.ArtifactsDir, "model2.json")
	if err := os.WriteFile(art2, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("protocol-model", art2, "second", nil); err == nil {
		t.Fatal("register accepted a dead ledger")
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := objAt(st, "artifacts").A
	if len(arts) != 1 || objStr(arts[0], "note") != "initial" {
		t.Fatalf("refused register mutated the projection: %d rows (%v)",
			len(arts), arts)
	}
}

// TestLedgerRefusalUndoesTheRefresh pins r17 P1#1: the converter's
// regex missed the refresh site (save in a helper, log further down),
// so a reconcile-after-external-rewrite with a read-only ledger
// half-landed a NEW sha + refresh_count with NO artifact.refreshed
// event — and stayed green forever (no state->log refreshed check).
func TestLedgerRefusalUndoesTheRefresh(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Refresh Unwind Program", InitOpts{CampaignID: "C-refrw00001"})
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(c.ArtifactsDir, "model.json")
	if err := os.WriteFile(art, []byte("{\"v\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("protocol-model", art, "initial", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(art, []byte("{\"v\":2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.EventsPath, []byte("GARBAGE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefreshArtifact(id, "op", "reconcile after external rewrite"); err == nil {
		t.Fatal("refresh accepted a dead ledger")
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	row := objAt(objAt(st, "artifacts").A[0], "sha256")
	wantOld, _ := validation.Sha256File(art)
	_ = wantOld
	if row.Kind != validation.Str || row.S == "" {
		t.Fatalf("unwind lost the artifact row: %v", row)
	}
	// The registration sha was for v:1 — after unwind the row must NOT
	// carry a refreshed_at/refresh_count (the projection is v:1-era):
	if rc := objAt(objAt(st, "artifacts").A[0], "refresh_count"); rc.Kind == validation.Int && rc.I > 0 {
		t.Fatalf("half-landed refresh survived the unwind: %v", rc)
	}
}
