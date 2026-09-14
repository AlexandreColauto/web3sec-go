package findings

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestRefusedMoveKeepsTheFindingOpen pins r17 P1#2: a move whose
// finding.status event the ledger refuses used to half-land — status
// DISPROVED with NO event, and DISPROVED is terminal in the transition
// table (legal exits: none). The finding stayed bricked with audit
// PASS; the only exit was hand-editing. SaveThenLog restores the file.
func TestRefusedMoveKeepsTheFindingOpen(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Move Unwind Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	id := objStr(f, "finding_id")
	if id == "" {
		t.Fatal("ingest lost the finding")
	}
	if err := os.WriteFile(c.EventsPath, []byte("GARBAGE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(c, id, "DISPROVED", "the invariant holds everywhere",
		"op", "", false); err == nil {
		t.Fatal("move accepted a dead ledger")
	}
	g, err := LoadFinding(c, id)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(g, false)
	if objStr(g, "status") != "HYPOTHESIS" {
		t.Fatalf("refused DISPROVED move must have been unwound: %s",
			body[:min(len(body), 160)])
	}
	if strings.Contains(body, "invariant holds everywhere") {
		t.Fatal("the refused history row survived the unwind")
	}
}
