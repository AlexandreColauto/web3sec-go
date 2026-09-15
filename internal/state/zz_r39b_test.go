package state

import (
	"os"
	"testing"

	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r39b — the empty projection is certified health no more.
//
// P3: VerifyLog's state-tail check was gated on len(stTail.A) > 0, so a
// state events array of [] under a LIVE ledger (the finding used a 2-event
// ledger) verified ok:true and the audit exited 0: a projection that lost
// its WHOLE head was certified. The RUNBOOK calls a projection with a hole
// in its head "not health" (assets/runbook/RUNBOOK.md, the r34 boundary
// note: "so is a mirror whose records are a SUFFIX of the log but not its
// cap window (a projection with a hole in its head is not health)"); the
// empty mirror is the extreme of that shape, and min(E, mirrorCap) is part
// of the documented invariant — for E > 0 the rule keeps at least 1 event.
// The genesis/zero-event shape stays honest: a campaign with NO events at
// all keeps verifying green, because an empty mirror is then exactly the
// rule's output (min(0, mirrorCap) = 0).
// ---------------------------------------------------------------------------

// TestR39bEmptyMirrorUnderLiveLedgerIsNotHealth: two live events, the
// projection emptied out from under them — verify must go red and name the
// empty projection, not certify it.
func TestR39bEmptyMirrorUnderLiveLedgerIsNotHealth(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "r39b empty mirror", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatal(err)
	} // live 2-event ledger
	// Fixture sanity: green before the tamper.
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("fixture must verify green before the tamper: %+v %v",
			v.Problems, err)
	}
	r38SetMirror(t, c, []validation.Value{})
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("an empty mirror under a live ledger verified OK: %+v", v)
	}
	if !hasProblem(v, "state events projection is EMPTY under a 2-event log") {
		t.Fatalf("the problem must name the empty projection: %+v", v.Problems)
	}
	if !hasProblem(v, "not health") {
		t.Fatalf("the problem must say the projection is not health: %+v",
			v.Problems)
	}
}

// TestR39bZeroEventCampaignStaysGreen: the genesis/zero-event shape — no
// events at all, empty mirror — is the rule's own output and stays health.
func TestR39bZeroEventCampaignStaysGreen(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "r39b zero events", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	r38SetMirror(t, c, []validation.Value{})
	// Cut the ledger to zero bytes: a campaign with no events at all.
	if err := os.WriteFile(c.EventsPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Events != 0 {
		t.Fatalf("a zero-event campaign must stay green: %+v", v)
	}
}
