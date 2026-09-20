package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// cliFindingFiles counts the F-*.json rows the campaign's findings store holds.
func cliFindingFiles(t *testing.T, c *state.Campaign) int {
	t.Helper()
	entries, err := os.ReadDir(c.FindingsDir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "F-") &&
			filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return n
}

// cliIngestAnswering runs `ingest --answers-priority` and returns the id the
// CLI answered with.
func cliIngestAnswering(t *testing.T, root, cid, payload, priority string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", payload, "--answers-priority", priority)
	if code != 0 {
		t.Fatalf("ingest (priority %s) exit %d: %q", priority, code, errS)
	}
	return strings.Fields(out)[1]
}

// assertPriorityClosedOn pins the closure ref of one plan priority.
func assertPriorityClosedOn(t *testing.T, c *state.Campaign, priority,
	fid string) {
	t.Helper()
	prio := nextPriority(t, t14bPlan(t, c), priority)
	if st := validation.ObjStr(prio, "status"); st != "answered" {
		t.Fatalf("priority %s status = %q, want answered", priority, st)
	}
	if ref := validation.ObjStr(prio, "closed_ref"); ref != fid {
		t.Fatalf("priority %s closed_ref = %q, want %s", priority, ref, fid)
	}
}

// assertIngestIdempotentLogged is the ledger half: the door records the hit.
func assertIngestIdempotentLogged(t *testing.T, c *state.Campaign) {
	t.Helper()
	for _, typ := range t14bEventTypes(t, c) {
		if typ == "finding.ingest_idempotent" {
			return
		}
	}
	t.Fatal("no finding.ingest_idempotent event on the ledger")
}

// Morph §7.5: a re-submitted payload is answered with the finding that already
// carries its content digest — and the orchestrator's priority-closure half
// must still run on that twin. The payload DID answer the question, so the
// second priority closes on the FIRST finding's id, the ledger records
// finding.ingest_idempotent, and no second finding file appears.
func TestIdempotentIngestStillClosesThePriority(t *testing.T) {
	c, root, cid := t14bPlannedCampaign(t)
	prios := t14bPriorities(t, t14bPlan(t, c))
	payload := t14bPayloadFile(t, root)
	fid := cliIngestAnswering(t, root, cid, payload,
		validation.ObjStr(prios[0], "id"))

	// the SAME payload again, answering a DIFFERENT question
	q2 := validation.ObjStr(prios[1], "id")
	if got := cliIngestAnswering(t, root, cid, payload, q2); got != fid {
		t.Fatalf("second ingest answered with %s, want the twin %s", got, fid)
	}
	assertPriorityClosedOn(t, c, q2, fid)
	if n := cliFindingFiles(t, c); n != 1 {
		t.Fatalf("findings on disk = %d, want 1", n)
	}
	assertIngestIdempotentLogged(t, c)
}
