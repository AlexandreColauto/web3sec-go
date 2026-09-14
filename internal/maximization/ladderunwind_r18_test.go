package maximization

import (
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
)

// TestRefusedLadderStartLeavesNothingToHide pins r18 P1-2, the round's
// sharpest catch: StartLadder wrote the ladder doc and stamped
// finding.maximization.ladder_id BEFORE logging. Refuse the event and
// the retry hits the idempotent early-return — the ladder exists, the
// finding projects it, `ladder.started` NEVER can. Permanent burn by
// construction. After SaveThenLog discipline the refused start leaves
// the pair at its pre-write bytes, so the SAME call that failed becomes
// a clean, fully-logged start on retry.
func TestRefusedLadderStartLeavesNothingToHide(t *testing.T) {
	c := newCampaign(t, "Ladder Burn")
	f := confirmedFinding(t, c, "Fee skim via rounding")
	fid := objStr(f, "finding_id")
	// Kill the ledger under the verb.
	if err := os.WriteFile(c.EventsPath, []byte("{\"broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := StartLadder(c, fid); err == nil {
		t.Fatal("start accepted a dead ledger")
	}
	// Nothing may remain: no ladder doc, no ladder_id on the finding.
	if _, err := os.Stat(ladderPath(c, fid)); !os.IsNotExist(err) {
		t.Fatalf("ladder doc survived a refused event: %v", err)
	}
	raw, err := os.ReadFile(findings.FindingPath(c, fid))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ladder_id") {
		t.Fatal("finding carries a ladder_id from a start that never logged")
	}
	// Repair the ledger: the retry must produce a REAL start.
	if err := os.WriteFile(c.EventsPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	lad, err := StartLadder(c, fid)
	if err != nil {
		t.Fatalf("retry after restored ledger must start, not hide: %v", err)
	}
	ev, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ev), "ladder.started") {
		t.Fatal("retry started without ever emitting ladder.started")
	}
	_ = lad
}
