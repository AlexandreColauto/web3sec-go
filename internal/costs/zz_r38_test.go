package costs

// zz_r38_test.go — r38 P2-2, THE COST HALF. `webv2 cost` appends costs.jsonl
// and then anchors the row with a cost.recorded event. Pre-r38 the append came
// first and a REFUSED c.Log returned the error with the row still on disk, so
// the honest refusal an operator hits (a ledger cut to a prefix of its own
// bytes: `head -n 2 events.jsonl`) booked spend the ledger never recorded:
// CostMirrorProblems red-lines "ghost spend" forever, `budget` refuses to
// price the campaign, `doctor` heals the mirror but cannot delete a cost row,
// no sanctioned verb deletes a row, and the retry appended a SECOND row.
//
// These tests pin the repro end to end at the package seam the verb calls:
// the refusal leaves costs.jsonl byte-identical (or still absent), a retry
// cannot duplicate, the cost audit stays exactly as green as it was before the
// refused write — plus the honest-success shape (rows land exactly once, each
// with its event).

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"websec/internal/state"
)

func p22Sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// p22Camp is a fresh campaign in a private temp root.
func p22Camp(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r38 P2-2 cost program",
		state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c
}

// p22SeedLedger grows the log (and its mirror) by n ordinary events.
func p22SeedLedger(t *testing.T, c *state.Campaign, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("seed ledger event %d: %v", i, err)
		}
	}
}

// p22TruncateTo cuts events.jsonl to its first keep RECORDS — the exact
// operator move in the repro (`head -n K`, a partial restore) — which leaves
// the state mirror longer than the log and makes the next c.Log refuse.
func p22TruncateTo(t *testing.T, c *state.Campaign, keep int) {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) <= keep {
		t.Fatalf("ledger holds %d record(s); cannot truncate to %d", len(lines), keep)
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:keep], "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("truncate ledger: %v", err)
	}
}

// p22Snap reads a store file that may legitimately be absent (had=false).
func p22Snap(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false
		}
		t.Fatalf("read %s: %v", path, err)
	}
	return raw, true
}

// p22CostEvents counts cost.recorded events in the ledger ON DISK.
func p22CostEvents(t *testing.T, c *state.Campaign) int {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	n := 0
	for _, e := range evs {
		if objStr(e, "type") == "cost.recorded" {
			n++
		}
	}
	return n
}

// p22CostAudit is the money audit the operator sees (budget/yields call it).
func p22CostAudit(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	return CostMirrorProblems(c)
}

// TestP22RefusedCostLeavesNoRowAndKeepsTheAuditGreen is the reported repro:
// three hints (seeded as ordinary events), truncate events.jsonl to its first
// 2 records, then record a cost. The write is refused — and costs.jsonl must
// not exist afterwards, not even for the retry with a different amount.
func TestP22RefusedCostLeavesNoRowAndKeepsTheAuditGreen(t *testing.T) {
	c := p22Camp(t, "C-p22cost0001")
	p22SeedLedger(t, c, 3)
	path := costsPath(c)
	pre, had := p22Snap(t, path)
	if had {
		t.Fatalf("costs.jsonl present before any cost: %q", pre)
	}
	p22TruncateTo(t, c, 2)
	if probs := p22CostAudit(t, c); probs != nil {
		t.Fatalf("pre-refusal cost audit is already red: %v", probs)
	}

	_, err := RecordCost(c, RecordOpts{Kind: "compute", AmountUSD: 5, Actor: "operator"})
	if err == nil {
		t.Fatal("RecordCost accepted a ledger truncated under the mirror")
	}
	t.Logf("refused cost #1: %v", err)
	if !strings.Contains(err.Error(), "doctor") {
		t.Errorf("refusal %q does not point at the sanctioned repair (doctor)", err)
	}
	post, postHad := p22Snap(t, path)
	if postHad {
		t.Errorf("refused cost left a row behind: %d byte(s), sha256 %s, %q",
			len(post), p22Sha(post), post)
	}
	if probs := p22CostAudit(t, c); probs != nil {
		t.Errorf("refused cost left the audit red: %v", probs)
	}

	// Retry with a DIFFERENT amount: pre-r38 this appended a second row with
	// still no event (two rows, zero events, permanently red).
	_, err = RecordCost(c, RecordOpts{Kind: "compute", AmountUSD: 7, Actor: "operator"})
	if err == nil {
		t.Fatal("the retry accepted a ledger truncated under the mirror")
	}
	t.Logf("refused cost #2 (retry, amount 7): %v", err)
	retry, retryHad := p22Snap(t, path)
	if retryHad {
		t.Errorf("the retry left a row behind: %d byte(s), sha256 %s, %q",
			len(retry), p22Sha(retry), retry)
	}
	rows, lerr := LoadCosts(c)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if n := len(rows); n != 0 {
		t.Errorf("costs.jsonl holds %d row(s) after two refused writes, want 0", n)
	}
	if n := p22CostEvents(t, c); n != 0 {
		t.Errorf("ledger holds %d cost.recorded event(s), want 0", n)
	}
	if probs := p22CostAudit(t, c); probs != nil {
		t.Errorf("the audit is red after the refused retry: %v", probs)
	}
}

// TestP22RefusedCostRestoresTheExactBytes pins the OTHER half of the unwind:
// when costs.jsonl already holds a legitimate row (so a refused write must
// rewrite the pre-write bytes, not remove the file), the refused write leaves
// the file byte-identical, the row count unchanged, and the audit green.
func TestP22RefusedCostRestoresTheExactBytes(t *testing.T) {
	c := p22Camp(t, "C-p22cost0002")
	p22SeedLedger(t, c, 3)
	if _, err := RecordCost(c, RecordOpts{
		Kind: "compute", AmountUSD: 5, Actor: "operator",
		Note: ptr("the legitimate row"),
	}); err != nil {
		t.Fatalf("healthy record: %v", err)
	}
	path := costsPath(c)
	pre, had := p22Snap(t, path)
	if !had {
		t.Fatal("a successful RecordCost left no costs.jsonl")
	}
	// Grow the ledger past the cost event, then cut the log back to a prefix
	// that STILL holds it: the mirror is longer than the log (the write is
	// refused) but nothing the cost audit reads was lost — the pre-refusal
	// state is green, so the audit staying green is a real assertion.
	p22SeedLedger(t, c, 2)
	p22TruncateTo(t, c, 5)
	if probs := p22CostAudit(t, c); probs != nil {
		t.Fatalf("pre-refusal cost audit is red: %v", probs)
	}
	t.Logf("pre-write: costs.jsonl %d byte(s) sha256 %s", len(pre), p22Sha(pre))

	_, err := RecordCost(c, RecordOpts{Kind: "compute", AmountUSD: 7, Actor: "operator"})
	if err == nil {
		t.Fatal("RecordCost accepted a ledger truncated under the mirror")
	}
	t.Logf("refused cost: %v", err)
	post, postHad := p22Snap(t, path)
	if !postHad || len(post) != len(pre) || p22Sha(post) != p22Sha(pre) {
		t.Fatalf("refused cost did not restore the exact bytes: pre sha256 %s "+
			"(%d bytes) vs post sha256 %s (%d bytes)", p22Sha(pre), len(pre),
			p22Sha(post), len(post))
	}
	rows, lerr := LoadCosts(c)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(rows) != 1 {
		t.Fatalf("costs.jsonl holds %d row(s) after the refused write, want 1", len(rows))
	}
	// The retry (a different amount) must not duplicate the row either.
	_, err = RecordCost(c, RecordOpts{Kind: "compute", AmountUSD: 9, Actor: "operator"})
	if err == nil {
		t.Fatal("the retry accepted a ledger truncated under the mirror")
	}
	again, againHad := p22Snap(t, path)
	if !againHad || p22Sha(again) != p22Sha(pre) {
		t.Fatalf("the retry changed costs.jsonl: sha256 %s, want %s",
			p22Sha(again), p22Sha(pre))
	}
	if rows, _ = LoadCosts(c); len(rows) != 1 {
		t.Fatalf("the retry duplicated the row: %d row(s), want 1", len(rows))
	}
	if n := p22CostEvents(t, c); n != 1 {
		t.Fatalf("ledger holds %d cost.recorded event(s), want the 1 original", n)
	}
	if probs := p22CostAudit(t, c); probs != nil {
		t.Fatalf("the audit went red on the refused write: %v", probs)
	}
}

// TestP22CostSuccessLandsOnceWithItsEvent pins the honest-success shape: on a
// healthy campaign each cost lands exactly one row AND exactly one event, and
// the audit is green.
func TestP22CostSuccessLandsOnceWithItsEvent(t *testing.T) {
	c := p22Camp(t, "C-p22cost0003")
	first, err := RecordCost(c, RecordOpts{Kind: "compute", AmountUSD: 5, Actor: "operator"})
	if err != nil {
		t.Fatalf("record #1: %v", err)
	}
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 0.5, Actor: "operator"}); err != nil {
		t.Fatalf("record #2: %v", err)
	}
	rows, lerr := LoadCosts(c)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(rows) != 2 {
		t.Fatalf("costs.jsonl holds %d row(s), want 2", len(rows))
	}
	if got, want := objStr(rows[0], "cost_id"), objStr(first, "cost_id"); got != want {
		t.Fatalf("first row cost_id = %s, want %s", got, want)
	}
	if n := p22CostEvents(t, c); n != 2 {
		t.Fatalf("ledger holds %d cost.recorded event(s), want 2", n)
	}
	if probs := p22CostAudit(t, c); probs != nil {
		t.Fatalf("audit red on the success path: %v", probs)
	}
}
