package completion

// zz_r38_test.go — r38 P2-2, THE WAIVER HALF. Waive() appends waivers.jsonl and
// then anchors the row with a completion.waived event. Pre-r38 the append came
// first and a REFUSED c.Log returned the error with the row still on disk, so
// the same honest refusal (a ledger cut to a prefix of its own bytes) recorded
// a disposition the ledger never saw: VerifyLog red-lines "a waiver without its
// event" for the row, doctor cannot remove it, no verb deletes a waiver row,
// and the retry appended a SECOND row.
//
// These tests pin the repro at the package seam the verb calls: the refusal
// leaves waivers.jsonl byte-identical (or still absent), a retry cannot
// duplicate, the waiver audit stays exactly as green as it was before the
// refused write — plus the honest-success shape.

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

func p22Camp(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r38 P2-2 waive program",
		state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c
}

func p22SeedLedger(t *testing.T, c *state.Campaign, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("seed ledger event %d: %v", i, err)
		}
	}
}

// p22TruncateTo cuts events.jsonl to its first keep records (the operator's
// `head -n K`), leaving the state mirror longer than the log: the next c.Log
// refuses rather than adopting the loss.
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

// p22WaivedEvents counts completion.waived events in the ledger ON DISK.
func p22WaivedEvents(t *testing.T, c *state.Campaign) int {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	n := 0
	for _, e := range evs {
		if objStr(e, "type") == "completion.waived" {
			n++
		}
	}
	return n
}

// p22WaiverProblems is the waiver half of verify_log — the audit that red-lines
// a row the ledger never recorded ("a waiver without its event"). Other verify
// problems (the operator's own mirror truncation) are not this test's subject.
func p22WaiverProblems(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var out []string
	for _, p := range v.Problems {
		if strings.Contains(p, "waivers.jsonl") {
			out = append(out, p)
		}
	}
	return out
}

// TestP22RefusedWaiveLeavesNoRowAndKeepsTheAuditGreen is the waiver repro: the
// ledger is cut under the mirror, waive is refused, and waivers.jsonl must not
// exist afterwards — not even for the retry.
func TestP22RefusedWaiveLeavesNoRowAndKeepsTheAuditGreen(t *testing.T) {
	c := p22Camp(t, "C-p22waive0001")
	p22SeedLedger(t, c, 3)
	path := WaiversPath(c)
	pre, had := p22Snap(t, path)
	if had {
		t.Fatalf("waivers.jsonl present before any waiver: %q", pre)
	}
	p22TruncateTo(t, c, 2)
	if probs := p22WaiverProblems(t, c); len(probs) != 0 {
		t.Fatalf("pre-refusal waiver audit is already red: %v", probs)
	}

	_, err := Waive(c, "dedup", "*", "r38 P2-2 refused waive reason", "operator")
	if err == nil {
		t.Fatal("Waive accepted a ledger truncated under the mirror")
	}
	t.Logf("refused waive #1: %v", err)
	if !strings.Contains(err.Error(), "doctor") {
		t.Errorf("refusal %q does not point at the sanctioned repair (doctor)", err)
	}
	post, postHad := p22Snap(t, path)
	if postHad {
		t.Errorf("refused waive left a row behind: %d byte(s), sha256 %s, %q",
			len(post), p22Sha(post), post)
	}
	if probs := p22WaiverProblems(t, c); len(probs) != 0 {
		t.Errorf("refused waive left the audit red: %v", probs)
	}

	_, err = Waive(c, "dedup", "*", "r38 P2-2 refused waive retry", "operator")
	if err == nil {
		t.Fatal("the retry accepted a ledger truncated under the mirror")
	}
	t.Logf("refused waive #2 (retry): %v", err)
	retry, retryHad := p22Snap(t, path)
	if retryHad {
		t.Errorf("the retry left a row behind: %d byte(s), sha256 %s, %q",
			len(retry), p22Sha(retry), retry)
	}
	rows, werr := Waivers(c, "")
	if werr != nil {
		t.Fatal(werr)
	}
	if len(rows) != 0 {
		t.Errorf("waivers.jsonl holds %d row(s) after two refused writes, want 0",
			len(rows))
	}
	if n := p22WaivedEvents(t, c); n != 0 {
		t.Errorf("ledger holds %d completion.waived event(s), want 0", n)
	}
	if probs := p22WaiverProblems(t, c); len(probs) != 0 {
		t.Errorf("the audit is red after the refused retry: %v", probs)
	}
}

// TestP22RefusedWaiveRestoresTheExactBytes pins the restore branch: with a
// legitimate row already in waivers.jsonl, a refused write must rewrite the
// pre-write bytes — not remove the file, not leave a second row.
func TestP22RefusedWaiveRestoresTheExactBytes(t *testing.T) {
	c := p22Camp(t, "C-p22waive0002")
	p22SeedLedger(t, c, 3)
	if _, err := Waive(c, "dedup", "PROOF-1",
		"the legitimate waiver reason", "operator"); err != nil {
		t.Fatalf("healthy waive: %v", err)
	}
	path := WaiversPath(c)
	pre, had := p22Snap(t, path)
	if !had {
		t.Fatal("a successful Waive left no waivers.jsonl")
	}
	// Grow the ledger past the waived event, then cut the log to a prefix that
	// still CONTAINS it: the write is refused, yet nothing the waiver audit
	// reads was lost — so "the audit stays green" is a real assertion.
	p22SeedLedger(t, c, 2)
	p22TruncateTo(t, c, 5)
	if probs := p22WaiverProblems(t, c); len(probs) != 0 {
		t.Fatalf("pre-refusal waiver audit is red: %v", probs)
	}
	t.Logf("pre-write: waivers.jsonl %d byte(s) sha256 %s", len(pre), p22Sha(pre))

	_, err := Waive(c, "dedup", "PROOF-2",
		"a refused second waiver reason", "operator")
	if err == nil {
		t.Fatal("Waive accepted a ledger truncated under the mirror")
	}
	t.Logf("refused waive: %v", err)
	post, postHad := p22Snap(t, path)
	if !postHad || len(post) != len(pre) || p22Sha(post) != p22Sha(pre) {
		t.Fatalf("refused waive did not restore the exact bytes: pre sha256 %s "+
			"(%d bytes) vs post sha256 %s (%d bytes)", p22Sha(pre), len(pre),
			p22Sha(post), len(post))
	}
	rows, werr := Waivers(c, "")
	if werr != nil {
		t.Fatal(werr)
	}
	if len(rows) != 1 {
		t.Fatalf("waivers.jsonl holds %d row(s) after the refused write, want 1",
			len(rows))
	}
	// The retry must not duplicate the row either.
	_, err = Waive(c, "dedup", "PROOF-3",
		"a refused third waiver reason", "operator")
	if err == nil {
		t.Fatal("the retry accepted a ledger truncated under the mirror")
	}
	again, againHad := p22Snap(t, path)
	if !againHad || p22Sha(again) != p22Sha(pre) {
		t.Fatalf("the retry changed waivers.jsonl: sha256 %s, want %s",
			p22Sha(again), p22Sha(pre))
	}
	if rows, _ = Waivers(c, ""); len(rows) != 1 {
		t.Fatalf("the retry duplicated the row: %d row(s), want 1", len(rows))
	}
	if n := p22WaivedEvents(t, c); n != 1 {
		t.Fatalf("ledger holds %d completion.waived event(s), want the 1 original", n)
	}
	if probs := p22WaiverProblems(t, c); len(probs) != 0 {
		t.Fatalf("the audit went red on the refused write: %v", probs)
	}
}

// TestP22WaiveSuccessLandsOnceWithItsEvent pins the honest-success shape.
func TestP22WaiveSuccessLandsOnceWithItsEvent(t *testing.T) {
	c := p22Camp(t, "C-p22waive0003")
	row, err := Waive(c, "dedup", "*", "r38 P2-2 success waiver reason", "operator")
	if err != nil {
		t.Fatalf("waive: %v", err)
	}
	if got, want := objStr(row, "subject"), "*"; got != want {
		t.Fatalf("row subject = %q, want %q", got, want)
	}
	rows, werr := Waivers(c, "dedup")
	if werr != nil {
		t.Fatal(werr)
	}
	if len(rows) != 1 {
		t.Fatalf("waivers.jsonl holds %d row(s), want 1", len(rows))
	}
	if n := p22WaivedEvents(t, c); n != 1 {
		t.Fatalf("ledger holds %d completion.waived event(s), want 1", n)
	}
	if probs := p22WaiverProblems(t, c); len(probs) != 0 {
		t.Fatalf("audit red on the success path: %v", probs)
	}
}
