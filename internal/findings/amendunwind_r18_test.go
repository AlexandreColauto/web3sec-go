package findings

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestRefusedAmendLeavesTheClaimIntact pins r18 P1-1: an amended claim
// whose finding.amended event was refused used to half-land — new text,
// claim_version 1, a history row — verify GREEN after repair, audit
// PASS, and the hash chain silent about the most load-bearing bytes a
// finding has.
func TestRefusedAmendLeavesTheClaimIntact(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Amend Unwind Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	id := validation.ObjStr(f, "finding_id")
	before := mustLoadRaw(t, c, id)
	if err := os.WriteFile(c.EventsPath, []byte("{\"garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Amend(c, id, AmendOpts{Claim: "TAMPERED CLAIM TEXT no ledger " +
		"trace", HasClaim: true, Note: "trying the laundering route",
		Actor: "op"})
	if err == nil {
		t.Fatal("amend accepted a dead ledger")
	}
	after := mustLoadRaw(t, c, id)
	if !strings.Contains(string(after), "rounding") ||
		strings.Contains(string(after), "TAMPERED") {
		t.Fatalf("refused amend must leave the claim bytes untouched:\n%s",
			string(after)[:200])
	}
	if string(before) != string(after) {
		t.Fatal("the finding file moved under a refused event")
	}
}

// TestRefusedSupersedeStaysFinishable pins r18 P1-3 (the round's most
// damaging): when the successor's save half-landed without
// finding.superseded, the old finding was ALREADY terminal SUPERSEDED —
// no verb could complete or undo the supersede. SaveThenLog keeps the
// successor byte-exact, and the transition event's own discipline keeps
// the pair consistent.
func TestRefusedSupersedeStaysFinishable(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Supersede Split Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	oldF, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	oldID := validation.ObjStr(oldF, "finding_id")
	newF, err := IngestHypothesis(c, hypoPayload(
		kv("title", validation.VStr(
			"User can withdraw more than deposited, refined analysis"))),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	newID := validation.ObjStr(newF, "finding_id")
	newBefore := mustLoadRaw(t, c, newID)
	// Dead ledger.
	if err := os.WriteFile(c.EventsPath, []byte("{\"garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Supersede(c, newID, oldID, "op"); err == nil {
		t.Fatal("supersede accepted a dead ledger")
	}
	// Successor bytes untouched (no re_parented_from, no supersedes):
	newAfter := mustLoadRaw(t, c, newID)
	if string(newBefore) != string(newAfter) {
		t.Fatalf("successor half-landed under a refused event:\n%s",
			string(newAfter)[:260])
	}
	// The OLD finding never moved either: the transition inside
	// Supersede runs its own SaveThenLog, which ALSO refused.
	oldRow, err := LoadFinding(c, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(oldRow, "status") != "HYPOTHESIS" {
		t.Fatalf("old finding went terminal with no event: %s",
			validation.ObjStr(oldRow, "status"))
	}
}

func mustLoadRaw(t *testing.T, c *state.Campaign, id string) []byte {
	t.Helper()
	raw, err := os.ReadFile(FindingPath(c, id))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
