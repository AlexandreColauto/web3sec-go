package completion

// R43A (P1) at the proofs — the escalation the critic captured: with
// findings/ unreadable, every stage whose clauses begin "every CONFIRMED
// finding needs X" came out DONE (vacuously true over an empty list), so
// `prove` certified maximal-exploitation [authoritative] while the store was
// unreadable. proof_status turns a proof error into an OPEN stage naming the
// error, so the fix is that the reader refuses instead of answering zero.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func r43aCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r43a", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

func r43aChmod(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skipf("cannot create an unreadable directory here (%s stayed readable)", dir)
	}
}

// r43aStages are the proof stages whose rules run over the findings store.
var r43aStages = []string{
	"maximal-exploitation", "hostile-review", "independent-verification",
	"mainnet-fork-poc", "reproduction", "bounty-gate", "dedup",
	"risk-calibration", "learning",
}

func r43aProofDone(t *testing.T, c *state.Campaign, stage string) (bool, validation.Value) {
	t.Helper()
	pr, err := ProofStatus(c, stage)
	if err != nil {
		t.Fatalf("ProofStatus(%s): %v", stage, err)
	}
	return pyTruthyBigNonEmpty(objAt(pr, "done")), pr
}

func TestR43aProofsStayOpenOnUnreadableFindingsStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43aproof1")
	r43aChmod(t, c.FindingsDir)

	if _, err := liveFindings(c); err == nil {
		t.Fatal("liveFindings swallowed the read failure")
	}
	for _, stage := range r43aStages {
		done, pr := r43aProofDone(t, c, stage)
		if done {
			t.Errorf("%s certified DONE with an unreadable findings store", stage)
		}
		joined := ""
		for _, m := range objAt(pr, "missing").A {
			joined += m.S + "\n"
		}
		if !strings.Contains(joined, "proof error: the findings store") ||
			!strings.Contains(joined, "cannot be listed") {
			t.Errorf("%s must report the proof error, got %q", stage, joined)
		}
	}
	// The authoritative headline of the critic's repro.
	if done, _ := r43aProofDone(t, c, "maximal-exploitation"); done {
		t.Fatal("maximal-exploitation [authoritative] must not be DONE")
	}
}

// TestR43aProofsStayDoneForAnEmptyFindingsStore is the other half of the
// distinction: a campaign with NO findings is legitimately vacuous, and the
// same stages are DONE. Only the unreadable case is a refusal.
func TestR43aProofsStayDoneForAnEmptyFindingsStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43aproof2")
	if err := os.RemoveAll(c.FindingsDir); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"maximal-exploitation", "hostile-review",
		"independent-verification", "mainnet-fork-poc", "reproduction",
		"bounty-gate", "dedup", "risk-calibration"} {
		if done, _ := r43aProofDone(t, c, stage); !done {
			t.Errorf("%s = open for an empty campaign; want the ported behaviour (DONE)", stage)
		}
	}
}

// TestR43aLearningProofRefusesUnreadableMemoryStore: the learning proof reads
// memory/ behind a dirExists() guard, i.e. an unreadable directory read as
// "no memory entries" and the proof stood on that.
func TestR43aLearningProofRefusesUnreadableMemoryStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43aproof3")
	r43aChmod(t, c.MemoryDir)

	done, pr := r43aProofDone(t, c, "learning")
	if done {
		t.Fatal("learning certified DONE with an unreadable memory store")
	}
	joined := ""
	for _, m := range objAt(pr, "missing").A {
		joined += m.S + "\n"
	}
	if !strings.Contains(joined, "cannot be listed") {
		t.Fatalf("learning must name the memory store: %q", joined)
	}
}
