package completion

// R43B (P3-3): proofLearning's memory-store guard was reported as a dead
// `if err != nil` — a branch that could never fire because the call it
// guarded returned no error, so an unlistable memory store was read as "no
// memory entries" and the learning proof stood on that. The call now returns
// ([]string, error) and the branch fires; this test pins the reachability, so
// if the guard ever goes vestigial again the suite says so.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
)

func TestR43bMemoryStoreGuardIsLive(t *testing.T) {
	c, err := state.Init(t.TempDir(), "r43b",
		state.InitOpts{CampaignID: "C-r43bproof1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.MemoryDir, 0o000); err != nil {
		t.Skipf("chmod 000 %s: %v", c.MemoryDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(c.MemoryDir, 0o755) })
	if _, err := os.ReadDir(c.MemoryDir); err == nil {
		t.Skipf("an unreadable memory/ stays listable here (root?): %s",
			c.MemoryDir)
	}
	pr, err := ProofStatus(c, "learning")
	if err != nil {
		t.Fatalf("ProofStatus(learning): %v", err)
	}
	if pyTruthyBigNonEmpty(objAt(pr, "done")) {
		t.Fatal("learning certified DONE over an unlistable memory store")
	}
	joined := ""
	for _, m := range objAt(pr, "missing").A {
		joined += m.S + "\n"
	}
	t.Logf("learning proof with an unlistable memory store:\n%s", joined)
	if !strings.Contains(joined, "cannot be listed") {
		t.Fatalf("the memory-store guard did not fire — the proof answered "+
			"over a store it could not list:\n%s", joined)
	}
	if !strings.Contains(joined, c.MemoryDir) {
		t.Fatalf("the refusal does not name the memory store %s:\n%s",
			c.MemoryDir, joined)
	}
	if strings.Contains(joined, "no memory entry for this terminal finding") {
		t.Fatalf("the read failure was reported as missing memory entries:\n%s",
			joined)
	}
}
