package learning

// R43A (P1): AllMemory answered "no memory rows" for a memory/ directory it
// could not list, and StripCampaignMemoryField skipped a campaign whose
// memory/ could not be examined — reporting a strip that never ran (its
// `if err != nil` check even tested a stale error).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
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

func TestR43aAllMemoryRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43amem1")
	r43aChmod(t, c.MemoryDir)

	got, err := AllMemory(c)
	if err == nil {
		t.Fatalf("AllMemory on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.MemoryDir) {
		t.Fatalf("refusal must name the memory store: %v", err)
	}
	if _, err := PendingMemory(c); err == nil {
		t.Fatal("PendingMemory swallowed the read failure")
	}
}

func TestR43aAllMemoryAbsentStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43amem2")
	if err := os.RemoveAll(c.MemoryDir); err != nil {
		t.Fatal(err)
	}
	got, err := AllMemory(c)
	if err != nil {
		t.Fatalf("an absent memory store is an empty campaign: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// TestR43aStripRefusesUnreadableMemoryDir: the sweep mutates every campaign's
// memory rows; a memory/ directory it cannot examine must refuse rather than
// be skipped (a silent skip under-reports the strip).
func TestR43aStripRefusesUnreadableMemoryDir(t *testing.T) {
	c := r43aCampaign(t, "C-r43amem3")
	r43aChmod(t, c.MemoryDir)

	got, err := StripCampaignMemoryField(filepath.Dir(filepath.Dir(c.Dir)),
		"promotion_status", "actor", "reason")
	if err == nil {
		t.Fatalf("StripCampaignMemoryField skipped an unreadable memory dir: %v", got)
	}
	if !strings.Contains(err.Error(), c.MemoryDir) &&
		!strings.Contains(err.Error(), "cannot be") {
		t.Fatalf("refusal must name the memory directory: %v", err)
	}
}
