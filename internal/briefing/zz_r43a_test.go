package briefing

// R43A (P1): Materializable read chains/ behind a dirExists() guard, so an
// unreadable chain store read as "nothing is materialized" — the premise of
// every materializable proposal in the brief.

import (
	"os"
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

func TestR43aMaterializableRefusesUnreadableChainStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43abrief1")
	r43aChmod(t, c.ChainsDir)

	got, err := Materializable(c)
	if err == nil {
		t.Fatalf("Materializable on an unreadable chain store returned %v", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ChainsDir) {
		t.Fatalf("refusal must name the chain store: %v", err)
	}
}

func TestR43aMaterializableMissingStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43abrief2")
	if err := os.RemoveAll(c.ChainsDir); err != nil {
		t.Fatal(err)
	}
	if _, err := Materializable(c); err != nil {
		t.Fatalf("an absent chain store is an empty campaign: %v", err)
	}
}
