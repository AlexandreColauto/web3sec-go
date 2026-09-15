package relations

// R43A (P1): chainsOf read an unlistable chains/ directory as "no chains", so
// relation minting answered zero materialized chains for a store it never
// read.

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

func TestR43aChainsOfRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43arel1")
	r43aChmod(t, c.ChainsDir)

	got, err := chainsOf(c)
	if err == nil {
		t.Fatalf("chainsOf on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ChainsDir) {
		t.Fatalf("refusal must name the chain store: %v", err)
	}
	// The public entry that reads them.
	if _, err := MintChainedWith(c, "CHAIN-x", nil); err == nil {
		t.Fatal("MintChainedWith swallowed the read failure")
	}
}

func TestR43aChainsOfAbsentStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43arel2")
	if err := os.RemoveAll(c.ChainsDir); err != nil {
		t.Fatal(err)
	}
	got, err := chainsOf(c)
	if err != nil {
		t.Fatalf("an absent chain store is an empty campaign: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
