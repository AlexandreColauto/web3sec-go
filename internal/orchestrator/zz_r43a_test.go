package orchestrator

// R43A (P1): defaultChainReport listed chains/ with the silent-empty helper
// and then swallowed every per-row Stat error, so chain_report answered
// "materialized chains: 0" for a store it could not read.

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

func TestR43aDefaultChainReportRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43aorch1")
	r43aChmod(t, c.ChainsDir)

	got, err := defaultChainReport(c)
	if err == nil {
		t.Fatalf("defaultChainReport on an unreadable chain store returned %v", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ChainsDir) {
		t.Fatalf("refusal must name the chain store: %v", err)
	}
}

func TestR43aDefaultChainReportMissingStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43aorch2")
	if err := os.RemoveAll(c.ChainsDir); err != nil {
		t.Fatal(err)
	}
	got, err := defaultChainReport(c)
	if err != nil {
		t.Fatalf("an absent chain store is an empty campaign: %v", err)
	}
	if n := len(objAt(got, "materialized").A); n != 0 {
		t.Fatalf("materialized = %d, want 0", n)
	}
}
