package chainengine

// R43A (P1): chainDocs read an unlistable chains/ directory as "no chain
// documents", so chain_report answered "materialized chains: 0" and, in the
// audit's projection, both directions became vacuous. It refuses now; only a
// missing directory stays empty.

import (
	"os"
	"strings"
	"testing"
	"websec/internal/validation"

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

func TestR43aChainReportRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43achain1")
	r43aChmod(t, c.ChainsDir)

	got, err := ChainReport(c)
	if err == nil {
		t.Fatalf("ChainReport on an unreadable chain store returned %v", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ChainsDir) {
		t.Fatalf("refusal must name the chain store: %v", err)
	}
}

func TestR43aChainReportMissingStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43achain2")
	if err := os.RemoveAll(c.ChainsDir); err != nil {
		t.Fatal(err)
	}
	got, err := ChainReport(c)
	if err != nil {
		t.Fatalf("an absent chain store is an empty campaign: %v", err)
	}
	if n := len(validation.ObjAt(got, "materialized").A); n != 0 {
		t.Fatalf("materialized = %d, want 0", n)
	}
}
