package report

// R43A (P1): report.Generate listed chains/ with the silent-empty helper, so
// an unreadable chain store rendered a report claiming there were no
// materialized chains.

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

func TestR43aGenerateRefusesUnreadableChainStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43areport1")
	r43aChmod(t, c.ChainsDir)

	got, err := Generate(c)
	if err == nil {
		t.Fatalf("Generate on an unreadable chain store returned a report")
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ChainsDir) {
		t.Fatalf("refusal must name the chain store: %v", err)
	}
	if got != "" {
		t.Fatalf("a refused generate must render nothing, got %q", got)
	}
}

func TestR43aGenerateRefusesUnreadableFindingsStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43areport2")
	r43aChmod(t, c.FindingsDir)

	if _, err := Generate(c); err == nil {
		t.Fatal("Generate rendered a report with an unreadable findings store")
	} else if !strings.Contains(err.Error(), "cannot be listed") {
		t.Fatalf("refusal must name the store: %v", err)
	}
}
