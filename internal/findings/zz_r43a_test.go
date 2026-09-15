package findings

// R43A (P1) at the findings store: LoadAllFindings answered "zero findings"
// for a findings/ directory it could not read, which is the ground every
// "every CONFIRMED finding needs X" proof clause stands on (they all pass
// vacuously on an empty list). A missing directory stays legitimately empty.

import (
	"os"
	"path/filepath"
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

func TestR43aLoadAllFindingsRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43afindings")
	r43aChmod(t, c.FindingsDir)

	got, err := LoadAllFindings(c)
	if err == nil {
		t.Fatalf("LoadAllFindings on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.FindingsDir) {
		t.Fatalf("refusal must name the store: %v", err)
	}
	// The live-findings reader (what findingsWith uses) must refuse too.
	if _, err := LoadLiveFindings(c); err == nil {
		t.Fatal("LoadLiveFindings swallowed the read failure")
	}
}

func TestR43aLoadAllFindingsAbsentStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43agone")
	if err := os.RemoveAll(c.FindingsDir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAllFindings(c)
	if err != nil {
		t.Fatalf("an absent store is an empty campaign: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestR43aLoadAllFindingsReadableStoreIsUnchanged(t *testing.T) {
	c := r43aCampaign(t, "C-r43aread")
	for _, n := range []string{"F-b.json", "F-a.json"} {
		if err := os.WriteFile(filepath.Join(c.FindingsDir, n),
			[]byte(`{"finding_id":"`+n+`","created_at":"2026-01-01T00:00:00Z"}`),
			0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LoadAllFindings(c)
	if err != nil {
		t.Fatalf("readable store: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
}

// TestR43aExecGateRefusesUnreadableExecStore is the E4+ evidence gate: with
// no cited artifact it searches the EXEC records for a matching run. An
// unreadable execs/ directory must not read as "no run exists" — that error
// is a statement about the campaign.
func TestR43aExecGateRefusesUnreadableExecStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43aexecgate")
	r43aChmod(t, c.ExecsDir)

	item := validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr("EV-1")},
		validation.KV{K: "level", V: validation.VStr("E4")},
		validation.KV{K: "sandbox_profile", V: validation.VStr("docker-networkless")},
	)
	err := checkExecGate(c, "F-x", item, false)
	if err == nil {
		t.Fatal("checkExecGate accepted evidence with an unreadable exec store")
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ExecsDir) {
		t.Fatalf("refusal must name the exec store: %v", err)
	}
}
