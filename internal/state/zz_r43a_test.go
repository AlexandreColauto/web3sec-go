package state

// R43A (P1) at the citation reader — the pattern THE LAW already demanded
// here (a missing store is no findings; a store that cannot be listed is an
// error, never "no citations"). r43a moved that decision into the listing
// helper itself, so these tests pin that it survived the move.

import (
	"os"
	"strings"
	"testing"
)

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

func TestR43aCitationFindingsRefusesUnreadableStore(t *testing.T) {
	c, err := newCampaign(t.TempDir(), "C-r43astate1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r43aChmod(t, c.FindingsDir)

	got, err := citationFindings(c)
	if err == nil {
		t.Fatalf("citationFindings on an unreadable store returned %v", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.FindingsDir) {
		t.Fatalf("refusal must name the findings store: %v", err)
	}
}

func TestR43aCitationFindingsMissingStoreIsNoFindings(t *testing.T) {
	c, err := newCampaign(t.TempDir(), "C-r43astate2")
	if err != nil {
		t.Fatal(err)
	}
	got, err := citationFindings(c)
	if err != nil {
		t.Fatalf("a missing findings store is no findings: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestR43aCitationFindingsReadableStoreIsRead(t *testing.T) {
	c, err := newCampaign(t.TempDir(), "C-r43astate3")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.FindingsDir+"/F-a.json",
		[]byte(`{"finding_id":"F-a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := citationFindings(c)
	if err != nil {
		t.Fatalf("readable store: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}
