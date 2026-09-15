package sandbox

// R43A (P1): AllExecs stat'ed execs/ and returned an empty list for ANY error
// — EACCES included. "Zero execs" is a claim about the store; a store that
// could not be read supports no claim. A missing directory stays empty.

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

func TestR43aAllExecsRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43aexec")
	r43aChmod(t, c.ExecsDir)

	got, err := AllExecs(c)
	if err == nil {
		t.Fatalf("AllExecs on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ExecsDir) {
		t.Fatalf("refusal must name the exec store: %v", err)
	}
}

func TestR43aAllExecsAbsentStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43aexecc")
	if err := os.RemoveAll(c.ExecsDir); err != nil {
		t.Fatal(err)
	}
	got, err := AllExecs(c)
	if err != nil {
		t.Fatalf("an absent exec store is an empty campaign: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// TestR43aAllExecsEmptyStoreIsEmpty keeps the honest empty case green.
func TestR43aAllExecsEmptyStoreIsEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r43aexecb")
	got, err := AllExecs(c)
	if err != nil {
		t.Fatalf("a genuinely empty exec store: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
