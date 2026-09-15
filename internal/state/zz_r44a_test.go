package state

// R44A (P1): the exec ledger had two readers with one name and OPPOSITE
// refusal semantics. sandbox.AllExecs refused an unlistable store (r43a);
// state.AllExecs — the one the audit's exec section reads — folded EVERY
// ReadDir error into `nil, nil`, so `chmod 000 <c>/execs/` (or replacing
// execs/ with a regular file) certified `audit PASS ... execs=0 problem(s)`
// exit 0 on a store it never read. Same treatment for ListCampaigns, whose
// silent "no campaigns" made artifact-prune render its exit-2 "unknown
// artifact" refusal for an artifact the unreadable store may well hold.
//
// Absence stays a fact: a missing execs/ or campaigns/ directory reads as
// empty, and a directory genuinely without a state file is not a campaign.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR44aAllExecsRefusesUnreadableStore(t *testing.T) {
	c, err := newCampaign(t.TempDir(), "C-r44aexec1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r43aChmod(t, c.ExecsDir)

	got, err := AllExecs(c)
	if err == nil {
		t.Fatalf("AllExecs on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ExecsDir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the store and the errno: %v", err)
	}
}

// The file-in-place-of-a-directory shape (ENOTDIR): the store exists but is
// not a directory, so no listing is possible and no count may be reported.
func TestR44aAllExecsRefusesNonDirectoryStore(t *testing.T) {
	c, err := newCampaign(t.TempDir(), "C-r44aexec2")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(c.ExecsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(c.ExecsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ExecsDir, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := AllExecs(c)
	if err == nil {
		t.Fatalf("AllExecs over a regular file returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "not a directory") ||
		!strings.Contains(err.Error(), c.ExecsDir) {
		t.Fatalf("refusal must name the store and the errno: %v", err)
	}
}

// The honest shapes stay green: no execs/ directory, and an empty one.
func TestR44aAllExecsAbsentAndEmptyStoresAreEmpty(t *testing.T) {
	absent, err := newCampaign(t.TempDir(), "C-r44aexec3")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(absent.ExecsDir); err != nil {
		t.Fatal(err)
	}
	got, err := AllExecs(absent)
	if err != nil || len(got) != 0 {
		t.Fatalf("an absent exec store is an empty campaign: %v, %v", got, err)
	}

	empty, err := newCampaign(t.TempDir(), "C-r44aexec4")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(empty.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = AllExecs(empty)
	if err != nil || len(got) != 0 {
		t.Fatalf("an empty exec store is an empty campaign: %v, %v", got, err)
	}
}

// A record whose existence cannot be decided (an EXEC-* directory that cannot
// be searched) must refuse, not be dropped from the list: dropping it would
// report a smaller ledger than the store holds.
func TestR44aAllExecsRefusesUndecidableRecord(t *testing.T) {
	c, err := newCampaign(t.TempDir(), "C-r44aexec5")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.ExecsDir, "EXEC-bad"), 0o755); err != nil {
		t.Fatal(err)
	}
	r43aChmod(t, filepath.Join(c.ExecsDir, "EXEC-bad"))

	got, err := AllExecs(c)
	if err == nil {
		t.Fatalf("an undecidable record was skipped silently: %v", got)
	}
	if !strings.Contains(err.Error(), c.ExecsDir) {
		t.Fatalf("refusal must name the exec store: %v", err)
	}
}

func TestR44aListCampaignsRefusesUnreadableStore(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root, "r44a", InitOpts{CampaignID: "C-r44alist1"}); err != nil {
		t.Fatal(err)
	}
	cdir := filepath.Join(root, "campaigns")
	r43aChmod(t, cdir)

	got, err := ListCampaigns(root)
	if err == nil {
		t.Fatalf("ListCampaigns on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), cdir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the campaign store and the errno: %v", err)
	}
}

func TestR44aListCampaignsRefusesNonDirectoryStore(t *testing.T) {
	root := t.TempDir()
	cdir := filepath.Join(root, "campaigns")
	if err := os.WriteFile(cdir, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ListCampaigns(root)
	if err == nil {
		t.Fatalf("ListCampaigns over a regular file returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "not a directory") ||
		!strings.Contains(err.Error(), cdir) {
		t.Fatalf("refusal must name the store and the errno: %v", err)
	}
}

// A campaign directory that cannot be searched cannot be decided to be a
// campaign: the pre-fix code folded the EACCES on campaign_state.json into
// "not a campaign", so pruneLookup skipped the very campaign that may hold
// the artifact.
func TestR44aListCampaignsRefusesUnsearchableCampaign(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root, "r44a", InitOpts{CampaignID: "C-r44alist2"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "campaigns", "C-r44alist2")
	r43aChmod(t, dir)

	got, err := ListCampaigns(root)
	if err == nil {
		t.Fatalf("an unsearchable campaign was silently dropped: %v", got)
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), "C-r44alist2") {
		t.Fatalf("refusal must name the campaign: %v", err)
	}
}

// Honest shapes: an absent campaigns/ root and an empty one are "no
// campaigns"; a directory without a state file is not a campaign.
func TestR44aListCampaignsAbsentEmptyAndLayoutFilter(t *testing.T) {
	gone := t.TempDir()
	got, err := ListCampaigns(gone)
	if err != nil || len(got) != 0 {
		t.Fatalf("an absent campaign store is no campaigns: %v, %v", got, err)
	}

	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "campaigns"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = ListCampaigns(empty)
	if err != nil || len(got) != 0 {
		t.Fatalf("an empty campaign store is no campaigns: %v, %v", got, err)
	}

	one := t.TempDir()
	if _, err := Init(one, "r44a", InitOpts{CampaignID: "C-r44alist3"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(one, "campaigns", "not-a-campaign"),
		0o755); err != nil {
		t.Fatal(err)
	}
	got, err = ListCampaigns(one)
	if err != nil {
		t.Fatalf("a dir without a state file is the layout filter: %v", err)
	}
	if len(got) != 1 || got[0] != "C-r44alist3" {
		t.Fatalf("got %v, want the one real campaign", got)
	}
}
