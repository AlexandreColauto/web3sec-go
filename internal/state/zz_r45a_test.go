package state

// R45A (P3): state.Open sat one door below the r44a ListCampaigns fix and had
// the same fold: EVERY os.Stat error on campaign_state.json was reported as
// "no such campaign: <dir>". An unsearchable campaigns/ (or campaign
// directory) therefore told the operator that the campaign they are looking
// at does not exist — and the sentence is load-bearing, because
// internal/cli.mapRunError keys its "you are not in the workspace" hint on the
// exact phrase, so a permission failure produced a wrong diagnosis twice over.
//
// Only os.IsNotExist is absence. EACCES/ENOTDIR/EIO are read failures this
// call did not perform, so they refuse naming the campaign and the errno and
// must never wear the absence sentence. Genuine absence (no campaigns/ yet, a
// campaign directory without a state file, a dangling symlink) keeps the
// byte-identical "no such campaign: <dir>" wording, and a chmod on the state
// FILE itself is not folded at all: stat does not read the file, so Open
// succeeds and the EACCES surfaces at read time — with the path and the errno
// — exactly as before.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r45aCampaign(t *testing.T, id string) (*Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := Init(root, "r45a", InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c, root
}

// TestR45aOpenRefusesUnreadableCampaignStore: `chmod 000 campaigns/` — the
// store cannot be searched, so no claim about the campaign is available.
func TestR45aOpenRefusesUnreadableCampaignStore(t *testing.T) {
	c, root := r45aCampaign(t, "C-r45aopen1")
	cdir := filepath.Join(root, "campaigns")
	r43aChmod(t, cdir)

	got, err := Open(root, c.CampaignID)
	if err == nil {
		t.Fatalf("Open on an unlistable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), c.Dir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the campaign and the errno: %v", err)
	}
	if strings.Contains(err.Error(), "no such campaign") {
		t.Fatalf("a read failure must not wear the absence sentence: %v", err)
	}
}

// TestR45aOpenRefusesUnsearchableCampaignDir: `chmod 000 campaigns/<C>/` —
// the campaign the operator is looking at, one door down.
func TestR45aOpenRefusesUnsearchableCampaignDir(t *testing.T) {
	c, root := r45aCampaign(t, "C-r45aopen2")
	r43aChmod(t, c.Dir)

	got, err := Open(root, c.CampaignID)
	if err == nil {
		t.Fatalf("Open on an unsearchable campaign returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), c.Dir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the campaign and the errno: %v", err)
	}
	if strings.Contains(err.Error(), "no such campaign") {
		t.Fatalf("a read failure must not wear the absence sentence: %v", err)
	}
}

// TestR45aOpenRefusesNonDirectoryCampaignPath: ENOTDIR — the campaign path is
// a regular file, so its state path cannot be examined at all. IsNotExist is
// false for ENOTDIR, so this must refuse rather than claim absence.
func TestR45aOpenRefusesNonDirectoryCampaignPath(t *testing.T) {
	c, root := r45aCampaign(t, "C-r45aopen3")
	if err := os.RemoveAll(c.Dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Dir, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Open(root, c.CampaignID)
	if err == nil {
		t.Fatalf("Open over a regular file returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("refusal must name the errno: %v", err)
	}
	if strings.Contains(err.Error(), "no such campaign") {
		t.Fatalf("ENOTDIR is not absence: %v", err)
	}
}

// TestR45aOpenAbsenceKeepsAbsenceWording pins the honest shapes byte for byte:
// a root with no campaigns/ yet, a campaign directory without a state file,
// and a dangling symlink in its place are all genuinely "no such campaign".
func TestR45aOpenAbsenceKeepsAbsenceWording(t *testing.T) {
	// No campaigns/ directory at all.
	bare := t.TempDir()
	want := "no such campaign: " + filepath.Join(bare, "campaigns", "C-abc12345")
	_, err := Open(bare, "C-abc12345")
	if err == nil || err.Error() != want {
		t.Fatalf("absent store:\n got %v\nwant %q", err, want)
	}

	// A campaign directory with no state file (the layout filter's shape).
	c, root := r45aCampaign(t, "C-r45aopen4")
	if err := os.Remove(c.StatePath); err != nil {
		t.Fatal(err)
	}
	want = "no such campaign: " + c.Dir
	if _, err := Open(root, c.CampaignID); err == nil || err.Error() != want {
		t.Fatalf("missing state file:\n got %v\nwant %q", err, want)
	}

	// A dangling symlink: ENOENT, the codified absence test.
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone.json"), c.StatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, c.CampaignID); err == nil || err.Error() != want {
		t.Fatalf("dangling link:\n got %v\nwant %q", err, want)
	}
}

// TestR45aOpenRealCampaignStillOpens: the readable shape is unchanged.
func TestR45aOpenRealCampaignStillOpens(t *testing.T) {
	c, root := r45aCampaign(t, "C-r45aopen5")
	got, err := Open(root, c.CampaignID)
	if err != nil {
		t.Fatalf("Open on a real campaign: %v", err)
	}
	if got.StatePath != c.StatePath {
		t.Fatalf("opened %v, want %v", got.StatePath, c.StatePath)
	}
}

// TestR45aUnreadableStateFileSurfacesAtReadTime documents the other spelling
// of the critic's repro: `chmod 000 campaign_state.json` is NOT a stat
// failure (stat needs no read permission on the file), so Open correctly
// succeeds — and the read that follows refuses naming the file and the errno.
// The fix must not turn this into "no such campaign" either, in either
// direction.
func TestR45aUnreadableStateFileSurfacesAtReadTime(t *testing.T) {
	c, root := r45aCampaign(t, "C-r45aopen6")
	if err := os.Chmod(c.StatePath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(c.StatePath, 0o644) })
	if _, rerr := os.ReadFile(c.StatePath); rerr == nil {
		t.Skipf("cannot make %s unreadable here (still readable)", c.StatePath)
	}

	got, err := Open(root, c.CampaignID)
	if err != nil {
		t.Fatalf("stat does not read the file, so Open must succeed: %v", err)
	}
	if _, err := got.State(); err == nil {
		t.Fatal("reading a 000-mode state file must fail")
	} else if !strings.Contains(err.Error(), c.StatePath) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("read failure must name the file and the errno: %v", err)
	} else if strings.Contains(err.Error(), "no such campaign") {
		t.Fatalf("a read failure must not wear the absence sentence: %v", err)
	}
}
