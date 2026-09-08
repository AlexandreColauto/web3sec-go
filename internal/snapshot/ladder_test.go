// Port of the ladder-detection half of Task 11: _git probe tolerance and
// _detect_ladder over no-vcs / git-clean / git-dirty targets.
package snapshot

import (
	"os"
	"os/exec"
	"regexp"
	"testing"
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestGitReturnsEmptyOnFailure(t *testing.T) {
	dir := t.TempDir()
	// Not a repo: rev-parse exits non-zero -> "" (never an error).
	if got := Git(dir, "rev-parse", "HEAD"); got != "" {
		t.Fatalf("Git on non-repo = %q, want empty", got)
	}
	// Missing path: git itself fails -> "".
	if got := Git(dir+"/does-not-exist", "rev-parse", "HEAD"); got != "" {
		t.Fatalf("Git on missing path = %q, want empty", got)
	}
}

func TestDetectLadderMissingTarget(t *testing.T) {
	if _, _, _, err := DetectLadder(t.TempDir() + "/nope"); err == nil {
		t.Fatal("DetectLadder on missing target: want error, got nil")
	}
}

func TestDetectLadderNoVCS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ladder, commit, dirty, err := DetectLadder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ladder != "no-vcs" || commit != nil || dirty != nil {
		t.Fatalf("got (%q, %v, %v), want (no-vcs, nil, nil)", ladder, commit, dirty)
	}
}

func TestDetectLadderMissingGitDegradesToNoVCS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitSetup(t, dir)
	// Hide git from PATH: the probe must degrade, never fail.
	t.Setenv("PATH", t.TempDir())
	ladder, commit, dirty, err := DetectLadder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ladder != "no-vcs" || commit != nil || dirty != nil {
		t.Fatalf("without git: got (%q, %v, %v), want (no-vcs, nil, nil)", ladder, commit, dirty)
	}
}

func TestDetectLadderGitCleanThenDirty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitSetup(t, dir)

	ladder, commit, dirty, err := DetectLadder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ladder != "git-clean" || commit == nil || !hex40.MatchString(*commit) {
		t.Fatalf("clean: got (%q, %v), want (git-clean, 40-hex)", ladder, commit)
	}
	if dirty == nil || *dirty {
		t.Fatalf("clean: dirty = %v, want false", dirty)
	}

	if err := os.WriteFile(dir+"/dirty.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ladder, commit2, dirty, err := DetectLadder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ladder != "git-dirty" || commit2 == nil || *commit2 != *commit {
		t.Fatalf("dirty: got (%q, %v), want (git-dirty, same commit)", ladder, commit2)
	}
	if dirty == nil || !*dirty {
		t.Fatalf("dirty: dirty = %v, want true", dirty)
	}
}

// gitSetup commits dir's current content. Skips when git is unavailable.
func gitSetup(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("-c", "init.defaultBranch=main", "init", "-q")
	run("add", "-A")
	run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
}
