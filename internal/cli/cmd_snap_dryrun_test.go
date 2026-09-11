package cli

// M2/M5 CLI tests: --dry-run previews without recording; a real pin
// warns on untracked files inside the target.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitInit makes dir a git-clean repo, skipping when git is absent.
func gitInit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{
		{"-c", "init.defaultBranch=main", "init", "-q"},
		{"add", "-A"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestSnapDryRunPreviewsAndRecordsNothing(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"dry-run:", "nothing recorded",
		"ladder:", "would-be snapshot:", "prune names", "node_modules",
		"untracked: none"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	// Nothing recorded: no snapshot store, no new events.
	if _, err := os.Stat(filepath.Join(root, "campaigns", cid,
		"snapshots")); !os.IsNotExist(err) {
		t.Fatal("dry-run created the snapshot store")
	}
	raw, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "\n") != 1 ||
		!strings.Contains(string(raw), "campaign.created") {
		t.Fatalf("dry-run logged events: %q", raw)
	}
}

func TestSnapDryRunIDMatchesPin(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	_, out, _ := run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	id := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "would-be snapshot:") {
			rest := strings.TrimSpace(
				strings.SplitN(ln, "would-be snapshot:", 2)[1])
			id = strings.SplitN(rest, " ", 2)[0]
		}
	}
	if id == "" {
		t.Fatalf("no would-be id in:\n%s", out)
	}
	code, pinOut, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("pin exit %d: %q", code, errS)
	}
	if !strings.Contains(pinOut, "pinned "+id+" ") {
		t.Fatalf("pin id differs from dry-run %s:\n%s", id, pinOut)
	}
}

func TestSnapWarnsOnUntrackedFiles(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	gitInit(t, tgt)
	if err := os.WriteFile(filepath.Join(tgt, "PoC_litter.t.sol"),
		[]byte("// litter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("pin exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "WARNING") ||
		!strings.Contains(out, "PoC_litter.t.sol") {
		t.Fatalf("pin does not warn on the untracked file:\n%s", out)
	}
	// The dry run warns too, naming the same file.
	code, out, errS = run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	if code != 0 {
		t.Fatalf("dry-run exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "PoC_litter.t.sol") {
		t.Fatalf("dry-run does not name the untracked file:\n%s", out)
	}
}

func TestSnapSilentOnCleanTree(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("pin exit %d: %q", code, errS)
	}
	if strings.Contains(out, "WARNING") || strings.Contains(out, "untracked") {
		t.Fatalf("clean-tree pin warns:\n%s", out)
	}
}
