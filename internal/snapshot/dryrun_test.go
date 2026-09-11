package snapshot

// M2/M5 tests: the dry-run preview and the untracked-files listing.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dryTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"src/Vault.sol":         "contract Vault {}\n",
		"node_modules/dep/x.js": "litter\n",
		"build/out.txt":         "generated\n",
		"foundry.toml":          "[profile.default]\n",
		"PoC_litter.t.sol":      "// operator litter\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDryRunPreviewsWithoutRecording(t *testing.T) {
	dir := dryTarget(t)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DryRunPin(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ladder != "no-vcs" {
		t.Fatalf("ladder = %q, want no-vcs", p.Ladder)
	}
	if !strings.HasPrefix(p.SnapshotID, "src-content-") {
		t.Fatalf("snapshot id = %q", p.SnapshotID)
	}
	if p.FileCount != 3 {
		t.Fatalf("file count = %d, want 3 (node_modules pruned)", p.FileCount)
	}
	found := false
	for _, n := range p.PruneNames {
		if n == "node_modules" {
			found = true
		}
	}
	if !found {
		t.Fatalf("prune names lack node_modules: %v", p.PruneNames)
	}
	if len(p.PrunedPaths) != 1 || p.PrunedPaths[0] != "build" {
		t.Fatalf("pruned paths = %v, want [build]", p.PrunedPaths)
	}
	// Nothing recorded: the target gains no snapshot store, no temp
	// staging leaks.
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("dry-run wrote into the target: %v -> %v", before, after)
	}
	for _, e := range after {
		if strings.HasPrefix(e.Name(), "staging-") {
			t.Fatalf("staging leaked: %s", e.Name())
		}
	}
}

func TestDryRunIDMatchesRealPin(t *testing.T) {
	dir := dryTarget(t)
	p, err := DryRunPin(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := pinCampaign(t, t.TempDir(), "C-dryrun0001")
	snap, err := PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strField(t, snap, "snapshot_id"); got != p.SnapshotID {
		t.Fatalf("dry-run id %q != pin id %q", p.SnapshotID, got)
	}
}

func TestUntrackedFilesListsOnlyUntracked(t *testing.T) {
	dir := dryTarget(t)
	gitSetup(t, dir)
	// PoC_litter.t.sol and everything else were committed by gitSetup's
	// `add -A`: clean tree lists nothing.
	if listed, more := UntrackedFiles(dir, excludeSet(nil)); len(listed) != 0 || more != 0 {
		t.Fatalf("clean tree lists %v (+%d)", listed, more)
	}
	// A new litter file is untracked; a pruned-dir file stays silent.
	if err := os.WriteFile(filepath.Join(dir, "PoC_new.t.sol"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "evil.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	listed, more := UntrackedFiles(dir, excludeSet(nil))
	if more != 0 || len(listed) != 1 || listed[0] != "PoC_new.t.sol" {
		t.Fatalf("untracked = %v (+%d), want exactly [PoC_new.t.sol]", listed, more)
	}
}

func TestUntrackedFilesSilentOffGit(t *testing.T) {
	dir := dryTarget(t)
	if listed, more := UntrackedFiles(dir, excludeSet(nil)); len(listed) != 0 || more != 0 {
		t.Fatalf("non-git target lists %v (+%d)", listed, more)
	}
}
