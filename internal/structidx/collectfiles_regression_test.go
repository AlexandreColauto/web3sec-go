package structidx

import (
	"os"
	"path/filepath"
	"testing"
)

// A dangling symlink (or FIFO/socket/device file) in the source tree must be
// skipped, not collected: the pre-fix code appended every non-dir entry, so a
// dangling link reached os.ReadFile in the caller and aborted the whole index
// build.
func TestCollectFilesSkipsNonRegularEntries(t *testing.T) {
	root := t.TempDir()
	// A real source file.
	if err := os.WriteFile(filepath.Join(root, "Real.sol"),
		[]byte("contract Real {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A dangling symlink (target does not exist).
	if err := os.Symlink(filepath.Join(root, "does-not-exist.sol"),
		filepath.Join(root, "Broken.sol")); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	got, err := collectFiles(root)
	if err != nil {
		t.Fatalf("collectFiles aborted on a dangling symlink: %v", err)
	}
	for _, p := range got {
		if filepath.Base(p) == "Broken.sol" {
			t.Errorf("dangling symlink Broken.sol was collected: %v", got)
		}
	}
	found := false
	for _, p := range got {
		if filepath.Base(p) == "Real.sol" {
			found = true
		}
	}
	if !found {
		t.Errorf("Real.sol missing from collected files: %v", got)
	}
}
