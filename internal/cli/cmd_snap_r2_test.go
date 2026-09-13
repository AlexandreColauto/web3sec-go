package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"websec/internal/state"
)

// r2SnapTarget writes a throwaway tree with the given file names.
func r2SnapTarget(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestSnapNamesExcludesThatMatchNothing pins critic r2 (R2-1): --exclude
// matches exact base names (a GLOB metavar was a lie); a pattern matching
// nothing is now said out loud, and a matching one is not.
func TestSnapNamesExcludesThatMatchNothing(t *testing.T) {
	_, root, cid := t2Campaign(t)
	tgt := r2SnapTarget(t, "A.sol", "lib/B.sol")
	code, out, errS := run(t, "--root", root, "snap", cid, tgt,
		"--exclude", "*.sol", "--exclude", "lib")
	if code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "matched nothing: *.sol") {
		t.Fatalf("the glob-shaped no-match must be named: %q", out)
	}
	if strings.Contains(out, "matched nothing: lib") {
		t.Fatalf("a matching exclude must not be called out: %q", out)
	}
}

// TestSnapEmptyTargetFailsCleanly pins critic r2 (R2-2): an empty target
// used to surface a raw lstat of an internal staging path.
func TestSnapEmptyTargetFailsCleanly(t *testing.T) {
	_, root, cid := t2Campaign(t)
	tgt := r2SnapTarget(t)
	code, _, errS := run(t, "--root", root, "snap", cid, tgt)
	if code == 0 {
		t.Fatal("pinning an empty target must not succeed silently")
	}
	if !strings.Contains(errS, "pins 0 files") || strings.Contains(errS, "staging-") {
		t.Fatalf("honest refusal expected: %q", errS)
	}
	// R3 (critic): a REFUSED operation must not have mutated anything —
	// no snapshot store, no events, no active_snapshot projection.
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(c.Dir, "snapshots")); !os.IsNotExist(statErr) {
		t.Fatalf("refused pin left a snapshot dir: %v", statErr)
	}
	if raw, rerr := os.ReadFile(filepath.Join(c.Dir, "events.jsonl")); rerr == nil &&
		strings.Contains(string(raw), "snapshot.pinned") {
		t.Fatal("refused pin logged snapshot.pinned")
	}
}
