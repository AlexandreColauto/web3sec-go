package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyTreeCopystatLast pins r5 issue 1: a read-only source ROOT (0500)
// and read-only SUBdirectories copy fine — content moves while every staged
// dir is writable, mode bits are sealed LAST, exactly like
// shutil.copystat-after-children. The pre-r5 code chmod'ed the root before
// the walk and mkdir'ed children with their final modes: the twin's own
// happy path, failed here.
func TestCopyTreeCopystatLast(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits; the probe would pass vacuously")
	}
	src := t.TempDir()
	// Sealing src breaks TempDir's RemoveAll; unseal it before teardown.
	t.Cleanup(func() {
		_ = filepath.WalkDir(src, func(pp string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(pp, 0o755)
			}
			return nil
		})
	})
	mk := func(p, body string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(src, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("README.md", "top\n", 0o644)
	if err := os.MkdirAll(filepath.Join(src, "locked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "locked", "in.txt"),
		[]byte("nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Seal the subdir first, then the root: order of sealing must not
	// matter to the copier.
	if err := os.Chmod(filepath.Join(src, "locked"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(src, 0o755) })
	// dst lands OUTSIDE t.TempDir(): the sealed 0500 dirs break TempDir's
	// own RemoveAll, so the test unseals and removes by hand.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	if err := os.MkdirAll(dstRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dstRoot, "staged")
	t.Cleanup(func() {
		_ = filepath.WalkDir(dst, func(pp string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(pp, 0o755)
			}
			return nil
		})
	})
	if err := copyTree(src, dst, nil); err != nil {
		t.Fatalf("read-only source must copy like the twin: %v", err)
	}
	for _, want := range []struct{ p, body string }{
		{"README.md", "top\n"}, {"locked/in.txt", "nested\n"},
	} {
		raw, err := os.ReadFile(filepath.Join(dst, want.p))
		if err != nil || string(raw) != want.body {
			t.Fatalf("content %s: %q %v", want.p, raw, err)
		}
	}
	// Modes sealed: root and subdir carry the source perms, not 0755.
	for _, p := range []string{"", "locked"} {
		st, err := os.Stat(filepath.Join(dst, p))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o500 {
			t.Fatalf("staged %q mode %v, want 0500 (copystat parity)",
				p, st.Mode().Perm())
		}
	}
}

// TestFailedPinLeavesNoStaging pins the leak half of r5 issue 1: when the
// copy fails (unreadable file under a sealed tree), the staging dir is
// discarded — a `staging-*` survivor would burn the snapshots audit red
// forever for a pin that never happened.
func TestFailedPinLeavesNoStaging(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything; the failure cannot be provoked")
	}
	base := t.TempDir()
	src := filepath.Join(base, "target")
	if err := os.MkdirAll(filepath.Join(src, "secret"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "ok.txt"), []byte("x\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(src, "secret", "key.pem")
	if err := os.WriteFile(hidden, []byte("y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hidden, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o644) })
	c := pinCampaign(t, filepath.Join(base, "camp"), "C-aabbccddee11")
	if _, err := PinSourceSnapshot(c, src, nil, nil); err == nil {
		t.Fatal("unreadable source file must fail the pin")
	}
	entries, _ := os.ReadDir(filepath.Join(c.Dir, "snapshots"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "staging-") {
			t.Fatalf("failed pin leaked %s into the store", e.Name())
		}
	}
}
