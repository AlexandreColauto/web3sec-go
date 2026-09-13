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
	// Modes sealed WHERE THE TWIN SEALS THEM: child directories carry the
	// source perms; the staged ROOT stays writable — the pin writes
	// snapshot.json into it after the copy (r6 regression: sealing the
	// root made every 0500-root target un-pinnable forever).
	for _, p := range []string{"locked"} {
		st, err := os.Stat(filepath.Join(dst, p))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o500 {
			t.Fatalf("staged %q mode %v, want 0500 (copystat parity)",
				p, st.Mode().Perm())
		}
	}
	// … and the root is EXPLICITLY 0755 (writable for the meta write).
	if rst, rerr := os.Stat(dst); rerr != nil {
		t.Fatal(rerr)
	} else if rst.Mode().Perm() != 0o755 {
		t.Fatalf("staged root must stay writable for the pin: %v",
			rst.Mode().Perm())
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

// TestPinReadOnlySourceRootSucceeds pins the r6 REGRESSION fix end to end:
// an 0500 source root must pin, write its manifest, and pass audit — the
// pre-fix code sealed the staged root before snapshot.json landed, burning
// the store with a half-pin no retry could heal.
func TestPinReadOnlySourceRootSucceeds(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	base := t.TempDir()
	src := filepath.Join(base, "target")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "V.sol"),
		[]byte("contract V {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(src, 0o755) })
	c := pinCampaign(t, filepath.Join(base, "camp"), "C-1122334455aa")
	snap, err := PinSourceSnapshot(c, src, nil, nil)
	if err != nil {
		t.Fatalf("read-only ROOT must pin like the twin: %v", err)
	}
	final := filepath.Join(c.Dir, "snapshots", objStrOf(t, snap, "snapshot_id"))
	if _, err := os.Stat(filepath.Join(final, "snapshot.json")); err != nil {
		t.Fatalf("manifest must exist after a sealed-child copy: %v", err)
	}
	// Re-pin (identical) must also succeed — the dirExists(final) re-hash
	// path the critic found permanently broken.
	if _, err := PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatalf("re-pin of a sealed-children store: %v", err)
	}
}

// TestRePinReadOnlyTreeLeavesNoStaging pins r7 issue 2: the re-pin
// (identical content) branch DISCARDS the fresh staging copy — and when the
// source tree seals its children (0500 dirs), a plain RemoveAll fails in
// silence, the ghost lands in the store, and every later audit burns red.
func TestRePinReadOnlyTreeLeavesNoStaging(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	base := t.TempDir()
	src := filepath.Join(base, "target")
	sub := filepath.Join(src, "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.sol", "deep/b.sol"} {
		if err := os.WriteFile(filepath.Join(src, filepath.FromSlash(f)),
			[]byte("content "+f+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(sub, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(src, 0o755)
		_ = os.Chmod(sub, 0o755)
		// The STORE keeps sealed copies too — unseal it for TempDir.
		root := filepath.Join(base, "camp")
		_ = filepath.WalkDir(root, func(pp string, d os.DirEntry,
			err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(pp, 0o755)
			}
			return nil
		})
	})
	c := pinCampaign(t, filepath.Join(base, "camp"), "C-deadbeef0001")
	if _, err := PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatalf("pin1 of read-only tree: %v", err)
	}
	if _, err := PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatalf("re-pin (identical) must succeed: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(c.Dir, "snapshots"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "staging-") {
			t.Fatalf("re-pin leaked %s (the r7 EACCES ghost)", e.Name())
		}
	}
}

// TestCopyTreeFileModeFidelity pins r7 issue 4: mode bits must arrive
// EXACTLY — os.WriteFile masks with the umask (0o666 & ^0o022 = 0o644),
// which quietly rewrote group/other bits on the staged tree under a copy2
// fidelity claim.
func TestCopyTreeFileModeFidelity(t *testing.T) {
	src := t.TempDir()
	f := filepath.Join(src, "script.sh")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o777); err != nil {
		t.Fatal(err) // the full perm, umask-proof
	}
	g := filepath.Join(src, "data.bin")
	if err := os.WriteFile(g, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(g, 0o664); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "staged")
	if err := copyTree(src, dst, nil); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"script.sh": 0o777,
		"data.bin": 0o664} {
		st, err := os.Stat(filepath.Join(dst, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Fatalf("staged %s mode %v, want %v (umask must not rewrite)",
				name, st.Mode().Perm(), want)
		}
	}
}
