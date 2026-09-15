package sandbox

// r45b pins for the sandbox half of the compiler-pin rail.
//
// envseam.go carries the FAITHFUL transcription of env.sandbox_preflight that
// stands in until internal/envgo installs the real implementation. Its
// pinnedCompiler had drifted from envgo/preflight.go's copy: this one folded
// only JSON null (so a falsy-but-present pin 0 / false / 0.0 was read as a
// compiler version and turned into a "not a solc version" FAIL), and its
// scalarText dropped floats. The r45b differential in
// internal/envgo/zz_r45b_test.go compares the two copies' "solc" row; these
// tests pin THIS copy on its own so a drift fails a sandbox test too, without
// needing the sibling package.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// r45bPinCampaign pins one source snapshot, then writes the config shape
// under test into the manifest (the writer's schema only accepts
// string-or-null, so the falsy non-string shapes are foreign/hand-edited
// manifests).
func r45bPinCampaign(t *testing.T, name string, cfg *validation.Value) (
	*state.Campaign, string) {
	t.Helper()
	c := newCampaign(t, name)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	pinPath := filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")
	manifest, rerr := validation.ReadJson(pinPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	manifest = setKeyAt(manifest, "config", *cfg)
	if werr := validation.WriteJson(pinPath, manifest, ""); werr != nil {
		t.Fatal(werr)
	}
	return c, pinPath
}

// setKeyAt replaces (or appends) one key of an object value.
func setKeyAt(v validation.Value, key string, val validation.Value) validation.Value {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return v
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
	return v
}

// r45bHide makes a file unreadable (EACCES) for the duration of the test.
// Skipped as root, where mode bits do not deny the read.
func r45bHide(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny the read")
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
}

// TestR45bSandboxPinnedCompilerFoldsFalsyPins pins the reconciled semantics
// on the sandbox copy: Python's `if compiler:` — a falsy-but-present pin is
// NO pin, str() renders a truthy scalar, and the manifest's absence is a fact.
func TestR45bSandboxPinnedCompilerFoldsFalsyPins(t *testing.T) {
	falsy := []struct {
		name string
		v    validation.Value
	}{
		{"null", validation.VNull()},
		{"empty-string", validation.VStr("")},
		{"false", validation.VBool(false)},
		{"zero-int", validation.VInt(0)},
		{"zero-float", validation.VFloat(0)},
		{"empty-array", validation.VArr()},
	}
	for _, tc := range falsy {
		cfg := validation.VObj(validation.KV{K: "compiler", V: tc.v})
		c, _ := r45bPinCampaign(t, "r45b-sb-falsy-"+tc.name, &cfg)
		pin, err := pinnedCompiler(c)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if pin != nil {
			t.Errorf("%s: compiler = %q, want no pin", tc.name, *pin)
		}
	}

	// Truthy shapes are str()-rendered and split on the first comma.
	truthy := []struct {
		name string
		v    validation.Value
		want string
	}{
		{"version", validation.VStr("0.8.24"), "0.8.24"},
		{"version-with-args", validation.VStr("0.8.24, --optimize"), "0.8.24"},
		{"version-padded", validation.VStr(" 0.8.24 "), "0.8.24"},
		{"float-version", validation.VFloat(1.5), "1.5"},
		{"bool-true", validation.VBool(true), "True"},
	}
	for _, tc := range truthy {
		cfg := validation.VObj(validation.KV{K: "compiler", V: tc.v})
		c, _ := r45bPinCampaign(t, "r45b-sb-truthy-"+tc.name, &cfg)
		pin, err := pinnedCompiler(c)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if pin == nil || *pin != tc.want {
			t.Errorf("%s: compiler = %v, want %q", tc.name, pin, tc.want)
		}
	}

	// A pin with no compiler key at all, and no active snapshot: both nil.
	noKey := validation.VObj(validation.KV{K: "build_system",
		V: validation.VStr("foundry")})
	c, _ := r45bPinCampaign(t, "r45b-sb-nokey", &noKey)
	if pin, err := pinnedCompiler(c); err != nil || pin != nil {
		t.Errorf("no compiler key: (%v, %v), want (nil, nil)", pin, err)
	}
	if pin, err := pinnedCompiler(newCampaign(t, "r45b-sb-nosnap")); err != nil ||
		pin != nil {
		t.Errorf("no active snapshot: (%v, %v), want (nil, nil)", pin, err)
	}
}

// TestR45bSandboxPinnedCompilerRefusesUnreadablePin: ENOENT is a fact, every
// other stat/read failure is a refusal naming the path and the errno.
func TestR45bSandboxPinnedCompilerRefusesUnreadablePin(t *testing.T) {
	c := newCampaign(t, "r45b-sb-eacces")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")

	r45bHide(t, pinPath)
	pin, err := pinnedCompiler(c)
	if err == nil {
		t.Fatalf("EACCES folded into %v", pin)
	}
	if !strings.Contains(err.Error(), pinPath) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the refusal must name the path %s and the errno: %v", pinPath, err)
	}
	// The seam default's preflight reports it as a FAIL naming the refusal.
	profile := "docker-networkless"
	withDaemon(t, false)
	pre, perr := SandboxPreflight(c, nil, &profile)
	if perr != nil {
		t.Fatal(perr)
	}
	solc := objAt(objAt(pre, "checks"), "solc")
	if strAt(solc, "status") != "fail" ||
		!strings.Contains(strAt(solc, "detail"), pinPath) {
		t.Errorf("preflight solc row = %s", validation.CanonCompact(solc))
	}
	_ = os.Chmod(pinPath, 0o644)

	// A genuinely absent manifest is a fact, not a refusal.
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	if pin, err := pinnedCompiler(c); err != nil || pin != nil {
		t.Errorf("removed manifest: (%v, %v), want (nil, nil)", pin, err)
	}

	// ENOTDIR: the manifest's parent is a regular file.
	c2 := newCampaign(t, "r45b-sb-enotdir")
	target2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(target2, "V.sol"),
		[]byte("contract V { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c2, target2, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid2, err := c2.ActiveSnapshotIDOrNone()
	if err != nil || sid2 == nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c2.Dir, "snapshots", *sid2)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pinnedCompiler(c2); err == nil ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Errorf("ENOTDIR: want a refusal naming the errno, got %v", err)
	}
}
