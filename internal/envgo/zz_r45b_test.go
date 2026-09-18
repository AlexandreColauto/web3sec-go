package envgo

// r45b pins for the compiler-pin rail.
//
// THE MISSING RAIL: the pinnedCompiler transcription exists twice — this
// package's preflight.go (WIRED over the sandbox seam by cmd/webv2/main.go)
// and sandbox/envseam.go (the seam DEFAULT) — and only the ClassifyFailure
// differential (zz_r38a_test.go) existed; nothing pinned the two compiler-pin
// readers together. They had already drifted: this copy folded a
// falsy-but-present pin (0, false, "", 0.0) through truthy(), the sandbox copy
// folded only JSON null, and its scalarText dropped floats. The differential
// below compares the "solc" check row the two preflights produce for the same
// campaign, which is where both differences become visible (a falsy pin read
// "na" through one transcription and a FAIL "not a solc version" through the
// other).
//
// The reference behaviour for a falsy-but-present pin is Python's
// `if compiler:` — the r44 comment on both copies already said so — so the
// reconciled semantics is validation.PyTruthy, the canonical predicate: a
// falsy pin IS no pin, and str() renders a truthy scalar.
//
// Site 3 is pinned here too: solc_probe and campaign_requirements are the
// third and fourth readers of the same manifest, and both now refuse on a pin
// they could not read instead of answering "no solc required" / "no chain pin".

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// r45bCfg wraps a config.compiler pin into the *config argument of
// PinSourceSnapshot (a non-empty object is written into snapshot.json
// verbatim, so the manifest carries EXACTLY the shape under test).
func r45bCfg(v validation.Value) *validation.Value {
	c := validation.VObj(validation.KV{K: "compiler", V: v})
	return &c
}

func r45bSep() *validation.Value {
	c := validation.VObj(validation.KV{K: "build_system",
		V: validation.VStr("foundry")})
	return &c
}

// r45bPinCampaign pins one source snapshot (config null — the target has no
// foundry.toml), then writes the config shape under test straight into the
// manifest. The writer validates `config.compiler` as string-or-null, so the
// falsy-but-present NON-string shapes are foreign/hand-edited manifests —
// unreachable through a sanctioned verb, which is exactly why the two
// transcriptions must not answer them differently. cfg == nil keeps the
// detected manifest (config null).
func r45bPinCampaign(t *testing.T, name string, cfg *validation.Value) (
	*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "V.sol"), "contract V { }")
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	pinPath := filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")
	if cfg != nil {
		manifest, rerr := validation.ReadJson(pinPath)
		if rerr != nil {
			t.Fatal(rerr)
		}
		manifest = setKey(manifest, "config", *cfg)
		if werr := validation.WriteJson(pinPath, manifest, ""); werr != nil {
			t.Fatal(werr)
		}
	}
	return c, pinPath
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

// r45bNoDocker pins both docker-daemon probes down and restores the sandbox
// preflight seam to its transcription, so the differential compares the two
// READERS and nothing else.
func r45bNoDocker(t *testing.T) {
	t.Helper()
	SetDockerDaemonOK(func() bool { return false })
	sandbox.SetDockerDaemonOK(func() bool { return false })
	sandbox.SetSandboxPreflight(nil)
	SetSolcDir(nil)
	t.Setenv("WEBV2_SOLC_DIR", "")
	t.Cleanup(func() {
		SetDockerDaemonOK(nil)
		sandbox.SetDockerDaemonOK(nil)
		sandbox.SetSandboxPreflight(nil)
		SetSolcDir(nil)
	})
}

func r45bSolcRow(t *testing.T, pre validation.Value) validation.Value {
	t.Helper()
	return validation.ObjAt(validation.ObjAt(pre, "checks"), "solc")
}

// TestR45bPinnedCompilerCopyMatchesSandboxDefault is THE differential: for
// every pin shape, the wired envgo preflight and the sandbox transcription
// must produce the byte-identical "solc" check row — and that row must be the
// reference behaviour (a falsy-but-present pin is no pin).
func TestR45bPinnedCompilerCopyMatchesSandboxDefault(t *testing.T) {
	r45bNoDocker(t)
	profile := "docker-networkless"
	cases := []struct {
		name       string
		cfg        *validation.Value
		wantStatus string
		wantDetail string
	}{
		{"no-config-at-all", nil, "na",
			"no compiler pinned by the active snapshot"},
		{"no-compiler-key", r45bSep(), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-null", r45bCfg(validation.VNull()), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-empty-string", r45bCfg(validation.VStr("")), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-false", r45bCfg(validation.VBool(false)), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-zero-int", r45bCfg(validation.VInt(0)), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-zero-float", r45bCfg(validation.VFloat(0)), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-empty-array", r45bCfg(validation.VArr()), "na",
			"no compiler pinned by the active snapshot"},
		{"compiler-float-version", r45bCfg(validation.VFloat(1.5)), "warn",
			"solc 1.5 pinned by foundry.toml"},
		{"compiler-true", r45bCfg(validation.VBool(true)), "fail",
			"which is not a solc version"},
		{"compiler-version", r45bCfg(validation.VStr("0.8.24")), "warn",
			"solc 0.8.24 pinned by foundry.toml"},
		{"compiler-version-with-args", r45bCfg(validation.VStr("0.8.24, --optimize")),
			"warn", "solc 0.8.24 pinned by foundry.toml"},
		{"compiler-version-padded", r45bCfg(validation.VStr(" 0.8.24 ")), "warn",
			"solc 0.8.24 pinned by foundry.toml"},
		// Shared, deliberate deviation: neither copy renders str() of a
		// list/object pin, so both answer "no compiler" where the reference
		// would str() it into a rejected version. Pinned so the two copies
		// cannot drift apart here either.
		{"compiler-list", r45bCfg(validation.VArr(validation.VStr("0.8.19"),
			validation.VStr("0.8.24"))), "na",
			"no compiler pinned by the active snapshot"},
	}
	for _, tc := range cases {
		c, _ := r45bPinCampaign(t, "r45b-"+tc.name, tc.cfg)
		wired, err := SandboxPreflight(c, nil, &profile)
		if err != nil {
			t.Fatalf("%s: envgo preflight: %v", tc.name, err)
		}
		def, err := sandbox.SandboxPreflight(c, nil, &profile)
		if err != nil {
			t.Fatalf("%s: sandbox preflight: %v", tc.name, err)
		}
		wiredRow, defRow := r45bSolcRow(t, wired), r45bSolcRow(t, def)
		if validation.CanonCompact(wiredRow) != validation.CanonCompact(defRow) {
			t.Errorf("%s: the two pinnedCompiler transcriptions disagree\n"+
				"  envgo:   %s\n  sandbox: %s", tc.name,
				validation.CanonCompact(wiredRow),
				validation.CanonCompact(defRow))
		}
		if got := validation.ObjStr(wiredRow, "status"); got != tc.wantStatus {
			t.Errorf("%s: solc status = %q, want %q (row %s)", tc.name, got,
				tc.wantStatus, validation.CanonCompact(wiredRow))
		}
		if got := validation.ObjStr(wiredRow, "detail"); !strings.Contains(got,
			tc.wantDetail) {
			t.Errorf("%s: detail %q lacks %q", tc.name, got, tc.wantDetail)
		}
	}
}

// TestR45bUnreadablePinRefusalMatchesSandbox pins the refusal half of the two
// transcriptions together: chmod 000 (EACCES) and a pin path whose parent is a
// regular file (ENOTDIR) must both be refusals naming the path, identically
// through envgo's preflight and the sandbox default.
func TestR45bUnreadablePinRefusalMatchesSandbox(t *testing.T) {
	r45bNoDocker(t)
	profile := "docker-networkless"

	c, pin := r45bPinCampaign(t, "r45b-eacces",
		r45bCfg(validation.VStr("0.8.24")))
	r45bHide(t, pin)
	wired, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	def, err := sandbox.SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	wiredRow, defRow := r45bSolcRow(t, wired), r45bSolcRow(t, def)
	if validation.CanonCompact(wiredRow) != validation.CanonCompact(defRow) {
		t.Errorf("EACCES: transcriptions disagree\n  envgo:   %s\n  sandbox: %s",
			validation.CanonCompact(wiredRow),
			validation.CanonCompact(defRow))
	}
	if got := validation.ObjStr(wiredRow, "status"); got != "fail" {
		t.Errorf("EACCES: solc status = %q, want fail", got)
	}
	detail := validation.ObjStr(wiredRow, "detail")
	if !strings.Contains(detail, pin) ||
		!strings.Contains(detail, "permission denied") {
		t.Errorf("EACCES: the refusal must name the path %s and the errno: %q",
			pin, detail)
	}

	// ENOTDIR: the manifest's parent is a regular file.
	c2, pin2 := r45bPinCampaign(t, "r45b-enotdir",
		r45bCfg(validation.VStr("0.8.24")))
	dir := filepath.Dir(pin2)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wired2, err := SandboxPreflight(c2, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	def2, err := sandbox.SandboxPreflight(c2, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	wiredRow2, defRow2 := r45bSolcRow(t, wired2), r45bSolcRow(t, def2)
	if validation.CanonCompact(wiredRow2) != validation.CanonCompact(defRow2) {
		t.Errorf("ENOTDIR: transcriptions disagree\n  envgo:   %s\n  sandbox: %s",
			validation.CanonCompact(wiredRow2),
			validation.CanonCompact(defRow2))
	}
	detail2 := validation.ObjStr(wiredRow2, "detail")
	if validation.ObjStr(wiredRow2, "status") != "fail" ||
		!strings.Contains(detail2, pin2) ||
		!strings.Contains(detail2, "not a directory") {
		t.Errorf("ENOTDIR: want a refusal naming %s, got %q", pin2, detail2)
	}
}

// TestR45bSolcProbeReadsThePinHonestly is site 3: solc_probe used pathExists
// (any stat error -> false) and folded a ReadJson error into (nil, nil) =
// "no solc required". ENOENT stays benign; EACCES/ENOTDIR/EISDIR are refusals.
func TestR45bSolcProbeReadsThePinHonestly(t *testing.T) {
	r45bNoDocker(t)

	// No active snapshot: a fact, not a refusal.
	c, err := state.Init(t.TempDir(), "r45b-probe-nosnap", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := SolcProbe(c, validation.VObj())
	if err != nil || out != nil {
		t.Fatalf("no snapshot: (out=%v, err=%v), want (nil, nil)", out, err)
	}

	// A pin with no compiler pinned: (nil, nil) — the benign shape.
	c2, _ := r45bPinCampaign(t, "r45b-probe-nocompiler", r45bCfg(validation.VNull()))
	out, err = SolcProbe(c2, validation.VObj())
	if err != nil || out != nil {
		t.Fatalf("pin without a compiler: (out=%v, err=%v), want (nil, nil)",
			out, err)
	}

	// A normal pin: the probe really reads it (daemon up, image absent).
	c3, _ := r45bPinCampaign(t, "r45b-probe-normal",
		r45bCfg(validation.VStr("0.8.24, --optimize")))
	probe := validation.VObj(
		validation.KV{K: "image", V: validation.VStr("img")},
		validation.KV{K: "daemon", V: validation.VBool(true)},
		validation.KV{K: "present", V: validation.VBool(false)})
	out, err = SolcProbe(c3, probe)
	if err != nil || out == nil {
		t.Fatalf("normal pin: (out=%v, err=%v), want a probe result", out, err)
	}
	if got := validation.ObjStr(*out, "required"); got != "0.8.24" {
		t.Errorf("required = %q, want 0.8.24 (split + strip)", got)
	}
	if got := validation.ObjStr(*out, "problem"); !strings.Contains(got, "not local") {
		t.Errorf("problem = %q, want the image-not-local refusal", got)
	}

	// EACCES: a refusal naming the path and the errno, not (nil, nil).
	c4, pin4 := r45bPinCampaign(t, "r45b-probe-eacces",
		r45bCfg(validation.VStr("0.8.24")))
	r45bHide(t, pin4)
	out, err = SolcProbe(c4, validation.VObj())
	if err == nil {
		t.Fatalf("EACCES folded into 'no solc required': out=%v", out)
	}
	if !strings.Contains(err.Error(), pin4) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the refusal must name the path %s and the errno: %v", pin4, err)
	}

	// ENOTDIR: the same class, a different errno.
	c5, pin5 := r45bPinCampaign(t, "r45b-probe-enotdir",
		r45bCfg(validation.VStr("0.8.24")))
	c5dir := filepath.Dir(pin5)
	if err := os.RemoveAll(c5dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c5dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SolcProbe(c5, validation.VObj()); err == nil ||
		!strings.Contains(err.Error(), pin5) ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Errorf("ENOTDIR: want a refusal naming %s, got %v", pin5, err)
	}

	// A genuinely absent manifest (the file removed) stays benign.
	c6, pin6 := r45bPinCampaign(t, "r45b-probe-removed",
		r45bCfg(validation.VStr("0.8.24")))
	if err := os.Remove(pin6); err != nil {
		t.Fatal(err)
	}
	out, err = SolcProbe(c6, validation.VObj())
	if err != nil || out != nil {
		t.Fatalf("removed manifest is a fact: (out=%v, err=%v)", out, err)
	}
}

// TestR45bCampaignRequirementsReadsThePinHonestly is the fourth reader: the
// chain-pin read was gated behind the local pathExists helper, so EACCES
// rendered the benign "no chain pin on the active snapshot" advisory.
func TestR45bCampaignRequirementsReadsThePinHonestly(t *testing.T) {
	r45bNoDocker(t)

	// No active snapshot: a fact.
	c, err := state.Init(t.TempDir(), "r45b-req-nosnap", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CampaignRequirements(c); err != nil {
		t.Fatalf("no snapshot is a fact, not a refusal: %v", err)
	}

	// A readable pin: the advisory path is unchanged.
	c2, _ := r45bPinCampaign(t, "r45b-req-readable", nil)
	if _, err := CampaignRequirements(c2); err != nil {
		t.Fatalf("readable pin must not refuse: %v", err)
	}

	// EACCES: a refusal naming the path and the errno.
	c3, pin3 := r45bPinCampaign(t, "r45b-req-eacces", nil)
	r45bHide(t, pin3)
	_, err = CampaignRequirements(c3)
	if err == nil {
		t.Fatal("EACCES rendered as the benign 'no chain pin' advisory")
	}
	if !strings.Contains(err.Error(), pin3) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the refusal must name the path %s and the errno: %v", pin3, err)
	}

	// EISDIR: the manifest path exists but is a directory.
	c4, pin4 := r45bPinCampaign(t, "r45b-req-eisdir", nil)
	if err := os.Remove(pin4); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pin4, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CampaignRequirements(c4); err == nil ||
		!strings.Contains(err.Error(), pin4) ||
		!strings.Contains(err.Error(), "directory") {
		t.Errorf("EISDIR: want a refusal naming %s, got %v", pin4, err)
	}

	// A genuinely absent manifest stays benign.
	c5, pin5 := r45bPinCampaign(t, "r45b-req-removed", nil)
	if err := os.Remove(pin5); err != nil {
		t.Fatal(err)
	}
	if _, err := CampaignRequirements(c5); err != nil {
		t.Fatalf("removed manifest is a fact: %v", err)
	}
}
