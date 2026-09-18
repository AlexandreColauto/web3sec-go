package sandbox

// P2 env-seam tests: classify_failure and sandbox_preflight (webv2.env).
//
// env.py is not owned by this wave; internal/sandbox carries a faithful
// transcription as the seam default so cmd_exec / cmd_classify are
// byte-exact against the live Python. The expected values below were
// captured from the reference by .scratch/t20/capture_cli.py.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// strScalar renders a scalar Value the way the CLI prints it.
func strScalar(v validation.Value) string {
	if v.Kind != validation.Str {
		return ""
	}
	return v.S
}

func classify(t *testing.T, cmd, stdout string, exit int) validation.Value {
	t.Helper()
	c := newCampaign(t, "envseam")
	rec, err := RegisterExec(c, RegisterOpts{Profile: "docker-networkless",
		Command: cmd, ReportedBy: "harness", ExitStatus: exit,
		StdoutText: stdout})
	if err != nil {
		t.Fatal(err)
	}
	return ClassifyFailure(rec)
}

// capture is the live-Python value of ENV.classify_failure for each case.
func TestClassifyFailureVerdicts(t *testing.T) {
	cases := []struct {
		name, cmd, out string
		exit           int
		class, signal  string
	}{
		{"docker-down", "forge test",
			"Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n",
			1, "environment", "docker/daemon/network error pattern in output"},
		{"solc", "forge test",
			"Failed to install solc 0.8.36: error sending request for url " +
				"(https://binaries.soliditylang.org/linux-amd64/list.json)\n",
			1, "environment", "solc download failure pattern (offline container)"},
		// Task 9 (production-readiness plan §Task 9): a MISSING toolchain
		// binary is ENVIRONMENT per RUNBOOK §0/§6a — and a missing Solidity
		// LIBRARY stays SETUP (repository setup, not the box).
		{"missing-solc", "forge test",
			"Error: solc 0.8.24 is not installed. Install it with " +
				"`svm install 0.8.24`\n",
			1, "environment", "toolchain binary absent (not found / not installed)"},
		{"missing-forge", "forge test", "sh: 1: forge: not found\n",
			1, "environment", "toolchain binary absent (not found / not installed)"},
		{"missing-docker", "forge test", "docker: command not found\n",
			1, "environment", "toolchain binary absent (not found / not installed)"},
		{"missing-library-stays-setup", "forge test",
			"Error: Source \"forge-std/Test.sol\" not found: File not found.\n",
			1, "setup", "compilation/setup error pattern"},
		{"setup", "forge test", "Error: compilation failed\n",
			1, "setup", "compilation/setup error pattern"},
		{"logic", "forge test", "assertion failed: x != y\n",
			1, "logic", "assertion/logic failure pattern in output"},
		{"unknown", "forge test", "something odd happened\n", 1, "unknown", ""},
		{"none", "forge test", "ok\n", 0, "none", ""},
		{"exit125", "forge test", "x\n", 125, "environment",
			"docker-level exit code 125"},
	}
	for _, tc := range cases {
		got := classify(t, tc.cmd, tc.out, tc.exit)
		if strAt(got, "class") != tc.class {
			t.Errorf("%s: class = %q, want %q (signals %s)", tc.name,
				strAt(got, "class"), tc.class,
				validation.CanonCompact(objAt(got, "signals")))
		}
		if tc.signal != "" &&
			!containsStrValue(objAt(got, "signals"), tc.signal) {
			t.Errorf("%s: signals = %s, want %s", tc.name,
				validation.CanonCompact(objAt(got, "signals")), tc.signal)
		}
		if strAt(got, "note") == "" {
			t.Errorf("%s: empty note", tc.name)
		}
	}
}

// TestClassifyFailureNotes pins the four note sentences byte-for-byte.
func TestClassifyFailureNotes(t *testing.T) {
	env := classify(t, "forge test", "connection refused\n", 1)
	if strAt(env, "note") != "fix the environment; do NOT spend a "+
		"fresh-context retry on this" {
		t.Errorf("environment note = %q", strAt(env, "note"))
	}
	setup := classify(t, "forge test", "compilation failed\n", 1)
	if strAt(setup, "note") != "retry in a fresh context with this failure record" {
		t.Errorf("setup note = %q", strAt(setup, "note"))
	}
	logic := classify(t, "forge test", "panic: oh no\n", 1)
	if strAt(logic, "note") != "the harness ran and the hypothesis lost a "+
		"round — this is the only class that argues the finding" {
		t.Errorf("logic note = %q", strAt(logic, "note"))
	}
	unknown := classify(t, "forge test", "hmm\n", 1)
	if strAt(unknown, "note") != "unclassified; routed as setup (the cheap error)" {
		t.Errorf("unknown note = %q", strAt(unknown, "note"))
	}
	none := classify(t, "forge test", "ok\n", 0)
	if strAt(none, "note") != "exec succeeded; nothing to classify" {
		t.Errorf("none note = %q", strAt(none, "note"))
	}
	// exit 126/127 are docker-level too
	for _, code := range []int{126, 127} {
		got := classify(t, "forge test", "x\n", code)
		if strAt(got, "class") != "environment" {
			t.Errorf("exit %d: class = %q", code, strAt(got, "class"))
		}
	}
	// Task 9: an absent toolchain binary is environment AND its note names
	// the fix (never the bare "fix the environment" shrug).
	absent := classify(t, "forge test",
		"Error: solc 0.8.24 is not installed\n", 1)
	if strAt(absent, "class") != "environment" ||
		!strings.Contains(strAt(absent, "note"), "WEBV2_SOLC_DIR") {
		t.Errorf("absent solc = %s", validation.CanonCompact(absent))
	}
}

// TestSandboxPreflightHostReadonly pins the host-readonly check set: every
// container check is "na", and a workdir becomes an "ok" bind check.
func TestSandboxPreflightHostReadonly(t *testing.T) {
	c := newCampaign(t, "preflight")
	profile := "host-readonly"
	pre, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if !boolAt(pre, "ok") {
		t.Errorf("ok = false: %s", validation.CanonCompact(pre))
	}
	checks := objAt(pre, "checks")
	if strAt(objAt(checks, "docker"), "status") != "na" ||
		strAt(objAt(checks, "image"), "status") != "na" ||
		strAt(objAt(checks, "solc"), "status") != "na" {
		t.Errorf("checks = %s", validation.CanonCompact(checks))
	}
	if objStr(objAt(checks, "docker"), "detail") !=
		"host-readonly executes on the host — no container involved" {
		t.Errorf("docker detail = %q",
			objStr(objAt(checks, "docker"), "detail"))
	}
	if len(objAt(pre, "issues").A) != 0 || len(objAt(pre, "warnings").A) != 0 {
		t.Errorf("preflight issues/warnings = %s",
			validation.CanonCompact(pre))
	}
	dir := filepath.Dir(c.Dir)
	pre2, err := SandboxPreflight(c, &dir, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if strAt(objAt(objAt(pre2, "checks"), "workdir"), "status") != "ok" {
		t.Errorf("workdir check = %s",
			validation.CanonCompact(objAt(objAt(pre2, "checks"), "workdir")))
	}
}

// TestSandboxPreflightMissingWorkdir pins the FAIL issue text cmd_exec
// prints (captured from the live Python CLI).
func TestSandboxPreflightMissingWorkdir(t *testing.T) {
	c := newCampaign(t, "preflight")
	profile := "host-readonly"
	missing := filepath.Join(t.TempDir(), "nope")
	pre, err := SandboxPreflight(c, &missing, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if boolAt(pre, "ok") {
		t.Error("ok = true, want false")
	}
	want := "workdir: workdir " + missing + " does not exist — a missing " +
		"bind source fails the whole run — fix: create " + missing +
		" or point --workdir at an existing directory"
	issues := objAt(pre, "issues")
	if len(issues.A) != 1 || issues.A[0].S != want {
		t.Fatalf("issues = %s\nwant %q", validation.CanonCompact(issues), want)
	}
	if objStr(objAt(objAt(pre, "checks"), "workdir"), "fix") !=
		"create "+missing+" or point --workdir at an existing directory" {
		t.Errorf("fix = %q",
			objStr(objAt(objAt(pre, "checks"), "workdir"), "fix"))
	}
}

// TestSandboxPreflightSeam pins the installer contract: SetSandboxPreflight
// swaps the implementation, nil restores the default.
func TestSandboxPreflightSeam(t *testing.T) {
	profile := "host-readonly"
	SetSandboxPreflight(func(*state.Campaign, *string, *string) (validation.Value, error) {
		return validation.VObj(validation.KV{K: "stub", V: validation.VBool(true)}), nil
	})
	t.Cleanup(func() { SetSandboxPreflight(nil) })
	got, err := SandboxPreflight(nil, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if !boolAt(got, "stub") {
		t.Errorf("seam stub not installed: %s", validation.CanonCompact(got))
	}
	SetSandboxPreflight(nil)
	SetClassifyFailure(func(validation.Value) validation.Value {
		return validation.VObj(validation.KV{K: "class", V: validation.VStr("stub")})
	})
	t.Cleanup(func() { SetClassifyFailure(nil) })
	if strAt(ClassifyFailure(validation.VObj()), "class") != "stub" {
		t.Error("classify seam stub not installed")
	}
}

// TestPreflightValueShape guards the JSON round-trip of the checks map (the
// CLI reads it back through objAt).
func TestPreflightValueShape(t *testing.T) {
	c := newCampaign(t, "preflight")
	profile := "host-readonly"
	pre, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	raw := validation.CanonCompact(pre)
	if !strings.Contains(raw, `"profile":"host-readonly"`) ||
		!strings.Contains(raw, `"issues":[]`) {
		t.Fatalf("compact = %s", raw)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(raw), &back); err != nil {
		t.Fatal(err)
	}
	if back["ok"] != true {
		t.Errorf("ok = %v", back["ok"])
	}
}

// TestSandboxPreflightContainer pins the container branch: a down daemon is a
// FAIL that names the fix, and the image/solc checks follow the daemon.
func TestSandboxPreflightContainer(t *testing.T) {
	c := newCampaign(t, "preflight")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "foundry.toml"), []byte(
		"[profile.default]\nsol = \"0.8.24\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	profile := "docker-networkless"
	withDaemon(t, false)
	pre, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	checks := objAt(pre, "checks")
	if strAt(objAt(checks, "docker"), "status") != "fail" {
		t.Errorf("docker = %s", validation.CanonCompact(objAt(checks, "docker")))
	}
	if strAt(objAt(checks, "image"), "status") != "na" {
		t.Errorf("image = %s", validation.CanonCompact(objAt(checks, "image")))
	}
	if boolAt(pre, "ok") {
		t.Error("ok = true with a down daemon")
	}
	want := "docker: docker daemon not answering — fix: start the docker " +
		"daemon (container profiles are the only honest execution path — " +
		"evidence produced un-sandboxed cannot be minted at E4+)"
	if got := strScalar(objAt(pre, "issues").A[0]); got != want {
		t.Errorf("issue = %q\nwant %q", got, want)
	}
	// A pinned compiler with WEBV2_SOLC_DIR unset is a WARN (the image may
	// ship it), naming the exact env var.
	found := false
	for _, w := range objAt(pre, "warnings").A {
		if strings.Contains(strScalar(w), "solc 0.8.24 pinned by "+
			"foundry.toml but WEBV2_SOLC_DIR is unset") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %s", validation.CanonCompact(objAt(pre, "warnings")))
	}
}

// TestSandboxPreflightSolcCache pins the three solc outcomes once the svm
// cache is pointed at a host dir.
func TestSandboxPreflightSolcCache(t *testing.T) {
	c := newCampaign(t, "preflight")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "foundry.toml"), []byte(
		"[profile.default]\nsol = \"0.8.24\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	withDaemon(t, true)
	svm := t.TempDir()
	t.Setenv("WEBV2_SOLC_DIR", svm)
	profile := "docker-networkless"

	pre, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	solc := objAt(objAt(pre, "checks"), "solc")
	if strAt(solc, "status") != "fail" ||
		!strings.Contains(strAt(solc, "detail"), "missing from the svm cache") {
		t.Errorf("solc (missing) = %s", validation.CanonCompact(solc))
	}
	img := objAt(objAt(pre, "checks"), "image")
	if st := strAt(img, "status"); st != "ok" && st != "warn" {
		t.Errorf("image = %s", validation.CanonCompact(img))
	}

	binDir := filepath.Join(svm, "0.8.24")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "solc-0.8.24"),
		[]byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pre2, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	solc2 := objAt(objAt(pre2, "checks"), "solc")
	if strAt(solc2, "status") != "ok" ||
		!strings.Contains(strAt(solc2, "detail"), "present in the svm cache") {
		t.Errorf("solc (present) = %s", validation.CanonCompact(solc2))
	}

	// fork-runner only WARNs about a missing binary (the bridge may reach
	// the registry).
	if err := os.RemoveAll(binDir); err != nil {
		t.Fatal(err)
	}
	fork := "fork-runner"
	pre3, err := SandboxPreflight(c, nil, &fork)
	if err != nil {
		t.Fatal(err)
	}
	solc3 := objAt(objAt(pre3, "checks"), "solc")
	if strAt(solc3, "status") != "warn" ||
		!strings.Contains(strAt(solc3, "detail"), "fork-runner bridge may "+
			"still reach the registry") {
		t.Errorf("solc (fork-runner) = %s", validation.CanonCompact(solc3))
	}
}

// TestDockerImageProbeShape pins the probe's value shape and the pinned-tag
// flag (the daemon-dependent fields are asserted loosely).
func TestDockerImageProbeShape(t *testing.T) {
	t.Setenv("WEBV2_DOCKER_IMAGE", "ghcr.io/foundry-rs/foundry:latest")
	probe := DockerImageProbe(nil)
	if strAt(probe, "image") != "ghcr.io/foundry-rs/foundry:latest" {
		t.Errorf("image = %q", strAt(probe, "image"))
	}
	if boolAt(probe, "pinned") {
		t.Error("a tag reference must not read as digest-pinned")
	}
	digest := "ghcr.io/foundry-rs/foundry@sha256:" + strings.Repeat("a", 64)
	probe2 := DockerImageProbe(&digest)
	if !boolAt(probe2, "pinned") {
		t.Errorf("digest reference must read as pinned: %s",
			validation.CanonCompact(probe2))
	}
}
