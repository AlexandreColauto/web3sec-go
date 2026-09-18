// envgo_test.go ports tests/test_env_solc.py and tests/test_doctor_preflight.py
// 1:1 (Python wins). Every test asserts at least two facts, like the source.
package envgo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// downloadErr is the run-3 solc download failure the classifier must route
// to the environment class.
const downloadErr = "error: failed to download solc 0.8.24\n" +
	"  --> error sending request for url " +
	"(https://binaries.soliditylang.org/linux-amd64/list.json): " +
	"dns error: failed to lookup address information: " +
	"Temporary failure in name resolution"

// campaignWithPin is _campaign_with_pin: a pin whose foundry.toml pins solc
// 0.8.24 (the active snapshot's config.compiler).
func campaignWithPin(t *testing.T, name string) (*state.Campaign, validation.Value) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "C.sol"), "// c")
	writeFile(t, filepath.Join(target, "foundry.toml"),
		"[profile.default]\nsol = \"0.8.24\"\n")
	snap, err := snapshot.PinSourceSnapshot(c, target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, snap
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// stubImage is the ENV.docker_image_probe monkeypatch of the Python tests.
func stubImage(daemon, present, pinned bool) func(*string) validation.Value {
	return func(*string) validation.Value {
		var digest validation.Value = validation.VNull()
		if present {
			digest = validation.VStr("sha256:abcd0123")
		}
		return validation.VObj(
			validation.KV{K: "image", V: validation.VStr("ghcr.io/test/img")},
			validation.KV{K: "daemon", V: validation.VBool(daemon)},
			validation.KV{K: "present", V: validation.VBool(present)},
			validation.KV{K: "digest", V: digest},
			validation.KV{K: "pinned", V: validation.VBool(pinned)},
			validation.KV{K: "detail", V: validation.VStr("stub")},
		)
	}
}

// up is _up: a healthy docker environment (daemon answers, image local).
func up(t *testing.T, imagePresent bool) {
	t.Helper()
	prevDaemon, prevProbe := dockerDaemonOK, dockerProbe
	dockerDaemonOK = func() bool { return true }
	dockerProbe = stubImage(true, imagePresent, true)
	t.Cleanup(func() { dockerDaemonOK, dockerProbe = prevDaemon, prevProbe })
}

// stubRun installs a subprocess.run stub returning one canned result.
func stubRun(t *testing.T, res procResult) {
	t.Helper()
	prev := runProc
	runProc = func([]string, time.Duration) (procResult, error) { return res, nil }
	t.Cleanup(func() { runProc = prev })
}

func stubSolcDir(t *testing.T, dir *string) {
	t.Helper()
	prev := solcDir
	solcDir = func() *string { return dir }
	t.Cleanup(func() { solcDir = prev })
}

func boolField(v validation.Value, key string) bool  { return boolAt(v, key) }
func strField(v validation.Value, key string) string { return validation.ObjStr(v, key) }

// --- tests/test_env_solc.py -------------------------------------------------

func TestDownloadFailureClassifiesEnvironmentWithFix(t *testing.T) {
	c, err := state.Init(t.TempDir(), "solcc", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge build",
		ReportedBy: "pytest", ExitStatus: 1,
		StdoutText: "", StderrText: downloadErr})
	if err != nil {
		t.Fatal(err)
	}
	res := ClassifyFailure(rec)
	if got := validation.ObjStr(res, "class"); got != "environment" {
		t.Fatalf("class = %q, want environment", got)
	}
	note := validation.ObjStr(res, "note")
	if !strings.Contains(note, "WEBV2_SOLC_DIR") {
		t.Errorf("note missing WEBV2_SOLC_DIR: %q", note)
	}
	if !strings.Contains(note, "fresh-context") {
		t.Errorf("note missing fresh-context: %q", note)
	}
}

func TestPlainLogicFailureStaysLogic(t *testing.T) {
	c, err := state.Init(t.TempDir(), "solcd", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test",
		ReportedBy: "pytest", ExitStatus: 1,
		StdoutText: "Failing: 1 tests, passed 0\n", StderrText: "test failed"})
	if err != nil {
		t.Fatal(err)
	}
	res := ClassifyFailure(rec)
	if cls := validation.ObjStr(res, "class"); cls != "logic" {
		t.Fatalf("class = %q, want logic (test failed is a logic signal)", cls)
	}
	note := validation.ObjStr(res, "note")
	if !strings.Contains(note, "only class that argues the finding") {
		t.Errorf("logic note = %q", note)
	}
	if strings.Contains(note, "WEBV2_SOLC_DIR") {
		t.Errorf("logic note carries the solc fix: %q", note)
	}
}

// stubDaemon pins the docker_daemon_ok probe so the profile loop never
// shells out to a real docker (Python monkeypatches ENV.docker_daemon_ok).
func stubDaemon(t *testing.T, ok bool) {
	t.Helper()
	prev := dockerDaemonOK
	dockerDaemonOK = func() bool { return ok }
	t.Cleanup(func() { dockerDaemonOK = prev })
}

func TestDoctorProbeReportsAbsentCompiler(t *testing.T) {
	c, _ := campaignWithPin(t, "solce")
	prev := dockerProbe
	dockerProbe = stubImage(true, true, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, true)
	stubRun(t, procResult{ReturnCode: 2, Stderr: "ls: cannot access " +
		"'/home/foundry/.svm/0.8.24': No such file"})

	report, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	solc := validation.ObjAt(report, "solc")
	if solc.Kind != validation.Obj {
		t.Fatalf("solc = %s", validation.DumpIndented(solc))
	}
	if got := validation.ObjStr(solc, "required"); got != "0.8.24" {
		t.Errorf("required = %q", got)
	}
	if boolField(solc, "present") {
		t.Errorf("present = true, want false")
	}
	found := false
	for _, i := range validation.ObjAt(report, "issues").A {
		if strings.Contains(i.S, "solc 0.8.24 missing") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack the missing-solc problem: %s",
			validation.DumpIndented(validation.ObjAt(report, "issues")))
	}
	if boolField(report, "ok") {
		t.Errorf("ok = true, want false")
	}
}

func TestDoctorProbeReportsPresentCompiler(t *testing.T) {
	c, _ := campaignWithPin(t, "solcf2")
	prev := dockerProbe
	dockerProbe = stubImage(true, true, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, true)
	stubRun(t, procResult{ReturnCode: 0, Stdout: "solc-0.8.24\n"})

	report, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	solc := validation.ObjAt(report, "solc")
	if !boolField(solc, "present") {
		t.Errorf("present = false, want true")
	}
	if p := validation.ObjAt(solc, "problem"); p.Kind != validation.Null {
		t.Errorf("problem = %s, want null", validation.DumpIndented(p))
	}
}

// campaignWithSol is campaignWithPin with a chosen foundry.toml `sol` value.
func campaignWithSol(t *testing.T, name, sol string) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "C.sol"), "// c")
	writeFile(t, filepath.Join(target, "foundry.toml"),
		"[profile.default]\nsol = \""+sol+"\"\n")
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDoctorRefusesNonVersionCompilerPin pins the 2026-09-10 fix: the compiler
// pin comes from the TARGET repo's foundry.toml, and it used to be pasted into
// `docker run … /bin/sh -c "ls /home/foundry/.svm/<pin>"` — a pin of
// `0.8.24; <anything>` ran in the probe container, whose exit 0 also forged
// "solc present". Nothing may be executed from an unvalidated pin.
func TestDoctorRefusesNonVersionCompilerPin(t *testing.T) {
	c := campaignWithSol(t, "solchinject", "0.8.24; touch /tmp/pwned")
	prev := dockerProbe
	dockerProbe = stubImage(true, true, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, true)
	ran := false
	prevRun := runProc
	runProc = func([]string, time.Duration) (procResult, error) {
		ran = true
		return procResult{ReturnCode: 0, Stdout: "solc-0.8.24\n"}, nil
	}
	t.Cleanup(func() { runProc = prevRun })

	report, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	solc := validation.ObjAt(report, "solc")
	if boolField(solc, "present") {
		t.Error("present = true for a pin that was never probed")
	}
	if boolField(solc, "checked") {
		t.Error("checked = true for a pin that was never probed")
	}
	problem := validation.ObjStr(solc, "problem")
	if !strings.Contains(problem, "not a solc version") {
		t.Errorf("problem = %q, want the not-a-version refusal", problem)
	}
	if ran {
		t.Error("the solc probe ran a container with an unvalidated pin")
	}
}

// TestSolcProbePassesVersionAsArgv: with a valid pin the version travels as an
// argv element, never as part of the shell source.
func TestSolcProbePassesVersionAsArgv(t *testing.T) {
	c, _ := campaignWithPin(t, "solcargv")
	prev := dockerProbe
	dockerProbe = stubImage(true, true, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, true)
	var argv []string
	prevRun := runProc
	runProc = func(a []string, _ time.Duration) (procResult, error) {
		argv = a
		return procResult{ReturnCode: 0, Stdout: "solc-0.8.24\n"}, nil
	}
	t.Cleanup(func() { runProc = prevRun })

	if _, err := Doctor(c); err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 {
		t.Fatal("the probe did not run")
	}
	if got := argv[len(argv)-1]; got != "0.8.24" {
		t.Errorf("last argv = %q, want the version as its own argument", got)
	}
	for i, a := range argv {
		if i > 0 && argv[i-1] == "-c" && strings.Contains(a, "0.8.24") {
			t.Errorf("the version is interpolated into the shell source: %q", a)
		}
	}
}

func TestDoctorProbeSkippedWithoutDaemon(t *testing.T) {
	c, _ := campaignWithPin(t, "solcg")
	prev := dockerProbe
	dockerProbe = stubImage(false, false, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, false)
	report, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	if s := validation.ObjAt(report, "solc"); s.Kind != validation.Null {
		t.Fatalf("solc = %s, want null (daemon issue already reported)",
			validation.DumpIndented(s))
	}
	if boolField(report, "ok") {
		t.Errorf("ok = true, want false without a daemon")
	}
}

func TestDoctorProbeNoneWithoutPinnedCompiler(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "solcf", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "C.sol"), "// c")
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	prev := dockerProbe
	dockerProbe = stubImage(true, true, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, true)
	report, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	if s := validation.ObjAt(report, "solc"); s.Kind != validation.Null {
		t.Fatalf("solc = %s, want null", validation.DumpIndented(s))
	}
}

// TestDoctorProfileFitMarksFloorGap pins feedback-triage A7: the doctor used
// to print "docker-networkless=ok" next to a campaign whose max CONFIRMED
// floor the profile cannot back. The report now carries a profile_fit
// section that pre-runs the same floor comparison and marks the gap.
// (The reference's class floors top out at E6, so against the default
// floor only fork-runner's direct E5 shape gets close; E6 always needs the
// independent-reproduction step on top.)
func TestDoctorProfileFitMarksFloorGap(t *testing.T) {
	c, _ := campaignWithPin(t, "fit7")
	prev := dockerProbe
	dockerProbe = stubImage(true, true, false)
	t.Cleanup(func() { dockerProbe = prev })
	stubDaemon(t, true)
	// ProfileAvailable probes the sandbox's own daemon seam
	sandbox.SetDockerDaemonOK(func() bool { return true })
	t.Cleanup(func() { sandbox.SetDockerDaemonOK(nil) })
	stubRun(t, procResult{ReturnCode: 0, Stdout: "solc-0.8.24\n"})

	report, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	fit := validation.ObjAt(report, "profile_fit")
	if fit.Kind != validation.Obj {
		t.Fatalf("profile_fit = %s, want an object",
			validation.DumpIndented(fit))
	}
	if got := validation.ObjStr(fit, "docker-networkless"); got !=
		"E4-only (campaign floor E6)" {
		t.Errorf("docker-networkless fit = %q", got)
	}
	if got := validation.ObjStr(fit, "fork-runner"); got !=
		"E5-only (campaign floor E6)" {
		t.Errorf("fork-runner fit = %q", got)
	}
	// host-readonly has no evidence ceiling and is never fit-marked
	if validation.ObjAt(fit, "host-readonly").Kind != validation.Null {
		t.Errorf("host-readonly must not appear in profile_fit: %s",
			validation.DumpIndented(fit))
	}
}

// TestEnvReportPinsMinicertoraHostProfile is the Task-5 close-out pin for the
// G8 third kind on the doctor surface the operator reads: the env report
// enumerates `minicertora` among the harness/host profiles, and the
// e4_capable filter EXCLUDES it — a host-side prover can never mint E4+
// reproduction evidence (HostProfile keys that filter, exactly as for halmos
// and forge-fuzz). The version row rides sandbox.toolVersions and is pinned
// next door in internal/sandbox (TestToolVersionsProbesMinicertora); this
// test pins the report's profile/e4_capable rows with a fake PATH shim in
// place, so neither row may be forged from the binary's presence.
func TestEnvReportPinsMinicertoraHostProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "minicertora"),
		[]byte("#!/bin/sh\necho 'minicertora 0.4.2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FORK_RPC_URL", "")
	// docker answers, so the container profiles ARE available and the
	// exclusion below is a real filter result, not an empty-list accident.
	sandbox.SetDockerDaemonOK(func() bool { return true })
	t.Cleanup(func() { sandbox.SetDockerDaemonOK(nil) })
	prev := dockerProbe
	dockerProbe = stubImage(true, true, true)
	t.Cleanup(func() { dockerProbe = prev })

	report, err := Doctor(nil)
	if err != nil {
		t.Fatal(err)
	}
	profiles := validation.ObjAt(report, "profiles")
	if !boolAt(profiles, "minicertora") {
		t.Errorf("profiles = %s, want minicertora enumerated",
			validation.DumpIndented(profiles))
	}
	if !boolAt(profiles, "halmos") {
		t.Errorf("profiles = %s, want halmos still enumerated",
			validation.DumpIndented(profiles))
	}
	e4 := validation.ObjAt(report, "e4_capable")
	for _, v := range e4.A {
		switch v.S {
		case "minicertora", "halmos", "forge-fuzz", "host-readonly":
			t.Errorf("e4_capable lists host profile %q: %s", v.S,
				validation.DumpIndented(e4))
		}
	}
	got := []string{}
	for _, v := range e4.A {
		got = append(got, v.S)
	}
	for _, want := range []string{"docker-networkless", "docker-gvisor",
		"fork-runner"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("e4_capable = %v, want %s included", got, want)
		}
	}
}

// --- tests/test_doctor_preflight.py ----------------------------------------

func TestPreflightOKWhenDaemonImageAndCachePresent(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight Program")
	up(t, true)
	svm := filepath.Join(t.TempDir(), "svm")
	if err := os.MkdirAll(filepath.Join(svm, "0.8.24"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(svm, "0.8.24", "solc-0.8.24"), "binary")
	stubSolcDir(t, &svm)

	pre, err := SandboxPreflight(c, nil, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
	if n := len(validation.ObjAt(pre, "issues").A); n != 0 {
		t.Errorf("issues = %d, want 0", n)
	}
	checks := validation.ObjAt(pre, "checks")
	for _, name := range []string{"docker", "image", "solc", "workdir"} {
		st := validation.ObjStr(validation.ObjAt(checks, name), "status")
		if st != "ok" && st != "na" {
			t.Errorf("%s status = %q: %s", name, st,
				validation.DumpIndented(validation.ObjAt(checks, name)))
		}
	}
	if got := validation.ObjStr(validation.ObjAt(checks, "solc"), "status"); got != "ok" {
		t.Errorf("solc status = %q, want ok", got)
	}
}

func TestPreflightMissingDaemonFailsWithFix(t *testing.T) {
	prevDaemon, prevProbe := dockerDaemonOK, dockerProbe
	dockerDaemonOK = func() bool { return false }
	dockerProbe = stubImage(false, false, false)
	t.Cleanup(func() { dockerDaemonOK, dockerProbe = prevDaemon, prevProbe })
	stubSolcDir(t, nil)

	pre, err := SandboxPreflight(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if boolField(pre, "ok") {
		t.Errorf("ok = true, want false")
	}
	found := false
	for _, i := range validation.ObjAt(pre, "issues").A {
		if strings.Contains(i.S, "docker daemon") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack docker daemon: %s",
			validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
}

func TestPreflightImageAbsentWarnsNotFails(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight Warn")
	up(t, false)
	stubSolcDir(t, nil)

	pre, err := SandboxPreflight(c, nil, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
	found := false
	for _, w := range validation.ObjAt(pre, "warnings").A {
		if strings.Contains(w.S, "pull") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings lack the pull note: %s",
			validation.DumpIndented(validation.ObjAt(pre, "warnings")))
	}
}

func TestPreflightHostReadonlySkipsContainerChecks(t *testing.T) {
	prevDaemon := dockerDaemonOK
	dockerDaemonOK = func() bool { return false }
	t.Cleanup(func() { dockerDaemonOK = prevDaemon })
	stubSolcDir(t, nil)

	pre, err := SandboxPreflight(nil, nil, strPtr("host-readonly"))
	if err != nil {
		t.Fatal(err)
	}
	checks := validation.ObjAt(pre, "checks")
	for _, name := range []string{"docker", "image", "solc"} {
		if got := validation.ObjStr(validation.ObjAt(checks, name), "status"); got != "na" {
			t.Errorf("%s status = %q, want na", name, got)
		}
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false")
	}
}

func TestPreflightWorkdirMissingFailsWithFix(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight WD")
	up(t, true)
	stubSolcDir(t, nil)
	missing := filepath.Join(t.TempDir(), "no-such-dir")

	pre, err := SandboxPreflight(c, &missing, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if boolField(pre, "ok") {
		t.Errorf("ok = true, want false")
	}
	found := false
	for _, i := range validation.ObjAt(pre, "issues").A {
		if strings.Contains(i.S, "no-such-dir") &&
			strings.Contains(strings.ToLower(i.S), "workdir") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack the workdir problem: %s",
			validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
}

func TestPreflightWorkdirFileFails(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight File")
	up(t, true)
	stubSolcDir(t, nil)
	f := filepath.Join(t.TempDir(), "afile")
	writeFile(t, f, "x")

	pre, err := SandboxPreflight(c, &f, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if boolField(pre, "ok") {
		t.Errorf("ok = true, want false")
	}
	found := false
	for _, i := range validation.ObjAt(pre, "issues").A {
		if strings.Contains(i.S, "not a directory") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack 'not a directory': %s",
			validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
}

func TestPreflightWorkdirOK(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight WD OK")
	up(t, true)
	stubSolcDir(t, nil)
	d := filepath.Join(t.TempDir(), "wd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}

	pre, err := SandboxPreflight(c, &d, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(pre, "checks"), "workdir"), "status"); got != "ok" {
		t.Errorf("workdir status = %q, want ok", got)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
}

func TestPreflightSolcCacheMissingFailsWithExactPath(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight Solc")
	up(t, true)
	svm := filepath.Join(t.TempDir(), "svm")
	if err := os.MkdirAll(svm, 0o755); err != nil {
		t.Fatal(err)
	}
	stubSolcDir(t, &svm)

	pre, err := SandboxPreflight(c, nil, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if boolField(pre, "ok") {
		t.Errorf("ok = true, want false")
	}
	var issue string
	for _, i := range validation.ObjAt(pre, "issues").A {
		if strings.Contains(strings.ToLower(i.S), "solc") {
			issue = i.S
		}
	}
	if !strings.Contains(issue, "solc-0.8.24") {
		t.Errorf("issue lacks solc-0.8.24: %q", issue)
	}
	if !strings.Contains(issue, filepath.Join(svm, "0.8.24")) {
		t.Errorf("issue lacks the exact path: %q", issue)
	}
}

func TestPreflightSolcCachePresentOK(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight Solc OK")
	up(t, true)
	svm := filepath.Join(t.TempDir(), "svm")
	if err := os.MkdirAll(filepath.Join(svm, "0.8.24"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(svm, "0.8.24", "solc-0.8.24"), "binary")
	stubSolcDir(t, &svm)

	pre, err := SandboxPreflight(c, nil, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(pre, "checks"), "solc"), "status"); got != "ok" {
		t.Errorf("solc status = %q, want ok", got)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
}

func TestPreflightSolcUnsetWarns(t *testing.T) {
	c, _ := campaignWithPin(t, "Preflight Unset")
	up(t, true)
	stubSolcDir(t, nil)

	pre, err := SandboxPreflight(c, nil, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
	found := false
	for _, w := range validation.ObjAt(pre, "warnings").A {
		if strings.Contains(w.S, "WEBV2_SOLC_DIR") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings lack WEBV2_SOLC_DIR: %s",
			validation.DumpIndented(validation.ObjAt(pre, "warnings")))
	}
}

func TestPreflightNoCompilerPinIsNA(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(filepath.Join(root, "other"), "No Toolchain",
		state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "plain")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "app.py"), "x = 1\n")
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	prevDaemon := dockerDaemonOK
	dockerDaemonOK = func() bool { return true }
	t.Cleanup(func() { dockerDaemonOK = prevDaemon })
	stubSolcDir(t, nil)

	pre, err := SandboxPreflight(c, nil, strPtr("docker-networkless"))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(pre, "checks"), "solc"), "status"); got != "na" {
		t.Errorf("solc status = %q, want na", got)
	}
	if boolField(pre, "ok") != true {
		t.Errorf("ok = false: %s", validation.DumpIndented(validation.ObjAt(pre, "issues")))
	}
}

// strField keeps the linter honest about the helper's use in assertions.
var _ = strField
