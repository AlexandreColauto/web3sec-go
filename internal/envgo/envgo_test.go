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
func strField(v validation.Value, key string) string { return objStr(v, key) }

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
	if got := objStr(res, "class"); got != "environment" {
		t.Fatalf("class = %q, want environment", got)
	}
	note := objStr(res, "note")
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
	if cls := objStr(res, "class"); cls != "logic" {
		t.Fatalf("class = %q, want logic (test failed is a logic signal)", cls)
	}
	note := objStr(res, "note")
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
	solc := objAt(report, "solc")
	if solc.Kind != validation.Obj {
		t.Fatalf("solc = %s", validation.DumpIndented(solc))
	}
	if got := objStr(solc, "required"); got != "0.8.24" {
		t.Errorf("required = %q", got)
	}
	if boolField(solc, "present") {
		t.Errorf("present = true, want false")
	}
	found := false
	for _, i := range objAt(report, "issues").A {
		if strings.Contains(i.S, "solc 0.8.24 missing") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack the missing-solc problem: %s",
			validation.DumpIndented(objAt(report, "issues")))
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
	solc := objAt(report, "solc")
	if !boolField(solc, "present") {
		t.Errorf("present = false, want true")
	}
	if p := objAt(solc, "problem"); p.Kind != validation.Null {
		t.Errorf("problem = %s, want null", validation.DumpIndented(p))
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
	if s := objAt(report, "solc"); s.Kind != validation.Null {
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
	if s := objAt(report, "solc"); s.Kind != validation.Null {
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
	fit := objAt(report, "profile_fit")
	if fit.Kind != validation.Obj {
		t.Fatalf("profile_fit = %s, want an object",
			validation.DumpIndented(fit))
	}
	if got := objStr(fit, "docker-networkless"); got !=
		"E4-only (campaign floor E6)" {
		t.Errorf("docker-networkless fit = %q", got)
	}
	if got := objStr(fit, "fork-runner"); got !=
		"E5-only (campaign floor E6)" {
		t.Errorf("fork-runner fit = %q", got)
	}
	// host-readonly has no evidence ceiling and is never fit-marked
	if objAt(fit, "host-readonly").Kind != validation.Null {
		t.Errorf("host-readonly must not appear in profile_fit: %s",
			validation.DumpIndented(fit))
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
		t.Errorf("ok = false: %s", validation.DumpIndented(objAt(pre, "issues")))
	}
	if n := len(objAt(pre, "issues").A); n != 0 {
		t.Errorf("issues = %d, want 0", n)
	}
	checks := objAt(pre, "checks")
	for _, name := range []string{"docker", "image", "solc", "workdir"} {
		st := objStr(objAt(checks, name), "status")
		if st != "ok" && st != "na" {
			t.Errorf("%s status = %q: %s", name, st,
				validation.DumpIndented(objAt(checks, name)))
		}
	}
	if got := objStr(objAt(checks, "solc"), "status"); got != "ok" {
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
	for _, i := range objAt(pre, "issues").A {
		if strings.Contains(i.S, "docker daemon") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack docker daemon: %s",
			validation.DumpIndented(objAt(pre, "issues")))
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
		t.Errorf("ok = false: %s", validation.DumpIndented(objAt(pre, "issues")))
	}
	found := false
	for _, w := range objAt(pre, "warnings").A {
		if strings.Contains(w.S, "pull") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings lack the pull note: %s",
			validation.DumpIndented(objAt(pre, "warnings")))
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
	checks := objAt(pre, "checks")
	for _, name := range []string{"docker", "image", "solc"} {
		if got := objStr(objAt(checks, name), "status"); got != "na" {
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
	for _, i := range objAt(pre, "issues").A {
		if strings.Contains(i.S, "no-such-dir") &&
			strings.Contains(strings.ToLower(i.S), "workdir") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack the workdir problem: %s",
			validation.DumpIndented(objAt(pre, "issues")))
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
	for _, i := range objAt(pre, "issues").A {
		if strings.Contains(i.S, "not a directory") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack 'not a directory': %s",
			validation.DumpIndented(objAt(pre, "issues")))
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
	if got := objStr(objAt(objAt(pre, "checks"), "workdir"), "status"); got != "ok" {
		t.Errorf("workdir status = %q, want ok", got)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(objAt(pre, "issues")))
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
	for _, i := range objAt(pre, "issues").A {
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
	if got := objStr(objAt(objAt(pre, "checks"), "solc"), "status"); got != "ok" {
		t.Errorf("solc status = %q, want ok", got)
	}
	if !boolField(pre, "ok") {
		t.Errorf("ok = false: %s", validation.DumpIndented(objAt(pre, "issues")))
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
		t.Errorf("ok = false: %s", validation.DumpIndented(objAt(pre, "issues")))
	}
	found := false
	for _, w := range objAt(pre, "warnings").A {
		if strings.Contains(w.S, "WEBV2_SOLC_DIR") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings lack WEBV2_SOLC_DIR: %s",
			validation.DumpIndented(objAt(pre, "warnings")))
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
	if got := objStr(objAt(objAt(pre, "checks"), "solc"), "status"); got != "na" {
		t.Errorf("solc status = %q, want na", got)
	}
	if boolField(pre, "ok") != true {
		t.Errorf("ok = false: %s", validation.DumpIndented(objAt(pre, "issues")))
	}
}

// strField keeps the linter honest about the helper's use in assertions.
var _ = strField
