package sandbox

// Task 17 (G8) sandbox-recipe tests: the halmos / forge-fuzz host profiles.
//
// The repo's policy layer is deny-by-default tripwires (there is no
// allowlist table), so "the allowlist accepts halmos argv" is
// PolicyCheck(...).allowed == true under the new profile, and the
// "deny-exec-write" half is the destructive-path tripwire still firing on
// smuggled `rm -rf /` — the same guard shape as the existing exec tests.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"websec/internal/validation"
)

// TestPolicyCheckAllowsHalmos pins the recipe's own argv as runnable: a
// halmos check under the halmos profile trips no deny rule.
func TestPolicyCheckAllowsHalmos(t *testing.T) {
	v, err := PolicyCheck(
		"halmos check --root . --match-contract InvariantHalmos", "halmos")
	if err != nil {
		t.Fatal(err)
	}
	if !boolAt(v, "allowed") {
		t.Errorf("allowed = false (violations %s), want true",
			validation.CanonCompact(objAt(v, "violations")))
	}
}

// TestPolicyCheckAllowsForgeFuzz is the forge-fuzz mirror: a forge fuzz
// run under the forge-fuzz profile trips no deny rule.
func TestPolicyCheckAllowsForgeFuzz(t *testing.T) {
	v, err := PolicyCheck(
		"forge test --match-contract InvariantFuzz", "forge-fuzz")
	if err != nil {
		t.Fatal(err)
	}
	if !boolAt(v, "allowed") {
		t.Errorf("allowed = false (violations %s), want true",
			validation.CanonCompact(objAt(v, "violations")))
	}
}

// TestPolicyCheckHalmosRejectsSmuggledDestructive pins the tripwire half:
// a halmos argv smuggling `rm -rf /` is still refused.
func TestPolicyCheckHalmosRejectsSmuggledDestructive(t *testing.T) {
	v, err := PolicyCheck("halmos check --root .; rm -rf /", "halmos")
	if err != nil {
		t.Fatal(err)
	}
	if boolAt(v, "allowed") {
		t.Error("allowed = true, want false")
	}
	if !containsStrValue(objAt(v, "violations"), "destructive-path") {
		t.Errorf("violations = %s, want destructive-path",
			validation.CanonCompact(objAt(v, "violations")))
	}
}

// TestHostProfilesAreHostOnly pins the Task 17 contract: the harness
// profiles execute on the host (available without a daemon) and can never
// back E4+ evidence.
func TestHostProfilesAreHostOnly(t *testing.T) {
	withDaemon(t, false)
	for _, p := range []string{"halmos", "forge-fuzz"} {
		if !ProfileAvailable(p) {
			t.Errorf("ProfileAvailable(%q) = false, want true", p)
		}
		if !HostProfile(p) {
			t.Errorf("HostProfile(%q) = false, want true", p)
		}
		if _, ok := E4_PROFILES[p]; ok {
			t.Errorf("%q must not be E4-capable", p)
		}
		if _, err := NewSandbox(newCampaign(t, "Acme Program"), p); err != nil {
			t.Errorf("NewSandbox(%q): %v", p, err)
		}
	}
	if network := networkLabel("halmos"); !strings.Contains(network, "unconfined") {
		t.Errorf("halmos network = %q, want an unconfined-host disclosure "+
			"(a host run has the host's network)", network)
	}
	if fs := profileFilesystem["forge-fuzz"]; fs != "readonly" {
		t.Errorf("forge-fuzz filesystem = %q, want readonly", fs)
	}
}

// TestHalmosProfileRunsOnHost pins the dispatch: a halmos run goes
// through /bin/sh on the host (no docker argv, null container), exactly
// like host-readonly.
func TestHalmosProfileRunsOnHost(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "halmos")
	if err != nil {
		t.Fatal(err)
	}
	var gotArgv []string
	withProc(t, func(argv []string, dir string, env []string,
		timeout time.Duration) (ProcResult, error) {
		gotArgv = argv
		return ProcResult{ReturnCode: 0, Stdout: "halmos 0.3.3\n"}, nil
	})
	rec, err := sb.Run("halmos check --root .", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotArgv) != 3 || gotArgv[0] != "/bin/sh" || gotArgv[1] != "-c" ||
		gotArgv[2] != "halmos check --root ." {
		t.Fatalf("host argv = %v, want [/bin/sh -c command]", gotArgv)
	}
	if objAt(rec, "container").Kind != validation.Null {
		t.Errorf("container = %s, want null",
			validation.CanonCompact(objAt(rec, "container")))
	}
	if got := intAt(rec, "exit_status"); got != 0 {
		t.Errorf("exit_status = %d, want 0", got)
	}
}

// TestToolVersionsProbesHalmos pins the probe list addition: a halmos on
// PATH reports its first `--version` line; an absent halmos is honestly
// omitted (no forged row).
func TestToolVersionsProbesHalmos(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'halmos 0.3.3'\n"
	if err := os.WriteFile(filepath.Join(dir, "halmos"), []byte(script),
		0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		if len(argv) == 2 && argv[0] == "halmos" && argv[1] == "--version" {
			return ProcResult{ReturnCode: 0, Stdout: "halmos 0.3.3\n"}, nil
		}
		return ProcResult{ReturnCode: 1}, nil
	})
	if got := strAt(toolVersions(), "halmos"); got != "halmos 0.3.3" {
		t.Errorf("halmos version = %q, want %q", got, "halmos 0.3.3")
	}

	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if v := objAt(toolVersions(), "halmos"); v.Kind != validation.Null {
		t.Errorf("absent halmos must be omitted, got %s",
			validation.CanonCompact(v))
	}
}

// TestMinicertoraProfilePolicy pins the G8 third kind's profile entries:
// host-side, network unconfined (honest label), readonly fs, E3-capped
// exactly like halmos.
func TestMinicertoraProfilePolicy(t *testing.T) {
	v, err := PolicyCheck("minicertora target/src/V.sol "+
		"artifacts/harness/INV-1/INV.mspec --solc-path /usr/local/bin/solc "+
		"--loop-bound 4 --timeout-ms 30000", "minicertora")
	if err != nil {
		t.Fatalf("PolicyCheck: %v", err)
	}
	if !boolAt(v, "allowed") {
		t.Errorf("allowed = false (violations %s), want true",
			validation.CanonCompact(objAt(v, "violations")))
	}
	if network := networkLabel("minicertora"); !strings.Contains(network, "unconfined") {
		t.Errorf("minicertora network = %q, want an unconfined-host "+
			"disclosure (a host run has the host's network)", network)
	}
	if fs := profileFilesystem["minicertora"]; fs != "readonly" {
		t.Errorf("minicertora filesystem = %q, want readonly", fs)
	}
	if !HostProfile("minicertora") {
		t.Error("minicertora must be a host profile (E3 cap)")
	}
	if !ProfileAvailable("minicertora") {
		t.Error("minicertora availability is the host toolchain, like halmos")
	}
	if _, ok := E4_PROFILES["minicertora"]; ok {
		t.Error("minicertora must not be E4-capable")
	}
	if _, err := NewSandbox(newCampaign(t, "Acme Program"), "minicertora"); err != nil {
		t.Errorf("NewSandbox(minicertora): %v", err)
	}
}

// TestMinicertoraProfileRejectsSmuggledDestructive is the tripwire half: a
// minicertora argv smuggling `rm -rf /` is still refused, exactly like the
// halmos profile.
func TestMinicertoraProfileRejectsSmuggledDestructive(t *testing.T) {
	v, err := PolicyCheck("minicertora x; rm -rf /", "minicertora")
	if err != nil {
		t.Fatalf("PolicyCheck: %v", err)
	}
	if boolAt(v, "allowed") {
		t.Error("allowed = true, want false")
	}
	if !containsStrValue(objAt(v, "violations"), "destructive-path") {
		t.Errorf("violations = %s, want destructive-path",
			validation.CanonCompact(objAt(v, "violations")))
	}
}

// TestToolVersionsProbesMinicertora mirrors TestToolVersionsProbesHalmos: a
// 'minicertora' shim on PATH reports its first `--version` line; an absent
// shim is honestly omitted (no forged row).
func TestToolVersionsProbesMinicertora(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'minicertora 0.4.2'\n"
	if err := os.WriteFile(filepath.Join(dir, "minicertora"), []byte(script),
		0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		if len(argv) == 2 && argv[0] == "minicertora" && argv[1] == "--version" {
			return ProcResult{ReturnCode: 0, Stdout: "minicertora 0.4.2\n"}, nil
		}
		return ProcResult{ReturnCode: 1}, nil
	})
	if got := strAt(toolVersions(), "minicertora"); got != "minicertora 0.4.2" {
		t.Errorf("minicertora version = %q, want %q", got, "minicertora 0.4.2")
	}

	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if v := objAt(toolVersions(), "minicertora"); v.Kind != validation.Null {
		t.Errorf("absent minicertora must be omitted, got %s",
			validation.CanonCompact(v))
	}
}

// TestTimeoutMarkerExplainsTheRecord pins critic r3: a -1 from a timeout is
// no longer indistinguishable from a kill — the recorded stderr carries the
// reason, like the never-ran path already does.
func TestTimeoutMarkerExplainsTheRecord(t *testing.T) {
	c := newCampaign(t, "TimeoutProbe")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	withProc(t, func(argv []string, dir string, env []string,
		timeout time.Duration) (ProcResult, error) {
		return ProcResult{ReturnCode: -1, Stdout: "partial",
			Stderr: "already streaming"}, errTimeout
	})
	rec, err := sb.Run("sleep 100", RunOpts{Timeout: 3})
	if err != nil {
		t.Fatal(err)
	}
	raw, rerr := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "stderr.log"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	stderr := string(raw)
	if !strings.Contains(stderr, "sandbox: timed out after 3s") {
		t.Fatalf("timeout must explain the record: %q", stderr)
	}
	if !strings.Contains(stderr, "already streaming") {
		t.Fatalf("captured stderr must survive the marker: %q", stderr)
	}
	withProc(t, func(argv []string, dir string, env []string,
		timeout time.Duration) (ProcResult, error) {
		return ProcResult{ReturnCode: -1}, errTimeout
	})
	rec2, err := sb.Run("sleep 101", RunOpts{Timeout: 3})
	if err != nil {
		t.Fatal(err)
	}
	raw2, rerr := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec2, "exec_id"), "stderr.log"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.HasSuffix(string(raw2), "killed\n") ||
		!strings.Contains(string(raw2), "timed out") {
		t.Fatalf("bare timeout record: %q", string(raw2))
	}
}

// TestNetworkLabelIsHonestForHostProfiles pins the Task 2 law: a host
// profile executes with the HOST's full network, so its label must disclose
// that instead of claiming "none" (the r36 F5 filesystem-label fix, applied
// to the network half of the environment sub-dict). Container profiles keep
// their label verbatim — the container IS the enforcement mechanism.
func TestNetworkLabelIsHonestForHostProfiles(t *testing.T) {
	for _, p := range []string{"host-readonly", "halmos", "forge-fuzz", "minicertora"} {
		got := networkLabel(p)
		if !strings.Contains(got, "unconfined") {
			t.Errorf("networkLabel(%q) = %q, want an unconfined-host disclosure", p, got)
		}
	}
	if got := networkLabel("docker-networkless"); got != "none" {
		t.Errorf("docker-networkless label = %q, want none", got)
	}
	if got := networkLabel("fork-runner"); got != "bridge-host-gateway" {
		t.Errorf("fork-runner label = %q, want bridge-host-gateway", got)
	}
}

// TestPreviewHostProfileNetworkIsHonest is the preview-level twin of the
// label test: the dry-run surface is what the operator reads BEFORE running,
// so it must not advertise network "none" for a host profile either.
func TestPreviewHostProfileNetworkIsHonest(t *testing.T) {
	pv, err := Preview("host-readonly", "true", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strAt(pv, "network"); !strings.Contains(got, "unconfined") {
		t.Errorf("Preview network = %q, want an unconfined-host disclosure", got)
	}
}

// TestHostProfileRecordNetworkIsHonest guards the OTHER call site: the
// environment sub-dict a host-profile EXEC record carries.
func TestHostProfileRecordNetworkIsHonest(t *testing.T) {
	env := environmentValue(validation.VObj(), nil, "host-readonly")
	if got := strAt(env, "network_access"); !strings.Contains(got, "unconfined") {
		t.Errorf("environment.network_access = %q, want an unconfined-host "+
			"disclosure", got)
	}
	if fs := strAt(env, "filesystem"); !strings.Contains(fs, "unconfined") {
		t.Errorf("environment.filesystem = %q, want the honest host label", fs)
	}
}
