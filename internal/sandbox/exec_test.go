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
	if network := profileNetwork["halmos"]; network != "none" {
		t.Errorf("halmos network = %q, want none", network)
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
