package cli

// P2 CLI tests — `exec` (ord 40). Every expected byte below is captured from
// the live Python twin by .scratch/t20/capture_cli.py (and the argparse
// errors by the same script's error cases).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// t20Fixture is capture_cli.py's fixture: one finding and the four exec
// records the captures cite.
type t20Fixture struct {
	c       *state.Campaign
	root    string
	fid     string
	pass    string
	host    string
	noTests string
	fail    string
}

func t20Setup(t *testing.T) *t20Fixture {
	t.Helper()
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { function f() external {} }"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		kvT("title", validation.VStr(
			"Unguarded rescue moves protocol-held tokens")),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("access-control")),
			kvT("description", validation.VStr(
				"rescue has no role check at all")))),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("target/V.sol")),
			kvT("function", validation.VStr("rescue"))))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()))),
	)
	f, err := ingestT20(t, c, payload, "attacker", "06")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	reg := func(profile, command, stdout string, exit int,
		findingID string) string {
		t.Helper()
		rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
			Profile: profile, Command: command, ReportedBy: "operator",
			ExitStatus: exit, FindingID: optStrT20(findingID),
			StdoutText: stdout})
		if err != nil {
			t.Fatalf("register exec: %v", err)
		}
		return objStr(rec, "exec_id")
	}
	return &t20Fixture{c: c, root: root, fid: fid,
		pass: reg("docker-networkless", "forge test --match-test poc",
			"PASS: poc\n", 0, fid),
		host: reg("host-readonly", "echo hi", "hi\n", 0, fid),
		noTests: reg("docker-networkless", "forge test --match-test none",
			"No tests found in test\nRan 0 tests\n", 0, fid),
		fail: reg("docker-networkless", "forge build",
			"Error: cannot connect to the Docker daemon\n", 1, "")}
}

func optStrT20(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// TestExecDryRunHost pins the host-readonly preview byte-for-byte.
func TestExecDryRunHost(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--dry-run", "--command", "ls")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "exec preview [host-readonly]  available: yes\n" +
		"  command (host shell, cwd (current directory)): ls\n" +
		"  note: runs on the HOST (no container): this exec can never back " +
		"E4+ evidence — use a container profile (docker-networkless, " +
		"fork-runner, ...) for reproduction evidence\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestExecDryRunContainer pins the container argv, network and workdir mode.
func TestExecDryRunContainer(t *testing.T) {
	f := t20Setup(t)
	if !sandbox.ProfileAvailable("docker-networkless") {
		t.Skip("docker runtime not present on this host")
	}
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "docker-networkless", "--dry-run", "--command",
		"forge build")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	// FOUNDRY_LINT_ON_BUILD=false is injected by default (feedback-triage
	// A3) — an intentional divergence from the reference argv.
	want := "exec preview [docker-networkless]  available: yes\n" +
		"  network: none\n" +
		"  workdir: (sandbox tmpfs) (tmpfs)\n" +
		"  env keys: FOUNDRY_LINT_ON_BUILD\n" +
		"  $ docker run --rm --init --network none --tmpfs " +
		"/wd:rw,size=1g -w /wd -e FOUNDRY_LINT_ON_BUILD=false " +
		"--entrypoint /bin/sh " +
		"ghcr.io/foundry-rs/foundry:latest -c 'forge build'\n" +
		"  note: entrypoint is pinned to /bin/sh -c (the image's entrypoint " +
		"is never used) — the command runs verbatim as a shell string\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestExecDryRunEnvKeys pins the repeatable --env ordering (A, B, then the
// profile's injected FORK_RPC_URL).
func TestExecDryRunEnvKeys(t *testing.T) {
	f := t20Setup(t)
	if !sandbox.ProfileAvailable("fork-runner") {
		t.Skip("docker runtime not present on this host")
	}
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "fork-runner", "--dry-run", "--command", "forge test",
		"--env", "A=1", "--env", "B=2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "exec preview [fork-runner]  available: yes\n" +
		"  network: bridge-host-gateway\n" +
		"  workdir: (sandbox tmpfs) (tmpfs)\n" +
		"  env keys: A, B, FORK_RPC_URL, FOUNDRY_LINT_ON_BUILD\n" +
		"  $ docker run --rm --init --add-host " +
		"host.docker.internal:host-gateway --tmpfs /wd:rw,size=1g -w /wd " +
		"-e A=1 -e B=2 -e FORK_RPC_URL=http://host.docker.internal:8545 " +
		"-e FOUNDRY_LINT_ON_BUILD=false " +
		"--entrypoint /bin/sh ghcr.io/foundry-rs/foundry:latest " +
		"-c 'forge test'\n" +
		"  note: entrypoint is pinned to /bin/sh -c (the image's entrypoint " +
		"is never used) — the command runs verbatim as a shell string\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestExecBadEnv pins the two --env refusals.
func TestExecBadEnv(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true", "--env", "NOEQUALS")
	if code != 2 || errS != "exec failed: --env expects K=V (got 'NOEQUALS')\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	code, _, errS = run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true", "--env", "9BAD=1")
	want := "exec failed: --env key '9BAD' is not a valid environment name " +
		"(K must match [A-Za-z_][A-Za-z0-9_]*)\n"
	if code != 2 || errS != want {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestExecUnknownProfile pins the dry-run profile refusal.
func TestExecUnknownProfile(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "bogus", "--dry-run", "--command", "ls")
	if code != 2 || errS != "exec failed: unknown profile 'bogus'\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestExecHostRun pins the real host-readonly run block (the exec id is
// generated, so only the stable parts are pinned).
func TestExecHostRun(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "EXEC-") ||
		!strings.Contains(out, "  [host-readonly] exit=0 true\n") {
		t.Fatalf("out %q", out)
	}
	want := "output: " + f.c.ExecsDir
	if !strings.Contains(out, want) ||
		!strings.Contains(out, "(mint with `webv2 mint ... --exec EXEC-") {
		t.Fatalf("out %q", out)
	}
	if !strings.HasSuffix(out, "  (host-readonly ran on the host — this exec "+
		"can NEVER back E4+ evidence; use a container profile for that)\n") {
		t.Fatalf("out %q", out)
	}
}

// TestExecMissingWorkdirPreflight pins the FAIL block and the operator
// hand-off line.
func TestExecMissingWorkdirPreflight(t *testing.T) {
	f := t20Setup(t)
	missing := filepath.Join(f.root, "nope")
	code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true",
		"--workdir", missing)
	want := "exec preflight FAIL: workdir: workdir " + missing +
		" does not exist — a missing bind source fails the whole run — fix: " +
		"create " + missing + " or point --workdir at an existing directory\n" +
		"environment problem, not hypothesis problem — fix the above and " +
		"re-run (re-check: webv2 doctor " + f.c.CampaignID + " / webv2 env doctor " +
		f.c.CampaignID + ")\n"
	if code != 2 || errS != want {
		t.Fatalf("exit %d err\n%q\nwant\n%q", code, errS, want)
	}
}

// TestExecArgparseErrors pins argparse's in-subparser errors.
func TestExecArgparseErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		msg  string
	}{
		{"no-command", []string{"exec", "C-x"},
			"the following arguments are required: --command"},
		{"command-noval", []string{"exec", "C-x", "--command"},
			"argument --command: expected one argument"},
		{"timeout-bad", []string{"exec", "C-x", "--command", "ls",
			"--timeout", "abc"},
			"argument --timeout: invalid int value: 'abc'"},
		{"command-eats-option", []string{"exec", "C-x", "--command",
			"--help"},
			"argument --command: expected one argument"},
		{"timeout-eats-option", []string{"exec", "C-x", "--command", "ls",
			"--timeout", "--help"},
			"argument --timeout: expected one argument"},
		{"nothing", []string{"exec"},
			"the following arguments are required: campaign, --command"},
	}
	for _, tc := range cases {
		code, _, errS := run(t, tc.args...)
		if code != 2 {
			t.Fatalf("%s: exit %d", tc.name, code)
		}
		want := argparseUsageBlocks["exec"] +
			"webv2 exec: error: " + tc.msg + "\n"
		if errS != want {
			t.Fatalf("%s: err\n%q\nwant\n%q", tc.name, errS, want)
		}
	}
}

// TestExecEqualsFormTakesAnyValue pins argparse's explicit '=' form: the
// value may look like an option.
func TestExecEqualsFormTakesAnyValue(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--command=-v", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, ": -v\n") {
		t.Fatalf("out %q", out)
	}
}

// TestExecExtraPositionalIsRootArgparse pins the root parser's rendering.
func TestExecExtraPositionalIsRootArgparse(t *testing.T) {
	code, _, errS := run(t, "exec", "C-x", "--command", "ls", "extra")
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(errS, "error: unrecognized arguments: extra\n") {
		t.Fatalf("err %q", errS)
	}
}

// TestExecEnvEmptyKeyRejected pins the "=value" refusal (port of
// tests/test_exec_env.py::test_env_empty_key_rejected).
func TestExecEnvEmptyKeyRejected(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true", "--env", "=value")
	want := "exec failed: --env key '' is not a valid environment name " +
		"(K must match [A-Za-z_][A-Za-z0-9_]*)\n"
	if code != 2 || errS != want {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// stubExecSandbox captures what the CLI hands Sandbox.run (port of
// tests/test_exec_env.py::test_env_valid_reaches_sandbox).
type stubExecSandbox struct {
	opts sandbox.RunOpts
}

func (s *stubExecSandbox) Run(command string,
	opts sandbox.RunOpts) (validation.Value, error) {
	s.opts = opts
	return validation.VObj(
		kvT("exec_id", validation.VStr("EXEC-stub")),
		kvT("profile", validation.VStr("host-readonly")),
		kvT("exit_status", validation.VInt(0)),
		kvT("command", validation.VStr(command)),
		kvT("stdout_path", validation.VStr("/dev/null")),
		kvT("stderr_path", validation.VStr("/dev/null"))), nil
}

func TestExecEnvValidReachesSandbox(t *testing.T) {
	f := t20Setup(t)
	stub := &stubExecSandbox{}
	prev := newExecSandbox
	newExecSandbox = func(c *state.Campaign,
		profile string) (execSandbox, error) {
		return stub, nil
	}
	t.Cleanup(func() { newExecSandbox = prev })
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true",
		"--env", "FOO=bar", "--env", "BAZ=qux")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if len(stub.opts.Env) != 2 || stub.opts.Env[0] != (sandbox.EnvVar{
		Key: "FOO", Value: "bar"}) || stub.opts.Env[1] != (sandbox.EnvVar{
		Key: "BAZ", Value: "qux"}) {
		t.Fatalf("env handed to Sandbox.run = %+v", stub.opts.Env)
	}
}

// TestExecDryRunNoDaemon pins the no-runtime preview: available: NO, the
// argv still shown, and NO exec record written (port of
// tests/test_exec_dry_run.py::test_cli_dry_run_no_record).
func TestExecDryRunNoDaemon(t *testing.T) {
	f := t20Setup(t)
	sandbox.SetDockerDaemonOK(func() bool { return false })
	t.Cleanup(func() { sandbox.SetDockerDaemonOK(nil) })
	before := execRecordCount(t, f)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "docker-networkless", "--dry-run", "--command",
		"forge build")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "exec preview [docker-networkless]  available: NO — install " +
		"the runtime to execute this profile\n" +
		"  network: none\n" +
		"  workdir: (sandbox tmpfs) (tmpfs)\n" +
		"  env keys: FOUNDRY_LINT_ON_BUILD\n" +
		"  $ docker run --rm --init --network none --tmpfs " +
		"/wd:rw,size=1g -w /wd -e FOUNDRY_LINT_ON_BUILD=false " +
		"--entrypoint /bin/sh " +
		"ghcr.io/foundry-rs/foundry:latest -c 'forge build'\n" +
		"  note: entrypoint is pinned to /bin/sh -c (the image's entrypoint " +
		"is never used) — the command runs verbatim as a shell string\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
	if after := execRecordCount(t, f); after != before {
		t.Fatalf("dry-run wrote an exec record (%d -> %d)", before, after)
	}
}

// execRecordCount is the number of EXEC-* dirs in the campaign.
func execRecordCount(t *testing.T, f *t20Fixture) int {
	t.Helper()
	entries, err := os.ReadDir(f.c.ExecsDir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "EXEC-") {
			n++
		}
	}
	return n
}

// TestExecHelpMentionsE4 pins the help surface (port of
// tests/test_exec_dry_run.py::test_cli_exec_help_mentions_e4).
func TestExecHelpMentionsE4(t *testing.T) {
	code, out, _ := run(t, "exec", "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "E4+") || !strings.Contains(out, "--dry-run") {
		t.Fatalf("help missing E4+/--dry-run:\n%s", out)
	}
}

// TestDockerExecCLIEndToEnd drives the whole T20 CLI surface through a REAL
// container run: exec (container profile) -> execs --id -> classify -> mint
// E4. Gated so the default suite stays pure-logic.
func TestDockerExecCLIEndToEnd(t *testing.T) {
	if os.Getenv("WEBV2_DOCKER_TESTS") == "" {
		t.Skip("WEBV2_DOCKER_TESTS=1 to run")
	}
	t.Setenv("WEBV2_DOCKER_IMAGE", "foundry-solc-0824:latest")
	if !sandbox.ProfileAvailable("docker-networkless") {
		t.Skip("docker runtime not present on this host")
	}
	f := t20Setup(t)
	// The bind source must live outside this process's /tmp (the DSH file
	// sandbox redirects it), or the daemon mounts an empty dir.
	parent := filepath.Join("..", "..", ".scratch", "t20")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	wd, err := os.MkdirTemp(parent, "cli-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(wd) })
	copyTree(t, filepath.Join("..", "reproduction", "testdata", "foundry-mini"), wd)

	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "docker-networkless", "--workdir", wd, "--command",
		"forge test --match-test test_two", "--finding", f.fid)
	if code != 0 {
		t.Fatalf("exec exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "[docker-networkless] exit=0") {
		t.Fatalf("exec out %q", out)
	}
	execID := out[:strings.Index(out, "  [")]
	code, out, errS = run(t, "--root", f.root, "execs", f.c.CampaignID,
		"--id", execID)
	if code != 0 || !strings.Contains(out, `"profile": "docker-networkless"`) ||
		!strings.Contains(out, `"workdir": "bind"`) {
		t.Fatalf("execs --id exit %d: %s%s", code, out, errS)
	}
	code, out, errS = run(t, "--root", f.root, "classify", f.c.CampaignID,
		execID)
	if code != 0 || !strings.HasPrefix(out, "exec "+execID+" (exit 0): NONE\n") {
		t.Fatalf("classify exit %d: %q %q", code, out, errS)
	}
	code, out, errS = run(t, "--root", f.root, "mint", f.c.CampaignID, f.fid,
		"--exec", execID, "--description", "containerized forge test proves "+
			"the invariant", "--tier", "T2")
	if code != 0 {
		t.Fatalf("mint exit %d: %s%s", code, out, errS)
	}
	if !strings.HasSuffix(out, "— level E4\n") {
		t.Fatalf("mint out %q", out)
	}
}

// copyTree copies a directory tree (testdata fixture -> docker-visible dir).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo,
		err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy tree: %v", err)
	}
}
