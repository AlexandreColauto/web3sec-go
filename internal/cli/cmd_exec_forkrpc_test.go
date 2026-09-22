package cli

// cmd_exec_forkrpc_test.go: the end-to-end surfacing the defect named —
// `webv2 exec --profile fork-runner` with FORK_RPC_URL unset (the shape
// that auto-injects the dead http://host.docker.internal:8545 default)
// must PRINT the fork_rpc preflight warning and still run (warn, never
// block: the observed OPTIMISM_NODE-shaped payload needs no fork RPC).

import (
	"strings"
	"testing"

	"websec/internal/envgo"
	"websec/internal/state"
	"websec/internal/validation"
)

// presentImageStub is an image probe that reports the image present, so
// the preflight output below contains exactly one warning: fork_rpc.
func presentImageStub() validation.Value {
	return validation.VObj(
		kvT("image", validation.VStr("ghcr.io/foundry-rs/foundry:latest")),
		kvT("daemon", validation.VBool(true)),
		kvT("present", validation.VBool(true)),
		kvT("digest", validation.VNull()),
		kvT("pinned", validation.VBool(false)),
		kvT("detail", validation.VStr("stub — tests do not pull images")))
}

// stubForkExecEnv pins a healthy container environment (daemon up, image
// local) around the exec so only fork_rpc can add a warning.
func stubForkExecEnv(t *testing.T) {
	t.Helper()
	envgo.SetDockerDaemonOK(func() bool { return true })
	envgo.SetDockerImageProbe(func(*string) validation.Value {
		return presentImageStub()
	})
	t.Cleanup(func() {
		envgo.SetDockerDaemonOK(nil)
		envgo.SetDockerImageProbe(nil)
	})
}

// stubExecForFork substitutes the sandbox for the run itself (the test
// asserts preflight output, not a real docker run).
func stubExecForFork(t *testing.T) {
	t.Helper()
	stub := &stubExecSandbox{}
	prev := newExecSandbox
	newExecSandbox = func(*state.Campaign, string) (execSandbox, error) {
		return stub, nil
	}
	t.Cleanup(func() { newExecSandbox = prev })
}

// TestExecForkRunnerWarnsOnUnsetForkRPC pins the CLI surfacing: the warn
// line names the variable and the injected default, stderr carries it,
// exit stays 0, and the run reaches the sandbox.
func TestExecForkRunnerWarnsOnUnsetForkRPC(t *testing.T) {
	ensureSeams() // wire first so the stubs below are not overwritten
	f := t20Setup(t)
	stubForkExecEnv(t)
	stubExecForFork(t)
	t.Setenv("FORK_RPC_URL", "")
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "fork-runner", "--command", "forge test")
	if code != 0 {
		t.Fatalf("exit %d: a fork_rpc WARN must not block: %s%s", code, out, errS)
	}
	want := "exec preflight warn: fork_rpc: FORK_RPC_URL is not set — " +
		"fork-runner injects the default " +
		"FORK_RPC_URL=http://host.docker.internal:8545"
	if !strings.Contains(errS, want) {
		t.Fatalf("stderr %q lacks the fork_rpc warning %q", errS, want)
	}
	if !strings.Contains(out, "EXEC-stub") {
		t.Errorf("stdout %q shows the run never reached the sandbox", out)
	}
}
