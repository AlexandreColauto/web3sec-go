package envgo

// preflight_fork_test.go: the r45b-style differential for the fork_rpc
// preflight row — the wired copy (this package) and the sandbox seam
// default must produce the byte-identical row for the same FORK_RPC_URL,
// and neither may emit a row outside fork-runner.

import (
	"errors"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/validation"
)

// forkRPCLoopbackURL / forkRPCRemoteURL are shared so the literals stay
// below goconst's repetition threshold in this package.
var (
	forkRPCLoopbackURL = "http://127.0.0.1:18545"
	forkRPCRemoteURL   = "http://rpc.example:7777"
)

// forkRPCDiffCase is one row of the differential table.
type forkRPCDiffCase struct {
	name, env  string
	probeErr   error
	wantStatus string
	wantDetail string
}

var forkRPCDiffCases = []forkRPCDiffCase{
	{"unset", "", nil, "warn", "FORK_RPC_URL is not set"},
	{"reachable", forkRPCLoopbackURL, nil, "ok", "answers eth_chainId"},
	{"dead", forkRPCLoopbackURL,
		errors.New("connect: connection refused"), "warn",
		"fork RPC unreachable: FORK_RPC_URL=http://127.0.0.1:18545"},
	{"dead-remote", forkRPCRemoteURL, errors.New("no such host"), "warn",
		"FORK_RPC_URL=http://rpc.example:7777"},
}

// TestPreflightForkRPCMatchesSandboxDefault pins the two transcriptions
// together (the r45b lesson): same row bytes, the expected status/detail,
// and NO fork_rpc row at all on a non-fork-runner profile.
func TestPreflightForkRPCMatchesSandboxDefault(t *testing.T) {
	r45bNoDocker(t)
	for _, tc := range forkRPCDiffCases {
		t.Run(tc.name, func(t *testing.T) { runForkRPCDiffCase(t, tc) })
	}
}

// runForkRPCDiffCase executes one differential row (hoisted for funlen).
func runForkRPCDiffCase(t *testing.T, tc forkRPCDiffCase) {
	t.Helper()
	t.Setenv("FORK_RPC_URL", tc.env)
	sandbox.SetForkRPCProbe(func(string) error { return tc.probeErr })
	t.Cleanup(func() { sandbox.SetForkRPCProbe(nil) })
	fork := "fork-runner"
	other := "vm-snapshot" // any non-fork-runner container profile
	wiredPre, werr := SandboxPreflight(nil, nil, &fork)
	defPre, derr := sandbox.SandboxPreflight(nil, nil, &fork)
	wired := forkRPCRowOf(t, wiredPre, werr)
	def := forkRPCRowOf(t, defPre, derr)
	if validation.CanonCompact(wired) != validation.CanonCompact(def) {
		t.Errorf("the two fork_rpc transcriptions disagree\n  envgo:   %s\n"+
			"  sandbox: %s", validation.CanonCompact(wired),
			validation.CanonCompact(def))
	}
	assertForkRPCDiffRow(t, wired, tc)
	leakPre, lerr := SandboxPreflight(nil, nil, &other)
	if leaked := forkRPCRowOf(t, leakPre, lerr); leaked.Kind != validation.Null {
		t.Errorf("fork_rpc row leaked to %q: %s", other,
			validation.CanonCompact(leaked))
	}
}

// assertForkRPCDiffRow checks the row's status and detail fragment
// (hoisted so runForkRPCDiffCase stays within funlen).
func assertForkRPCDiffRow(t *testing.T, row validation.Value,
	tc forkRPCDiffCase) {
	t.Helper()
	if got := validation.ObjStr(row, "status"); got != tc.wantStatus {
		t.Errorf("status = %q, want %q", got, tc.wantStatus)
	}
	if d := validation.ObjStr(row, "detail"); !strings.Contains(d,
		tc.wantDetail) {
		t.Errorf("detail %q lacks %q", d, tc.wantDetail)
	}
}

// forkRPCRowOf reads checks.fork_rpc out of one preflight result, failing
// the test on a preflight error (hoisted for the funlen budget).
func forkRPCRowOf(t *testing.T, pre validation.Value,
	err error) validation.Value {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(validation.ObjAt(pre, "checks"), "fork_rpc")
}
