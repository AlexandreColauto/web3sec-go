package sandbox

// envseam_forkrpc_test.go: the fork_rpc preflight row — table-driven row
// behaviour (absent / unset / reachable / dead, probe never firing outside
// fork-runner) plus the seam-default preflight surfacing it as a WARN that
// does not block.

import (
	"errors"
	"strings"
	"testing"

	"websec/internal/validation"
)

// forkRPCProfileName / forkRPCOtherProfile are the profile pointers the
// table shares (one literal per file, referenced everywhere below; the
// fork profile comes from the production const).
var (
	forkRPCProfileName  = forkRunnerProfile
	forkRPCOtherProfile = "docker-networkless"
	forkRPCHostProfile  = "host-readonly"
)

// forkRPCPrefCase is one row of the fork_rpc preflight table.
type forkRPCPrefCase struct {
	name       string
	profile    *string // nil = the container-readiness (doctor) view
	env        string  // FORK_RPC_URL for the probe ("" = unset)
	probeErr   error
	wantCalls  int      // probe invocations the case must cause
	wantRow    bool     // a nil row means "no fork_rpc check at all"
	wantStatus string   // row.status when wantRow
	wantDetail []string // detail fragments that must appear
	wantAbsent []string // fragments the detail must NOT contain
}

var forkRPCPrefCases = []forkRPCPrefCase{
	{name: "no-profile", profile: nil, env: "http://rpc.example:1", wantCalls: 0},
	{name: "container-profile-not-forked", profile: &forkRPCOtherProfile,
		env: "http://rpc.example:1", wantCalls: 0},
	{name: "host-profile", profile: &forkRPCHostProfile,
		env: "http://rpc.example:1", wantCalls: 0},
	{name: "fork-unset", profile: &forkRPCProfileName, env: "", wantCalls: 0,
		wantRow: true, wantStatus: "warn", wantDetail: []string{
			"FORK_RPC_URL is not set",
			"FORK_RPC_URL=http://host.docker.internal:8545",
			"does not read FORK_RPC_URL is unaffected"}},
	{name: "fork-reachable-loopback", profile: &forkRPCProfileName,
		env: "http://127.0.0.1:18545", wantCalls: 1, wantRow: true,
		wantStatus: "ok", wantDetail: []string{
			"FORK_RPC_URL=http://127.0.0.1:18545",
			"the container sees http://host.docker.internal:18545",
			"answers eth_chainId"}},
	{name: "fork-dead-loopback", profile: &forkRPCProfileName,
		env: "http://127.0.0.1:18545", probeErr: errors.New(
			"connect: connection refused"), wantCalls: 1, wantRow: true,
		wantStatus: "warn", wantDetail: []string{
			"fork RPC unreachable",
			"FORK_RPC_URL=http://127.0.0.1:18545",
			"the container sees http://host.docker.internal:18545",
			"connect: connection refused"}},
	{name: "fork-dead-remote", profile: &forkRPCProfileName,
		env: "http://rpc.example:9999", probeErr: errors.New("no such host"),
		wantCalls: 1, wantRow: true, wantStatus: "warn",
		wantDetail: []string{"fork RPC unreachable",
			"FORK_RPC_URL=http://rpc.example:9999"},
		wantAbsent: []string{"the container sees"}},
}

// TestForkRPCPreflightRow pins the row semantics per profile/env/probe
// outcome, including that the probe NEVER fires outside fork-runner or
// when FORK_RPC_URL is unset (no network in those paths).
func TestForkRPCPreflightRow(t *testing.T) {
	for _, tc := range forkRPCPrefCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FORK_RPC_URL", tc.env)
			calls := 0
			SetForkRPCProbe(func(string) error {
				calls++
				return tc.probeErr
			})
			t.Cleanup(func() { SetForkRPCProbe(nil) })
			checkForkRPCRowCase(t, tc, ForkRPCPreflight(tc.profile), calls)
		})
	}
}

// checkForkRPCRowCase asserts one table row's expectations against the
// computed ForkRPCRow (hoisted so the test function stays within funlen).
func checkForkRPCRowCase(t *testing.T, tc forkRPCPrefCase, row *ForkRPCRow,
	calls int) {
	t.Helper()
	if !tc.wantRow {
		if row != nil || calls != 0 {
			t.Fatalf("row = %+v, calls = %d, want nil/0", row, calls)
		}
		return
	}
	if row == nil {
		t.Fatal("row = nil, want a fork_rpc check")
	}
	if calls != tc.wantCalls {
		t.Errorf("probe calls = %d, want %d", calls, tc.wantCalls)
	}
	if row.Status != tc.wantStatus {
		t.Errorf("status = %q, want %q", row.Status, tc.wantStatus)
	}
	assertForkRPCDetail(t, row.Detail, tc.wantDetail, tc.wantAbsent)
}

// assertForkRPCDetail checks the required and forbidden detail fragments
// (hoisted so checkForkRPCRowCase stays within gocyclo).
func assertForkRPCDetail(t *testing.T, detail string, want, absent []string) {
	t.Helper()
	for _, frag := range want {
		if !strings.Contains(detail, frag) {
			t.Errorf("detail %q lacks %q", detail, frag)
		}
	}
	for _, frag := range absent {
		if strings.Contains(detail, frag) {
			t.Errorf("detail %q must not contain %q", detail, frag)
		}
	}
}

// hasPrefixedWarning reports whether the preflight carries a warning line
// starting with the given text (check name + ": " + detail prefix).
func hasPrefixedWarning(pre validation.Value, prefix string) bool {
	for _, w := range validation.ObjAt(pre, "warnings").A {
		if w.Kind == validation.Str && strings.HasPrefix(w.S, prefix) {
			return true
		}
	}
	return false
}

// TestSandboxPreflightForkRPCWarnsAndBlocksNothing pins the surfacing
// through the seam-default preflight itself: an unset FORK_RPC_URL under
// fork-runner produces the fork_rpc WARN in checks and warnings, and the
// WARN does NOT turn preflight not-ok (a working OPTIMISM_NODE-shaped run
// must not be refused for a variable it never reads).
func TestSandboxPreflightForkRPCWarnsAndBlocksNothing(t *testing.T) {
	withDaemon(t, true)
	t.Setenv("FORK_RPC_URL", "")
	pre, err := SandboxPreflight(nil, nil, &forkRPCProfileName)
	if err != nil {
		t.Fatal(err)
	}
	row := validation.ObjAt(validation.ObjAt(pre, "checks"), "fork_rpc")
	if got := validation.ObjStr(row, "status"); got != "warn" {
		t.Errorf("checks.fork_rpc.status = %q, want warn (row %s)", got,
			validation.CanonCompact(row))
	}
	if !hasPrefixedWarning(pre, "fork_rpc: FORK_RPC_URL is not set") {
		t.Errorf("warnings = %s", validation.CanonCompact(
			validation.ObjAt(pre, "warnings")))
	}
	if !boolAt(pre, "ok") {
		t.Errorf("a fork_rpc WARN must not block the run: %s",
			validation.CanonCompact(pre))
	}
}
