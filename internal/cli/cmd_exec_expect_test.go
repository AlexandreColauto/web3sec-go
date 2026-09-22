package cli

// v16 P1-10a §5.3: `webv2 exec` gains --expect {pass,fail} and
// --expect-failure TEXT, declared BEFORE the run and recorded on the EXEC
// record. Both byte-pinned surfaces — execHelp (argparse's --help output,
// byte-exact) and the argparseUsageBlocks["exec"] usage map — changed
// together, as captured from the Python reference's argparse with the two
// new add_argument calls (this Python reproduces the PRE-change blocks
// byte-for-byte, which is what makes the capture trustworthy).
//
// The third law pinned here is BEHAVIOURAL: both flags must reach
// Sandbox.run as RunOpts.Expect / ExpectFailure. It replaced a source-string
// scan that passed under most partial breakages (a flag parsed but never
// threaded, or threaded under the wrong name, still left the literal in the
// source) — this version fails if either flag stops parsing or stops being
// wired.

import (
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
)

// execHelpPinned is argparse's `webv2 exec --help` with the two new
// options, byte-exact.
const execHelpPinned = `usage: webv2 exec [-h] [--profile PROFILE] [--dry-run] --command COMMAND
                  [--workdir WORKDIR] [--finding FINDING] [--timeout TIMEOUT]
                  [--env K=V] [--expect {pass,fail}] [--expect-failure TEXT]
                  campaign

positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --profile PROFILE     execution profile: host-readonly (host shell — can
                        NEVER back E4+ evidence) or a container profile
                        (docker-networkless, docker-gvisor, vm-snapshot, fork-
                        runner — required for E4+ evidence)
  --dry-run             print the exact container argv, env keys, network and
                        workdir mode, then exit — no execution, no EXEC
                        record, works even when the runtime is absent
  --command COMMAND
  --workdir WORKDIR     working directory (bind-mounted)
  --finding FINDING     finding this exec is for
  --timeout TIMEOUT
  --env K=V             environment variable for the container (repeatable);
                        recorded by key in the EXEC ledger
  --expect {pass,fail}  what this run must do to count as a reproduction
                        (default: pass — a passing suite). Declared BEFORE the
                        run and recorded on the EXEC ledger; an absent-guard
                        defect is evidenced by the expected refusal NOT
                        happening, which fails by construction
  --expect-failure TEXT
                        with --expect fail: the failure signature the run must
                        show, asserted to appear in the captured output
                        (required, and refused under --expect pass)
`

// execUsagePinned is argparse's usage block (what argparseUsageBlocks
// ["exec"] must hold), byte-exact.
const execUsagePinned = `usage: webv2 exec [-h] [--profile PROFILE] [--dry-run] --command COMMAND
                  [--workdir WORKDIR] [--finding FINDING] [--timeout TIMEOUT]
                  [--env K=V] [--expect {pass,fail}] [--expect-failure TEXT]
                  campaign
`

// TestExecHelpUsagePinnedVerbatim pins design test 9: the help output the
// CLI prints, the execHelp constant, and the usage map entry are all
// byte-for-byte the captured argparse bytes.
func TestExecHelpUsagePinnedVerbatim(t *testing.T) {
	code, out, errS := run(t, "exec", "--help")
	if code != 0 {
		t.Fatalf("exec --help exit %d, want 0 (stderr %q)", code, errS)
	}
	if out != execHelpPinned {
		t.Fatalf("exec --help drifted from the pinned argparse bytes:\n"+
			"--- got ---\n%s\n--- want ---\n%s", out, execHelpPinned)
	}
	if errS != "" {
		t.Errorf("exec --help wrote stderr %q", errS)
	}
	if execHelp != execHelpPinned {
		t.Error("execHelp const drifted from its pinned bytes")
	}
	if argparseUsageBlocks["exec"] != execUsagePinned {
		t.Errorf("argparseUsageBlocks[\"exec\"] drifted:\n got %q\nwant %q",
			argparseUsageBlocks["exec"], execUsagePinned)
	}
	for _, marker := range []string{"--expect {pass,fail}",
		"--expect-failure TEXT", "[--expect {pass,fail}]"} {
		if !strings.Contains(execHelpPinned, marker) {
			t.Errorf("the pin itself is missing %q — the test would pass "+
				"vacuously", marker)
		}
	}
}

// TestExecExpectFlagsReachSandbox is the standing flag-wiring law, made
// behavioural: the two flags must reach Sandbox.run as RunOpts.Expect /
// ExpectFailure, and the absent case must stay keyless. A rename or a broken
// thread is a loud failure here — either argparse rejects the flag (exit 2)
// or the stub sees the wrong value.
func TestExecExpectFlagsReachSandbox(t *testing.T) {
	f := t20Setup(t)
	cases := []struct {
		name       string
		args       []string
		wantExpect string
		wantSig    string
	}{
		{"declared fail pair", []string{"--expect", "fail",
			"--expect-failure", "MarketNotListed"}, "fail", "MarketNotListed"},
		{"absent declaration", nil, "", ""},
		{"explicit pass", []string{"--expect", "pass"}, "pass", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := runExecWithStub(t, f, c.args)
			if opts.Expect != c.wantExpect ||
				opts.ExpectFailure != c.wantSig {
				t.Fatalf("flags reached Sandbox.run as Expect=%q "+
					"ExpectFailure=%q, want %q/%q", opts.Expect,
					opts.ExpectFailure, c.wantExpect, c.wantSig)
			}
		})
	}
}

// runExecWithStub runs `exec` with the sandbox seam stubbed and returns what
// the CLI handed Sandbox.run (extracted for the funlen cap).
func runExecWithStub(t *testing.T, f *t20Fixture,
	args []string) sandbox.RunOpts {
	t.Helper()
	stub := &stubExecSandbox{}
	prev := newExecSandbox
	newExecSandbox = func(c *state.Campaign,
		profile string) (execSandbox, error) {
		return stub, nil
	}
	t.Cleanup(func() { newExecSandbox = prev })
	full := append([]string{"--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "forge test"}, args...)
	code, out, errS := run(t, full...)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	return stub.opts
}

// execExpectRefusalCases is TestExecExpectFlagRefusals' table: each row's
// FULL expected stderr (usage block included). The contract checks run
// after argparse's own required checks, like Python's
// parse_args-then-validate.
var execExpectRefusalCases = []struct {
	name string
	args []string
	want string
}{
	{"invalid choice",
		[]string{"exec", "C-x", "--expect", "maybe", "--command", "ls"},
		"webv2 exec: error: argument --expect: invalid choice: " +
			"'maybe' (choose from 'pass', 'fail')\n"},
	{"signature requires --expect fail",
		[]string{"exec", "C-x", "--expect-failure", "sig",
			"--command", "ls"},
		"webv2 exec: error: argument --expect-failure: requires " +
			"--expect fail — a declared failure signature on a run " +
			"expected to pass is a contradiction (declare --expect " +
			"fail with it, or drop it)\n"},
	{"fail requires a signature",
		[]string{"exec", "C-x", "--expect", "fail", "--command", "ls"},
		"webv2 exec: error: argument --expect: --expect fail requires " +
			"--expect-failure TEXT — the failure signature must be " +
			"declared before the run; there is no signature-less " +
			"admission\n"},
	{"missing value",
		[]string{"exec", "C-x", "--expect"},
		"webv2 exec: error: argument --expect: expected one argument\n"},
	{"argparse required check wins over the contract check",
		[]string{"exec", "C-x", "--expect-failure", "sig"},
		"webv2 exec: error: the following arguments are required: " +
			"--command\n"},
}

// TestExecExpectFlagRefusals pins the new error surfaces byte-exact (the
// table lives above so the test body stays under the funlen cap).
func TestExecExpectFlagRefusals(t *testing.T) {
	for _, c := range execExpectRefusalCases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errS := run(t, c.args...)
			if code != 2 {
				t.Errorf("exit %d, want 2 (stdout %q)", code, out)
			}
			want := execUsagePinned + c.want
			if errS != want {
				t.Errorf("stderr drifted:\n got %q\nwant %q", errS, want)
			}
		})
	}
}

// TestExecExpectFlagsParseTogether is the positive path: the legal
// declaration parses and reaches the state layer (it fails only because the
// fixture campaign does not exist — an argparse error would be exit 2 with
// a usage block).
func TestExecExpectFlagsParseTogether(t *testing.T) {
	code, _, errS := run(t, "exec", "C-nonexistent01", "--expect", "fail",
		"--expect-failure", "MarketNotListed", "--command", "forge test")
	if code == 2 {
		t.Fatalf("the legal flag pair must parse; got an argparse error: %q",
			errS)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("want the state-layer refusal, got: %q", errS)
	}
}
