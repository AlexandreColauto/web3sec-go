// Port of tests/test_sequence_runner.py — runner driver: build_command
// determinism, run_sequence wiring, and a stub-cast end-to-end of the
// generated shell (hermetic: no docker).
package sequencepoc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/harness"
	"websec/internal/reproduction"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// --- R5 golden: the generated driver text is a spec surface ----------------

// TestBuildCommandGoldenText pins the FULL generated driver byte-for-byte
// for three fixture specs. The expected text was produced by the LIVE
// Python module (sequence_poc.build_command) and must never be hand-edited.
func TestBuildCommandGoldenText(t *testing.T) {
	for _, name := range []string{"runner", "simple", "edge"} {
		t.Run(name, func(t *testing.T) {
			specPath := filepath.Join("testdata", "spec_"+name+".json")
			spec, err := LoadSequenceSpec(specPath)
			if err != nil {
				t.Fatalf("LoadSequenceSpec(%s): %v", specPath, err)
			}
			want, err := os.ReadFile(filepath.Join("testdata",
				"driver_"+name+".golden"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			got, err := BuildCommand(spec, "/wd")
			if err != nil {
				t.Fatalf("BuildCommand: %v", err)
			}
			if got != string(want) {
				t.Fatalf("driver text diverges from Python golden\n%s",
					firstDiff(string(want), got))
			}
		})
	}
}

// firstDiff reports the first differing line for a readable failure.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return fmt.Sprintf("line %d:\n  want %q\n  got  %q", i+1, w, g)
		}
	}
	return "identical"
}

// --- build_command ---------------------------------------------------------

func TestBuildCommandIsPure(t *testing.T) {
	spec := runnerSpec(t)
	a, err := BuildCommand(spec, "/wd")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildCommand(spec, "/wd")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("build_command is not deterministic")
	}
}

func TestBuildCommandContainsTheContractPieces(t *testing.T) {
	spec := runnerSpec(t)
	cmd, err := BuildCommand(spec, "/wd")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"anvil_mine 3", // mine_blocks=3, decimal
		"--unlocked",   // anvil:0 actor unlocked send
		"--from",
		"FORK_KEY_VICTIM", // 0x-actor key via env
		SpecHash(spec),    // binding hash embedded
		"sequence_result.json",
		`[ -n "${A_attacker}" ]`, // empty resolution fails closed
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("driver missing %q", want)
		}
	}
	for _, forbidden := range []string{"evm_mine", "expect_revert",
		"--unlocked-account"} {
		if strings.Contains(cmd, forbidden) {
			t.Errorf("driver must not contain %q", forbidden)
		}
	}
}

// --- run_sequence wiring ---------------------------------------------------

func TestRunSequenceRequiresForkProfile(t *testing.T) {
	// Hermetic: simulate "no docker daemon" — the point is the fork-runner
	// profile check, not whether this host runs a daemon.
	c := testCampaign(t)
	p := writeSpec(t, t.TempDir(), runnerSpec(t))
	sandbox.SetDockerDaemonOK(func() bool { return false })
	defer sandbox.SetDockerDaemonOK(nil)
	_, err := RunSequence(c, p, RunSequenceOpts{})
	if err == nil || !strings.Contains(err.Error(), "fork-runner") {
		t.Fatalf("want fork-runner runtime error, got %v", err)
	}
}

// fakeRunSequence swaps the sandbox seam for a stub that captures the run
// options without docker. The fake rec exits non-zero with no finding, so
// run_sequence takes the hermetic path (no mint, no fork).
func fakeRunSequence(t *testing.T, captured *sandbox.RunOpts,
	profile *string) {
	t.Helper()
	prev := sandboxRun
	sandboxRun = func(c *state.Campaign, prof, command string,
		opts sandbox.RunOpts) (validation.Value, error) {
		*profile, *captured = prof, opts
		out := filepath.Join(t.TempDir(), "fake-out")
		if err := os.MkdirAll(out, 0o755); err != nil {
			return validation.VNull(), err
		}
		stdout := filepath.Join(out, "stdout.log")
		if err := os.WriteFile(stdout, []byte("fake"), 0o644); err != nil {
			return validation.VNull(), err
		}
		return validation.VObj(
			validation.KV{K: "exec_id", V: validation.VStr("EXEC-fake")},
			validation.KV{K: "exit_status", V: validation.VInt(1)},
			validation.KV{K: "stdout_path", V: validation.VStr(stdout)},
		), nil
	}
	t.Cleanup(func() { sandboxRun = prev })
}

func TestRunSequenceForwardsForkRPCURL(t *testing.T) {
	c := testCampaign(t)
	p := writeSpec(t, t.TempDir(), runnerSpec(t))
	var opts sandbox.RunOpts
	var profile string
	fakeRunSequence(t, &opts, &profile)
	t.Setenv("FORK_RPC_URL", "http://remote-fork:9854")
	if _, err := RunSequence(c, p, RunSequenceOpts{}); err != nil {
		t.Fatal(err)
	}
	if profile != "fork-runner" {
		t.Errorf("profile = %q, want fork-runner", profile)
	}
	if len(opts.Env) != 1 || opts.Env[0].Key != "FORK_RPC_URL" ||
		opts.Env[0].Value != "http://remote-fork:9854" {
		t.Errorf("env = %+v, want FORK_RPC_URL=http://remote-fork:9854",
			opts.Env)
	}
	// run_sequence passes no timeout in the reference, so Sandbox.run's
	// default (300s) must be in force. Zero means the Go twin kills the
	// container instantly (time.NewTimer(0)) while the reference runs for
	// up to five minutes — the P2 docker e2e reproduced exactly that.
	if opts.Timeout != 300 {
		t.Errorf("timeout = %d, want the Sandbox.run default 300",
			opts.Timeout)
	}
}

func TestRunSequenceWithoutForkRPCURLInjectsNothing(t *testing.T) {
	c := testCampaign(t)
	p := writeSpec(t, t.TempDir(), runnerSpec(t))
	var opts sandbox.RunOpts
	var profile string
	fakeRunSequence(t, &opts, &profile)
	os.Unsetenv("FORK_RPC_URL")
	if _, err := RunSequence(c, p, RunSequenceOpts{}); err != nil {
		t.Fatal(err)
	}
	if len(opts.Env) != 0 {
		t.Errorf("env = %+v, want empty", opts.Env)
	}
}

func TestRunSequenceRejectsFindingMismatch(t *testing.T) {
	// Pass-2 M1 pin: a spec claiming finding A run with --finding B must
	// fail loud instead of silently attributing A's PoC to B.
	c := testCampaign(t)
	p := writeSpec(t, t.TempDir(), runnerSpec(t)) // finding_id F-run1
	other := "F-other"
	_, err := RunSequence(c, p, RunSequenceOpts{FindingID: &other})
	if err == nil || !strings.Contains(err.Error(), "wrong finding") {
		t.Fatalf("want wrong-finding ValueError, got %v", err)
	}
}

func TestBuildCommandRejectsUnvalidatedActorIndex(t *testing.T) {
	// M1: injection via a raw anvil index raises instead of embedding.
	bad := runnerSpec(t)
	bad = setPath(t, bad, []string{"actors", "attacker"},
		validation.VStr("anvil:0) || echo PWNED >&2; echo ("))
	_, err := BuildCommand(bad, "/wd")
	if err == nil || !strings.Contains(err.Error(), "anvil index") {
		t.Fatalf("want anvil-index ValueError, got %v", err)
	}
}

func TestLoadRejectsRoleCollisionAndShellToleratesLeadingZero(t *testing.T) {
	dir := t.TempDir()
	bad := mustParse(t, `{
      "spec_id": "SEQ-TEST-02", "finding_id": "F-run1",
      "actors": {"attacker": "anvil:0", "ATTACKER": "anvil:1",
                 "victim": "`+addr("bb")+`"},
      "steps": [
        {"step": 1, "actor": "attacker", "target": "`+addr("cd")+`",
         "function": "deposit(uint256)", "args": ["1000"]},
        {"step": 2, "actor": "victim", "target": "`+addr("cd")+`",
         "function": "claim()", "expect_revert": true}
      ],
      "final_assertions": []}`)
	p2 := filepath.Join(dir, "bad2.json")
	if err := os.WriteFile(p2, []byte(validation.DumpIndented(bad)),
		0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSequenceSpec(p2)
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("want role-collision ValueError, got %v", err)
	}
	zero := runnerSpec(t)
	zero = setPath(t, zero, []string{"actors", "attacker"},
		validation.VStr("anvil:007"))
	cmd, err := BuildCommand(zero, "/wd") // must not raise; shell strips zeros
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "anvil_addr 007") {
		t.Error("driver must keep the leading-zero index for anvil_addr")
	}
}

// --- hermetic driver end-to-end -------------------------------------------

func TestDriverEndToEndPass(t *testing.T) {
	t.Parallel()
	spec := runnerSpec(t)
	code, stdout, stderr, wd := driverRun(t, spec, stubCast, "wd")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	_ = stdout
	res := readResult(t, wd)
	if got := objStr(res, "spec_hash"); got != SpecHash(spec) {
		t.Errorf("spec_hash = %s", got)
	}
	steps := stepsOf(t, res)
	if len(steps) != 2 || stepStatus(steps[0]) != "success" ||
		stepStatus(steps[1]) != "revert" {
		t.Fatalf("statuses = %v", steps)
	}
	if objStr(steps[0], "actor") != "attacker" ||
		objStr(steps[1], "actor") != "victim" {
		t.Errorf("actors wrong: %v", steps)
	}
	if got := objStr(steps[0], "tx_hash"); got !=
		"0xdeadbeef0000000000000000000000000000000000000000000000000000cafe" {
		t.Errorf("tx_hash = %s", got)
	}
	if got := objStr(steps[1], "revert_reason"); got !=
		"execution reverted: claim too early" {
		t.Errorf("revert_reason = %q", got)
	}
	asserts := listOf(objAt(res, "final_assertions"))
	if len(asserts) != 2 || !objAt(asserts[0], "passed").B ||
		!objAt(asserts[1], "passed").B {
		t.Errorf("assertions = %v", asserts)
	}
	if objStr(res, "overall") != "pass" {
		t.Errorf("overall = %s", objStr(res, "overall"))
	}
}

func TestDriverFailsOnUnexpectedRevert(t *testing.T) {
	t.Parallel()
	bad := runnerSpec(t)
	bad = setPath(t, bad, []string{"steps", "1", "expect_revert"},
		validation.VBool(false))
	code, _, _, wd := driverRun(t, bad, stubCast, "wd")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	res := readResult(t, wd)
	if objStr(res, "overall") != "fail" {
		t.Error("overall must be fail")
	}
	if got := len(stepsOf(t, res)); got != 1 {
		t.Errorf("partial steps = %d, want 1", got)
	}
}

func TestDriverFailsOnAssertion(t *testing.T) {
	t.Parallel()
	bad := runnerSpec(t)
	bad = setPath(t, bad, []string{"final_assertions", "0", "value"},
		validation.VStr("2000000000000000000000"))
	code, _, _, wd := driverRun(t, bad, stubCast, "wd")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	res := readResult(t, wd)
	for _, s := range stepsOf(t, res) {
		if st := stepStatus(s); st != "success" && st != "revert" {
			t.Errorf("unexpected status %q", st)
		}
	}
	a0 := listOf(objAt(res, "final_assertions"))[0]
	if objAt(a0, "passed").B {
		t.Error("assertion must fail")
	}
	if got := objStr(a0, "observed"); got != "0xde0b6b3a7640000" {
		t.Errorf("observed = %q", got)
	}
	if objStr(res, "overall") != "fail" {
		t.Error("overall must be fail")
	}
}

func TestDriverRevertWithoutReasonStillRecords(t *testing.T) {
	t.Parallel()
	stub := strings.Replace(stubCast,
		`echo "execution reverted: claim too early" >&2`, "exit 1", 1)
	code, _, _, wd := driverRun(t, runnerSpec(t), stub, "wd")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	res := readResult(t, wd)
	steps := stepsOf(t, res)
	if got := objStr(steps[1], "revert_reason"); got != "" {
		t.Errorf("revert_reason = %q, want empty", got)
	}
}

// --- step value threading (L-defer T3) ------------------------------------

// valuedSpec is a two-step spec whose FIRST step carries the optional wei
// `value` the witness bridge now emits; the second step carries none, so
// one driver covers both halves of the law (present -> `cast send --value`,
// absent -> no flag at all).
func valuedSpec(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{
  "spec_id": "SEQ-TEST-07", "finding_id": "F-val1",
  "actors": {"attacker": "anvil:0", "victim": "`+addr("bb")+`"},
  "steps": [
    {"step": 1, "actor": "attacker", "target": "`+addr("cd")+`",
     "function": "deposit(uint256)", "args": ["1000"],
     "value": "1000000000000000000"},
    {"step": 2, "actor": "victim", "target": "`+addr("cd")+`",
     "function": "claim()"}
  ],
  "final_assertions": []
}`)
}

// TestBuildCommandThreadsStepValue pins the generated send line: a step's
// `value` rides as `cast send --value <literal>` (the wei amount is a tx
// field of the CALL, so it belongs on the send line, before the actor
// flag), and a spec without the key is byte-unchanged — no flag, no
// empty `--value`.
func TestBuildCommandThreadsStepValue(t *testing.T) {
	got, err := BuildCommand(valuedSpec(t), "/wd")
	if err != nil {
		t.Fatal(err)
	}
	wantSend := `out=$(cast send --rpc-url "$FORK_RPC_URL" ` + addr("cd") +
		` 'deposit(uint256)' 1000 --value 1000000000000000000 ` +
		`--from "${A_attacker}" --unlocked 2>"$WD/seq_err.txt")`
	if !strings.Contains(got, wantSend) {
		t.Fatalf("valued send line missing\n got %s\nwant line %s",
			firstDiff(wantSend, got), wantSend)
	}
	// The value-less step never grows a flag.
	claim := `out=$(cast send --rpc-url "$FORK_RPC_URL" ` + addr("cd") +
		` 'claim()' --private-key "${FORK_KEY_VICTIM:-}"` +
		` 2>"$WD/seq_err.txt")`
	if !strings.Contains(got, claim) {
		t.Fatalf("value-less send line wrong:\n%s",
			firstDiff(claim, got))
	}
	// And the pre-T3 fixtures produce no `--value` anywhere: the flag is
	// the valued step's, not a new constant in every driver.
	plain, err := BuildCommand(runnerSpec(t), "/wd")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "--value") {
		t.Error("a spec without a value must not emit --value")
	}
}

// stubCastRecordArgv is a stub `cast` that records every `send` argv it
// receives (one line per call, in call order) so the test can read what the
// generated driver ACTUALLY passed, not just what it was built from.
const stubCastRecordArgv = `#!/bin/sh
case "$1" in
  rpc)
    case "$*" in
      *eth_accounts*) printf '%s\n' '["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","0x70997970c51812dc3a010c7d01b50e0d17dc79c8"]' ;;
      *) exit 0 ;;
    esac ;;
  send)
    printf '%s\n' "$*" >> cast_argv.txt
    printf '%s\n' "blockNumber 20000001" "transactionHash 0xdeadbeef0000000000000000000000000000000000000000000000000000cafe"
    exit 0 ;;
  *) exit 0 ;;
esac
`

// TestDriverStepValueReachesCastArgv is the executor's end-to-end row: run
// the generated shell against a `cast` that records its argv and prove the
// value the spec declares is the value the fork call carries — present on
// the valued step, absent on the value-less one.
func TestDriverStepValueReachesCastArgv(t *testing.T) {
	t.Parallel()
	code, _, stderr, wd := driverRun(t, valuedSpec(t), stubCastRecordArgv, "wd")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	raw, err := os.ReadFile(filepath.Join(wd, "cast_argv.txt"))
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("recorded %d send calls, want 2: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "deposit(uint256)") ||
		!strings.Contains(lines[0], "--value 1000000000000000000") {
		t.Fatalf("step 1 argv = %q, want the declared value on the call",
			lines[0])
	}
	if !strings.Contains(lines[1], "claim()") ||
		strings.Contains(lines[1], "--value") {
		t.Fatalf("step 2 argv = %q, want no value flag", lines[1])
	}
	// The executed spec still binds to its own hash (the value is part of
	// the spec bytes, so a result minted from a valued spec cannot be
	// confused with a value-less one).
	res := readResult(t, wd)
	if got, want := objStr(res, "spec_hash"), SpecHash(valuedSpec(t)); got != want {
		t.Fatalf("spec_hash = %s, want %s", got, want)
	}
}

// TestStepValueLoadLaw pins the loader half of the same law: the key is
// optional (the pre-T3 spec loads untouched), a wei literal loads and
// survives verbatim, and a non-literal is refused at LOAD time with the
// field named — never silently dropped on the way to the fork.
func TestStepValueLoadLaw(t *testing.T) {
	if _, err := LoadSequenceSpec(writeSpec(t, t.TempDir(),
		valuedSpec(t))); err != nil {
		t.Fatalf("valued spec must load: %v", err)
	}
	loaded, err := LoadSequenceSpec(writeSpec(t, t.TempDir(), valuedSpec(t)))
	if err != nil {
		t.Fatal(err)
	}
	step := listOf(objAt(loaded, "steps"))[0]
	if got := objStr(step, "value"); got != "1000000000000000000" {
		t.Fatalf("loaded value = %q, want it verbatim", got)
	}
	bad := mustParse(t, `{
  "spec_id": "SEQ-TEST-08", "finding_id": "F-val2",
  "actors": {"attacker": "anvil:0"},
  "steps": [{"step": 1, "actor": "attacker", "target": "`+addr("cd")+`",
             "function": "deposit(uint256)", "value": "1 ether"}],
  "final_assertions": []
}`)
	got := loadErr(t, bad)
	if !strings.Contains(got, "value") ||
		!strings.Contains(got, "does not match") {
		t.Fatalf("pretty value error = %q, want a schema pattern refusal "+
			"naming value", got)
	}
}

func TestResultSchemaRegistered(t *testing.T) {
	minimal := mustParse(t, `{"spec_hash": "sha256:`+strings.Repeat("0", 64)+
		`", "steps": [], "final_assertions": [], "overall": "pass",`+
		` "generated_at": "2026-07-15T00:00:00Z"}`)
	if err := validation.Validate(minimal, "sequence_result", 1); err != nil {
		t.Fatalf("sequence_result schema: %v", err)
	}
	raw, err := validation.ReadSchemaFile("campaign_state")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	kinds := objAt(objAt(objAt(objAt(objAt(doc, "properties"), "artifacts"),
		"items"), "properties"), "kind")
	found := false
	for _, k := range listOf(objAt(kinds, "enum")) {
		if k.Kind == validation.Str && k.S == "sequence-result" {
			found = true
		}
	}
	if !found {
		t.Error("campaign_state artifact kinds must include sequence-result")
	}
}

func TestDriverComparisonOpsLeAndNe(t *testing.T) {
	t.Parallel()
	spec := runnerSpec(t)
	spec = setPath(t, spec, []string{"final_assertions"}, mustParse(t, `[
      {"id": "A3", "kind": "call", "target": "`+addr("cd")+`",
       "function": "get()", "op": "<=", "value": "7"},
      {"id": "A4", "kind": "call", "target": "`+addr("cd")+`",
       "function": "get()", "op": "!=", "value": "8"}]`))
	code, _, stderr, wd := driverRun(t, spec, stubCast, "wd")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	res := readResult(t, wd)
	for i, a := range listOf(objAt(res, "final_assertions")) {
		if !objAt(a, "passed").B {
			t.Errorf("assertion %d must pass", i)
		}
	}
	bad := setPath(t, spec, []string{"final_assertions", "0", "value"},
		validation.VStr("6"))
	bad = setPath(t, bad, []string{"final_assertions", "1", "value"},
		validation.VStr("7"))
	code2, _, _, wd2 := driverRun(t, bad, stubCast, "wd2")
	if code2 != 1 {
		t.Fatalf("exit = %d, want 1", code2)
	}
	res2 := readResult(t, wd2)
	for i, a := range listOf(objAt(res2, "final_assertions")) {
		if objAt(a, "passed").B {
			t.Errorf("assertion %d must fail", i)
		}
	}
	if objStr(res2, "overall") != "fail" {
		t.Error("overall must be fail")
	}
}

func TestDriverHostileRPCOutputStaysValidJSON(t *testing.T) {
	t.Parallel()
	stub := strings.Replace(stubCast,
		`printf '%s\n' "0xde0b6b3a7640000"`,
		`printf '%s\n' 'evil"quote\backslash'`, 1)
	spec := runnerSpec(t)
	spec = setPath(t, spec, []string{"final_assertions"}, mustParse(t, `[
      {"id": "A1", "kind": "balance", "account": "attacker",
       "op": ">=", "value": "2000"}]`))
	_, _, _, wd := driverRun(t, spec, stub, "wd")
	res := readResult(t, wd) // must parse
	a0 := listOf(objAt(res, "final_assertions"))[0]
	if objAt(a0, "passed").B {
		t.Error("assertion must fail")
	}
	obs := objStr(a0, "observed")
	if strings.ContainsAny(obs, `"\`) {
		t.Errorf("observed %q must be sanitized", obs)
	}
}

func TestDriverEmptyAccountsFailClosed(t *testing.T) {
	t.Parallel()
	stub := strings.Replace(stubCast,
		`printf '%s\n' '["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",`+
			`"0x70997970c51812dc3a010c7d01b50e0d17dc79c8"]'`,
		`printf '%s\n' '[]'`, 1)
	code, _, stderr, _ := driverRun(t, runnerSpec(t), stub, "wd")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "empty address") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestDriverPassEmitsStdoutSummary(t *testing.T) {
	t.Parallel()
	// C1 pin: the pass path must print to stdout — mint_repro_evidence
	// refuses exit-0 execs with EMPTY captured output.
	code, stdout, stderr, _ := driverRun(t, runnerSpec(t), stubCast, "wd")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("pass path printed nothing — E5 mint would refuse")
	}
	if !strings.Contains(stdout, "PASS") ||
		!strings.Contains(stdout, SpecHash(runnerSpec(t))) {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestCapturedPassStdoutMintsE5(t *testing.T) {
	t.Parallel()
	// C1 end-to-end pin: the driver's real captured stdout backs
	// attempt_and_mint to E5 fork-test evidence; empty output still refuses.
	code, stdout, stderr, wd := driverRun(t, runnerSpec(t), stubCast, "wd")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(wd, "sequence_result.json")); err != nil {
		t.Fatal("no sequence_result.json")
	}
	c := testCampaign(t)
	fid := mkSeqFinding(t, c)
	fidStr := fid
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "fork-runner", Command: "true", ReportedBy: "pytest-harness",
		FindingID: &fidStr, StdoutText: stdout, StderrText: stderr})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Dir(objStr(rec, "stdout_path"))
	spec := runnerSpec(t)
	if err := os.WriteFile(filepath.Join(out, "spec.json"),
		CanonicalJSON(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(wd, "sequence_result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "sequence_result.json"), body,
		0o644); err != nil {
		t.Fatal(err)
	}
	tier, etype := "T4", "fork-test"
	if _, err := reproduction.AttemptAndMint(c, fid, objStr(rec, "exec_id"),
		"sequence PoC SEQ-TEST-02 (2 steps) on the pinned fork", &tier,
		&etype); err != nil {
		t.Fatal(err)
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvidence(f2, "E5", objStr(rec, "exec_id")) {
		t.Error("E5 fork-test evidence not minted")
	}
	// control: the empty-output gate still holds for a silent exec
	fid2 := mkSeqFinding(t, c)
	rec2, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "fork-runner", Command: "true", ReportedBy: "pytest-harness",
		FindingID: &fid2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reproduction.RecordAttempt(c, fid2, "reproduced",
		reproduction.RecordOpts{Tier: &tier, ExecID: strPtr(objStr(rec2,
			"exec_id"))}); err != nil {
		t.Fatal(err)
	}
	_, err = reproduction.MintReproEvidence(c, fid2, objStr(rec2, "exec_id"),
		"silent run", &tier, &etype)
	if err == nil || !strings.Contains(err.Error(), "EMPTY") {
		t.Fatalf("want EMPTY refusal, got %v", err)
	}
}

// mkSeqFinding is _mk_finding: ingest a real finding, then set status +
// exploit_sequence through the storage layer.
func mkSeqFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	payload := mustParse(t, `{
      "title": "multi-tx sequence bug",
      "root_cause": {"class": "access-control",
                     "description": "missing check across two calls"},
      "affected": [{"path": "src/V.sol", "contract": "V",
                    "function": "claim"}],
      "attacker": {"profile": "arbitrary EOA", "capabilities": []}}`)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f = setKey(f, "status", validation.VStr("POSSIBLE"))
	f = setKey(f, "exploit_sequence", mustParse(t, `[
      {"step": 1, "actor": "attacker", "action": "deposit"},
      {"step": 2, "actor": "victim", "action": "drain"}]`))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return fid
}

// hasEvidence is any(e.get("level") == level and e.get("artifact_id") == id).
func hasEvidence(f validation.Value, level, artifactID string) bool {
	for _, e := range listOf(objAt(f, "evidence")) {
		if objStr(e, "level") == level && objStr(e, "artifact_id") == artifactID {
			return true
		}
	}
	return false
}

func strPtr(s string) *string { return &s }

// --- small mutation helpers ------------------------------------------------

// setKey is dict assignment preserving position (append when new).
func setKey(o validation.Value, key string, val validation.Value) validation.Value {
	for i, kv := range o.O {
		if kv.K == key {
			o.O[i].V = val
			return o
		}
	}
	o.O = append(o.O, validation.KV{K: key, V: val})
	return o
}

// setPath is a deep assignment for fixture mutation: path elements index
// objects by key and arrays by decimal index.
func setPath(t *testing.T, v validation.Value, path []string,
	val validation.Value) validation.Value {
	t.Helper()
	if len(path) == 0 {
		return val
	}
	head, rest := path[0], path[1:]
	if v.Kind == validation.Arr {
		idx, err := strconv.Atoi(head)
		if err != nil || idx < 0 || idx >= len(v.A) {
			t.Fatalf("setPath: bad array index %q", head)
		}
		v.A[idx] = setPath(t, v.A[idx], rest, val)
		return v
	}
	for i, kv := range v.O {
		if kv.K == head {
			v.O[i].V = setPath(t, kv.V, rest, val)
			return v
		}
	}
	t.Fatalf("setPath: no key %q", head)
	return v
}

// --- L-defer T4: the assertion seam is inert without a layout --------------

// dropKey returns v without key (the spec shape a pre-layout caller has).
func dropKey(v validation.Value, key string) validation.Value {
	out := make([]validation.KV, 0, len(v.O))
	for _, kv := range v.O {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	return validation.VObj(out...)
}

// wBridgedVerdict is a one-call counterexample whose final_storage reading
// ("total") a layout can ground: the fixture both the executor fact-row and
// the actor-alias gap row below bridge through harness.BridgeSequenceWithLayout.
func wBridgedVerdict(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{"rule":"inv_1","verdict":"VIOLATED",`+
		`"confidence":"confirmed","failed_assertion":`+
		`{"expression":"total >= before"},"calls":[{"step":0,`+
		`"function":"deposit(uint256)","target":"`+addr("cd")+`",`+
		`"args":["1000"],"env":{"msg.sender":"`+addr("aa")+`",`+
		`"msg.value":"0"},"reverted":false}],`+
		`"final_storage":{"total":"7"}}`)
}

// withoutSpecHash drops the SPEC_HASH line from generated driver text: the
// hash binds the driver to the exact spec, so it legitimately moves when
// final_assertions moves. Comparing the text without it isolates "did the
// RUN change" from "did the document change".
func withoutSpecHash(cmd string) string {
	lines := strings.Split(cmd, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "SPEC_HASH=") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// withLoaderSafeActorKeys renames the bridge's `actor-N` aliases to the
// loader's and driver's role-key spelling (`actor_N`): checkRoleKeys and
// actorFragments both require [A-Za-z][A-Za-z0-9_]*, so the hyphenated
// spelling the bridge emits is refused by the run path — the gap pinned by
// TestBridgedActorAliasesAreRefusedByTheRunPath. Nothing else about the
// bridged document is touched, so the fact-row below stays about the
// assertion seam.
func withLoaderSafeActorKeys(t *testing.T, doc validation.Value) validation.Value {
	t.Helper()
	actors := objAt(doc, "actors")
	for i := range actors.O {
		actors.O[i].K = strings.ReplaceAll(actors.O[i].K, "actor-", "actor_")
	}
	for i, s := range listOf(objAt(doc, "steps")) {
		role := objStr(s, "actor")
		if !strings.HasPrefix(role, "actor-") {
			continue
		}
		setPath(t, doc, []string{"steps", strconv.Itoa(i), "actor"},
			validation.VStr(strings.ReplaceAll(role, "actor-", "actor_")))
	}
	return doc
}

// TestBridgeAbsentLayoutLeavesTheRunUnchanged is the executor fact-row for
// the layout door: when the witness bridge is handed an ABSENT layout (nil)
// or one that grounds nothing the report read, it emits no assertions and
// the run is UNAFFECTED — the document loads through LoadSequenceSpec and
// generates driver text byte-identical to the same spec with no
// final_assertions key at all, with no assertion block (`add_assert`,
// `cast storage`) anywhere in it. The final sub-case is the control that
// makes the negative rows bite: the SAME verdict with a layout that does
// ground the reading grows the storage assertion into the driver.
//
// The actor keys are renamed to the loader's role-key spelling first (see
// withLoaderSafeActorKeys): the bridge's `actor-N` spelling is refused by
// LoadSequenceSpec and BuildCommand alike for a reason that has nothing to
// do with assertions, and the bridge's bytes are frozen by its own
// byte-pins. That divergence is pinned separately below and reported in
// .scratch/t4-report.md.
func TestBridgeAbsentLayoutLeavesTheRunUnchanged(t *testing.T) {
	verdict := wBridgedVerdict(t)
	bridged := func(t *testing.T, layout map[string]string) validation.Value {
		t.Helper()
		doc, refusal := harness.BridgeSequenceWithLayout(verdict,
			"SEQ-MINI-01", "F-abc123", layout)
		if refusal != "" {
			t.Fatalf("bridge refusal = %q", refusal)
		}
		path := filepath.Join(t.TempDir(), "seq.json")
		if err := os.WriteFile(path,
			[]byte(validation.CanonCompact(
				withLoaderSafeActorKeys(t, doc))), 0o644); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadSequenceSpec(path)
		if err != nil {
			t.Fatalf("bridged spec does not load: %v", err)
		}
		return loaded
	}
	for name, layout := range map[string]map[string]string{
		"absent layout (nil)": nil,
		"unsupported layout (names nothing the report read)": {
			"Vault.balance": "3"},
		"unresolvable layout (no target derivable)": {
			"Vault.total": "3"},
	} {
		t.Run(name, func(t *testing.T) {
			loaded := bridged(t, layout)
			cmd, err := BuildCommand(loaded, "/wd")
			if err != nil {
				t.Fatal(err)
			}
			base, err := BuildCommand(dropKey(loaded, "final_assertions"),
				"/wd")
			if err != nil {
				t.Fatal(err)
			}
			// The ONLY line allowed to move is SPEC_HASH: the driver binds
			// itself to the exact spec, and final_assertions is part of that
			// spec, so the hash is supposed to change. No step and no
			// assertion line may.
			if a, b := withoutSpecHash(cmd), withoutSpecHash(base); a != b {
				t.Fatalf("final_assertions moved the run:\n%s\nwant\n%s",
					firstDiff(b, a), b)
			}
			// shHelpers always DEFINES add_assert(); the assertion surface
			// is the call site plus the storage read.
			if strings.Contains(cmd, "ASSERTS=$(add_assert") ||
				strings.Contains(cmd, "cast storage") {
				t.Fatalf("an assertion block was emitted:\n%s", cmd)
			}
		})
	}
	t.Run("control: a grounding layout does reach the driver", func(t *testing.T) {
		cmd, err := BuildCommand(bridged(t, map[string]string{
			"Vault": addr("cd"), "Vault.total": "3"}), "/wd")
		if err != nil {
			t.Fatal(err)
		}
		want := `raw=$(cast storage --rpc-url "$FORK_RPC_URL" ` + addr("cd") +
			` 3 2>"$WD/seq_err.txt") || raw=""`
		if !strings.Contains(cmd, want) {
			t.Fatalf("storage assertion missing\n got %s\nwant line %s",
				firstDiff(want, cmd), want)
		}
	})
}

// TestBridgedActorAliasesAreRefusedByTheRunPath pins an integration gap this
// task's round-trip surfaced, and no more than that: the witness bridge
// aliases its senders `actor-1, actor-2, …` (harness.BridgeSequence,
// byte-pinned in internal/harness/witness_test.go), while the sequence run
// path requires role keys matching [A-Za-z][A-Za-z0-9_]* — such a key
// becomes the shell variable A_<role> and the env var FORK_KEY_<ROLE>, and a
// hyphen is illegal in both. So a bridged document is refused by
// LoadSequenceSpec AND by BuildCommand today; nothing about
// final_assertions changes that.
//
// The bridge's bytes are frozen this wave (its output is pinned
// byte-for-byte, and `actor-1` is documented in
// docs/MINICERTORA_ARCHITECTURE.md §L4), so aligning the spelling belongs
// to the fork wave that first mints a .seq.json from the CLI. This row is
// the evidence a reader of that wave needs; when the spellings are aligned
// the row flips to asserting the round trip.
func TestBridgedActorAliasesAreRefusedByTheRunPath(t *testing.T) {
	doc, refusal := harness.BridgeSequenceWithLayout(wBridgedVerdict(t),
		"SEQ-MINI-01", "F-abc123", map[string]string{
			"Vault": addr("cd"), "Vault.total": "3"})
	if refusal != "" {
		t.Fatalf("bridge refusal = %q", refusal)
	}
	path := filepath.Join(t.TempDir(), "seq.json")
	if err := os.WriteFile(path, []byte(validation.CanonCompact(doc)),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSequenceSpec(path); err == nil ||
		!strings.Contains(err.Error(), "role key") {
		t.Fatalf("loader error = %v, want a role-key refusal", err)
	}
	if _, err := BuildCommand(doc, "/wd"); err == nil ||
		!strings.Contains(err.Error(), "shell-safe") {
		t.Fatalf("driver error = %v, want a shell-safe-identifier refusal",
			err)
	}
}
