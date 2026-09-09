// Shared fixtures for the sequence_poc port tests. Port of the module
// helpers in tests/test_sequence_{spec,runner,coverage,guidance,pin_gate}.py.
package sequencepoc

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// mustParse parses a JSON literal into the ordered Value.
func mustParse(t *testing.T, text string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(text))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return v
}

// addr is `"0x" + b * 20`.
func addr(b string) string { return "0x" + strings.Repeat(b, 20) }

// testCampaign is Campaign.init(tmp_path, "test-program").
func testCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatalf("Campaign.init: %v", err)
	}
	return c
}

// writeSpec writes a spec JSON to <dir>/spec.json.
func writeSpec(t *testing.T, dir string, spec validation.Value) string {
	t.Helper()
	p := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(p, []byte(validation.DumpIndented(spec)), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	return p
}

// writeSpecText writes raw spec text (malformed-JSON fixtures).
func writeSpecText(t *testing.T, dir, text string) string {
	t.Helper()
	p := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	return p
}

// driverRun is _run_driver: install the stub `cast` in the workdir, build
// the command with that workdir, run it under /bin/sh, and return
// (exit, stdout, stderr, workdir).
func driverRun(t *testing.T, spec validation.Value, stub, tag string) (int, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	wd := filepath.Join(dir, tag)
	if err := os.MkdirAll(wd, 0o755); err != nil {
		t.Fatalf("mkdir wd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wd, "cast"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write stub cast: %v", err)
	}
	cmdStr, err := BuildCommand(spec, wd)
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	cmd.Env = append(os.Environ(),
		"PATH="+wd+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FORK_RPC_URL=http://stub")
	err = cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("driver run: %v", err)
		}
	}
	return code, out.String(), errBuf.String(), wd
}

// stubCast is STUB_CAST from test_sequence_runner.py, verbatim.
const stubCast = `#!/bin/sh
case "$1" in
  rpc)
    case "$*" in
      *anvil_mine*) exit 0 ;;
      *evm_mine*) echo "stub: evm_mine is not used by the driver" >&2; exit 1 ;;
      *eth_accounts*) printf '%s\n' '["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","0x70997970c51812dc3a010c7d01b50e0d17dc79c8"]' ;;
      *) exit 0 ;;
    esac ;;
  send)
    if [ -f .sent_once ]; then
      echo "execution reverted: claim too early" >&2
      exit 1
    fi
    touch .sent_once
    printf '%s\n' "blockNumber 20000001" "transactionHash 0xdeadbeef0000000000000000000000000000000000000000000000000000cafe"
    exit 0 ;;
  balance)
    printf '%s\n' "0xde0b6b3a7640000"
    exit 0 ;;
  storage)
    printf '%s\n' "0x10000000000000000"
    exit 0 ;;
  call)
    printf '%s\n' "7"
    exit 0 ;;
  *) exit 0 ;;
esac
`

// runnerSpec is SPEC from test_sequence_runner.py.
func runnerSpec(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{
  "spec_id": "SEQ-TEST-02", "finding_id": "F-run1",
  "actors": {"attacker": "anvil:0", "victim": "`+addr("bb")+`"},
  "steps": [
    {"step": 1, "actor": "attacker", "target": "`+addr("cd")+`",
     "function": "deposit(uint256)", "args": ["1000"]},
    {"step": 2, "actor": "victim", "target": "`+addr("cd")+`",
     "function": "claim()", "mine_blocks": 3, "expect_revert": true}
  ],
  "final_assertions": [
    {"id": "A1", "kind": "balance", "account": "attacker",
     "op": ">=", "value": "2000"},
    {"id": "A2", "kind": "storage", "target": "`+addr("cd")+`", "slot": "5",
     "op": "==", "value": "18446744073709551616"}
  ]
}`)
}

// readResult loads sequence_result.json from a driver workdir.
func readResult(t *testing.T, wd string) validation.Value {
	t.Helper()
	p := filepath.Join(wd, "sequence_result.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("no sequence_result.json in %s: %v", wd, err)
	}
	v, err := validation.ReadJson(p)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	return v
}

// stepsOf is result["steps"] as a slice.
func stepsOf(t *testing.T, result validation.Value) []validation.Value {
	t.Helper()
	steps := objAt(result, "steps")
	if steps.Kind != validation.Arr {
		t.Fatalf("result steps is %v", steps.Kind)
	}
	return steps.A
}

// assertStep is one step record's (status, tx_hash, revert_reason).
func stepStatus(s validation.Value) string { return objStr(s, "status") }
