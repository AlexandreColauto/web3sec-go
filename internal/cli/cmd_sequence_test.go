// Port of tests/test_sequence_guidance.py's CLI half — argparse parity for
// the `sequence` subparser (pinned from the live CLI at COLUMNS=80) and the
// run/verify handler exit contract (0/2/3, one stderr line, no traceback).
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/findings"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// --- argparse parity -------------------------------------------------------

func TestSequenceArgparseParity(t *testing.T) {
	root := mkroot(t)
	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"no-subcommand", []string{"sequence"}, 2, "",
			t14SequenceUsage + "webv2 sequence: error: the following " +
				"arguments are required: sequence_cmd\n"},
		{"unknown-flag", []string{"sequence", "--bogus"}, 2, "",
			t14SequenceUsage + "webv2 sequence: error: the following " +
				"arguments are required: sequence_cmd\n"},
		{"invalid-choice", []string{"sequence", "bogus"}, 2, "",
			t14SequenceUsage + "webv2 sequence: error: argument " +
				"sequence_cmd: invalid choice: 'bogus' (choose from 'run', " +
				"'verify')\n"},
		{"help", []string{"sequence", "-h"}, 0, t14SequenceHelp, ""},
		{"run-help", []string{"sequence", "run", "-h"}, 0,
			t14SequenceRunHelp, ""},
		{"verify-help", []string{"sequence", "verify", "-h"}, 0,
			t14SequenceVerifyHelp, ""},
		{"run-missing-all", []string{"sequence", "run"}, 2, "",
			t14SequenceRunUsage + "webv2 sequence run: error: the following " +
				"arguments are required: campaign, spec, --finding\n"},
		{"run-missing-two", []string{"sequence", "run", "C-1"}, 2, "",
			t14SequenceRunUsage + "webv2 sequence run: error: the following " +
				"arguments are required: spec, --finding\n"},
		{"run-finding-no-value", []string{"sequence", "run", "--finding"}, 2,
			"", t14SequenceRunUsage + "webv2 sequence run: error: argument " +
				"--finding: expected one argument\n"},
		{"run-workdir-no-value", []string{"sequence", "run", "C-1", "s.json",
			"--finding", "F-x", "--workdir"}, 2, "",
			t14SequenceRunUsage + "webv2 sequence run: error: argument " +
				"--workdir: expected one argument\n"},
		{"verify-missing", []string{"sequence", "verify", "C-1"}, 2, "",
			t14SequenceVerifyUsage + "webv2 sequence verify: error: the " +
				"following arguments are required: finding\n"},
		{"verify-exec-no-value", []string{"sequence", "verify", "C-1", "F-x",
			"--exec"}, 2, "", t14SequenceVerifyUsage + "webv2 sequence " +
			"verify: error: argument --exec: expected one argument\n"},
		{"run-unknown-flag-loses-to-missing", []string{"sequence", "run",
			"C-1", "--bogus"}, 2, "",
			t14SequenceRunUsage + "webv2 sequence run: error: the following " +
				"arguments are required: spec, --finding\n"},
		{"verify-unknown-flag-loses-to-missing", []string{"sequence", "verify",
			"C-1", "--bogus"}, 2, "",
			t14SequenceVerifyUsage + "webv2 sequence verify: error: the " +
				"following arguments are required: finding\n"},
		{"run-finding-value-looks-like-option", []string{"sequence", "run",
			"--finding", "-h", "C-1", "s.json"}, 2, "",
			t14SequenceRunUsage + "webv2 sequence run: error: argument " +
				"--finding: expected one argument\n"},
		{"run-workdir-value-looks-like-option", []string{"sequence", "run",
			"C-1", "s.json", "--finding", "F-x", "--workdir", "--bogus"}, 2, "",
			t14SequenceRunUsage + "webv2 sequence run: error: argument " +
				"--workdir: expected one argument\n"},
		{"verify-exec-value-looks-like-option", []string{"sequence", "verify",
			"C-1", "F-x", "--exec", "--bogus"}, 2, "",
			t14SequenceVerifyUsage + "webv2 sequence verify: error: " +
				"argument --exec: expected one argument\n"},
		{"run-attached-value", []string{"sequence", "run", "C-1", "s.json",
			"--finding=F-x", "--workdir=/tmp"}, 1, "",
			"error: malformed campaign id: 'C-1'\n"},
		{"run-bare-dash-value", []string{"sequence", "run", "C-1", "s.json",
			"--finding", "-"}, 1, "", "error: malformed campaign id: 'C-1'\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errS := run(t, append([]string{"--root", root},
				tc.args...)...)
			if code != tc.code || out != tc.stdout || errS != tc.stderr {
				t.Fatalf("code=%d out=%q err=%q\nwant code=%d out=%q err=%q",
					code, out, errS, tc.code, tc.stdout, tc.stderr)
			}
		})
	}
}

// TestSequenceRunHelpStatesTheCoverageRule pins D5's documentation half: the
// operator learns the coverage rule from --help, not only from a failed run.
func TestSequenceRunHelpStatesTheCoverageRule(t *testing.T) {
	code, out, errS := run(t, "sequence", "run", "--help")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "coverage: the executed steps must use every "+
		"actor the finding's exploit_sequence declares") {
		t.Fatalf("help = %q", flat)
	}
	if !strings.Contains(flat, "a declared role that sends no transaction "+
		"still counts until that sequence drops it") {
		t.Fatalf("help = %q", flat)
	}
	for _, line := range strings.Split(out, "\n") {
		if utf8.RuneCountInString(line) > 80 {
			t.Fatalf("help line exceeds 80 columns: %q", line)
		}
	}
}

func TestSequenceUnrecognizedUsesRootUsage(t *testing.T) {
	root := mkroot(t)
	cases := [][]string{
		{"sequence", "run", "C-1", "s.json", "--finding", "F-x", "--bogus"},
		{"sequence", "verify", "C-1", "F-x", "--bogus"},
		{"sequence", "run", "C-1", "s.json", "extra", "--finding", "F-x"},
		{"sequence", "run", "C-1", "s.json", "--finding", "F-x", "e2", "e3"},
		{"sequence", "run", "C-1", "s.json", "extra", "--bogus",
			"--finding", "F-x"},
		{"sequence", "verify", "C-1", "F-x", "extra", "--bogus"},
	}
	wantArg := []string{"--bogus", "--bogus", "extra", "e2 e3",
		"extra --bogus", "extra --bogus"}
	for i, args := range cases {
		code, _, errS := run(t, append([]string{"--root", root}, args...)...)
		if code != 2 {
			t.Errorf("case %d exit %d, want 2", i, code)
		}
		want := t14TopUsage + "webv2: error: unrecognized arguments: " +
			wantArg[i] + "\n"
		if errS != want {
			t.Errorf("case %d stderr = %q, want %q", i, errS, want)
		}
	}
}

// --- handler contract ------------------------------------------------------

// seqCLISeq is SEQ from test_sequence_guidance.py.
func seqCLISeq(t *testing.T) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(`[
      {"step": 1, "actor": "alice", "action": "deposit"},
      {"step": 2, "actor": "bob", "action": "drain"}]`))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// seqCLIFinding is _mk: a live finding with the requested exploit_sequence.
func seqCLIFinding(t *testing.T, root, cid string, seq validation.Value) string {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := validation.ParseOrdered([]byte(`{
      "title": "multi-tx sequence bug",
      "root_cause": {"class": "access-control",
                     "description": "missing check across two calls"},
      "affected": [{"path": "src/V.sol", "contract": "V",
                    "function": "claim"}],
      "attacker": {"profile": "arbitrary EOA", "capabilities": []}}`))
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f = seqSetKey(f, "status", validation.VStr("POSSIBLE"))
	if seq.Kind == validation.Arr {
		f = seqSetKey(f, "exploit_sequence", seq)
	}
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return fid
}

// seqSetKey is dict assignment preserving position.
func seqSetKey(o validation.Value, key string,
	v validation.Value) validation.Value {
	for i, kv := range o.O {
		if kv.K == key {
			o.O[i].V = v
			return o
		}
	}
	o.O = append(o.O, validation.KV{K: key, V: v})
	return o
}

// plantFinding hand-edits a finding file on disk, bypassing save_finding's
// schema validation (Python's _plant).
func plantFinding(t *testing.T, root, cid, fid string, mutate func(validation.Value) validation.Value) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	p := findings.FindingPath(c, fid)
	f, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	f = mutate(f)
	body, err := json.Marshal(jsonAny(f))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// jsonAny converts a Value to a Go any for a lossless JSON round-trip.
func jsonAny(v validation.Value) any {
	switch v.Kind {
	case validation.Null:
		return nil
	case validation.Bool:
		return v.B
	case validation.Int:
		if v.Big != "" {
			return json.Number(v.Big)
		}
		return json.Number(strings.TrimSpace(validation.PythonFloat(float64(v.I))))
	case validation.Flt:
		return v.F
	case validation.Str:
		return v.S
	case validation.Arr:
		out := make([]any, len(v.A))
		for i, it := range v.A {
			out[i] = jsonAny(it)
		}
		return out
	case validation.Obj:
		out := map[string]any{}
		for _, kv := range v.O {
			out[kv.K] = jsonAny(kv.V)
		}
		return out
	}
	return nil
}

func TestSequenceRunErrorConvention(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	bad := filepath.Join(root, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "sequence", "run", cid, bad,
		"--finding", "F-x")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (out=%q err=%q)", code, out, errS)
	}
	if !strings.Contains(errS, "sequence run failed") ||
		strings.Contains(errS, "Traceback") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestSequenceVerifyExitCodes(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := seqCLIFinding(t, root, cid, seqCLISeq(t))
	// no attempts yet -> FAIL, exit 3
	code, out, errS := run(t, "--root", root, "sequence", "verify", cid, fid)
	if code != 3 {
		t.Fatalf("exit %d, want 3 (out=%q err=%q)", code, out, errS)
	}
	if !strings.Contains(out, "no recorded attempts trace to exec records") {
		t.Errorf("stdout = %q", out)
	}
	// unknown finding -> error, exit 2
	code, _, errS = run(t, "--root", root, "sequence", "verify", cid, "F-nope")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "sequence verify failed") {
		t.Errorf("stderr = %q", errS)
	}
}

func TestSequenceVerifyUnknownExecExit2(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := seqCLIFinding(t, root, cid, seqCLISeq(t))
	code, _, errS := run(t, "--root", root, "sequence", "verify", cid, fid,
		"--exec", "EXEC-nope")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "unknown exec") ||
		strings.Contains(errS, "Traceback") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestSequenceVerifyNotRequiredIsVacuous(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := seqCLIFinding(t, root, cid, validation.VNull())
	code, out, errS := run(t, "--root", root, "sequence", "verify", cid, fid)
	if code != 0 {
		t.Fatalf("exit %d, want 0 (out=%q err=%q)", code, out, errS)
	}
	if !strings.Contains(out, "not sequence-required") {
		t.Errorf("stdout = %q", out)
	}
}

func TestSequenceVerifyMalformedBlocksNoTraceback(t *testing.T) {
	// I2 pin: attempts=None and verification="confirmed" (which the gate
	// normalizes fail-closed) must follow the CLI's exit-0/2/3 convention —
	// no unhandled traceback, no exit 1.
	root := mkroot(t)
	cid := initOne(t, root)
	fid := seqCLIFinding(t, root, cid, seqCLISeq(t))
	mutations := []func(validation.Value) validation.Value{
		func(f validation.Value) validation.Value {
			return seqSetKey(f, "verification", mustJSON(t,
				`{"reproduction": {"attempts": null}}`))
		},
		func(f validation.Value) validation.Value {
			return seqSetKey(f, "verification",
				validation.VStr("confirmed"))
		},
		func(f validation.Value) validation.Value {
			return seqSetKey(f, "verification", mustJSON(t,
				`{"reproduction": {"attempts": ["bad", null, 42]}}`))
		},
	}
	for i, mutate := range mutations {
		plantFinding(t, root, cid, fid, mutate)
		code, _, errS := run(t, "--root", root, "sequence", "verify", cid, fid)
		if code != 3 {
			t.Errorf("case %d exit %d, want 3 (err=%q)", i, code, errS)
		}
		if strings.Contains(errS, "Traceback") {
			t.Errorf("case %d traceback: %q", i, errS)
		}
	}
}

// TestSequenceRunSuccessSingleLoad pins the happy path: the summary line
// comes from ONE captured spec load, run_sequence is called once, and no
// SystemExit/traceback happens. The stub corrupts the spec file after the
// first load, so a second CLI-side load would fail the command — the
// behavioral equivalent of Python's load counter.
func TestSequenceRunSuccessSingleLoad(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := seqCLIFinding(t, root, cid, seqCLISeq(t))
	spec := `{"spec_id": "SEQ-TEST-04", "finding_id": "` + fid + `",
      "actors": {"attacker": "anvil:0", "victim": "0x` + strings.Repeat("aa", 20) + `"},
      "steps": [
        {"step": 1, "actor": "attacker", "target": "0x` + strings.Repeat("cd", 20) + `",
         "function": "deposit(uint256)", "args": ["1"]},
        {"step": 2, "actor": "victim", "target": "0x` + strings.Repeat("cd", 20) + `",
         "function": "drain()"}],
      "final_assertions": []}`
	specPath := filepath.Join(root, "spec.json")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := sequencepoc.RunSequenceFunc
	t.Cleanup(func() { sequencepoc.RunSequenceFunc = prev })
	calls := 0
	sequencepoc.RunSequenceFunc = func(c *state.Campaign, p string,
		opts sequencepoc.RunSequenceOpts) (validation.Value, error) {
		calls++
		// A second CLI-side load would now hit invalid JSON.
		if err := os.WriteFile(p, []byte("{broken"), 0o644); err != nil {
			return validation.VNull(), err
		}
		return mustJSON(t, `{"exec_id": "EXEC-stub1", "exit_status": 0,
          "stderr_path": "`+filepath.Join(root, "e.err")+`"}`), nil
	}
	code, out, errS := run(t, "--root", root, "sequence", "run", cid, specPath,
		"--finding", fid)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "EXEC-stub1") || !strings.Contains(out, "steps=2") {
		t.Errorf("stdout = %q", out)
	}
	if !strings.Contains(out, "sequence verify") ||
		!strings.Contains(out, cid) || !strings.Contains(out, fid) {
		t.Errorf("verify hint incomplete: %q", out)
	}
	if calls != 1 {
		t.Errorf("run_sequence calls = %d, want 1", calls)
	}
}

func TestSequenceRunForwardsWorkdirAndFinding(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := seqCLIFinding(t, root, cid, seqCLISeq(t))
	spec := `{"spec_id": "SEQ-TEST-05", "finding_id": "` + fid + `",
      "actors": {"a": "anvil:0"},
      "steps": [{"step": 1, "actor": "a", "target": "0x` +
		strings.Repeat("cd", 20) + `", "function": "f()"},
                {"step": 2, "actor": "a", "target": "0x` +
		strings.Repeat("cd", 20) + `", "function": "g()"}],
      "final_assertions": []}`
	specPath := filepath.Join(root, "spec.json")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	wd := filepath.Join(root, "wd")
	prev := sequencepoc.RunSequenceFunc
	t.Cleanup(func() { sequencepoc.RunSequenceFunc = prev })
	var gotFinding, gotWorkdir string
	sequencepoc.RunSequenceFunc = func(c *state.Campaign, p string,
		opts sequencepoc.RunSequenceOpts) (validation.Value, error) {
		if opts.FindingID != nil {
			gotFinding = *opts.FindingID
		}
		if opts.Workdir != nil {
			gotWorkdir = *opts.Workdir
		}
		return mustJSON(t, `{"exec_id": "EXEC-stub2", "exit_status": 1,
          "stderr_path": "e.err"}`), nil
	}
	code, out, _ := run(t, "--root", root, "sequence", "run", cid, specPath,
		"--finding", fid, "--workdir", wd)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if gotFinding != fid || gotWorkdir != wd {
		t.Errorf("finding=%q workdir=%q, want %q/%q", gotFinding, gotWorkdir,
			fid, wd)
	}
	if !strings.Contains(out, "T4 attempt recorded as failed (exit 1)") ||
		!strings.Contains(out, "inspect e.err") {
		t.Errorf("stdout = %q", out)
	}
}

// mustJSON parses a fixture literal.
func mustJSON(t *testing.T, text string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(text))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return v
}
