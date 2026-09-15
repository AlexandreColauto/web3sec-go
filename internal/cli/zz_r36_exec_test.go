package cli

// r36 hostile-audit pins at the CLI boundary (`webv2 exec`, cmd_exec.go) —
// the sibling of internal/sandbox/zz_r36_test.go, which pins the sandbox
// side of the same findings. (Named zz_r36_exec_test.go because the
// assigned name zz_r36_test.go was concurrently taken by another agent's
// unwind-on-refusal pins.) Each pin names the finding it closes:
//
//	CLI-1  --timeout validation: 0 / negative / int64-range / duration-
//	       overflow must fail closed with the argparse contract (exit 2,
//	       usage block, one error line) BEFORE any run or record; the
//	       pre-fix code accepted 0 and -5 and the sandbox silently ran
//	       them as its 300s default, and accepted a duration-overflowing
//	       count whose kill timer wraps into an instant kill recorded as
//	       a timeout of the requested length — a lying record.
//	CLI-2  the operator must hear the sandbox's own timeout/kill note and
//	       the output_capture accounting on a FAILED run (forwarded
//	       verbatim from the record; nothing invented on absence), while
//	       the success-path stdout shape stays byte-identical.
//
// No docker is needed: the run-path pins use the host-readonly profile.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
)

// TestR36ExecTimeoutRefusals pins CLI-1: every invalid --timeout is
// refused with exit 2 + the argparse rendering, and no EXEC record is
// written on any refusal path.
func TestR36ExecTimeoutRefusals(t *testing.T) {
	f := t20Setup(t)
	cases := []struct {
		name, val, msg string
	}{
		{"zero", "0",
			"argument --timeout: must be a positive number of seconds " +
				"(got 0) — the sandbox cannot honor a zero or negative " +
				"timeout; re-run with --timeout N where N >= 1"},
		{"negative", "-5",
			"argument --timeout: must be a positive number of seconds " +
				"(got -5) — the sandbox cannot honor a zero or negative " +
				"timeout; re-run with --timeout N where N >= 1"},
		{"duration-overflow", "9223372037",
			"argument --timeout: 9223372037 seconds exceeds the largest " +
				"timeout the sandbox can honor (9223372036) — re-run with " +
				"a smaller --timeout"},
		{"int64-range", "99999999999999999999",
			"argument --timeout: invalid int value: '99999999999999999999'"},
	}
	for _, tc := range cases {
		before := execRecordCount(t, f)
		code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
			"--profile", "host-readonly", "--command", "true",
			"--timeout", tc.val)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2", tc.name, code)
		}
		want := argparseUsageBlocks["exec"] +
			"webv2 exec: error: " + tc.msg + "\n"
		if errS != want {
			t.Fatalf("%s: err\n%q\nwant\n%q", tc.name, errS, want)
		}
		if after := execRecordCount(t, f); after != before {
			t.Fatalf("%s: a refusal wrote an EXEC record (%d -> %d)",
				tc.name, before, after)
		}
	}
}

// TestR36ExecTimeoutReachesSandbox pins CLI-1's happy path: a valid
// --timeout is forwarded to Sandbox.run unchanged, and the absent flag
// keeps the 300s default.
func TestR36ExecTimeoutReachesSandbox(t *testing.T) {
	f := t20Setup(t)
	stub := &stubExecSandbox{}
	prev := newExecSandbox
	newExecSandbox = func(c *state.Campaign,
		profile string) (execSandbox, error) {
		return stub, nil
	}
	t.Cleanup(func() { newExecSandbox = prev })
	if code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true",
		"--timeout", "42"); code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if stub.opts.Timeout != 42 {
		t.Fatalf("Sandbox.run got timeout %d, want 42", stub.opts.Timeout)
	}
	if code, _, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true"); code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if stub.opts.Timeout != 300 {
		t.Fatalf("Sandbox.run got timeout %d, want the 300 default",
			stub.opts.Timeout)
	}
}

// TestR36ExecSuccessStdoutShapeUnchanged pins CLI-2's boundary: a
// successful run's stdout is byte-identical to the pre-fix shape — the
// note/capture forwarding must never fire on exit 0.
func TestR36ExecSuccessStdoutShapeUnchanged(t *testing.T) {
	f := t20Setup(t)
	prev := newExecSandbox
	newExecSandbox = func(c *state.Campaign,
		profile string) (execSandbox, error) {
		return &stubExecSandbox{}, nil
	}
	t.Cleanup(func() { newExecSandbox = prev })
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "true")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	want := "EXEC-stub  [host-readonly] exit=0 true\n" +
		"output: /dev/null / /dev/null (mint with `webv2 mint ... " +
		"--exec EXEC-stub`)\n" +
		"  (host-readonly ran on the host — this exec can NEVER back E4+ " +
		"evidence; use a container profile for that)\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestR36ExecTimeoutNoteForwardedToOperator pins CLI-2: a host-readonly
// run killed by --timeout prints exit=-1 AND the sandbox's own note line,
// forwarded verbatim from the record's stderr log — and nothing the
// sandbox did not say (no survivor claim beyond the sandbox's own).
func TestR36ExecTimeoutNoteForwardedToOperator(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--command", "sleep 30",
		"--timeout", "1")
	if code != 0 {
		t.Fatalf("exec verb exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "] exit=-1 sleep 30") {
		t.Fatalf("summary line missing exit=-1: %q", out)
	}
	// The forwarded note is the LAST line of the record's stderr.log.
	execID := out[:strings.Index(out, "  [")]
	raw, err := os.ReadFile(filepath.Join(f.c.ExecsDir, execID,
		"stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimRight(string(raw), "\n")
	note := text[strings.LastIndexByte(text, '\n')+1:]
	if !strings.HasPrefix(note, "sandbox: timed out after 1s") {
		t.Fatalf("stderr.log lacks the sandbox note: %q", note)
	}
	if !strings.Contains(out, "  "+note+"\n") {
		t.Fatalf("stdout must forward the sandbox note verbatim\n"+
			"note: %q\nout: %q", note, out)
	}
	if strings.Contains(out, "STILL RUNNING") ||
		strings.Contains(out, "REMAINS RUNNING") {
		t.Fatalf("stdout claims a survivor the sandbox never reported: %q",
			out)
	}
}

// TestR36ExecSuccessTruncationKeepsShape pins the exit-0 boundary of the
// F6 forward: a run whose captured LOG hit the cap still exits 0 and
// keeps the documented stdout shape (the marker lives in the log and the
// record's output_capture; truncation of the capture is not a failure of
// the run, and the CLI must not invent one).
func TestR36ExecSuccessTruncationKeepsShape(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--timeout", "60",
		"--command", "head -c 30000000 /dev/zero | tr '\\0' 'x'")
	if code != 0 {
		t.Fatalf("exec verb exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "] exit=0 ") || strings.Contains(out, "truncated") {
		t.Fatalf("an exit-0 run must keep the documented stdout shape: %q",
			out)
	}
	stdoutLog, err := os.ReadFile(filepath.Join(f.c.ExecsDir,
		out[:strings.Index(out, "  [")], "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stdoutLog), "TRUNCATED") {
		t.Fatalf("stdout.log lacks the truncation marker (tail: %q)",
			stdoutLog[max(0, len(stdoutLog)-200):])
	}
}

// TestR36ExecTruncationOnFailureForwarded pins the failure-path forward:
// an exit!=0 run whose capture was truncated prints the capture note with
// the record's own counts, before the classified line.
func TestR36ExecTruncationOnFailureForwarded(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "exec", f.c.CampaignID,
		"--profile", "host-readonly", "--timeout", "60",
		"--command", "head -c 30000000 /dev/zero | tr '\\0' 'x'; exit 3")
	if code != 0 {
		t.Fatalf("exec verb exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "] exit=3 ") {
		t.Fatalf("summary line: %q", out)
	}
	want := "  stdout truncated: the run wrote 30000000 bytes and the " +
		"capture keeps at most 10485760 — the log on disk is marked truncated\n"
	if !strings.Contains(out, want) {
		t.Fatalf("capture note missing:\nout: %q\nwant: %q", out, want)
	}
}
