package cli

// P2 CLI tests — `mint` (ord 43). Every expected byte is captured from the
// live Python twin by .scratch/t20/capture_cli.py.

import (
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/findings"
)

// TestMintHappy pins the success line and the E4 level.
func TestMintHappy(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := f.fid + ": minted default evidence from " + f.pass +
		" — level E4\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestMintIdempotent pins the no-op line (same exec, same type).
// feedback-triage A2: the no-op is keyed on (exec, type), not exec alone,
// and the message now names the type (intentional divergence from the
// reference wording — KNOWN_DIVERGENCES).
func TestMintIdempotent(t *testing.T) {
	f := t20Setup(t)
	args := []string{"--root", f.root, "mint", f.c.CampaignID, f.fid,
		"--exec", f.pass, "--description", "unit PoC drains", "--tier", "T2"}
	if code, _, errS := run(t, args...); code != 0 {
		t.Fatalf("first mint exit %d: %q", code, errS)
	}
	code, out, errS := run(t, args...)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := f.fid + ": exec " + f.pass + " already minted as foundry-test " +
		"— idempotent no-op (evidence level E4)\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestMintSameExecSecondTypeLands pins feedback-triage A2 at the CLI level:
// after a default (foundry-test) mint, the same exec under a different
// --type must MINT, not no-op.
func TestMintSameExecSecondTypeLands(t *testing.T) {
	f := t20Setup(t)
	if code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2"); code != 0 {
		t.Fatalf("first mint exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "differential pass",
		"--tier", "T2", "--type", "unit-test")
	if code != 0 {
		t.Fatalf("second-type mint exit %d: %q", code, errS)
	}
	want := f.fid + ": minted unit-test evidence from " + f.pass +
		" — level E4\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestMintHostProfileRefused pins the container-profile refusal (exit 2).
func TestMintHostProfileRefused(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID, f.fid,
		"--exec", f.host, "--description", "x")
	want := "mint failed: exec " + f.host + " ran under 'host-readonly'; " +
		"E4+ evidence requires a container/VM profile — re-run the repro " +
		"sandboxed\n"
	if code != 2 || errS != want {
		t.Fatalf("exit %d err\n%q\nwant\n%q", code, errS, want)
	}
}

// TestMintNoTestsRefused pins the forge-meaningfulness refusal (exit 2).
func TestMintNoTestsRefused(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID, f.fid,
		"--exec", f.noTests, "--description", "x")
	want := "mint failed: exec " + f.noTests + ": forge output shows no " +
		"tests were run (ran=0); 'No tests found' is not a reproduction — " +
		"check the --match-test filter / test path and re-run\n"
	if code != 2 || errS != want {
		t.Fatalf("exit %d err\n%q\nwant\n%q", code, errS, want)
	}
}

// TestMintMissingExecIsGenericError pins exit 1 for the missing record
// (Python's FileNotFoundError is not in cmd_mint's except tuple), and that
// the attempt was rolled back so the exec id is not burned.
func TestMintMissingExecIsGenericError(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID, f.fid,
		"--exec", "EXEC-missing", "--description", "x")
	if code != 1 {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "error: [Errno 2] No such file or directory: '" + f.c.ExecsDir +
		"/EXEC-missing/exec_record.json'\n"
	if errS != want {
		t.Fatalf("err\n%q\nwant\n%q", errS, want)
	}
	finding, err := findings.LoadFinding(f.c, f.fid)
	if err != nil {
		t.Fatal(err)
	}
	repro := validation.ObjAt(validation.ObjAt(validation.ObjAt(finding, "verification"), "reproduction"),
		"attempts")
	if len(repro.A) != 0 {
		t.Fatalf("attempts not rolled back: %s", validation.DumpIndentedASCII(repro))
	}
}

// TestMintUnknownFinding pins the generic exit-1 lookup failure.
func TestMintUnknownFinding(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID, "F-nope",
		"--exec", f.pass, "--description", "x")
	if code != 1 || errS != "error: no finding 'F-nope' in "+f.c.CampaignID+
		"\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestMintEmptyDescription pins the --description refusal (exit 2).
func TestMintEmptyDescription(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID, f.fid,
		"--exec", f.pass, "--description", "")
	if code != 2 ||
		errS != "mint requires --description (what the PoC demonstrates)\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestMintTypedEvidence pins the --type echo and the type validation.
func TestMintTypedEvidence(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2", "--type", "unit-test")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := f.fid + ": minted unit-test evidence from " + f.pass +
		" — level E4\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestMintArgparseErrors pins the required/choice error surface.
func TestMintArgparseErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		msg  string
	}{
		{"nothing", []string{"mint"},
			"the following arguments are required: campaign, finding, " +
				"--exec, --description"},
		{"missing-opts", []string{"mint", "C-x", "F-y"},
			"the following arguments are required: --exec, --description"},
		{"exec-eats-option", []string{"mint", "C-x", "F-y", "--exec",
			"--help"},
			"argument --exec: expected one argument"},
		{"description-eats-option", []string{"mint", "C-x", "F-y",
			"--exec", "E", "--description", "--help"},
			"argument --description: expected one argument"},
		{"bad-tier", []string{"mint", "C-x", "F-y", "--exec", "E",
			"--description", "d", "--tier", "T9"},
			"argument --tier: invalid choice: 'T9' (choose from 'T1', 'T2', " +
				"'T3', 'T4')"},
		{"bad-type", []string{"mint", "C-x", "F-y", "--exec", "E",
			"--description", "d", "--type", "nope"},
			"argument --type: invalid choice: 'nope' (choose from " +
				"'balance-delta', 'differential', 'fork-test', " +
				"'foundry-test', 'fuzz', 'historical-analog', " +
				"'invariant-test', 'manual', 'reachability', 'reasoning', " +
				"'static-analysis', 'symbolic-witness', 'trace', " +
				"'unit-test')"},
	}
	for _, tc := range cases {
		code, _, errS := run(t, tc.args...)
		if code != 2 {
			t.Fatalf("%s: exit %d", tc.name, code)
		}
		want := argparseUsageBlocks["mint"] +
			"webv2 mint: error: " + tc.msg + "\n"
		if errS != want {
			t.Fatalf("%s: err\n%q\nwant\n%q", tc.name, errS, want)
		}
	}
}

// TestMintHelp pins the help surface (the --type choice list included).
func TestMintHelp(t *testing.T) {
	code, out, errS := run(t, "mint", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, "usage: webv2 mint [-h] --exec EXEC_ID "+
		"--description DESCRIPTION\n") ||
		!strings.Contains(out, "--tier {T1,T2,T3,T4}") ||
		!strings.Contains(out, "symbolic-witness,trace,unit-test}") {
		t.Fatalf("out %q", out)
	}
}
