package cli

// P1b CLI tests — `verdict` (ord 45).
//
// Ports: tests/test_cli.py::test_verdict_prints_full_reason (the round-3
// feedback: the console line truncated what was persisted) plus the
// argparse surface and the unknown-finding shape.

import (
	"strings"
	"testing"
)

func TestVerdictPrintsFullReason(t *testing.T) {
	c, root := t15Campaign(t, "verdict")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	reason := "the attacker controls the share price through the " +
		"first-depositor position and the direct-transfer path is " +
		"unbounded" + strings.Repeat(" ", 20) +
		"trailing detail that must survive"
	if len(reason) <= 60 {
		t.Fatal("fixture must exceed the old 60-char cap")
	}
	code, out, errS := run(t, "--root", root, "verdict", c.CampaignID, fid,
		"--verdict", "confirmed", "--reason", reason)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, reason) {
		t.Fatalf("output %q must carry the FULL reason", out)
	}
	if !strings.Contains(out, "critic_reasoning") {
		t.Fatalf("output %q must name the persistence location", out)
	}
	if !strings.HasPrefix(out, "critic verdict on "+fid+": confirmed\n") {
		t.Fatalf("first line %q", strings.SplitN(out, "\n", 2)[0])
	}
}

func TestVerdictInvalidChoiceIsArgparse(t *testing.T) {
	code, _, errS := run(t, "verdict", "C-x", "F-x", "--verdict", "bogus",
		"--reason", "r")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["verdict"] +
		"webv2 verdict: error: argument --verdict: invalid choice: 'bogus' " +
		"(choose from 'pending', 'confirmed', 'possible', 'disproved', " +
		"'duplicate', 'out_of_scope', 'informational')\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestVerdictMissingOptionsIsArgparse(t *testing.T) {
	code, _, errS := run(t, "verdict", "C-x", "F-x")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["verdict"] +
		"webv2 verdict: error: the following arguments are required: " +
		"--verdict, --reason\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestVerdictUnknownFinding(t *testing.T) {
	c, root := t15Campaign(t, "verdict")
	code, _, errS := run(t, "--root", root, "verdict", c.CampaignID,
		"F-000000000000", "--verdict", "confirmed", "--reason", "r")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errS, "no finding 'F-000000000000'") {
		t.Fatalf("stderr %q", errS)
	}
}
