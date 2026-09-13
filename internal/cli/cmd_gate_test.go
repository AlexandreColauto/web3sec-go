package cli

// P1b CLI tests — `gate` (ord 56).
//
// Ports: tests/test_cli_gate_dryrun.py (the failing-check list with fixes,
// the unknown-finding exit 2, and the all-pass dry-run BEFORE any status
// move), tests/test_cli.py::test_gate_empty_message (no policy → the error
// is about the policy), and the --explain surface.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

func TestGateDryrunListsFailingChecksWithFixes(t *testing.T) {
	c, root := t15Campaign(t, "gate")
	f := t15Finding(t, c, "an inflation hypothesis", "first-depositor-inflation")
	fid := objStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	for _, want := range []string{"check(s) failing:", "critic-verdict", "fix:",
		"memory-check", "evidence-floor"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(out, fid+" (status HYPOTHESIS): CONFIRMED gate — ") {
		t.Fatalf("first line %q", strings.SplitN(out, "\n", 2)[0])
	}
	if !strings.Contains(out, "since last attempt: (none recorded)") {
		t.Fatalf("output must report the delta:\n%s", out)
	}
}

func TestGateDryrunUnknownFindingExits2(t *testing.T) {
	c, root := t15Campaign(t, "gate")
	code, _, errS := run(t, "--root", root, "gate", c.CampaignID,
		"F-doesnotexist00")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "no finding") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestGateDryrunAllChecksPass is tests/test_cli_gate_dryrun.py::
// test_dryrun_passes_when_all_checks_met: a logic-error finding (the E4
// floor class) that satisfies every clause reports all-pass and exits 0
// BEFORE any status move.
func TestGateDryrunAllChecksPass(t *testing.T) {
	c, root := t15Campaign(t, "gate-pass")
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := t15Finding(t, c, "a logic flow hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	rec := t15ExecRecordFor(t, c, "EXEC-0000000001", fid)
	item := validation.VObj(
		kvT("evidence_id", validation.VStr("EV-1")),
		kvT("level", validation.VStr("E4")),
		kvT("type", validation.VStr("foundry-test")),
		kvT("description", validation.VStr("PoC passes")),
		kvT("sandbox_profile", objAt(rec, "profile")),
		kvT("artifact_id", objAt(rec, "exec_id")),
	)
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	// mint also stamps the reproduction status the gate's reproduction
	// clause reads (findings.mint: verification.reproduction).
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDictCLI(objAt(vf, "verification"))
	ver = setObjFieldCLI(ver, "reproduction", validation.VObj(
		kvT("tier_reached", validation.VStr("T2")),
		kvT("status", validation.VStr("reproduced")),
		kvT("attempts", validation.VArr())))
	vf = setObjFieldCLI(vf, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if code, _, errS := run(t, "--root", root, "verdict", c.CampaignID, fid,
		"--verdict", "confirmed", "--reason", "mechanism sound"); code != 0 {
		t.Fatalf("verdict exit %d: %q", code, errS)
	}
	if code, _, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", fid, "--mode", "negative"); code != 0 {
		t.Fatalf("recall exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, "all checks pass") {
		t.Fatalf("output %q", out)
	}
}

func TestGateAllRequiresPolicy(t *testing.T) {
	c, root := t15Campaign(t, "gate")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if !strings.Contains(errS, "policy") {
		t.Fatalf("stderr %q must be about the policy", errS)
	}
}

func TestGateNoArgsPrintsItsOwnUsage(t *testing.T) {
	code, _, errS := run(t, "gate")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if errS != "usage: webv2 gate <campaign> [FINDING] | "+
		"webv2 gate --explain <CHECK>\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestGateExplain(t *testing.T) {
	code, out, errS := run(t, "gate", "--explain", "critic-verdict")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "check:      critic-verdict  (gate: confirmed)") ||
		!strings.Contains(out, "remediation: webv2 verdict <campaign> <fid> --verdict confirmed") {
		t.Fatalf("output %q", out)
	}
}

func TestGateExplainUnknownCheckExits2(t *testing.T) {
	code, _, errS := run(t, "gate", "--explain", "no-such-check")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.HasPrefix(errS,
		"gate explain failed: \"unknown check id 'no-such-check' (known: [") {
		t.Fatalf("stderr %q", errS)
	}
}

func TestGateExplainMissingValueIsArgparse(t *testing.T) {
	code, _, errS := run(t, "gate", "--explain")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["gate"] +
		"webv2 gate: error: argument --explain: expected one argument\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// t15ExecRecordFor writes a finished exec record bound to a finding.
func t15ExecRecordFor(t *testing.T, c *state.Campaign, execID,
	findingID string) validation.Value {
	t.Helper()
	dir := c.ExecsDir + "/" + execID
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := dir + "/stdout.log"
	if err := os.WriteFile(stdout, []byte("PASS: test_exploit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr("docker-networkless")),
		kvT("finding_id", validation.VStr(findingID)),
		kvT("artifact_id", validation.VNull()),
		kvT("command", validation.VStr("forge test")),
		kvT("policy_verdict", validation.VObj(
			kvT("allowed", validation.VBool(true)),
			kvT("violations", validation.VArr()))),
		kvT("origin", validation.VStr("externally-reported")),
		kvT("reported_by", validation.VStr("verifier-b")),
		kvT("started_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvT("finished_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvT("exit_status", validation.VInt(0)),
		kvT("stdout_path", validation.VStr(stdout)),
		kvT("stderr_path", validation.VStr("")),
	)
	if err := validation.WriteJson(dir+"/exec_record.json", rec,
		"sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	return rec
}
