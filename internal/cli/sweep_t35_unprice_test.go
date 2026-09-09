package cli

// Port of tests/test_unpriceable_impact.py::test_brief_gate_and_report_survive_an_unpriceable_decision:
// `priceable: false` must not crash any read surface.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/sandbox"
	"websec/internal/validation"
)

// Port of tests/test_unpriceable_impact.py::test_brief_gate_and_report_survive_an_unpriceable_decision.
func TestBriefGateAndReportSurviveAnUnpriceableDecision(t *testing.T) {
	c, root := t15Campaign(t, "surfaces")
	t15GlobalRow(t, "MEM-shared01", "logic-error")
	f := t15Finding(t, c, "Attacker skews the oracle and borrows unbacked "+
		"funds", "oracle-manipulation")
	fid := objStr(f, "finding_id")
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		FindingID: &fid, ReportedBy: "test-harness",
		StdoutText: "PASS: test_x\n"})
	if err != nil {
		t.Fatal(err)
	}
	for i, lv := range []string{"E4", "E5"} {
		etype := "foundry-test"
		if lv == "E5" {
			etype = "fork-test"
		}
		if _, err := findings.AddEvidence(c, fid, validation.VObj(
			kvT("evidence_id", validation.VStr("EV-u"+string(rune('0'+i)))),
			kvT("level", validation.VStr(lv)),
			kvT("type", validation.VStr(etype)),
			kvT("description", validation.VStr("gate fixture")),
			kvT("sandbox_profile", objAt(rec, "profile")),
			kvT("artifact_id", objAt(rec, "exec_id")))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"mechanism sound"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kvT("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kvT("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = setOrAppendKV(ver.O, "reproduction", validation.VObj(
		kvT("tier_reached", validation.VStr("T3")),
		kvT("status", validation.VStr("reproduced")),
		kvT("attempts", validation.VArr())))
	f.O = setOrAppendKV(f.O, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	if _, err := risk.RecordUnpriceable(c, fid,
		"capacity basis: the sink is an address[255] test constant",
		"the sink is a test fixture", "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED",
		"unpriceable decision recorded", "", "", false); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range [][]string{{"brief", c.CampaignID},
		{"report", c.CampaignID}, {"budget", c.CampaignID}} {
		code, out, errS := run(t, append([]string{"--root", root}, cmd...)...)
		if code != 0 {
			t.Errorf("%v exit %d: %s%s", cmd, code, out, errS)
		}
	}
	// the bounty gate legitimately exits 2 without a policy — the point is
	// that it stops on the policy, not on `priceable: false`.
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID)
	_ = code
	combined := out + errS
	if strings.Contains(combined, "Traceback") {
		t.Errorf("gate crashed on priceable:false:\n%s", combined)
	}
	if !strings.Contains(combined, "policy") {
		t.Errorf("gate did not stop on the policy:\n%s", combined)
	}
}
