package findings

import (
	"testing"

	"websec/internal/validation"
)

// Port of tests/test_review_fixes.py::test_add_evidence_rejects_failed_or_silent_exec.
func TestAddEvidenceRejectsFailedOrSilentExec(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")

	failed := testExec(t, c, "docker-networkless", fid, 1, "[FAIL] poc\n")
	_, err = AddEvidence(c, fid, execEvidenceItem(failed, "E4",
		"foundry-test", "unit repro", "EV-f1"))
	wantErr(t, err, "exited with status")

	silent := testExec(t, c, "docker-networkless", fid, 0, "")
	_, err = AddEvidence(c, fid, execEvidenceItem(silent, "E4",
		"foundry-test", "unit repro", "EV-f2"))
	wantErr(t, err, "no captured output")

	good := testExec(t, c, "docker-networkless", fid, 0,
		"Ran 1 test\n[PASS] poc\n")
	if _, err := AddEvidence(c, fid, execEvidenceItem(good, "E4",
		"foundry-test", "unit repro", "EV-f3")); err != nil {
		t.Fatalf("honest exec must be accepted: %v", err)
	}
}

// Port of tests/test_review_fixes.py::test_e4_exec_must_belong_to_the_finding.
func TestE4ExecMustBelongToTheFinding(t *testing.T) {
	c := ingestCamp(t)
	fa, err := IngestHypothesis(c, hypoPayload(kv("title",
		validation.VStr("finding A title ok"))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fb, err := IngestHypothesis(c, hypoPayload(kv("title",
		validation.VStr("finding B title ok"))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fidA, fidB := validation.ObjStr(fa, "finding_id"), validation.ObjStr(fb, "finding_id")
	rec := testExec(t, c, "docker-networkless", fidB, 0,
		"Ran 1 test\n[PASS] poc\n")

	// No citation on A: the profile match must not accept B's exec.
	_, err = AddEvidence(c, fidA, validation.VObj(
		kv("evidence_id", validation.VStr("EV-x1")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
		kv("description", validation.VStr("unit repro")),
	))
	wantErr(t, err, "for this finding")

	// The exec DOES back its own finding.
	if _, err := AddEvidence(c, fidB, execEvidenceItem(rec, "E4",
		"foundry-test", "unit repro", "EV-x2")); err != nil {
		t.Fatalf("exec must back its own finding: %v", err)
	}
}

// Port of tests/test_review_fixes.py::test_s1_confirmation_gate_requires_fork_tier_at_e5_floor
// (the E4-floor half: an E4-floor class carries no reproduction-tier clause).
func TestConfirmationGateHasNoTierClauseAtE4Floor(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(kv("root_cause",
		validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"the setter has no access check"))))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := Transition(c, fid, "POSSIBLE", "triage", "", "", false); err != nil {
		t.Fatal(err)
	}
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(validation.ObjAt(vf, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T2")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr()),
	))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	detail, err := ConfirmationGateDetail(c, vf)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range detail {
		if f.CheckID == "reproduction-tier" {
			t.Fatalf("E4-floor class must carry no reproduction-tier clause: %v", f)
		}
	}
}
