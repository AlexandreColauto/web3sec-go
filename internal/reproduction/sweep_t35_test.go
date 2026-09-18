package reproduction

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// Port of tests/test_review_fixes.py::test_mint_rejects_exec_with_nonzero_exit.
func TestMintRejectsExecWithNonzeroExit(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := integrityHypo(t, c, "logic-error")
	rec := registerExec(t, c, "docker-networkless", "forge test",
		"", "ops", 1, fid)
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "unit repro",
		nil, nil)
	if err == nil || !strings.Contains(err.Error(), "exited with status") {
		t.Fatalf("err = %v, want the nonzero-exit refusal", err)
	}
}

// Port of tests/test_review_fixes.py::test_mint_rejects_silent_exec.
func TestMintRejectsSilentExec(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := integrityHypo(t, c, "logic-error")
	rec := registerExec(t, c, "docker-networkless", "forge test",
		"", "ops", 0, fid)
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "no-op run",
		nil, nil)
	if err == nil || !strings.Contains(err.Error(), "EMPTY captured output") {
		t.Fatalf("err = %v, want the empty-output refusal", err)
	}
}

// Port of tests/test_review_fixes.py::test_independent_mint_rejects_failed_exec.
func TestIndependentMintRejectsFailedExec(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := integrityHypo(t, c, "logic-error")
	registerExec(t, c, "docker-networkless", "forge test",
		"Ran 1 test\n[PASS] poc\n", "alice", 0, fid)
	bad := registerExec(t, c, "fork-runner", "anvil fork",
		"", "bob", 1, "")
	_, err := MintIndependentEvidence(c, fid, validation.ObjStr(bad, "exec_id"),
		"independent", "bob")
	if err == nil || !strings.Contains(err.Error(), "exited with status") {
		t.Fatalf("err = %v, want the failed-exec refusal", err)
	}
}

// Port of tests/test_review_fixes.py::test_independent_mint_rejects_silent_exec.
func TestIndependentMintRejectsSilentExec(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := integrityHypo(t, c, "logic-error")
	good := registerExec(t, c, "docker-networkless", "forge test",
		"Ran 1 test\n[PASS] poc\n", "alice", 0, fid)
	execID := validation.ObjStr(good, "exec_id")
	tier := "T1"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	if _, err := MintReproEvidence(c, fid, execID, "unit repro", &tier,
		nil); err != nil {
		t.Fatal(err)
	}
	silent := registerExec(t, c, "fork-runner", "forge test",
		"", "bob", 0, "")
	_, err := MintIndependentEvidence(c, fid, validation.ObjStr(silent, "exec_id"),
		"independent", "bob")
	if err == nil || !strings.Contains(err.Error(), "EMPTY captured output") {
		t.Fatalf("err = %v, want the E6 empty-output refusal", err)
	}
}

// Port of tests/test_review_fixes.py::test_s1_mint_rejects_tier_above_recorded_ladder.
func TestMintRejectsTierAboveRecordedLadder(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := integrityHypo(t, c, "logic-error")
	rec := registerExec(t, c, "docker-networkless", "forge test",
		"Ran 1 test\n[PASS] poc\n", "alice", 0, fid)
	execID := validation.ObjStr(rec, "exec_id")
	tier := "T3"
	_, err := MintReproEvidence(c, fid, execID, "unit repro", &tier, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot mint at tier") {
		t.Fatalf("err = %v, want the tier-ladder refusal", err)
	}
	// ...and the recorded path works: claim the rung, then mint it.
	tier2 := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier2}); err != nil {
		t.Fatal(err)
	}
	out, err := MintReproEvidence(c, fid, execID, "unit repro", &tier2, nil)
	if err != nil {
		t.Fatal(err)
	}
	repro := validation.ObjAt(validation.ObjAt(validation.ObjAt(out, "verification"), "reproduction"),
		"tier_reached")
	if repro.Kind != validation.Str || repro.S != "T2" {
		t.Fatalf("tier_reached = %v, want T2", repro)
	}
}
