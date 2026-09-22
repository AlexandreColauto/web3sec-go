package reproduction

// v16 P1-10a §5.3 — end-to-end: an absent-guard reproduction declared at
// EXEC TIME (`--expect fail --expect-failure ...`) mints E4 through the
// REAL MintReproEvidence path (exec-record gate -> AddEvidence -> E4+
// verifyExecReference), while the identical record WITHOUT the declaration
// keeps today's refusal, byte for byte. This is the case the whole change
// exists for: a suite failing BECAUSE the guard never fired, exit 1 by
// construction.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// absentGuardOut is the honest reproduction of a missing-access-control
// defect: forge counters, [FAIL] lines, the signature on a failing line,
// exit 1.
const absentGuardOut = "[FAIL] testFinalizeDeposit() MissingGuard was not " +
	"raised — expected revert (block: 99811375)\n" +
	"Suite result: FAILED. 0 passed; 5 failed; 0 skipped; 0 pending\n" +
	"Ran 5 tests for test/Bridge.t.sol:BridgeTest\n"

// expectExec seeds the docker-networkless exec record these tests measure —
// the operator's PRE-RUN declaration included — and its ledger entry, and
// returns the record.
//
// The declaration has to be on disk before the run's ledger entry exists.
// v1.6's exec-record anchor commits `sandbox.exec.registered` to the digest of
// the whole record, so a record whose expectation keys were stamped in
// AFTERWARDS is indistinguishable from the tamper the anchor refuses
// (internal/findings' TestMintRefusesAnExecRecordEditedAfterTheEvent owns that
// subject). register_exec has no expectation keyword — the CLI's own run path
// (`webv2 exec --expect ...`, sandbox.RunOpts.Expect -> applyExecExpectation)
// stamps them into the record the FIRST write already carries — and a real
// docker-networkless run is not available to a unit test, so the record is
// written here and then anchored by its own event, in regExecLog's order:
// record first, digest second. (Before the anchor this helper rewrote a
// registered record in place.)
func expectExec(t *testing.T, c *state.Campaign, fid, stdout string, exit int,
	outcome, signature string) validation.Value {
	t.Helper()
	execID := "EXEC-" + validation.Sha256Hex([]byte(stdout))[:10]
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := expectRecord(c, fid, execID, stdoutPath, exit, outcome, signature)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	ref := execID
	data := validation.VObj(append([]validation.KV{
		{K: "profile", V: validation.VStr("docker-networkless")},
		{K: "exit", V: validation.VInt(int64(exit))},
	}, sandbox.ExecRecordAnchorKVs(rec)...)...)
	if _, err := c.Log("sandbox.exec.registered", &ref, &data); err != nil {
		t.Fatal(err)
	}
	return rec
}

// expectRecord is expectExec's record body: the docker-networkless shape
// register_exec writes, with the pre-run declaration already in place.
func expectRecord(c *state.Campaign, fid, execID, stdoutPath string, exit int,
	outcome, signature string) validation.Value {
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr("docker-networkless")),
		kv("finding_id", validation.VStr(fid)),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr("forge test")),
		kv("workdir", validation.VNull()),
		kv("policy_verdict", validation.VObj(
			kv("allowed", validation.VBool(true)),
			kv("violations", validation.VArr()))),
		kv("container", validation.VNull()),
		kv("origin", validation.VStr("externally-reported")),
		kv("reported_by", validation.VStr("tester")),
		kv("started_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kv("finished_at", validation.VStr("2026-09-11T05:06:08+00:00")),
		kv("exit_status", validation.VInt(int64(exit))),
		kv("stdout_path", validation.VStr(stdoutPath)),
		kv("stderr_path", validation.VStr(filepath.Join(
			filepath.Dir(stdoutPath), "stderr.log"))),
	)
	if outcome != "" {
		rec.O = append(rec.O, kv("expected_outcome", validation.VStr(outcome)))
	}
	if signature != "" {
		rec.O = append(rec.O, kv("expected_failure", validation.VStr(signature)))
	}
	return rec
}

// TestMintExpectedFailureEndToEnd is the design's admitted case through the
// real mint, plus its backward-compat control.
func TestMintExpectedFailureEndToEnd(t *testing.T) {
	// ADMITTED: declared before the run, signature on a FAIL line,
	// non-zero exit, class logic.
	c := newCampaign(t, "Acme Program")
	fid := ingest(t, c, hypoPayload("access-control"), "code", "")
	rec := expectExec(t, c, fid, absentGuardOut, 1, "fail", "MissingGuard")
	execID := validation.ObjStr(rec, "exec_id")
	out, err := MintReproEvidence(c, fid, execID,
		"the guard that should have refused never fired", nil, nil, "")
	if err != nil {
		t.Fatalf("the admitted expected-failure record must mint E4 end "+
			"to end; got: %v", err)
	}
	item := evidenceFor(out, execID)
	if item.Kind != validation.Obj {
		t.Fatal("the minted evidence item must land on the finding")
	}
	if got := validation.ObjStr(item, "level"); got != "E4" {
		t.Errorf("level = %q, want E4 (MintEvidenceLevelType is "+
			"unchanged)", got)
	}
	if got, want := validation.ObjStr(item, "type"),
		EffectiveEvidenceType(nil, nil, out); got != want {
		t.Errorf("type = %q, want the derivation's own %q (type semantics "+
			"unchanged)", got, want)
	}
}

// evidenceFor returns the minted item citing execID (VNull when absent).
func evidenceFor(f validation.Value, execID string) validation.Value {
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			return e
		}
	}
	return validation.VNull()
}

// TestMintLegacyFailingRecordStillRefused is the CONTROL: the identical
// run with NO declared expectation keeps today's refusal, byte for byte
// (the load-bearing backward law).
func TestMintLegacyFailingRecordStillRefused(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := ingest(t, c, hypoPayload("access-control"), "code", "")
	rec := registerExec(t, c, "docker-networkless", "forge test",
		absentGuardOut, "tester", 1, fid)
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"no declaration", nil, nil, "")
	if err == nil {
		t.Fatal("a legacy non-zero-exit record must still be refused")
	}
	want := "exec " + validation.ObjStr(rec, "exec_id") +
		" exited with status 1; a run that did not succeed is not a " +
		"reproduction — fix the PoC and re-run before minting evidence"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal drifted:\n got %q\nwant %q", err.Error(), want)
	}
}

// TestMintExpectedFailureSignatureMissingEndToEnd: the declared "fail"
// record whose output does not carry the signature still refuses at mint —
// no signature, no mint, at the real ledger layer too.
func TestMintExpectedFailureSignatureMissingEndToEnd(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := ingest(t, c, hypoPayload("access-control"), "code", "")
	rec := expectExec(t, c, fid, absentGuardOut, 1, "fail",
		"TotallyAbsentSignature")
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"wrong signature", nil, nil, "")
	if err == nil || !strings.Contains(err.Error(),
		"does not appear on any captured per-test failure line") {
		t.Fatalf("the signature-less mint must be refused; got: %v", err)
	}
}
