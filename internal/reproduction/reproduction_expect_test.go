package reproduction

// v16 P1-10a §5.3 — end-to-end: an absent-guard reproduction declared at
// EXEC TIME (`--expect fail --expect-failure ...`) mints E4 through the
// REAL MintReproEvidence path (exec-record gate -> AddEvidence -> E4+
// verifyExecReference), while the identical record WITHOUT the declaration
// keeps today's refusal, byte for byte. This is the case the whole change
// exists for: a suite failing BECAUSE the guard never fired, exit 1 by
// construction.

import (
	"path/filepath"
	"strings"
	"testing"

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

// stampExpect rewrites the registered exec record with the expectation keys
// `webv2 exec --expect ...` would have carried, and returns the updated
// record. (RegisterExec has no expectation keyword — the CLI's own run path
// stamps them at registration; the ledger-entry twin stays untouched.)
func stampExpect(t *testing.T, c *state.Campaign, rec validation.Value,
	kvs ...validation.KV) validation.Value {
	t.Helper()
	rec.O = append(rec.O, kvs...)
	p := filepath.Join(c.ExecsDir, validation.ObjStr(rec, "exec_id"),
		"exec_record.json")
	if err := validation.WriteJson(p, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
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
	rec := registerExec(t, c, "docker-networkless", "forge test",
		absentGuardOut, "tester", 1, fid)
	rec = stampExpect(t, c, rec,
		validation.KV{K: "expected_outcome", V: validation.VStr("fail")},
		validation.KV{K: "expected_failure",
			V: validation.VStr("MissingGuard")})
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
	rec := registerExec(t, c, "docker-networkless", "forge test",
		absentGuardOut, "tester", 1, fid)
	rec = stampExpect(t, c, rec,
		validation.KV{K: "expected_outcome", V: validation.VStr("fail")},
		validation.KV{K: "expected_failure",
			V: validation.VStr("TotallyAbsentSignature")})
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"wrong signature", nil, nil, "")
	if err == nil || !strings.Contains(err.Error(),
		"does not appear on any captured per-test failure line") {
		t.Fatalf("the signature-less mint must be refused; got: %v", err)
	}
}
