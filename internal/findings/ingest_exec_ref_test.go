package findings

// Wave N, T2 — ingest evidence items may cite an existing EXEC.
//
// The three laws these tests pin:
//
//  1. ORDER: the WHOLE payload is schema-validated before any ledger read or
//     gate math, so a schema typo is never masked by an E4/ledger refusal.
//  2. LEDGER: exec_ref must name an exec this campaign's ledger holds, that
//     SUCCEEDED, and that is bound to this finding (or to no finding at all).
//  3. NO FORK: the landed item is the item `mint` would have minted — same
//     gate (findings.ValidateExecRecord), same shape, same tier derivation.
//
// Presence-gated: items without exec_ref keep the pre-T2 rule (execution
// evidence is refused at ingest), which TestIngestRejectsPreloadedExecution-
// Evidence in ingest_test.go still pins untouched.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// t2ExecRefItem is one evidence item citing an exec.
func t2ExecRefItem(ref, eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("the sandboxed PoC reproduced it")),
		kv("exec_ref", validation.VStr(ref)),
	)
}

// t2ExecRefPayload is hypoPayload plus that one item.
func t2ExecRefPayload(ref, eid string) validation.Value {
	return hypoPayload(kv("evidence", validation.VArr(t2ExecRefItem(ref, eid))))
}

// TestIngestSchemaErrorPrecedesExecGate is the masking-order law: a payload
// that carries BOTH a schema error AND an E4 claim reports the SCHEMA error —
// whether the claim is a pre-loaded E4 item (the pre-T2 E4 gate) or an item
// whose exec_ref the ledger does not hold (the T2 ledger check).
func TestIngestSchemaErrorPrecedesExecGate(t *testing.T) {
	c := ingestCamp(t)
	preloaded := validation.VObj(
		kv("evidence_id", validation.VStr("EV-x")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("smuggled execution evidence")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
	)
	badTitle := kv("title", validation.VStr("short"))

	cases := []struct {
		name  string
		item  validation.Value
		notIn string
	}{
		{"E4 claim without exec", preloaded, "EXECUTION evidence"},
		{"exec_ref the ledger does not hold", t2ExecRefItem(
			"EXEC-deadbeef01", "EV-x"), "ingest refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := IngestHypothesis(c,
				hypoPayload(badTitle, kv("evidence", validation.VArr(tc.item))),
				"code", "", "")
			wantErr(t, err, "finding validation failed at title: 'short' "+
				"is too short")
			if strings.Contains(err.Error(), tc.notIn) {
				t.Fatalf("the schema error was masked by %q: %v", tc.notIn, err)
			}
		})
	}
}

// TestIngestExecRefPatternIsSchemaChecked: the exec_ref SHAPE is the schema's
// business (^EXEC-[0-9a-f]{6,}$ — the ids state.NewID mints are EXEC- plus 10
// lowercase hex chars), so a malformed ref is a schema error, not a ledger
// lookup and not a refusal.
func TestIngestExecRefPatternIsSchemaChecked(t *testing.T) {
	c := ingestCamp(t)
	for _, ref := range []string{"EXEC-NotHex01", "EXEC-abc", "not-an-exec"} {
		t.Run(ref, func(t *testing.T) {
			_, err := IngestHypothesis(c, t2ExecRefPayload(ref, "EV-x"),
				"code", "", "")
			wantErr(t, err, "finding validation failed at evidence/0/exec_ref")
			if strings.Contains(err.Error(), "ingest refused") {
				t.Fatalf("a malformed ref reached the ledger: %v", err)
			}
		})
	}
}

// TestIngestExecRefUnknownRefused: an exec_ref the ledger does not hold is
// refused BY NAME (accept: unknown exec_ref → refuse naming it).
func TestIngestExecRefUnknownRefused(t *testing.T) {
	c := ingestCamp(t)
	_, err := IngestHypothesis(c, t2ExecRefPayload("EXEC-deadbeef01", "EV-x"),
		"code", "", "")
	wantErr(t, err, "ingest refused: evidence EV-x cites exec_ref "+
		"'EXEC-deadbeef01', which this campaign's ledger does not hold")
}

// TestIngestExecRefNotSucceededRefused: the exec must have SUCCEEDED — a
// non-zero exit and an exit-0-with-no-output run both refuse, through mint's
// own exec-record gate (one message source, two verbs).
func TestIngestExecRefNotSucceededRefused(t *testing.T) {
	c := ingestCamp(t)
	failed := testExec(t, c, "docker-networkless", "", 1, "boom\n")
	fid := validation.ObjStr(failed, "exec_id")
	_, err := IngestHypothesis(c, t2ExecRefPayload(fid, "EV-y"), "code", "", "")
	wantErr(t, err, "ingest refused: evidence EV-y exec_ref "+fid+": exec "+
		fid+" exited with status 1; a run that did not succeed is not a "+
		"reproduction")

	silent := testExec(t, c, "docker-networkless", "", 0, "")
	sid := validation.ObjStr(silent, "exec_id")
	_, err = IngestHypothesis(c, t2ExecRefPayload(sid, "EV-z"), "code", "", "")
	wantErr(t, err, "exec "+sid+" exited 0 with EMPTY captured output")
}

// TestIngestExecRefBoundElsewhereRefused: an exec bound to ANOTHER finding
// stays bound — the operator re-runs it under the survivor.
//
// I-14 pins the PRECEDENCE the doc comment states: the binding check runs
// BEFORE the exec-record gate, so a bound exec that ALSO failed its run is
// refused for the binding. That refusal deliberately masks the record's own
// defect (re-running the same broken PoC under this finding cannot help while
// the ledger row names the other one), so the message must be the binding
// message and must NOT be the exec-record one.
func TestIngestExecRefBoundElsewhereRefused(t *testing.T) {
	c := ingestCamp(t)
	other := "F-000000000000"
	rec := testExec(t, c, "docker-networkless", other, 0, "PASS\n")
	id := validation.ObjStr(rec, "exec_id")
	_, err := IngestHypothesis(c, t2ExecRefPayload(id, "EV-b"), "code", "", "")
	wantErr(t, err, "ingest refused: exec_ref "+id+" is bound to finding "+
		"'"+other+"', not F-")

	// The masking case: bound elsewhere AND a failing record.
	failed := testExec(t, c, "docker-networkless", other, 1, "boom\n")
	failedID := validation.ObjStr(failed, "exec_id")
	_, err = IngestHypothesis(c, t2ExecRefPayload(failedID, "EV-b2"), "code", "", "")
	wantErr(t, err, "ingest refused: exec_ref "+failedID+" is bound to finding "+
		"'"+other+"'")
	if strings.Contains(err.Error(), "exited with status") {
		t.Errorf("a bound-elsewhere refusal must not leak the exec-record gate "+
			"message it masks: %v", err)
	}
}

// TestIngestExecRefLandsMintedEvidence: the happy path. The item lands as the
// evidence mint would have minted from that exec — E4/foundry-test for a
// finding whose recorded tier is "none", metadata from the exec record, the
// snapshot pin from the finding — and exec_ref itself never lands.
func TestIngestExecRefLandsMintedEvidence(t *testing.T) {
	c := ingestCamp(t)
	rec := testExec(t, c, "docker-networkless", "", 0, "PASS: test_exploit\n")
	id := validation.ObjStr(rec, "exec_id")
	f, err := IngestHypothesis(c, t2ExecRefPayload(id, "EV-ok"), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ev := validation.ObjAt(f, "evidence")
	if len(ev.A) != 1 {
		t.Fatalf("evidence items = %d, want 1", len(ev.A))
	}
	item := ev.A[0]
	if err := validateEvidenceItem(item); err != nil {
		t.Fatalf("the minted item is not schema-valid: %v", err)
	}
	for _, want := range []struct{ key, val string }{
		{"level", "E4"},
		{"type", "foundry-test"},
		{"artifact_id", id},
		{"sandbox_profile", "docker-networkless"},
		{"command", validation.ObjStr(rec, "command")},
		{"description", "the sandboxed PoC reproduced it"},
		{"snapshot_id", validation.PyStr(validation.ObjAt(validation.ObjAt(f, "snapshot_ids"), "source"))},
	} {
		if got := validation.ObjStr(item, want.key); got != want.val {
			t.Errorf("item %s = %q, want %q", want.key, got, want.val)
		}
	}
	for _, kvp := range item.O {
		if kvp.K == "exec_ref" {
			t.Fatalf("exec_ref must not land on the finding: %v",
				validation.PyRepr(item))
		}
	}
}

// TestIngestExecRefFollowsRecordedTier: the tier is mint's derivation, not the
// payload's word — a payload whose finding records T3 lands E5/fork-test (the
// same item mint would produce), and the derivation itself is one function.
func TestIngestExecRefFollowsRecordedTier(t *testing.T) {
	if lvl, typ := MintEvidenceLevelType("T3", nil); lvl != "E5" ||
		typ != "fork-test" {
		t.Fatalf("T3 → (%s, %s), want (E5, fork-test)", lvl, typ)
	}
	c := ingestCamp(t)
	rec := testExec(t, c, "docker-networkless", "", 0, "PASS: test_exploit\n")
	id := validation.ObjStr(rec, "exec_id")
	p := t2ExecRefPayload(id, "EV-t3")
	p.O = validation.SetOrAppend(p.O, "verification", validation.VObj(
		kv("reproduction", validation.VObj(
			kv("tier_reached", validation.VStr("T3"))))))
	// the payload declares what the derivation will say (I-4): declaring a
	// LIE is refused outright, tested in TestIngestExecRefRejectsFalseType.
	if items := validation.ObjAt(p, "evidence").A; len(items) == 1 {
		it := validation.VObj(items[0].O...)
		for i, e := range it.O {
			if e.K == "type" {
				it.O[i] = kv("type", validation.VStr("fork-test"))
			}
			if e.K == "level" {
				it.O[i] = kv("level", validation.VStr("E5"))
			}
		}
		p.O = validation.SetOrAppend(p.O, "evidence",
			validation.VArr(it))
	}
	f, err := IngestHypothesis(c, p, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	item := validation.ObjAt(f, "evidence").A[0]
	if lvl, typ := validation.ObjStr(item, "level"), validation.ObjStr(item, "type"); lvl != "E5" ||
		typ != "fork-test" {
		t.Fatalf("landed (%s, %s), want (E5, fork-test)", lvl, typ)
	}
}

// TestIngestExecRefRejectsFalseType pins critic I-4: a declared type/level
// that disagrees with the mint derivation is REFUSED, naming the derived pair
// — never silently rewritten, because the recorded type feeds the gate's
// EVIDENCE_TYPE_GROUPS membership.
func TestIngestExecRefRejectsFalseType(t *testing.T) {
	c := ingestCamp(t)
	rec := testExec(t, c, "docker-networkless", "", 0, "PASS: test_exploit\n")
	id := validation.ObjStr(rec, "exec_id")
	p := t2ExecRefPayload(id, "EV-lie") // declares E4/foundry-test: honest pair
	f, err := IngestHypothesis(c, p, "code", "", "")
	if err != nil {
		t.Fatalf("truthful pair must pass: %v", err)
	}
	_ = f
	// now flip the finding's recorded tier so the derivation says E5/fork-test
	// while the payload still declares E4/foundry-test.
	p2 := t2ExecRefPayload(id, "EV-lie2")
	// morph §7.5: the door folds an identical payload into the finding the
	// first ingest wrote, so the second payload must be a DISTINCT claim for
	// the exec-ref gate below to run at all (the verification flip alone does
	// not move the content digest).
	p2.O = validation.SetOrAppend(p2.O, "title", validation.VStr(
		"User can withdraw more than deposited via rounding (re-filed)"))
	p2.O = validation.SetOrAppend(p2.O, "verification", validation.VObj(
		kv("reproduction", validation.VObj(
			kv("tier_reached", validation.VStr("T3"))))))
	_, err = IngestHypothesis(c, p2, "code", "", "")
	if err == nil {
		t.Fatal("a declared type contradicting the derivation must be refused")
	}
	if !strings.Contains(err.Error(), "derives 'fork-test'") {
		t.Fatalf("refusal must name the derived type: %v", err)
	}
}
