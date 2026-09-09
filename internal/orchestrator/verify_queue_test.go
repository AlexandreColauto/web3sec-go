// Port of tests/test_independent_verification.py::
// test_independent_verification_queue_orders_mandatory_first.
//
// The queue is a PURE READ over CONFIRMED findings that still lack E6:
// nothing confirmed => empty; a confirmed access-control finding at its own
// E4 floor is listed but not mandatory; once E6 lands it leaves the queue.
// `mandatory` follows the CAMPAIGN's effective floor for the class.
package orchestrator

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

func TestIndependentVerificationQueueOrdersMandatoryFirst(t *testing.T) {
	c := seqQueueCampaign(t)
	o := New(c)

	q, err := o.IndependentVerificationQueue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.A) != 0 {
		t.Fatalf("empty campaign queue = %s", validation.CanonCompact(q))
	}

	// A CONFIRMED access-control finding at E4 (its own CONFIRMED floor).
	fid := seqFindingIn(t, c, validation.VNull())
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ev := append(listAt(f, "evidence"), validation.VObj(
		kvOf("evidence_id", validation.VStr("EV-authz")),
		kvOf("level", validation.VStr("E4")),
		kvOf("type", validation.VStr("foundry-test")),
		kvOf("description", validation.VStr("unit repro")),
	))
	f.O = setOrAppendKV(f.O, "evidence", validation.VArr(ev...))
	f.O = setOrAppendKV(f.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}

	q, err = o.IndependentVerificationQueue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.A) != 1 || strAt(q.A[0], "finding_id") != fid {
		t.Fatalf("queue = %s; want one row for %s",
			validation.CanonCompact(q), fid)
	}
	if boolAt(q.A[0], "mandatory") {
		t.Errorf("row = %s; access-control at its E4 floor must not be mandatory",
			validation.CanonCompact(q.A[0]))
	}
	if got := strAt(q.A[0], "evidence_level"); got != "E4" {
		t.Errorf("evidence_level = %q, want E4", got)
	}

	// Once E6 lands it leaves the queue.
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ev = append(listAt(f, "evidence"), validation.VObj(
		kvOf("evidence_id", validation.VStr("EV-e6")),
		kvOf("level", validation.VStr("E6")),
		kvOf("type", validation.VStr("fork-test")),
		kvOf("description", validation.VStr("independent rerun")),
	))
	f.O = setOrAppendKV(f.O, "evidence", validation.VArr(ev...))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	q, err = o.IndependentVerificationQueue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.A) != 0 {
		t.Fatalf("queue after E6 = %s; want empty", validation.CanonCompact(q))
	}
}
