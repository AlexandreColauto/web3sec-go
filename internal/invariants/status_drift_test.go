// status_drift_test.go — N/T3: the model↔ledger invariant-status comparison
// itself (the CLI report is pinned in internal/cli). Detect-and-name only: the
// comparison reads both documents and writes neither.
package invariants

import (
	"testing"

	"websec/internal/validation"
)

func TestModelStatusDriftNamesDisagreementsOnly(t *testing.T) {
	c := docCamp(t)
	ledger := validation.VObj(kv("invariants", validation.VObj(
		kv("INV-1", validation.VObj(
			kv("test_status", validation.VStr("untested")),
			kv("status", validation.VStr("UNVERIFIED")),
			kv("source", validation.VStr("model")))),
		kv("INV-2", validation.VObj(
			kv("test_status", validation.VStr("untested")),
			kv("status", validation.VStr("CHECKED_AGAINST_CODE")),
			kv("source", validation.VStr("model")))))))
	if err := validation.WriteJson(linksPath(c), ledger, ""); err != nil {
		t.Fatal(err)
	}
	before, err := validation.Sha256File(linksPath(c))
	if err != nil {
		t.Fatal(err)
	}
	model := validation.VObj(kv("invariants", validation.VArr(
		validation.VObj(kv("id", validation.VStr("INV-1")),
			kv("status", validation.VStr("CONTRADICTED"))),
		validation.VObj(kv("id", validation.VStr("INV-2")),
			kv("status", validation.VStr("CHECKED_AGAINST_CODE"))),
		validation.VObj(kv("id", validation.VStr("INV-3")),
			kv("status", validation.VStr("UNVERIFIED"))),
		validation.VObj(kv("id", validation.VStr("INV-4"))),
	)))
	rows, err := ModelStatusDrift(c, model)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("drift rows = %+v, want exactly the INV-1 disagreement", rows)
	}
	if rows[0].InvariantID != "INV-1" ||
		rows[0].ModelStatus != "CONTRADICTED" ||
		rows[0].LedgerStatus != "UNVERIFIED" {
		t.Errorf("drift row = %+v", rows[0])
	}
	after, err := validation.Sha256File(linksPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Error("the comparison rewrote the ledger")
	}
}

// TestModelStatusDriftSilentInputs: no model, a model that is not an object,
// and a model whose statuses all agree with the ledger.
func TestModelStatusDriftSilentInputs(t *testing.T) {
	c := docCamp(t)
	rows, err := ModelStatusDrift(c, validation.VNull())
	if err != nil || len(rows) != 0 {
		t.Fatalf("no model: rows=%+v err=%v", rows, err)
	}
	rows, err = ModelStatusDrift(c, validation.VArr())
	if err != nil || len(rows) != 0 {
		t.Fatalf("non-object model: rows=%+v err=%v", rows, err)
	}
	// an object model WITHOUT an invariants block (the case the T3 review
	// probed by hand): silent, never a crash or a phantom row.
	rows, err = ModelStatusDrift(c, validation.VObj(
		kv("name", validation.VStr("m"))))
	if err != nil || len(rows) != 0 {
		t.Fatalf("model without invariants: rows=%+v err=%v", rows, err)
	}
	// no ledger file at all: the model's claim has nothing to disagree with.
	rows, err = ModelStatusDrift(c, modelWithInvariants())
	if err != nil || len(rows) != 0 {
		t.Fatalf("no ledger: rows=%+v err=%v", rows, err)
	}
}

// TestModelStatusDriftNormalizesIDs: the ledger key INV-1 and the model's
// INV-01 are the same invariant.
func TestModelStatusDriftNormalizesIDs(t *testing.T) {
	c := docCamp(t)
	ledger := validation.VObj(kv("invariants", validation.VObj(
		kv("INV-1", validation.VObj(
			kv("test_status", validation.VStr("untested")),
			kv("status", validation.VStr("UNVERIFIED")))))))
	if err := validation.WriteJson(linksPath(c), ledger, ""); err != nil {
		t.Fatal(err)
	}
	model := validation.VObj(kv("invariants", validation.VArr(
		validation.VObj(kv("id", validation.VStr("INV-01")),
			kv("status", validation.VStr("CONTRADICTED"))))))
	rows, err := ModelStatusDrift(c, model)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].InvariantID != "INV-1" {
		t.Fatalf("normalized drift rows = %+v", rows)
	}
}
