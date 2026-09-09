package invariants

// Port of tests/test_tier1_minor_sweep.py::test_s3_uncovered_critical_spans_id_spellings.

import (
	"testing"

	"websec/internal/validation"
)

func TestUncoveredCriticalSpansIDSpellings(t *testing.T) {
	c := docCamp(t)
	if _, err := SeedFromModel(c, validation.VObj(
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-001")),
			kv("statement", validation.VStr(
				"fee accumulator cannot be set backwards")),
			kv("severity_if_broken", validation.VStr("critical"))))))); err != nil {
		t.Fatal(err)
	}
	out, err := UncoveredCritical(c, validation.VObj(
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"fee accumulator cannot be set backwards")),
			kv("severity_if_broken", validation.VStr("critical")))))))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, e := range out {
		ids = append(ids, objStr(e, "invariant_id"))
	}
	if len(ids) != 1 || ids[0] != "INV-1" {
		t.Errorf("uncovered ids = %v, want [INV-1]", ids)
	}
}
