package findings

// T25 seam test: the fork_diff block is schema-validated on write and
// round-trips, but the confirmation gate never reads it
// (tests/test_forkdiff.py::test_confirmation_gate_ignores_fork_diff and
// ::test_finding_schema_accepts_fork_diff).

import (
	"testing"

	"websec/internal/validation"
)

func TestConfirmationGateIgnoresForkDiff(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	before, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	gatesBefore, err := ConfirmationGates(c, f)
	if err != nil {
		t.Fatal(err)
	}
	// The five schema-pinned keys: a wrong name or a missing one would make
	// SaveFinding's schema validation fail (additionalProperties: false).
	withFD := f
	withFD.O = append([]validation.KV(nil), f.O...)
	withFD.O = append(withFD.O, validation.KV{K: "fork_diff",
		V: validation.VObj(
			validation.KV{K: "matched_baseline", V: validation.VStr("alpha-ref")},
			validation.KV{K: "score", V: validation.VFloat(0.92)},
			validation.KV{K: "verdict", V: validation.VStr("strong")},
			validation.KV{K: "extra_selectors",
				V: validation.VArr(validation.VStr("sweep(address)"))},
			validation.KV{K: "missing_selectors", V: validation.VArr()},
		)})
	if err := SaveFinding(c, &withFD); err != nil {
		t.Fatalf("schema-validated write with fork_diff: %v", err)
	}
	reloaded, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(objAt(reloaded, "fork_diff"), "verdict"); got != "strong" {
		t.Fatalf("fork_diff.verdict = %q, want strong", got)
	}
	after, err := ConfirmationGateDetail(c, reloaded)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonCompact(validation.VArr(toVals(before)...)) !=
		validation.CanonCompact(validation.VArr(toVals(after)...)) {
		t.Fatalf("gate detail changed after fork_diff:\n before %v\n after  %v",
			before, after)
	}
	gatesAfter, err := ConfirmationGates(c, reloaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(gatesAfter) != len(gatesBefore) {
		t.Fatalf("gates = %v, want %v", gatesAfter, gatesBefore)
	}
	for i := range gatesAfter {
		if gatesAfter[i] != gatesBefore[i] {
			t.Fatalf("gates = %v, want %v", gatesAfter, gatesBefore)
		}
	}
}

// toVals renders GateFailure rows for a canonical comparison.
func toVals(xs []GateFailure) []validation.Value {
	out := make([]validation.Value, len(xs))
	for i, x := range xs {
		out[i] = validation.VObj(
			validation.KV{K: "check_id", V: validation.VStr(x.CheckID)},
			validation.KV{K: "message", V: validation.VStr(x.Message)},
			validation.KV{K: "remediation", V: validation.VStr(x.Remediation)},
		)
	}
	return out
}
