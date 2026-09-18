package findings

// gate_probe_anchor_copy_test.go — the COPY half of the B4-predicate pin
// (see the external gate_probe_anchor_heal_test.go for why the split): same
// vectors, same table, asserted against gateHighRiskRow itself. Mutating the
// copy's thresholds fails THIS build, not an incident.

import (
	"testing"

	"websec/internal/validation"
)

func copyRiskVectors() []struct {
	name string
	row  validation.Value
	want bool
} {
	kv := func(k string, v validation.Value) validation.KV {
		return validation.KV{K: k, V: v}
	}
	return []struct {
		name string
		row  validation.Value
		want bool
	}{
		{"tier0", validation.VObj(kv("tier", validation.VInt(0))), true},
		{"gap3", validation.VObj(kv("tier", validation.VInt(2)),
			kv("assertion_gap", validation.VInt(3))), true},
		{"low", validation.VObj(kv("tier", validation.VInt(1)),
			kv("assertion_gap", validation.VInt(2))), false},
		{"missing tier reads as 0", validation.VObj(), true},
		{"tier5 gap10", validation.VObj(kv("tier", validation.VInt(5)),
			kv("assertion_gap", validation.VInt(10))), true},
	}
}

func TestGateHighRiskRowCopyAgrees(t *testing.T) {
	for _, v := range copyRiskVectors() {
		if got := gateHighRiskRow(v.row); got != v.want {
			t.Errorf("gateHighRiskRow(%s) = %v, want %v — the copy in "+
				"gate_probe_anchor.go drifted; fix it or update planner's "+
				"predicate AND both vector tables in the same commit",
				v.name, got, v.want)
		}
	}
}
