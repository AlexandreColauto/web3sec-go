// confirmed_split_test.go — the eval spec's false-positive budget counts
// "all other CONFIRMED findings"; the raw FP count includes live POSSIBLE
// rows. Both numbers stay visible; the incentive to file honest hypotheses
// is restored by printing the split (C-12f17fd555 §10a).
package evalscore

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func withStatus(class, path, status string) validation.Value {
	f := finding(class, path)
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr(status))
	return f
}

func TestConfirmedPrecisionSplit(t *testing.T) {
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1": {
			withStatus("access-control", "src/Vault.sol", "CONFIRMED"),      // anchors CASE-A
			withStatus("oracle-manipulation", "src/Other.sol", "CONFIRMED"), // raw FP
			withStatus("unmatched-class", "src/Hyp.sol", "POSSIBLE"),        // raw FP, not a claim
		},
		"ctrl": {},
	})
	if r.FP != 2 {
		t.Fatalf("raw FP = %d, want 2 (raw semantics unchanged)", r.FP)
	}
	if r.ConfirmedLive != 2 || r.ConfirmedAnchored != 1 {
		t.Fatalf("confirmed split = %d/%d, want 2 live / 1 anchored", r.ConfirmedLive, r.ConfirmedAnchored)
	}
	if !strings.Contains(r.ConfirmedPrecisionLine, "1/2") {
		t.Fatalf("ConfirmedPrecisionLine = %q, want the 1/2 wilson line", r.ConfirmedPrecisionLine)
	}
}

func TestConfirmedPrecisionEmptyProgram(t *testing.T) {
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1":   {withStatus("unmatched-class", "src/Hyp.sol", "POSSIBLE")},
		"ctrl": {},
	})
	if r.ConfirmedPrecisionLine != "" {
		t.Fatalf("no CONFIRMED findings: line = %q, want empty", r.ConfirmedPrecisionLine)
	}
}
