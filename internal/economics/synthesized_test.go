// synthesized_test.go — the universal template equations carry empty
// enforced_by BY CONSTRUCTION; reporting them as equation gaps accuses the
// operator of a gap that no operator input can clear without guessing an
// internal literal (C-12f17fd555: "sum(user_claims) + protocol_liabilities
// <= total_assets" flagged with 3 recorded relations, all enforced).
package economics

import (
	"testing"

	"websec/internal/validation"
)

func accountingModel() validation.Value {
	// One accounting variable is enough to trigger the universal
	// sum(user_claims) template (AccountingVars non-empty). The shape
	// matches protocolgraph.AccountingVars: a contract's state variable
	// marked `accounting: true` (kind is descriptive, not the trigger).
	return validation.VObj(
		validation.KV{K: "contracts", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "name", V: validation.VStr("Vault")},
				validation.KV{K: "state_variables", V: validation.VArr(
					validation.VObj(
						validation.KV{K: "name", V: validation.VStr("totalAssets")},
						validation.KV{K: "kind", V: validation.VStr("accounting")},
						validation.KV{K: "accounting", V: validation.VBool(true)},
					),
				)},
			),
		)},
	)
}

func TestEquationGapsSkipSynthesized(t *testing.T) {
	gaps := EquationGaps(accountingModel())
	for _, g := range gaps {
		eq := objStrOf(g, "equation")
		if eq == "sum(user_claims) + protocol_liabilities <= total_assets" {
			t.Fatalf("synthesized template reported as a gap: %+v", g)
		}
	}
	// The template still exists in the equation list — adoptable, not hidden.
	found := false
	for _, eq := range BuildEquations(accountingModel()) {
		if objStrOf(eq, "equation") == "sum(user_claims) + protocol_liabilities <= total_assets" {
			found = true
			if !validation.PyTruthy(objAt(eq, "synthesized")) {
				t.Fatal("template equation must carry synthesized: true")
			}
		}
	}
	if !found {
		t.Fatal("template equation missing from BuildEquations")
	}
}
