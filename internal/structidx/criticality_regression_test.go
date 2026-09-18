package structidx

import (
	"testing"

	"websec/internal/validation"
)

// State machines store states as objects ({id, terminal, ...}); the state id
// is the state name. Before the fix, critTokens (string-only) tokenized
// nothing from an object state, so a state machine whose STATE (not its name
// or transitions) names a contract failed to lift that contract to
// consensus-critical.
func TestCriticalityTokenizesStateIDs(t *testing.T) {
	model := validation.VObj(
		validation.KV{K: "contracts", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "name", V: validation.VStr("Vault")},
				validation.KV{K: "path", V: validation.VStr("Vault.sol")},
			),
		)},
		validation.KV{K: "state_machines", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "name", V: validation.VStr("lifecycle")},
				// The machine NAME is not the contract; only the state id is.
				validation.KV{K: "states", V: validation.VArr(
					validation.VObj(validation.KV{K: "id", V: validation.VStr("Vault")}),
				)},
				validation.KV{K: "transitions", V: validation.VArr()},
			),
		)},
	)
	got := CriticalityRank(model, validation.VObj())
	found := false
	for _, r := range got {
		if validation.ObjStr(r, "contract") != "Vault" {
			continue
		}
		found = true
		if tier := validation.ObjStr(r, "tier"); tier != "consensus-critical" {
			t.Errorf("Vault tier = %q, want consensus-critical (state id must be tokenized)", tier)
		}
	}
	if !found {
		t.Fatal("Vault not present in the ranking")
	}
}
