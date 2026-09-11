// components_assumptions_test.go: G10+G9 model schema — additive
// `components[]` + `chain_assumptions[]`.
//
// `chains[]` is `array<string>` and stays that way (legacy models must keep
// validating); cross-chain assumptions ride a SEPARATE optional list keyed
// by chain name, and `components[]` follows the audit-doc shape verbatim.
package protocolgraph

import (
	"os"
	"testing"

	"websec/internal/validation"
)

// mustParseJSON parses an inline JSON literal into an ordered Value.
func mustParseJSON(t *testing.T, raw string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return v
}

// TestComponentsAndAssumptionsRoundTrip pins the additive keys: a model
// carrying both lists must validate, and the canonical bytes must survive
// a parse→marshal→parse round trip unchanged.
func TestComponentsAndAssumptionsRoundTrip(t *testing.T) {
	raw := `{"protocol_id":"p","name":"nn","contracts":[],"actors":[],"assets":[],"relations":[],` +
		`"components":[{"kind":"frontend","path":"app/","trust":"untrusted","in_scope":true,"paid_for":true}],` +
		`"chain_assumptions":[{"chain":"mainnet","finality":"probabilistic","confirmation_depth":12,"messenger":"canonical","separator":"eip712-domain"}]}`
	v := mustParseJSON(t, raw)
	if err := validation.Validate(v, "protocol_model", 1); err != nil {
		t.Fatalf("additive schema rejects new keys: %v", err)
	}
	compact := validation.CanonCompact(v)
	if got := validation.CanonCompact(mustParseJSON(t, compact)); got != compact {
		t.Errorf("round trip unstable\n got: %s\nwant: %s", got, compact)
	}
}

// TestLegacyModelWithoutNewKeysStillValid reuses the byte-exact legacy
// fixture from TestGatewayModelArtifactRoundTrip: validate + marshal +
// compare bytes to prove the additive keys change nothing for old models.
func TestLegacyModelWithoutNewKeysStillValid(t *testing.T) {
	raw, err := os.ReadFile("testdata/gateway_model.json")
	if err != nil {
		t.Fatal(err)
	}
	v := mustParseJSON(t, string(raw))
	if err := validation.Validate(v, "protocol_model", 1); err != nil {
		t.Fatalf("legacy model rejected: %v", err)
	}
	compact := validation.CanonCompact(v)
	if got := validation.CanonCompact(mustParseJSON(t, compact)); got != compact {
		t.Errorf("legacy bytes unstable\n got: %s\nwant: %s", got, compact)
	}
	// A minimal legacy literal with none of the new keys stays valid too.
	minimal := mustParseJSON(t,
		`{"protocol_id":"p","name":"nn","contracts":[],"actors":[],"assets":[],"relations":[]}`)
	if err := validation.Validate(minimal, "protocol_model", 1); err != nil {
		t.Fatalf("minimal legacy model rejected: %v", err)
	}
}
