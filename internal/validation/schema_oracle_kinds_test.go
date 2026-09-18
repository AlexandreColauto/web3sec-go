package validation

// B3 (docs/feedback-triage-morph-r2.md:130) — the protocol_model oracles
// `kind` enum was seven price-shaped values with no honest way to say "this
// oracle is something else" (assets/schema/protocol_model.schema.json:436).
// It now carries "data-availability" (blob DA is a recurring L2 category) and
// "other", APPENDED so the legend order of the pre-existing values is
// untouched — EnumLegend renders document order
// (internal/validation/schema_enum.go:142-153) and that order is what the
// operator sees in a refusal. A sibling optional `kind_note` string lands on
// the same object: the oracle item is additionalProperties:false (:432), so
// the note is a real schema change and not free-form slack — without the
// declaration every model carrying a note would be refused outright.

import (
	"strings"
	"testing"
)

// oracleKindModel renders a minimal protocol_model document (the six
// top-level required keys, :9) carrying exactly one oracle of the given kind
// plus whatever extra members the case needs. `extra` is spliced verbatim
// after the kind so a case can add `, "kind_note": "..."` or a type-broken
// value.
func oracleKindModel(kind, extra string) string {
	return `{
 "protocol_id": "acme-vault",
 "name": "Acme Vault",
 "contracts": [{"name": "Vault"}],
 "actors": [{"id": "user", "kind": "EOA"}],
 "assets": [{"id": "USDC", "kind": "token"}],
 "relations": [],
 "oracles": [{"id": "ORC-1", "kind": "` + kind + `"` + extra + `}]
}`
}

// validateOracleModel parses and schema-validates one rendered document.
func validateOracleModel(t *testing.T, doc string) error {
	t.Helper()
	v, err := ParseOrdered([]byte(doc))
	if err != nil {
		t.Fatalf("parse protocol_model: %v", err)
	}
	return Validate(v, "protocol_model", 1)
}

// TestProtocolModelOracleKindOtherAndDataAvailability pins that both new enum
// values are admitted, that kind_note rides along, and — deliberately — that
// the note stays OPTIONAL at the schema layer: "required by convention" is a
// convention, not a validation rule, so a bare "other" still loads and the
// disclosure burden never becomes a wall.
func TestProtocolModelOracleKindOtherAndDataAvailability(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  string
		extra string
	}{
		{"other-with-note", "other",
			`, "kind_note": "in-house TWAP maintained by the protocol team"`},
		{"other-bare", "other", ``},
		{"data-availability", "data-availability",
			`, "kind_note": "EIP-4844 blobs posted through the sequencer inbox"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateOracleModel(t, oracleKindModel(tc.kind, tc.extra)); err != nil {
				t.Errorf("oracle kind %q must validate: %v", tc.kind, err)
			}
		})
	}
}

// TestProtocolModelOracleKindNoteIsOptionalString pins the kind_note type:
// the string form is admitted (above) and a non-string is refused by the
// declared `type` rather than by the additionalProperties catch-all.
func TestProtocolModelOracleKindNoteIsOptionalString(t *testing.T) {
	err := validateOracleModel(t, oracleKindModel("other", `, "kind_note": 42`))
	if err == nil {
		t.Fatal("kind_note: 42 must be refused")
	}
	if !strings.Contains(err.Error(), "kind_note") {
		t.Errorf("refusal must name the offending path kind_note: %q", err.Error())
	}
	// The type copy is the real pin: deleting the kind_note DECLARATION from
	// the schema leaves only the additionalProperties catch-all, whose text
	// also names the path — without this assertion that mutation passes.
	if !strings.Contains(err.Error(), "is not of type 'string'") {
		t.Errorf("refusal must come from the declared string type, not the "+
			"additionalProperties catch-all: %q", err.Error())
	}
}

// TestProtocolModelOracleKindUnknownRefused pins that the enum is still
// CLOSED — the two additions widen it, they do not open it — and that the
// refusal text lists the new values, which is how an operator learns the
// catch-all exists.
func TestProtocolModelOracleKindUnknownRefused(t *testing.T) {
	err := validateOracleModel(t, oracleKindModel("made-up-oracle", ""))
	if err == nil {
		t.Fatal(`oracle kind "made-up-oracle" must be refused`)
	}
	for _, want := range []string{"made-up-oracle", "data-availability", "other"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
}

// TestProtocolModelOracleLegendListsNewKinds pins the operator-facing legend
// line for the enum (SchemaEnumLegend is derived from the schema document, so
// this is the end-to-end proof the file — not a hand-maintained list — is the
// source) and the contractual ORDER: the seven pre-existing values keep their
// positions and the two new ones are appended.
func TestProtocolModelOracleLegendListsNewKinds(t *testing.T) {
	legend, err := SchemaEnumLegend("protocol_model")
	if err != nil {
		t.Fatal(err)
	}
	want := "oracles[]/kind: chainlink|twap|spot-amm|pyth|custom|manual|" +
		"sequencer-uptime|data-availability|other"
	for _, line := range legend {
		if strings.HasPrefix(line, "oracles[]/kind: ") {
			if line != want {
				t.Errorf("oracle-kind legend:\n got %q\nwant %q", line, want)
			}
			return
		}
	}
	t.Fatalf("legend carries no oracles[]/kind line:\n%s",
		strings.Join(legend, "\n"))
}
