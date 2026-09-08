// unpriceable_schema_test.go ports
// tests/test_unpriceable_impact.py::test_schema_accepts_priceable_false_with_ceiling:
// the economic_impact addition is additive, and the block stays closed
// (additionalProperties false) so an invented figure is still rejected.
//
// The generated golden table (schema_golden_test.go) is not hand-edited: its
// rows are byte-exact probe output, and an additive optional property changes
// none of them.
package validation

import (
	"errors"
	"strings"
	"testing"
)

const unpSchemaCeiling = "capacity basis: the sink is an address[255] test " +
	"constant — no live liquidity bounds it"

// unpFindingJSON is the minimum schema-valid finding with an economic_impact
// block carrying the given body (raw JSON, so the test also pins the
// decoded-value path).
func unpFindingJSON(impact string) string {
	return `{"finding_id":"F-0123456789ab","campaign_id":"C-abc123def456",` +
		`"snapshot_ids":{"source":"abc123def456"},` +
		`"title":"Reentrancy in withdraw","status":"HYPOTHESIS",` +
		`"trajectory":"code",` +
		`"root_cause":{"class":"reentrancy","description":"withdraw allows ` +
		`reentrant calls"},` +
		`"attacker":{"profile":"arbitrary EOA","capabilities":[]},` +
		`"evidence":[],"risk":{},"dedup":{},"history":[],` +
		`"created_at":"2026-01-01T00:00:00Z",` +
		`"updated_at":"2026-01-01T00:00:00Z",` +
		`"economic_impact":` + impact + `}`
}

func TestFindingSchemaAcceptsPriceableFalseWithCeiling(t *testing.T) {
	v, err := ParseOrdered([]byte(unpFindingJSON(
		`{"priceable":false,"ceiling":` + CanonCompact(VStr(unpSchemaCeiling)) + `}`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(v, "finding", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// priceable alone is legal schema-wise (the API refuses it; the schema
	// must still accept the state an older/hand-edited file can hold)
	v, err = ParseOrdered([]byte(unpFindingJSON(`{"priceable":false}`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(v, "finding", 1); err != nil {
		t.Fatalf("bare flag must be schema-valid: %v", err)
	}
	// the block stays closed: an invented figure is an additional property
	v, err = ParseOrdered([]byte(unpFindingJSON(
		`{"priceable":false,"ceiling":` + CanonCompact(VStr(unpSchemaCeiling)) +
			`,"invented_figure":630450}`)))
	if err != nil {
		t.Fatal(err)
	}
	err = Validate(v, "finding", 1)
	if err == nil {
		t.Fatal("invented_figure must be rejected")
	}
	var se *SchemaError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T; want *SchemaError", err)
	}
	if !strings.Contains(se.Msg, "Additional properties are not allowed") ||
		!strings.Contains(se.Msg, "invented_figure") {
		t.Errorf("message = %q", se.Msg)
	}
}
