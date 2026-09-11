package validation

import (
	"strings"
	"testing"
)

// TestUnknownSchema pins the ported KeyError text (the known-schema tuple
// order is contractual).
func TestUnknownSchema(t *testing.T) {
	err := Validate(VObj(), "bogus", 1)
	if err == nil {
		t.Fatal("expected error for unknown schema")
	}
	want := "unknown schema 'bogus'; known: (" +
		"'finding', 'snapshot', 'campaign_state', 'protocol_model', " +
		"'campaign_plan', 'coverage', 'chain', 'bounty_policy', " +
		"'sandbox_execution', 'memory', 'drift_report', 'structural_index', " +
		"'relation', 'shared_signature', 'shared_memory_row', 'variant_ladder', " +
		"'price_table', 'assumption', 'model_request', 'model_response', " +
		"'trajectory', 'playbook', 'evaluation_case', 'archetype', " +
		"'sequence_poc', 'sequence_result', 'sft_example', 'probe_surface', " +
		"'class_weights')"
	if err.Error() != want {
		t.Errorf("unknown-schema text:\n got %q\nwant %q", err.Error(), want)
	}
	if _, ok := err.(*SchemaError); ok {
		t.Error("unknown schema must not be a *SchemaError")
	}
}

// TestValidFinding: the OQ3 base finding is schema-valid.
func TestValidFinding(t *testing.T) {
	v, err := ParseOrdered([]byte(`{
 "finding_id": "F-0123456789ab",
 "campaign_id": "C-abc123def456",
 "snapshot_ids": {"source": "abc123def456"},
 "title": "Reentrancy in withdraw",
 "status": "HYPOTHESIS",
 "trajectory": "code",
 "root_cause": {"class": "reentrancy", "description": "withdraw allows reentrant calls"},
 "attacker": {"profile": "arbitrary EOA", "capabilities": []},
 "evidence": [],
 "risk": {},
 "dedup": {},
 "history": [],
 "created_at": "2026-01-01T00:00:00Z",
 "updated_at": "2026-01-01T00:00:00Z"
}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(v, "finding", 1); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
}

// TestSingleErrorPapercut pins the "(+0 more errors)" suffix Python emits
// for a single-error document at max_errors=1, and its absence at
// max_errors>1.
func TestSingleErrorPapercut(t *testing.T) {
	// Build a finding with exactly one violation: bad status.
	mut := strings.Replace(validFindingJSON, `"status": "HYPOTHESIS"`, `"status": "BOGUS"`, 1)
	d, _ := ParseOrdered([]byte(mut))
	err := Validate(d, "finding", 1)
	var se *SchemaError
	if asSchemaError(err, &se) {
		want := "finding validation failed at status: 'BOGUS' is not one of " +
			"['HYPOTHESIS', 'NEEDS_RESEARCH', 'PROVISIONALLY_VALID', 'POSSIBLE', " +
			"'CONFIRMED', 'DISPROVED', 'DUPLICATE', 'OUT_OF_SCOPE', 'INFORMATIONAL', " +
			"'CHAIN', 'SUPERSEDED'] (+0 more errors)"
		if se.Msg != want {
			t.Errorf("single-error max_errors=1:\n got %q\nwant %q", se.Msg, want)
		}
	}
	err3 := Validate(d, "finding", 3)
	if asSchemaError(err3, &se) {
		if strings.Contains(se.Msg, "more errors") {
			t.Errorf("max_errors=3 must not carry a count line: %q", se.Msg)
		}
	}
}

// validFindingJSON is the shared OQ3 base finding.
const validFindingJSON = `{
 "finding_id": "F-0123456789ab",
 "campaign_id": "C-abc123def456",
 "snapshot_ids": {"source": "abc123def456"},
 "title": "Reentrancy in withdraw",
 "status": "HYPOTHESIS",
 "trajectory": "code",
 "root_cause": {"class": "reentrancy", "description": "withdraw allows reentrant calls"},
 "attacker": {"profile": "arbitrary EOA", "capabilities": []},
 "evidence": [],
 "risk": {},
 "dedup": {},
 "history": [],
 "created_at": "2026-01-01T00:00:00Z",
 "updated_at": "2026-01-01T00:00:00Z"
}`

func asSchemaError(err error, se **SchemaError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*SchemaError); ok {
		*se = e
		return true
	}
	return false
}
