package validation

// Task 18 (G8) schema round-trip: the OPTIONAL verification.harness rung
// object on protocol_model invariant items. With the field absent the
// schema accepts exactly as before (golden campaigns carry no such field);
// with it present every rung validates, bounded_k accepts int-or-null,
// and the enum / required / additionalProperties guards hold.

import (
	"strings"
	"testing"
)

// harnessModelDoc wraps one invariant fragment in a minimal valid
// protocol_model document.
func harnessModelDoc(inv string) string {
	return `{"protocol_id":"sharevault","name":"ShareVault",` +
		`"contracts":[{"name":"C"}],"actors":[{"id":"a","kind":"EOA"}],` +
		`"assets":[{"id":"t","kind":"token"}],"relations":[],` +
		`"invariants":[` + inv + `]}`
}

const harnessBaseInv = `{"id":"INV-1",` +
	`"statement":"total assets must cover all outstanding shares",` +
	`"severity_if_broken":"critical"}`

func mustParseHarness(t *testing.T, doc string) Value {
	t.Helper()
	v, err := ParseOrdered([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return v
}

func TestVerificationHarnessAbsentStillValid(t *testing.T) {
	v := mustParseHarness(t, harnessModelDoc(harnessBaseInv))
	if err := Validate(v, "protocol_model", 1); err != nil {
		t.Fatalf("invariant without verification.harness must stay valid: %v",
			err)
	}
}

func TestVerificationHarnessRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		rung string
		bk   string
	}{
		{"counterexample null bound", "counterexample", "null"},
		{"proved-bounded int bound", "proved-bounded", "100"},
		{"inconclusive null bound", "inconclusive", "null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := `{"id":"INV-1",` +
				`"statement":"total assets must cover all outstanding shares",` +
				`"severity_if_broken":"critical",` +
				`"verification":{"harness":{"kind":"halmos",` +
				`"rung":"` + tc.rung + `","exec":"EXEC-7",` +
				`"bounded_k":` + tc.bk + `,"summary":"s"}}}`
			// Round-trip through the canonical writer first, so the
			// shape validated is the shape the registry persists.
			v := mustParseHarness(t, harnessModelDoc(inv))
			v2 := mustParseHarness(t, CanonCompact(v))
			if err := Validate(v2, "protocol_model", 1); err != nil {
				t.Fatalf("rung %q must validate: %v", tc.rung, err)
			}
		})
	}
}

// TestVerificationHarnessProofSidecar pins the Task-4 schema extension:
// verification.harness carries an OPTIONAL proof object (the minicertora
// verdict sidecar). Every scalar is nullable, ghosts items are copied
// verbatim (unconstrained), and additionalProperties:false still bites.
func TestVerificationHarnessProofSidecar(t *testing.T) {
	inv := `{"id":"INV-1",` +
		`"statement":"total assets must cover all outstanding shares",` +
		`"severity_if_broken":"critical",` +
		`"verification":{"harness":{"kind":"minicertora",` +
		`"rung":"proved-bounded","exec":"EXEC-7","bounded_k":4,` +
		`"summary":"proved bounded (k=4)","proof":{` +
		`"tool_version":"0.4.2","solc_version":"0.8.36",` +
		`"spec_version":"v0.1","evm_version":"paris",` +
		`"confidence":"modeled","reason":null,` +
		`"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},` +
		`"assumptions":["msg.value-default-zero"],"warnings":[],` +
		`"ghosts":[{"slot":"total","expr":"x+1"}]}}}}`
	v := mustParseHarness(t, harnessModelDoc(inv))
	v2 := mustParseHarness(t, CanonCompact(v))
	if err := Validate(v2, "protocol_model", 1); err != nil {
		t.Fatalf("proof sidecar must validate: %v", err)
	}
	// A key the sidecar does not name is still rejected.
	bad := `{"id":"INV-1",` +
		`"statement":"s","severity_if_broken":"critical",` +
		`"verification":{"harness":{"kind":"minicertora",` +
		`"rung":"inconclusive","exec":"EXEC-7",` +
		`"proof":{"bogus":1}}}}`
	if err := Validate(mustParseHarness(t, harnessModelDoc(bad)),
		"protocol_model", 1); err == nil {
		t.Fatal("an unknown proof property must fail validation")
	}
}

func TestVerificationHarnessRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		inv  string
		want string
	}{
		{"bad rung enum",
			`,"verification":{"harness":{"kind":"halmos",` +
				`"rung":"proven","exec":"EXEC-7"}}`,
			"rung"},
		{"missing exec",
			`,"verification":{"harness":{"kind":"halmos",` +
				`"rung":"inconclusive"}}`,
			"exec"},
		{"extra property",
			`,"verification":{"harness":{"kind":"halmos",` +
				`"rung":"inconclusive","exec":"EXEC-7","ladder":"x"}}`,
			"ladder"},
		{"bad bounded_k type",
			`,"verification":{"harness":{"kind":"halmos",` +
				`"rung":"proved-bounded","exec":"EXEC-7","bounded_k":"100"}}`,
			"bounded_k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := `{"id":"INV-1",` +
				`"statement":"total assets must cover all outstanding shares",` +
				`"severity_if_broken":"critical"` + tc.inv + `}`
			v := mustParseHarness(t, harnessModelDoc(inv))
			err := Validate(v, "protocol_model", 1)
			if err == nil {
				t.Fatalf("invalid harness object must fail validation")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q must mention %q", err.Error(),
					tc.want)
			}
		})
	}
}
