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
// verdict sidecar). The key set and the promised shapes are what the
// schema owns; every VALUE is copied verbatim from the prover's line, and
// additionalProperties:false still bites (the rejection rows below).
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
		`"ghosts":[{"slot":"total","expr":"x+1"}],` +
		`"invariant":{"name":"cap_respected","per_function":[` +
		`{"selector":"0xd0e30db0","function":"deposit","kind":"proved",` +
		`"reason":null,"details":""}],` +
		`"init":{"selector":"constructor","function":"constructor",` +
		`"kind":"proved","reason":null,"details":""},` +
		`"witness_function":null},` +
		`"calls":[{"step":1,"function":"withdraw","reverted":true}]}}}}`
	v := mustParseHarness(t, harnessModelDoc(inv))
	v2 := mustParseHarness(t, CanonCompact(v))
	if err := Validate(v2, "protocol_model", 1); err != nil {
		t.Fatalf("proof sidecar must validate: %v", err)
	}
	// The proof rejections (unknown key, fourth bounds key, scalar shape)
	// are pinned by TestVerificationHarnessRejects below.
}

// TestVerificationHarnessProofNullArrays pins the mcArr contract in the
// schema: a scalar in an array slot is malformed tool input, and the Go
// builder renders those three slots as null rather than dropping the key
// or inventing an empty list — so the sidecar's sets must accept null.
func TestVerificationHarnessProofNullArrays(t *testing.T) {
	inv := `{"id":"INV-1",` +
		`"statement":"total assets must cover all outstanding shares",` +
		`"severity_if_broken":"critical",` +
		`"verification":{"harness":{"kind":"minicertora",` +
		`"rung":"proved-bounded","exec":"EXEC-7","bounded_k":null,` +
		`"summary":"proved bounded","proof":{` +
		`"tool_version":"0.4.2","solc_version":null,` +
		`"spec_version":null,"evm_version":null,` +
		`"confidence":"modeled","reason":null,` +
		`"bounds":{"loop_bound":null,"path_cap":null,` +
		`"solver_timeout_ms":null},` +
		`"assumptions":null,"warnings":null,"ghosts":null,` +
		`"invariant":null,"calls":null}}}}`
	v := mustParseHarness(t, harnessModelDoc(inv))
	v2 := mustParseHarness(t, CanonCompact(v))
	if err := Validate(v2, "protocol_model", 1); err != nil {
		t.Fatalf("null array slots must validate: %v", err)
	}
}

// TestVerificationHarnessProofVerbatimValues pins the final-review ruling:
// the schema must stop contradicting the mapper's verbatim law. mcOr/
// mcArr copy the prover's own report values as parsed
// (internal/harness/minicertora.go; the mixed-kind assumptions row
// [1,"two",null] is pinned by TestMapMinicertoraProofArraysVerbatim), so a
// malformed tool value — a number in a version slot, a non-string caveat
// item, a string where a bound integer was promised — must stay copyable
// evidence and VALIDATE. The contract is the key set and the promised
// shapes (arrays-or-null, bounds-or-null object), never the value types.
func TestVerificationHarnessProofVerbatimValues(t *testing.T) {
	inv := `{"id":"INV-1",` +
		`"statement":"total assets must cover all outstanding shares",` +
		`"severity_if_broken":"critical",` +
		`"verification":{"harness":{"kind":"minicertora",` +
		`"rung":"inconclusive","exec":"EXEC-7","bounded_k":null,` +
		`"summary":"inconclusive (solver-timeout: x)","proof":{` +
		`"tool_version":42,"solc_version":{"build":"0.8.36"},` +
		`"spec_version":["v0.1"],"evm_version":false,` +
		`"confidence":3.5,"reason":{"code":7},` +
		`"bounds":{"loop_bound":"eight","path_cap":[1,2],` +
		`"solver_timeout_ms":{"ms":null}},` +
		`"assumptions":[1,"two",null],"warnings":[{"code":"w1"}],` +
		`"ghosts":["nope",3],` +
		// RULING-12KEY: the promised SHAPES are object-or-null and
		// array-or-null, and the values INSIDE them are admitted
		// verbatim — a malformed inner roll-up still validates.
		`"invariant":{"per_function":"not-a-list"},` +
		`"calls":[{"step":"one","args":"not-a-list"}]}}}}`
	v := mustParseHarness(t, harnessModelDoc(inv))
	v2 := mustParseHarness(t, CanonCompact(v))
	if err := Validate(v2, "protocol_model", 1); err != nil {
		t.Fatalf("verbatim (malformed-but-copyable) proof values must "+
			"validate: %v", err)
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
		// The required array: the twelve-key sidecar set is mandatory
		// (mcProof always emits all twelve keys), so a proof object that
		// drops one — a hand-written or drifted sidecar — is refused with
		// the missing key named.
		{"proof missing warnings key",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"proved-bounded","exec":"EXEC-7",` +
				`"proof":{"tool_version":"0.4.2","solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":"modeled","reason":null,"bounds":null,` +
				`"assumptions":[],"ghosts":[],` +
				`"invariant":null,"calls":null}}}`,
			"warnings"},
		// RULING-12KEY's two new keys are as mandatory as their ten
		// siblings: dropping either one is refused by name.
		{"proof missing invariant key",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"proved-bounded","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,"bounds":null,` +
				`"assumptions":[],"warnings":[],"ghosts":[],` +
				`"calls":null}}}`,
			"invariant"},
		{"proof missing calls key",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"proved-bounded","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,"bounds":null,` +
				`"assumptions":[],"warnings":[],"ghosts":[],` +
				`"invariant":null}}}`,
			"calls"},
		// The verbatim ruling loosens VALUES, not the KEYS: an unknown
		// proof key is still refused (additionalProperties:false).
		{"unknown proof key",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"inconclusive","exec":"EXEC-7",` +
				`"proof":{"bogus":1}}}`,
			"bogus"},
		// ...and so is a fourth key inside the fixed three-key bounds
		// object, whatever its value's shape. (The required set is
		// spelled out so the bounds violation is the error reported,
		// not ten missing-key errors.)
		{"bounds fourth key",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"proved-bounded","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,` +
				`"bounds":{"loop_bound":4,"path_cap":64,` +
				`"solver_timeout_ms":30000,"loop_bound_exhaustive":true},` +
				`"assumptions":[],"warnings":[],"ghosts":[],` +
				`"invariant":null,"calls":null}}}`,
			"loop_bound_exhaustive"},
		// The promised SHAPES still hold: an array-or-null slot may not
		// be a scalar, and bounds may not be a scalar either. (mcArr
		// renders such a tool value as null, so these never ship — but a
		// hand-written sidecar is refused, not silently blessed.)
		{"ghosts scalar",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"inconclusive","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,"bounds":null,` +
				`"assumptions":[],"warnings":[],` +
				`"ghosts":"not-a-list","invariant":null,"calls":null}}}`,
			"ghosts"},
		{"bounds scalar",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"inconclusive","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,"bounds":7,` +
				`"assumptions":[],"warnings":[],"ghosts":[],` +
				`"invariant":null,"calls":null}}}`,
			"bounds"},
		// RULING-12KEY's own shape floors: invariant is
		// object-or-null, calls is array-or-null. A scalar in either
		// slot is refused (mcObjOr/mcArrOr would have rendered null —
		// a hand-written sidecar may not smuggle one in).
		{"invariant scalar",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"inconclusive","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,"bounds":null,` +
				`"assumptions":[],"warnings":[],"ghosts":[],` +
				`"invariant":"nope","calls":null}}}`,
			"invariant"},
		{"calls scalar",
			`,"verification":{"harness":{"kind":"minicertora",` +
				`"rung":"inconclusive","exec":"EXEC-7",` +
				`"proof":{"tool_version":null,"solc_version":null,` +
				`"spec_version":null,"evm_version":null,` +
				`"confidence":null,"reason":null,"bounds":null,` +
				`"assumptions":[],"warnings":[],"ghosts":[],` +
				`"invariant":null,"calls":"nope"}}}`,
			"calls"},
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
