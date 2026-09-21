package bounty

// The Phase 1 consistency criterion (framework-plan-v1.6 Part 7): every policy
// boolean naming an evidence tier is referenced by that tier's gate, or the
// build fails. Three directions, all required: a schema boolean with no
// binding is red; a binding whose check never fires is red; and a check that
// fires with the boolean OFF is red too — that last one is what distinguishes
// "the gate reads the boolean" from "the gate always runs this check".

import (
	"encoding/json"
	"strings"
	"testing"

	"websec/internal/validation"
)

// policyBooleanKeys returns every boolean key under
// poc_requirements in the EMBEDDED policy schema. Map iteration order is
// unspecified; every assertion below is order-independent.
func policyBooleanKeys(t *testing.T) []string {
	t.Helper()
	raw, err := validation.ReadSchemaFile("bounty_policy")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	props, _ := doc["properties"].(map[string]any)
	poc, _ := props["poc_requirements"].(map[string]any)
	fields, _ := poc["properties"].(map[string]any)
	if len(fields) == 0 {
		t.Fatal("bounty_policy schema has no poc_requirements.properties")
	}
	keys := make([]string, 0, len(fields))
	for key, spec := range fields {
		m, _ := spec.(map[string]any)
		if m["type"] == "boolean" {
			keys = append(keys, key)
		}
	}
	return keys
}

func TestPolicyBooleansAreReferencedByTheirGate(t *testing.T) {
	bound := map[string]PolicyGateBinding{}
	for _, b := range PolicyGateBindings {
		bound[b.Key] = b
	}
	for _, key := range policyBooleanKeys(t) {
		full := "poc_requirements." + key
		if _, ok := bound[full]; !ok {
			t.Errorf("%s is a policy boolean naming an evidence tier with no "+
				"gate binding — wire it to a check or delete it from the schema", full)
		}
	}
	for _, b := range PolicyGateBindings {
		if _, ok := BountyRemediation[b.Check]; !ok {
			t.Errorf("binding %s -> %q has no BountyRemediation entry", b.Key, b.Check)
		}
		assertCheckFollowsBoolean(t, b)
	}
}

// gateWithBoolean runs the gate on the standard fixture with one
// poc_requirements boolean forced on or off, and returns the emitted row for
// check (Null when the gate never emitted it).
func gateWithBoolean(t *testing.T, b PolicyGateBinding, on bool) validation.Value {
	t.Helper()
	c, fid := bountyFixture(t)
	p := testPolicy()
	req := validation.ObjAt(p, "poc_requirements")
	leaf := b.Key[strings.LastIndex(b.Key, ".")+1:]
	req.O = validation.SetOrAppend(req.O, leaf, validation.VBool(on))
	p.O = validation.SetOrAppend(p.O, "poc_requirements", req)
	result, err := EvaluateBountyGate(c, fid, p, true)
	if err != nil {
		t.Fatalf("%s (on=%v): gate: %v", b.Key, on, err)
	}
	return checkRow(result, b.Check)
}

// assertCheckFollowsBoolean is the second and third directions: the bound
// check must fire when the boolean is ON, and must not run at all when it is
// OFF. A row that appears either way means the binding is a label, not a gate.
func assertCheckFollowsBoolean(t *testing.T, b PolicyGateBinding) {
	t.Helper()
	if row := gateWithBoolean(t, b, true); row.Kind == validation.Null {
		t.Errorf("%s is bound to check %q, but the gate never emitted that row",
			b.Key, b.Check)
	}
	if row := gateWithBoolean(t, b, false); row.Kind != validation.Null {
		t.Errorf("check %q ran with %s = false — the gate does not read the "+
			"boolean it is bound to", b.Check, b.Key)
	}
}
