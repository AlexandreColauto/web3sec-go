package validation

import (
	"strings"
	"testing"
)

// schemaProps reads one schema document from the embedded assets and returns
// its top-level `properties` object.
func schemaProps(t *testing.T, name string) Value {
	t.Helper()
	raw, err := ReadSchemaFile(name)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	return vObjAt(schema, "properties")
}

// Port of tests/test_ingest.py::test_preconditions_has_schema_description:
// the two fields that were confused with each other carry the descriptions
// that tell them apart.
func TestFindingSchemaDescribesPreconditionsAndAssumptions(t *testing.T) {
	props := schemaProps(t, "finding")
	desc := schemaFieldStr(vObjAt(props, "preconditions"), "description")
	if !strings.Contains(desc, "NOT the claim's assumptions") {
		t.Errorf("preconditions.description = %q, want the assumptions pointer",
			desc)
	}
	ad := schemaFieldStr(vObjAt(props, "assumptions"), "description")
	if !strings.Contains(ad, "NOT to be confused") {
		t.Errorf("assumptions.description = %q, want the preconditions pointer",
			ad)
	}
}

// Port of tests/test_severity_split.py::test_finding_schema_accepts_new_fields.
func TestFindingSchemaAcceptsSeveritySplitFields(t *testing.T) {
	props := schemaProps(t, "finding")
	sev := schemaEnumStrings(vObjAt(props, "reported_severity"))
	want := "low,medium,high,critical"
	if strings.Join(sev, ",") != want {
		t.Fatalf("reported_severity enum = %v, want %s", sev, want)
	}
	raw, err := ReadSchemaFile("finding")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	risk := vObjAt(vObjAt(schema, "definitions"), "risk")
	iv := vObjAt(vObjAt(risk, "properties"), "impact_vector")
	keys := []string{}
	for _, kv := range vObjAt(iv, "properties").O {
		keys = append(keys, kv.K)
	}
	wantKeys := "asset_exposure,insolvency_risk,privilege_class," +
		"recoverability,score"
	if strings.Join(sortedStringsT35(keys), ",") != wantKeys {
		t.Fatalf("impact_vector properties = %v, want %s", keys, wantKeys)
	}
}

// schemaFieldStr reads a string field of an object value.
func schemaFieldStr(v Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == Str {
			return kv.V.S
		}
	}
	return ""
}

// schemaEnumStrings reads an `enum` array of strings.
func schemaEnumStrings(v Value) []string {
	out := []string{}
	for _, kv := range v.O {
		if kv.K == "enum" && kv.V.Kind == Arr {
			for _, e := range kv.V.A {
				out = append(out, e.S)
			}
		}
	}
	return out
}

// sortedStringsT35 is a tiny insertion sort (no extra imports for a fixture).
func sortedStringsT35(in []string) []string {
	out := append([]string{}, in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
