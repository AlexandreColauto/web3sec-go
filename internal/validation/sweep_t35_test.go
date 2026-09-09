package validation

// T35 testmap re-triage:
// tests/test_symmetry_teeth.py::test_lens_schema_has_symmetry_and_priority_has_sibling_of
// — the campaign_plan schema declares the L-04 symmetry table (>= 1 quoted
// primitive per family) and the nullable sibling_of pointer.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLensSchemaHasSymmetryAndPriorityHasSiblingOf(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "schema",
		"campaign_plan.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props, _ := doc["properties"].(map[string]any)
	lensProps := props["lenses"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	sym, ok := lensProps["symmetry"].(map[string]any)
	if !ok {
		t.Fatal("lenses[].symmetry is not declared in the schema")
	}
	items := sym["items"].(map[string]any)
	required := map[string]bool{}
	for _, r := range items["required"].([]any) {
		required[r.(string)] = true
	}
	for _, key := range []string{"family", "primitives"} {
		if !required[key] {
			t.Errorf("symmetry.items.required lacks %q: %v", key,
				items["required"])
		}
	}
	prims := items["properties"].(map[string]any)["primitives"].(map[string]any)
	if got := prims["minItems"]; got != float64(1) {
		t.Errorf("symmetry.items.properties.primitives.minItems = %v, want 1",
			got)
	}
	prioProps := props["priorities"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	sib, ok := prioProps["sibling_of"].(map[string]any)
	if !ok {
		t.Fatal("priorities[].sibling_of is not declared in the schema")
	}
	hasNull := false
	switch typ := sib["type"].(type) {
	case []any:
		for _, tv := range typ {
			if tv == "null" {
				hasNull = true
			}
		}
	case string:
		hasNull = typ == "null"
	}
	if !hasNull {
		t.Errorf("sibling_of.type = %v, want it to allow null", sib["type"])
	}
}
