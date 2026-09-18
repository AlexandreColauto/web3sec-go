package validation

// schema_enum_values_test.go: SchemaEnumValues — the path-addressed enum read
// (schema_enum.go) that the CLI's early `artifact-register --kind` refusal
// derives its allow-list from. Two properties matter to that caller and are
// pinned here: the values come back in SCHEMA DOCUMENT ORDER (the order the
// exit-2 message lists them in), and they come from the schema FILE, not a
// hand-maintained copy (the SCHEMA_DIR override, the same seam
// TestSchemaEnumLegendIsDerivedFromTheSchemaFile uses).

import (
	"testing"
)

// enumStrings renders a []Value through LegendValue, the spelling an operator
// types.
func enumStrings(vals []Value) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, LegendValue(v))
	}
	return out
}

func TestSchemaEnumValuesReadsTheNamedPathInDocumentOrder(t *testing.T) {
	vals, ok, err := SchemaEnumValues("campaign_state", "artifacts[]/kind")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("campaign_state has no enum at artifacts[]/kind")
	}
	got := enumStrings(vals)
	if len(got) < 2 {
		t.Fatalf("enum %v: want the artifact-row kind values", got)
	}
	// Document order: the schema's array starts at "recon" and ends at
	// "other" (assets/schema/campaign_state.schema.json, artifacts[].kind).
	// Both are load-bearing: the default kind this verb uses is "other", and
	// "recon" is the first value the refusal text lists.
	if got[0] != "recon" {
		t.Fatalf("first value = %q, want recon (document order)", got[0])
	}
	if got[len(got)-1] != "other" {
		t.Fatalf("last value = %q, want other (document order)", got[len(got)-1])
	}
	// The values the verb's help block names as common must really be legal.
	for _, want := range []string{"invariants", "report", "poc", "other"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("artifact-row kind enum is missing %q: %v", want, got)
		}
	}
	// A path with no enum is (nil, false, nil), never an empty allow-list and
	// never an error.
	none, ok, err := SchemaEnumValues("campaign_state", "artifacts[]/nope")
	if err != nil {
		t.Fatalf("a missing path must not be an error: %v", err)
	}
	if ok || len(none) != 0 {
		t.Fatalf("artifacts[]/nope: ok=%v values=%v, want false/nil", ok, none)
	}
}

// TestSchemaEnumValuesFollowsTheSchemaFile is the anti-hard-coding pin: the
// same lookup against a mutated schema FILE answers the mutated enum. A
// literal list in Go would keep answering "recon" and would keep rejecting
// the added value.
func TestSchemaEnumValuesFollowsTheSchemaFile(t *testing.T) {
	raw, err := ReadSchemaFile("campaign_state")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	// properties.artifacts.items.properties.kind.enum: add one value, drop
	// one, keeping every other key in place (setMember preserves position).
	props := vObjAt(schema, "properties")
	artifacts := vObjAt(props, "artifacts")
	items := vObjAt(artifacts, "items")
	itemProps := vObjAt(items, "properties")
	kind := vObjAt(itemProps, "kind")
	kind = dropEnumValue(setEnumValue(kind, "b2-bogus-kind"), "recon")
	schema = setMember(schema, "properties",
		setMember(props, "artifacts",
			setMember(artifacts, "items",
				setMember(items, "properties",
					setMember(itemProps, "kind", kind)))))

	dir := t.TempDir()
	if err := writeSchemaFile(dir, "campaign_state", schema); err != nil {
		t.Fatal(err)
	}
	SetSchemaDir(dir)
	defer ResetSchemaDir()

	vals, ok, err := SchemaEnumValues("campaign_state", "artifacts[]/kind")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the mutated schema still holds the enum")
	}
	got := enumStrings(vals)
	has := func(x string) bool {
		for _, g := range got {
			if g == x {
				return true
			}
		}
		return false
	}
	if !has("b2-bogus-kind") {
		t.Fatalf("the value added to the schema FILE is missing: %v", got)
	}
	if has("recon") {
		t.Fatalf("the value dropped from the schema FILE is still there: %v",
			got)
	}
	if got[len(got)-1] != "b2-bogus-kind" {
		t.Fatalf("added value must land last (document order): %v", got)
	}
}
