package validation

// schema_enum_test.go: the walker half of tests/test_ingest_discoverability.py
// — refs/array items resolve, dict-valued map schemas are descended, and the
// walker finds EVERY enum in the schema (brute-force completeness oracle).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func schemaOf(t *testing.T, doc string) Value {
	t.Helper()
	v, err := ParseOrdered([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Port of test_enum_walker_resolves_refs_and_array_items.
func TestEnumWalkerResolvesRefsAndArrayItems(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","properties":{
		"a":{"enum":["x","y"]},
		"b":{"type":"array","items":{"enum":["z"]}},
		"c":{"$ref":"#/definitions/d"}},
		"definitions":{"d":{"type":"object","properties":{
			"e":{"enum":["q",null]}}}}}`)
	got := EnumLegend(schema)
	want := []string{"a: x|y", "b[]: z", "c/e: q|null"}
	if len(got) != len(want) {
		t.Fatalf("legend = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("legend[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	paths := SchemaEnumPaths(schema)
	if len(paths) != 3 {
		t.Fatalf("paths = %d, want 3", len(paths))
	}
	if paths[2].Path != "c/e" || len(paths[2].Values) != 2 {
		t.Fatalf("ref path = %+v", paths[2])
	}
}

// Port of test_enum_walker_descends_into_dict_valued_map_schemas.
func TestEnumWalkerDescendsIntoDictValuedMapSchemas(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","properties":{
		"verdicts":{"type":"object","additionalProperties":
			{"enum":["same","distinct"]}},
		"named":{"type":"object","patternProperties":
			{"^x-":{"enum":["on","off"]}}},
		"closed":{"type":"object","additionalProperties":false}}}`)
	got := EnumLegend(schema)
	want := []string{
		"verdicts/additionalProperties: same|distinct",
		"named/patternProperties/^x-: on|off"}
	if len(got) != len(want) {
		t.Fatalf("legend = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("legend[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// a boolean additionalProperties is not a schema and yields no path
	for _, p := range SchemaEnumPaths(schema) {
		if p.Path == "closed/additionalProperties" {
			t.Fatal("additionalProperties:false must not be walked")
		}
	}
}

// bruteEnumPaths is _brute_enum_paths: every enum found by a GENERIC walk
// that descends into EVERY dict-valued keyword (not an allowlist), so a
// nesting the walker does not know about surfaces as a missing path.
func bruteEnumPaths(schema Value) []EnumPath {
	out := []EnumPath{}
	var walk func(node Value, path string, refs []string)
	walk = func(node Value, path string, refs []string) {
		if node.Kind != Obj {
			return
		}
		if ref := vObjStr(node, "$ref"); ref != "" {
			const prefix = "#/definitions/"
			if len(ref) > len(prefix) && ref[:len(prefix)] == prefix &&
				!inStrList(ref, refs) {
				walk(vObjAt(vObjAt(schema, "definitions"), ref[len(prefix):]),
					path, append(refs, ref))
			}
			return
		}
		if enum := vObjAt(node, "enum"); enum.Kind == Arr {
			out = append(out, EnumPath{Path: path, Values: enum.A})
		}
		for _, kv := range node.O {
			if kv.K == "definitions" || kv.K == "enum" {
				continue
			}
			switch {
			case kv.K == "properties" && kv.V.Kind == Obj:
				for _, ch := range kv.V.O {
					walk(ch.V, pathJoin(path, ch.K), refs)
				}
			case kv.K == "items":
				walk(kv.V, path+"[]", refs)
			case kv.V.Kind == Obj:
				walk(kv.V, pathJoin(path, kv.K), refs)
			}
		}
	}
	walk(schema, "", nil)
	return out
}

// Port of test_enum_walker_finds_every_enum_in_the_schema.
func TestEnumWalkerFindsEveryEnumInTheSchema(t *testing.T) {
	raw, err := ReadSchemaFile("finding")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	walked := SchemaEnumPaths(schema)
	brute := bruteEnumPaths(schema)
	if len(walked) < 20 {
		t.Fatalf("walker found only %d enums", len(walked))
	}
	// every definition is referenced from the root, so the ref-resolving
	// scan is a fair oracle (asserted, not assumed)
	defs := vObjAt(schema, "definitions")
	refs := regexp.MustCompile(`#/definitions/([A-Za-z0-9_]+)`).
		FindAllStringSubmatch(string(raw), -1)
	refSet := map[string]bool{}
	for _, m := range refs {
		refSet[m[1]] = true
	}
	if len(refSet) != len(defs.O) {
		t.Fatalf("refs = %d, definitions = %d", len(refSet), len(defs.O))
	}
	for _, kv := range defs.O {
		if !refSet[kv.K] {
			t.Fatalf("definition %q is never referenced", kv.K)
		}
	}
	if len(walked) != len(brute) {
		t.Fatalf("walked %d, brute %d\nwalked=%v\nbrute=%v", len(walked),
			len(brute), walked, brute)
	}
	toMap := func(paths []EnumPath) map[string]string {
		out := map[string]string{}
		for _, p := range paths {
			if _, dup := out[p.Path]; dup {
				t.Fatalf("path %q rendered twice", p.Path)
			}
			out[p.Path] = CanonCompact(VArr(p.Values...))
		}
		return out
	}
	walkedMap, bruteMap := toMap(walked), toMap(brute)
	for path, vals := range bruteMap {
		if walkedMap[path] != vals {
			t.Fatalf("path %q: walked %q, brute %q", path, walkedMap[path],
				vals)
		}
	}
	if len(walkedMap) != len(bruteMap) {
		t.Fatalf("paths: walked %d, brute %d", len(walkedMap), len(bruteMap))
	}
	found := false
	for _, p := range walked {
		if p.Path == "dedup/candidate_verdicts/additionalProperties" {
			found = true
		}
	}
	if !found {
		t.Fatal("the map-valued verdict enum is missing")
	}
}

// TestSchemaEnumLegendIsDerivedFromTheSchemaFile is
// test_legend_is_derived_from_the_schema_file: an enum added/removed in the
// schema FILE changes the legend with no code edit (Python monkeypatches
// validation.SCHEMA_DIR; the Go port points the same seam at a temp dir).
func TestSchemaEnumLegendIsDerivedFromTheSchemaFile(t *testing.T) {
	raw, err := ReadSchemaFile("finding")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	status := vObjAt(vObjAt(schema, "properties"), "status")
	status = setEnumValue(status, "BOGUS_STATUS")
	props := setMember(vObjAt(schema, "properties"), "status", status)
	sev := vObjAt(props, "reported_severity")
	sev = dropEnumValue(sev, "low")
	schema = setMember(schema, "properties",
		setMember(props, "reported_severity", sev))

	dir := t.TempDir()
	if err := writeSchemaFile(dir, "finding", schema); err != nil {
		t.Fatal(err)
	}
	SetSchemaDir(dir)
	defer ResetSchemaDir()

	legend, err := SchemaEnumLegend("finding")
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, ln := range legend {
		joined += ln + "\n"
	}
	if !containsLine(joined, "BOGUS_STATUS") {
		t.Fatalf("added enum missing from the legend:\n%s", joined)
	}
	if !containsLine(joined, "reported_severity: medium|high|critical") {
		t.Fatalf("removed enum still rendered:\n%s", joined)
	}
	if containsLine(joined, "reported_severity: low|") {
		t.Fatalf("removed value still rendered:\n%s", joined)
	}
}

// setMember is a single-key set that keeps the key's position.
func setMember(v Value, key string, val Value) Value {
	out := VObj()
	replaced := false
	for _, kv := range v.O {
		if kv.K == key {
			out.O = append(out.O, KV{K: key, V: val})
			replaced = true
			continue
		}
		out.O = append(out.O, kv)
	}
	if !replaced {
		out.O = append(out.O, KV{K: key, V: val})
	}
	return out
}

func setEnumValue(v Value, add string) Value {
	vals := append(append([]Value{}, vObjAt(v, "enum").A...), VStr(add))
	return setMember(v, "enum", VArr(vals...))
}

func dropEnumValue(v Value, drop string) Value {
	vals := []Value{}
	for _, x := range vObjAt(v, "enum").A {
		if x.Kind == Str && x.S == drop {
			continue
		}
		vals = append(vals, x)
	}
	return setMember(v, "enum", VArr(vals...))
}

func writeSchemaFile(dir, name string, schema Value) error {
	return os.WriteFile(filepath.Join(dir, name+".schema.json"),
		[]byte(CanonCompact(schema)), 0o644)
}

func containsLine(hay, needle string) bool { return strings.Contains(hay, needle) }
