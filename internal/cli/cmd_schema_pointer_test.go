package cli

// cmd_schema_pointer_test.go — B1(c): every `--example` branch ends with one
// ADDITIVE stderr line naming `webv2 schema <name>`.
//
// The whole point of the line is that it is additive: the bytes each branch
// printed before this change must still be there, in order, with exactly one
// line appended. These tests pin the pre-B1 stderr text (scope/model in full,
// ingest as prose + the schema-walked legend) and then the single appended
// pointer — so a future edit that reflows the existing prose fails here.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// scopeExampleStderrPreB1 is the byte-exact stderr `scope --example` printed
// before B1 (cmd_scope.go's contract line).
const scopeExampleStderrPreB1 = "this policy template IS the scope schema " +
	"contract: save as policy.json, replace program, program_url, chains and " +
	"scope with the program's own terms, then: webv2 scope <campaign> " +
	"--policy policy.json\n"

// modelExampleStderrPreB1 is the same for the B1 `model --example` branch's
// contract line (this file pins it as of its introduction).
const modelExampleStderrPreB1 = "this model template IS the protocol_model " +
	"schema contract: save as model.json, replace protocol_id, name, " +
	"contracts, actors, assets, relations and invariants with the protocol's " +
	"own, then: webv2 model <campaign> model.json\n"

// ingestExampleStderrPreB1 is ingest's contract prose, before the legend.
const ingestExampleStderrPreB1 = "This payload IS the ingest schema " +
	"contract: the fields, nesting and value types shown are exactly what " +
	"`webv2 ingest <campaign> --json-file` validates against — a payload that " +
	"differs in shape fails validation, and the error names the offending " +
	"field.\n" +
	"save as payload.json, then: webv2 ingest <campaign> --json-file " +
	"payload.json\n(or pipe: webv2 ingest --example | webv2 ingest " +
	"<campaign> --json-file -)\n"

// TestScopeExampleStderrKeepsItsBytesAndGainsThePointer: existing line
// verbatim, one pointer appended, stdout untouched.
func TestScopeExampleStderrKeepsItsBytesAndGainsThePointer(t *testing.T) {
	code, out, errS := run(t, "scope", "--example")
	if code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	want := scopeExampleStderrPreB1 + schemaPointerLine("bounty_policy")
	if errS != want {
		t.Fatalf("stderr = %q\nwant %q", errS, want)
	}
	if out != t14ExamplePolicy {
		t.Fatal("stdout is not the policy template verbatim")
	}
}

// TestModelExampleStderrKeepsItsBytesAndGainsThePointer: same contract for
// the new model branch.
func TestModelExampleStderrKeepsItsBytesAndGainsThePointer(t *testing.T) {
	code, out, errS := run(t, "model", "--example")
	if code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	want := modelExampleStderrPreB1 + schemaPointerLine("protocol_model")
	if errS != want {
		t.Fatalf("stderr = %q\nwant %q", errS, want)
	}
	if out != t14ExampleModel {
		t.Fatal("stdout is not the model template verbatim")
	}
}

// TestIngestExampleStderrKeepsItsBytesAndGainsThePointer: the prose and the
// schema-walked legend are byte-identical, the pointer is the last line.
func TestIngestExampleStderrKeepsItsBytesAndGainsThePointer(t *testing.T) {
	code, out, errS := run(t, "ingest", "--example")
	if code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	legend, err := validation.SchemaEnumLegend("finding")
	if err != nil {
		t.Fatalf("legend: %v", err)
	}
	var b strings.Builder
	b.WriteString(ingestExampleStderrPreB1)
	b.WriteString("closed-enum fields (auto-generated from " +
		"schema/finding.schema.json — every allowed value):\n")
	for _, line := range legend {
		b.WriteString("  " + line + "\n")
	}
	b.WriteString(schemaPointerLine("finding"))
	if errS != b.String() {
		t.Fatalf("stderr changed beyond the appended pointer:\ngot  %q\nwant %q",
			errS, b.String())
	}
	if out != t14ExamplePayload {
		t.Fatal("stdout is not the ingest payload verbatim")
	}
}

// TestExamplePointersNameRealSchemas: the pointer names a schema the new verb
// can actually serve, and the line is exactly one line — a pointer that
// names an unknown schema is worse than no pointer.
func TestExamplePointersNameRealSchemas(t *testing.T) {
	known := map[string]bool{}
	for _, n := range validation.KnownSchemas() {
		known[n] = true
	}
	for _, tc := range []struct {
		args []string
		name string
	}{
		{[]string{"ingest", "--example"}, "finding"},
		{[]string{"scope", "--example"}, "bounty_policy"},
		{[]string{"model", "--example"}, "protocol_model"},
	} {
		_, _, errS := run(t, tc.args...)
		line := schemaPointerLine(tc.name)
		if !known[tc.name] {
			t.Errorf("%v: pointer names unknown schema %q", tc.args, tc.name)
		}
		if !strings.HasSuffix(errS, line) {
			t.Errorf("%v: stderr does not end with the pointer %q: %q",
				tc.args, line, errS)
		}
		if strings.Count(errS, "schema: webv2 schema ") != 1 {
			t.Errorf("%v: stderr carries %d pointer lines, want exactly 1: %q",
				tc.args, strings.Count(errS, "schema: webv2 schema "), errS)
		}
		// And the pointer really is a runnable command.
		if code, _, _ := run(t, "schema", tc.name); code != 0 {
			t.Errorf("schema %s: exit %d, want 0", tc.name, code)
		}
	}
}
