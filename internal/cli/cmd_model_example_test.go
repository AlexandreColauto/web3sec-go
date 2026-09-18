package cli

// cmd_model_example_test.go — B1 (docs/feedback-triage-morph-r2.md §B1):
// `model --example`.
//
// The template has to be MORE than "some JSON": it is the shape contract an
// operator copies, so it must validate against protocol_model (the exact
// schema the load path enforces) and it must actually load. The negative
// control is the other half of that claim — a deliberately broken copy has to
// FAIL, or the test would pass on a fixture that satisfies nothing.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestModelExampleIsSchemaValid is the fixture contract: stdout parses,
// validates against protocol_model with a generous error budget, and stays
// pure JSON (the pointer prose rides stderr).
func TestModelExampleIsSchemaValid(t *testing.T) {
	// No --root and no campaign: --example wins before the campaign
	// requirement, exactly like scope/ingest.
	code, out, errS := run(t, "model", "--example")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (stderr %q)", code, errS)
	}
	if !strings.HasPrefix(out, "{\n  \"protocol_id\":") {
		t.Fatalf("stdout is not the template: %q", firstLine(out))
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Fatalf("stdout must end with the document's own newline: %q",
			out[len(out)-4:])
	}
	v, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("example is not JSON: %v", err)
	}
	if err := validation.Validate(v, "protocol_model", 25); err != nil {
		t.Fatalf("example fails its own schema: %v", err)
	}
	if strings.Contains(out, "schema: webv2 schema") {
		t.Fatalf("the pointer leaked to stdout (must stay pipeable)")
	}
	if !strings.Contains(errS, "webv2 model <campaign> model.json") {
		t.Errorf("stderr does not name the load command: %q", errS)
	}
	if !strings.Contains(errS, schemaPointerLine("protocol_model")) {
		t.Errorf("stderr does not carry the schema pointer: %q", errS)
	}
}

// TestModelExampleNegativeControl: a copy with one closed-enum value broken
// must be REFUSED, so the test above cannot pass on a fixture that satisfies
// nothing (or on a schema that stopped checking the field).
func TestModelExampleNegativeControl(t *testing.T) {
	_, out, _ := run(t, "model", "--example")
	broken := strings.Replace(out,
		`"severity_if_broken": "critical"`,
		`"severity_if_broken": "catastrophic"`, 1)
	if broken == out {
		t.Fatal("negative control did not apply — the example no longer " +
			"carries the severity_if_broken value this test breaks")
	}
	bv, err := validation.ParseOrdered([]byte(broken))
	if err != nil {
		t.Fatalf("broken copy does not parse: %v", err)
	}
	if err := validation.Validate(bv, "protocol_model", 25); err == nil {
		t.Fatal("a deliberately broken copy validated — the example is not " +
			"exercising protocol_model")
	}
}

// TestModelExampleWinsBeforeCampaignRequirement: a positional campaign (even
// a nonexistent one) does not turn --example into an open/validate path.
func TestModelExampleWinsBeforeCampaignRequirement(t *testing.T) {
	code, out, errS := run(t, "model", "--example", "C-does-not-exist")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (stderr %q)", code, errS)
	}
	if out != t14ExampleModel {
		t.Fatal("stdout is not the template verbatim")
	}
}

// TestModelExampleLoadsEndToEnd: the template is not just schema-valid, it
// loads through the real verb (the strongest available statement that the
// shape contract is the load contract).
func TestModelExampleLoadsEndToEnd(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	path := filepath.Join(root, "model.json")
	if err := os.WriteFile(path, []byte(t14ExampleModel), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "model", cid, path)
	if code != 0 {
		t.Fatalf("model load exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "model loaded:") {
		t.Fatalf("load output = %q, want the load report", out)
	}
	if !strings.Contains(out, "1 invariant(s)") {
		t.Fatalf("load output = %q, want the template's single invariant", out)
	}
}
