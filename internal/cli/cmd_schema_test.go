package cli

// cmd_schema_test.go — B1 (docs/feedback-triage-morph-r2.md §B1):
// `webv2 schema [--list] [<name>]`.
//
// The verb's contract is a byte contract: the name list is the contractual
// knownSchemas order, `schema <name>` is the RAW embedded document (the same
// bytes validation.ReadSchemaFile hands Validate), and an unknown name is the
// canonical `unknown schema 'x'; known: (...)` refusal at exit 2 — never a
// second, drifting spelling of the list.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestSchemaListMatchesKnownSchemas: both spellings of the listing print the
// knownSchemas list in its contractual order, one name per line, and nothing
// else.
func TestSchemaListMatchesKnownSchemas(t *testing.T) {
	want := strings.Join(validation.KnownSchemas(), "\n") + "\n"
	if want == "\n" {
		t.Fatal("knownSchemas is empty")
	}
	for _, args := range [][]string{{"schema"}, {"schema", "--list"}} {
		code, out, errS := run(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d, want 0 (stderr %q)", args, code, errS)
		}
		if errS != "" {
			t.Errorf("%v: stderr = %q, want empty", args, errS)
		}
		if out != want {
			t.Errorf("%v: stdout = %q, want the knownSchemas list %q",
				args, out, want)
		}
	}
}

// TestSchemaPrintsRawEmbeddedBytes: `schema <name>` is the raw document —
// byte-identical to ReadSchemaFile (no re-indent, no appended newline beyond
// the file's own), so `webv2 schema finding | jq .` sees the enforced bytes.
func TestSchemaPrintsRawEmbeddedBytes(t *testing.T) {
	for _, name := range []string{"finding", "protocol_model",
		"bounty_policy", "campaign_state"} {
		code, out, errS := run(t, "schema", name)
		if code != 0 {
			t.Fatalf("schema %s: exit %d (stderr %q)", name, code, errS)
		}
		if errS != "" {
			t.Errorf("schema %s: stderr = %q, want empty", name, errS)
		}
		raw, err := validation.ReadSchemaFile(name)
		if err != nil {
			t.Fatalf("ReadSchemaFile(%s): %v", name, err)
		}
		if out != string(raw) {
			t.Errorf("schema %s: stdout is not the embedded bytes "+
				"(len %d vs %d)", name, len(out), len(raw))
		}
		if !strings.Contains(out, `"$schema"`) {
			t.Errorf("schema %s: stdout does not look like a schema document",
				name)
		}
	}
}

// TestSchemaUnknownNameExits2: the refusal reuses validation's canonical text
// (schema.go:51) verbatim, on stderr, at exit 2, with stdout empty.
func TestSchemaUnknownNameExits2(t *testing.T) {
	code, out, errS := run(t, "schema", "bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errS)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty (a refusal is stderr-only)", out)
	}
	want := validation.Validate(validation.VNull(), "bogus", 1).Error() + "\n"
	if errS != want {
		t.Fatalf("stderr = %q, want the canonical unknown-schema text %q",
			errS, want)
	}
	if !strings.HasPrefix(errS, "unknown schema 'bogus'; known: ('finding'") {
		t.Errorf("stderr lost the knownSchemas list: %q", errS)
	}
}

// TestSchemaHelpExitsZero: -h/--help answers before any argument validation
// (help_test.go's rule) with this verb's own block.
func TestSchemaHelpExitsZero(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, out, errS := run(t, "schema", flag)
		if code != 0 {
			t.Fatalf("schema %s: exit %d, want 0 (stderr %q)", flag, code, errS)
		}
		if errS != "" {
			t.Errorf("schema %s: stderr = %q, want empty", flag, errS)
		}
		if !strings.HasPrefix(out, "usage: webv2 schema [-h] [--list] [name]\n") {
			t.Errorf("schema %s: usage line = %q", flag, firstLine(out))
		}
		if !strings.Contains(out, "--list") || !strings.Contains(out, "name") {
			t.Errorf("schema %s: help does not advertise the name/--list "+
				"arguments: %q", flag, out)
		}
	}
}

// TestSchemaListWithNameIsRefused: `--list` and a name are mutually
// exclusive; silently listing (or silently printing) would hide the typo.
func TestSchemaListWithNameIsRefused(t *testing.T) {
	code, out, errS := run(t, "schema", "--list", "finding")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errS)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	want := schemaUsage + "webv2 schema: error: argument --list: " +
		"not allowed with argument name\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

// TestSchemaSurplusArgumentIsUnrecognized: a second positional is the ROOT
// parser's failure, like every other t14 verb.
func TestSchemaSurplusArgumentIsUnrecognized(t *testing.T) {
	code, _, errS := run(t, "schema", "finding", "extra")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errS)
	}
	want := t14TopUsage + "webv2: error: unrecognized arguments: extra\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}
