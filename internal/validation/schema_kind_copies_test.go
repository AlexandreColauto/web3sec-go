package validation

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

// The declaration's kind vocabulary — the words input_artifacts[].kind accepts
// — is written into TWO schema documents in the pack: the standalone
// model_request contract ValidateRequest enforces, and the trajectory ledger's
// own copy of the same record (definitions.model_request), which
// ValidateDefinitionFailures compiles a SECOND time when a model.request event
// is read back. Nothing makes one derive from the other: the loader here
// registers exactly one resource per compile (loadSchema: one AddResource, no
// UseLoader) and v6's default FileLoader rejects the https:// loc, so a
// cross-file $ref does not even compile; SchemaEnumPaths follows only local
// #/definitions/ refs, so a remote ref would also drop the enum from the
// legend. The duplicate therefore stays, and this is the guard that the two
// copies are the same set — the drift it exists for is a widening applied to
// one file, which leaves the ledger refusing events the boundary accepts.
//
// declarationKindCopies is the same vocabulary as (schema, JSON path into the
// embedded document), read through ReadSchemaFile — the pack's own bytes,
// never a restatement of the list. Order: the enforced contract first, the
// ledger's copy second, so a failure names the document that moved.
var declarationKindCopies = []struct {
	schema string
	path   []string
}{
	{"model_request", []string{"properties", "input_artifacts", "items",
		"properties", "kind", "enum"}},
	{"trajectory", []string{"definitions", "model_request", "properties",
		"input_artifacts", "items", "properties", "kind", "enum"}},
}

// enumAtPath reads one closed enum out of a named schema document. A path that
// no longer lands on a string array is a hard failure, not an empty list: the
// property moved and this test would otherwise compare two nothings.
func enumAtPath(t *testing.T, schema string, path []string) []string {
	t.Helper()
	raw, err := ReadSchemaFile(schema)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	node := doc
	for _, key := range path {
		node = ObjAt(node, key)
	}
	where := schema + ".schema.json " + strings.Join(path, ".")
	if node.Kind != Arr {
		t.Fatalf("%s is %s, want the enum array — the kind vocabulary moved "+
			"and this test no longer reads it", where, CanonSpaced(node))
	}
	out := make([]string, 0, len(node.A))
	for _, v := range node.A {
		if v.Kind != Str {
			t.Fatalf("%s holds a non-string %s", where, CanonSpaced(v))
		}
		out = append(out, v.S)
	}
	return out
}

// TestDeclarationKindCopiesAgree holds the pack's two copies of the
// declaration's kind vocabulary equal AS SETS. Order is not part of the
// contract: draft-07 `enum` matches membership, so a reordering changes no
// verdict, while a member present in one copy and absent from the other does —
// it is either a kind no truthful declaration can name (the ledger copy is
// short) or a kind the ledger refuses after the boundary accepted it (the
// request copy is short). That asymmetry is the whole finding this guards.
func TestDeclarationKindCopiesAgree(t *testing.T) {
	enforced := declarationKindCopies[0]
	want := enumAtPath(t, enforced.schema, enforced.path)
	sort.Strings(want)
	for _, copy := range declarationKindCopies[1:] {
		got := enumAtPath(t, copy.schema, copy.path)
		sort.Strings(got)
		if !slices.Equal(want, got) {
			t.Fatalf("the declaration's kind vocabulary is written in two schema "+
				"documents and they disagree:\n  %s %s = %q\n  %s %s = %q\n"+
				"a kind one copy lacks is a kind the other document's verdict "+
				"refuses (or accepts and the ledger then refuses)",
				enforced.schema, strings.Join(enforced.path, "."), want,
				copy.schema, strings.Join(copy.path, "."), got)
		}
	}
}
