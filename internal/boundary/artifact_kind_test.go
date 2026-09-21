package boundary

// The declaration rests on two vocabularies: the id-bearing KEY prefixes the
// cited-set walk matches on, and the kind words input_artifacts[].kind.enum
// accepts. They must be the SAME SET — an id collected under `evidence_id` is
// only declarable if the enum names "evidence" — so both are read from their
// producers (the compiled key pattern, the embedded schema documents) and held
// equal, and a REAL critic bundle is then declared truthfully.

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/roles"
	"websec/internal/validation"
)

// declarationKindVocabularies are the two places the declaration's kind
// vocabulary is WRITTEN, as (schema, JSON path) into the embedded document: the
// standalone model_request contract ValidateRequest enforces, and the
// trajectory ledger's model_request definition — the SAME record, validated a
// second time when the event is read back (trajectory.contractFailures). Both
// are the declaration's contract; a kind one of them lacks is a kind no
// recorded request may name.
var declarationKindVocabularies = []struct {
	schema string
	path   []string
}{
	{"model_request", []string{"properties", "input_artifacts", "items",
		"properties", "kind", "enum"}},
	{"trajectory", []string{"definitions", "model_request", "properties",
		"input_artifacts", "items", "properties", "kind", "enum"}},
}

// schemaEnumAt reads one enum out of a named schema document. The document is
// the producer's own bytes (validation.ReadSchemaFile reads the embedded
// assets), so the vocabulary compared below is never a restatement of it.
func schemaEnumAt(t *testing.T, schema string, path []string) []string {
	t.Helper()
	raw, err := validation.ReadSchemaFile(schema)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	node := doc
	for _, key := range path {
		node = validation.ObjAt(node, key)
	}
	where := schema + " " + strings.Join(path, ".")
	if node.Kind != validation.Arr {
		t.Fatalf("%s is %s, want the enum array — the kind vocabulary moved "+
			"and this test no longer reads it", where, validation.CanonSpaced(node))
	}
	out := make([]string, 0, len(node.A))
	for _, v := range node.A {
		if v.Kind != validation.Str {
			t.Fatalf("%s holds a non-string %s", where, validation.CanonSpaced(v))
		}
		out = append(out, v.S)
	}
	return out
}

// TestArtifactKeyPrefixesMatchDeclarationKinds is the drift guard: the prefixes
// ArtifactKeyPrefixes reads out of the compiled pattern and every enum that
// declares the kind vocabulary are compared as sets. A prefix with no enum
// member is an id no truthful declaration can name (the finding this test
// exists for: seven prefixes, six kinds); an enum member with no prefix is a
// kind no id-bearing key ever produces.
func TestArtifactKeyPrefixesMatchDeclarationKinds(t *testing.T) {
	matched := ArtifactKeyPrefixes()
	if len(matched) == 0 {
		t.Fatal("ArtifactKeyPrefixes read no alternation out of the compiled " +
			"key pattern — the accessor no longer reads the pattern it documents")
	}
	sort.Strings(matched)
	for _, vocab := range declarationKindVocabularies {
		declared := schemaEnumAt(t, vocab.schema, vocab.path)
		sort.Strings(declared)
		if !slices.Equal(matched, declared) {
			t.Fatalf("the key pattern's prefixes %q and %s %s %q are not the "+
				"same set: an id collected under a prefix with no matching kind "+
				"cannot be declared truthfully", matched, vocab.schema,
				strings.Join(vocab.path, "."), declared)
		}
	}
}

// eachKeyedID calls visit(kind, id) for every id the bundle carries under an
// id-bearing key, with the kind named by the key itself — never guessed from
// the id's shape.
func eachKeyedID(bundle validation.Value, visit func(kind, id string)) {
	var walk func(v validation.Value)
	walk = func(v validation.Value) {
		switch v.Kind {
		case validation.Obj:
			for _, kv := range v.O {
				kind, ok := ArtifactKeyKind(kv.K)
				if !ok {
					walk(kv.V)
					continue
				}
				collectIDs(kv.V, func(id string) { visit(kind, id) })
			}
		case validation.Arr:
			for _, e := range v.A {
				walk(e)
			}
		}
	}
	walk(bundle)
}

// truthfulDeclaration declares every id the bundle cites under the kind its own
// key names: nothing is relabelled to fit the vocabulary.
func truthfulDeclaration(bundle validation.Value) validation.Value {
	out := []validation.Value{}
	eachKeyedID(bundle, func(kind, id string) {
		if !saneArtifactID(id) || isNonArtifactID(id) {
			return
		}
		out = append(out, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr(kind)},
			validation.KV{K: "id", V: validation.VStr(id)}))
	})
	return validation.VArr(out...)
}

// criticRequest is the record a critic stage would write for this bundle: the
// truthful declaration, the critic role, and its response contract.
func criticRequest(bundle validation.Value) validation.Value {
	return BuildRequest(bundle, truthfulDeclaration(bundle), "critic",
		"qwen3-14b:local", "0123456789abcdef", "critic_verdict")
}

// declaresKind reports whether the declaration names id under kind.
func declaresKind(decl validation.Value, kind, id string) bool {
	for _, a := range decl.A {
		if validation.ObjStr(a, "kind") == kind && validation.ObjStr(a, "id") == id {
			return true
		}
	}
	return false
}

// TestRealCriticBundleCanBeDeclaredTruthfully is the acceptance half. The
// critic bundle roles.BuildCriticContext builds for a real campaign cites the
// finding, its pinned snapshot AND its recorded evidence item; declaring those
// under their own kinds must satisfy ValidateRequest. It could not before: the
// kind vocabulary had no "evidence", so the evidence id was either refused or
// declared as "artifact" — a lie the record then carried.
func TestRealCriticBundleCanBeDeclaredTruthfully(t *testing.T) {
	c, fid := realCampaignWithAFinding(t)
	bundle, err := roles.BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	decl := truthfulDeclaration(bundle)
	if err := ValidateRequest(criticRequest(bundle)); err != nil {
		t.Fatalf("a truthful declaration of a real critic bundle was refused: %v",
			err)
	}
	// Non-vacuity: the refusal this fix removes was on the EVIDENCE item, so
	// every evidence id the finding recorded must be declared as one.
	finding, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range validation.ObjAt(finding, "evidence").A {
		eid := validation.ObjStr(e, "evidence_id")
		if !declaresKind(decl, "evidence", eid) {
			t.Fatalf("evidence %q is not declared as kind \"evidence\": %s",
				eid, validation.CanonSpaced(decl))
		}
	}
}

// TestTruthfulCriticRecordSatisfiesTheLedger is the other half of the same
// acceptance: the record the boundary accepts is ALSO the record the ledger's
// own copy of the contract accepts. boundary.LogRequest writes it as a
// model.request event and the audit reads it back through
// trajectory.contractFailures, so a vocabulary the ledger copy lacks would make
// the framework flag a campaign it wrote itself.
func TestTruthfulCriticRecordSatisfiesTheLedger(t *testing.T) {
	c, fid := realCampaignWithAFinding(t)
	bundle, err := roles.BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	failures, err := validation.ValidateDefinitionFailures(criticRequest(bundle),
		"trajectory", "model_request")
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 {
		t.Fatalf("trajectory#model_request refuses the truthful record the "+
			"boundary accepts: %s", strings.Join(failures, "; "))
	}
}
