package protocolgraph

// I4 (Wave I Task 8): operator-supplied DNS/dependency facts for
// components[]. These tests pin the four laws of the feature: the two
// schemas accept the additive blocks and reject malformed ones, ApplyFacts
// is a fail-closed order-preserving idempotent join, FactsFromDir reads the
// seven offline manifests deterministically (never a socket), and the
// operator_facts/component schema subtrees cannot drift apart.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/jval"
	"websec/internal/validation"
)

// factsModelJSON is the join fixture: three components with the two identity
// fields (url and path) the join reads.
const factsModelJSON = `{` +
	`"protocol_id":"factsdemo","name":"Facts Demo",` +
	`"components":[` +
	`{"kind":"frontend","url":"https://app.example","trust":"semi-trusted",` +
	`"in_scope":true,"paid_for":true},` +
	`{"kind":"offchain-service","path":"@openzeppelin/contracts",` +
	`"trust":"trusted","in_scope":true,"paid_for":false},` +
	`{"kind":"keeper-service","path":"apps/keeper","trust":"semi-trusted",` +
	`"in_scope":true,"paid_for":false}],` +
	`"contracts":[{"name":"Vault","path":"src/Vault.sol"}],` +
	`"actors":[{"id":"user","kind":"EOA"}],` +
	`"assets":[{"id":"share","kind":"share"}],` +
	`"relations":[]}`

// factsDocJSON is the operator document that matches the fixture model: one
// DNS fact on the frontend and two dependency facts on the services.
const factsDocJSON = `{"schema_version":"1","facts":[` +
	`{"target":{"kind":"frontend","url":"https://app.example"},` +
	`"dns":{"observed_at":"2026-01-02","source":"operator ticket OPS-77",` +
	`"records":{"a":["203.0.113.7"],"txt":["v=spf1 -all"]}}},` +
	`{"target":{"kind":"offchain-service","path":"@openzeppelin/contracts"},` +
	`"dependency":{"observed_at":"2026-01-02",` +
	`"source":"operator-supplied manifest","package":"@openzeppelin/contracts",` +
	`"version":"v4.9.3",` +
	`"pin":"@openzeppelin/contracts/=lib/openzeppelin-contracts@v4.9.3/",` +
	`"resolved_from":"remappings.txt"}},` +
	`{"target":{"kind":"keeper-service","path":"apps/keeper"},` +
	`"dependency":{"observed_at":"2026-01-02",` +
	`"source":"operator-supplied manifest","package":"lodash",` +
	`"version":"4.17.21"}}]}`

func parseFactsFixture(t *testing.T, text string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(text))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return v
}

// ---- schemas --------------------------------------------------------------

func TestOperatorFactsSchemaRejectsMalformedFacts(t *testing.T) {
	rows := []struct{ name, doc, want string }{
		{"dns missing observed_at",
			`{"schema_version":"1","facts":[{"target":{"kind":"domain","url":"https://x.example"},` +
				`"dns":{"source":"registrar export 2026-01-01"}}]}`,
			"'observed_at' is a required property"},
		{"dns bad date pattern",
			`{"schema_version":"1","facts":[{"target":{"kind":"domain","url":"https://x.example"},` +
				`"dns":{"observed_at":"01/02/2026","source":"registrar export"}}]}`,
			"does not match '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'"},
		{"dns unknown records key",
			`{"schema_version":"1","facts":[{"target":{"kind":"domain","url":"https://x.example"},` +
				`"dns":{"observed_at":"2026-01-02","source":"registrar export",` +
				`"records":{"soa":["ns1.x.example"]}}}]}`,
			"Additional properties are not allowed ('soa' was unexpected)"},
		{"fact unknown key",
			`{"schema_version":"1","facts":[{"target":{"kind":"domain","url":"https://x.example"},` +
				`"dns":{"observed_at":"2026-01-02","source":"registrar export"},"live":true}]}`,
			"Additional properties are not allowed ('live' was unexpected)"},
		{"dependency missing package",
			`{"schema_version":"1","facts":[{"target":{"kind":"frontend","path":"apps/web"},` +
				`"dependency":{"observed_at":"2026-01-02","source":"operator-supplied manifest"}}]}`,
			"'package' is a required property"},
		{"target kind outside the enum",
			`{"schema_version":"1","facts":[{"target":{"kind":"dns-server","path":"."},` +
				`"dns":{"observed_at":"2026-01-02","source":"registrar export"}}]}`,
			"'dns-server' is not one of"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := validation.Validate(parseFactsFixture(t, row.doc), "operator_facts", 1)
			if err == nil {
				t.Fatalf("expected %q to be rejected", row.name)
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), row.want)
			}
		})
	}
}

// TestProtocolModelAcceptsComponentFacts: the two components[] additions are
// additive — a model carrying them validates, and the blocks reject a bad
// observed_at exactly like the operator document does.
func TestProtocolModelAcceptsComponentFacts(t *testing.T) {
	good := strings.Replace(factsModelJSON, `"paid_for":true}`,
		`"paid_for":true,"dns":{"observed_at":"2026-01-02",`+
			`"source":"registrar export","records":{"ns":["ns1.example"]}},`+
			`"dependency":{"observed_at":"2026-01-02","source":"operator",`+
			`"package":"lodash","version":"4.17.21"}}`, 1)
	if err := validation.Validate(parseFactsFixture(t, good), "protocol_model", 1); err != nil {
		t.Fatalf("additive component facts must validate: %v", err)
	}
	bad := strings.Replace(factsModelJSON, `"paid_for":true}`,
		`"paid_for":true,"dns":{"observed_at":"2026-1-2","source":"x"}}`, 1)
	err := validation.Validate(parseFactsFixture(t, bad), "protocol_model", 1)
	if err == nil {
		t.Fatal("a bad observed_at on components[].dns must be rejected")
	}
	if !strings.Contains(err.Error(), "does not match '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'") {
		t.Fatalf("error = %q", err.Error())
	}
}

// schemaSubtree pulls one nested schema node out of an embedded schema.
func schemaSubtree(t *testing.T, schema string, path ...string) validation.Value {
	t.Helper()
	raw, err := validation.ReadSchemaFile(schema)
	if err != nil {
		t.Fatalf("read %s: %v", schema, err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", schema, err)
	}
	node := doc
	for _, key := range path {
		node = validation.ObjAt(node, key)
	}
	if node.Kind != validation.Obj {
		t.Fatalf("%s: subtree %v is not an object", schema, path)
	}
	return node
}

// TestFactBlocksCannotDrift: the dns/dependency blocks are duplicated
// literally (the loader has no cross-file $ref); this guard fails the moment
// one copy is edited without the other.
func TestFactBlocksCannotDrift(t *testing.T) {
	rows := []struct {
		name string
		comp []string
		fact []string
	}{
		{"dns",
			[]string{"properties", "components", "items", "properties", "dns"},
			[]string{"properties", "facts", "items", "properties", "dns"}},
		{"dependency",
			[]string{"properties", "components", "items", "properties", "dependency"},
			[]string{"properties", "facts", "items", "properties", "dependency"}},
	}
	for _, row := range rows {
		a := schemaSubtree(t, "protocol_model", row.comp...)
		b := schemaSubtree(t, "operator_facts", row.fact...)
		if jval.CanonCompact(a) != jval.CanonCompact(b) {
			t.Errorf("%s block drifted:\n protocol_model: %s\n operator_facts: %s",
				row.name, jval.CanonCompact(a), jval.CanonCompact(b))
		}
	}
}

// TestExampleFactsDocumentValidates: the checked-in example (an embedded
// asset, so the manifest must cover it) is schema-valid.
func TestExampleFactsDocumentValidates(t *testing.T) {
	raw, err := assets.ProtocolFS.ReadFile("protocol/example_facts.json")
	if err != nil {
		t.Fatalf("embedded example facts: %v", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse example: %v", err)
	}
	if err := validation.Validate(doc, "operator_facts", 1); err != nil {
		t.Fatalf("example_facts.json is not a valid operator_facts document: %v", err)
	}
}

// ---- ApplyFacts -----------------------------------------------------------

func TestApplyFactsNoMatchErrors(t *testing.T) {
	model := parseFactsFixture(t, factsModelJSON)
	facts := parseFactsFixture(t, `{"schema_version":"1","facts":[{`+
		`"target":{"kind":"frontend","url":"https://typo.example"},`+
		`"dns":{"observed_at":"2026-01-02","source":"registrar export"}}]}`)
	_, err := ApplyFacts(model, facts)
	if err == nil {
		t.Fatal("a fact matching no component must error")
	}
	want := "operator facts: no component matches kind=frontend url=https://typo.example"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestApplyFactsPathNoMatchErrors(t *testing.T) {
	model := parseFactsFixture(t, factsModelJSON)
	facts := parseFactsFixture(t, `{"schema_version":"1","facts":[{`+
		`"target":{"kind":"keeper-service","path":"apps/nope"},`+
		`"dependency":{"observed_at":"2026-01-02","source":"operator",`+
		`"package":"lodash"}}]}`)
	_, err := ApplyFacts(model, facts)
	if err == nil {
		t.Fatal("a path fact matching no component must error")
	}
	want := "operator facts: no component matches kind=keeper-service path=apps/nope"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestApplyFactsAmbiguousTargetErrors(t *testing.T) {
	model := parseFactsFixture(t, `{"protocol_id":"dup","name":"Dup",`+
		`"components":[`+
		`{"kind":"domain","url":"https://x.example","trust":"t","in_scope":true,"paid_for":false},`+
		`{"kind":"domain","url":"https://x.example","trust":"t","in_scope":true,"paid_for":false}],`+
		`"contracts":[],"actors":[],"assets":[],"relations":[]}`)
	facts := parseFactsFixture(t, `{"schema_version":"1","facts":[{`+
		`"target":{"kind":"domain","url":"https://x.example"},`+
		`"dns":{"observed_at":"2026-01-02","source":"registrar export"}}]}`)
	_, err := ApplyFacts(model, facts)
	if err == nil {
		t.Fatal("an ambiguous join must error")
	}
	if !strings.Contains(err.Error(), "matches 2 components") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestApplyFactsDuplicateFactErrors(t *testing.T) {
	model := parseFactsFixture(t, factsModelJSON)
	one := `{"target":{"kind":"frontend","url":"https://app.example"},` +
		`"dns":{"observed_at":"2026-01-02","source":"registrar export"}}`
	facts := parseFactsFixture(t, `{"schema_version":"1","facts":[`+one+`,`+
		strings.Replace(one, `"source":"registrar export"`,
			`"source":"second registrar export"`, 1)+`]}`)
	_, err := ApplyFacts(model, facts)
	if err == nil {
		t.Fatal("two dns facts for one component must error")
	}
	if !strings.Contains(err.Error(), "duplicate dns fact") {
		t.Fatalf("error = %q", err.Error())
	}

	dep := `{"target":{"kind":"keeper-service","path":"apps/keeper"},` +
		`"dependency":{"observed_at":"2026-01-02","source":"operator",` +
		`"package":"lodash","version":"4.17.21"}}`
	facts = parseFactsFixture(t, `{"schema_version":"1","facts":[`+dep+`,`+
		strings.Replace(dep, `"version":"4.17.21"`, `"version":"4.17.20"`, 1)+`]}`)
	_, err = ApplyFacts(model, facts)
	if err == nil {
		t.Fatal("two dependency facts for one component must error")
	}
	if !strings.Contains(err.Error(), "duplicate dependency fact") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestApplyFactsPreservesOrderAndIsIdempotent(t *testing.T) {
	model := parseFactsFixture(t, factsModelJSON)
	facts := parseFactsFixture(t, factsDocJSON)
	merged, counts, err := ApplyFactsCounted(model, facts)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if counts.Applied != 3 || counts.DNS != 1 || counts.Dependency != 2 ||
		counts.Components != 3 {
		t.Fatalf("counts = %+v", counts)
	}
	comps := validation.ObjAt(merged, "components")
	if comps.Kind != validation.Arr || len(comps.A) != 3 {
		t.Fatalf("components = %s", jval.CanonCompact(comps))
	}
	// order preserved: the same kinds, in the same order
	wantKinds := []string{"frontend", "offchain-service", "keeper-service"}
	for i, k := range wantKinds {
		if got := validation.ObjAt(comps.A[i], "kind").S; got != k {
			t.Fatalf("components[%d].kind = %q, want %q", i, got, k)
		}
	}
	if validation.ObjAt(comps.A[0], "dns").Kind != validation.Obj {
		t.Fatalf("components[0] did not receive the dns fact: %s",
			jval.CanonCompact(comps.A[0]))
	}
	if validation.ObjAt(comps.A[1], "dependency").Kind != validation.Obj {
		t.Fatalf("components[1] did not receive the dependency fact")
	}
	if validation.ObjAt(comps.A[2], "dependency").Kind != validation.Obj {
		t.Fatalf("components[2] did not receive the dependency fact")
	}
	// every source model field survives the merge: the input model plus the
	// two attached sub-objects is exactly the output (canonical compare is
	// key-order independent, so an added/removed field fails this).
	expect := parseFactsFixture(t, `{"protocol_id":"factsdemo","name":"Facts Demo","components":[`+
		`{"kind":"frontend","url":"https://app.example","trust":"semi-trusted",`+
		`"in_scope":true,"paid_for":true,"dns":`+jval.CanonCompact(validation.ObjAt(comps.A[0], "dns"))+`},`+
		`{"kind":"offchain-service","path":"@openzeppelin/contracts",`+
		`"trust":"trusted","in_scope":true,"paid_for":false,"dependency":`+
		jval.CanonCompact(validation.ObjAt(comps.A[1], "dependency"))+`},`+
		`{"kind":"keeper-service","path":"apps/keeper","trust":"semi-trusted",`+
		`"in_scope":true,"paid_for":false,"dependency":`+
		jval.CanonCompact(validation.ObjAt(comps.A[2], "dependency"))+`}],`+
		`"contracts":[{"name":"Vault","path":"src/Vault.sol"}],`+
		`"actors":[{"id":"user","kind":"EOA"}],`+
		`"assets":[{"id":"share","kind":"share"}],`+
		`"relations":[]}`)
	if jval.CanonCompact(merged) != jval.CanonCompact(expect) {
		t.Fatalf("merged model moved non-fact bytes:\ngot  %s\nwant %s",
			jval.CanonCompact(merged), jval.CanonCompact(expect))
	}
	// idempotent: a second apply over the merged model is a no-op
	again, _, err := ApplyFactsCounted(merged, facts)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if jval.CanonCompact(again) != jval.CanonCompact(merged) {
		t.Fatalf("apply is not idempotent:\n%s\n%s",
			jval.CanonCompact(merged), jval.CanonCompact(again))
	}
}

// ---- FactsFromDir ---------------------------------------------------------

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestFactsFromDirRemappings(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "remappings.txt", "# generated by forge remappings\n"+
		"\n"+
		"@openzeppelin/contracts/=lib/openzeppelin-contracts@v4.9.3/\n"+
		"forge-std/=lib/forge-std/src/\n")
	doc, err := FactsFromDir(dir, "2026-01-02")
	if err != nil {
		t.Fatalf("FactsFromDir: %v", err)
	}
	if err := validation.Validate(doc, "operator_facts", 1); err != nil {
		t.Fatalf("extracted document is not schema-valid: %v", err)
	}
	facts := validation.ObjAt(doc, "facts")
	if facts.Kind != validation.Arr || len(facts.A) != 2 {
		t.Fatalf("facts = %s", jval.CanonCompact(facts))
	}
	d0 := validation.ObjAt(facts.A[0], "dependency")
	if validation.ObjAt(d0, "package").S != "@openzeppelin/contracts" ||
		validation.ObjAt(d0, "version").S != "v4.9.3" ||
		validation.ObjAt(d0, "observed_at").S != "2026-01-02" ||
		validation.ObjAt(d0, "source").S != "operator-supplied manifest" ||
		validation.ObjAt(d0, "resolved_from").S != "remappings.txt" ||
		validation.ObjAt(d0, "pin").S != "@openzeppelin/contracts/=lib/openzeppelin-contracts@v4.9.3/" {
		t.Fatalf("fact[0] = %s", jval.CanonCompact(facts.A[0]))
	}
	if validation.ObjAt(facts.A[0], "target").Kind != validation.Obj {
		t.Fatalf("fact[0] has no target")
	}
	d1 := validation.ObjAt(facts.A[1], "dependency")
	if validation.ObjAt(d1, "package").S != "forge-std" || validation.ObjAt(d1, "version").S != "" ||
		validation.ObjAt(d1, "pin").S != "forge-std/=lib/forge-std/src/" {
		t.Fatalf("fact[1] = %s", jval.CanonCompact(facts.A[1]))
	}
}

func TestFactsFromDirRejectsBadDate(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "remappings.txt", "forge-std/=lib/forge-std/src/\n")
	if _, err := FactsFromDir(dir, ""); err == nil {
		t.Fatal("an empty observed_at must error")
	}
	if _, err := FactsFromDir(dir, "02.01.2026"); err == nil {
		t.Fatal("a non-YYYY-MM-DD observed_at must error")
	}
}

func TestFactsFromDirEmptyDirErrors(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "README.md", "nothing to see\n")
	_, err := FactsFromDir(dir, "2026-01-02")
	if err == nil {
		t.Fatal("a directory with no supported manifest must error")
	}
	if !strings.Contains(err.Error(), "no supported manifest in") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestFactsFromDirMalformedEntryNamesFileAndLine(t *testing.T) {
	cases := []struct{ file, content, want string }{
		{"remappings.txt", "forge-std/=lib/forge-std/src/\nbroken line\n",
			"remappings.txt:2:"},
		{"go.sum", "github.com/x/y v1.2.3 h1:aaa=\nnot a go.sum line\n",
			"go.sum:2:"},
		{"Cargo.lock", "version = 3\n\n[[package]]\nname = \"serde\"\n",
			"Cargo.lock:3:"},
		{"package-lock.json", "{\n  \"packages\": {\n" +
			"    \"node_modules/lodash\": {\n      \"resolved\": \"x\"\n    }\n  }\n}\n",
			"package-lock.json:3:"},
		{"yarn.lock", "lodash@^4.17.21:\n  resolved \"https://x\"\n",
			"yarn.lock:1:"},
		{"pnpm-lock.yaml", "importers:\n  .:\n    dependencies:\n      lodash:\n" +
			"        specifier: ^4.17.21\n",
			"pnpm-lock.yaml:4:"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, c.file, c.content)
			_, err := FactsFromDir(dir, "2026-01-02")
			if err == nil {
				t.Fatalf("%s: malformed entry must error", c.file)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %q, want file+line %q", err.Error(), c.want)
			}
		})
	}
}

// TestFactsFromDirLockfileFormats: all six lockfile readers, in the pinned
// manifest order, each entry a fact with a name and a version.
func TestFactsFromDirLockfileFormats(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "package-lock.json", `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://x"},
    "node_modules/lodash/node_modules/ms": {"version": "2.0.0"}
  }
}
`)
	writeFixture(t, dir, "yarn.lock", `# yarn lockfile v1

"@babel/core@^7.0.0":
  version "7.23.0"
  resolved "https://x"

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
`)
	writeFixture(t, dir, "pnpm-lock.yaml", `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      vitest:
        specifier: ^1.0.0
        version: 1.6.0
`)
	writeFixture(t, dir, "Cargo.lock", `version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "syn"
version = "2.0.60"
`)
	writeFixture(t, dir, "go.sum", "github.com/x/y v1.2.3 h1:aaa=\n"+
		"github.com/x/y v1.2.3/go.mod h1:bbb=\n"+
		"golang.org/x/text v0.14.0 h1:ccc=\n")
	writeFixture(t, dir, "foundry.lock", `{
  "lib/openzeppelin-contracts": {
    "tag": {
      "name": "v5.0.0",
      "rev": "b7954c3e9ce1d487b49489f5800f52f4b77b7351"
    }
  },
  "lib/forge-std": {
    "rev": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
  }
}
`)
	doc, err := FactsFromDir(dir, "2026-01-02")
	if err != nil {
		t.Fatalf("FactsFromDir: %v", err)
	}
	type got struct{ pkg, ver, from string }
	var seen []got
	facts := validation.ObjAt(doc, "facts")
	for _, f := range facts.A {
		d := validation.ObjAt(f, "dependency")
		seen = append(seen, got{validation.ObjAt(d, "package").S, validation.ObjAt(d, "version").S,
			validation.ObjAt(d, "resolved_from").S})
	}
	want := []got{
		{"lodash", "4.17.21", "package-lock.json"},
		{"@babel/core", "7.23.0", "yarn.lock"},
		{"lodash", "4.17.21", "yarn.lock"},
		{"lodash", "4.17.21", "pnpm-lock.yaml"},
		{"vitest", "1.6.0", "pnpm-lock.yaml"},
		{"serde", "1.0.200", "Cargo.lock"},
		{"syn", "2.0.60", "Cargo.lock"},
		{"github.com/x/y", "v1.2.3", "go.sum"},
		{"golang.org/x/text", "v0.14.0", "go.sum"},
		{"openzeppelin-contracts", "v5.0.0", "foundry.lock"},
		{"forge-std", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", "foundry.lock"},
	}
	if len(seen) != len(want) {
		t.Fatalf("extracted %d facts, want %d:\n%v", len(seen), len(want), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("fact[%d] = %+v, want %+v", i, seen[i], want[i])
		}
	}
}

// TestFactsFromDirNeverProducesDNS: there is nothing offline to resolve from,
// so no extracted fact may carry a dns block (the only DNS home is the
// operator's own JSON document).
func TestFactsFromDirNeverProducesDNS(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "remappings.txt", "forge-std/=lib/forge-std/src/\n")
	doc, err := FactsFromDir(dir, "2026-01-02")
	if err != nil {
		t.Fatalf("FactsFromDir: %v", err)
	}
	if strings.Contains(jval.CanonCompact(doc), `"dns"`) {
		t.Fatalf("extraction produced a dns fact: %s", jval.CanonCompact(doc))
	}
}
