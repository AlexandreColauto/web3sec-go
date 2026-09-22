package bounty

// gate_evidence_vocab_test.go pins check6ExploitContract's classification
// table (evidenceTypeClasses) against the vocabulary the schema really
// declares: definitions.evidence_item.properties.type.enum in the checked-in
// finding schema, READ FROM THE SCHEMA BYTES (never a pasted list), plus
// findings.MintEvidenceLevelType, the ONE derivation `mint` and the ingest
// exec_ref path share.
//
// Three laws, one per failure mode:
//   - the table must cover the enum EXACTLY, so a fifteenth member cannot ship
//     unclassified (TestExploitContractTableCoversTheWholeEnum, which proves
//     the law bites by mutating a scratch copy of the schema);
//   - the clause must follow the table, runnable member by member
//     (TestExploitContractFollowsTheClassificationTable);
//   - the refusal text must name NO set, because a list in the record goes
//     stale silently (TestExploitContractRefusalNamesNoSet).

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/findings"
	"websec/internal/validation"
)

// schemaBytes is the embedded finding schema, byte for byte.
func schemaBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := assets.FS.ReadFile("schema/finding.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// evidenceEnumFromSchema parses ONE finding-schema document and returns the
// evidence_item type enum it declares. The real embedded schema and a mutated
// scratch copy are read through this same path, so the mutation exercises the
// reader the shipped file goes through.
func evidenceEnumFromSchema(t *testing.T, raw []byte) []string {
	t.Helper()
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse finding schema: %v", err)
	}
	item := validation.ObjAt(validation.ObjAt(doc, "definitions"), "evidence_item")
	members := validation.ObjAt(validation.ObjAt(item, "properties"), "type")
	out := make([]string, 0, len(validation.ObjAt(members, "enum").A))
	for _, m := range validation.ObjAt(members, "enum").A {
		if m.Kind != validation.Str {
			t.Fatalf("evidence type enum member is %v, not a string", m.Kind)
		}
		out = append(out, m.S)
	}
	if len(out) == 0 {
		t.Fatal("finding.schema.json has no evidence_item type enum")
	}
	return out
}

// evidenceTypeEnum reads evidence_item's type enum out of the real schema.
func evidenceTypeEnum(t *testing.T) []string {
	t.Helper()
	return evidenceEnumFromSchema(t, schemaBytes(t))
}

// checkEvidenceCoverage is the law the table must satisfy: its key set is
// EXACTLY the enum's member set, and every entry states a reason. A member
// with no class is an unclassified type; a key with no member is a class for a
// type the schema no longer declares; a blank reason is an undocumented taste
// call.
func checkEvidenceCoverage(enum []string) error {
	members := map[string]bool{}
	for _, m := range enum {
		members[m] = true
	}
	var unclassified, stale, unreasoned []string
	for _, m := range enum {
		if _, ok := evidenceTypeClasses[m]; !ok {
			unclassified = append(unclassified, m)
		}
	}
	for typ, cls := range evidenceTypeClasses {
		if !members[typ] {
			stale = append(stale, typ)
		}
		if strings.TrimSpace(cls.why) == "" {
			unreasoned = append(unreasoned, typ)
		}
	}
	if len(unclassified)+len(stale)+len(unreasoned) == 0 {
		return nil
	}
	sort.Strings(unclassified)
	sort.Strings(stale)
	sort.Strings(unreasoned)
	return fmt.Errorf("evidence-type classification is out of step with the "+
		"schema enum: unclassified %v, not-in-enum %v, no stated reason %v",
		unclassified, stale, unreasoned)
}

// scratchSchemaWithType returns the enum of a scratch COPY of the finding
// schema with one extra member spliced into the evidence_item type enum — the
// schema a future contributor would have. The copy is written to a temp file
// and read back through evidenceEnumFromSchema, so it is parsed exactly like
// the shipped file.
func scratchSchemaWithType(t *testing.T, extra string) []string {
	t.Helper()
	raw := schemaBytes(t)
	anchor := []byte(`"manual"`) // the enum's last member
	if n := bytes.Count(raw, anchor); n != 1 {
		t.Fatalf("splice anchor %s appears %d times in the schema, want 1 — "+
			"pick a unique anchor", anchor, n)
	}
	i := bytes.Index(raw, anchor)
	mutated := make([]byte, 0, len(raw)+len(extra)+16)
	mutated = append(mutated, raw[:i+len(anchor)]...)
	mutated = append(mutated, []byte(",\n            \""+extra+"\"")...)
	mutated = append(mutated, raw[i+len(anchor):]...)
	path := filepath.Join(t.TempDir(), "finding.schema.json")
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	back, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return evidenceEnumFromSchema(t, back)
}

// enumHas reports membership in the schema-read vocabulary.
func enumHas(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// exploitContractResult runs the real clause against one evidence item and
// returns its result row.
func exploitContractResult(t *testing.T, typ string) string {
	t.Helper()
	req := validation.VObj(kv("require_exploit_contract", validation.VBool(true)))
	f := validation.VObj(kv("evidence", validation.VArr(validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("type", validation.VStr(typ))))))
	g := &gate{policy: validation.VObj(kv("poc_requirements", req)), f: f}
	if err := g.check6ExploitContract(req); err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(g.checks[0], "result")
}

// TestExploitContractTableCoversTheWholeEnum is the anti-drift law. It reads
// the schema (never a copied list), requires the table to cover it exactly,
// and then MUTATES a scratch copy of the schema by adding a fifteenth member:
// the same law must fail, naming it.
func TestExploitContractTableCoversTheWholeEnum(t *testing.T) {
	enum := evidenceTypeEnum(t)
	if err := checkEvidenceCoverage(enum); err != nil {
		t.Fatalf("the shipped schema and the classification table disagree: %v", err)
	}
	const fifteenth = "harness-replay"
	mutated := scratchSchemaWithType(t, fifteenth)
	if len(mutated) != len(enum)+1 || !enumHas(mutated, fifteenth) {
		t.Fatalf("scratch schema enum %v is not the shipped enum plus %q — "+
			"the splice missed the enum", mutated, fifteenth)
	}
	err := checkEvidenceCoverage(mutated)
	if err == nil {
		t.Fatalf("adding %q to the schema enum did NOT fail the coverage "+
			"check: a fifteenth member would ship unclassified", fifteenth)
	}
	if !strings.Contains(err.Error(), fifteenth) {
		t.Fatalf("coverage failure %q does not name %q", err, fifteenth)
	}
}

// TestExploitContractFollowsTheClassificationTable drives the real clause over
// every enum member: runnable passes, everything else fails. The first group
// is the regression this change fixes (runnable forge artifacts that are not
// the two literals the clause used to match); the second is still refused.
func TestExploitContractFollowsTheClassificationTable(t *testing.T) {
	for _, typ := range evidenceTypeEnum(t) {
		want := "fail"
		if evidenceTypeClasses[typ].runnable {
			want = "pass"
		}
		if got := exploitContractResult(t, typ); got != want {
			t.Errorf("check6ExploitContract(%q) = %s, want %s (%s)",
				typ, got, want, evidenceTypeClasses[typ].why)
		}
	}
	for _, typ := range []string{"unit-test", "fuzz", "invariant-test",
		"symbolic-witness"} {
		if got := exploitContractResult(t, typ); got != "pass" {
			t.Errorf("check6ExploitContract(%q) = %s, want pass: a triager "+
				"can run it", typ, got)
		}
	}
	for _, typ := range []string{"trace", "reasoning", "static-analysis",
		"reachability", "balance-delta", "differential", "historical-analog",
		"manual"} {
		if got := exploitContractResult(t, typ); got != "fail" {
			t.Errorf("check6ExploitContract(%q) = %s, want fail: a result "+
				"about a run is not a runnable contract", typ, got)
		}
	}
}

// TestExploitContractRefusalNamesNoSet: the blocker text is a statement in the
// record, so it must not enumerate accepted types — a parenthetical list goes
// stale the moment the vocabulary moves, and then the record lies.
func TestExploitContractRefusalNamesNoSet(t *testing.T) {
	req := validation.VObj(kv("require_exploit_contract", validation.VBool(true)))
	f := validation.VObj(kv("evidence", validation.VArr(validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("type", validation.VStr("trace"))))))
	g := &gate{policy: validation.VObj(kv("poc_requirements", req)), f: f}
	if err := g.check6ExploitContract(req); err != nil {
		t.Fatal(err)
	}
	if len(g.blockers) != 1 {
		t.Fatalf("blockers = %v, want exactly one", g.blockers)
	}
	for _, typ := range evidenceTypeEnum(t) {
		if strings.Contains(g.blockers[0], typ) {
			t.Errorf("refusal text %q names the evidence type %q — it must "+
				"not enumerate a set that can drift", g.blockers[0], typ)
		}
	}
}

// TestExploitContractTypesMatchTheMintedVocabulary derives the mint defaults
// by calling MintEvidenceLevelType (a local claim -> E4, a fork claim -> E5),
// proves both are schema enum members AND are classified runnable, and proves
// the gate recognises exactly them while refusing a non-runnable enum member.
func TestExploitContractTypesMatchTheMintedVocabulary(t *testing.T) {
	enum := evidenceTypeEnum(t)
	localLevel, localType := findings.MintEvidenceLevelType("T2", nil)
	forkLevel, forkType := findings.MintEvidenceLevelType("T3", nil)
	if localLevel != "E4" || forkLevel != "E5" {
		t.Fatalf("mint defaults = %s/%s, want E4/E5", localLevel, forkLevel)
	}
	if localType == forkType {
		t.Fatalf("mint defaults collapse to one type %q", localType)
	}
	for _, typ := range []string{localType, forkType} {
		if !enumHas(enum, typ) {
			t.Errorf("minted type %q is not in the schema enum %v", typ, enum)
		}
		if !evidenceTypeClasses[typ].runnable {
			t.Errorf("minted default %q is classified non-runnable", typ)
		}
	}
	for _, tc := range []struct{ name, typ, want string }{
		{"local default", localType, "pass"},
		{"fork default", forkType, "pass"},
		{"non-runnable enum member", "trace", "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exploitContractResult(t, tc.typ); got != tc.want {
				t.Errorf("check6ExploitContract(%q) = %s, want %s",
					tc.typ, got, tc.want)
			}
		})
	}
}
