package bounty

// gate_evidence_vocab_test.go pins check6ExploitContract's two literal
// evidence types against the vocabulary that really produces them:
// definitions.evidence_item.properties.type.enum in the checked-in finding
// schema (read from the embedded file, never a pasted list) and
// findings.MintEvidenceLevelType, the ONE derivation `mint` and the ingest
// exec_ref path share. The gate matches on a hand-copied pair; if either the
// enum or the minted default is renamed, this test fails instead of the
// clause silently becoming an always-fail that nothing reports.

import (
	"testing"

	"websec/assets"
	"websec/internal/findings"
	"websec/internal/validation"
)

// evidenceTypeEnum reads evidence_item's type enum out of the real schema.
func evidenceTypeEnum(t *testing.T) []string {
	t.Helper()
	raw, err := assets.FS.ReadFile("schema/finding.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
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

// TestExploitContractTypesMatchTheMintedVocabulary derives the pair by
// calling MintEvidenceLevelType (a local claim -> E4, a fork claim -> E5),
// proves both are schema enum members, and proves the gate recognises exactly
// them while refusing a non-runnable enum member.
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
