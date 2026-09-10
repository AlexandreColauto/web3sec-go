package slither

import (
	"os"
	"testing"

	"websec/internal/validation"
)

func loadFixture(t *testing.T) validation.Value {
	t.Helper()
	raw, err := os.ReadFile("testdata/slither_sample.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// ParseOrdered (not json.Unmarshal+FromAny) is the pipeline's real
	// decoder: it keeps integer line numbers Int instead of Flt, which the
	// adapter's anchor guard relies on.
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	return doc
}

func TestToPayloadsMappingAndOrder(t *testing.T) {
	ps, err := ToPayloads(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// Informational checks (solc-version, assembly) are DROPPED: two remain.
	if len(ps) != 2 {
		t.Fatalf("want 2 payloads, got %d", len(ps))
	}
	// Deterministic order: class-key path order is (src/Pay.sol:11) then
	// (src/Vault.sol:44/50) — sorted by (first path, first line, check).
	if got := objStr(objAt(ps[0], "root_cause"), "class"); got != "unchecked-external-call" {
		t.Fatalf("payload 0 class: %s", got)
	}
	if got := objStr(objAt(ps[1], "root_cause"), "class"); got != "reentrancy" {
		t.Fatalf("payload 1 class: %s", got)
	}
	pro := objAt(ps[1], "provenance")
	tools := valsOf(objAt(pro, "sast_tools"))
	if len(tools) != 1 || tools[0].S != "slither:reentrancy-eth" {
		t.Fatalf("sast_tools: %v", tools)
	}
	if objStr(pro, "discovered_by") != "sast/slither" {
		t.Fatal("discovered_by must name the SAST lane")
	}
	aff := valsOf(objAt(ps[1], "affected"))
	if len(aff) != 2 {
		t.Fatalf("reentrancy affected: %d (both vertices, sorted by line)", len(aff))
	}
	if lines := valsOf(objAt(aff[0], "lines")); lines[0].I != 44 {
		t.Fatal("affected must be sorted by line")
	}
	// the type:"sink" vertex at line 51 is NOT an affected entry
	for _, a := range aff {
		if ln := valsOf(objAt(a, "lines")); ln[0].I == 51 {
			t.Fatal("non-source vertices must be filtered out")
		}
	}
}

func TestUnmappedCheckKeepsDefaultClass(t *testing.T) {
	doc := validation.FromAny(map[string]any{"results": []any{
		map[string]any{"check": "something-new", "description": "brand new finding text",
			"impact": "High", "confidence": "Medium",
			"vertices": []any{map[string]any{"filename": "a.sol", "line_no": 3}}},
	}})
	ps, err := ToPayloads(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || objStr(objAt(ps[0], "root_cause"), "class") != "logic-error" {
		t.Fatalf("unmapped checks must land logic-error, got %d payloads", len(ps))
	}
}

func TestNoResultsIsEmpty(t *testing.T) {
	ps, err := ToPayloads(validation.FromAny(map[string]any{"results": []any{}}))
	if err != nil || len(ps) != 0 {
		t.Fatalf("want empty, got %d %v", len(ps), err)
	}
}

func TestPayloadPassesHypothesisValidation(t *testing.T) {
	ps, err := ToPayloads(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// The payload is a hypothesis payload (the --example shape): no
	// finding_id/status yet, but the required non-system keys must be there.
	for _, p := range ps {
		for _, k := range []string{"title", "root_cause", "affected", "attacker", "evidence"} {
			if objAt(p, k).Kind == validation.Null {
				t.Fatalf("payload missing %s", k)
			}
		}
	}
}
