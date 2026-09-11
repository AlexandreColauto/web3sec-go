// Fixture provenance (Wave I Task 5 — real tool capture, not hand-written).
//
//	host tool : slither 0.11.6 (`slither --version` -> "0.11.6")
//	source    : a scratch copy of this repo's assets/evalsuite/src (17 .sol files)
//	commands  : mkdir -p .scratch/probe && cp -r assets/evalsuite/src .scratch/probe/src
//	            cd .scratch/probe && slither src --json sl.json
//	raw shape : {success, error, results:{detectors:[...]}} — 26 detector rows
//	            (High 3, Medium 5, Low 8, Informational 5, Optimization 5)
//	trim      : testdata/slither_sample.json keeps WHOLE rows #2 (reentrancy-eth),
//	            #3 (low-level-calls, Informational) and #4 (unchecked-lowlevel)
//	            verbatim — no field inside a kept row was edited. The trimming
//	            script (.scratch/trim.py) splices the original source text of
//	            each kept row, so the kept rows are byte-identical to the
//	            capture above.
//	tolerant  : testdata/slither_tolerant.json is hand-trimmed over the same
//	            capture (see .scratch/mktolerant.py) to pin the loader's drop
//	            rules: is_dependency element, lines:[] element, an element with
//	            an empty filename_relative, an Informational row and a row with
//	            no `elements` key at all.
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

func loadTolerant(t *testing.T) validation.Value {
	t.Helper()
	raw, err := os.ReadFile("testdata/slither_tolerant.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	return doc
}

// TestToPayloadsRealShape walks the REAL Slither document: results.detectors[]
// with elements[].source_mapping. The Informational row is dropped, the two
// admitted rows survive, and the order is (path, line, check).
func TestToPayloadsRealShape(t *testing.T) {
	ps, err := ToPayloads(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// Informational low-level-calls is DROPPED: reentrancy-eth (High) and
	// unchecked-lowlevel (Medium) remain.
	if len(ps) != 2 {
		t.Fatalf("want 2 payloads, got %d", len(ps))
	}
	// Deterministic order: src/ES03BankReentrancy.sol before
	// src/ES04LenderUnderflow.sol.
	if got := objStr(objAt(ps[0], "root_cause"), "class"); got != "reentrancy" {
		t.Fatalf("payload 0 class: %s", got)
	}
	if got := objStr(objAt(ps[1], "root_cause"), "class"); got != "unchecked-external-call" {
		t.Fatalf("payload 1 class: %s", got)
	}
	pro := objAt(ps[1], "provenance")
	tools := valsOf(objAt(pro, "sast_tools"))
	if len(tools) != 1 || tools[0].S != "slither:unchecked-lowlevel" {
		t.Fatalf("sast_tools: %v", tools)
	}
	if objStr(pro, "discovered_by") != "sast/slither" {
		t.Fatal("discovered_by must name the SAST lane")
	}
	// affected paths come from source_mapping.filename_relative, lines from
	// source_mapping.lines[0]; reentrancy-eth has three anchorable elements.
	aff := valsOf(objAt(ps[0], "affected"))
	if len(aff) != 3 {
		t.Fatalf("reentrancy affected: %d, want 3", len(aff))
	}
	got := []int64{}
	for _, a := range aff {
		if p := objStr(a, "path"); p != "src/ES03BankReentrancy.sol" {
			t.Fatalf("affected path: %q", p)
		}
		lines := valsOf(objAt(a, "lines"))
		if len(lines) != 2 || lines[0].I != lines[1].I {
			t.Fatalf("affected lines shape: %v", lines)
		}
		got = append(got, lines[0].I)
	}
	want := []int64{6, 8, 10}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("affected lines %v, want %v (sorted by line)", got, want)
		}
	}
	// unchecked-lowlevel has two anchorable elements (function at line 7 and
	// the low-level call at line 10); both are affected sites.
	aff1 := valsOf(objAt(ps[1], "affected"))
	if len(aff1) != 2 || objStr(aff1[0], "path") != "src/ES04LenderUnderflow.sol" {
		t.Fatalf("unchecked-lowlevel affected: %v", aff1)
	}
	for i, wantLine := range []int64{7, 10} {
		if ln := valsOf(objAt(aff1[i], "lines"))[0].I; ln != wantLine {
			t.Fatalf("unchecked-lowlevel affected[%d] line: %d, want %d", i, ln, wantLine)
		}
	}
}

// TestToPayloadsTolerantEdges pins the drop rules on a real-shape document:
// dependency elements, unanchorable elements and empty detectors never
// produce a payload; the filename fallback chain is relative -> short ->
// absolute.
func TestToPayloadsTolerantEdges(t *testing.T) {
	ps, err := ToPayloads(loadTolerant(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("want 1 payload (Informational + no-elements rows drop), got %d", len(ps))
	}
	if got := objStr(objAt(ps[0], "root_cause"), "class"); got != "unchecked-external-call" {
		t.Fatalf("class: %s", got)
	}
	aff := valsOf(objAt(ps[0], "affected"))
	// element 0 (lines [7..11], relative filename) and element 3 (empty
	// filename_relative -> filename_short, lines [9]); the dependency element
	// and the empty-lines element are dropped.
	if len(aff) != 2 {
		t.Fatalf("affected: %d, want 2 (dep + empty-lines dropped)", len(aff))
	}
	for i, wantLine := range []int64{7, 9} {
		if objStr(aff[i], "path") != "src/ES04LenderUnderflow.sol" {
			t.Fatalf("affected[%d] path: %q", i, objStr(aff[i], "path"))
		}
		if ln := valsOf(objAt(aff[i], "lines"))[0].I; ln != wantLine {
			t.Fatalf("affected[%d] line: %d, want %d", i, ln, wantLine)
		}
	}
}

func TestUnmappedCheckKeepsDefaultClass(t *testing.T) {
	doc := validation.FromAny(map[string]any{"results": map[string]any{"detectors": []any{
		map[string]any{"check": "something-new", "description": "brand new finding text",
			"impact": "High", "confidence": "Medium",
			"elements": []any{map[string]any{"type": "function", "name": "f",
				"source_mapping": map[string]any{
					"filename_relative": "a.sol", "lines": []any{3}, "is_dependency": false}}}},
	}}})
	ps, err := ToPayloads(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || objStr(objAt(ps[0], "root_cause"), "class") != "logic-error" {
		t.Fatalf("unmapped checks must land logic-error, got %d payloads", len(ps))
	}
}

func TestNoDetectorsIsEmpty(t *testing.T) {
	ps, err := ToPayloads(validation.FromAny(map[string]any{
		"success": true,
		"error":   nil,
		"results": map[string]any{"detectors": []any{}},
	}))
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
