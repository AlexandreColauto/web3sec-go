// Fixture provenance (Wave I Task 5 — real tool capture, not hand-written).
//
//	host tool : aderyn 0.6.8 (`aderyn --version` -> "aderyn 0.6.8")
//	source    : a scratch copy of this repo's assets/evalsuite/src (17 .sol files)
//	commands  : mkdir -p .scratch/probe && cp -r assets/evalsuite/src .scratch/probe/src
//	            cd .scratch/probe && aderyn src --output ad.json
//	raw shape : {files_summary, files_details, issue_count{high,low},
//	             high_issues{issues[]}, low_issues{issues[]}, detectors_used[]}
//	            issue_count = {high: 4, low: 16}
//	trim      : testdata/aderyn_sample.json keeps the full envelope and ALL
//	            16 low_issues rows verbatim; high_issues keeps only issue #2
//	            (reentrancy-state-change) — whole rows removed, no field of a
//	            kept row was edited (trim.py [untracked] splices the capture's
//	            original source text).
package aderyn

import (
	"os"
	"strings"
	"testing"

	"websec/internal/validation"
)

func loadFixture(t *testing.T) validation.Value {
	t.Helper()
	raw, err := os.ReadFile("testdata/aderyn_sample.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	return doc
}

// TestToPayloadsRealShape walks the REAL Aderyn document. Only
// high_issues.issues[] is admitted, and low_issues (16 real rows) is ignored.
func TestToPayloadsRealShape(t *testing.T) {
	ps, err := ToPayloads(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("want 1 payload (only high_issues is admitted), got %d", len(ps))
	}
	p := ps[0]
	if got := validation.ObjStr(validation.ObjAt(p, "root_cause"), "class"); got != "reentrancy" {
		t.Fatalf("class: %s", got)
	}
	if got := validation.ObjStr(validation.ObjAt(p, "root_cause"), "mechanism"); got != "static pattern: aderyn/reentrancy-state-change" {
		t.Fatalf("mechanism: %s", got)
	}
	// Title = "Aderyn <detector>: " + first line of the description, clipped
	// to 120 RUNES (the real description's first line is longer than that).
	title := validation.ObjStr(p, "title")
	if !strings.HasPrefix(title, "Aderyn reentrancy-state-change: Changing state after an external call") {
		t.Fatalf("title prefix: %q", title)
	}
	if n := len([]rune(title)); n != 120 || !strings.HasSuffix(title, "...") {
		t.Fatalf("title must be clipped to 120 runes ending in \"...\": %d runes %q", n, title)
	}
	// root_cause.description keeps the CLIPPED full prose (900 runes), so the
	// first line is still present there.
	desc := validation.ObjStr(validation.ObjAt(p, "root_cause"), "description")
	if !strings.HasPrefix(desc, "Changing state after an external call") {
		t.Fatalf("root_cause.description: %q", desc)
	}
	if firstLine(desc) != "Changing state after an external call can lead to re-entrancy attacks.Use the checks-effects-interactions pattern to avoid this issue." {
		t.Fatalf("firstLine(description) = %q", firstLine(desc))
	}
	if got := validation.ObjStr(validation.ObjAt(p, "attacker"), "profile"); got != "static analysis (Aderyn)" {
		t.Fatalf("attacker profile: %s", got)
	}
	pro := validation.ObjAt(p, "provenance")
	if got := validation.ObjStr(pro, "discovered_by"); got != "sast/aderyn" {
		t.Fatalf("discovered_by: %s", got)
	}
	tools := valsOf(validation.ObjAt(pro, "sast_tools"))
	if len(tools) != 1 || tools[0].S != "aderyn:reentrancy-state-change" {
		t.Fatalf("sast_tools: %v", tools)
	}
	if ev := valsOf(validation.ObjAt(p, "evidence")); len(ev) != 0 {
		t.Fatalf("evidence must be empty: %v", ev)
	}
	// instances[] -> affected[]: contract_path + line_no, sorted by line.
	aff := valsOf(validation.ObjAt(p, "affected"))
	if len(aff) != 2 {
		t.Fatalf("affected: %d, want 2", len(aff))
	}
	wantPath := "ES03BankReentrancy.sol"
	if got := validation.ObjStr(aff[0], "path"); got != wantPath {
		t.Fatalf("affected[0] path: %q, want %q", got, wantPath)
	}
	lines := valsOf(validation.ObjAt(aff[0], "lines"))
	if len(lines) != 2 || lines[0].I != lines[1].I {
		t.Fatalf("affected lines shape: %v", lines)
	}
	if validation.ObjAt(aff[0], "entry_point").B {
		t.Fatal("tool payloads are never entry points")
	}
}

// TestClassTable pins every mapping the plan locked, plus the default.
func TestClassTable(t *testing.T) {
	want := map[string]string{
		"reentrancy-state-change":         "reentrancy",
		"unchecked-low-level-call":        "unchecked-external-call",
		"unchecked-return":                "unchecked-external-call",
		"unchecked-send":                  "unchecked-external-call",
		"delegate-call-unchecked-address": "unchecked-external-call",
		"arbitrary-transfer-from":         "access-control",
		"tx-origin-used-for-auth":         "access-control",
		"centralization-risk":             "access-control",
		"unprotected-initializer":         "upgrade-initializer",
		"weak-randomness":                 "signature-replay",
		"costly-loop":                     "dos-griefing",
		"contract-locks-ether":            "dos-griefing",
	}
	if len(checkClasses) != len(want) {
		t.Fatalf("class table size: %d, want %d", len(checkClasses), len(want))
	}
	for k, v := range want {
		if checkClasses[k] != v {
			t.Fatalf("class table[%q] = %q, want %q", k, checkClasses[k], v)
		}
	}
	if checkClasses["reentrancy-state-change"] != "reentrancy" {
		t.Fatal("sanity")
	}
}

func TestUnmappedDetectorKeepsDefaultClass(t *testing.T) {
	doc := validation.FromAny(map[string]any{"high_issues": map[string]any{
		"issues": []any{map[string]any{
			"title": "T", "detector_name": "something-new",
			"description": "brand new finding text",
			"instances":   []any{map[string]any{"contract_path": "a.sol", "line_no": 3}},
		}}}})
	ps, err := ToPayloads(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || validation.ObjStr(validation.ObjAt(ps[0], "root_cause"), "class") != "logic-error" {
		t.Fatalf("unmapped detectors must land logic-error, got %d payloads", len(ps))
	}
}

func TestNoHighIssuesIsEmpty(t *testing.T) {
	ps, err := ToPayloads(validation.FromAny(map[string]any{
		"high_issues": map[string]any{"issues": []any{}},
		"low_issues":  map[string]any{"issues": []any{}},
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
	for _, p := range ps {
		for _, k := range []string{"title", "root_cause", "affected", "attacker", "evidence"} {
			if validation.ObjAt(p, k).Kind == validation.Null {
				t.Fatalf("payload missing %s", k)
			}
		}
	}
}
