package briefing

// Task 24 (G12): briefing class labels render the OWASP alias suffix when the
// class has one, and stay byte-identical otherwise (presence-gated).

import (
	"strings"
	"testing"
)

// TestCorpusLineRendersAliasSuffix: a discounted label whose class is mapped
// names the pinned OWASP id on the display line; the stored JSON key stays
// the bare machine label.
func TestCorpusLineRendersAliasSuffix(t *testing.T) {
	c := newCamp(t, "Acme Program")
	t35SeedGlobal(t, t35GlobalRow("MEM-rollup01", "logic-error"),
		t35GlobalRow("MEM-miss01", "proof-forgery"))
	f1 := hypo(t, c, "logic-error", nil, nil, "label-only gap finding")
	f2 := hypo(t, c, "logic-error", nil, nil, "silent gap finding")
	t35RecordCheck(t, c, objStr(f1, "finding_id"), []string{"MEM-rollup01"})
	t35RecordCheck(t, c, objStr(f2, "finding_id"), []string{"MEM-miss01"})
	b := build(t, c, false)
	lines := t35CorpusLines(t, b)
	if len(lines) != 1 {
		t.Fatalf("corpus lines = %v, want exactly 1", lines)
	}
	if !strings.Contains(lines[0], "bug_class=logic-error [OWASP SC03]") {
		t.Errorf("corpus line lacks the alias suffix: %q", lines[0])
	}
}

// TestCorpusLineLeavesStoredKeysBare: the suffix is display-only — the
// stored corpus_recall.discounted machine keys keep the bare label while
// the rendered line names the pinned OWASP id.
func TestCorpusLineLeavesStoredKeysBare(t *testing.T) {
	c := newCamp(t, "Acme Program")
	t35SeedGlobal(t, t35GlobalRow("MEM-rollup01", "logic-error"))
	f1 := hypo(t, c, "logic-error", nil, nil, "label-only gap finding")
	t35RecordCheck(t, c, objStr(f1, "finding_id"), []string{"MEM-rollup01"})
	b := build(t, c, false)
	lines := t35CorpusLines(t, b)
	if len(lines) != 1 {
		t.Fatalf("corpus lines = %v, want exactly 1", lines)
	}
	if !strings.Contains(lines[0], "bug_class=logic-error [OWASP SC03]") {
		t.Errorf("corpus line lacks the alias suffix: %q", lines[0])
	}
	cr := objAt(b, "corpus_recall")
	if got := objStringList(t, cr, "discounted"); len(got) != 1 ||
		got[0] != "bug_class=logic-error" {
		t.Errorf("corpus_recall.discounted = %v, want the bare machine key", got)
	}
}

// TestAliasSuffixLabelTable: the display-only label transform.
func TestAliasSuffixLabelTable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"bug_class=reentrancy", "bug_class=reentrancy [OWASP SC05]"},
		{"bug_class=logic-error", "bug_class=logic-error [OWASP SC03]"},
		{"bug_class=donation", "bug_class=donation"},
		{"bug_class=unmapped", "bug_class=unmapped"},
		{"something-else", "something-else"},
	} {
		if got := aliasSuffixLabel(tc.in); got != tc.want {
			t.Errorf("aliasSuffixLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
