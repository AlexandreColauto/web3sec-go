package briefing

// Port of tests/test_recall_relevance.py's brief-rendering half: the
// `corpus:` next-action line and the corpus_recall counts.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35SeedGlobal installs one or more approved shared-store rows.
func t35SeedGlobal(t *testing.T, rows ...validation.Value) {
	t.Helper()
	wrapper := []validation.Value{}
	for _, row := range rows {
		wrapper = append(wrapper, validation.VObj(
			kv("program_key", validation.VStr("test|other|-")),
			kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
			kv("row", row),
			kv("scope", validation.VStr("global"))))
	}
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return wrapper, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
	})
}

// t35GlobalRow is _seed_row's row body (promoted, dev partition).
func t35GlobalRow(memoryID, bugClass string) validation.Value {
	return validation.VObj(
		kv("memory_id", validation.VStr(memoryID)),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Shared memory pattern")),
		kv("bug_class", validation.VStr(bugClass)),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Seeded incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")))
}

// t35RecordCheck records one negative-mode memory check citing memoryIDs.
func t35RecordCheck(t *testing.T, c *state.Campaign, fid string,
	memoryIDs []string) {
	t.Helper()
	ids := []validation.Value{}
	for _, id := range memoryIDs {
		ids = append(ids, validation.VStr(id))
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(ids...)),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
}

// t35CorpusLines is the brief's rendered corpus lines. Task 7 fix round 1
// (I-2): the line is command-first now — `webv2 recall …  # corpus: …` — so
// the reason suffix is the marker, not the line prefix.
func t35CorpusLines(t *testing.T, b validation.Value) []string {
	t.Helper()
	out := []string{}
	for _, a := range objAt(b, "next_actions").A {
		if strings.Contains(a.S, "  # corpus: ") {
			out = append(out, a.S)
		}
	}
	return out
}

// Port of tests/test_recall_relevance.py::test_brief_shows_corpus_line_when_checks_are_irrelevant.
func TestBriefShowsCorpusLineWhenChecksAreIrrelevant(t *testing.T) {
	c := newCamp(t, "Acme Program")
	t35SeedGlobal(t, t35GlobalRow("MEM-defi0001", "oracle-manipulation"))
	f := hypo(t, c, "logic-error", nil, nil, "Untitled finding")
	fid := objStr(f, "finding_id")
	t35RecordCheck(t, c, fid, []string{"MEM-defi0001"})
	b := build(t, c, false)
	lines := t35CorpusLines(t, b)
	if len(lines) != 1 {
		t.Fatalf("corpus lines = %v, want exactly 1", lines)
	}
	if !strings.Contains(lines[0], "1 memory check cites no overlapping row") {
		t.Errorf("line = %q", lines[0])
	}
	wantCmd := "webv2 recall " + c.CampaignID + " --finding " + fid
	if !strings.Contains(lines[0], wantCmd) {
		t.Errorf("line %q lacks the runnable command %q", lines[0], wantCmd)
	}
	cr := objAt(b, "corpus_recall")
	for k, want := range map[string]int64{
		"irrelevant_checks": 1, "silent_checks": 1, "label_only_checks": 0} {
		if got := objAt(cr, k).I; got != want {
			t.Errorf("corpus_recall.%s = %d, want %d", k, got, want)
		}
	}
	if got := objStringList(t, cr, "findings"); len(got) != 1 ||
		got[0] != fid {
		t.Errorf("corpus_recall.findings = %v, want [%s]", got, fid)
	}
}

// Port of tests/test_recall_relevance.py::test_brief_line_names_the_discounted_label_and_never_claims_silence.
func TestBriefLineNamesDiscountedLabelAndNeverClaimsSilence(t *testing.T) {
	c := newCamp(t, "Acme Program")
	t35SeedGlobal(t, t35GlobalRow("MEM-rollup01", "logic-error"),
		t35GlobalRow("MEM-miss01", "proof-forgery"))
	f1 := hypo(t, c, "logic-error", nil, nil, "label-only gap finding")
	f2 := hypo(t, c, "logic-error", nil, nil, "silent gap finding")
	t35RecordCheck(t, c, objStr(f1, "finding_id"),
		[]string{"MEM-rollup01"})
	t35RecordCheck(t, c, objStr(f2, "finding_id"), []string{"MEM-miss01"})
	b := build(t, c, false)
	lines := t35CorpusLines(t, b)
	if len(lines) != 1 {
		t.Fatalf("corpus lines = %v, want exactly 1", lines)
	}
	for _, want := range []string{"2 memory checks cite no overlapping row",
		"non-discriminative class label", "bug_class=logic-error"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("line %q lacks %q", lines[0], want)
		}
	}
	if strings.Contains(strings.ToLower(lines[0]), "silent") {
		t.Errorf("line must not claim silence: %q", lines[0])
	}
	cr := objAt(b, "corpus_recall")
	for k, want := range map[string]int64{
		"irrelevant_checks": 2, "label_only_checks": 1, "silent_checks": 1} {
		if got := objAt(cr, k).I; got != want {
			t.Errorf("corpus_recall.%s = %d, want %d", k, got, want)
		}
	}
	if got := objStringList(t, cr, "discounted"); len(got) != 1 ||
		got[0] != "bug_class=logic-error" {
		t.Errorf("corpus_recall.discounted = %v", got)
	}
	got := objStringList(t, cr, "findings")
	want := []string{objStr(f1, "finding_id"), objStr(f2, "finding_id")}
	if !sameStringSet(got, want) {
		t.Errorf("corpus_recall.findings = %v, want %v", got, want)
	}
}

// Port of tests/test_recall_relevance.py::test_brief_corpus_command_names_the_campaign_and_counts_extra_findings.
func TestBriefCorpusCommandNamesCampaignAndCountsExtraFindings(t *testing.T) {
	c := newCamp(t, "Acme Program")
	t35SeedGlobal(t, t35GlobalRow("MEM-defi0001", "oracle-manipulation"))
	f1 := hypo(t, c, "logic-error", nil, nil, "first gap finding")
	f2 := hypo(t, c, "logic-error", nil, nil, "second gap finding")
	t35RecordCheck(t, c, objStr(f1, "finding_id"), []string{"MEM-defi0001"})
	t35RecordCheck(t, c, objStr(f2, "finding_id"), []string{"MEM-defi0001"})
	b := build(t, c, false)
	lines := t35CorpusLines(t, b)
	if len(lines) != 1 {
		t.Fatalf("corpus lines = %v, want exactly 1", lines)
	}
	first := objStr(f1, "finding_id")
	if second := objStr(f2, "finding_id"); second < first {
		first = second
	}
	if !strings.Contains(lines[0], "webv2 recall "+c.CampaignID+
		" --finding "+first) {
		t.Errorf("line %q lacks the deterministic command", lines[0])
	}
	if !strings.Contains(lines[0], "— 1 more findings") {
		// re-pinned deliberately (Task 7 fix round 1, I-2): the paren-free
		// reason suffix rewords the old "(+1 more finding(s))"
		t.Errorf("line %q lacks the extra-findings count", lines[0])
	}
	if got := objAt(objAt(b, "corpus_recall"), "irrelevant_checks").I; got != 2 {
		t.Errorf("irrelevant_checks = %d, want 2", got)
	}
}

// Port of tests/test_recall_relevance.py::test_brief_has_no_corpus_line_without_irrelevant_checks.
func TestBriefHasNoCorpusLineWithoutIrrelevantChecks(t *testing.T) {
	c := newCamp(t, "Acme Program")
	t35SeedGlobal(t, t35GlobalRow("MEM-over01", "bridge-message"))
	f := hypo(t, c, "bridge-message", nil, nil, "overlapping finding")
	t35RecordCheck(t, c, objStr(f, "finding_id"), []string{"MEM-over01"})
	b := build(t, c, false)
	if lines := t35CorpusLines(t, b); len(lines) != 0 {
		t.Errorf("corpus lines = %v, want none", lines)
	}
	cr := objAt(b, "corpus_recall")
	if got := objAt(cr, "irrelevant_checks").I; got != 0 {
		t.Errorf("irrelevant_checks = %d, want 0", got)
	}
	if got := objStringList(t, cr, "findings"); len(got) != 0 {
		t.Errorf("findings = %v, want []", got)
	}
}

// Port of tests/test_recall_relevance.py::test_brief_is_clean_on_an_empty_campaign.
func TestBriefIsCleanOnAnEmptyCampaign(t *testing.T) {
	c := newCamp(t, "Acme Program")
	b := build(t, c, false)
	if lines := t35CorpusLines(t, b); len(lines) != 0 {
		t.Errorf("corpus lines = %v, want none", lines)
	}
	cr := objAt(b, "corpus_recall")
	for k, want := range map[string]int64{
		"checks": 0, "irrelevant_checks": 0, "label_only_checks": 0,
		"no_rows_checks": 0, "silent_checks": 0} {
		if got := objAt(cr, k).I; got != want {
			t.Errorf("corpus_recall.%s = %d, want 0", k, got)
		}
	}
	for _, k := range []string{"discounted", "findings"} {
		if got := objAt(cr, k); got.Kind != validation.Arr || len(got.A) != 0 {
			t.Errorf("corpus_recall.%s = %v, want []", k, got)
		}
	}
}

// sameStringSet compares two string slices order-insensitively.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
