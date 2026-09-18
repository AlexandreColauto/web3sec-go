package findings

// relevance_test.go: port of tests/test_recall_relevance.py (task B3 / plan
// D2) — the P1 half. The P3 half (learning.queue_memory stamping
// granted/required, briefing.py's `corpus:` next-action line, `webv2 recall`
// printing the verdict) belongs to the shared-memory/briefing/CLI surfaces
// this port does not cover yet; the tests that need a campaign-derived row
// stand in for learning.queue_memory via the learning seam and say so.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures ----

// relevanceRow is _seed_row's row shape: the fields the relevance predicate
// reads, plus overrides for the legacy shapes (`terminal`, hand-written
// capability lists) the memory schema does not declare.
func relevanceRow(memoryID, bugClass string, overrides ...validation.KV) validation.Value {
	row := validation.VObj(
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
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	for _, o := range overrides {
		row.O = validation.SetOrAppend(row.O, o.K, o.V)
	}
	return row
}

// installRelevanceStore wires both tier seams for one test: shared rows in
// the {row: ...} wrapper shape, learning rows raw (see VisibleMemoryRows).
func installRelevanceStore(t *testing.T, shared, learned []validation.Value) {
	t.Helper()
	prevShared, prevLearn := sharedMemoryRowsFunc, learningAllMemoryFunc
	sharedMemoryRowsFunc = func(string) ([]validation.Value, error) {
		out := make([]validation.Value, 0, len(shared))
		for _, r := range shared {
			out = append(out, validation.VObj(kv("row", r)))
		}
		return out, nil
	}
	learningAllMemoryFunc = func(*state.Campaign) ([]validation.Value, error) {
		return learned, nil
	}
	t.Cleanup(func() {
		sharedMemoryRowsFunc, learningAllMemoryFunc = prevShared, prevLearn
	})
}

// mintRelevanceFinding is _mint: a finding with a class, an optional cwe and
// explicit capability lists.
func mintRelevanceFinding(t *testing.T, c *state.Campaign, class, cwe string,
	granted, required []string) validation.Value {
	t.Helper()
	root := validation.VObj(
		kv("class", validation.VStr(class)),
		kv("description", validation.VStr("mechanism described in detail here")),
	)
	if cwe != "" {
		root.O = append(root.O, kv("cwe", validation.VStr(cwe)))
	}
	f, err := IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Untitled finding")),
		kv("root_cause", root),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
		kv("capabilities", validation.VObj(
			kv("granted", validation.StrArr(granted)),
			kv("required", validation.StrArr(required)),
		)),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// recordCheck is the one-check RecordMemoryCheck call the tests all make.
func recordCheck(t *testing.T, c *state.Campaign, findingID string,
	ids []string, mode string, note string) validation.Value {
	t.Helper()
	check := validation.VObj(
		kv("memory_ids", validation.StrArr(ids)),
		kv("mode", validation.VStr(mode)),
	)
	if note != "" {
		check.O = append(check.O, kv("note", validation.VStr(note)))
	}
	out, err := RecordMemoryCheck(c, findingID, []validation.Value{check})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// memoryEntries is out["provenance"]["memory_checks"].
func memoryEntries(v validation.Value) []validation.Value {
	return validation.ObjAt(asDict(validation.ObjAt(v, "provenance")), "memory_checks").A
}

// corpusGapData is every corpus.gap event's data, in log order.
func corpusGapData(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := []validation.Value{}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "corpus.gap" {
			out = append(out, asDict(validation.ObjAt(e, "data")))
		}
	}
	return out
}

// orderedJSON is compact JSON that preserves object key order (CanonCompact
// sorts keys; the verdict's key order is contractual, so assertions on it
// need the ordered form).
func orderedJSON(v validation.Value) string {
	switch v.Kind {
	case validation.Obj:
		parts := make([]string, 0, len(v.O))
		for _, f := range v.O {
			parts = append(parts, validation.CanonCompact(validation.VStr(f.K))+
				":"+orderedJSON(f.V))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case validation.Arr:
		parts := make([]string, 0, len(v.A))
		for _, e := range v.A {
			parts = append(parts, orderedJSON(e))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	return validation.CanonCompact(v)
}

// canonRelevance is the ordered compact JSON of an entry's verdict.
func canonRelevance(t *testing.T, entry validation.Value) string {
	t.Helper()
	return orderedJSON(validation.ObjAt(entry, "relevance"))
}

// ---- 1. zero-overlap: stamped, logged, and the gate clause still passes ----

// Port of test_zero_overlap_check_is_stamped_logged_and_still_satisfies_gate.
func TestZeroOverlapCheckIsStampedLoggedAndStillSatisfiesGate(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-defi0001", "oracle-manipulation"))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := validation.ObjStr(f, "finding_id")
	out := recordCheck(t, c, fid, []string{"MEM-defi0001"}, "negative", "")
	entry := memoryEntries(out)[0]
	if v := validation.ObjAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		t.Errorf("recalled_irrelevant = %v, want true", v)
	}
	if got := canonRelevance(t, entry); got != `{"overlapping":[],"basis":[]}` {
		t.Errorf("relevance = %s", got)
	}

	gaps := corpusGapData(t, c)
	if len(gaps) != 1 {
		t.Fatalf("corpus.gap events = %d, want 1", len(gaps))
	}
	data := gaps[0]
	if got := validation.ObjStr(data, "finding"); got != fid {
		t.Errorf("gap finding = %q, want %q", got, fid)
	}
	if got := validation.CanonCompact(validation.ObjAt(data, "memory_ids")); got !=
		`["MEM-defi0001"]` {
		t.Errorf("gap memory_ids = %s", got)
	}
	if got := validation.ObjStr(data, "mode"); got != "negative" {
		t.Errorf("gap mode = %q, want negative", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(data, "lineage")); got !=
		`["bug_class=logic-error"]` {
		t.Errorf("gap lineage = %s", got)
	}
	if validation.ObjStr(data, "reason") == "" {
		t.Error("gap reason empty")
	}
	if got := validation.ObjStr(data, "reason_code"); got != GAP_NO_SHARED_TAG {
		t.Errorf("reason_code = %q, want %q", got, GAP_NO_SHARED_TAG)
	}

	// the ACT still satisfies the clause — no new gate
	if fails, err := MemoryCheckFails(c, fid); err != nil || fails != nil {
		t.Fatalf("memory_check_fails = %v, %v; want nil, nil", fails, err)
	}
}

// Port of test_zero_row_check_is_stamped_and_logged: a `negative` check
// citing zero rows. Nothing was consulted, so the reason says exactly that —
// it must not borrow the "corpus is silent on this lineage" claim.
func TestZeroRowCheckIsStampedAndLogged(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t)
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := validation.ObjStr(f, "finding_id")
	out := recordCheck(t, c, fid, nil, "negative", "")
	entry := memoryEntries(out)[0]
	if v := validation.ObjAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		t.Errorf("recalled_irrelevant = %v, want true", v)
	}
	if got := canonRelevance(t, entry); got != `{"overlapping":[],"basis":[]}` {
		t.Errorf("relevance = %s", got)
	}
	gaps := corpusGapData(t, c)
	if len(gaps) != 1 || len(validation.ObjAt(gaps[0], "memory_ids").A) != 0 {
		t.Fatalf("gaps = %v", gaps)
	}
	if got := validation.ObjStr(gaps[0], "reason_code"); got != GAP_NO_ROWS_CITED {
		t.Errorf("reason_code = %q, want %q", got, GAP_NO_ROWS_CITED)
	}
	reason := validation.ObjStr(gaps[0], "reason")
	if !strings.Contains(reason, "no rows") {
		t.Errorf("reason %q misses 'no rows'", reason)
	}
	if strings.Contains(strings.ToLower(reason), "silent") {
		t.Errorf("reason %q must not claim silence", reason)
	}
	if fails, err := MemoryCheckFails(c, fid); err != nil || fails != nil {
		t.Fatalf("memory_check_fails = %v, %v; want nil, nil", fails, err)
	}
}

// Port of test_repeating_an_identical_check_logs_no_second_gap.
func TestRepeatingAnIdenticalCheckLogsNoSecondGap(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-defi0001", "oracle-manipulation"))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := validation.ObjStr(f, "finding_id")
	recordCheck(t, c, fid, []string{"MEM-defi0001"}, "negative", "")
	out := recordCheck(t, c, fid, []string{"MEM-defi0001"}, "negative", "")
	if n := len(memoryEntries(out)); n != 1 {
		t.Fatalf("memory_checks = %d, want 1", n)
	}
	if n := len(corpusGapData(t, c)); n != 1 {
		t.Fatalf("corpus.gap events = %d, want 1 (deduped: no duplicate signal)", n)
	}
}

// ---- 2. overlap bases: capability label, bug_class, cwe ----

// Port of test_discriminative_bug_class_alone_is_overlap.
func TestDiscriminativeBugClassAloneIsOverlap(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-bridge01", "bridge-message"))
	f := mintRelevanceFinding(t, c, "bridge-message", "", nil, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-bridge01"}, "negative", "")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent on overlap")
	}
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-bridge01"],"basis":["bug_class"]}` {
		t.Errorf("relevance = %s", got)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_coarse_class_alone_is_stamped_and_logs_one_gap: the catch-all
// alone is NOT overlap, and the reason names the discounted label — the
// corpus has rows in that class, so it must NOT claim silence.
func TestCoarseClassAloneIsStampedAndLogsOneGap(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-rollup01", "logic-error"))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := validation.ObjStr(f, "finding_id")
	out := recordCheck(t, c, fid, []string{"MEM-rollup01"}, "negative", "")
	entry := memoryEntries(out)[0]
	if v := validation.ObjAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		t.Errorf("recalled_irrelevant = %v, want true", v)
	}
	rel := validation.ObjAt(entry, "relevance")
	if got := validation.CanonCompact(validation.ObjAt(rel, "overlapping")); got != "[]" {
		t.Errorf("overlapping = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "basis")); got != "[]" {
		t.Errorf("basis = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "discounted")); got !=
		`["bug_class=logic-error"]` {
		t.Errorf("discounted = %s", got)
	}
	if rule := validation.ObjStr(rel, "rule"); !strings.Contains(rule, "second basis") {
		t.Errorf("rule %q misses 'second basis'", rule)
	}
	gaps := corpusGapData(t, c)
	if len(gaps) != 1 {
		t.Fatalf("corpus.gap events = %d, want 1", len(gaps))
	}
	if got := validation.CanonCompact(validation.ObjAt(gaps[0], "memory_ids")); got !=
		`["MEM-rollup01"]` {
		t.Errorf("gap memory_ids = %s", got)
	}
	if got := validation.ObjStr(gaps[0], "reason_code"); got != GAP_SHARED_CATCH_ALL_ONLY {
		t.Errorf("reason_code = %q, want %q", got, GAP_SHARED_CATCH_ALL_ONLY)
	}
	if reason := validation.ObjStr(gaps[0], "reason"); !strings.Contains(reason,
		"second basis") {
		t.Errorf("gap reason %q misses 'second basis'", reason)
	}
	if fails, err := MemoryCheckFails(c, fid); err != nil || fails != nil {
		t.Fatalf("memory_check_fails = %v, %v; want nil, nil", fails, err)
	}
}

// Port of test_discounted_gap_reason_does_not_claim_corpus_silence.
func TestDiscountedGapReasonDoesNotClaimCorpusSilence(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-rollup01", "logic-error"))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-rollup01"}, "negative", "")
	data := corpusGapData(t, c)[0]
	reason := validation.ObjStr(data, "reason")
	for _, want := range []string{"non-discriminative class label",
		"bug_class=logic-error", "second basis"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q misses %q", reason, want)
		}
	}
	if strings.Contains(strings.ToLower(reason), "silent") {
		t.Errorf("reason %q must not claim silence", reason)
	}
	// the event shape is unchanged: same name, same fields, plus reason_code
	wantKeys := []string{"finding", "memory_ids", "mode", "lineage", "reason",
		"reason_code"}
	gotKeys := make([]string, 0, len(data.O))
	for _, f := range data.O {
		gotKeys = append(gotKeys, f.K)
	}
	sort.Strings(gotKeys)
	sort.Strings(wantKeys)
	if strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
		t.Errorf("gap keys = %v, want %v", gotKeys, wantKeys)
	}
	if got := validation.CanonCompact(validation.ObjAt(data, "lineage")); got !=
		`["bug_class=logic-error"]` {
		t.Errorf("lineage = %s", got)
	}
}

// Port of test_truly_silent_gap_keeps_the_silence_wording.
func TestTrulySilentGapKeepsTheSilenceWording(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-miss01", "proof-forgery"))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-miss01"}, "negative", "")
	data := corpusGapData(t, c)[0]
	if got := validation.ObjStr(data, "reason_code"); got != GAP_NO_SHARED_TAG {
		t.Errorf("reason_code = %q, want %q", got, GAP_NO_SHARED_TAG)
	}
	reason := validation.ObjStr(data, "reason")
	if !strings.Contains(strings.ToLower(reason), "silent") {
		t.Errorf("reason %q must claim silence", reason)
	}
	if strings.Contains(reason, "non-discriminative") {
		t.Errorf("reason %q must not name the discount rule", reason)
	}
}

// Port of test_nondiscriminative_classes_is_only_the_taxonomy_catch_all.
func TestNondiscriminativeClassesIsOnlyTheTaxonomyCatchAll(t *testing.T) {
	got := NondiscriminativeClasses()
	if len(got) != 1 {
		t.Fatalf("nondiscriminative_classes = %v, want exactly the catch-all", got)
	}
	if _, ok := got[CATCH_ALL_BUG_CLASS]; !ok {
		t.Errorf("catch-all %q missing", CATCH_ALL_BUG_CLASS)
	}
	for _, cls := range []string{"oracle-manipulation", "economic-invariant",
		"signature-replay"} {
		if _, ok := got[cls]; ok {
			t.Errorf("%q must NOT be non-discriminative", cls)
		}
	}
}

// Port of test_same_class_cite_counts_for_every_class_but_the_catch_all.
func TestSameClassCiteCountsForEveryClassButTheCatchAll(t *testing.T) {
	for _, cls := range []string{"oracle-manipulation", "economic-invariant",
		"signature-replay"} {
		t.Run(cls, func(t *testing.T) {
			c := ingestCamp(t)
			installMemoryStore(t, relevanceRow("MEM-sameline01", cls))
			f := mintRelevanceFinding(t, c, cls, "", nil, nil)
			fid := validation.ObjStr(f, "finding_id")
			out := recordCheck(t, c, fid, []string{"MEM-sameline01"},
				"negative", "")
			entry := memoryEntries(out)[0]
			if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
				t.Error("recalled_irrelevant must be absent")
			}
			if got := canonRelevance(t, entry); got !=
				`{"overlapping":["MEM-sameline01"],"basis":["bug_class"]}` {
				t.Errorf("relevance = %s", got)
			}
			if gaps := corpusGapData(t, c); len(gaps) != 0 {
				t.Errorf("corpus.gap events = %d, want 0", len(gaps))
			}
			if fails, err := MemoryCheckFails(c, fid); err != nil || fails != nil {
				t.Fatalf("memory_check_fails = %v, %v; want nil, nil", fails, err)
			}
		})
	}
}

// Port of
// test_twenty_coarse_class_rows_for_a_rollup_finding_are_all_irrelevant:
// the plan's motivating case — 20 DeFi rows cited for a rollup question
// whose class is the catch-all. All 20 share ONLY the catch-all label.
func TestTwentyCoarseClassRowsForARollupFindingAreAllIrrelevant(t *testing.T) {
	c := ingestCamp(t)
	ids := make([]string, 0, 20)
	rows := make([]validation.Value, 0, 20)
	for i := 1; i <= 20; i++ {
		mid := fmt.Sprintf("MEM-defi%04d", i)
		ids = append(ids, mid)
		rows = append(rows, relevanceRow(mid, "logic-error",
			kv("pattern", validation.VStr(fmt.Sprintf(
				"Unrelated DeFi lending-market row number %d", i))),
			kv("evidence_summary", validation.VStr(fmt.Sprintf(
				"DeFi incident %d.", i)))))
	}
	installMemoryStore(t, rows...)
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := validation.ObjStr(f, "finding_id")
	out := recordCheck(t, c, fid, ids, "negative", "")
	entry := memoryEntries(out)[0]
	if v := validation.ObjAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		t.Errorf("recalled_irrelevant = %v, want true", v)
	}
	if got := validation.CanonCompact(validation.ObjAt(validation.ObjAt(entry, "relevance"),
		"overlapping")); got != "[]" {
		t.Errorf("overlapping = %s", got)
	}
	gaps := corpusGapData(t, c)
	if len(gaps) != 1 {
		t.Fatalf("corpus.gap events = %d, want 1", len(gaps))
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	if got := validation.CanonCompact(validation.ObjAt(gaps[0], "memory_ids")); got !=
		validation.CanonCompact(validation.StrArr(sorted)) {
		t.Errorf("gap memory_ids = %s", got)
	}
	if fails, err := MemoryCheckFails(c, fid); err != nil || fails != nil {
		t.Fatalf("memory_check_fails = %v, %v; want nil, nil", fails, err)
	}
}

// Port of test_coarse_class_plus_shared_capability_is_not_stamped: the
// rule's escape hatch — the same catch-all class DOES count once a second
// basis (a shared capability label) is present. PORT-NOTE: the row stands in
// for learning.queue_memory's output (P3, unported), which is exactly the
// row shape the review fix stamps.
func TestCoarseClassPlusSharedCapabilityIsNotStamped(t *testing.T) {
	c := ingestCamp(t)
	derived := relevanceRow("MEM-derived01", "logic-error",
		kv("pattern", validation.VStr("share-price read from a manipulable "+
			"spot market")),
		kv("granted", validation.StrArr([]string{"control_perceived_asset_price"})))
	installRelevanceStore(t, nil, []validation.Value{derived})
	f := mintRelevanceFinding(t, c, "logic-error", "",
		[]string{"control_perceived_asset_price"}, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-derived01"}, "comparative", "same capability primitive")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent")
	}
	rel := validation.ObjAt(entry, "relevance")
	if got := validation.CanonCompact(validation.ObjAt(rel, "overlapping")); got !=
		`["MEM-derived01"]` {
		t.Errorf("overlapping = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "basis")); got !=
		`["capability"]` {
		t.Errorf("basis = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "discounted")); got !=
		`["bug_class=logic-error"]` {
		t.Errorf("discounted = %s", got)
	}
	if rule := validation.ObjStr(rel, "rule"); !strings.Contains(rule, "second basis") {
		t.Errorf("rule %q misses 'second basis'", rule)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_mixed_cite_whose_only_shared_class_is_a_real_lineage_counts.
func TestMixedCiteWhoseOnlySharedClassIsARealLineageCounts(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t,
		relevanceRow("MEM-oracle01", "oracle-manipulation"),
		relevanceRow("MEM-miss01", "proof-forgery"))
	f := mintRelevanceFinding(t, c, "oracle-manipulation", "", nil, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-miss01", "MEM-oracle01"}, "negative", "")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent")
	}
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-oracle01"],"basis":["bug_class"]}` {
		t.Errorf("relevance = %s", got)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_cwe_overlap_is_not_stamped.
func TestCWEEOverlapIsNotStamped(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-cwe01", "oracle-manipulation",
		kv("cwe", validation.VStr("CWE-682"))))
	f := mintRelevanceFinding(t, c, "logic-error", "CWE-682", nil, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-cwe01"}, "comparative", "same arithmetic root cause")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent")
	}
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-cwe01"],"basis":["cwe"]}` {
		t.Errorf("relevance = %s", got)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_capability_label_overlap_is_not_stamped: granted/required are
// schema-declared since fix round 1 (part (a)); a hand-written row's raw
// label is normalized on both sides.
func TestCapabilityLabelOverlapIsNotStamped(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-cap01", "oracle-manipulation",
		kv("granted", validation.StrArr([]string{"Control-Perceived_Asset Price"}))))
	f := mintRelevanceFinding(t, c, "logic-error", "",
		[]string{"control_perceived_asset_price"}, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-cap01"}, "comparative", "same capability primitive")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent")
	}
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-cap01"],"basis":["capability"]}` {
		t.Errorf("relevance = %s", got)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_row_terminal_counts_as_capability_label.
func TestRowTerminalCountsAsCapabilityLabel(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-term01", "oracle-manipulation",
		kv("terminal", validation.VStr("extract_protocol_liquidity"))))
	f := mintRelevanceFinding(t, c, "logic-error", "",
		[]string{"extract_protocol_liquidity"}, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-term01"}, "negative", "")
	entry := memoryEntries(out)[0]
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-term01"],"basis":["capability"]}` {
		t.Errorf("relevance = %s", got)
	}
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent on overlap")
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_cite_against_a_campaign_derived_row_overlaps_on_capability:
// end to end, the stamped labels make a cite overlap on capability even when
// the bug classes differ. PORT-NOTE: the row stands in for
// learning.queue_memory (P3, unported).
func TestCiteAgainstACampaignDerivedRowOverlapsOnCapability(t *testing.T) {
	c := ingestCamp(t)
	derived := relevanceRow("MEM-derived02", "logic-error",
		kv("granted", validation.StrArr([]string{"control_perceived_asset_price"})))
	installRelevanceStore(t, nil, []validation.Value{derived})
	f := mintRelevanceFinding(t, c, "oracle-manipulation", "",
		[]string{"control_perceived_asset_price"}, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-derived02"}, "comparative", "same capability primitive")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent")
	}
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-derived02"],"basis":["capability"]}` {
		t.Errorf("relevance = %s", got)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_mixed_cite_is_not_stamped_and_lists_only_overlapping_rows.
func TestMixedCiteIsNotStampedAndListsOnlyOverlappingRows(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t,
		relevanceRow("MEM-over01", "bridge-message"),
		relevanceRow("MEM-miss01", "proof-forgery"))
	f := mintRelevanceFinding(t, c, "bridge-message", "", nil, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-miss01", "MEM-over01"}, "negative", "")
	entry := memoryEntries(out)[0]
	if _, ok := fieldAt(entry, "recalled_irrelevant"); ok {
		t.Error("recalled_irrelevant must be absent")
	}
	if got := canonRelevance(t, entry); got !=
		`{"overlapping":["MEM-over01"],"basis":["bug_class"]}` {
		t.Errorf("relevance = %s", got)
	}
	if gaps := corpusGapData(t, c); len(gaps) != 0 {
		t.Errorf("corpus.gap events = %d, want 0", len(gaps))
	}
}

// Port of test_mixed_cite_where_the_only_shared_class_is_coarse_is_stamped:
// a row that agrees ONLY on the catch-all does not rescue a cite, even when
// it sits beside rows that share nothing at all.
func TestMixedCiteWhereTheOnlySharedClassIsCoarseIsStamped(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t,
		relevanceRow("MEM-coarse01", "logic-error"),
		relevanceRow("MEM-miss01", "proof-forgery"))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-miss01", "MEM-coarse01"}, "negative", "")
	entry := memoryEntries(out)[0]
	if v := validation.ObjAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		t.Errorf("recalled_irrelevant = %v, want true", v)
	}
	rel := validation.ObjAt(entry, "relevance")
	if got := validation.CanonCompact(validation.ObjAt(rel, "overlapping")); got != "[]" {
		t.Errorf("overlapping = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "discounted")); got !=
		`["bug_class=logic-error"]` {
		t.Errorf("discounted = %s", got)
	}
	if n := len(corpusGapData(t, c)); n != 1 {
		t.Errorf("corpus.gap events = %d, want 1", n)
	}
}

// ---- 3. prose never counts ----

// Port of test_prose_only_similarity_scores_zero_overlap.
func TestProseOnlySimilarityScoresZeroOverlap(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-prose01", "oracle-manipulation",
		kv("pattern", validation.VStr("Donation attack on share price")),
		kv("evidence_summary", validation.VStr("Donation attack on share price"))))
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-prose01"}, "comparative", "identical prose, different lineage")
	entry := memoryEntries(out)[0]
	if v := validation.ObjAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		t.Errorf("recalled_irrelevant = %v, want true", v)
	}
	if got := canonRelevance(t, entry); got != `{"overlapping":[],"basis":[]}` {
		t.Errorf("relevance = %s", got)
	}
	if n := len(corpusGapData(t, c)); n != 1 {
		t.Errorf("corpus.gap events = %d, want 1", n)
	}
}

// ---- 4. back-compat: pre-existing entries keep verifying, byte-identical ----

// Port of test_pre_existing_check_without_relevance_still_verifies_unchanged.
func TestPreExistingCheckWithoutRelevanceStillVerifiesUnchanged(t *testing.T) {
	c := ingestCamp(t)
	row := relevanceRow("MEM-old00001", "logic-error")
	installMemoryStore(t, row)
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := validation.ObjStr(f, "finding_id")
	legacy := validation.VObj(
		kv("memory_ids", validation.StrArr([]string{"MEM-old00001"})),
		kv("mode", validation.VStr("negative")),
		kv("consulted_at", validation.VStr("2026-09-01T00:00:00+00:00")),
		kv("row_digest", validation.VStr(ComputeRowDigest(
			[]string{"MEM-old00001"},
			map[string]validation.Value{"MEM-old00001": row}))),
	)
	f.O = validation.SetOrAppend(f.O, "provenance",
		validation.VObj(kv("memory_checks", validation.VArr(legacy))))
	if err := SaveFinding(c, &f); err != nil {
		t.Fatalf("the schema must still accept the old shape: %v", err)
	}
	if fails, err := MemoryCheckFails(c, fid); err != nil || fails != nil {
		t.Fatalf("memory_check_fails = %v, %v; want nil, nil", fails, err)
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	entries := memoryEntries(stored)
	if len(entries) != 1 {
		t.Fatalf("memory_checks = %d, want 1", len(entries))
	}
	if got, want := validation.DumpIndented(entries[0]),
		validation.DumpIndented(legacy); got != want {
		t.Errorf("stored entry = %s, want %s", got, want)
	}
	// no retroactive stamp, no retroactive event
	if n := len(corpusGapData(t, c)); n != 0 {
		t.Errorf("corpus.gap events = %d, want 0", n)
	}
}

// ---- 5. determinism ----

// withoutConsultedAt drops consulted_at (the one wall-clock field).
func withoutConsultedAt(v validation.Value) validation.Value {
	out := validation.VObj()
	for _, f := range v.O {
		if f.K != "consulted_at" {
			out.O = append(out.O, f)
		}
	}
	return out
}

// Port of test_two_identical_recordings_produce_identical_entries.
func TestTwoIdenticalRecordingsProduceIdenticalEntries(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t,
		relevanceRow("MEM-det00001", "bridge-message"),
		relevanceRow("MEM-miss001", "proof-forgery"))
	entries := []validation.Value{}
	for _, title := range []string{"first deterministic recording",
		"second deterministic recording"} {
		f := mintRelevanceFinding(t, c, "bridge-message", "", nil, nil)
		f.O = validation.SetOrAppend(f.O, "title", validation.VStr(title))
		out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
			[]string{"MEM-miss001", "MEM-det00001"}, "negative", "")
		entries = append(entries, memoryEntries(out)[0])
	}
	a, b := orderedJSON(withoutConsultedAt(entries[0])),
		orderedJSON(withoutConsultedAt(entries[1]))
	if a != b {
		t.Errorf("entries differ:\n%s\n%s", a, b)
	}
	if got := validation.CanonCompact(validation.ObjAt(entries[0], "memory_ids")); got !=
		`["MEM-det00001","MEM-miss001"]` {
		t.Errorf("memory_ids = %s", got)
	}
	if got := canonRelevance(t, entries[0]); got !=
		`{"overlapping":["MEM-det00001"],"basis":["bug_class"]}` {
		t.Errorf("relevance = %s", got)
	}
}

// Port of test_two_identical_coarse_recordings_produce_identical_entries:
// the discount rule is part of the verdict, so it must be canonical too.
func TestTwoIdenticalCoarseRecordingsProduceIdenticalEntries(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, relevanceRow("MEM-coarse01", "logic-error"))
	entries := []validation.Value{}
	for _, title := range []string{"first coarse recording",
		"second coarse recording"} {
		f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
		f.O = validation.SetOrAppend(f.O, "title", validation.VStr(title))
		out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
			[]string{"MEM-coarse01"}, "negative", "")
		entries = append(entries, memoryEntries(out)[0])
	}
	a, b := orderedJSON(withoutConsultedAt(entries[0])),
		orderedJSON(withoutConsultedAt(entries[1]))
	if a != b {
		t.Errorf("entries differ:\n%s\n%s", a, b)
	}
	rel := validation.ObjAt(entries[0], "relevance")
	if got := validation.CanonCompact(validation.ObjAt(rel, "overlapping")); got != "[]" {
		t.Errorf("overlapping = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "basis")); got != "[]" {
		t.Errorf("basis = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rel, "discounted")); got !=
		`["bug_class=logic-error"]` {
		t.Errorf("discounted = %s", got)
	}
	if rule := validation.ObjStr(rel, "rule"); !strings.Contains(rule, "second basis") {
		t.Errorf("rule %q misses 'second basis'", rule)
	}
}

// ---- 6. the read surface the brief calls (corpus_recall_gaps) ----

// Port of the `corpus_recall` shape assertions from the briefing tests
// (tests/test_recall_relevance.py section 4). The `corpus:` next-action LINE
// itself is briefing.py (P3, unported); this is the pure read it consumes.
func TestCorpusRecallGapsCountsTheSplitAdditively(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t,
		relevanceRow("MEM-rollup01", "logic-error"),
		relevanceRow("MEM-miss01", "proof-forgery"),
		relevanceRow("MEM-defi0001", "oracle-manipulation"))

	empty, err := CorpusRecallGaps(c)
	if err != nil {
		t.Fatal(err)
	}
	wantEmpty := `{"checks":0,"irrelevant_checks":0,"label_only_checks":0,` +
		`"no_rows_checks":0,"silent_checks":0,"discounted":[],"findings":[]}`
	if got := orderedJSON(empty); got != wantEmpty {
		t.Fatalf("empty corpus_recall = %s, want %s", got, wantEmpty)
	}

	labelOnly := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	silent := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	noRows := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	miss := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	recordCheck(t, c, validation.ObjStr(labelOnly, "finding_id"),
		[]string{"MEM-rollup01"}, "negative", "")
	recordCheck(t, c, validation.ObjStr(silent, "finding_id"),
		[]string{"MEM-miss01"}, "negative", "")
	recordCheck(t, c, validation.ObjStr(noRows, "finding_id"), nil, "negative", "")
	recordCheck(t, c, validation.ObjStr(miss, "finding_id"),
		[]string{"MEM-defi0001"}, "negative", "")

	got, err := CorpusRecallGaps(c)
	if err != nil {
		t.Fatal(err)
	}
	if v := validation.ObjAt(got, "checks"); v.I != 4 {
		t.Errorf("checks = %v, want 4", v)
	}
	if v := validation.ObjAt(got, "irrelevant_checks"); v.I != 4 {
		t.Errorf("irrelevant_checks = %v, want 4", v)
	}
	if v := validation.ObjAt(got, "label_only_checks"); v.I != 1 {
		t.Errorf("label_only_checks = %v, want 1", v)
	}
	if v := validation.ObjAt(got, "no_rows_checks"); v.I != 1 {
		t.Errorf("no_rows_checks = %v, want 1", v)
	}
	if v := validation.ObjAt(got, "silent_checks"); v.I != 2 {
		t.Errorf("silent_checks = %v, want 2", v)
	}
	if gotLabels := validation.CanonCompact(validation.ObjAt(got, "discounted")); gotLabels !=
		`["bug_class=logic-error"]` {
		t.Errorf("discounted = %s", gotLabels)
	}
	ids := []string{validation.ObjStr(labelOnly, "finding_id"), validation.ObjStr(silent, "finding_id"),
		validation.ObjStr(noRows, "finding_id"), validation.ObjStr(miss, "finding_id")}
	sort.Strings(ids)
	if gotFindings := validation.CanonCompact(validation.ObjAt(got, "findings")); gotFindings !=
		validation.CanonCompact(validation.StrArr(ids)) {
		t.Errorf("findings = %s, want %s", gotFindings,
			validation.CanonCompact(validation.StrArr(ids)))
	}
}

// ---- 7. helper edge cases Python's implementation is explicit about ----

// _norm_tag is str(value or "").strip().lower(): a non-string truthy value is
// stringified (never dropped), a falsy value is empty.
func TestNormTagStringifiesTruthyNonStrings(t *testing.T) {
	if got := normTag(validation.VInt(5)); got != "5" {
		t.Errorf("normTag(5) = %q, want \"5\"", got)
	}
	if got := normTag(validation.VBool(true)); got != "true" {
		t.Errorf("normTag(true) = %q, want \"true\"", got)
	}
	if got := normTag(validation.VStr("  Logic-Error ")); got != "logic-error" {
		t.Errorf("normTag(strip/lower) = %q, want logic-error", got)
	}
	for _, falsy := range []validation.Value{validation.VNull(),
		validation.VStr(""), validation.VInt(0), validation.VBool(false),
		validation.VArr(), validation.VObj()} {
		if got := normTag(falsy); got != "" {
			t.Errorf("normTag(%v) = %q, want empty", falsy, got)
		}
	}
}

// _norm_cap_values: a bare string is ONE label, never iterated character by
// character (a malformed row must not manufacture spurious overlap).
func TestBareStringCapabilityFieldIsOneLabel(t *testing.T) {
	row := relevanceRow("MEM-capstr01", "oracle-manipulation",
		kv("granted", validation.VStr("Control-Perceived_Asset Price")))
	tags := MemoryRowRelevanceTags(row)
	if got := validation.CanonCompact(validation.StrArr(tags["capability"])); got !=
		`["control_perceived_asset_price"]` {
		t.Fatalf("capability tags = %s", got)
	}
	// a bare string on the FINDING side overlaps the same single label
	c := ingestCamp(t)
	installMemoryStore(t, row)
	f := mintRelevanceFinding(t, c, "logic-error", "",
		[]string{"control_perceived_asset_price"}, nil)
	out := recordCheck(t, c, validation.ObjStr(f, "finding_id"),
		[]string{"MEM-capstr01"}, "comparative", "same primitive")
	if got := canonRelevance(t, memoryEntries(out)[0]); got !=
		`{"overlapping":["MEM-capstr01"],"basis":["capability"]}` {
		t.Errorf("relevance = %s", got)
	}
	// a non-list, non-string field contributes nothing at all
	if got := MemoryRowRelevanceTags(relevanceRow("MEM-capobj01",
		"oracle-manipulation",
		kv("granted", validation.VObj(kv("a", validation.VStr("b")))))); len(got["capability"]) != 0 {
		t.Errorf("object granted contributed %v", got["capability"])
	}
}

// corpus_recall_gaps counts only `recalled_irrelevant is True` (Python's
// identity check), so a hand-written truthy 1 is not a stamped gap.
func TestCorpusRecallGapsIgnoresAStampThatIsNotTrue(t *testing.T) {
	c := ingestCamp(t)
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	checks := validation.VArr(
		validation.VObj(
			kv("memory_ids", validation.StrArr([]string{"MEM-x"})),
			kv("mode", validation.VStr("negative")),
			kv("recalled_irrelevant", validation.VInt(1)),
		),
		validation.VObj(
			kv("memory_ids", validation.StrArr([]string{"MEM-y"})),
			kv("mode", validation.VStr("negative")),
			kv("recalled_irrelevant", validation.VBool(true)),
			kv("relevance", validation.VObj(
				kv("overlapping", validation.VArr()),
				kv("basis", validation.VArr()),
				kv("discounted", validation.StrArr([]string{"bug_class=logic-error"})),
			)),
		),
	)
	f.O = validation.SetOrAppend(f.O, "provenance",
		validation.VObj(kv("memory_checks", checks)))
	if err := validation.WriteJson(FindingPath(c, validation.ObjStr(f, "finding_id")), f,
		""); err != nil {
		t.Fatal(err)
	}
	got, err := CorpusRecallGaps(c)
	if err != nil {
		t.Fatal(err)
	}
	if v := validation.ObjAt(got, "checks"); v.I != 2 {
		t.Errorf("checks = %v, want 2", v)
	}
	if v := validation.ObjAt(got, "irrelevant_checks"); v.I != 1 {
		t.Errorf("irrelevant_checks = %v, want 1", v)
	}
	if v := validation.ObjAt(got, "label_only_checks"); v.I != 1 {
		t.Errorf("label_only_checks = %v, want 1", v)
	}
	if v := validation.ObjAt(got, "silent_checks"); v.I != 0 {
		t.Errorf("silent_checks = %v, want 0", v)
	}
}
