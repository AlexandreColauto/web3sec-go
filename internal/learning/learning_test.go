// Port of the learning.py test functions: tests/test_history_learning.py
// (the three LR tests), tests/test_campaign_memory_strip.py,
// tests/test_promotion.py, tests/test_partition_guards.py (the approve
// half) and the two queue_memory capability-label tests from
// tests/test_recall_relevance.py. The Python twin was retired 2026-09-09; this package is the source of truth.
package learning

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

func newCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// mintFinding is test_recall_relevance._mint (capability knobs only).
func mintFinding(t *testing.T, c *state.Campaign, class string,
	granted, required []string, title string) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.StrArr(granted)),
			kv("required", validation.StrArr(required)))),
	), "code", "test", "")
	if err != nil {
		t.Fatalf("ingest hypothesis: %v", err)
	}
	return f
}

// eventsOf is [e for e in camp.events() if e["type"] == eventType].
func eventsOf(t *testing.T, c *state.Campaign, eventType string) []validation.Value {
	t.Helper()
	evts, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	out := []validation.Value{}
	for _, e := range evts {
		if validation.ObjStr(e, "type") == eventType {
			out = append(out, e)
		}
	}
	return out
}

func mustQueue(t *testing.T, c *state.Campaign, o QueueOpts) validation.Value {
	t.Helper()
	mem, err := QueueMemory(c, o)
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	return mem
}

func strPtr(s string) *string { return &s }

// ---- test_history_learning.py ---------------------------------------------

// test_drift_report_and_hypotheses
func TestDriftReportAndHypotheses(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	report, err := RecordDrifts(c, "src-content-abc", []validation.Value{
		validation.VObj(
			kv("layer", validation.VStr("deployment-vs-source")),
			kv("direction", validation.VStr("implementation-weaker")),
			kv("claim", validation.VStr("docs promise withdraw delay of 1 day")),
			kv("reality", validation.VStr("implementation has no delay")),
			kv("risk", validation.VFloat(0.9))),
		validation.VObj(
			kv("layer", validation.VStr("natspec-vs-implementation")),
			kv("direction", validation.VStr("divergent")),
			kv("claim", validation.VStr("NatSpec says reverts on zero")),
			kv("reality", validation.VStr("silently accepts"))),
	})
	if err != nil {
		t.Fatalf("record drifts: %v", err)
	}
	drifts := validation.ObjAt(report, "drifts")
	if got := validation.ObjStr(drifts.A[0], "id"); got != "DRIFT-001" {
		t.Fatalf("first drift id = %q", got)
	}
	if got := validation.ObjStr(drifts.A[1], "id"); got != "DRIFT-002" {
		t.Fatalf("second drift id = %q", got)
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, "drift_report.json")); err != nil {
		t.Fatalf("drift report artifact: %v", err)
	}
	hyps := DriftHypotheses(report)
	if len(hyps) != 2 {
		t.Fatalf("hypotheses = %d", len(hyps))
	}
	if riskOf(hyps[0]) < riskOf(hyps[len(hyps)-1]) {
		t.Fatalf("hypotheses not risk-sorted: %v", hyps)
	}
	if got := validation.ObjStr(hyps[0], "layer"); got != "deployment-vs-source" {
		t.Fatalf("top layer = %q", got)
	}
}

// test_memory_promotion_requires_human
func TestMemoryPromotionRequiresHuman(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	mem := mustQueue(t, c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern: "donation attack blocked by virtual share offset",
		Negative: &validation.Value{O: []validation.KV{
			kv("why_safe", validation.VStr("offset prevents share inflation"))},
			Kind: validation.Obj}})
	if got := validation.ObjStr(mem, "promotion_status"); got != "pending" {
		t.Fatalf("promotion_status = %q", got)
	}
	if _, err := PromotionCommands(c, validation.ObjStr(mem, "memory_id"), "operator-xand"); err == nil {
		t.Fatal("promotion_commands accepted an unapproved row")
	}
	approved, err := ApproveMemory(c, validation.ObjStr(mem, "memory_id"), "operator-xand")
	if err != nil {
		t.Fatalf("approve memory: %v", err)
	}
	if got := validation.ObjStr(approved, "approved_by"); got != "operator-xand" {
		t.Fatalf("approved_by = %q", got)
	}
	cmds, err := PromotionCommands(c, validation.ObjStr(mem, "memory_id"), "operator-xand")
	if err != nil {
		t.Fatalf("promotion commands: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("commands = %d", len(cmds))
	}
	if got := validation.ObjStr(cmds[0], "substrate"); got != "shared-memory-store" {
		t.Fatalf("substrate = %q", got)
	}
	if !strings.Contains(validation.ObjStr(cmds[0], "command"), "webv2 publish "+c.CampaignID) {
		t.Fatalf("command = %q", validation.ObjStr(cmds[0], "command"))
	}
	if _, err := ApproveMemory(c, "MEM-doesnotexist", "x"); err == nil {
		t.Fatal("approve_memory accepted a missing row")
	}
}

// test_negative_memory_local_lookup
func TestNegativeMemoryLocalLookup(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	mustQueue(t, c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern: "first depositor share inflation via rounding",
		Negative: &validation.Value{Kind: validation.Obj, O: []validation.KV{
			kv("why_safe", validation.VStr("virtual share offset"))}}})
	mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "unguarded rescue drains vault"})
	hits, err := NegativeMemoryLookup(c, "share inflation on first deposit")
	if err != nil {
		t.Fatalf("negative lookup: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d", len(hits))
	}
	if !strings.Contains(validation.ObjStr(hits[0], "pattern"), "inflation") {
		t.Fatalf("hit pattern = %q", validation.ObjStr(hits[0], "pattern"))
	}
}

// ---- test_campaign_memory_strip.py ----------------------------------------

// stripRow is test_campaign_memory_strip._row.
func stripRow(t *testing.T, c *state.Campaign, memoryID string, legacy bool,
	status string) validation.Value {
	t.Helper()
	row := validation.VObj(
		kv("memory_id", validation.VStr(memoryID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr(status)),
		kv("pattern", validation.VStr("Pattern "+memoryID)),
		kv("bug_class", validation.VStr("reentrancy")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Legacy incident.")),
		kv("promotion_status", validation.VStr("human-approved")),
		kv("approved_by", validation.VStr("alex")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")))
	if legacy {
		row.O = append(row.O, kv("rag_doc_id", validation.VNull()))
	}
	if err := validation.WriteJson(filepath.Join(c.MemoryDir, memoryID+".json"),
		row, ""); err != nil {
		t.Fatalf("write row: %v", err)
	}
	return row
}

// test_strip_removes_field_and_logs_event
func TestStripRemovesFieldAndLogsEvent(t *testing.T) {
	root := t.TempDir()
	a, err := state.Init(root, "strip-a", state.InitOpts{})
	if err != nil {
		t.Fatalf("init a: %v", err)
	}
	b, err := state.Init(root, "strip-b", state.InitOpts{})
	if err != nil {
		t.Fatalf("init b: %v", err)
	}
	stripRow(t, a, "MEM-legacy0001", true, "CONFIRMED")
	stripRow(t, a, "MEM-legacy0002", true, "CONFIRMED")
	cleanPath := filepath.Join(a.MemoryDir, "MEM-clean00001.json")
	stripRow(t, a, "MEM-clean00001", false, "CONFIRMED")
	cleanBefore, err := os.ReadFile(cleanPath)
	if err != nil {
		t.Fatalf("read clean: %v", err)
	}
	stripRow(t, b, "MEM-legacy0003", false, "CONFIRMED")

	out, err := StripCampaignMemoryField(root, "rag_doc_id", "operator",
		"final-review I-1: schema retirement stranded campaign rows")
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if got := validation.ObjAt(out, "total_stripped"); got.I != 2 {
		t.Fatalf("total_stripped = %v", got)
	}
	camps := validation.ObjAt(out, "campaigns").A
	if len(camps) != 1 || validation.ObjStr(camps[0], "campaign_id") != a.CampaignID {
		t.Fatalf("campaigns = %v", camps)
	}
	if got := validation.ObjAt(camps[0], "rows_stripped"); got.I != 2 {
		t.Fatalf("rows_stripped = %v", got)
	}
	for _, mid := range []string{"MEM-legacy0001", "MEM-legacy0002"} {
		row, err := validation.ReadJson(filepath.Join(a.MemoryDir, mid+".json"))
		if err != nil {
			t.Fatalf("read %s: %v", mid, err)
		}
		if _, ok := fieldAt(row, "rag_doc_id"); ok {
			t.Fatalf("%s still carries rag_doc_id", mid)
		}
		if err := validation.Validate(row, "memory", 1); err != nil {
			t.Fatalf("%s does not validate: %v", mid, err)
		}
	}
	cleanAfter, err := os.ReadFile(cleanPath)
	if err != nil {
		t.Fatalf("read clean after: %v", err)
	}
	if string(cleanAfter) != string(cleanBefore) {
		t.Fatal("clean row was rewritten")
	}
	stripsA := eventsOf(t, a, "memory.field-stripped")
	if len(stripsA) != 1 {
		t.Fatalf("strip events on A = %d", len(stripsA))
	}
	want := validation.VObj(
		kv("actor", validation.VStr("operator")),
		kv("field", validation.VStr("rag_doc_id")),
		kv("reason", validation.VStr("final-review I-1: schema retirement "+
			"stranded campaign rows")),
		kv("rows_stripped", validation.VInt(2)))
	if got := validation.CanonCompact(validation.ObjAt(stripsA[0], "data")); got !=
		validation.CanonCompact(want) {
		t.Fatalf("strip data = %s", got)
	}
	if validation.ObjStr(stripsA[0], "prev_hash") == "" || validation.ObjStr(stripsA[0], "event_hash") == "" {
		t.Fatal("strip event is not hash-chained")
	}
	if got := eventsOf(t, b, "memory.field-stripped"); len(got) != 0 {
		t.Fatalf("strip events on B = %d", len(got))
	}
}

// test_strip_idempotent_no_duplicate_log
func TestStripIdempotentNoDuplicateLog(t *testing.T) {
	root := t.TempDir()
	a, err := state.Init(root, "strip-idem", state.InitOpts{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	stripRow(t, a, "MEM-legacy0001", true, "CONFIRMED")
	first, err := StripCampaignMemoryField(root, "rag_doc_id", "operator", "r1")
	if err != nil {
		t.Fatalf("first strip: %v", err)
	}
	if got := validation.ObjAt(first, "total_stripped"); got.I != 1 {
		t.Fatalf("first total = %v", got)
	}
	second, err := StripCampaignMemoryField(root, "rag_doc_id", "operator", "r1")
	if err != nil {
		t.Fatalf("second strip: %v", err)
	}
	if got := validation.ObjAt(second, "total_stripped"); got.I != 0 {
		t.Fatalf("second total = %v", got)
	}
	if got := validation.ObjAt(second, "campaigns"); len(got.A) != 0 {
		t.Fatalf("second campaigns = %v", got)
	}
	if got := eventsOf(t, a, "memory.field-stripped"); len(got) != 1 {
		t.Fatalf("strip events = %d", len(got))
	}
}

// test_campaign_typed_root_and_stripped_rows_approve
func TestCampaignTypedRootAndStrippedRowsApprove(t *testing.T) {
	root := t.TempDir()
	a, err := state.Init(root, "strip-approve", state.InitOpts{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	stripRow(t, a, "MEM-legacy0001", true, "CONFIRMED")
	row, err := validation.ReadJson(filepath.Join(a.MemoryDir, "MEM-legacy0001.json"))
	if err != nil {
		t.Fatalf("read legacy: %v", err)
	}
	if err := validation.Validate(row, "memory", 1); err == nil {
		t.Fatal("legacy row passed strict validation")
	}
	out, err := StripCampaignMemoryField(a.Root, "rag_doc_id", "operator", "r2")
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if got := validation.ObjAt(out, "total_stripped"); got.I != 1 {
		t.Fatalf("total_stripped = %v", got)
	}
	row2, err := validation.ReadJson(filepath.Join(a.MemoryDir, "MEM-legacy0001.json"))
	if err != nil {
		t.Fatalf("read stripped: %v", err)
	}
	if err := validation.Validate(row2, "memory", 1); err != nil {
		t.Fatalf("stripped row does not validate: %v", err)
	}
}

// ---- test_promotion.py ----------------------------------------------------

// test_promotion_commands_require_approval
func TestPromotionCommandsRequireApproval(t *testing.T) {
	c := newCampaign(t, "test-program")
	mem := mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "some confirmed pattern here"})
	_, err := PromotionCommands(c, validation.ObjStr(mem, "memory_id"), "")
	if err == nil || !strings.Contains(err.Error(), "human approval") {
		t.Fatalf("error = %v", err)
	}
}

// test_promotion_commands_single_substrate
func TestPromotionCommandsSingleSubstrate(t *testing.T) {
	c := newCampaign(t, "test-program")
	mem := mustQueue(t, c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern: "donation attack blocked by virtual share offset"})
	if _, err := ApproveMemory(c, validation.ObjStr(mem, "memory_id"), "operator-xand"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	cmds, err := PromotionCommands(c, validation.ObjStr(mem, "memory_id"), "operator-xand")
	if err != nil {
		t.Fatalf("commands: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("commands = %d", len(cmds))
	}
	if got, want := validation.ObjStr(cmds[0], "command"),
		"webv2 publish "+c.CampaignID+" --actor operator-xand"; got != want {
		t.Fatalf("command = %q want %q", got, want)
	}
}

// test_permission_error_on_unapproved_is_not_a_command
func TestPermissionErrorOnUnapprovedIsNotACommand(t *testing.T) {
	c := newCampaign(t, "test-program")
	mem := mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "pattern awaiting approval"})
	cmds, err := PromotionCommands(c, validation.ObjStr(mem, "memory_id"), "")
	if err == nil {
		t.Fatalf("emitted %d commands for an unapproved row", len(cmds))
	}
	if cmds != nil {
		t.Fatalf("partial command list: %v", cmds)
	}
}

// ---- test_partition_guards.py (the approve half) --------------------------

// queuePartitioned is test_partition_guards.queue_partitioned.
func queuePartitioned(t *testing.T, c *state.Campaign,
	partition string) validation.Value {
	t.Helper()
	mem := mustQueue(t, c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern:  "a prior observation partitioned " + partition,
		BugClass: strPtr("reentrancy")})
	if partition != "dev" {
		mem.O = validation.SetOrAppend(mem.O, "partition", validation.VStr(partition))
		path := filepath.Join(c.MemoryDir, validation.ObjStr(mem, "memory_id")+".json")
		if err := validation.WriteJson(path, mem, "memory"); err != nil {
			t.Fatalf("stamp partition: %v", err)
		}
	}
	return mem
}

// test_approve_memory_rejects_non_dev_rows
func TestApproveMemoryRejectsNonDevRows(t *testing.T) {
	c := newCampaign(t, "test-program")
	for _, partition := range []string{"held-out", "training"} {
		mem := queuePartitioned(t, c, partition)
		_, err := ApproveMemory(c, validation.ObjStr(mem, "memory_id"), "operator")
		if err == nil || !strings.Contains(err.Error(), partition) {
			t.Fatalf("partition %s: error = %v", partition, err)
		}
		stored, err := validation.ReadJson(filepath.Join(c.MemoryDir,
			validation.ObjStr(mem, "memory_id")+".json"))
		if err != nil {
			t.Fatalf("read stored: %v", err)
		}
		if got := validation.ObjStr(stored, "promotion_status"); got != "pending" {
			t.Fatalf("promotion_status moved to %q", got)
		}
	}
}

// test_approve_memory_allows_dev_row
func TestApproveMemoryAllowsDevRow(t *testing.T) {
	c := newCampaign(t, "test-program")
	mem := queuePartitioned(t, c, "dev")
	out, err := ApproveMemory(c, validation.ObjStr(mem, "memory_id"), "operator")
	if err != nil {
		t.Fatalf("approve dev row: %v", err)
	}
	if got := validation.ObjStr(out, "promotion_status"); got != "human-approved" {
		t.Fatalf("promotion_status = %q", got)
	}
	if got := validation.ObjStr(out, "approved_by"); got != "operator" {
		t.Fatalf("approved_by = %q", got)
	}
}

// ---- test_recall_relevance.py (the queue-time capability labels) ----------

// test_campaign_derived_memory_row_carries_capability_labels
func TestCampaignDerivedMemoryRowCarriesCapabilityLabels(t *testing.T) {
	c := newCampaign(t, "test-program")
	src := mintFinding(t, c, "logic-error",
		[]string{"Control-Perceived_Asset Price"}, []string{"role owner"},
		"capability source finding")
	mem := mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern:   "unvalidated share-price read against a live pool",
		FindingID: strPtr(validation.ObjStr(src, "finding_id"))})
	if got := strList(validation.ObjAt(mem, "granted")); !equalStrings(got,
		[]string{"control_perceived_asset_price"}) {
		t.Fatalf("granted = %v", got)
	}
	if got := strList(validation.ObjAt(mem, "required")); !equalStrings(got,
		[]string{"role_owner"}) {
		t.Fatalf("required = %v", got)
	}
	if err := validation.Validate(mem, "memory", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// test_memory_row_without_capability_labels_keeps_validating
func TestMemoryRowWithoutCapabilityLabelsKeepsValidating(t *testing.T) {
	c := newCampaign(t, "test-program")
	mem := mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "row with no capability labels at all"})
	if _, ok := fieldAt(mem, "granted"); ok {
		t.Fatal("granted stamped on a row with no source finding")
	}
	if _, ok := fieldAt(mem, "required"); ok {
		t.Fatal("required stamped on a row with no source finding")
	}
	if err := validation.Validate(mem, "memory", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestQueueMemoryShapeAndEvent pins the queued row's full field order, the
// rejection-class derivation and the memory.queued event (queue_memory's
// contract; the Python tests assert the pieces across files).
func TestQueueMemoryShapeAndEvent(t *testing.T) {
	c := newCampaign(t, "test-program")
	mem := mustQueue(t, c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern: "donation attack blocked by virtual share offset"})
	want := []string{"memory_id", "campaign_id", "finding_id", "snapshot_id",
		"created_at", "kind", "status", "pattern", "bug_class", "cwe",
		"evidence_summary", "schema_version", "rejection_class",
		"promotion_status", "approved_by", "approved_at"}
	got := make([]string, 0, len(mem.O))
	for _, kv := range mem.O {
		got = append(got, kv.K)
	}
	if !equalStrings(got, want) {
		t.Fatalf("field order = %v", got)
	}
	if v := validation.ObjStr(mem, "rejection_class"); v != "invalid-hypothesis" {
		t.Fatalf("rejection_class = %q", v)
	}
	evts := eventsOf(t, c, "memory.queued")
	if len(evts) != 1 {
		t.Fatalf("memory.queued events = %d", len(evts))
	}
	if got := validation.ObjStr(evts[0], "ref"); got != validation.ObjStr(mem, "memory_id") {
		t.Fatalf("event ref = %q", got)
	}
}

// TestQueueMemoryRejectsInvalidVocabulary pins the three argument refusals.
func TestQueueMemoryRejectsInvalidVocabulary(t *testing.T) {
	c := newCampaign(t, "test-program")
	if _, err := QueueMemory(c, QueueOpts{Kind: "disproved", Status: "MAYBE",
		Pattern: "a pattern long enough to validate"}); err == nil ||
		!strings.Contains(err.Error(), "invalid memory status") {
		t.Fatalf("status error = %v", err)
	}
	if _, err := QueueMemory(c, QueueOpts{Kind: "guess", Status: "DISPROVED",
		Pattern: "a pattern long enough to validate"}); err == nil ||
		!strings.Contains(err.Error(), "invalid memory kind") {
		t.Fatalf("kind error = %v", err)
	}
	rc := "wishful"
	if _, err := QueueMemory(c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern:        "a pattern long enough to validate",
		RejectionClass: &rc}); err == nil ||
		!strings.Contains(err.Error(), "invalid rejection_class") {
		t.Fatalf("rejection_class error = %v", err)
	}
}

// TestPlannerHintAndLoad is planner_hint / load_planner_hints (the cmd_hint
// library path this port now backs).
func TestPlannerHintAndLoad(t *testing.T) {
	c := newCampaign(t, "test-program")
	row, err := PlannerHint(c, HintOpts{Kind: "priority",
		Content: "prioritise the share-inflation lineage next pass",
		Actor:   "operator"})
	if err != nil {
		t.Fatalf("planner hint: %v", err)
	}
	if got := validation.ObjStr(row, "actor"); got != "operator" {
		t.Fatalf("actor = %q", got)
	}
	if _, err := PlannerHint(c, HintOpts{Kind: "priority",
		Content: "short"}); err == nil {
		t.Fatal("short hint accepted")
	}
	kind := "priority"
	rows, err := LoadPlannerHints(c, &kind)
	if err != nil {
		t.Fatalf("load hints: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("hints = %d", len(rows))
	}
	other := "note"
	rows, err = LoadPlannerHints(c, &other)
	if err != nil {
		t.Fatalf("load hints: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("filtered hints = %d", len(rows))
	}
}

// TestReflectionAndBenchmark append to the two JSONL logs.
func TestReflectionAndBenchmark(t *testing.T) {
	c := newCampaign(t, "test-program")
	entry, err := ReflectionEntry(c, ReflectionOpts{Round: 1,
		FalseAssumptions: []string{"assumed the pool was empty"},
		WhatWorked:       []string{"fork repro"}})
	if err != nil {
		t.Fatalf("reflection: %v", err)
	}
	if got := validation.ObjAt(entry, "round"); got.I != 1 {
		t.Fatalf("round = %v", got)
	}
	raw, err := os.ReadFile(filepath.Join(c.Dir, "learnings.jsonl"))
	if err != nil {
		t.Fatalf("read learnings: %v", err)
	}
	if !strings.HasSuffix(string(raw), "\n") || strings.Count(string(raw), "\n") != 1 {
		t.Fatalf("learnings.jsonl = %q", raw)
	}
	bench, err := BenchmarkCase(c, BenchmarkOpts{Name: "dust",
		Repo: "acme/vault", Expected: "CONFIRMED"})
	if err != nil {
		t.Fatalf("benchmark: %v", err)
	}
	if !strings.HasPrefix(validation.ObjStr(bench, "case_id"), "BENCH-") {
		t.Fatalf("case_id = %q", validation.ObjStr(bench, "case_id"))
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "benchmarks.jsonl")); err != nil {
		t.Fatalf("benchmarks.jsonl: %v", err)
	}
}

// TestPendingMemoryListsOnlyPending rows.
func TestPendingMemoryListsOnlyPending(t *testing.T) {
	c := newCampaign(t, "test-program")
	pending := mustQueue(t, c, QueueOpts{Kind: "disproved", Status: "DISPROVED",
		Pattern: "pending row pattern text"})
	approved := mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "approved row pattern text"})
	if _, err := ApproveMemory(c, validation.ObjStr(approved, "memory_id"), "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	rows, err := PendingMemory(c)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("pending rows = %d", len(rows))
	}
	if got := validation.ObjStr(rows[0], "memory_id"); got != validation.ObjStr(pending, "memory_id") {
		t.Fatalf("pending row = %q", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMemoryIDCannotEscapeTheMemoryDir: the memory id comes from argv and is
// joined into a path, so an id with a separator or ".." must be refused before
// any stat/read — with the same not-found error the missing-row path returns
// (the CLI's wording for garbage ids is unchanged).
func TestMemoryIDCannotEscapeTheMemoryDir(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	outside := filepath.Join(filepath.Dir(c.MemoryDir), "MEM-escapee.json")
	if err := validation.WriteJson(outside, validation.VObj(
		kv("memory_id", validation.VStr("MEM-escapee")),
		kv("promotion_status", validation.VStr("candidate")),
	), ""); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../MEM-escapee", "../../etc/passwd",
		"MEM-../MEM-escapee", "/etc/passwd"} {
		if _, err := ApproveMemory(c, id, "operator"); err == nil {
			t.Errorf("approve accepted id %q", id)
		} else if !strings.Contains(err.Error(), id) {
			t.Errorf("id %q: error = %q, want the id (the not-found shape)",
				id, err.Error())
		}
		if _, err := RejectMemory(c, id, "no", "false-positive"); err == nil {
			t.Errorf("reject accepted id %q", id)
		}
	}
}
