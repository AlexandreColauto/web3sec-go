package ingest

// Port of tests/test_ingest.py's ingest-core functions: the common record
// shape in, validated framework structures out. These tests pin the contract:
// deterministic case ids, the outcome->(status, rejection_class) table over
// all six outcomes, pure-function validation errors (pattern required, mutual
// exclusion, unmapped priors dropped), partition propagation, the one-record
// chained replace_program_key, and the publish_ingested orchestration.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/evalstore"
	"websec/internal/sharedmem"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func maps() validation.Value {
	return validation.VObj(
		kv("default", validation.VStr("unmapped")),
		kv("aliases", validation.VObj(
			kv("Access Control", validation.VStr("access-control")))))
}

// record is the Python `_record` fixture (overrides replace whole keys).
func record(over ...validation.KV) validation.Value {
	base := []validation.KV{
		kv("id", validation.VStr("REC-1")),
		kv("dataset", validation.VStr("scabench")),
		kv("url", validation.VStr("https://example.com/rec-1")),
		kv("program", validation.VObj(
			kv("program", validation.VStr("Acme Protocol")),
			kv("platform", validation.VStr("immunefi")),
			kv("chains", validation.VArr(validation.VStr("ethereum"))))),
		kv("title", validation.VStr("Vault allows reentrant withdraw")),
		kv("description", validation.VStr(strings.Repeat(
			"The withdraw function makes an external call before updating "+
				"balances, allowing reentry and fund drainage. ", 3))),
		kv("bug_class_label", validation.VStr("reentrancy")),
		kv("outcome", validation.VStr("disproved")),
		kv("severity", validation.VStr("high")),
		kv("root_cause", validation.VStr(
			"external call fires before the state update")),
		kv("locations", validation.VArr(validation.VObj(
			kv("file", validation.VStr("src/Vault.sol")),
			kv("line", validation.VInt(42))))),
		kv("code", validation.VObj(
			kv("repo", validation.VStr("acme/vault")),
			kv("commit", validation.VStr(strings.Repeat("a", 40))),
			kv("files", validation.VArr(validation.VStr("src/Vault.sol"))))),
		kv("negative", validation.VBool(true)),
		kv("prior", validation.VBool(false)),
		kv("pattern", validation.VStr("external call before state update is "+
			"safe when a reentrancy guard is present")),
		kv("exploit", validation.VNull()),
		kv("partition", validation.VStr("dev")),
	}
	return validation.VObj(merge(base, over)...)
}

func merge(base []validation.KV, over []validation.KV) []validation.KV {
	out := append([]validation.KV(nil), base...)
	for _, o := range over {
		replaced := false
		for i := range out {
			if out[i].K == o.K {
				out[i].V = o.V
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, o)
		}
	}
	return out
}

func setupStore(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "eval")
	evalstore.SetEvalDir(dir)
	t.Cleanup(evalstore.ResetEvalDir)
	return dir
}

func mustIngest(t *testing.T, rec validation.Value) Result {
	t.Helper()
	m := maps()
	res, err := IngestRecord(rec, &m)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// ---------------------------------------------------------------------------
// outcome table: all six outcomes

func TestIngestNegativeOutcomeTable(t *testing.T) {
	table := []struct{ outcome, status, rejection string }{
		{"disproved", "DISPROVED", "invalid-hypothesis"},
		{"confirmed-not-exploitable", "UNREACHABLE", "not-exploitable"},
		{"economic-no-go", "NON-ECONOMIC", "below-threshold"},
		{"out-of-scope", "OUT_OF_SCOPE", "invalid-hypothesis"},
		{"duplicate", "DUPLICATE", ""},
	}
	for _, tc := range table {
		t.Run(tc.outcome, func(t *testing.T) {
			res := mustIngest(t, record(kv("outcome", validation.VStr(tc.outcome))))
			caseDoc, rows := res.EvalCase, res.MemoryRows
			if got := objStr(objAt(caseDoc, "gold"), "outcome"); got != tc.outcome {
				t.Fatalf("outcome = %q", got)
			}
			if got := objStr(objAt(caseDoc, "gold"), "bug_class"); got != "reentrancy" {
				t.Fatalf("bug_class = %q", got)
			}
			if got := objStr(caseDoc, "partition"); got != "dev" {
				t.Fatalf("partition = %q", got)
			}
			if len(rows) != 1 {
				t.Fatalf("rows = %d", len(rows))
			}
			row := rows[0]
			if got := objStr(row, "status"); got != tc.status {
				t.Fatalf("status = %q", got)
			}
			if got := objAt(row, "rejection_class"); tc.rejection == "" {
				if got.Kind != validation.Null {
					t.Fatalf("rejection_class = %v", got)
				}
			} else if got.Kind != validation.Str || got.S != tc.rejection {
				t.Fatalf("rejection_class = %v", got)
			}
			if got := objAt(row, "schema_version"); got.I != 2 {
				t.Fatalf("schema_version = %v", got)
			}
			if got := objStr(row, "partition"); got != "dev" {
				t.Fatalf("row partition = %q", got)
			}
			if got := objAt(row, "deciding_propositions"); got.Kind != validation.Arr ||
				len(got.A) != 0 {
				t.Fatalf("deciding_propositions = %v", got)
			}
			if got := objStr(row, "campaign_id"); got != "ingest:scabench:REC-1" {
				t.Fatalf("campaign_id = %q", got)
			}
			if err := validation.Validate(row, "memory", 1); err != nil {
				t.Fatal(err)
			}
			if err := validation.Validate(caseDoc, "evaluation_case", 1); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIngestConfirmedExploitableNonNegativeHasNoRows(t *testing.T) {
	res := mustIngest(t, record(
		kv("outcome", validation.VStr("confirmed-exploitable")),
		kv("negative", validation.VBool(false))))
	if got := objStr(objAt(res.EvalCase, "gold"), "outcome"); got != "confirmed-exploitable" {
		t.Fatalf("outcome = %q", got)
	}
	if len(res.MemoryRows) != 0 {
		t.Fatalf("rows = %v", res.MemoryRows)
	}
	if res.CampaignSeed == nil {
		t.Fatal("campaign_seed = nil")
	}
	if got := objStr(objAt(*res.CampaignSeed, "expected"), "bug_class"); got != "reentrancy" {
		t.Fatalf("expected.bug_class = %q", got)
	}
}

func TestIngestConfirmedExploitableNegativeIsContradiction(t *testing.T) {
	m := maps()
	_, err := IngestRecord(record(
		kv("outcome", validation.VStr("confirmed-exploitable")),
		kv("negative", validation.VBool(true))), &m)
	if err == nil || !strings.Contains(err.Error(), "not a non-issue") {
		t.Fatalf("err = %v", err)
	}
}

func TestIngestTaxonomyAliasAndUnmapped(t *testing.T) {
	res := mustIngest(t, record(
		kv("bug_class_label", validation.VStr("Access Control"))))
	if res.Canonical != "access-control" || !res.Mapped {
		t.Fatalf("taxonomy = (%q,%v)", res.Canonical, res.Mapped)
	}
	if got := objStr(objAt(res.EvalCase, "gold"), "bug_class"); got != "access-control" {
		t.Fatalf("bug_class = %q", got)
	}
	res = mustIngest(t, record(
		kv("bug_class_label", validation.VStr("weird new bug xyz"))))
	if res.Canonical != "unmapped" || res.Mapped {
		t.Fatalf("taxonomy = (%q,%v)", res.Canonical, res.Mapped)
	}
	if got := objStr(objAt(res.EvalCase, "gold"), "bug_class"); got != "unmapped" {
		t.Fatalf("bug_class = %q", got)
	}
}

// ---------------------------------------------------------------------------
// identity + purity errors

func TestIngestDeterministicCaseIDAndDuplicateRejected(t *testing.T) {
	setupStore(t)
	first := mustIngest(t, record())
	second := mustIngest(t, record())
	firstID := objStr(first.EvalCase, "case_id")
	if firstID != objStr(second.EvalCase, "case_id") {
		t.Fatalf("ids differ: %q %q", firstID, objStr(second.EvalCase, "case_id"))
	}
	if !strings.HasPrefix(firstID, "CASE-") {
		t.Fatalf("case_id = %q", firstID)
	}
	if _, err := evalstore.AddCase(first.EvalCase); err != nil {
		t.Fatal(err)
	}
	_, err := evalstore.AddCase(second.EvalCase)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
}

func TestIngestNonNegativeRecordHasNoRows(t *testing.T) {
	res := mustIngest(t, record(
		kv("outcome", validation.VStr("confirmed-exploitable")),
		kv("negative", validation.VBool(false))))
	if len(res.MemoryRows) != 0 {
		t.Fatalf("rows = %v", res.MemoryRows)
	}
	if res.Canonical == "" {
		t.Fatal("canonical empty")
	}
}

func TestIngestNegativeWithoutPatternRejected(t *testing.T) {
	m := maps()
	for _, pattern := range []validation.Value{
		validation.VNull(), validation.VStr("short")} {
		_, err := IngestRecord(record(kv("pattern", pattern)), &m)
		if err == nil || !strings.Contains(err.Error(), "pattern") {
			t.Fatalf("pattern %v: err = %v", pattern, err)
		}
	}
}

func TestIngestNegativeAndPriorMutuallyExclusive(t *testing.T) {
	m := maps()
	_, err := IngestRecord(record(kv("negative", validation.VBool(true)),
		kv("prior", validation.VBool(true))), &m)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

func TestIngestPriorEmitsConfirmedRowWithPattern(t *testing.T) {
	res := mustIngest(t, record(
		kv("outcome", validation.VStr("confirmed-exploitable")),
		kv("negative", validation.VBool(false)),
		kv("prior", validation.VBool(true))))
	if len(res.MemoryRows) != 1 {
		t.Fatalf("rows = %d", len(res.MemoryRows))
	}
	row := res.MemoryRows[0]
	if got := objStr(row, "status"); got != "CONFIRMED" {
		t.Fatalf("status = %q", got)
	}
	if got := objAt(row, "rejection_class"); got.Kind != validation.Null {
		t.Fatalf("rejection_class = %v", got)
	}
	if got := objStr(row, "kind"); got != "confirmed" {
		t.Fatalf("kind = %q", got)
	}
	if got := objStr(row, "pattern"); got != "external call before state "+
		"update is safe when a reentrancy guard is present" {
		t.Fatalf("pattern = %q", got)
	}
	if err := validation.Validate(row, "memory", 1); err != nil {
		t.Fatal(err)
	}
}

func TestIngestUnmappedPriorEmitsNoRow(t *testing.T) {
	res := mustIngest(t, record(
		kv("outcome", validation.VStr("confirmed-exploitable")),
		kv("negative", validation.VBool(false)),
		kv("prior", validation.VBool(true)),
		kv("bug_class_label", validation.VStr("weird new bug xyz"))))
	if len(res.MemoryRows) != 0 {
		t.Fatalf("rows = %v", res.MemoryRows)
	}
	if got := objStr(objAt(res.EvalCase, "gold"), "bug_class"); got != "unmapped" {
		t.Fatalf("bug_class = %q", got)
	}
}

func TestIngestCampaignSeedAbsentWithoutRepo(t *testing.T) {
	rec := record(kv("code", validation.VObj(
		kv("repo", validation.VStr("  ")),
		kv("commit", validation.VNull()),
		kv("files", validation.VArr()))))
	res := mustIngest(t, rec)
	if res.CampaignSeed != nil {
		t.Fatalf("campaign_seed = %v", *res.CampaignSeed)
	}
	if res.EvalCase.Kind != validation.Obj {
		t.Fatal("eval case missing")
	}
}

// ---------------------------------------------------------------------------
// partition propagation

func TestIngestHeldOutPartitionPropagatesToCaseAndRow(t *testing.T) {
	res := mustIngest(t, record(kv("partition", validation.VStr("held-out"))))
	if got := objStr(res.EvalCase, "partition"); got != "held-out" {
		t.Fatalf("case partition = %q", got)
	}
	if len(res.MemoryRows) != 1 {
		t.Fatalf("rows = %d", len(res.MemoryRows))
	}
	if got := objStr(res.MemoryRows[0], "partition"); got != "held-out" {
		t.Fatalf("row partition = %q", got)
	}
}

// ---------------------------------------------------------------------------
// replace_program_key

func memRow(mid string) validation.Value {
	return validation.VObj(
		kv("memory_id", validation.VStr(mid)),
		kv("campaign_id", validation.VStr("ingest:scabench:REC-1")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-04T12:00:00+00:00")),
		kv("kind", validation.VStr("disproved")),
		kv("status", validation.VStr("DISPROVED")),
		kv("pattern", validation.VStr(
			"a prior observation about this program pattern here")),
		kv("bug_class", validation.VStr("reentrancy")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("evidence")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VStr("invalid-hypothesis")),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("dataset-ingestion")),
		kv("approved_at", validation.VStr("2026-09-04T12:00:00+00:00")))
}

func wrap(key, mid string) validation.Value {
	return validation.VObj(
		kv("program_key", validation.VStr(key)),
		kv("published_at", validation.VStr("2026-09-04T12:00:00+00:00")),
		kv("scope", validation.VStr("global")),
		kv("row", memRow(mid)))
}

func TestIngestReplaceProgramKey(t *testing.T) {
	root := t.TempDir()
	store := isolateGlobalStore(t)
	keyA, keyB := "Acme|immunefi|ethereum", "Beta|immunefi|ethereum"
	if err := sharedmem.WriteStore(store, nil, []validation.Value{
		wrap(keyA, "MEM-aaa111"), wrap(keyA, "MEM-aaa222"),
		wrap(keyB, "MEM-bbb111")}); err != nil {
		t.Fatal(err)
	}
	seed, err := sharedmem.ManifestAppend(store, validation.VObj(
		kv("record_id", validation.VStr("PUB-seed")),
		kv("at", validation.VStr("2026-09-04T12:00:00+00:00")),
		kv("signatures_sha256", validation.VStr(
			sharedmem.FileSha256(sharedmem.SignaturesPath(store)))),
		kv("memory_sha256", validation.VStr(
			sharedmem.FileSha256(sharedmem.MemoryPath(store))))))
	if err != nil {
		t.Fatal(err)
	}
	before := len(readManifest(t, store))

	rec, err := ReplaceProgramKey(keyA, []validation.Value{
		wrap(keyA, "MEM-new001"), wrap(keyA, "MEM-new002")}, "global")
	if err != nil {
		t.Fatal(err)
	}
	mems, err := sharedmem.TierMemory(store)
	if err != nil {
		t.Fatal(err)
	}
	gotA, gotB := []string{}, []string{}
	for _, w := range mems {
		mid := objStr(objAt(w, "row"), "memory_id")
		switch objStr(w, "program_key") {
		case keyA:
			gotA = append(gotA, mid)
		case keyB:
			gotB = append(gotB, mid)
		}
	}
	sortStrings(gotA)
	if strings.Join(gotA, ",") != "MEM-new001,MEM-new002" {
		t.Fatalf("key A rows = %v", gotA)
	}
	if strings.Join(gotB, ",") != "MEM-bbb111" {
		t.Fatalf("key B rows = %v", gotB)
	}
	if got := objStr(rec, "action"); got != "program_key.replaced" {
		t.Fatalf("action = %q", got)
	}
	if got := objAt(rec, "removed_count").I; got != 2 {
		t.Fatalf("removed_count = %d", got)
	}
	if got := objAt(rec, "added_count").I; got != 2 {
		t.Fatalf("added_count = %d", got)
	}
	if got := objStr(rec, "prev_hash"); got != objStr(seed, "record_hash") {
		t.Fatalf("prev_hash = %q want %q", got, objStr(seed, "record_hash"))
	}
	if got := len(readManifest(t, store)); got != before+1 {
		t.Fatalf("manifest len = %d want %d", got, before+1)
	}
	ver, err := sharedmem.VerifySharedStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(ver, "ok").B {
		t.Fatalf("verify = %v", ver)
	}
}

// ---------------------------------------------------------------------------
// publish_ingested

func TestIngestPublishIngested(t *testing.T) {
	setupStore(t)
	root := t.TempDir()
	store := isolateGlobalStore(t)
	dev := mustIngest(t, record())
	dev2 := mustIngest(t, record(kv("id", validation.VStr("REC-2"))))
	held := mustIngest(t, record(
		kv("id", validation.VStr("REC-9")),
		kv("outcome", validation.VStr("confirmed-exploitable")),
		kv("negative", validation.VBool(false)),
		kv("prior", validation.VBool(true)),
		kv("partition", validation.VStr("held-out"))))
	out, err := PublishIngested([]Result{dev, dev2, held}, "scabench", nil, "global")
	if err != nil {
		t.Fatal(err)
	}
	if out.CasesAdded != 3 {
		t.Fatalf("cases_added = %d", out.CasesAdded)
	}
	if out.RowsAdded != 2 {
		t.Fatalf("rows_added = %d", out.RowsAdded)
	}
	if out.ManifestRecord == nil ||
		objStr(*out.ManifestRecord, "action") != "program_key.replaced" {
		t.Fatalf("manifest_record = %v", out.ManifestRecord)
	}
	cases, err := evalstore.ListCases(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 3 {
		t.Fatalf("list_cases = %d", len(cases))
	}
	mems, err := sharedmem.TierMemory(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(mems) != 2 {
		t.Fatalf("mems = %d", len(mems))
	}
	for _, w := range mems {
		if objStr(w, "scope") != "global" {
			t.Fatalf("scope = %q", objStr(w, "scope"))
		}
		if orDev(objStr(objAt(w, "row"), "partition")) != "dev" {
			t.Fatalf("row partition leaked")
		}
	}
	ver, err := sharedmem.VerifySharedStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(ver, "ok").B {
		t.Fatalf("verify = %v", ver)
	}
}

func TestIngestPublishIngestedExplicitProgramKey(t *testing.T) {
	setupStore(t)
	root := t.TempDir()
	store := isolateGlobalStore(t)
	res := mustIngest(t, record())
	key := "Custom|-|ethereum"
	out, err := PublishIngested([]Result{res}, "scabench", &key, "global")
	if err != nil {
		t.Fatal(err)
	}
	if out.CasesAdded != 1 || out.RowsAdded != 1 {
		t.Fatalf("out = %+v", out)
	}
	mems, err := sharedmem.TierMemory(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(mems) != 1 || objStr(mems[0], "program_key") != key {
		t.Fatalf("mems = %v", mems)
	}
	ver, err := sharedmem.VerifySharedStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(ver, "ok").B {
		t.Fatalf("verify = %v", ver)
	}
}

// ---------------------------------------------------------------------------
// review fixes: snapshot_note forwarding + replace_program_key partition guard

func TestIngestSnapshotNoteForwardedToEvalCase(t *testing.T) {
	rec := record(kv("code", validation.VObj(
		kv("repo", validation.VStr("acme/vault")),
		kv("commit", validation.VStr(strings.Repeat("a", 40))),
		kv("files", validation.VArr()),
		kv("snapshot_note", validation.VStr(
			"commit not verified against source")))))
	caseDoc := mustIngest(t, rec).EvalCase
	if got := objStr(objAt(caseDoc, "code"), "snapshot_note"); got !=
		"commit not verified against source" {
		t.Fatalf("snapshot_note = %q", got)
	}
	if err := validation.Validate(caseDoc, "evaluation_case", 1); err != nil {
		t.Fatal(err)
	}
	plain := mustIngest(t, record()).EvalCase
	for _, kv := range objAt(plain, "code").O {
		if kv.K == "snapshot_note" {
			t.Fatal("snapshot_note leaked into the plain case")
		}
	}
}

func TestIngestReplaceProgramKeyRejectsNonDevRows(t *testing.T) {
	store := isolateGlobalStore(t)
	heldRow := memRow("MEM-held01")
	for i := range heldRow.O {
		if heldRow.O[i].K == "partition" {
			heldRow.O[i].V = validation.VStr("held-out")
		}
	}
	bad := validation.VObj(
		kv("program_key", validation.VStr("Acme|immunefi|ethereum")),
		kv("published_at", validation.VStr("2026-09-04T12:00:00+00:00")),
		kv("scope", validation.VStr("global")),
		kv("row", heldRow))
	_, err := ReplaceProgramKey("Acme|immunefi|ethereum",
		[]validation.Value{bad}, "global")
	if err == nil || !strings.Contains(err.Error(), "not 'dev'") {
		t.Fatalf("err = %v", err)
	}
	mems, err := sharedmem.TierMemory(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(mems) != 0 {
		t.Fatalf("store not untouched: %v", mems)
	}
	if got := len(readManifest(t, store)); got != 0 {
		t.Fatalf("manifest = %d", got)
	}
}

// ---- helpers -------------------------------------------------------------

// isolateGlobalStore points the user-global tier at a per-test dir (the
// conftest fixture's monkeypatch of global_store_dir).
func isolateGlobalStore(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shared-memory")
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", dir)
	return dir
}

func readManifest(t *testing.T, store string) []validation.Value {
	t.Helper()
	path := sharedmem.ManifestPath(store)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	data, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	return data.A
}

func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
