package forge

// Port of tests/test_datasets.py's FORGE-Curated half: shape + pinned mapping,
// the severity/outcome/prior table, CWE label extraction, the Cause-section
// root cause, commit/repo rules, ingest_record shapes, plus the gated
// integration pass over the real clone. The fixture is the Python
// `_sample_report` written to a tmp_path `findings/` dir exactly as the Python
// tests build theirs.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"websec/internal/ingest"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func obj(kvs ...validation.KV) validation.Value { return validation.VObj(kvs...) }

func arr(items ...validation.Value) validation.Value { return validation.VArr(items...) }

func text(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return ""
}

func ptrText(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// sampleReport is the Python `_sample_report`.
func sampleReport() validation.Value {
	return obj(
		kv("path", validation.VStr(
			"dataset-curated/reports/TrailofBits/sample-vault.pdf")),
		kv("project_info", obj(
			kv("url", arr(validation.VStr("https://github.com/demo/vault"))),
			kv("commit_id", arr(validation.VStr(
				"a24ebf0141e9350a42639d8593c1436241deae59"))),
			kv("address", arr()),
			kv("chain", validation.VStr("ethereum")),
			kv("compiler_version", validation.VStr("n/a")),
			kv("audit_date", validation.VStr("2024-08-05")),
			kv("project_path", obj(
				kv("vault", validation.VStr(
					"dataset-curated/contracts/sample-vault-source")))))),
		kv("findings", arr(
			obj(
				kv("id", validation.VInt(0)),
				kv("category", obj(
					kv("1", arr(validation.VStr("CWE-284"))),
					kv("2", arr(validation.VStr("CWE-285"))))),
				kv("title", validation.VStr(
					"Missing approval reset lets anyone drain the Vault")),
				kv("description", validation.VStr(
					"The _wrap function grants the wrapper an ERC20 approval "+
						"and never resets it, so a malicious wrapper keeps the "+
						"allowance after the deposit settles and drains the "+
						"Vault later.\n"+
						"Cause: The approval is not reset to zero after the "+
						"deposit call, leaving a standing allowance for an "+
						"untrusted contract.\n"+
						"Exploitation: Deploy a wrapper that preserves the "+
						"approval, then transfer the Vault balance out.\n"+
						"Impact: Full drainage of the underlying tokens.\n")),
				kv("severity", validation.VStr("High")),
				kv("location", arr(
					validation.VStr("Vault.sol::deposit#1169-1172"),
					validation.VStr("Vault.sol::erc4626BufferWrapOrUnwrap"),
					validation.VStr("https://github.com/demo/vault/pull/855"),
					validation.VStr("some prose without an anchor"))),
				kv("files", arr(validation.VStr(
					"a24ebf0141e9350a42639d8593c1436241deae59/demo/"+
						"vault/src/Vault.sol")))),
			obj(
				kv("id", validation.VInt(1)),
				kv("category", obj(
					kv("2", arr(validation.VStr("CWE-682"))),
					kv("3", arr(validation.VStr("CWE-190"))))),
				kv("title", validation.VStr(
					"Unbalanced liquidity mints excess shares")),
				kv("description", validation.VStr(
					"Providing unbalanced liquidity to the buffer mints more "+
						"shares than the depositor is owed because the quote "+
						"rounds in the depositor's favour on every path. The "+
						"extra shares dilute every other holder over time.")),
				kv("severity", validation.VStr("Medium")),
				kv("location", arr(validation.VStr("Buffer.sol::quote#12-22"))),
				kv("files", arr())),
			obj(
				kv("id", validation.VInt(2)),
				kv("category", obj()),
				kv("title", validation.VStr(
					"Missing docstrings across the buffer interface")),
				kv("description", validation.VStr(
					"Several public and external functions on the buffer "+
						"lack NatSpec documentation, which slows integrators "+
						"and risks misuse of the quoting functions.")),
				kv("severity", validation.VStr("Low")),
				kv("location", arr()),
				kv("files", arr())),
			obj(
				kv("id", validation.VInt(3)),
				kv("category", obj(
					kv("1", arr(validation.VStr("CWE-710"))))),
				kv("title", validation.VStr(
					"Quote functions should not be payable")),
				kv("description", validation.VStr(
					"The quote entry points are marked payable even though "+
						"the fallback reverts on non-zero value, which "+
						"confuses integrators about whether ether is "+
						"accepted.")),
				kv("severity", validation.VStr("Informational")),
				kv("location", arr(validation.VStr("Buffer.sol::quote"))),
				kv("files", arr())))),
	)
}

// loadSample is `_forge_load_sample`.
func loadSample(t *testing.T) []validation.Value {
	t.Helper()
	src := filepath.Join(t.TempDir(), "dataset-curated")
	if err := os.MkdirAll(filepath.Join(src, "findings"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(src, "findings", "sample-vault.json")
	if err := validation.WriteJson(path, sampleReport(), ""); err != nil {
		t.Fatal(err)
	}
	recs, err := LoadRecords(&src)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	return recs
}

func useRepoMaps(t *testing.T) validation.Value {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	taxonomy.SetConfigDir(filepath.Join(root, "internal", "taxonomy", "testdata"))
	maps, err := taxonomy.LoadMaps([]string{"forge"})
	if err != nil {
		t.Fatalf("LoadMaps: %v", err)
	}
	return maps
}

func TestForgeRecordShapeAndPinnedMapping(t *testing.T) {
	recs := loadSample(t)
	if len(recs) != 4 {
		t.Fatalf("record count = %d want 4", len(recs))
	}
	first := recs[0]
	if got := text(at(first, "id")); got != "sample-vault-0" {
		t.Fatalf("id = %q", got)
	}
	if got := text(at(first, "dataset")); got != "forge-curated" {
		t.Fatalf("dataset = %q", got)
	}
	if at(first, "url").Kind != validation.Null {
		t.Fatal("url must be None")
	}
	wantProgram := validation.CanonSpaced(obj(
		kv("program", validation.VStr("sample-vault")),
		kv("platform", validation.VNull()),
		kv("chains", arr(validation.VStr("ethereum")))))
	if got := validation.CanonSpaced(at(first, "program")); got != wantProgram {
		t.Fatalf("program = %s want %s", got, wantProgram)
	}
	if got := text(at(first, "bug_class_label")); got != "CWE-284" {
		t.Fatalf("bug_class_label = %q", got)
	}
	if got := text(at(first, "outcome")); got != "confirmed-exploitable" {
		t.Fatalf("outcome = %q", got)
	}
	if got := text(at(first, "severity")); got != "high" {
		t.Fatalf("severity = %q", got)
	}
	if at(first, "negative").B || !at(first, "prior").B {
		t.Fatal("negative must be False and prior True")
	}
	if text(at(first, "pattern")) != text(at(first, "title")) {
		t.Fatalf("pattern = %q must equal title", text(at(first, "pattern")))
	}
	if at(first, "exploit").Kind != validation.Null {
		t.Fatal("exploit must be None")
	}
	if got := text(at(first, "partition")); got != "dev" {
		t.Fatalf("partition = %q", got)
	}
	if got := text(at(at(first, "code"), "repo")); got != "https://github.com/demo/vault" {
		t.Fatalf("code.repo = %q", got)
	}
	if got := text(at(at(first, "code"), "commit")); got !=
		"a24ebf0141e9350a42639d8593c1436241deae59" {
		t.Fatalf("code.commit = %q", got)
	}
	if got := text(at(at(first, "code"), "files").A[0]); got != "src/Vault.sol" {
		t.Fatalf("code.files = %q", got)
	}
	wantLoc := validation.CanonSpaced(arr(
		obj(kv("file", validation.VStr("Vault.sol")),
			kv("line", validation.VInt(1169))),
		obj(kv("file", validation.VStr("Vault.sol"))),
		obj(kv("file", validation.VStr("src/Vault.sol")))))
	if got := validation.CanonSpaced(at(first, "locations")); got != wantLoc {
		t.Fatalf("locations = %s want %s", got, wantLoc)
	}
}

func TestForgeOutcomeSeverityPriorTable(t *testing.T) {
	recs := loadSample(t)
	var got []string
	for _, r := range recs {
		got = append(got, text(at(r, "severity"))+"|"+
			text(at(r, "outcome"))+"|"+boolStr(at(r, "prior").B))
	}
	want := "high|confirmed-exploitable|true," +
		"medium|confirmed-exploitable|true," +
		"low|confirmed-not-exploitable|false," +
		"informational|out-of-scope|false"
	if strings.Join(got, ",") != want {
		t.Fatalf("table = %v want %s", got, want)
	}
	var hasPattern []string
	for _, r := range recs {
		hasPattern = append(hasPattern, boolStr(at(r, "pattern").Kind != validation.Null))
	}
	if strings.Join(hasPattern, ",") != "true,true,false,false" {
		t.Fatalf("pattern presence = %v", hasPattern)
	}
	// Bands not covered by the 4-finding sample, pinned the same way:
	if s, err := MapSeverity(ptr("Critical")); err != nil || ptrText(s) != "high" {
		t.Fatalf("MapSeverity(Critical) = %v %v", s, err)
	}
	if o, err := MapOutcome(ptr("Critical")); err != nil || o != "confirmed-exploitable" {
		t.Fatalf("MapOutcome(Critical) = %q %v", o, err)
	}
	if s, err := MapSeverity(nil); err != nil || s != nil {
		t.Fatalf("MapSeverity(None) = %v %v", s, err)
	}
	if o, err := MapOutcome(nil); err != nil || o != "out-of-scope" {
		t.Fatalf("MapOutcome(None) = %q %v", o, err)
	}
}

func TestForgeUnknownSeverityRejected(t *testing.T) {
	_, err := MapSeverity(ptr("N/A"))
	if err == nil || !strings.Contains(err.Error(), "unknown severity") {
		t.Fatalf("err = %v want unknown severity", err)
	}
}

func TestForgeCWELabelExtraction(t *testing.T) {
	got := ExtractLabel(obj(kv("1", arr(validation.VStr("CWE-284"))),
		kv("2", arr(validation.VStr("CWE-285")))))
	if ptrText(got) != "CWE-284" {
		t.Fatalf("label = %v", ptrText(got))
	}
	got = ExtractLabel(obj(kv("2", arr(validation.VStr("CWE-682"))),
		kv("3", arr(validation.VStr("CWE-190")))))
	if ptrText(got) != "CWE-190" {
		t.Fatalf("label = %v", ptrText(got))
	}
	if got := ExtractLabel(obj()); got != nil {
		t.Fatalf("empty category = %v want None", ptrText(got))
	}
	if got := ExtractLabel(validation.VNull()); got != nil {
		t.Fatalf("None category = %v want None", ptrText(got))
	}
}

func TestForgeRootCauseCauseSection(t *testing.T) {
	recs := loadSample(t)
	if got := text(at(recs[0], "root_cause")); got !=
		"The approval is not reset to zero after the deposit call, "+
			"leaving a standing allowance for an untrusted contract." {
		t.Fatalf("rec0 root_cause = %q", got)
	}
	if got := text(at(recs[1], "root_cause")); got !=
		"Providing unbalanced liquidity to the buffer mints more shares "+
			"than the depositor is owed because the quote rounds in the "+
			"depositor's favour on every path. The extra shares dilute every "+
			"other holder over time." {
		t.Fatalf("rec1 root_cause = %q", got)
	}
	for _, rec := range recs {
		if n := len([]rune(text(at(rec, "root_cause")))); n < 10 || n > 2000 {
			t.Fatalf("%s root_cause len = %d", text(at(rec, "id")), n)
		}
	}
}

func TestForgeCommitAndRepoRules(t *testing.T) {
	if got := CleanCommit(validation.VStr(
		"0x7032978ef1fc44271145bb593be45be1c7a0b6c5")); ptrText(got) !=
		"7032978ef1fc44271145bb593be45be1c7a0b6c5" {
		t.Fatalf("0x-stripped commit = %v", ptrText(got))
	}
	for _, bad := range []validation.Value{
		validation.VStr("8e6a02b...00e2a89"), validation.VStr("n/a"),
		validation.VStr("null"), validation.VStr("Version 1"),
		validation.VStr(""), validation.VNull()} {
		if got := CleanCommit(bad); got != nil {
			t.Fatalf("CleanCommit(%s) = %v want None",
				validation.PyRepr(bad), ptrText(got))
		}
	}
	if got := CleanCommit(arr(validation.VStr("n/a"),
		validation.VStr(strings.Repeat("b", 40)))); ptrText(got) != strings.Repeat("b", 40) {
		t.Fatalf("list commit = %v", ptrText(got))
	}
	if got := CleanCommit(arr(validation.VNull())); got != nil {
		t.Fatalf("CleanCommit([None]) = %v want None", ptrText(got))
	}
	// No URL anywhere -> explicit placeholder (ingest_record needs repo).
	code := BuildCode(obj(kv("url", validation.VNull()),
		kv("commit_id", validation.VNull())), nil, "slug", false)
	if got := text(at(code, "repo")); got != "unknown/slug" {
		t.Fatalf("placeholder repo = %q", got)
	}
	if at(code, "commit").Kind != validation.Null {
		t.Fatal("placeholder code must carry no commit")
	}
	// Without-source reports earn a snapshot note.
	code = BuildCode(obj(
		kv("url", arr(validation.VStr("https://github.com/demo/vault"))),
		kv("commit_id", arr(validation.VStr(strings.Repeat("a", 40))))),
		nil, "slug", true)
	if got := text(at(code, "repo")); got != "https://github.com/demo/vault" {
		t.Fatalf("repo = %q", got)
	}
	if at(code, "snapshot_note").Kind != validation.Str {
		t.Fatal("without-source report must earn a snapshot_note")
	}
}

func TestForgeIngestRecordPureShapes(t *testing.T) {
	maps := useRepoMaps(t)
	recs := loadSample(t)
	results := make([]ingest.Result, 0, len(recs))
	for _, rec := range recs {
		res, err := ingest.IngestRecord(rec, &maps)
		if err != nil {
			t.Fatalf("%s: %v", text(at(rec, "id")), err)
		}
		results = append(results, res)
	}
	var classes []string
	for _, res := range results {
		classes = append(classes, text(at(at(res.EvalCase, "gold"), "bug_class")))
	}
	want := "access-control,precision-rounding,unmapped,unmapped"
	if strings.Join(classes, ",") != want {
		t.Fatalf("bug classes = %v want %s", classes, want)
	}
	for i, res := range results {
		cse := res.EvalCase
		if got := text(at(cse, "partition")); got != "dev" {
			t.Fatalf("rec%d partition = %q", i, got)
		}
		wantSource := validation.CanonSpaced(obj(
			kv("dataset", validation.VStr("forge-curated")),
			kv("record_id", validation.VStr(text(at(recs[i], "id"))))))
		if got := validation.CanonSpaced(at(cse, "source")); got != wantSource {
			t.Fatalf("rec%d source = %s want %s", i, got, wantSource)
		}
		if n := len([]rune(text(at(at(cse, "gold"), "root_cause")))); n < 10 || n > 2000 {
			t.Fatalf("rec%d gold.root_cause len = %d", i, n)
		}
	}
	// Positive priors survive only when the class is mapped (the core drops
	// classless priors); non-priors never emit rows.
	if len(results[0].MemoryRows) != 1 {
		t.Fatalf("rec0 memory_rows = %d want 1", len(results[0].MemoryRows))
	}
	if got := text(at(results[0].MemoryRows[0], "status")); got != "CONFIRMED" {
		t.Fatalf("rec0 row status = %q", got)
	}
	if len(results[1].MemoryRows) != 1 {
		t.Fatalf("rec1 memory_rows = %d want 1", len(results[1].MemoryRows))
	}
	if len(results[2].MemoryRows) != 0 || len(results[3].MemoryRows) != 0 {
		t.Fatalf("non-priors must emit no rows: %d %d",
			len(results[2].MemoryRows), len(results[3].MemoryRows))
	}
}

func TestForgeIntegration3590RecordsShapesAndHistogram(t *testing.T) {
	requireClone(t)
	recs, err := LoadRecords(nil)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 3590 {
		t.Fatalf("record count = %d want 3590", len(recs))
	}
	priors := 0
	hist := map[string]int{}
	for _, rec := range recs {
		if at(rec, "negative").B {
			t.Fatalf("%s negative must be False", text(at(rec, "id")))
		}
		if at(rec, "prior").B {
			priors++
			sev := text(at(rec, "severity"))
			if sev != "high" && sev != "medium" {
				t.Fatalf("%s prior severity = %q", text(at(rec, "id")), sev)
			}
		}
		key := text(at(rec, "severity"))
		if at(rec, "severity").Kind == validation.Null {
			key = "None"
		}
		hist[key]++
	}
	if priors != 1086 {
		t.Fatalf("priors = %d want 1086", priors)
	}
	want := map[string]int{"high": 459, "medium": 627, "low": 1078,
		"informational": 1278, "None": 148}
	if len(hist) != len(want) {
		t.Fatalf("histogram buckets = %v want %v", hist, want)
	}
	for k, v := range want {
		if hist[k] != v {
			t.Fatalf("hist[%s] = %d want %d", k, hist[k], v)
		}
	}
	for _, rec := range recs {
		id := text(at(rec, "id"))
		if got := text(at(rec, "dataset")); got != "forge-curated" {
			t.Fatalf("%s dataset = %q", id, got)
		}
		if got := text(at(rec, "partition")); got != "dev" {
			t.Fatalf("%s partition = %q", id, got)
		}
		if n := len([]rune(text(at(rec, "title")))); n < 5 || n > 500 {
			t.Fatalf("%s title len = %d", id, n)
		}
		if n := len([]rune(text(at(rec, "description")))); n < 20 || n > 10000 {
			t.Fatalf("%s description len = %d", id, n)
		}
		if n := len([]rune(text(at(rec, "root_cause")))); n < 10 || n > 2000 {
			t.Fatalf("%s root_cause len = %d", id, n)
		}
		if text(at(at(rec, "code"), "repo")) == "" {
			t.Fatalf("%s code.repo empty", id)
		}
		if c := at(at(rec, "code"), "commit"); c.Kind == validation.Str {
			if ptrText(CleanCommit(c)) != c.S {
				t.Fatalf("%s commit %q is not schema-safe", id, c.S)
			}
		}
	}
}

func TestForgeIntegrationIngestRecordShapes(t *testing.T) {
	requireClone(t)
	maps := useRepoMaps(t)
	recs, err := LoadRecords(nil)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	rows := 0
	for _, rec := range recs {
		res, err := ingest.IngestRecord(rec, &maps)
		if err != nil {
			t.Fatalf("%s: %v", text(at(rec, "id")), err)
		}
		cse := res.EvalCase
		if got := text(at(cse, "partition")); got != "dev" {
			t.Fatalf("%s partition = %q", text(at(rec, "id")), got)
		}
		if got := text(at(at(cse, "source"), "dataset")); got != "forge-curated" {
			t.Fatalf("%s source.dataset = %q", text(at(rec, "id")), got)
		}
		if res.CampaignSeed == nil {
			t.Fatalf("%s campaign_seed must not be None", text(at(rec, "id")))
		}
		if len(res.MemoryRows) > 0 {
			rows++
			if !at(rec, "prior").B {
				t.Fatalf("%s memory row without prior", text(at(rec, "id")))
			}
			if got := text(at(at(cse, "gold"), "bug_class")); got == "unmapped" {
				t.Fatalf("%s memory row with unmapped class", text(at(rec, "id")))
			}
		}
	}
	if rows == 0 {
		t.Fatal("mapped Medium+ priors must reach memory rows")
	}
}

// requireClone is the Python `GATED` skipif (FORGE-Curated clone absent), with
// the dataset-root override honored.
func requireClone(t *testing.T) {
	t.Helper()
	if root := os.Getenv("WEBV2_DATASETS_ROOT"); root != "" {
		SetDatasetDir(filepath.Join(root, "FORGE-Curated", "dataset-curated"))
	}
	if !dirExists(DatasetDir) {
		t.Skip("FORGE-Curated clone absent")
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func ptr(s string) *string { return &s }
