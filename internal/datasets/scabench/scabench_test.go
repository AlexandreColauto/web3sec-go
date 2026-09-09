package scabench

// Port of tests/test_datasets.py's ScaBench half: shape, severity, U+FFF
// stripping, length rules, commit refs, plus the skipif-gated integration pass
// over the real snapshot. The fixture is the Python `_sample` (two projects,
// three findings), written to a tmp_path JSON file exactly as the Python tests
// build theirs.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/ingest"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func obj(kvs ...validation.KV) validation.Value { return validation.VObj(kvs...) }

func arr(items ...validation.Value) validation.Value { return validation.VArr(items...) }

func setField(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, p := range v.O {
		if p.K == key {
			out = append(out, kv(key, val))
			replaced = true
			continue
		}
		out = append(out, p)
	}
	if !replaced {
		out = append(out, kv(key, val))
	}
	return validation.VObj(out...)
}

func text(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// longParas is LONG_PARAS: 5 paragraphs of "PARA-<i> " + 110 padding sentences.
func longParas() []string {
	out := make([]string, 5)
	for i := range out {
		out[i] = "PARA-" + string(rune('0'+i)) + " " +
			strings.Repeat("lorem ipsum dolor sit amet. ", 110)
	}
	return out
}

// sample is the Python `_sample`.
func sample() validation.Value {
	long := strings.Join(longParas(), "\n\n")
	return arr(
		obj(
			kv("project_id", validation.VStr("code4rena_demo_2025_01")),
			kv("name", validation.VStr("Demo Protocol")),
			kv("platform", validation.VStr("code4rena")),
			kv("codebases", arr(obj(
				kv("codebase_id", validation.VStr("Demo Protocol_aaaaaa")),
				kv("repo_url", validation.VStr("https://github.com/demo/protocol")),
				kv("commit", validation.VStr(strings.Repeat("a", 40))),
				kv("tree_url", validation.VStr("https://github.com/demo/protocol/tree/"+
					strings.Repeat("a", 40))),
				kv("tarball_url", validation.VStr("https://github.com/demo/protocol/archive/"+
					strings.Repeat("a", 40)+".tar.gz"))))),
			kv("vulnerabilities", arr(
				obj(kv("finding_id", validation.VStr("2025-01-demo_H-01")),
					kv("severity", validation.VStr("high")),
					kv("title", validation.VStr("Vault allows reentrant withdraw")),
					kv("description", validation.VStr("Too short."))),
				obj(kv("finding_id", validation.VStr("2025-01-demo_M-01")),
					kv("severity", validation.VStr("medium")),
					kv("title", validation.VStr("Oracle price can be stale")),
					kv("description", validation.VStr("The oracle reports\uffff a stale "+
						"price\ufffe when the feed stalls, "+
						"letting keepers settle at a bad rate.")))))),
		obj(
			kv("project_id", validation.VStr("sherlock_demo_2025_02")),
			kv("name", validation.VStr("Demo Lend")),
			kv("platform", validation.VStr("sherlock")),
			kv("codebases", arr(obj(
				kv("codebase_id", validation.VStr("Demo Lend_main")),
				kv("repo_url", validation.VStr("https://github.com/demo/lend")),
				kv("commit", validation.VStr("main")),
				kv("tree_url", validation.VStr("https://github.com/demo/lend/tree/main")),
				kv("tarball_url", validation.VStr(""))))),
			kv("vulnerabilities", arr(
				obj(kv("finding_id", validation.VStr(
					"2025.02.01 - Final - Demo Lend Report_L-01")),
					kv("severity", validation.VStr("low")),
					kv("title", validation.VStr("Dust griefing on liquidation")),
					kv("description", validation.VStr(long)))))),
	)
}

// loadSample is `_scabench_load_sample`.
func loadSample(t *testing.T) []validation.Value {
	t.Helper()
	src := filepath.Join(t.TempDir(), "sample.json")
	if err := validation.WriteJson(src, sample(), ""); err != nil {
		t.Fatal(err)
	}
	recs, err := LoadRecords(&src)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	return recs
}

// unmappedMaps is the Python `MAPS` fixture.
func unmappedMaps() validation.Value {
	return obj(kv("default", validation.VStr("unmapped")),
		kv("aliases", obj()))
}

func TestScabenchRecordShapeAndPinnedMapping(t *testing.T) {
	recs := loadSample(t)
	if len(recs) != 3 {
		t.Fatalf("record count = %d want 3", len(recs))
	}
	first := recs[0]
	if got := text(at(first, "id")); got != "code4rena_demo_2025_01-2025-01-demo_H-01" {
		t.Fatalf("id = %q", got)
	}
	if got := text(at(first, "dataset")); got != "scabench" {
		t.Fatalf("dataset = %q", got)
	}
	if at(first, "url").Kind != validation.Null {
		t.Fatal("url must be None")
	}
	wantProgram := validation.CanonSpaced(obj(
		kv("program", validation.VStr("Demo Protocol")),
		kv("platform", validation.VStr("code4rena")),
		kv("chains", arr())))
	if got := validation.CanonSpaced(at(first, "program")); got != wantProgram {
		t.Fatalf("program = %s want %s", got, wantProgram)
	}
	if got := text(at(first, "bug_class_label")); got != "unmapped" {
		t.Fatalf("bug_class_label = %q", got)
	}
	if got := text(at(first, "outcome")); got != "confirmed-exploitable" {
		t.Fatalf("outcome = %q", got)
	}
	if got := text(at(first, "severity")); got != "high" {
		t.Fatalf("severity = %q", got)
	}
	if at(first, "negative").B || at(first, "prior").B {
		t.Fatal("negative and prior must both be False")
	}
	if at(first, "pattern").Kind != validation.Null ||
		at(first, "exploit").Kind != validation.Null {
		t.Fatal("pattern and exploit must both be None")
	}
	if len(at(first, "locations").A) != 0 {
		t.Fatal("locations must be []")
	}
	if got := text(at(first, "partition")); got != "held-out" {
		t.Fatalf("partition = %q", got)
	}
	var sevs []string
	for _, r := range recs {
		sevs = append(sevs, text(at(r, "severity")))
	}
	if strings.Join(sevs, ",") != "high,medium,low" {
		t.Fatalf("severities = %v", sevs)
	}
}

func TestScabenchShortDescriptionComposedFromTitle(t *testing.T) {
	rec := loadSample(t)[0]
	if got := text(at(rec, "description")); got != "Vault allows reentrant withdraw\n\nToo short." {
		t.Fatalf("description = %q", got)
	}
	if n := len([]rune(text(at(rec, "description")))); n < 20 || n > 10000 {
		t.Fatalf("description len = %d", n)
	}
}

func TestScabenchUffffStripped(t *testing.T) {
	rec := loadSample(t)[1]
	if strings.Contains(text(at(rec, "description")), "\uffff") {
		t.Fatal("U+FFFF survived")
	}
	if strings.Contains(text(at(rec, "description")), "\ufffe") {
		t.Fatal("U+FFFE survived")
	}
	want := "The oracle reports a stale price when the feed stalls, " +
		"letting keepers settle at a bad rate."
	if got := text(at(rec, "description")); got != want {
		t.Fatalf("description = %q want %q", got, want)
	}
}

func TestScabenchLongDescriptionParagraphTruncated(t *testing.T) {
	rec := loadSample(t)[2]
	if n := len([]rune(text(at(rec, "description")))); n > 10000 {
		t.Fatalf("description len = %d > 10000", n)
	}
	want := strings.Join(longParas()[:3], "\n\n")
	if got := text(at(rec, "description")); got != want {
		t.Fatalf("description = %q want first 3 paragraphs", got[:80])
	}
	// Go-only parity pin (caught by the T34 cross-twin record digest, not by
	// the Python suite): compose_root_cause strips only " ." from the joined
	// cause, so a paragraph ending "\n." keeps the interior newline.
	if got := ComposeRootCause("T", "line one\n.\n\nsecond"); got != "T. line one\n" {
		t.Fatalf("interior-newline root cause = %q want %q", got, "T. line one\n")
	}
}

func TestScabenchTitleLengthRulesDirect(t *testing.T) {
	padded := FitTitle("abc", "2025-01-demo_H-01")
	if n := len([]rune(padded)); n < 5 || n > 500 {
		t.Fatalf("padded title len = %d", n)
	}
	if !strings.Contains(padded, "2025-01-demo_H-01") {
		t.Fatalf("padded title = %q", padded)
	}
	clipped := FitTitle(strings.Repeat("x", 600), "fid")
	if n := len([]rune(clipped)); n != 500 {
		t.Fatalf("clipped title len = %d want 500", n)
	}
	if !strings.HasSuffix(clipped, "...") {
		t.Fatalf("clipped title must end with ...: %q", clipped[len(clipped)-6:])
	}
}

func TestScabenchCommitRefRules(t *testing.T) {
	full, err := BuildCode(obj(
		kv("repo_url", validation.VStr("https://github.com/demo/r")),
		kv("commit", validation.VStr(strings.Repeat("b", 40)))))
	if err != nil {
		t.Fatalf("BuildCode: %v", err)
	}
	if got := text(at(full, "commit")); got != strings.Repeat("b", 40) {
		t.Fatalf("commit = %q", got)
	}
	if at(full, "snapshot_note").Kind != validation.Null {
		t.Fatal("full SHA must not earn a snapshot_note")
	}
	for _, bad := range []string{"main", ""} {
		code, cerr := BuildCode(obj(
			kv("repo_url", validation.VStr("https://github.com/demo/r")),
			kv("commit", validation.VStr(bad))))
		if cerr != nil {
			t.Fatalf("BuildCode(%q): %v", bad, cerr)
		}
		if at(code, "commit").Kind != validation.Null {
			t.Fatalf("commit %q must be omitted", bad)
		}
		if got := text(at(code, "snapshot_note")); got !=
			"commit as published in dataset; not a verified ref" {
			t.Fatalf("snapshot_note = %q", got)
		}
	}
}

func TestScabenchUnknownSeverityRejected(t *testing.T) {
	project := sample().A[0]
	finding := setField(at(project, "vulnerabilities").A[0], "severity",
		validation.VStr("critical"))
	_, err := BuildRecord(project, finding)
	if err == nil || !strings.Contains(err.Error(), "unknown severity") {
		t.Fatalf("err = %v want unknown severity", err)
	}
}

func TestScabenchIngestRecordPureShapes(t *testing.T) {
	maps := unmappedMaps()
	for _, rec := range loadSample(t) {
		res, err := ingest.IngestRecord(rec, &maps)
		if err != nil {
			t.Fatalf("%s: %v", text(at(rec, "id")), err)
		}
		cse := res.EvalCase
		if got := text(at(cse, "partition")); got != "held-out" {
			t.Fatalf("partition = %q", got)
		}
		if got := text(at(at(cse, "gold"), "bug_class")); got != "unmapped" {
			t.Fatalf("gold.bug_class = %q", got)
		}
		if got := text(at(at(cse, "gold"), "outcome")); got != "confirmed-exploitable" {
			t.Fatalf("gold.outcome = %q", got)
		}
		if got := text(at(at(cse, "source"), "dataset")); got != "scabench" {
			t.Fatalf("source.dataset = %q", got)
		}
		if len(res.MemoryRows) != 0 {
			t.Fatalf("memory_rows = %d want 0", len(res.MemoryRows))
		}
		if res.CampaignSeed == nil {
			t.Fatal("campaign_seed must not be None")
		}
		if got, want := text(at(*res.CampaignSeed, "repo")),
			text(at(at(rec, "code"), "repo")); got != want {
			t.Fatalf("seed repo = %q want %q", got, want)
		}
		if n := len([]rune(text(at(at(cse, "gold"), "root_cause")))); n < 10 || n > 2000 {
			t.Fatalf("gold.root_cause len = %d", n)
		}
	}
}

func TestScabenchIntegration555RecordsAllHeldOutUnmapped(t *testing.T) {
	requireSource(t)
	recs, err := LoadRecords(nil)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	if len(recs) != 555 {
		t.Fatalf("record count = %d want 555", len(recs))
	}
	for _, rec := range recs {
		sev := text(at(rec, "severity"))
		if sev != "high" && sev != "medium" && sev != "low" &&
			sev != "informational" {
			t.Fatalf("%s severity = %q", text(at(rec, "id")), sev)
		}
		if n := len([]rune(text(at(rec, "description")))); n < 20 || n > 10000 {
			t.Fatalf("%s description len = %d", text(at(rec, "id")), n)
		}
		if n := len([]rune(text(at(rec, "title")))); n < 5 || n > 500 {
			t.Fatalf("%s title len = %d", text(at(rec, "id")), n)
		}
		if strings.Contains(text(at(rec, "description")), "\uffff") ||
			strings.Contains(text(at(rec, "description")), "\ufffe") {
			t.Fatalf("%s still carries a noncharacter", text(at(rec, "id")))
		}
		if got := text(at(rec, "partition")); got != "held-out" {
			t.Fatalf("%s partition = %q", text(at(rec, "id")), got)
		}
		if got := text(at(rec, "bug_class_label")); got != "unmapped" {
			t.Fatalf("%s bug_class_label = %q", text(at(rec, "id")), got)
		}
		if got := text(at(rec, "outcome")); got != "confirmed-exploitable" {
			t.Fatalf("%s outcome = %q", text(at(rec, "id")), got)
		}
	}
}

func TestScabenchIntegrationIngestRecordShapes(t *testing.T) {
	requireSource(t)
	maps := unmappedMaps()
	recs, err := LoadRecords(nil)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	for _, rec := range recs {
		res, err := ingest.IngestRecord(rec, &maps)
		if err != nil {
			t.Fatalf("%s: %v", text(at(rec, "id")), err)
		}
		if got := text(at(res.EvalCase, "partition")); got != "held-out" {
			t.Fatalf("%s partition = %q", text(at(rec, "id")), got)
		}
		if got := text(at(at(res.EvalCase, "gold"), "bug_class")); got != "unmapped" {
			t.Fatalf("%s gold.bug_class = %q", text(at(rec, "id")), got)
		}
		if len(res.MemoryRows) != 0 {
			t.Fatalf("%s memory_rows = %d", text(at(rec, "id")), len(res.MemoryRows))
		}
	}
}

// requireSource is the Python `SOURCE.exists()` skipif, with the dataset-root
// override honored (WEBV2_DATASETS_ROOT points at a real data/datasets dir).
func requireSource(t *testing.T) {
	t.Helper()
	if root := os.Getenv("WEBV2_DATASETS_ROOT"); root != "" {
		SetSourceFile(filepath.Join(root, "scabench", "datasets",
			"curated-2025-08-18", "curated-2025-08-18.json"))
	}
	if !fileExists(SourceFile) {
		t.Skip("scabench clone absent")
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
