package sherlock

// Tests for the G3 sherlock loader: the judge-mapping table per row, the
// unknown-judge rejection naming the row id, the Ingest round-trip into a
// temp eval store (VerifyEvalStore passes), the partition law + override,
// and determinism (load twice byte-equal; ingest twice byte-equal with the
// clock pinned via WEBV2_NOW).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/evalstore"
	"websec/internal/validation"
)

func load(t *testing.T, path string) []validation.Value {
	t.Helper()
	rows, err := LoadRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func field(t *testing.T, v validation.Value, key string) validation.Value {
	t.Helper()
	got := objAt(v, key)
	if got.Kind == validation.Null && key != "severity" {
		t.Fatalf("record is missing %q: %s", key, validation.CanonCompact(v))
	}
	return got
}

func strField(t *testing.T, v validation.Value, key string) string {
	t.Helper()
	got := field(t, v, key)
	if got.Kind != validation.Str {
		t.Fatalf("record %q is not a string: %s", key, validation.CanonCompact(v))
	}
	return got.S
}

// TestSherlockJudgeMapping pins the brief's verbatim table, one fixture row
// per line: High fresh, Medium known, Low+griefing, QA, Invalid, Duplicate,
// Griefing fresh.
func TestSherlockJudgeMapping(t *testing.T) {
	rows := load(t, "testdata/normalized_sample.jsonl")
	if len(rows) != 7 {
		t.Fatalf("got %d rows, want 7", len(rows))
	}
	type want struct {
		id, outcome, severity, class string // severity "" = null
	}
	wants := []want{
		{"sh-2025-03-vault-H-01", "confirmed-exploitable", "high", "access-control"},
		{"sh-2025-03-vault-M-01", "out-of-scope", "medium", "reentrancy"},
		{"sh-2025-03-vault-L-01", "economic-no-go", "low", "dos-griefing"},
		{"sh-2025-03-vault-Q-01", "out-of-scope", "", "dos-griefing"},
		{"sh-2025-03-vault-X-01", "disproved", "high", "access-control"},
		{"sh-2025-03-vault-D-01", "duplicate", "medium", "unchecked-external-call"},
		{"sh-2025-03-vault-G-01", "economic-no-go", "low", "dos-griefing"},
	}
	for i, w := range wants {
		row := rows[i]
		if got := strField(t, row, "id"); got != w.id {
			t.Fatalf("row %d: id = %q, want %q (file order is the contract)", i, got, w.id)
		}
		if got := strField(t, row, "outcome"); got != w.outcome {
			t.Errorf("row %s: outcome = %q, want %q", w.id, got, w.outcome)
		}
		sev := objAt(row, "severity")
		if w.severity == "" {
			if sev.Kind != validation.Null {
				t.Errorf("row %s: severity = %s, want null",
					w.id, validation.CanonCompact(sev))
			}
		} else if sev.Kind != validation.Str || sev.S != w.severity {
			t.Errorf("row %s: severity = %s, want %q",
				w.id, validation.CanonCompact(sev), w.severity)
		}
		if got := strField(t, row, "bug_class"); got != w.class {
			t.Errorf("row %s: bug_class = %q, want %q", w.id, got, w.class)
		}
		if got := strField(t, row, "partition"); got != "held-out" {
			t.Errorf("row %s: partition = %q, want held-out (loader law)", w.id, got)
		}
		if got := strField(t, row, "dataset"); got != "sherlock" {
			t.Errorf("row %s: dataset = %q, want sherlock", w.id, got)
		}
	}
}

// TestSherlockJudgeTableDrift pins the named map itself: exactly the seven
// judges with their default outcomes (flag law lives in mapOutcome, tested
// below).
func TestSherlockJudgeTableDrift(t *testing.T) {
	want := map[string]string{
		"High": "confirmed-exploitable", "Medium": "confirmed-exploitable",
		"Low": "confirmed-exploitable",
		"QA":  "out-of-scope", "Invalid": "disproved",
		"Duplicate": "duplicate", "Griefing": "economic-no-go",
	}
	if len(judgeToOutcome) != len(want) {
		t.Fatalf("judgeToOutcome has %d entries, want %d", len(judgeToOutcome), len(want))
	}
	for judge, outcome := range want {
		if got, ok := judgeToOutcome[judge]; !ok || got != outcome {
			t.Errorf("judgeToOutcome[%q] = %q, want %q", judge, got, outcome)
		}
	}
}

// TestSherlockFlagLaw covers the paths the 7-row fixture cannot: a fresh Low
// (accepted — the fixture Low carries griefing:true), a known Low and a known
// High (both out-of-scope), and a known Griefing (out-of-scope by the same
// known rule as every other judge).
func TestSherlockFlagLaw(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		id, judge, known, griefing, dup, outcome string
	}{
		{"l-fresh", "Low", "false", "false", "", "confirmed-exploitable"},
		{"l-known", "Low", "true", "false", "", "out-of-scope"},
		{"h-known", "High", "true", "false", "", "out-of-scope"},
		{"g-known", "Griefing", "true", "false", "", "out-of-scope"},
	}
	var lines []string
	for _, c := range cases {
		lines = append(lines,
			`{"id":"`+c.id+`","class":"access-control","severity":"Low",`+
				`"judge":"`+c.judge+`","known":`+c.known+`,"griefing":`+c.griefing+`,"duplicate_of":"`+c.dup+`",`+
				`"title":"Flag-law probe row with a long enough title",`+
				`"url":"https://example.com/`+c.id+`","program":"probe"}`)
	}
	path := filepath.Join(dir, "flags.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows := load(t, path)
	for i, c := range cases {
		if got := strField(t, rows[i], "outcome"); got != c.outcome {
			t.Errorf("row %s: outcome = %q, want %q", c.id, got, c.outcome)
		}
	}
}

// TestSherlockUnknownJudgeRejected: the Banana row fails LoadRecords with an
// "unknown judge" error naming the row id.
func TestSherlockUnknownJudgeRejected(t *testing.T) {
	_, err := LoadRecords("testdata/normalized_bad.jsonl")
	if err == nil {
		t.Fatal("LoadRecords accepted judge Banana, want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown judge") {
		t.Errorf("error %q does not say 'unknown judge'", msg)
	}
	if !strings.Contains(msg, "sh-2025-03-vault-B-01") {
		t.Errorf("error %q does not name the row id", msg)
	}
}

// TestSherlockDuplicateWithoutPointer: Duplicate with an empty duplicate_of fails
// naming the row id.
func TestSherlockDuplicateWithoutPointer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dup.jsonl")
	line := `{"id":"dup-noptr","class":"access-control","severity":"High",` +
		`"judge":"Duplicate","known":false,"duplicate_of":"",` +
		`"title":"Duplicate verdict row missing its pointer target",` +
		`"url":"https://example.com/dup-noptr","program":"probe"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRecords(path)
	if err == nil {
		t.Fatal("LoadRecords accepted a pointer-less Duplicate, want an error")
	}
	if !strings.Contains(err.Error(), "dup-noptr") {
		t.Errorf("error %q does not name the row id", err.Error())
	}
}

func pinClock(t *testing.T) {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-09-11T00:00:00.000000+00:00")
}

func tempStore(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "eval")
	evalstore.SetEvalDir(dir)
	t.Cleanup(evalstore.ResetEvalDir)
	return dir
}

// TestSherlockIngestRoundTrip ingests the fixture into a temp WEBV2_EVAL_DIR store:
// every row becomes a schema-valid case, VerifyEvalStore passes, and the
// case shape carries the provenance law.
func TestSherlockIngestRoundTrip(t *testing.T) {
	pinClock(t)
	dir := tempStore(t)
	rows := load(t, "testdata/normalized_sample.jsonl")
	stored, err := Ingest(dir, rows, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 7 {
		t.Fatalf("ingested %d cases, want 7", len(stored))
	}
	if got := evalstore.VerifyEvalStore(); !got.OK || got.Count != 7 {
		t.Fatalf("verify = %+v", got)
	}
	caseIDRe := regexp.MustCompile(`^CASE-[0-9a-f]{12}$`)
	for i, c := range stored {
		row := rows[i]
		if !caseIDRe.MatchString(strField(t, c, "case_id")) {
			t.Errorf("case %d: bad case_id %q", i, strField(t, c, "case_id"))
		}
		source := field(t, c, "source")
		if got := strField(t, source, "dataset"); got != "sherlock" {
			t.Errorf("case %d: source.dataset = %q", i, got)
		}
		if got, want := strField(t, source, "record_id"), strField(t, row, "id"); got != want {
			t.Errorf("case %d: source.record_id = %q, want %q", i, got, want)
		}
		if got, want := strField(t, source, "url"), strField(t, row, "url"); got != want {
			t.Errorf("case %d: source.url = %q, want %q", i, got, want)
		}
		if got := strField(t, c, "partition"); got != "held-out" {
			t.Errorf("case %d: partition = %q, want held-out", i, got)
		}
		program := field(t, c, "program")
		if got, want := strField(t, program, "program"), strField(t, row, "program"); got != want {
			t.Errorf("case %d: program.program = %q, want %q", i, got, want)
		}
		if got := objAt(program, "platform"); got.Kind != validation.Null {
			t.Errorf("case %d: program.platform is not null", i)
		}
		gold := field(t, c, "gold")
		if got, want := strField(t, gold, "outcome"), strField(t, row, "outcome"); got != want {
			t.Errorf("case %d: gold.outcome = %q, want %q", i, got, want)
		}
		if got, want := strField(t, gold, "bug_class"), strField(t, row, "bug_class"); got != want {
			t.Errorf("case %d: gold.bug_class = %q, want %q", i, got, want)
		}
		if validation.CanonCompact(objAt(gold, "severity")) !=
			validation.CanonCompact(objAt(row, "severity")) {
			t.Errorf("case %d: gold.severity drifted from the row", i)
		}
		if len(strField(t, gold, "root_cause")) < 10 {
			t.Errorf("case %d: gold.root_cause too short", i)
		}
		code := field(t, c, "code")
		if got := strField(t, code, "repo"); !strings.HasPrefix(got, "sherlock://") {
			t.Errorf("case %d: code.repo = %q, want the sherlock:// synthetic pointer", i, got)
		}
		if commit := objAt(code, "commit"); commit.Kind != validation.Null {
			t.Errorf("case %d: code.commit must be absent (no pinned snapshot)", i)
		}
		if strField(t, code, "snapshot_note") == "" {
			t.Errorf("case %d: code.snapshot_note must say the snapshot is unpinned", i)
		}
		if strField(t, c, "created_at") != "2026-09-11T00:00:00.000000+00:00" {
			t.Errorf("case %d: created_at does not honor the WEBV2_NOW pin", i)
		}
	}
}

// TestSherlockPartitionOverride: the caller option beats the held-out default.
func TestSherlockPartitionOverride(t *testing.T) {
	pinClock(t)
	dir := tempStore(t)
	rows := load(t, "testdata/normalized_sample.jsonl")
	dev := "dev"
	stored, err := Ingest(dir, rows[:1], IngestOptions{Partition: &dev})
	if err != nil {
		t.Fatal(err)
	}
	if got := strField(t, stored[0], "partition"); got != "dev" {
		t.Fatalf("partition = %q, want dev", got)
	}
	bogus := "nope"
	if _, err := Ingest(dir, rows[:1], IngestOptions{Partition: &bogus}); err == nil {
		t.Fatal("Ingest accepted partition 'nope', want an error")
	}
}

// TestSherlockDeterminism: load twice byte-equal; ingest twice (clock pinned)
// byte-equal. Determinism lives in the row content.
func TestSherlockDeterminism(t *testing.T) {
	pinClock(t)
	a := load(t, "testdata/normalized_sample.jsonl")
	b := load(t, "testdata/normalized_sample.jsonl")
	if len(a) != len(b) {
		t.Fatalf("loads differ in length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if validation.CanonCompact(a[i]) != validation.CanonCompact(b[i]) {
			t.Fatalf("row %d differs between loads", i)
		}
	}
	d1 := filepath.Join(t.TempDir(), "eval")
	d2 := filepath.Join(t.TempDir(), "eval")
	first, err := Ingest(d1, a, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	evalstore.ResetEvalDir()
	second, err := Ingest(d2, b, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	evalstore.ResetEvalDir()
	for i := range first {
		if validation.CanonCompact(first[i]) != validation.CanonCompact(second[i]) {
			t.Fatalf("case %d differs between ingests", i)
		}
	}
}
