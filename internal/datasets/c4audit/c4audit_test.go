package c4audit

// Tests for the G3 c4audit loader: the judge-mapping table per row, the
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

// TestC4JudgeMapping pins the brief's verbatim table, one fixture row per
// line: High/known, QA, Invalid, Informational, Duplicate.
func TestC4JudgeMapping(t *testing.T) {
	rows := load(t, "testdata/normalized_sample.jsonl")
	if len(rows) != 6 {
		t.Fatalf("got %d rows, want 6", len(rows))
	}
	type want struct {
		id, outcome, severity, class string // severity "" = null
	}
	wants := []want{
		{"c4-2025-07-swap-zeroX-H-01", "confirmed-exploitable", "high", "access-control"},
		{"c4-2025-07-swap-zeroX-H-02", "out-of-scope", "medium", "reentrancy"},
		{"c4-2025-07-swap-zeroX-Q-01", "out-of-scope", "", "dos-griefing"},
		{"c4-2025-07-swap-zeroX-X-01", "disproved", "high", "access-control"},
		{"c4-2025-07-swap-zeroX-I-01", "out-of-scope", "", "precision-rounding"},
		{"c4-2025-07-swap-zeroX-H-03", "duplicate", "high", "unchecked-external-call"},
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
		if got := strField(t, row, "dataset"); got != "c4audit" {
			t.Errorf("row %s: dataset = %q, want c4audit", w.id, got)
		}
	}
}

// TestC4JudgeTableDrift pins the named map itself: exactly the seven judges
// with their default outcomes (flag law lives in mapOutcome, tested below).
func TestC4JudgeTableDrift(t *testing.T) {
	want := map[string]string{
		"High": "confirmed-exploitable", "Medium": "confirmed-exploitable",
		"QA": "out-of-scope", "Invalid": "disproved",
		"Informational": "out-of-scope", "Gas": "out-of-scope",
		"Duplicate": "duplicate",
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

// TestC4FlagLaw covers the paths the 6-row fixture cannot: a Medium judge
// (accepted when fresh, out-of-scope when known) and Gas.
func TestC4FlagLaw(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		id, judge, known, dup, outcome string
	}{
		{"m-fresh", "Medium", "false", "", "confirmed-exploitable"},
		{"m-known", "Medium", "true", "", "out-of-scope"},
		{"g-one", "Gas", "false", "", "out-of-scope"},
	}
	var lines []string
	for _, c := range cases {
		lines = append(lines,
			`{"id":"`+c.id+`","class":"access-control","severity":"Medium",`+
				`"judge":"`+c.judge+`","known":`+c.known+`,"duplicate_of":"`+c.dup+`",`+
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

// TestC4UnknownJudgeRejected: the Banana row fails LoadRecords with an
// "unknown judge" error naming the row id.
func TestC4UnknownJudgeRejected(t *testing.T) {
	_, err := LoadRecords("testdata/normalized_bad.jsonl")
	if err == nil {
		t.Fatal("LoadRecords accepted judge Banana, want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown judge") {
		t.Errorf("error %q does not say 'unknown judge'", msg)
	}
	if !strings.Contains(msg, "c4-2025-07-swap-zeroX-B-01") {
		t.Errorf("error %q does not name the row id", msg)
	}
}

// TestC4DuplicateWithoutPointer: Duplicate with an empty duplicate_of fails
// naming the row id.
func TestC4DuplicateWithoutPointer(t *testing.T) {
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

// TestC4IngestRoundTrip ingests the fixture into a temp WEBV2_EVAL_DIR store:
// every row becomes a schema-valid case, VerifyEvalStore passes, and the
// case shape carries the provenance law.
func TestC4IngestRoundTrip(t *testing.T) {
	pinClock(t)
	dir := tempStore(t)
	rows := load(t, "testdata/normalized_sample.jsonl")
	stored, err := Ingest(dir, rows, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 6 {
		t.Fatalf("ingested %d cases, want 6", len(stored))
	}
	if got := evalstore.VerifyEvalStore(); !got.OK || got.Count != 6 {
		t.Fatalf("verify = %+v", got)
	}
	caseIDRe := regexp.MustCompile(`^CASE-[0-9a-f]{12}$`)
	for i, c := range stored {
		row := rows[i]
		if !caseIDRe.MatchString(strField(t, c, "case_id")) {
			t.Errorf("case %d: bad case_id %q", i, strField(t, c, "case_id"))
		}
		source := field(t, c, "source")
		if got := strField(t, source, "dataset"); got != "c4audit" {
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
		if got := strField(t, code, "repo"); !strings.HasPrefix(got, "c4audit://") {
			t.Errorf("case %d: code.repo = %q, want the c4audit:// synthetic pointer", i, got)
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

// TestC4PartitionOverride: the caller option beats the held-out default.
func TestC4PartitionOverride(t *testing.T) {
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

// TestC4Determinism: load twice byte-equal; ingest twice (clock pinned)
// byte-equal. Determinism lives in the row content.
func TestC4Determinism(t *testing.T) {
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
