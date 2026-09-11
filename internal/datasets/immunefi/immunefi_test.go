package immunefi

// Tests for the G3 immunefi loader: the status-mapping table per row
// (paid/notes law, downgrade history, split row-per-report), the
// unknown-status rejection naming the row id, the Ingest round-trip into a
// temp eval store (VerifyEvalStore passes), the partition law + override,
// the ingest registry vocabulary membership, and determinism (load twice
// byte-equal; ingest twice byte-equal with the clock pinned via WEBV2_NOW).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/evalstore"
	"websec/internal/ingest"
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

// TestImmunefiStatusMapping pins the brief's verbatim table, one fixture row
// per line: accepted+paid, accepted unpaid, rejected, downgraded, two splits.
func TestImmunefiStatusMapping(t *testing.T) {
	rows := load(t, "testdata/normalized_sample.jsonl")
	if len(rows) != 6 {
		t.Fatalf("got %d rows, want 6", len(rows))
	}
	type want struct {
		id, outcome, severity, class string // severity "" = null
	}
	wants := []want{
		{"imm-2025-0314-a", "confirmed-exploitable", "high", "access-control"},
		{"imm-2025-0315-b", "confirmed-exploitable", "high", "reentrancy"},
		{"imm-2025-0316-c", "disproved", "medium", "access-control"},
		{"imm-2025-0317-d", "confirmed-exploitable", "high", "precision-rounding"},
		{"imm-2025-0318-e", "confirmed-exploitable", "medium", "unchecked-external-call"},
		{"imm-2025-0318-f", "confirmed-exploitable", "low", "dos-griefing"},
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
		if got := strField(t, row, "dataset"); got != "immunefi-resolved" {
			t.Errorf("row %s: dataset = %q, want immunefi-resolved", w.id, got)
		}
	}
}

// TestImmunefiPaidRidesNotes: the paid fact is a notes verbatim, never a
// smuggled gold key. The paid row's case notes carry paid_usd=<amount>; the
// unpaid acceptance carries no paid_usd token.
func TestImmunefiPaidRidesNotes(t *testing.T) {
	pinClock(t)
	dir := tempStore(t)
	rows := load(t, "testdata/normalized_sample.jsonl")
	stored, err := Ingest(dir, rows[:2], IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	paid := strField(t, stored[0], "notes")
	if !strings.Contains(paid, "paid_usd=120000") {
		t.Errorf("paid case notes %q do not carry paid_usd=120000 verbatim", paid)
	}
	gold := field(t, stored[0], "gold")
	if got := objAt(gold, "paid"); got.Kind != validation.Null {
		t.Errorf("gold smuggles a paid key: %s", validation.CanonCompact(gold))
	}
	if got := objAt(gold, "paid_usd"); got.Kind != validation.Null {
		t.Errorf("gold smuggles a paid_usd key: %s", validation.CanonCompact(gold))
	}
	unpaid := strField(t, stored[1], "notes")
	if strings.Contains(unpaid, "paid_usd=") {
		t.Errorf("unpaid case notes %q carry a paid_usd token", unpaid)
	}
}

// TestImmunefiDowngradeNotes: a downgrade is still an acceptance
// (confirmed-exploitable) and its history rides notes as
// "downgraded from <X>".
func TestImmunefiDowngradeNotes(t *testing.T) {
	pinClock(t)
	dir := tempStore(t)
	rows := load(t, "testdata/normalized_sample.jsonl")
	stored, err := Ingest(dir, rows[3:4], IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	gold := field(t, stored[0], "gold")
	if got := strField(t, gold, "outcome"); got != "confirmed-exploitable" {
		t.Fatalf("downgraded outcome = %q, want confirmed-exploitable", got)
	}
	notes := strField(t, stored[0], "notes")
	if !strings.Contains(notes, "downgraded from critical") {
		t.Errorf("downgraded notes %q do not say 'downgraded from critical'", notes)
	}
}

// TestImmunefiCriticalFoldsToHigh: the policy band critical has no
// evaluation_case enum slot, so gold carries high and notes mark the fold.
func TestImmunefiCriticalFoldsToHigh(t *testing.T) {
	pinClock(t)
	dir := tempStore(t)
	rows := load(t, "testdata/normalized_sample.jsonl")
	stored, err := Ingest(dir, rows[:1], IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	gold := field(t, stored[0], "gold")
	if got := strField(t, gold, "severity"); got != "high" {
		t.Fatalf("critical gold.severity = %q, want high (schema has no critical band)", got)
	}
	notes := strField(t, stored[0], "notes")
	if !strings.Contains(notes, "critical") || !strings.Contains(notes, "folded to high") {
		t.Errorf("critical notes %q do not mark the fold", notes)
	}
}

// TestImmunefiStatusTableDrift pins the named map itself: exactly the four
// statuses with their default outcomes (paid/notes law lives in buildCase,
// tested above).
func TestImmunefiStatusTableDrift(t *testing.T) {
	want := map[string]string{
		"accepted": "confirmed-exploitable", "rejected": "disproved",
		"downgraded": "confirmed-exploitable", "split": "confirmed-exploitable",
	}
	if len(statusToOutcome) != len(want) {
		t.Fatalf("statusToOutcome has %d entries, want %d", len(statusToOutcome), len(want))
	}
	for status, outcome := range want {
		if got, ok := statusToOutcome[status]; !ok || got != outcome {
			t.Errorf("statusToOutcome[%q] = %q, want %q", status, got, outcome)
		}
	}
}

// TestImmunefiUnknownStatusRejected: the escalated row fails LoadRecords
// with an "unknown status" error naming the row id.
func TestImmunefiUnknownStatusRejected(t *testing.T) {
	_, err := LoadRecords("testdata/normalized_bad.jsonl")
	if err == nil {
		t.Fatal("LoadRecords accepted status escalated, want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown status") {
		t.Errorf("error %q does not say 'unknown status'", msg)
	}
	if !strings.Contains(msg, "imm-2025-0319-z") {
		t.Errorf("error %q does not name the row id", msg)
	}
}

// TestImmunefiRegistryMembership: the ingest adapter registry accepts the
// immunefi-resolved vocabulary. No test in internal/ingest pins the list
// itself (rg for the dataset names across *_test.go finds only fixture
// uses), so the membership pin lives here: a record with this dataset must
// pass the vocabulary gate — i.e. any IngestRecord error must NOT be
// "unknown dataset".
func TestImmunefiRegistryMembership(t *testing.T) {
	rec := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("imm-probe")},
		validation.KV{K: "dataset", V: validation.VStr(Dataset)},
		validation.KV{K: "url", V: validation.VStr("https://example.com/imm-probe")},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr("probe")},
			validation.KV{K: "platform", V: validation.VStr("immunefi")},
			validation.KV{K: "chains", V: validation.VArr()})},
		validation.KV{K: "title", V: validation.VStr("probe title row long enough")},
		validation.KV{K: "description", V: validation.VStr(strings.Repeat("probe description sentence. ", 4))},
		validation.KV{K: "bug_class_label", V: validation.VStr("access-control")},
		validation.KV{K: "outcome", V: validation.VStr("confirmed-exploitable")},
		validation.KV{K: "severity", V: validation.VStr("high")},
		validation.KV{K: "root_cause", V: validation.VStr("probe root cause statement here")},
		validation.KV{K: "locations", V: validation.VArr()},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr("immunefi://probe")},
			validation.KV{K: "files", V: validation.VArr()})},
		validation.KV{K: "negative", V: validation.VBool(false)},
		validation.KV{K: "prior", V: validation.VBool(false)},
		validation.KV{K: "pattern", V: validation.VNull()},
		validation.KV{K: "exploit", V: validation.VNull()},
		validation.KV{K: "partition", V: validation.VStr("held-out")},
	)
	maps := validation.VObj(
		validation.KV{K: "default", V: validation.VStr("unmapped")},
		validation.KV{K: "aliases", V: validation.VObj()})
	if _, err := ingest.IngestRecord(rec, &maps); err != nil {
		if strings.Contains(err.Error(), "unknown dataset") {
			t.Fatalf("registry rejects immunefi-resolved: %v", err)
		}
		t.Fatal(err)
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

// TestImmunefiIngestRoundTrip ingests the fixture into a temp WEBV2_EVAL_DIR
// store: every row becomes a schema-valid case, VerifyEvalStore passes, and
// the case shape carries the provenance law (immunefi platform stamp,
// synthetic code pointer, no commit).
func TestImmunefiIngestRoundTrip(t *testing.T) {
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
		if got := strField(t, source, "dataset"); got != "immunefi-resolved" {
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
		if got := strField(t, program, "platform"); got != "immunefi" {
			t.Errorf("case %d: program.platform = %q, want immunefi", i, got)
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
		if got := strField(t, code, "repo"); !strings.HasPrefix(got, "immunefi://") {
			t.Errorf("case %d: code.repo = %q, want the immunefi:// synthetic pointer", i, got)
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

// TestImmunefiPartitionOverride: the caller option beats the held-out default.
func TestImmunefiPartitionOverride(t *testing.T) {
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

// TestImmunefiDeterminism: load twice byte-equal; ingest twice (clock pinned)
// byte-equal. Determinism lives in the row content.
func TestImmunefiDeterminism(t *testing.T) {
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

// TestImmunefiBadRowProbes: strictness beyond the unknown status —
// non-object lines and wrong-typed paid fail loudly.
func TestImmunefiBadRowProbes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jsonl")
	line := `{"id":"bad-paid","status":"accepted","paid":"yes","paid_usd":"","class":"access-control","severity":"High",` +
		`"root_cause":"Wrong-typed paid flag probe row, long enough title",` +
		`"url":"https://example.com/bad-paid","program":"probe"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecords(path); err == nil {
		t.Fatal("LoadRecords accepted a string paid flag, want an error")
	}
}
