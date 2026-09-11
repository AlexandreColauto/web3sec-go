// adjudicate_test.go — the non-gold adjudication store (adjudicate.go) and
// the Report split it feeds. Fixtures come from evalscore_test.go
// (kvE/goldCase/finding/testSuite/campaignFor) and are reused, not rebuilt.
package evalscore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// liveFinding is a synthetic live finding WITH the join key the adjudication
// store reads (finding_id), on top of the anchor keys finding() sets.
func liveFinding(id, class, path string) validation.Value {
	v := finding(class, path)
	v.O = validation.SetOrAppend(v.O, "finding_id", validation.VStr(id))
	return v
}

// adj is a valid row; a test mutates exactly one field to hit one rule.
func adj(id, verdict, basis string) Adjudication {
	return Adjudication{
		Finding: id,
		Verdict: verdict,
		Basis:   basis,
		Reason:  "checked against the dataset and the source",
		Actor:   "auditor",
	}
}

// TestValidateRules pins every rejection rule (and the valid rows) of the one
// fail-loud gate: each way an adjudication could be unfalsifiable.
func TestValidateRules(t *testing.T) {
	base := adj("F-aaaaaaaaaaaa", verdictAdditional, "reproduction")
	cases := []struct {
		name    string
		mut     func(*Adjudication)
		ok      bool
		wantSub string
	}{
		{name: "valid additional", mut: func(a *Adjudication) {}, ok: true},
		{name: "valid false-positive", mut: func(a *Adjudication) { a.Verdict = verdictFalsePositive }, ok: true},
		{name: "valid gated", mut: func(a *Adjudication) {
			a.Verdict = verdictGated
			a.Assumption = "the oracle is manipulable inside one block"
		}, ok: true},
		{name: "severity tbd is legal", mut: func(a *Adjudication) { a.Severity = "tbd" }, ok: true},
		{name: "empty finding", mut: func(a *Adjudication) { a.Finding = "" }, wantSub: "must name the finding"},
		{name: "whitespace finding", mut: func(a *Adjudication) { a.Finding = "  " }, wantSub: "must name the finding"},
		{name: "unknown verdict", mut: func(a *Adjudication) { a.Verdict = "maybe" },
			wantSub: "additional-true-positive, false-positive, assumption-gated"},
		{name: "unknown basis", mut: func(a *Adjudication) { a.Basis = "vibes" },
			wantSub: "dataset-cross-check, author-review, reproduction, code-argument"},
		{name: "unknown severity", mut: func(a *Adjudication) { a.Severity = "urgent" },
			wantSub: "tbd, low, medium, high, critical"},
		{name: "short reason", mut: func(a *Adjudication) { a.Reason = "too short" },
			wantSub: ">= 10 chars"},
		{name: "empty actor", mut: func(a *Adjudication) { a.Actor = "   " }, wantSub: "must name its actor"},
		{name: "gated without assumption", mut: func(a *Adjudication) { a.Verdict = verdictGated },
			wantSub: "assumption IS the whole content"},
		{name: "additional with assumption", mut: func(a *Adjudication) {
			a.Assumption = "an assumption the verdict does not gate on"
		}, wantSub: "belongs in reason"},
		{name: "false-positive with assumption", mut: func(a *Adjudication) {
			a.Verdict = verdictFalsePositive
			a.Assumption = "an assumption the verdict does not gate on"
		}, wantSub: "belongs in reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			tc.mut(&a)
			err := Validate(a)
			if tc.ok {
				if err != nil {
					t.Fatalf("Validate(%+v) = %v, want nil", a, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate(%+v) = nil, want an error", a)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Validate error %q does not name %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// row builds one state-doc adjudication row from string fields.
func row(pairs ...string) validation.Value {
	kvs := make([]validation.KV, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		kvs = append(kvs, kvE(pairs[i], validation.VStr(pairs[i+1])))
	}
	return validation.VObj(kvs...)
}

// withAdjudications rewrites the campaign state file's eval_adjudications key
// (or removes it when present is false). Schema validation is disabled on
// purpose: the malformed rows under test cannot survive it.
func withAdjudications(t *testing.T, c *state.Campaign, v validation.Value, present bool) {
	t.Helper()
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatalf("ReadJson: %v", err)
	}
	kvs := make([]validation.KV, 0, len(st.O)+1)
	for _, kve := range st.O {
		if kve.K == "eval_adjudications" {
			continue
		}
		kvs = append(kvs, kve)
	}
	if present {
		kvs = append(kvs, kvE("eval_adjudications", v))
	}
	if err := validation.WriteJson(c.StatePath, validation.VObj(kvs...), ""); err != nil {
		t.Fatalf("WriteJson: %v", err)
	}
}

// TestLoadAbsentNullEmptyAllMeanNoRows: the three "nothing was judged" shapes
// are the same answer, and none of them is an error.
func TestLoadAbsentNullEmptyAllMeanNoRows(t *testing.T) {
	cases := []struct {
		name    string
		v       validation.Value
		present bool
	}{
		{name: "absent"},
		{name: "null", v: validation.VNull(), present: true},
		{name: "empty array", v: validation.VArr(), present: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := campaignFor(t, "p1prog")
			withAdjudications(t, c, tc.v, tc.present)
			got, err := Load(c)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("Load = %+v, want no rows", got)
			}
		})
	}
}

// TestLoadSkipsNonStringRows: a valid row reads, a row whose fields are not
// all strings is skipped whole, and a non-object element never panics.
func TestLoadSkipsNonStringRows(t *testing.T) {
	c := campaignFor(t, "p1prog")
	want := Adjudication{
		Finding: "F-aaaaaaaaaaaa",
		Verdict: verdictAdditional,
		Basis:   "dataset-cross-check",
		Reason:  "a real bug the gold set does not contain",
		Actor:   "auditor",
		At:      "2026-01-01T00:00:00.000000+00:00",
	}
	malformed := row("finding", "F-bbbbbbbbbbbb", "verdict", verdictGated)
	malformed.O = validation.SetOrAppend(malformed.O, "assumption", validation.VInt(7))
	withAdjudications(t, c, validation.VArr(
		validation.VObj(
			kvE("finding", validation.VStr(want.Finding)),
			kvE("verdict", validation.VStr(want.Verdict)),
			kvE("basis", validation.VStr(want.Basis)),
			kvE("reason", validation.VStr(want.Reason)),
			kvE("actor", validation.VStr(want.Actor)),
			kvE("at", validation.VStr(want.At)),
		),
		malformed,
		validation.VStr("not an object"),
	), true)

	got, err := Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Load = %+v, want exactly %+v", got, want)
	}
	idx := Index(got)
	if _, ok := idx["F-aaaaaaaaaaaa"]; !ok {
		t.Fatalf("Index missing the finding key: %+v", idx)
	}
	if len(idx) != 1 {
		t.Fatalf("Index = %+v, want one entry", idx)
	}
}

// TestScoreSuiteWithSplitsUnanchored: one anchored finding, one of each
// adjudicated state, one unadjudicated. The raw counters are unchanged; the
// split names what the raw count conflated, and the adjusted line removes the
// true and the gated findings from the penalty (1/3 instead of 1/5).
func TestScoreSuiteWithSplitsUnanchored(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {
			liveFinding("F-aaaaaaaaaaaa", "access-control", "src/Vault.sol"),      // anchors CASE-A
			liveFinding("F-bbbbbbbbbbbb", "oracle-manipulation", "src/Vault.sol"), // additional
			liveFinding("F-cccccccccccc", "reentrancy", "src/Other.sol"),          // wrong => false positive
			liveFinding("F-dddddddddddd", "unchecked-call", "src/Vault.sol"),      // gated
			liveFinding("F-eeeeeeeeeeee", "weak-randomness", "src/Vault.sol"),     // unadjudicated
		},
		"ctrl": {},
	}
	gated := adj("F-dddddddddddd", verdictGated, "code-argument")
	gated.Assumption = "the unchecked call reaches an attacker-controlled target"
	adjs := []Adjudication{
		adj("F-bbbbbbbbbbbb", verdictAdditional, "dataset-cross-check"),
		adj("F-cccccccccccc", verdictFalsePositive, "reproduction"),
		gated,
	}
	r := ScoreSuiteWith([]string{"p1", "ctrl"}, live, testSuite(), adjs)
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"GoldTotal", r.GoldTotal, 3},
		{"Hits", r.Hits, 2}, // CASE-A plus the clean control; CASE-B matches nothing
		{"Misses", r.Misses, 1},
		{"FP", r.FP, 4}, // the raw unanchored count, unchanged
		{"Anchored", r.Anchored, 1},
		{"Unanchored", r.Unanchored, 4},
		{"Additional", r.Additional, 1},
		{"Gated", r.Gated, 1},
		{"FalsePositives", r.FalsePositives, 1},
		{"Unadjudicated", r.Unadjudicated, 1},
		{"StaleAdjudications", r.StaleAdjudications, 0},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if r.Unanchored != r.FP {
		t.Errorf("Unanchored %d != FP %d (same raw count, two names)", r.Unanchored, r.FP)
	}
	if want := wilson.Format(1, 5, "precision"); r.PrecisionLine != want {
		t.Errorf("PrecisionLine = %q, want %q", r.PrecisionLine, want)
	}
	if want := wilson.Format(1, 3, "precision"); r.AdjustedPrecisionLine != want {
		t.Errorf("AdjustedPrecisionLine = %q, want %q", r.AdjustedPrecisionLine, want)
	}
	if r.AdjustedPrecisionLine == r.PrecisionLine {
		t.Fatalf("adjusted line %q must differ from the raw one", r.AdjustedPrecisionLine)
	}
}

// TestScoreSuiteWithStaleAdjudications: a row for a finding that anchored a
// gold case, and a row for an id outside the live set, are both reported as
// stale and move no bucket.
func TestScoreSuiteWithStaleAdjudications(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {liveFinding("F-aaaaaaaaaaaa", "access-control", "src/Vault.sol")},
	}
	adjs := []Adjudication{
		adj("F-aaaaaaaaaaaa", verdictAdditional, "dataset-cross-check"), // anchored => applies to nothing
		adj("F-ffffffffffff", verdictAdditional, "dataset-cross-check"), // unknown id
	}
	r := ScoreSuiteWith([]string{"p1"}, live, testSuite(), adjs)
	if r.StaleAdjudications != 2 {
		t.Errorf("StaleAdjudications = %d, want 2", r.StaleAdjudications)
	}
	if r.Anchored != 1 || r.Unanchored != 0 {
		t.Errorf("anchored/unanchored = %d/%d, want 1/0", r.Anchored, r.Unanchored)
	}
	if r.Additional != 0 || r.Gated != 0 || r.FalsePositives != 0 || r.Unadjudicated != 0 {
		t.Errorf("stale rows must move no bucket: %+v", r)
	}
	if r.AdjustedPrecisionLine != r.PrecisionLine {
		t.Errorf("with no applied row the adjusted line must equal the raw one")
	}
}

// TestScoreSuiteBackCompatWithNoAdjudications is the guarantee the wave
// depends on: with no rows (nil or empty), ScoreSuiteWith returns the exact
// Report ScoreSuite always returned, field for field.
func TestScoreSuiteBackCompatWithNoAdjudications(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {
			liveFinding("F-aaaaaaaaaaaa", "access-control", "src/Vault.sol"),
			liveFinding("F-bbbbbbbbbbbb", "oracle-manipulation", "src/Vault.sol"),
		},
		"ctrl": {},
	}
	base := ScoreSuite([]string{"p1", "ctrl"}, live, testSuite())
	for _, adjs := range [][]Adjudication{nil, {}} {
		got := ScoreSuiteWith([]string{"p1", "ctrl"}, live, testSuite(), adjs)
		if got != base {
			t.Fatalf("ScoreSuiteWith(%v) = %+v, want the ScoreSuite report %+v",
				adjs, got, base)
		}
	}
}

// TestRecordLifecycle: Record validates, refuses a non-live id, replaces a
// prior row for the same finding, stamps at, writes schema-valid state, and
// logs one eval.adjudicated per accepted call.
func TestRecordLifecycle(t *testing.T) {
	c := campaignFor(t, "p1prog")
	for _, id := range []string{"F-aaaaaaaaaaaa", "F-bbbbbbbbbbbb"} {
		p := filepath.Join(c.FindingsDir, id+".json")
		if err := validation.WriteJson(p, liveFinding(id, "access-control", "src/Vault.sol"), ""); err != nil {
			t.Fatalf("WriteJson: %v", err)
		}
	}
	first, err := Record(c, adj("F-aaaaaaaaaaaa", verdictAdditional, "dataset-cross-check"))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if first.At == "" {
		t.Error("Record must stamp at")
	}
	if _, err := c.State(); err != nil {
		t.Fatalf("state after Record does not validate: %v", err)
	}
	rows, err := Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 1 || rows[0].Finding != "F-aaaaaaaaaaaa" ||
		rows[0].Verdict != verdictAdditional || rows[0].At != first.At {
		t.Fatalf("rows = %+v, want the recorded row", rows)
	}

	// A second Record for the same finding REPLACES the prior row.
	if _, err := Record(c, adj("F-aaaaaaaaaaaa", verdictFalsePositive, "author-review")); err != nil {
		t.Fatalf("Record replace: %v", err)
	}
	rows, err = Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 1 || rows[0].Verdict != verdictFalsePositive {
		t.Fatalf("replace left %+v, want one false-positive row", rows)
	}

	// A gated row round-trips its assumption through state and schema.
	gated := adj("F-bbbbbbbbbbbb", verdictGated, "code-argument")
	gated.Assumption = "the call target is attacker controlled"
	if _, err := Record(c, gated); err != nil {
		t.Fatalf("Record gated: %v", err)
	}
	rows, err = Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2", rows)
	}
	idx := Index(rows)
	if idx["F-bbbbbbbbbbbb"].Assumption != gated.Assumption {
		t.Errorf("assumption did not round-trip: %+v", idx["F-bbbbbbbbbbbb"])
	}

	// A non-live id and an unvalidated row are both refused.
	if _, err := Record(c, adj("F-ffffffffffff", verdictAdditional, "reproduction")); err == nil {
		t.Error("Record must refuse a finding that is not live")
	}
	if _, err := Record(c, adj("F-bbbbbbbbbbbb", "maybe", "reproduction")); err == nil {
		t.Error("Record must refuse an unvalidated row")
	}

	// One event per accepted Record: the additional, the replacement and the
	// gated row (the refusals log nothing).
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := strings.Count(string(raw), `"eval.adjudicated"`); n != 3 {
		t.Errorf("eval.adjudicated events = %d, want 3", n)
	}
}

// docRow is an otherwise-VALID state-doc adjudication row: only verdict,
// assumption and reason vary across the schema cases below. Validate would
// accept every row it builds; the SCHEMA is what has to refuse the bad ones,
// because a hand-edited state file never passes through Record.
func docRow(id, verdict, assumption, reason string) validation.Value {
	pairs := []string{
		"finding", id,
		"verdict", verdict,
		"basis", "reproduction",
		"reason", reason,
		"actor", "auditor",
		"at", "2026-01-01T00:00:00.000000+00:00",
	}
	if assumption != "" {
		pairs = append(pairs, "assumption", assumption)
	}
	return row(pairs...)
}

// stateDocWith returns the campaign's state doc with eval_adjudications set
// to v — a hand-built doc of exactly the kind the score path reads. The
// campaign's own schema-validation call is the subject of the test, so it is
// exercised here rather than a proxy for it.
func stateDocWith(t *testing.T, c *state.Campaign, v validation.Value) validation.Value {
	t.Helper()
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatalf("ReadJson: %v", err)
	}
	return validation.VObj(validation.SetOrAppend(st.O, "eval_adjudications", v)...)
}

// TestSchemaGatesAssumptionBothWays is the schema half of "Validate is no
// longer the only gate": a gated verdict with no assumption, and a non-gated
// verdict carrying one, are both refused by campaign_state itself — the
// SCORE path validates against this schema on read (the campaign tests'
// own validation call), so a hand-edited row cannot slip past it.
func TestSchemaGatesAssumptionBothWays(t *testing.T) {
	const reason = "checked against the dataset and the source"
	const assumption = "the oracle is manipulable inside one block"
	cases := []struct {
		name    string
		rows    []validation.Value
		wantErr string // "" = the schema must accept the doc
	}{
		{name: "empty array", rows: nil},
		{name: "additional without assumption",
			rows: []validation.Value{docRow("F-aaaaaaaaaaaa", verdictAdditional, "", reason)}},
		{name: "false-positive without assumption",
			rows: []validation.Value{docRow("F-aaaaaaaaaaaa", verdictFalsePositive, "", reason)}},
		{name: "gated with assumption",
			rows: []validation.Value{docRow("F-aaaaaaaaaaaa", verdictGated, assumption, reason)}},
		{name: "gated without assumption",
			rows:    []validation.Value{docRow("F-aaaaaaaaaaaa", verdictGated, "", reason)},
			wantErr: "eval_adjudications/0: 'assumption' is a required property"},
		{name: "additional with assumption",
			rows:    []validation.Value{docRow("F-aaaaaaaaaaaa", verdictAdditional, assumption, reason)},
			wantErr: "eval_adjudications/0/verdict: 'assumption-gated' was expected"},
		{name: "false-positive with assumption",
			rows:    []validation.Value{docRow("F-aaaaaaaaaaaa", verdictFalsePositive, assumption, reason)},
			wantErr: "eval_adjudications/0/verdict: 'assumption-gated' was expected"},
		{name: "blank reason",
			rows:    []validation.Value{docRow("F-aaaaaaaaaaaa", verdictFalsePositive, "", "          ")},
			wantErr: "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := campaignFor(t, "p1prog")
			doc := stateDocWith(t, c, validation.VArr(tc.rows...))
			err := validation.Validate(doc, "campaign_state", 1)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want the doc accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate = nil, want a refusal naming %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate error %q does not name %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestScoreSuiteWithInvalidRowsAreRefusedNotScored: the SCORE path refuses
// what Validate refuses, so a hand-edited row can never move the precision
// number. Each bad row leaves every bucket exactly where no row at all would
// leave it, and is reported once in InvalidAdjudications.
func TestScoreSuiteWithInvalidRowsAreRefusedNotScored(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {
			liveFinding("F-aaaaaaaaaaaa", "access-control", "src/Vault.sol"),      // anchors CASE-A
			liveFinding("F-bbbbbbbbbbbb", "oracle-manipulation", "src/Vault.sol"), // unanchored
		},
		"ctrl": {},
	}
	programs := []string{"p1", "ctrl"}
	base := ScoreSuiteWith(programs, live, testSuite(), nil)
	cases := []struct {
		name string
		bad  Adjudication
	}{
		{name: "unknown verdict", bad: adj("F-bbbbbbbbbbbb", "maybe", "reproduction")},
		{name: "gated without an assumption", bad: adj("F-bbbbbbbbbbbb", verdictGated, "code-argument")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScoreSuiteWith(programs, live, testSuite(), []Adjudication{tc.bad})
			if got.InvalidAdjudications != 1 {
				t.Errorf("InvalidAdjudications = %d, want 1", got.InvalidAdjudications)
			}
			got.InvalidAdjudications = base.InvalidAdjudications
			if got != base {
				t.Errorf("an invalid row moved the report:\n got %+v\nwant %+v", got, base)
			}
		})
	}
}

// TestScoreSuiteWithDuplicateRowsCountFindingsNotRows: two rows for one
// finding id are ONE adjudication — the last row wins, exactly as Index
// would have resolved them — and the stale loop counts findings, so a
// duplicated row for an anchored finding is stale once, not twice. Every
// counter in the Report therefore counts the same unit.
func TestScoreSuiteWithDuplicateRowsCountFindingsNotRows(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {
			liveFinding("F-aaaaaaaaaaaa", "access-control", "src/Vault.sol"),      // anchored => its rows are stale
			liveFinding("F-bbbbbbbbbbbb", "oracle-manipulation", "src/Vault.sol"), // unanchored => one verdict counts
		},
		"ctrl": {},
	}
	gated := adj("F-bbbbbbbbbbbb", verdictGated, "code-argument")
	gated.Assumption = "the call target is attacker controlled"
	adjs := []Adjudication{
		adj("F-aaaaaaaaaaaa", verdictAdditional, "dataset-cross-check"),
		adj("F-aaaaaaaaaaaa", verdictFalsePositive, "author-review"), // duplicate for an anchored finding
		gated,
		adj("F-bbbbbbbbbbbb", verdictAdditional, "dataset-cross-check"), // last row for F-bbb wins
	}
	r := ScoreSuiteWith([]string{"p1", "ctrl"}, live, testSuite(), adjs)
	if r.InvalidAdjudications != 0 {
		t.Errorf("InvalidAdjudications = %d, want 0 (every row here is valid)", r.InvalidAdjudications)
	}
	if r.Additional != 1 || r.Gated != 0 || r.FalsePositives != 0 || r.Unadjudicated != 0 {
		t.Errorf("exactly one verdict must win: Additional=%d Gated=%d FP=%d Unadjudicated=%d",
			r.Additional, r.Gated, r.FalsePositives, r.Unadjudicated)
	}
	if want := r.Additional + r.Gated + r.FalsePositives + r.Unadjudicated; want != r.Unanchored {
		t.Errorf("buckets sum to %d, want the unanchored count %d", want, r.Unanchored)
	}
	if r.StaleAdjudications != 1 {
		t.Errorf("StaleAdjudications = %d, want 1 (two ROWS, one FINDING)",
			r.StaleAdjudications)
	}
}

// TestScoreSuiteWithRefusedRowDoesNotShadowAReadableOne: refused rows are
// dropped BEFORE the dedupe, so hand-edited garbage cannot hide the valid
// row that names the same finding.
func TestScoreSuiteWithRefusedRowDoesNotShadowAReadableOne(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {liveFinding("F-bbbbbbbbbbbb", "oracle-manipulation", "src/Vault.sol")},
	}
	adjs := []Adjudication{
		adj("F-bbbbbbbbbbbb", verdictAdditional, "dataset-cross-check"),
		adj("F-bbbbbbbbbbbb", verdictGated, "code-argument"), // refused: no assumption
	}
	r := ScoreSuiteWith([]string{"p1"}, live, testSuite(), adjs)
	if r.Additional != 1 || r.Gated != 0 || r.Unadjudicated != 0 {
		t.Errorf("the readable row must survive: %+v", r)
	}
	if r.InvalidAdjudications != 1 {
		t.Errorf("InvalidAdjudications = %d, want 1", r.InvalidAdjudications)
	}
	if r.StaleAdjudications != 0 {
		t.Errorf("StaleAdjudications = %d, want 0 (the refused row is not a row)",
			r.StaleAdjudications)
	}
}
