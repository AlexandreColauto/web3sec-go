// Port of Task 4 step 1: the presence-gated eval audit section.
//
// A campaign whose program matches the eval suite (ES03BankReentrancy,
// one dev case in the real pack) renders the pinned ## eval lines; a
// campaign matching nothing returns ErrSkip (the gate is closed —
// AuditCampaign omits the section, so golden campaigns keep 14
// sections). The section is exercised directly (the sections package
// cannot import the audit package without an import cycle); the
// registry-level omission is pinned by internal/audit's own gate test.
//
// The non-gold adjudication block (evalscore/adjudicate.go, written by
// `webv2 adjudicate`) is appended after the J-perclass cells and gated on
// len(rows) > 0 alone: the tests at the end of this file pin the block, its
// value keys, the stale line, and the byte-identity of the zero-row campaign.
package sections

import (
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"websec/internal/evalscore"
	"websec/internal/state"
	"websec/internal/validation"
)

// evalFinding builds a synthetic live finding: only the anchor keys the
// scorer reads (root_cause.class, affected[0].path) are populated.
func evalFinding(class, path string) validation.Value {
	return validation.VObj(
		KV("root_cause", validation.VObj(KV("class", validation.VStr(class)))),
		KV("affected", validation.VArr(
			validation.VObj(KV("path", validation.VStr(path))),
		)),
	)
}

// evalCampaign opens a scratch campaign pinning the given program and
// writes the given live findings as raw finding docs (LoadLiveFindings
// reads them without schema validation).
func evalCampaign(t *testing.T, program string, live []validation.Value) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	for i, f := range live {
		// H12: strconv.Itoa, not string(rune('0'+i)) — the rune form is
		// only correct while the index stays below 10.
		p := filepath.Join(c.FindingsDir,
			"F-eval000000000"+strconv.Itoa(i)+".json")
		if err := validation.WriteJson(p, f, ""); err != nil {
			t.Fatalf("WriteJson: %v", err)
		}
	}
	return c
}

// evalLines reads the section's pinned markdown lines.
func evalLines(t *testing.T, sec validation.Value) []string {
	t.Helper()
	lv := objAt(sec, "lines")
	if lv.Kind != validation.Arr {
		t.Fatalf("no lines array: %s", validation.DumpIndented(sec))
	}
	var out []string
	for _, l := range lv.A {
		out = append(out, l.S)
	}
	return out
}

func TestEvalRendersPinnedLines(t *testing.T) {
	// ES03BankReentrancy matches exactly one real-pack case
	// (CASE-000000000003, dev, reentrancy @ ES03BankReentrancy.sol):
	// one anchored finding + one wrong-class FP.
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalFinding("reentrancy", "src/ES03BankReentrancy.sol"),
		evalFinding("oracle-manipulation", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	// The five base lines plus the I3 band block ARE the byte walk: the
	// shipped suite is partition-clean (uniform parseable deployed_at, no
	// held-out duplicate of a dev row), so the presence-gated I1b problem
	// block adds nothing here. Both findings score 0.0 (neither carries
	// risk/evidence fields) and one of them anchors, so the single
	// non-empty bucket is [0,1) at 1/2. Nothing was retracted, so the
	// fabrication ledger is absent.
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 1/2 (95% CI 9.5–90.5%)",
		"- false positives (unanchored live findings): 1",
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 1/2 (95% CI 9.5–90.5%)",
		// J-perclass: the per-class cells land AFTER the I3 blocks. The
		// FP class gets its own (zero-case) row — a live finding is
		// attributed to exactly one class, never dropped.
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - oracle-manipulation: recall 0/0 (95% CI n/a), precision 0/1 (95% CI 0.0–79.3%)",
		"  - reentrancy: recall 1/1 (95% CI 20.7–100.0%), precision 1/1 (95% CI 20.7–100.0%)",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("eval section must stay ok=true (informational): %s",
			validation.DumpIndented(sec))
	}
	if n := len(objAt(sec, "problems").A); n != 0 {
		t.Errorf("problems = %d, want 0", n)
	}
}

// partitionCase builds a minimal suite row: only the keys this section,
// evalscore and the I1b partition health actually read.
func partitionCase(caseID, partition, program, deployed, created,
	class, rootCause, file string) validation.Value {
	row := []validation.KV{
		KV("case_id", validation.VStr(caseID)),
		KV("partition", validation.VStr(partition)),
		KV("program", validation.VObj(KV("program", validation.VStr(program)))),
		KV("created_at", validation.VStr(created)),
		KV("gold", validation.VObj(
			KV("outcome", validation.VStr("confirmed-exploitable")),
			KV("bug_class", validation.VStr(class)),
			KV("severity", validation.VStr("high")),
			KV("root_cause", validation.VStr(rootCause)),
			KV("locations", validation.VArr(validation.VObj(
				KV("file", validation.VStr(file))))))),
		KV("code", validation.VObj(KV("repo", validation.VStr("internal://evalsuite")))),
	}
	if deployed != "" {
		row = append(row, KV("deployed_at", validation.VStr(deployed)))
	}
	return validation.VObj(row...)
}

// withEvalCases points the section's suite loader at a synthetic pack for
// one test. The shipped pack cannot exercise the I1b problem render: it is
// partition-clean by construction.
func withEvalCases(t *testing.T, cases []validation.Value) {
	t.Helper()
	restore := evalCases
	evalCases = func() ([]validation.Value, error) { return cases, nil }
	t.Cleanup(func() { evalCases = restore })
}

// TestEvalRendersPartitionProblemsWhenPresent: a suite row whose
// deployed_at cannot be parsed is excluded at scoring time, and the
// section says so — the block appears only when there is something to
// report, and the campaign's own ok stays true (a store defect is not a
// campaign defect; the run is fail-open).
func TestEvalRendersPartitionProblemsWhenPresent(t *testing.T) {
	withEvalCases(t, []validation.Value{
		partitionCase("CASE-0000000000d1", "dev", "ES03BankReentrancy",
			"2026-05-01", "2026-01-01T00:00:00+00:00", "reentrancy",
			"withdraw sends funds before the balance update",
			"src/ES03BankReentrancy.sol"),
		partitionCase("CASE-0000000000h1", "held-out", "Other", "2026-1-1",
			"2026-01-01T00:00:00+00:00", "oracle-manipulation",
			"spot reserves price the borrow limit", "src/Lender.sol"),
	})
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalFinding("reentrancy", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	got := evalLines(t, sec)
	wantProblems := []string{
		"- partition problems (rows excluded from the scorecard, never mutated): 1",
		"  - unparseable-deployed_at CASE-0000000000h1",
	}
	// Five base lines, then the I1b problem block, then the I3 band block
	// (the single live finding scores 0.0 and anchors, so [0,1) is 1/1),
	// then the J-perclass class block.
	wantBands := []string{
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 1/1 (95% CI 20.7–100.0%)",
	}
	wantClasses := []string{
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - reentrancy: recall 1/1 (95% CI 20.7–100.0%), precision 1/1 (95% CI 20.7–100.0%)",
	}
	if len(got) != 11 {
		t.Fatalf("lines = %q\nwant the five pinned lines + %q + %q + %q",
			got, wantProblems, wantBands, wantClasses)
	}
	if !reflect.DeepEqual(got[5:7], wantProblems) {
		t.Fatalf("problem block = %q\nwant %q", got[5:7], wantProblems)
	}
	if !reflect.DeepEqual(got[7:9], wantBands) {
		t.Fatalf("band block = %q\nwant %q", got[7:9], wantBands)
	}
	if !reflect.DeepEqual(got[9:], wantClasses) {
		t.Fatalf("class block = %q\nwant %q", got[9:], wantClasses)
	}
	probs := objAt(sec, "problems")
	if probs.Kind != validation.Arr || len(probs.A) != 1 ||
		probs.A[0].S != "unparseable-deployed_at CASE-0000000000h1" {
		t.Fatalf("problems value = %s", validation.CanonCompact(probs))
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("a store-side partition problem must not fail the campaign: %s",
			validation.DumpIndented(sec))
	}
}

// TestEvalOmitsProblemBlockWhenClean: the same synthetic pack minus the
// unusable date renders exactly the five pinned lines and an empty
// problems array — the presence gate, proven at the byte level.
func TestEvalOmitsProblemBlockWhenClean(t *testing.T) {
	withEvalCases(t, []validation.Value{
		partitionCase("CASE-0000000000d1", "dev", "ES03BankReentrancy",
			"2026-05-01", "2026-01-01T00:00:00+00:00", "reentrancy",
			"withdraw sends funds before the balance update",
			"src/ES03BankReentrancy.sol"),
	})
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalFinding("reentrancy", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 1/1 (95% CI 20.7–100.0%)",
		"- false positives (unanchored live findings): 0",
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 1/1 (95% CI 20.7–100.0%)",
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - reentrancy: recall 1/1 (95% CI 20.7–100.0%), precision 1/1 (95% CI 20.7–100.0%)",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	if n := len(objAt(sec, "problems").A); n != 0 {
		t.Fatalf("problems = %d, want 0", n)
	}
}

func TestEvalSkipsWhenNothingMatched(t *testing.T) {
	c := evalCampaign(t, "nothing-here", nil)
	_, err := Eval(c)
	if !errors.Is(err, ErrSkip) {
		t.Fatalf("Eval = %v, want ErrSkip (gate closed)", err)
	}
}

func TestEvalRegisteredLast(t *testing.T) {
	var names []string
	RegisterAll(func(name string, _ SectionFunc) { names = append(names, name) })
	// eval keeps its slot past all fourteen ported sections; the r4
	// presence-gated price_table was appended after it (audit_test pins
	// the full order). eval must stay immediately before price_table.
	if len(names) < 2 || names[len(names)-1] != "price_table" ||
		names[len(names)-2] != "eval" {
		t.Fatalf("eval/price_table tail order wrong: %v", names)
	}
}

// evalScoredFinding is evalFinding plus the acceptance-score inputs the I3
// block consumes: risk.validated.band with an irreversible reversibility
// (band "critical" ⇒ 3.0 + 1.0 = 4.0), and an optional status retraction
// signal. An empty band leaves the finding at score 0.0.
func evalScoredFinding(class, path, band, status string) validation.Value {
	kvs := []validation.KV{
		KV("root_cause", validation.VObj(KV("class", validation.VStr(class)))),
		KV("affected", validation.VArr(validation.VObj(
			KV("path", validation.VStr(path))))),
	}
	if band != "" {
		kvs = append(kvs, KV("risk", validation.VObj(
			KV("validated", validation.VObj(KV("band", validation.VStr(band)))),
			KV("reversibility", validation.VStr("irreversible")))))
	}
	if status != "" {
		kvs = append(kvs, KV("status", validation.VStr(status)))
	}
	return validation.VObj(kvs...)
}

// TestEvalRendersBandBlockAfterFPLine: with live findings under a
// suite-matched program the I3 block lands directly after the FP line —
// one row per non-empty acceptance bucket (ascending), then the
// fabrication ledger. The DISPROVED row is still a LIVE finding
// (LoadLiveFindings filters only DUPLICATE/OUT_OF_SCOPE/SUPERSEDED) and it
// still anchors: status is not an anchor rule. It is the ledger, not the
// recall line, that reports the retraction.
//
// Scores: critical+irreversible = 4.0 → [4+); the other two have no risk
// fields → 0.0 → [0,1), where one of the two anchors.
func TestEvalRendersBandBlockAfterFPLine(t *testing.T) {
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalScoredFinding("reentrancy", "src/ES03BankReentrancy.sol", "critical", ""),
		evalFinding("oracle-manipulation", "src/ES03BankReentrancy.sol"),
		evalScoredFinding("reentrancy", "src/ES03BankReentrancy.sol", "", "DISPROVED"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 2/3 (95% CI 20.8–93.9%)",
		"- false positives (unanchored live findings): 1",
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 1/2 (95% CI 9.5–90.5%)",
		"  - [4+): 1/1 (95% CI 20.7–100.0%)",
		"- fabrication ledger: 1/3 live findings retracted as disproved; " +
			"by band [0,1)=1, [1,2)=0, [2,4)=0, [4+)=0",
		// J-perclass: the class block is the LAST thing appended, i.e.
		// after the fabrication ledger. Both retracted and anchored rows
		// still count as LIVE findings.
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - oracle-manipulation: recall 0/0 (95% CI n/a), precision 0/1 (95% CI 0.0–79.3%)",
		"  - reentrancy: recall 1/1 (95% CI 20.7–100.0%), precision 2/2 (95% CI 34.2–100.0%)",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	// The value keys carry the same numbers for machine consumers.
	bands := objAt(sec, "bands")
	if bands.Kind != validation.Arr || len(bands.A) != 2 {
		t.Fatalf("bands = %s, want two rows", validation.CanonCompact(bands))
	}
	row := bands.A[0]
	if lo := objAt(row, "lo"); lo.Kind != validation.Flt || lo.F != 0 {
		t.Fatalf("first row lo = %s, want 0", validation.CanonCompact(lo))
	}
	if hi := objAt(row, "hi"); hi.Kind != validation.Flt || hi.F != 1 {
		t.Fatalf("first row hi = %s, want 1", validation.CanonCompact(hi))
	}
	if n := objAt(row, "anchored"); n.Kind != validation.Int || n.I != 1 {
		t.Fatalf("first row anchored = %s, want 1", validation.CanonCompact(n))
	}
	if n := objAt(row, "total"); n.Kind != validation.Int || n.I != 2 {
		t.Fatalf("first row total = %s, want 2", validation.CanonCompact(n))
	}
	if l := objStr(row, "line"); l != "precision: 1/2 (95% CI 9.5–90.5%)" {
		t.Fatalf("first row line = %q", l)
	}
	// The last row's upper edge is +Inf. The ordered-JSON writer has no
	// Infinity token (encoding/json rejects it), so `hi` is ABSENT there
	// rather than unparseable: absence IS the open upper edge.
	if hi := objAt(bands.A[1], "hi"); hi.Kind != validation.Null {
		t.Fatalf("last row hi = %s, want absent (open +Inf edge)",
			validation.CanonCompact(hi))
	}
	if fab := objAt(sec, "fabricated"); fab.Kind != validation.Int || fab.I != 1 {
		t.Fatalf("fabricated = %s, want 1", validation.CanonCompact(fab))
	}
	fabBands := objAt(sec, "fabrication_bands")
	if fabBands.Kind != validation.Arr || len(fabBands.A) != 4 ||
		fabBands.A[0].I != 1 || fabBands.A[3].I != 0 {
		t.Fatalf("fabrication_bands = %s, want [1 0 0 0]",
			validation.CanonCompact(fabBands))
	}
	if u := objAt(sec, "unscorable"); u.Kind != validation.Null {
		t.Fatalf("unscorable = %s, want absent when zero",
			validation.CanonCompact(u))
	}
}

// TestEvalBandBlockAbsentWithZeroLiveFindings is the presence gate at the
// byte level: a matched program with no live findings renders EXACTLY the
// pre-I3 five lines and carries none of the new value keys.
func TestEvalBandBlockAbsentWithZeroLiveFindings(t *testing.T) {
	c := evalCampaign(t, "ES03BankReentrancy", nil)
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 0/1 (95% CI 0.0–79.3%)",
		"- precision: 0/0 (95% CI n/a)",
		"- false positives (unanchored live findings): 0",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant the unchanged five %q", got, want)
	}
	for _, key := range []string{"bands", "unscorable", "fabricated",
		"fabrication_bands", "classes"} {
		if v := objAt(sec, key); v.Kind != validation.Null {
			t.Errorf("%s = %s, want absent when the gate is closed",
				key, validation.CanonCompact(v))
		}
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("eval section must stay ok=true: %s", validation.DumpIndented(sec))
	}
}

// TestEvalBandValueRoundTrips: the section value is serialized into the
// audit report, so it must survive the framework's own ordered
// writer/parser. This is the test behind the open [4+) edge being an
// ABSENT `hi`: emitting +Inf would write an Infinity token that
// encoding/json (and therefore ParseOrdered) rejects, leaving a report
// nothing could read back.
func TestEvalBandValueRoundTrips(t *testing.T) {
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalScoredFinding("reentrancy", "src/ES03BankReentrancy.sol", "critical", ""),
		evalFinding("oracle-manipulation", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	canon := validation.Canon(sec, true)
	back, err := validation.ParseOrdered([]byte(canon))
	if err != nil {
		t.Fatalf("the section value does not round-trip: %v\n%s", err, canon)
	}
	if got := validation.Canon(back, true); got != canon {
		t.Fatalf("round-trip moved bytes:\n got %s\nwant %s", got, canon)
	}
}

// TestEvalClassesValueAndUnmappedBucket: the `classes` value carries the
// same numbers the block renders, one row per class, in the SAME order the
// lines appear. A live finding with no root_cause.class is attributed to
// `unmapped` — rendered and counted, never dropped.
func TestEvalClassesValueAndUnmappedBucket(t *testing.T) {
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		validation.VObj( // no root_cause at all
			KV("affected", validation.VArr(validation.VObj(
				KV("path", validation.VStr("src/ES03BankReentrancy.sol"))))),
		),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 0/1 (95% CI 0.0–79.3%)",
		"- precision: 0/1 (95% CI 0.0–79.3%)",
		"- false positives (unanchored live findings): 1",
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 0/1 (95% CI 0.0–79.3%)",
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - reentrancy: recall 0/1 (95% CI 0.0–79.3%), precision 0/0 (95% CI n/a)",
		"  - unmapped: recall 0/0 (95% CI n/a), precision 0/1 (95% CI 0.0–79.3%)",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	classes := objAt(sec, "classes")
	if classes.Kind != validation.Arr || len(classes.A) != 2 {
		t.Fatalf("classes = %s, want two rows",
			validation.CanonCompact(classes))
	}
	unmapped := classes.A[1]
	if got := objStr(unmapped, "class"); got != "unmapped" {
		t.Fatalf("second class row = %q, want unmapped", got)
	}
	if n := objAt(unmapped, "cases"); n.Kind != validation.Int || n.I != 0 {
		t.Fatalf("unmapped cases = %s, want 0",
			validation.CanonCompact(n))
	}
	if n := objAt(unmapped, "live"); n.Kind != validation.Int || n.I != 1 {
		t.Fatalf("unmapped live = %s, want 1",
			validation.CanonCompact(n))
	}
	if n := objAt(unmapped, "anchored"); n.Kind != validation.Int || n.I != 0 {
		t.Fatalf("unmapped anchored = %s, want 0",
			validation.CanonCompact(n))
	}
	if p := objStr(unmapped, "precision"); p != "precision: 0/1 (95% CI 0.0–79.3%)" {
		t.Fatalf("unmapped precision = %q", p)
	}
	if r := objStr(unmapped, "recall"); r != "recall: 0/0 (95% CI n/a)" {
		t.Fatalf("unmapped recall = %q", r)
	}
	if r := objStr(classes.A[0], "class"); r != "reentrancy" {
		t.Fatalf("first class row = %q, want reentrancy (sorted by Class)", r)
	}
}

// ---------------------------------------------------------------------------
// Non-gold adjudications
// ---------------------------------------------------------------------------

// evalRow is evalFinding plus the finding_id the adjudication store joins
// on (evalscore.Record refuses an id that is not in the live set).
func evalRow(class, path, findingID string) validation.Value {
	f := evalFinding(class, path)
	return validation.VObj(append([]validation.KV{
		KV("finding_id", validation.VStr(findingID))}, f.O...)...)
}

// evalAdjudicated is the pinned two-finding campaign — one anchored
// reentrancy finding, one unanchored oracle finding, both on the gold file —
// with one row written through evalscore.Record, the production writer.
func evalAdjudicated(t *testing.T, a evalscore.Adjudication) *state.Campaign {
	t.Helper()
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalRow("reentrancy", "src/ES03BankReentrancy.sol", "F-aaaaaaaaaaaa"),
		evalRow("oracle-manipulation", "src/ES03BankReentrancy.sol",
			"F-bbbbbbbbbbbb"),
	})
	if _, err := evalscore.Record(c, a); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return c
}

// evalPinnedLines is the byte walk every zero-adjudication rendering of this
// fixture must still produce (TestEvalRendersPinnedLines' `want`, which the
// I3/J blocks already fixed): five base lines, the band block, the class
// block.
func evalPinnedLines() []string {
	return []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 1/2 (95% CI 9.5–90.5%)",
		"- false positives (unanchored live findings): 1",
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 1/2 (95% CI 9.5–90.5%)",
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - oracle-manipulation: recall 0/0 (95% CI n/a), precision 0/1 (95% CI 0.0–79.3%)",
		"  - reentrancy: recall 1/1 (95% CI 20.7–100.0%), precision 1/1 (95% CI 20.7–100.0%)",
	}
}

// TestEvalRendersAdjudicationBlock: one additional-true-positive row on the
// unanchored finding adds the three-line block AFTER the class cells, lifts
// the penalty from the adjusted precision line (1/2 raw → 1/1 adjusted) and
// leaves the RAW fp/precision lines untouched, and carries the row in the
// `adjudications` value with the section's row key order.
func TestEvalRendersAdjudicationBlock(t *testing.T) {
	c := evalAdjudicated(t, evalscore.Adjudication{
		Finding: "F-bbbbbbbbbbbb", Verdict: "additional-true-positive",
		Severity: "tbd", Basis: "author-review", Actor: "alice",
		Reason: "the oracle spot price is never validated",
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := append(evalPinnedLines(),
		"- non-gold adjudications: 1 of 1 unanchored findings adjudicated "+
			"(additional-true-positive 1, false-positive 0, assumption-gated 0)",
		"- adjusted precision (denominator excludes findings adjudicated "+
			"true or gated): precision: 1/1 (95% CI 20.7–100.0%)",
		"- unadjudicated unanchored findings: 0")
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	rows := objAt(sec, "adjudications")
	if rows.Kind != validation.Arr || len(rows.A) != 1 {
		t.Fatalf("adjudications = %s, want one row",
			validation.CanonCompact(rows))
	}
	row := rows.A[0]
	if got := objStr(row, "finding"); got != "F-bbbbbbbbbbbb" {
		t.Fatalf("row finding = %q", got)
	}
	if got := objStr(row, "verdict"); got != "additional-true-positive" {
		t.Fatalf("row verdict = %q", got)
	}
	if got := objStr(row, "severity"); got != "tbd" {
		t.Fatalf("row severity = %q", got)
	}
	if got := objStr(row, "basis"); got != "author-review" {
		t.Fatalf("row basis = %q", got)
	}
	if got := objStr(row, "actor"); got != "alice" {
		t.Fatalf("row actor = %q", got)
	}
	if got := objStr(row, "reason"); got !=
		"the oracle spot price is never validated" {
		t.Fatalf("row reason = %q", got)
	}
	// Optional row keys are ABSENT, not empty.
	if v := objAt(row, "assumption"); v.Kind != validation.Null {
		t.Errorf("row assumption = %s, want absent",
			validation.CanonCompact(v))
	}
	if v := objAt(row, "exec"); v.Kind != validation.Null {
		t.Errorf("row exec = %s, want absent", validation.CanonCompact(v))
	}
	if got := objStr(sec, "adjusted_precision"); got !=
		"precision: 1/1 (95% CI 20.7–100.0%)" {
		t.Fatalf("adjusted_precision = %q", got)
	}
	if n := objAt(sec, "unadjudicated"); n.Kind != validation.Int || n.I != 0 {
		t.Fatalf("unadjudicated = %s, want 0", validation.CanonCompact(n))
	}
	if v := objAt(sec, "stale_adjudications"); v.Kind != validation.Null {
		t.Fatalf("stale_adjudications = %s, want absent when zero",
			validation.CanonCompact(v))
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("a recorded adjudication must not fail the campaign: %s",
			validation.DumpIndented(sec))
	}
}

// TestEvalRendersStaleAdjudicationLine: a row on the ANCHORED finding applies
// to no unanchored finding, so the stale line and the stale_adjudications
// key appear — and the tally says none of the unanchored set was judged.
func TestEvalRendersStaleAdjudicationLine(t *testing.T) {
	c := evalAdjudicated(t, evalscore.Adjudication{
		Finding: "F-aaaaaaaaaaaa", Verdict: "additional-true-positive",
		Severity: "tbd", Basis: "author-review", Actor: "alice",
		Reason: "the oracle spot price is never validated",
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := append(evalPinnedLines(),
		"- non-gold adjudications: 0 of 1 unanchored findings adjudicated "+
			"(additional-true-positive 0, false-positive 0, assumption-gated 0)",
		"- adjusted precision (denominator excludes findings adjudicated "+
			"true or gated): precision: 1/2 (95% CI 9.5–90.5%)",
		"- unadjudicated unanchored findings: 1",
		"- stale adjudications (rows that apply to no unanchored finding): 1")
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	if n := objAt(sec, "stale_adjudications"); n.Kind != validation.Int || n.I != 1 {
		t.Fatalf("stale_adjudications = %s, want 1",
			validation.CanonCompact(n))
	}
	if n := objAt(sec, "unadjudicated"); n.Kind != validation.Int || n.I != 1 {
		t.Fatalf("unadjudicated = %s, want 1", validation.CanonCompact(n))
	}
}

// TestEvalAdjudicationBlockAbsentWithZeroRows is the presence gate at the
// byte level: a campaign with NO stored row renders exactly the lines it
// rendered before the adjudication block existed and carries none of the new
// value keys. (TestEvalRendersPinnedLines, TestEvalOmitsProblemBlockWhenClean
// and TestEvalBandBlockAbsentWithZeroLiveFindings pin the same bytes from
// the other directions.)
func TestEvalAdjudicationBlockAbsentWithZeroRows(t *testing.T) {
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalRow("reentrancy", "src/ES03BankReentrancy.sol", "F-aaaaaaaaaaaa"),
		evalRow("oracle-manipulation", "src/ES03BankReentrancy.sol",
			"F-bbbbbbbbbbbb"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, evalPinnedLines()) {
		t.Fatalf("lines = %q\nwant the unchanged %q", got, evalPinnedLines())
	}
	for _, key := range []string{"adjudications", "adjusted_precision",
		"unadjudicated", "stale_adjudications"} {
		if v := objAt(sec, key); v.Kind != validation.Null {
			t.Errorf("%s = %s, want absent with zero rows",
				key, validation.CanonCompact(v))
		}
	}
	for _, l := range evalLines(t, sec) {
		if strings.Contains(l, "adjudicat") {
			t.Errorf("zero-row campaign rendered an adjudication line: %q", l)
		}
	}
	// The key set is exactly the pre-adjudication one.
	wantKeys := map[string]bool{
		"matched": true, "dev": true, "held_out": true, "hits": true,
		"misses": true, "fp": true, "recall": true, "precision": true,
		"lines": true, "problems": true, "bands": true, "classes": true,
		"ok": true,
	}
	for _, kv := range sec.O {
		if !wantKeys[kv.K] {
			t.Errorf("unexpected section key %q", kv.K)
		}
	}
}
