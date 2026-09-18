package backtest

// backtest_test: the band-coverage honesty contract (Task 12 fix round
// 1). The evaluation_case gold.severity enum has no critical slot, so a
// critical value can only reach Run outside the validated path — and the
// output must label that row's zero contribution instead of silently
// merging it with the null-severity rows.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// mkCase builds one eval row RAW (no AddCase): AddCase validates against
// the evaluation_case schema and rejects gold.severity "critical", so the
// out-of-band shape under test can only be constructed directly —
// exactly the hand-edit/bypass shape the honesty label exists for. Run
// itself reads only case_id, partition, and the gold outcome/class/
// severity keys, so no other field is needed.
//
// rootCause is I1b's third near-dup key component. Each fixture row needs
// a DISTINCT narrative: rows sharing only a bare class label collapse to
// the same DupKey (the validated store cannot produce that shape —
// gold.root_cause is required, minLength 10), and a test that trips the
// near-dup scan by accident would be testing the wrong thing.
func mkCase(id, partition, class, outcome, severity, rootCause string) validation.Value {
	gold := []validation.KV{
		{K: "outcome", V: validation.VStr(outcome)},
		{K: "bug_class", V: validation.VStr(class)},
		{K: "root_cause", V: validation.VStr(rootCause)},
	}
	if severity != "" {
		gold = append(gold,
			validation.KV{K: "severity", V: validation.VStr(severity)})
	}
	return validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(id)},
		validation.KV{K: "partition", V: validation.VStr(partition)},
		validation.KV{K: "gold", V: validation.VObj(gold...)},
	)
}

// mkDated is mkCase plus the two dates the I1b temporal rule reads.
// deployed == "" leaves the key absent (the store's absent-ok semantics).
func mkDated(id, partition, deployed, created, class, outcome,
	rootCause string) validation.Value {
	c := mkCase(id, partition, class, outcome, "high", rootCause)
	kv := []validation.KV{
		{K: "created_at", V: validation.VStr(created)},
	}
	if deployed != "" {
		kv = append(kv, validation.KV{K: "deployed_at", V: validation.VStr(deployed)})
	}
	c.O = append(c.O, kv...)
	return c
}

func TestCriticalBandScoresZeroAndCoverageCountsIt(t *testing.T) {
	cases := []validation.Value{
		mkCase("CASE-0000000000d1", "dev", "reentrancy",
			"confirmed-exploitable", "high",
			"withdraw sends funds before the balance update"),
		mkCase("CASE-0000000000d2", "dev", "reentrancy",
			"disproved", "low",
			"the queue reverts on a single failed target"),
		mkCase("CASE-0000000000h1", "held-out", "reentrancy",
			"confirmed-exploitable", "critical",
			"the signature digest omits the chain id"),
		mkCase("CASE-0000000000h2", "held-out", "reentrancy",
			"confirmed-exploitable", "high",
			"spot reserves price the borrow limit"),
		mkCase("CASE-0000000000h3", "held-out", "reentrancy",
			"disproved", "low",
			"initialize is callable by anyone"),
	}
	out, code := Run(cases, 3)
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, BandLine+"\n") {
		t.Fatalf("output must carry the bands honesty line:\n%s", out)
	}
	// The critical held-out row contributes no band: 2 of 3 rows count.
	if !strings.Contains(out,
		"band coverage: 2/3 rows contributed\n") {
		t.Fatalf("critical row must count as non-contributing:\n%s",
			out)
	}
	// Rows without dates order by created_at — here, all absent — so the
	// I1b discipline excludes nothing and prints no line for it.
	if strings.Contains(out, "held-out excluded:") {
		t.Fatalf("dateless rows must not be excluded:\n%s", out)
	}
}

func TestPseudoFindingCriticalIsBandless(t *testing.T) {
	// Unit honesty: a critical severity builds a bandless pseudo-finding
	// (0 from severity — score-indistinguishable from a null-severity
	// row, but labeled by BandLine and the coverage count, never
	// silent), while a representable band still carries through.
	pf := pseudoFinding("reentrancy", "critical")
	if got := validation.ObjAt(validation.ObjAt(pf, "risk"), "validated"); got.Kind != validation.Null {
		t.Fatalf("critical pseudo-finding carries validated = %v, want bandless", got)
	}
	pfHigh := pseudoFinding("reentrancy", "high")
	if got := orStr(validation.ObjAt(validation.ObjAt(validation.ObjAt(pfHigh, "risk"), "validated"), "band")); got != "high" {
		t.Fatalf("high pseudo-finding band = %q, want high", got)
	}
}

// ---- I1b (Wave I, Task 2): the exclusion line ---------------------------

// TestBacktestPrintsTemporalExclusionAndDropsTheRow: the held-out row is
// OLDER than the dev row it would be scored against, so it leaves the
// held-out leg. The line sits between the store census and the band
// coverage — and the coverage denominator proves the drop (1 surviving
// held-out row, not 2).
func TestBacktestPrintsTemporalExclusionAndDropsTheRow(t *testing.T) {
	cases := []validation.Value{
		mkDated("CASE-0000000000d1", "dev", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"withdraw sends funds before the balance update"),
		mkDated("CASE-0000000000h1", "held-out", "2026-01-01",
			"2026-12-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"the signature digest omits the chain id"),
		mkDated("CASE-0000000000h2", "held-out", "2026-05-01",
			"2026-12-01T00:00:00+00:00", "reentrancy",
			"disproved",
			"spot reserves price the borrow limit"),
	}
	out, code := Run(cases, 2)
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out)
	}
	want := "eval store: 3 adjudicated, 0 skipped\n" +
		"held-out excluded: 1 temporal, 0 near-dup\n" +
		"band coverage: 1/1 rows contributed\n"
	if !strings.Contains(out, want) {
		t.Fatalf("output must carry the exclusion line in place:\n%s", out)
	}
	// The excluded row is not ranked: the top-2 window sees one row.
	if !strings.Contains(out,
		"note: --top 2 clamped to 1 held-out cases\n") {
		t.Fatalf("excluded row still counted in the clamp:\n%s", out)
	}
}

// TestBacktestPrintsNearDupExclusion: the held-out row restates the dev
// row (same class + same root-cause narrative, so identical DupKeys and
// Jaccard 1.0 — the same by-construction pair the evalstore tests pin).
func TestBacktestPrintsNearDupExclusion(t *testing.T) {
	cases := []validation.Value{
		mkDated("CASE-0000000000d1", "dev", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"withdraw sends funds before the balance update"),
		mkDated("CASE-0000000000h1", "held-out", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"withdraw sends funds before the balance update"),
		mkDated("CASE-0000000000h2", "held-out", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"disproved",
			"spot reserves price the borrow limit"),
	}
	out, code := Run(cases, 2)
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out)
	}
	want := "eval store: 3 adjudicated, 0 skipped\n" +
		"held-out excluded: 0 temporal, 1 near-dup\n" +
		"held-out problem: near-dup CASE-0000000000h1 ~ " +
		"CASE-0000000000d1 1.0\n" +
		"band coverage: 1/1 rows contributed\n"
	if !strings.Contains(out, want) {
		t.Fatalf("output must carry the near-dup count and problem line:\n%s", out)
	}
}

// TestBacktestPrintsUnparseableProblem: a held-out row whose deployed_at
// cannot be parsed is excluded without being temporal or a duplicate, so
// NEITHER count moves (0 temporal, 0 near-dup) — and the problem line is
// what stops that from being a silent shrink of the scorecard.
func TestBacktestPrintsUnparseableProblem(t *testing.T) {
	cases := []validation.Value{
		mkDated("CASE-0000000000d1", "dev", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"withdraw sends funds before the balance update"),
		mkDated("CASE-0000000000h1", "held-out", "2026-1-1",
			"2026-12-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"the signature digest omits the chain id"),
		mkDated("CASE-0000000000h2", "held-out", "2026-05-01",
			"2026-12-01T00:00:00+00:00", "reentrancy",
			"disproved",
			"spot reserves price the borrow limit"),
	}
	out, code := Run(cases, 2)
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out)
	}
	want := "eval store: 3 adjudicated, 0 skipped\n" +
		"held-out excluded: 0 temporal, 0 near-dup\n" +
		"held-out problem: unparseable-deployed_at CASE-0000000000h1\n" +
		"band coverage: 1/1 rows contributed\n"
	if !strings.Contains(out, want) {
		t.Fatalf("output must name the unparseable row:\n%s", out)
	}
}

// TestBacktestCleanRunPrintsNoExclusionLine: the line is presence-gated,
// so a clean store's bytes do not move. Two comparable, non-duplicate
// held-out rows keep the whole leg.
func TestBacktestCleanRunPrintsNoExclusionLine(t *testing.T) {
	cases := []validation.Value{
		mkDated("CASE-0000000000d1", "dev", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"withdraw sends funds before the balance update"),
		mkDated("CASE-0000000000h1", "held-out", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"the signature digest omits the chain id"),
		mkDated("CASE-0000000000h2", "held-out", "2026-06-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"disproved",
			"spot reserves price the borrow limit"),
	}
	out, code := Run(cases, 2)
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "excluded") {
		t.Fatalf("a clean run must not grow a line:\n%s", out)
	}
	if !strings.Contains(out, "band coverage: 2/2 rows contributed\n") {
		t.Fatalf("both held-out rows must rank:\n%s", out)
	}
}

// TestBacktestFullyExcludedHeldOutExitsEmpty: exclusion happens BEFORE the
// emptiness check, so a held-out set that lost every row falls through the
// EXISTING EmptyMessage path — exit 2, no verdict over nothing.
func TestBacktestFullyExcludedHeldOutExitsEmpty(t *testing.T) {
	cases := []validation.Value{
		mkDated("CASE-0000000000d1", "dev", "2026-05-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"withdraw sends funds before the balance update"),
		mkDated("CASE-0000000000h1", "held-out", "2026-01-01",
			"2026-01-01T00:00:00+00:00", "reentrancy",
			"confirmed-exploitable",
			"the signature digest omits the chain id"),
	}
	out, code := Run(cases, 2)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EmptyMessage path)\n%s", code, out)
	}
	if out != EmptyMessage {
		t.Fatalf("out = %q\nwant EmptyMessage %q", out, EmptyMessage)
	}
}
