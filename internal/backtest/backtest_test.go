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
func mkCase(id, partition, class, outcome, severity string) validation.Value {
	gold := []validation.KV{
		{K: "outcome", V: validation.VStr(outcome)},
		{K: "bug_class", V: validation.VStr(class)},
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

func TestCriticalBandScoresZeroAndCoverageCountsIt(t *testing.T) {
	cases := []validation.Value{
		mkCase("CASE-0000000000d1", "dev", "reentrancy",
			"confirmed-exploitable", "high"),
		mkCase("CASE-0000000000d2", "dev", "reentrancy",
			"disproved", "low"),
		mkCase("CASE-0000000000h1", "held-out", "reentrancy",
			"confirmed-exploitable", "critical"),
		mkCase("CASE-0000000000h2", "held-out", "reentrancy",
			"confirmed-exploitable", "high"),
		mkCase("CASE-0000000000h3", "held-out", "reentrancy",
			"disproved", "low"),
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
}

func TestPseudoFindingCriticalIsBandless(t *testing.T) {
	// Unit honesty: a critical severity builds a bandless pseudo-finding
	// (0 from severity — score-indistinguishable from a null-severity
	// row, but labeled by BandLine and the coverage count, never
	// silent), while a representable band still carries through.
	pf := pseudoFinding("reentrancy", "critical")
	if got := objAt(objAt(pf, "risk"), "validated"); got.Kind != validation.Null {
		t.Fatalf("critical pseudo-finding carries validated = %v, want bandless", got)
	}
	pfHigh := pseudoFinding("reentrancy", "high")
	if got := orStr(objAt(objAt(objAt(pfHigh, "risk"), "validated"), "band")); got != "high" {
		t.Fatalf("high pseudo-finding band = %q, want high", got)
	}
}
