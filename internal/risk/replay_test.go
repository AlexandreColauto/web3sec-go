package risk

import (
	"math"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

func TestComputeReplaySeparatesDemonstratedFromComputed(t *testing.T) {
	freq := 1000.0
	rec := ComputeReplay(2, 500, 1000000, 0.05, &freq)
	demo := validation.ObjAt(rec, "demonstrated")
	if got := validation.ObjAt(demo, "rounds_run").I; got != 2 {
		t.Fatalf("rounds_run = %d, want 2", got)
	}
	if got := validation.ObjAt(demo, "extracted_usd_per_round").F; got != 500 {
		t.Fatalf("extracted_usd_per_round = %v", got)
	}
	comp := validation.ObjAt(rec, "computed")
	if got := validation.ObjAt(comp, "rounds_to_exhaustion").I; got != 2000 {
		t.Fatalf("rounds_to_exhaustion = %d, want 2000", got)
	}
	if got := validation.ObjAt(comp, "ceiling_usd").F; got != 1000000 {
		t.Fatalf("ceiling_usd = %v, want the pool", got)
	}
	// 2000 rounds * 0.05 gas = 100 USD of attack cost.
	if got := validation.ObjAt(comp, "cumulative_attack_cost_usd").F; math.Abs(got-100) > 1e-9 {
		t.Fatalf("cumulative_attack_cost_usd = %v, want 100", got)
	}
	// 2000 rounds at 1000 rounds/day = 2 days.
	if got := validation.ObjAt(comp, "time_to_exhaustion_days").F; math.Abs(got-2) > 1e-9 {
		t.Fatalf("time_to_exhaustion_days = %v, want 2", got)
	}
	if got := validation.ObjStr(rec, "rule_cited"); got != "sherlock-replayability" {
		t.Fatalf("rule_cited = %q", got)
	}
}

func TestComputeReplayRoundsUpAPartialFinalRound(t *testing.T) {
	rec := ComputeReplay(2, 300, 1000, 0, nil)
	if got := validation.ObjAt(validation.ObjAt(rec, "computed"), "rounds_to_exhaustion").I; got != 4 {
		t.Fatalf("rounds_to_exhaustion = %d, want 4 (ceil(1000/300))", got)
	}
}

// TestReplayProfitabilityIsRequired: an attack that costs more than the pool
// cannot be scored as a total loss without a recorded blocker.
func TestReplayProfitabilityIsRequired(t *testing.T) {
	// 1 round to exhaust a 1000 USD pool, 5000 USD of gas: absurd.
	absurd := ComputeReplay(2, 1000, 1000, 5000, nil)
	if err := ValidateReplayProfitability(absurd); err == nil ||
		!strings.Contains(err.Error(), "unprofitable") {
		t.Fatalf("err = %v, want the profitability refusal", err)
	}
	absurd = SetReplayAssumptions(absurd, nil,
		[]string{"gas estimate assumes mainnet priority fees; measured 0.05/round"})
	if err := ValidateReplayProfitability(absurd); err != nil {
		t.Fatalf("blocked record refused: %v", err)
	}
	if err := ValidateReplayProfitability(ComputeReplay(2, 1000, 1000, 100, nil)); err != nil {
		t.Fatalf("profitable record refused: %v", err)
	}
}

// TestRecordReplayWritesProjectionAndOneEvent: the write path stores the block
// under `replay` with exactly one finding.replay_recorded event, and refuses an
// unprofitable record with the finding byte-identical (no half-land).
func TestRecordReplayWritesProjectionAndOneEvent(t *testing.T) {
	c := riskCamp(t)
	fid := ingest(t, c)
	rec := SetReplayAssumptions(ComputeReplay(2, 500, 1000, 0.05, nil), nil,
		[]string{"gas measured at 0.05/round"})
	if _, err := RecordReplay(c, fid, rec, ReplayRuleCited, "op"); err != nil {
		t.Fatalf("record: %v", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(f, "replay").Kind; got != validation.Obj {
		t.Fatalf("finding.replay kind = %v, want an object", got)
	}
	if got := r40dEventCount(t, c, "finding.replay_recorded"); got != 1 {
		t.Fatalf("finding.replay_recorded events = %d, want 1", got)
	}
	before := r40dSha(t, findingsPathFor(t, c, fid))
	if _, err := RecordReplay(c, fid, ComputeReplay(2, 500, 500, 5000, nil),
		ReplayRuleCited, "op"); err == nil {
		t.Fatal("an unprofitable record was accepted on the write path")
	}
	if got := r40dSha(t, findingsPathFor(t, c, fid)); got != before {
		t.Fatal("the refused record moved the finding bytes")
	}
}
