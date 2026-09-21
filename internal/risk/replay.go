package risk

// The replayability calculator (framework-plan-v1.6 §2.4): Sherlock's rule as
// a declared impact transform — a single-shot loss repeatable without bound is
// scored as TOTAL loss, not per-shot magnitude. Two quantities come out of
// this and must never be conflated in a report: DEMONSTRATED (what the
// verification run actually extracted) and COMPUTED (the arithmetic
// extrapolation to the pool). Presenting the second as the first is
// misrepresentation, and on Immunefi that is a zero-payout violation.

import (
	"fmt"
	"math"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ReplayRuleCited is the rule a replay record cites: the Sherlock
// replayability rule, the §2.4 transform this calculator implements.
const ReplayRuleCited = "sherlock-replayability"

// ComputeReplay builds the §2.4 replay record. poolUSD is the value at stake
// (the finding's --max-loss): the ceiling a replay can reach. frequencyPerDay
// is optional; when absent the time-to-exhaustion figure is omitted rather
// than guessed.
func ComputeReplay(demonstratedRounds int64, extractedPerRound, poolUSD,
	gasCostUSD float64, frequencyPerDay *float64) validation.Value {
	rounds := int64(0)
	if extractedPerRound > 0 {
		rounds = int64(math.Ceil(poolUSD / extractedPerRound))
	}
	cost := float64(rounds) * gasCostUSD
	computed := validation.VObj(
		validation.KV{K: "rounds_to_exhaustion", V: validation.VInt(rounds)},
		validation.KV{K: "ceiling_usd", V: validation.VFloat(poolUSD)},
		validation.KV{K: "cumulative_attack_cost_usd", V: validation.VFloat(cost)},
	)
	if frequencyPerDay != nil && *frequencyPerDay > 0 {
		computed.O = validation.SetOrAppend(computed.O, "time_to_exhaustion_days",
			validation.VFloat(float64(rounds) / *frequencyPerDay))
	}
	return validation.VObj(
		validation.KV{K: "demonstrated", V: validation.VObj(
			validation.KV{K: "rounds_run", V: validation.VInt(demonstratedRounds)},
			validation.KV{K: "extracted_usd_per_round", V: validation.VFloat(extractedPerRound)},
		)},
		validation.KV{K: "computed", V: computed},
		validation.KV{K: "rule_cited", V: validation.VStr(ReplayRuleCited)},
		validation.KV{K: "replay_assumptions", V: validation.VArr()},
		validation.KV{K: "replay_blockers", V: validation.VArr()},
	)
}

// SetReplayAssumptions replaces the record's two text arrays: the assumptions
// the extrapolation rests on, and the blockers that make an otherwise
// refused (unprofitable) record recordable.
func SetReplayAssumptions(rec validation.Value, assumptions,
	blockers []string) validation.Value {
	rec.O = validation.SetOrAppend(rec.O, "replay_assumptions",
		validation.VArr(strValues(assumptions)...))
	rec.O = validation.SetOrAppend(rec.O, "replay_blockers",
		validation.VArr(strValues(blockers)...))
	return rec
}

// ValidateReplayProfitability refuses the absurd case: an attack that costs
// more than it extracts cannot be scored as a total loss. The escape is a
// recorded blocker (the cost figure is wrong, or the pool is not the ceiling),
// not silence.
func ValidateReplayProfitability(rec validation.Value) error {
	comp := validation.ObjAt(rec, "computed")
	cost := validation.ObjAt(comp, "cumulative_attack_cost_usd").F
	ceiling := validation.ObjAt(comp, "ceiling_usd").F
	if cost <= ceiling {
		return nil
	}
	if len(validation.ObjAt(rec, "replay_blockers").A) > 0 {
		return nil
	}
	return fmt.Errorf("replay is unprofitable: attack cost %.2f exceeds the "+
		"ceiling %.2f — record a replay_blocker or drop the total-loss claim",
		cost, ceiling)
}

// RecordReplay writes the replay block onto the finding under `replay` and
// logs exactly one finding.replay_recorded event (SaveThenLog: the projection
// write unwinds if the ledger write fails). The profitability law is checked
// HERE, before any byte is written, so a refused record leaves the finding
// untouched — same discipline as the §2.2 ordering law.
func RecordReplay(c *state.Campaign, findingID string, rec validation.Value,
	ruleCited, actor string) (validation.Value, error) {
	if err := ValidateReplayProfitability(rec); err != nil {
		return validation.VNull(), err
	}
	if ruleCited != "" {
		rec.O = validation.SetOrAppend(rec.O, "rule_cited",
			validation.VStr(ruleCited))
	}
	if actor == "" {
		actor = "operator"
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	f.O = validation.SetOrAppend(f.O, "replay", rec)
	if err := findings.SaveThenLog(c, &f, func() error {
		data := validation.VObj(
			validation.KV{K: "rule_cited", V: validation.ObjAt(rec, "rule_cited")},
			validation.KV{K: "actor", V: validation.VStr(actor)},
		)
		_, lerr := c.Log("finding.replay_recorded", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// strValues is the local []string → []Value conversion (the plan's
// deliberately-duplicated four-liner; see the Global Constraints).
func strValues(items []string) []validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return out
}
