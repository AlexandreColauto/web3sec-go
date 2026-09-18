// Risk — economic exposure: economic_risk in value and float form, plus the bounty score (split from risk.go; pure structural move).

package risk

import (
	"math"

	"websec/internal/validation"
)

// EconomicRisk is economic_risk: theoretical exposure and realistic
// extraction are different numbers; both are recorded. The args are raw JSON
// values because Python passes the caller's int/float identity through to
// the result (an int stays an int in the stored finding).
func EconomicRisk(maxLossUSD, extractableUSD, capitalRequiredUSD validation.Value) validation.Value {
	out, err := economicRisk(maxLossUSD, extractableUSD, capitalRequiredUSD)
	if err != nil {
		return validation.VNull() // economic_risk's contract: null on unusable input
	}
	return out
}

// EconomicRiskFloat is the nil-tolerant numeric form of EconomicRisk for
// callers that hold Go floats (nil = Python None).
func EconomicRiskFloat(maxLossUSD, extractableUSD, capitalRequiredUSD *float64) validation.Value {
	out, err := economicRisk(optNum(maxLossUSD), optNum(extractableUSD),
		optNum(capitalRequiredUSD))
	if err != nil {
		return validation.VNull() // economic_risk's contract: null on unusable input
	}
	return out
}

// economicRisk is economic_risk on raw JSON values so that an int stays an
// int in the stored finding (Python passes impact.get(...) through).
func economicRisk(maxLoss, extractable, capital validation.Value) (validation.Value, error) {
	var lev validation.Value = validation.VNull()
	if extractable.Kind != validation.Null && capital.Kind != validation.Null &&
		!isZeroNum(capital) {
		ex, err := asFloat(extractable)
		if err != nil {
			return validation.VNull(), err
		}
		ca, err := asFloat(capital)
		if err != nil {
			return validation.VNull(), err
		}
		lev = validation.VFloat(validation.PythonRound(ex/ca, 3))
	}
	return validation.VObj(
		validation.KV{K: "extractable_usd", V: extractable},
		validation.KV{K: "capital_required_usd", V: capital},
		validation.KV{K: "leverage_ratio", V: lev},
		validation.KV{K: "notes", V: validation.VStr(
			"max_loss_usd recorded on economic_impact; extractable is bounded " +
				"by on-chain liquidity, not by the theoretical exposure")},
	), nil
}

// isZeroNum is Python's `capital_required_usd not in (None, 0)`: numeric
// zero (and -0.0, and false) compares equal to 0.
func isZeroNum(v validation.Value) bool {
	switch v.Kind {
	case validation.Int:
		return v.Big == "" && v.I == 0
	case validation.Flt:
		return v.F == 0
	case validation.Bool:
		return !v.B
	}
	return false
}

// BountyScore is bounty_score: advisory prioritization number in [0, 10].
// Deliberately simple: it orders human/compute attention, it does NOT decide
// submission. eligibility nil = Python None (not False).
func BountyScore(risk validation.Value, eligibility *bool, amplifierBonus float64) float64 {
	base := numOrZero(validation.ObjAt(validation.ObjAt(risk, "validated"), "score"))
	econ := numOrZero(validation.ObjAt(validation.ObjAt(risk, "economic"), "extractable_usd"))
	bonus := 0.0
	if econ >= 100_000 {
		bonus = 1.0
	} else if econ > 0 {
		bonus = 0.5
	}
	score := math.Min(10.0, base+bonus+math.Max(0.0, amplifierBonus))
	if eligibility != nil && !*eligibility {
		score = math.Min(score, 4.0)
	}
	return validation.PythonRound(score, 2)
}

// ---- impact vector: the computed half of severity -------------------------
// The model's self-assessed severity is data (reported_severity), not a
// verdict. This vector is what the framework computes from recorded fields:
// four named components, each banded, each weighted. Advisory — display-only
// in the report, never the confirmation gate, ordering, or validated_risk.
