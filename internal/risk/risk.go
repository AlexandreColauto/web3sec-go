// Package risk is the port of webv2/risk.py: three-pass risk calibration.
//
// Risk is computed at three distinct moments and each answers a different
// question — never one score:
//
//	prior_risk      (0..1, at triage)   "is this worth validating at all?"
//	validated_risk  (1..10, post-proof) "how bad is this, given the evidence?"
//	economic_risk   (USD, post-proof)   "what is actually extractable given
//	                                     on-chain liquidity?"
//	bounty_score    (advisory)          prioritization only; a score never
//	                                     replaces the evidence gate.
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/validation"
)

// wBlast is _W_BLAST: deterministic weight table for validated_risk (1..10).
var wBlast = map[string]float64{
	"single-user": 1.0, "subset-of-users": 3.0, "all-users": 5.0,
	"protocol-solvency": 7.0, "bridge-canonical": 8.0,
}

// wLevel is _W_LEVEL, keyed by evidence level E0..E7.
var wLevel = map[string]float64{
	"E0": 0.0, "E1": 0.5, "E2": 1.0, "E3": 1.5, "E4": 2.0,
	"E5": 2.5, "E6": 3.0, "E7": 3.0,
}

// wReversibility is the victim-perspective recoverability weight inside
// validated_risk (IMPROVEMENTS E5): funds the victim can never get back are
// worse than funds a trusted party might return at its discretion, which are
// worse than funds the victim or the protocol can restore. The field is
// ABSENT by default — a finding that never classified recoverability scores
// exactly as before (0.0 contribution), so existing campaigns are
// byte-identical.
var wReversibility = map[string]float64{
	"irreversible": 3.0, "trusted-party": 2.0, "reversible": 0.0,
}

// priorBase is the triage base table inside prior_risk.
var priorBase = map[string]float64{
	"access-control": 0.9, "authorization": 0.9, "upgrade-initializer": 0.85,
	"oracle-manipulation": 0.8, "flash-loan": 0.75, "share-price-inflation": 0.8,
	"bridge-message": 0.85, "cross-chain-replay": 0.85, "reentrancy": 0.7,
	"economic-invariant": 0.7, "liquidation-logic": 0.75, "precision-rounding": 0.5,
	"dos-griefing": 0.45, "logic-error": 0.5, "token-integration": 0.55,
}

// PriorRisk is prior_risk: cheap, explainable triage score in [0, 1].
// invariantID nil/empty and capitalUSD nil mirror Python's None.
func PriorRisk(bugClass string, reachableUnprivileged, requiresForkState,
	historicalAnalog bool, invariantID *string, capitalUSD *float64) validation.Value {
	base, ok := priorBase[bugClass]
	if !ok {
		base = 0.4
	}
	score := base
	factors := []string{"base(" + bugClass + ")=" + validation.PythonFloat(base)}
	if reachableUnprivileged {
		score += 0.1
		factors = append(factors, "unprivileged-reachable +0.1")
	}
	if historicalAnalog {
		score += 0.08
		factors = append(factors, "historical-analog +0.08")
	}
	if invariantID != nil && *invariantID != "" {
		score += 0.05
		factors = append(factors, "tied-to-invariant +0.05")
	}
	if capitalUSD != nil && *capitalUSD > 1_000_000 {
		score -= 0.05
		factors = append(factors, "high-capital-requirement -0.05")
	}
	if requiresForkState {
		score += 0.02
		factors = append(factors, "fork-state-dependent +0.02")
	}
	return validation.VObj(
		validation.KV{K: "score",
			V: validation.VFloat(validation.PythonRound(math.Min(score, 1.0), 3))},
		validation.KV{K: "factors", V: validation.StrArr(factors)},
	)
}

// ValidationCost is validation_cost: cheap / standard / expensive — used by
// the planner's decision rule.
func ValidationCost(class string, needsFork, needsSymbolic bool) string {
	if needsFork || class == "bridge-message" || class == "cross-chain-replay" {
		return "expensive"
	}
	if needsSymbolic || class == "economic-invariant" ||
		class == "oracle-manipulation" {
		return "standard"
	}
	return "cheap"
}

// AmplifierBonus is amplifier_bonus: advisory +0.5 per distinct amplifier in
// (playbook tags ∩ detected signals), capped at 1.0. A medium flaw touching
// two live amplifiers sorts above one that touches none — ordering context,
// never a gate.
func AmplifierBonus(playbookTags []string, detected validation.Value) (float64, []string) {
	tags := make(map[string]struct{}, len(playbookTags))
	for _, t := range playbookTags {
		tags[t] = struct{}{}
	}
	hit := []string{}
	for _, kv := range detected.O {
		if _, ok := tags[kv.K]; ok {
			hit = append(hit, kv.K)
		}
	}
	sort.Strings(hit)
	return validation.PythonRound(math.Min(0.5*float64(len(hit)), 1.0), 2), hit
}

// ValidatedRisk is validated_risk: deterministic 1..10 score from recorded
// finding fields. 10 = protocol-wide loss, independently reproduced, no
// controls. The band mapping follows Immunefi-style conventions.
func ValidatedRisk(finding validation.Value) (validation.Value, error) {
	score, rationale, err := validatedScore(finding)
	if err != nil {
		return validation.VNull(), err
	}
	score = math.Max(1.0, math.Min(10.0, score))
	return validation.VObj(
		validation.KV{K: "score",
			V: validation.VFloat(validation.PythonRound(score, 2))},
		validation.KV{K: "band", V: validation.VStr(riskBand(score))},
		validation.KV{K: "rationale", V: validation.VStr(strings.Join(rationale, "; "))},
	), nil
}

// validatedScore is the arithmetic half of validated_risk: the score before
// the 1..10 clamp plus the rationale lines in Python's append order.
func validatedScore(finding validation.Value) (float64, []string, error) {
	impact := orObj(validation.ObjAt(finding, "economic_impact"))
	blast := blastRadius(impact)
	score := 2.0
	if w, ok := wBlast[blast]; ok {
		score = w
	}
	rationale := []string{"blast_radius(" + blast + ")=" + validation.PythonFloat(score)}
	level, err := findings.FindingLevel(finding)
	if err != nil {
		return 0, nil, err
	}
	lw := 0.5
	if w, ok := wLevel[level]; ok {
		lw = w
	}
	score += lw
	rationale = append(rationale, "evidence("+level+")=+"+validation.PythonFloat(lw))
	if n := pyLen(privilegesOf(finding)); n == 0 {
		score += 1.0
		rationale = append(rationale, "unprivileged-attacker +1.0")
	} else {
		rationale = append(rationale, fmt.Sprintf("privileged (%d) +0", n))
	}
	if ev, ok := fieldAt(impact, "extractable_usd"); ok && ev.Kind != validation.Null {
		usd, err := asFloat(ev)
		if err != nil {
			return 0, nil, err
		}
		bump := extractableBump(usd)
		score += bump
		rationale = append(rationale,
			"extractable($"+pyUsd0f(usd)+") +"+validation.PythonFloat(bump))
	}
	// Reversibility (IMPROVEMENTS E5): the victim-perspective recoverability
	// classification, when present. Absent field = no line, no weight — the
	// byte-identical guarantee for findings that never classified it.
	if rv := orStr(validation.ObjAt(orObj(validation.ObjAt(finding, "risk")), "reversibility")); rv != "" {
		if w, ok := wReversibility[rv]; ok {
			score += w
			rationale = append(rationale,
				"reversibility("+rv+") +"+validation.PythonFloat(w))
		} else {
			// An unrecognized value contributes nothing but is surfaced, so a
			// typo can never silently inflate or deflate the band.
			rationale = append(rationale,
				"reversibility("+rv+") +0.0 (unrecognized)")
		}
	}
	return score, rationale, nil
}

// extractableBump is the nested conditional in validated_risk.
func extractableBump(usd float64) float64 {
	switch {
	case usd >= 10_000_000:
		return 1.0
	case usd >= 1_000_000:
		return 0.7
	case usd >= 100_000:
		return 0.4
	case usd > 0:
		return 0.2
	}
	return 0.0
}

// riskBand is the band ladder at the tail of validated_risk.
func riskBand(score float64) string {
	switch {
	case score >= 8.5:
		return "critical"
	case score >= 6.5:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 2.0:
		return "low"
	}
	return "informational"
}

// blastRadius is impact.get("blast_radius", "subset-of-users"): the default
// applies only when the key is absent (a present null renders as "None").
func blastRadius(impact validation.Value) string {
	if v, ok := fieldAt(impact, "blast_radius"); ok {
		return validation.PyStr(v)
	}
	return "subset-of-users"
}

// privilegesOf is (finding.get("attacker") or {}).get("required_privileges").
func privilegesOf(finding validation.Value) validation.Value {
	return validation.ObjAt(orObj(validation.ObjAt(finding, "attacker")), "required_privileges")
}
