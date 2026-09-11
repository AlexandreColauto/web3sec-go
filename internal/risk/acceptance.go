package risk

// acceptance.go — IMPROVEMENTS A3: the deterministic acceptance score.
//
// The framework's failed behavior: 23 critic-confirmed findings against 2
// gold bugs, and no answer to "which 5 are worth paying attention to". The
// score answers that per finding, from recorded fields only — no model, no
// sampling, the same input always yields the same number:
//
//	acceptance = wSeverity(band) + wEvidence(level) + wCritic(verdict)
//	           - wAck(dedup_meta.in_code_ack present)
//	           - wAcceptedRisk(bounty.accepted_risk recorded)
//	           + wCorroboration(dedup_meta.corroborated_by) = +0.5 (G1)
//	           + outlook(verification.triager_outlook) = ±0.5 (G6)
//	           + wReversibility(risk.reversibility)
//	           + wPrior(class base rate over adjudicated outcomes, G3 —
//	             policy-gated OFF via AcceptanceWithPriors, default 0;
//	             applied LAST, just before the floor clamp)
//
// Weights (the validated_risk wLevel table is reused for evidence, so the
// score and the 1..10 band can never disagree about what E4 is worth):
//
//	severity   critical 3.0 / high 2.0 / medium 1.0 / low 0.5
//	evidence   E0 0.0 ... E7 3.0            (wLevel)
//	critic     confirmed +1.5 / disproved -2.0 (disqualified) / else 0
//	ack        -1.0 when the finding sits in acknowledged code (A2)
//	risk       -2.0 when the program documented the risk as accepted (A1)
//	reversib.  irreversible +1.0 / trusted-party +0.5 / reversible 0
//
// The critic column keys on the REAL critic_verdict enum
// (pending/confirmed/possible/disproved/duplicate/out_of_scope/informational).
// Only 'confirmed' is worth something and only an ACTIVE refutation
// ('disproved') DISQUALIFIES the finding — it drops out of the top-K table
// entirely in addition to its weight. The non-committal verdicts
// (pending/possible/informational) and the scope verdicts (duplicate /
// out_of_scope, which the live-set filter already removes) contribute 0:
// the score ranks findings, it never invents a refutation the critic did not
// record. The score is clamped at 0: a number this low means "do not spend
// reviewer time here", and negative likelihood is not a thing.

import (
	"fmt"
	"math"
	"sort"

	"websec/internal/findings"
	"websec/internal/validation"
)

// wAcceptanceSeverity keys on validated_risk.band (riskBand's ladder).
var wAcceptanceSeverity = map[string]float64{
	"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5,
}

// wAcceptanceCritic keys on verification.critic_verdict — the real enum from
// the finding schema (pending/confirmed/possible/disproved/duplicate/
// out_of_scope/informational). Only 'confirmed' adds weight and only
// 'disproved' subtracts; every other verdict is absent from the table (0),
// so a non-committal or scope verdict never moves the score.
var wAcceptanceCritic = map[string]float64{
	"confirmed": 1.5,
	"disproved": -2.0,
}

// Acceptance demotions (A2 in-code acknowledgement, A1 accepted risk).
const (
	acceptanceAckDemotion        = 1.0
	acceptanceRiskDemotion       = 2.0
	acceptanceCorroborationBonus = 0.5
	acceptanceDefaultTopK        = 10
)

// wAcceptanceOutlook is the G6 nudge table: bounded, symmetric, and absent
// outcomes contribute nothing (same posture as reversibility). The key SET
// is asserted equal to findings.TriagerOutlooks() by TestOutlookEnumSync —
// adding an outcome to the enum without a weight here (or without one
// there) fails a test, not a campaign.
var wAcceptanceOutlook = map[string]float64{"likely": 0.5, "uncertain": 0.0, "unlikely": -0.5}

// wAcceptanceReversibility is the acceptance-likelihood half of the E5
// classification: funds that are gone forever are worth reviewing first.
// Deliberately NOT wReversibility (3.0/2.0/0.0): that table prices the
// DAMAGE inside validated_risk; here it only breaks severity ties in the
// reviewer's queue.
var wAcceptanceReversibility = map[string]float64{
	"irreversible": 1.0, "trusted-party": 0.5, "reversible": 0.0,
}

// AcceptanceEntry is one scored finding: the clamped score, the
// disqualification flag, and which demotions fired (for the table's
// demotion markers). PriorFactor/Prior are the G3 calibrated prior term:
// additive, omitempty, and set ONLY when the prior clause fires — a zero
// entry renders exactly as before (the AckDemoted presence pattern: no
// marker, no JSON key, no byte moves when the term is absent).
type AcceptanceEntry struct {
	Finding      validation.Value
	Score        float64
	Disqualified bool
	AckDemoted   bool
	RiskDemoted  bool
	Corroborated bool
	PriorFactor  float64 `json:"prior_factor,omitempty"`
	Prior        string  `json:"prior,omitempty"`
}

// Acceptance computes the full entry. Every component is optional: an
// absent field contributes 0, exactly like the E5 reversibility factor, so
// a bare HYPOTHESIS scores 0.0 and nothing panics on partial findings.
//
// Byte law: Acceptance is AcceptanceWithPriors with nil priors, and the
// prior clause runs ONLY when priors != nil — so the default path cannot
// move one float.
func Acceptance(finding validation.Value) AcceptanceEntry {
	return AcceptanceWithPriors(finding, nil, Prior{})
}

// AcceptanceWithPriors computes the full entry with the G3 calibrated
// class prior (wPrior). Body is Acceptance's, verbatim, plus the prior
// clause after ALL existing terms and just before the floor clamp: the
// term participates in the clamp like every other weight, and nil priors
// yield BIT-IDENTICAL results (x+0.0 == x exactly — the clause is skipped
// wholesale, not added as zero).
//
// The clause fires only when every gate holds: priors != nil, the
// finding's root_cause.class is known in the map, the class prior is not
// a fallback, and its n >= DefaultMinN (the thickness the priors'
// producer demands). The term is the verbatim law:
//
//	wPrior = clamp(2*(rate - global.rate) * min(1, n/30), -0.5, +0.5)
//
// Presence-gated in both score and entry: when the gates fail — or the
// term computes to exactly zero — score is untouched AND PriorFactor/Prior
// stay zero-valued (omitempty ⇒ absent in every rendering).
func AcceptanceWithPriors(finding validation.Value, priors map[string]Prior,
	global Prior) AcceptanceEntry {
	e := AcceptanceEntry{Finding: finding}
	score := 0.0

	riskObj := orObj(objAt(finding, "risk"))

	// severity band (validated_risk, when the impact has been validated)
	if band := orStr(objAt(orObj(objAt(riskObj, "validated")), "band")); band != "" {
		if w, ok := wAcceptanceSeverity[band]; ok {
			score += w
		}
		// an unrecognized band contributes nothing (same posture as E5's
		// unknown reversibility: surface in the band text, never invent)
	}

	// evidence level — the validated_risk wLevel table (E0 0.0 .. E7 3.0)
	level, err := findings.FindingLevel(finding)
	if err == nil {
		if w, ok := wLevel[level]; ok {
			score += w
		}
	}

	// hostile-critic verdict (the real enum; only confirmed / disproved are
	// worth anything — see wAcceptanceCritic)
	if v := orStr(objAt(orObj(objAt(finding, "verification")),
		"critic_verdict")); v != "" {
		if w, ok := wAcceptanceCritic[v]; ok {
			score += w
			e.Disqualified = v == "disproved"
		}
	}

	// triager outlook (G6): likelihood call under the live policy, bounded
	// and never disqualifying — only the critic disproves.
	if o := objAt(orObj(objAt(finding, "verification")), "triager_outlook"); o.Kind ==
		validation.Obj {
		if w, ok := wAcceptanceOutlook[orStr(objAt(o, "outcome"))]; ok {
			score += w
		}
	}

	// demotions
	if a := objAt(orObj(objAt(finding, "dedup_meta")), "in_code_ack"); a.Kind ==
		validation.Obj {
		score -= acceptanceAckDemotion
		e.AckDemoted = true
	}
	if ar := objAt(orObj(objAt(finding, "bounty")), "accepted_risk"); ar.Kind ==
		validation.Obj {
		score -= acceptanceRiskDemotion
		e.RiskDemoted = true
	}

	// corroboration (G1): operator-resolved same-root-cause pair where the
	// partner is SAST-flagged; recorded by dedup.ResolveCandidate, consumed
	// here. Absent => 0, so existing bytes never move.
	if cb := objAt(orObj(objAt(finding, "dedup_meta")), "corroborated_by"); cb.Kind ==
		validation.Str && cb.S != "" {
		score += acceptanceCorroborationBonus
		e.Corroborated = true
	}

	// reversibility (E5 classification)
	if rv := orStr(objAt(riskObj, "reversibility")); rv != "" {
		if w, ok := wAcceptanceReversibility[rv]; ok {
			score += w
		}
	}

	// prior (G3 wPrior): the class base rate over adjudicated outcomes,
	// policy-gated OFF at the caller (risk stays pure — the caller resolves
	// the flag and the priors). LAST in the addition chain, just before
	// the clamp: document position — a late term still clamps, an early
	// one would too, but only this position keeps "nil priors ⇒ the old
	// bytes" provable by inspection (everything above is untouched).
	if priors != nil {
		cls := orStr(objAt(orObj(objAt(finding, "root_cause")), "class"))
		if p, ok := priors[cls]; ok && !p.Fallback && p.N >= DefaultMinN {
			term := 2 * (p.Rate - global.Rate) *
				math.Min(1, float64(p.N)/30)
			if term > 0.5 {
				term = 0.5
			} else if term < -0.5 {
				term = -0.5
			}
			score += term
			if term != 0 {
				e.PriorFactor = term
				e.Prior = p.Render()
			}
		}
	}

	if score < 0 {
		score = 0
	}
	e.Score = score
	return e
}

// AcceptanceScore is the (score, disqualified) convenience for callers that
// only need the number (the gate stores it; the ranking uses Acceptance).
func AcceptanceScore(finding validation.Value) (float64, bool) {
	e := Acceptance(finding)
	return e.Score, e.Disqualified
}

// AcceptanceRanking builds the ranking the report's top-K table and
// `webv2 rank` print. by is "acceptance" (default) or "severity"; anything
// else falls back to acceptance. Order: qualified rows first, then
// disqualified; within each group by the chosen key, ties broken by
// finding_id so two runs over the same tree always print the same table.
//
// Byte law: AcceptanceRanking delegates with nil priors, so NO current
// caller changes behavior.
func AcceptanceRanking(fs []validation.Value, by string) []AcceptanceEntry {
	return AcceptanceRankingWithPriors(fs, by, nil, Prior{})
}

// AcceptanceRankingWithPriors is the campaign-aware ranking hub: the
// caller (a layer that holds the campaign policy) resolves the
// acceptance_priors flag, calls AcceptancePriors once, and passes the map
// here. Nil priors score every finding with Acceptance exactly.
func AcceptanceRankingWithPriors(fs []validation.Value, by string,
	priors map[string]Prior, global Prior) []AcceptanceEntry {
	entries := make([]AcceptanceEntry, 0, len(fs))
	for _, f := range fs {
		entries = append(entries, AcceptanceWithPriors(f, priors, global))
	}
	less := func(a, b AcceptanceEntry) bool {
		if a.Disqualified != b.Disqualified {
			return !a.Disqualified
		}
		switch by {
		case "severity":
			ra := bandRankOr(validatedBandOf(a.Finding), -1)
			rb := bandRankOr(validatedBandOf(b.Finding), -1)
			if ra != rb {
				return ra > rb
			}
			va := validatedScoreOf(a.Finding)
			vb := validatedScoreOf(b.Finding)
			if va != vb {
				return va > vb
			}
		default: // "acceptance"
			if a.Score != b.Score {
				return a.Score > b.Score
			}
		}
		return findingIDOf(a.Finding) < findingIDOf(b.Finding)
	}
	sort.SliceStable(entries, func(i, j int) bool { return less(entries[i], entries[j]) })
	return entries
}

func findingIDOf(f validation.Value) string { return orStr(objAt(f, "finding_id")) }

func validatedScoreOf(f validation.Value) float64 {
	riskObj := orObj(objAt(f, "risk"))
	validated := objAt(riskObj, "validated")
	return numOrZero(objAt(validated, "score"))
}

// AcceptanceTopK caps a ranking at K entries — the QUALIFIED ones first, so
// a cap never spends its budget on a disqualified row. K <= 0 = top
// acceptanceDefaultTopK. Returns the slice plus whether the cap was reached
// (more qualified findings existed than the cap kept).
func AcceptanceTopK(entries []AcceptanceEntry, k int) ([]AcceptanceEntry, bool) {
	if k <= 0 {
		k = acceptanceDefaultTopK
	}
	qualified := 0
	for _, e := range entries {
		if !e.Disqualified {
			qualified++
		}
	}
	capped := qualified > k
	out := entries[:0]
	taken := 0
	for _, e := range entries {
		if e.Disqualified {
			continue
		}
		if taken >= k {
			break
		}
		out = append(out, e)
		taken++
	}
	return out, capped
}

// ScoreText is the table print format: two decimals, the width the column
// budget in report and rank both assume. Scores are clamped at 0 and the
// demotion markers are rendered separately, so no sign handling is needed.
func ScoreText(x float64) string { return fmt.Sprintf("%.2f", x) }

// validatedBandOf is the finding's validated_risk band ("" when
// unvalidated). (workorder_test.go owns the name bandOf.)
func validatedBandOf(f validation.Value) string {
	riskObj := orObj(objAt(f, "risk"))
	return orStr(objAt(objAt(riskObj, "validated"), "band"))
}
