// The Results precision block (A3): the live acceptance ranking table,
// the unscored notice and the G13 lens-yield cost attribution block.
package report

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/bounty"
	"websec/internal/costs"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// precisionBlock is the A3 "which findings matter" block in Results: the
// dual critic/evidence counts, the false-positive ratio (the share of
// critic-confirmed live findings that fail the evidence floor) and
// the top-K acceptance table — the operator's ranked answer over every LIVE
// finding (the production live predicate, findings.LoadLiveFindings:
// DUPLICATE / OUT_OF_SCOPE / SUPERSEDED excluded; a DISPROVED finding stays
// visible, disqualified at the bottom, so a critic/pipeline disagreement is
// legible). The score is recomputed live (risk.AcceptanceScore), never read
// from the stored field, so the table is current even before the next gate
// run.
//
// Budget: submission_budget.max_findings caps K (0/absent = top 10);
// rank_by flips the key from acceptance score to severity band. A reached
// cap prints a note; disqualified (critic-disproved) findings drop out of
// the table and are named below it.
//
// Presence gate (the additive convention — a new section must not change
// an existing campaign's bytes): the block renders only when an A3 field
// is present — the gate stored risk.acceptance_score on at least one
// finding, or the policy opted in with submission_budget. A campaign with
// neither renders no block at all.
func precisionBlock(campaign *state.Campaign, all []validation.Value,
	policy validation.Value) []string {
	// A campaign with no policy is UNSCORED: the acceptance scores, the
	// submission budget and the accepted-risks check all come from the policy,
	// so without one nothing separates "the program will pay" from "real but
	// accepted". Saying nothing here is what let a 23-finding campaign look
	// complete next to a 2-finding gold. Presence-gated: a scoped campaign
	// never prints the notice.
	unscored := policy.Kind != validation.Obj || len(policy.O) == 0
	if unscored && validation.ObjAt(policy, "submission_budget").Kind != validation.Obj {
		stored := false
		for _, f := range all {
			v := validation.ObjAt(validation.ObjAt(f, "risk"), "acceptance_score")
			if v.Kind == validation.Flt || v.Kind == validation.Int {
				stored = true
				break
			}
		}
		if !stored {
			return append(unscoredNotice(campaign), "")
		}
	}
	var live []validation.Value
	criticN, evidenceN, criticNoEvidenceN := 0, 0, 0
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" ||
			s == "SUPERSEDED" {
			continue
		}
		live = append(live, f)
		if criticVerdictOf(f) == "confirmed" {
			criticN++
			// The ratio's numerator, counted in the same pass and over the
			// same set as its denominator: of the critic-confirmed
			// findings, the ones the evidence floor does NOT clear. The
			// old subtraction compared this count against the disjoint
			// evidence-confirmed count, so a finding the critic confirmed
			// but did not evidence (or vice versa) could drive the ratio
			// negative — the campaign printed -25.0% for 4 vs 5.
			if findings.EvidenceDeficit(f, "CONFIRMED", campaign) != nil {
				criticNoEvidenceN++
			}
		}
		if findings.EvidenceDeficit(f, "CONFIRMED", campaign) == nil {
			evidenceN++
		}
	}
	L := []string{}
	if unscored {
		L = append(L, unscoredNotice(campaign)...)
	}
	if len(live) == 0 {
		L = append(L, "- **precision:** no live findings to rank")
		L = append(L, "")
		return L
	}
	ratio := "n/a (no critic-confirmed findings)"
	if criticN > 0 {
		ratio = fmt.Sprintf("%.1f%%", float64(criticNoEvidenceN)/
			float64(criticN)*100)
	}
	L = append(L, fmt.Sprintf(
		"- **precision:** critic-confirmed: %d  - evidence-confirmed: %d  "+
			"- false-positive ratio: %s", criticN, evidenceN, ratio))

	k, rankBy := 0, "acceptance"
	if sb := validation.ObjAt(policy, "submission_budget"); sb.Kind == validation.Obj {
		if mf := intAt(sb, "max_findings"); mf > 0 {
			k = int(mf)
		}
		if rb := validation.ObjStr(sb, "rank_by"); rb == "severity" {
			rankBy = "severity"
		}
	}
	keyName := "acceptance"
	if rankBy == "severity" {
		keyName = "severity"
	}
	entries := risk.AcceptanceRanking(live, rankBy)
	if bounty.PriorsEnabled(policy) {
		// G3 wPrior, policy-gated OFF by default: a store failure
		// resolves to nil priors, which rank bit-identically to the
		// plain path above — the flag degrades to today's order, never
		// to an error.
		priors, global, _ := risk.AcceptancePriors(risk.DefaultMinN)
		entries = risk.AcceptanceRankingWithPriors(live, rankBy,
			priors, global)
	}
	top, capped := risk.AcceptanceTopK(entries, k)
	if k > 0 {
		L = append(L, fmt.Sprintf(
			"- **top %d by %s:** (submission budget)", k, keyName))
	} else {
		L = append(L, fmt.Sprintf("- **top %d by %s:**", len(top), keyName))
	}
	L = append(L, "  | # | finding | band | evidence | critic | score |")
	L = append(L, "  |---|---------|------|----------|--------|-------|")
	for i, e := range top {
		L = append(L, fmt.Sprintf("  | %d | %s | %s | %s | %s | %s |",
			i+1, rankCell(e), bandCell(e), evidenceCell(e),
			criticCell(e), scoreCell(e)))
	}
	if capped {
		L = append(L, fmt.Sprintf(
			"  - capped at %d by the submission budget: %d more qualified "+
				"finding(s) not shown",
			k, countQualified(entries)-len(top)))
	}
	var dq []string
	for _, e := range entries {
		if e.Disqualified {
			dq = append(dq, findingIDOf(e.Finding))
		}
	}
	if len(dq) > 0 {
		L = append(L, fmt.Sprintf(
			"- disqualified (critic disproved): %s — excluded from the table",
			strings.Join(dq, ", ")))
	}
	L = append(L, "")
	return L
}

// lensYieldBlock is the G13 cost-attribution table in Results: spend per
// lens against the confirmations that lens produced, plus the framework's
// own unit economics (cost per critic-confirmed / per evidence-confirmed
// finding). Advisory only — it ranks spend, it gates nothing, and the
// caller presence-gates it: no lens data, no bytes. Deterministic: rows
// arrive L-id ascending with "unattributed" last (costs.LensYield), money
// renders to 2 decimals, null quotients render n/a (never inf).
func lensYieldBlock(campaign *state.Campaign,
	ly []validation.Value) []string {
	perCritic, perEvidence := "n/a", "n/a"
	if rep, err := costs.YieldReport(campaign); err == nil {
		totals := validation.ObjAt(rep, "totals")
		if v := validation.ObjAt(totals,
			"cost_per_critic_confirmed_usd"); v.Kind != validation.Null {
			perCritic = "$" + lensMoney(v)
		}
		if v := validation.ObjAt(totals,
			"cost_per_evidence_confirmed_usd"); v.Kind != validation.Null {
			perEvidence = "$" + lensMoney(v)
		}
	}
	L := []string{"- **lens yield (advisory — never gates):** cost per " +
		"critic-confirmed " + perCritic + " / per evidence-confirmed " +
		perEvidence}
	L = append(L, "  | lens | planned | confirmed | cost_usd |")
	L = append(L, "  |---|---|---|---|")
	for _, r := range ly {
		L = append(L, fmt.Sprintf("  | %s | %d | %d | $%s |",
			validation.ObjStr(r, "lens"), lensInt(r, "n_planned"),
			lensInt(r, "n_confirmed"), lensMoney(validation.ObjAt(r, "cost_usd"))))
	}
	L = append(L, "")
	return L
}

// lensMoney is Python's f"${x:.2f}" for the number shapes the rollup
// holds (int 0 included — the unattributed bucket starts at zero).
func lensMoney(v validation.Value) string {
	switch v.Kind {
	case validation.Flt:
		return strconv.FormatFloat(v.F, 'f', 2, 64)
	case validation.Int:
		if v.Big != "" {
			if f, err := strconv.ParseFloat(v.Big, 64); err == nil {
				return strconv.FormatFloat(f, 'f', 2, 64)
			}
		}
		return strconv.FormatFloat(float64(v.I), 'f', 2, 64)
	}
	return "0.00"
}

// lensInt is int(r.get(key, 0)) for the rollup's count shapes.
func lensInt(r validation.Value, key string) int64 {
	if v := validation.ObjAt(r, key); v.Kind == validation.Int {
		return v.I
	}
	return 0
}
