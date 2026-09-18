// The D1 all-findings inventory table and its per-cell renderers, plus
// the shared finding-id / critic-verdict accessors and the acceptance
// table cell helpers used by the precision block.
package report

import (
	"fmt"
	"sort"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/validation"
)

// allFindingsTable is the D1 "All findings" table: one row per finding. Order
// is STATUS FIRST (confirmed/chain, then hypothesis, then dismissed), and only
// then the live acceptance score descending with the finding id as tie-break.
//
// Status must lead because the score is not comparable across statuses, and the
// golden campaign proved it: a HYPOTHESIS whose band was stamped outranked three
// CONFIRMED findings that had no validated band yet, because an absent band
// contributes zero to the live score — so the inventory opened with an unproven
// claim above the confirmed ones. Within a status group the key is the same one
// risk.AcceptanceRanking uses (the precision table, `webv2 rank`), with the
// critic-disproved last: a disproved finding can keep a high score because the
// band survives the verdict in the arithmetic, and it must never head a group as
// if it were a candidate. Every cell degrades to "—" rather than failing the
// report — this is the view an operator reads when something already looks
// wrong, so it must render even for a half-populated finding.
func allFindingsTable(all []validation.Value) []string {
	sorted := append([]validation.Value{}, all...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := allFindingStatusRank(sorted[i]), allFindingStatusRank(sorted[j])
		if ri != rj {
			return ri < rj
		}
		si, di := risk.AcceptanceScore(sorted[i])
		sj, dj := risk.AcceptanceScore(sorted[j])
		if di != dj {
			return !di
		}
		if si != sj {
			return si > sj
		}
		return findingIDOf(sorted[i]) < findingIDOf(sorted[j])
	})
	L := []string{fmt.Sprintf("### All findings (%d)", len(sorted)), ""}
	L = append(L, "  | finding | status | evidence | critic | risk | accept "+
		"| submit | chain |")
	L = append(L, "  |---------|--------|----------|--------|------|--------"+
		"|--------|-------|")
	for _, f := range sorted {
		L = append(L, fmt.Sprintf("  | %s | %s | %s | %s | %s | %s | %s | %s |",
			allFindingCell(f), validation.ObjStr(f, "status"), allFindingEvidence(f),
			allFindingCritic(f), allFindingRisk(f), allFindingAccept(f),
			allFindingSubmit(f), allFindingChain(f)))
	}
	dq := 0
	for _, f := range sorted {
		if _, d := risk.AcceptanceScore(f); d {
			dq++
		}
	}
	note := "  - ordered by status (confirmed/chain → hypothesis → " +
		"dismissed), then live acceptance score"
	if dq > 0 {
		note += fmt.Sprintf("; %d critic-disproved finding(s) sorted last "+
			"within their status (shown for completeness, never as "+
			"candidates)", dq)
	}
	L = append(L, note)
	L = append(L, "")
	return L
}

// allFindingStatusRank orders the inventory by what the campaign currently
// believes: 0 for the findings it stands behind (CONFIRMED, or a member of a
// materialized chain), 1 for the unproven claims, 2 for everything it has
// dismissed (duplicates, out-of-scope, intended behaviour, unreachable,
// non-economic, test-harness-only, and the critic-disproved). An unknown status
// is treated as a claim, not as a dismissal — the table shows what it does not
// recognize rather than burying it.
func allFindingStatusRank(f validation.Value) int {
	switch validation.ObjStr(f, "status") {
	case "CONFIRMED", "CHAIN":
		return 0
	case "HYPOTHESIS", "":
		return 1
	default:
		return 2
	}
}

// allFindingCell is the id plus a readable title, the same shape the precision
// table uses.
func allFindingCell(f validation.Value) string {
	id := findingIDOf(f)
	title := validation.ObjStr(f, "title")
	if len(title) > 40 {
		title = title[:40] + "…"
	}
	if title != "" {
		return id + " " + title
	}
	return id
}

func allFindingEvidence(f validation.Value) string {
	l, err := findings.FindingLevel(f)
	if err != nil || l == "" {
		return "—"
	}
	return l
}

func allFindingCritic(f validation.Value) string {
	if v := criticVerdictOf(f); v != "" {
		return v
	}
	return "—"
}

// allFindingRisk is score + validated band, the risk-calibration pair.
func allFindingRisk(f validation.Value) string {
	riskObj := validation.AsObj(validation.ObjAt(f, "risk"))
	band := validation.ObjStr(validation.AsObj(validation.ObjAt(riskObj, "validated")), "band")
	score := ""
	if x, ok := risk.AcceptanceScore(f); ok {
		score = risk.ScoreText(x)
	}
	switch {
	case score != "" && band != "":
		return score + " " + band
	case score != "":
		return score
	case band != "":
		return band
	}
	return "—"
}

// allFindingAccept is the stored A3 acceptance score, empty unless the gate
// ran (the live value is the risk column's first half).
func allFindingAccept(f validation.Value) string {
	v := validation.ObjAt(validation.ObjAt(f, "risk"), "acceptance_score")
	switch v.Kind {
	case validation.Flt:
		return risk.ScoreText(v.F)
	case validation.Int:
		return risk.ScoreText(float64(v.I))
	}
	return "—"
}

func allFindingSubmit(f validation.Value) string {
	if pyTruthyInt64Only(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "bounty")), "submission_ready")) {
		return "yes"
	}
	return "—"
}

// allFindingChain is the chain membership: a per-finding chain id when the
// finding carries one, otherwise a marker for the CHAIN status.
func allFindingChain(f validation.Value) string {
	if id := validation.ObjStr(f, "chain_id"); id != "" {
		return id
	}
	if validation.ObjStr(f, "status") == "CHAIN" {
		return "chain"
	}
	return "—"
}

func countQualified(entries []risk.AcceptanceEntry) int {
	n := 0
	for _, e := range entries {
		if !e.Disqualified {
			n++
		}
	}
	return n
}

// rankCell is the finding cell: id + truncated title (the table is the
// operator's "which 5 of 23" answer, so the title must be readable there).
func rankCell(e risk.AcceptanceEntry) string {
	id := findingIDOf(e.Finding)
	title := validation.ObjStr(e.Finding, "title")
	if len(title) > 40 {
		title = title[:40] + "…"
	}
	if title != "" {
		return id + " " + title
	}
	return id
}

func bandCell(e risk.AcceptanceEntry) string {
	riskObj := validation.AsObj(validation.ObjAt(e.Finding, "risk"))
	b := validation.ObjStr(validation.AsObj(validation.ObjAt(riskObj, "validated")), "band")
	if b == "" {
		return "—"
	}
	return b
}

// evidenceCell is the finding's highest evidence level (FindingLevel is
// E0 when the finding holds none — shown as E0, not hidden).
func evidenceCell(e risk.AcceptanceEntry) string {
	l, err := findings.FindingLevel(e.Finding)
	if err != nil {
		return "—"
	}
	return l
}

func criticCell(e risk.AcceptanceEntry) string {
	v := criticVerdictOf(e.Finding)
	if v == "" {
		return "—"
	}
	return v
}

// scoreCell is the two-decimal score with its demotion markers (A2 ack, A1
// accepted risk, G5 soundness mitigation) — the markers are what make a
// demoted number legible.
// The G3 prior marker rides the same presence pattern: absent when the
// term is zero, so policy-off tables never move.
func scoreCell(e risk.AcceptanceEntry) string {
	s := risk.ScoreText(e.Score)
	if e.AckDemoted {
		s += " -ack"
	}
	if e.RiskDemoted {
		s += " -risk"
	}
	if e.MitigationDemoted {
		s += " -mitigation"
	}
	if e.PriorFactor != 0 {
		s += " +prior"
	}
	return s
}

func findingIDOf(f validation.Value) string {
	return validation.ObjStr(f, "finding_id")
}

func criticVerdictOf(f validation.Value) string {
	return validation.ObjStr(validation.ObjAt(f, "verification"), "critic_verdict")
}
