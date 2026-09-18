// metrics_campaign.go: campaign_metrics split out of metrics.go — per-campaign
// precision/recall/tier metrics with case-linked counts.
package metrics

import (
	"slices"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- campaign_metrics ----------------------------------------------------

// CampaignMetrics is campaign_metrics: read-only metrics for one campaign,
// from events + findings + memory. Missing data becomes Null fields plus notes
// entries, never an error.
func CampaignMetrics(c *state.Campaign) validation.Value {
	notes := []string{}
	if c == nil {
		return emptyMetrics("unknown", []string{"campaign unreadable"})
	}
	campaignID := c.CampaignID
	fnds := safeFindings(c, &notes)
	total := len(fnds)
	confirmations, disprovals, duplicates := 0, 0, 0
	tiers := make([]string, 0, total)
	for _, f := range fnds {
		switch validation.ObjStr(f, "status") {
		case "CONFIRMED", "CHAIN":
			confirmations++
		case "DISPROVED":
			disprovals++
		case "DUPLICATE":
			duplicates++
		}
		tiers = append(tiers, maxTierOf(f))
	}
	deadEnds := 0
	for i, f := range fnds {
		if inSet(findings.TERMINAL, validation.ObjStr(f, "status")) && tiers[i] == "E0" {
			deadEnds++
		}
	}
	histogram := make([]validation.KV, 0, len(findings.EVIDENCE_ORDER))
	counts := map[string]int{}
	for _, t := range tiers {
		counts[t]++
	}
	for _, t := range findings.EVIDENCE_ORDER {
		histogram = append(histogram, validation.KV{K: t,
			V: validation.VInt(int64(counts[t]))})
	}
	created, resolved := assumptionCounts(fnds)
	recallNum, recallDen, frrNum, frrDen := caseLinkedCounts(c, fnds, &notes)
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(campaignID)},
		validation.KV{K: "findings_total", V: validation.VInt(int64(total))},
		validation.KV{K: "confirmations", V: validation.VInt(int64(confirmations))},
		validation.KV{K: "disprovals", V: validation.VInt(int64(disprovals))},
		validation.KV{K: "confirmation_precision", V: rate(confirmations,
			confirmations+disprovals)},
		validation.KV{K: "duplicate_rate", V: rate(duplicates, total)},
		validation.KV{K: "dead_end_rate", V: rate(deadEnds, total)},
		validation.KV{K: "avg_evidence_tier", V: avgTier(tiers, total)},
		validation.KV{K: "evidence_tier_histogram", V: validation.VObj(histogram...)},
		validation.KV{K: "critic_recall", V: rate(recallNum, recallDen)},
		validation.KV{K: "false_rejection_rate", V: rate(frrNum, frrDen)},
		validation.KV{K: "assumption_efficiency", V: rate(resolved, created)},
		validation.KV{K: "notes", V: validation.StrArr(notes)})
}

// assumptionCounts walks the blocking assumptions of every finding.
func assumptionCounts(fnds []validation.Value) (created, resolved int) {
	for _, finding := range fnds {
		assumptions := validation.ObjAt(finding, "assumptions")
		if assumptions.Kind != validation.Arr {
			continue
		}
		for _, a := range assumptions.A {
			if a.Kind != validation.Obj || !truthy(validation.ObjAt(a, "blocking")) {
				continue
			}
			created++
			if inSet(assumptionResolved, validation.ObjStr(a, "status")) {
				resolved++
			}
		}
	}
	return created, resolved
}

// avgTier is `sum(EVIDENCE_ORDER.index(t)) / total if total else None`.
func avgTier(tiers []string, total int) validation.Value {
	if total == 0 {
		return validation.VNull()
	}
	sum := 0
	for _, t := range tiers {
		if i, ok := tierIndex(t); ok {
			sum += i
		}
	}
	return validation.VFloat(float64(sum) / float64(total))
}

// caseLinkedCounts is campaign_metrics' recall/false-rejection loop.
func caseLinkedCounts(c *state.Campaign, fnds []validation.Value,
	notes *[]string) (recallNum, recallDen, frrNum, frrDen int) {
	caseIDs := linkedCaseIDs(c, notes)
	if len(caseIDs) == 0 {
		*notes = append(*notes,
			"no eval_case_id linked — case-linked metrics are None")
		return 0, 0, 0, 0
	}
	caseMap := findingCaseMap(c, notes)
	terminal := []validation.Value{}
	for _, f := range fnds {
		if inSet(exportableStatuses, validation.ObjStr(f, "status")) {
			terminal = append(terminal, f)
		}
	}
	for _, caseID := range caseIDs {
		caseDoc := loadCase(caseID, notes)
		if caseDoc == nil {
			continue
		}
		gold := validation.ObjStr(validation.ObjAt(*caseDoc, "gold"), "outcome")
		if !slices.Contains(outcomeValues, gold) {
			*notes = append(*notes, "case "+caseID+": gold outcome "+
				validation.PyReprStr(gold)+" unrecognized — skipped")
			continue
		}
		linked := []validation.Value{}
		for _, f := range terminal {
			if caseMap[validation.ObjStr(f, "finding_id")] == caseID {
				linked = append(linked, f)
			}
		}
		if len(linked) == 0 && len(caseIDs) == 1 && len(terminal) == 1 {
			linked = terminal // single-case, single-verdict fallback
		}
		if len(linked) == 0 {
			*notes = append(*notes, "case "+caseID+
				": no terminal finding linked — skipped")
			continue
		}
		if len(linked) > 1 {
			*notes = append(*notes, "case "+caseID+": "+
				itoa(len(linked))+" findings linked — skipped as ambiguous")
			continue
		}
		status := validation.ObjStr(linked[0], "status")
		disproved := status == "DISPROVED"
		switch {
		case inSet(notExploitableGold, gold):
			recallDen++
			if disproved {
				recallNum++
			}
		case inSet(exploitableGolds, gold):
			frrDen++
			if disproved {
				frrNum++
			}
		default:
			*notes = append(*notes, "case "+caseID+": gold "+
				validation.PyReprStr(gold)+" is neither exploitable nor "+
				"not-exploitable — skipped")
		}
	}
	return recallNum, recallDen, frrNum, frrDen
}

// outcomeValues is trajectory.OUTCOME_VALUES: the gold outcome vocabulary.
var outcomeValues = []string{
	"confirmed-exploitable", "confirmed-not-exploitable", "disproved",
	"out-of-scope", "duplicate", "economic-no-go", "unfinished",
}

// emptyMetrics is _empty_metrics.
func emptyMetrics(campaignID string, notes []string) validation.Value {
	histogram := make([]validation.KV, 0, len(findings.EVIDENCE_ORDER))
	for _, t := range findings.EVIDENCE_ORDER {
		histogram = append(histogram, validation.KV{K: t, V: validation.VInt(0)})
	}
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(campaignID)},
		validation.KV{K: "findings_total", V: validation.VInt(0)},
		validation.KV{K: "confirmations", V: validation.VInt(0)},
		validation.KV{K: "disprovals", V: validation.VInt(0)},
		validation.KV{K: "confirmation_precision", V: validation.VNull()},
		validation.KV{K: "duplicate_rate", V: validation.VNull()},
		validation.KV{K: "dead_end_rate", V: validation.VNull()},
		validation.KV{K: "avg_evidence_tier", V: validation.VNull()},
		validation.KV{K: "evidence_tier_histogram", V: validation.VObj(histogram...)},
		validation.KV{K: "critic_recall", V: validation.VNull()},
		validation.KV{K: "false_rejection_rate", V: validation.VNull()},
		validation.KV{K: "assumption_efficiency", V: validation.VNull()},
		validation.KV{K: "notes", V: validation.StrArr(notes)})
}
