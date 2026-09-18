// metrics_training.go: training_export split out of metrics.go — one row per
// terminal finding with partition-based exclusion.
package metrics

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- training_export -----------------------------------------------------

// TrainingExport is training_export: one row per terminal finding, for the
// training dataset. Held-out/training-partition rows are dropped by default.
func TrainingExport(campaigns []*state.Campaign,
	includeExcluded bool) []validation.Value {
	rows := []validation.Value{}
	for _, c := range campaigns {
		notes := []string{}
		fnds := safeFindings(c, &notes)
		caseMap := findingCaseMap(c, &notes)
		links := linkedCaseIDs(c, &notes)
		cost := costSummary(c, &notes)
		for _, finding := range fnds {
			if !inSet(exportableStatuses, validation.ObjStr(finding, "status")) {
				continue
			}
			fid := validation.ObjStr(finding, "finding_id")
			caseID := caseMap[fid]
			if caseID == "" && len(links) == 1 {
				caseID = links[0]
			}
			excluded, reason := exportExclusion(caseID)
			if excluded && !includeExcluded {
				continue
			}
			rows = append(rows, trainingRow(c, finding, fid, caseID,
				cost, excluded, reason))
		}
	}
	return rows
}

func trainingRow(c *state.Campaign, finding validation.Value, fid,
	caseID string, cost float64, excluded bool, reason string) validation.Value {
	caseV := validation.VNull()
	if caseID != "" {
		caseV = validation.VStr(caseID)
	}
	outcomeV := validation.VNull()
	if o, ok := STATUS_TO_OUTCOME[validation.ObjStr(finding, "status")]; ok {
		outcomeV = validation.VStr(o)
	}
	reasonV := validation.VNull()
	if reason != "" {
		reasonV = validation.VStr(reason)
	}
	return validation.VObj(
		validation.KV{K: "case_id", V: caseV},
		validation.KV{K: "finding_id", V: validation.VStr(fid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "outcome", V: outcomeV},
		validation.KV{K: "evidence_tier", V: validation.VStr(maxTierOf(finding))},
		validation.KV{K: "cost_summary", V: validation.VFloat(cost)},
		validation.KV{K: "labels", V: validation.VObj(
			validation.KV{K: "human", V: validation.VBool(false)})},
		validation.KV{K: "excluded", V: validation.VBool(excluded)},
		validation.KV{K: "exclude_reason", V: reasonV})
}

// exportExclusion is _export_exclusion.
func exportExclusion(caseID string) (bool, string) {
	if caseID == "" {
		return false, ""
	}
	partition := casePartition(caseID)
	if partition == nil {
		return true, unreadableCaseReason
	}
	switch *partition {
	case "dev":
		return false, ""
	case "held-out":
		return true, heldOutReason
	case "training":
		return true, trainingReason
	}
	return true, unreadableCaseReason
}
