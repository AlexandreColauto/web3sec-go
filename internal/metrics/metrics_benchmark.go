// metrics_benchmark.go: benchmark_report split out of metrics.go — per-case
// gold-vs-terminal scoring and the aggregate 2x2.
package metrics

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- benchmark_report ----------------------------------------------------

// BenchmarkReport is benchmark_report: per-case gold-vs-terminal match plus
// the aggregate 2x2.
func BenchmarkReport(caseIDs []string, campaigns []*state.Campaign) validation.Value {
	notes := []string{}
	perCase := []validation.Value{}
	cells := []string{}
	for _, caseID := range caseIDs {
		row, cell := scoreCase(caseID, campaigns, &notes)
		perCase = append(perCase, row)
		cells = append(cells, cell)
	}
	tp, fp, tn, fn := 0, 0, 0, 0
	for _, cell := range cells {
		switch cell {
		case "tp":
			tp++
		case "fp":
			fp++
		case "tn":
			tn++
		case "fn":
			fn++
		}
	}
	precision := rate(tp, tp+fp)
	recall := rate(tp, tp+fn)
	f1 := validation.VNull()
	if precision.Kind == validation.Flt && recall.Kind == validation.Flt &&
		precision.F+recall.F > 0 {
		f1 = validation.VFloat(2 * precision.F * recall.F /
			(precision.F + recall.F))
	}
	return validation.VObj(
		validation.KV{K: "cases", V: validation.VArr(perCase...)},
		validation.KV{K: "tp", V: validation.VInt(int64(tp))},
		validation.KV{K: "fp", V: validation.VInt(int64(fp))},
		validation.KV{K: "tn", V: validation.VInt(int64(tn))},
		validation.KV{K: "fn", V: validation.VInt(int64(fn))},
		validation.KV{K: "precision", V: precision},
		validation.KV{K: "recall", V: recall},
		validation.KV{K: "f1", V: f1},
		validation.KV{K: "notes", V: validation.StrArr(notes)})
}

// campaignForCase is _campaign_for_case.
func campaignForCase(caseID string, campaigns []*state.Campaign,
	notes *[]string) *state.Campaign {
	for _, c := range campaigns {
		for _, linked := range linkedCaseIDs(c, notes) {
			if linked == caseID {
				return c
			}
		}
	}
	return nil
}

// scoreCase is _score_case (returning the row and its 2x2 cell).
func scoreCase(caseID string, campaigns []*state.Campaign,
	notes *[]string) (validation.Value, string) {
	c := campaignForCase(caseID, campaigns, notes)
	if c == nil {
		*notes = append(*notes,
			"case "+caseID+": no campaign links it — skipped")
		return caseRow(caseID, "", "", "", validation.VNull(),
			"no campaign links this case"), ""
	}
	caseDoc := loadCase(caseID, notes)
	if caseDoc == nil {
		return caseRow(caseID, c.CampaignID, "", "", validation.VNull(),
			"gold unreadable — skipped"), ""
	}
	gold := validation.ObjStr(validation.ObjAt(*caseDoc, "gold"), "outcome")
	terminal, caseMap := terminalAndMap(c, notes)
	linked := linkedTerminal(terminal, caseMap, caseID)
	if len(linked) == 0 && len(terminal) == 1 {
		linked = terminal // single-verdict campaign: the verdict is the answer
	}
	if len(linked) != 1 {
		reason := "no terminal finding linked"
		if len(linked) != 0 {
			reason = itoa(len(linked)) + " findings linked — ambiguous"
		}
		*notes = append(*notes, "case "+caseID+": "+reason+" — skipped")
		return caseRow(caseID, c.CampaignID, gold, "", validation.VNull(),
			reason), ""
	}
	status := validation.ObjStr(linked[0], "status")
	cell := cellOf(gold, status)
	if cell == "" {
		*notes = append(*notes, "case "+caseID+": gold "+
			validation.PyReprStr(gold)+" / status "+validation.PyReprStr(status)+
			" outside the 2x2 — per-case match only")
	}
	return caseRow(caseID, c.CampaignID, gold, status,
		verdictMatch(gold, status), ""), cell
}

// terminalAndMap reads the exportable terminals + the per-finding case map.
func terminalAndMap(c *state.Campaign, notes *[]string) ([]validation.Value,
	map[string]string) {
	fnds := safeFindings(c, notes)
	terminal := []validation.Value{}
	for _, f := range fnds {
		if inSet(exportableStatuses, validation.ObjStr(f, "status")) {
			terminal = append(terminal, f)
		}
	}
	return terminal, findingCaseMap(c, notes)
}

func linkedTerminal(terminal []validation.Value, caseMap map[string]string,
	caseID string) []validation.Value {
	out := []validation.Value{}
	for _, f := range terminal {
		if caseMap[validation.ObjStr(f, "finding_id")] == caseID {
			out = append(out, f)
		}
	}
	return out
}

// cellOf is the 2x2 cell for a (gold, status) pair ("" outside the 2x2).
func cellOf(gold, status string) string {
	switch {
	case inSet(positiveGolds, gold) && inSet(predPositive, status):
		return "tp"
	case inSet(positiveGolds, gold) && inSet(predNegative, status):
		return "fn"
	case inSet(negativeGolds, gold) && inSet(predNegative, status):
		return "tn"
	case inSet(negativeGolds, gold) && inSet(predPositive, status):
		return "fp"
	}
	return ""
}

// verdictMatch is _verdict_match.
func verdictMatch(gold, status string) validation.Value {
	if gold == "" || status == "" {
		return validation.VNull()
	}
	satisfied, ok := GOLD_TO_STATUSES[gold]
	if !ok {
		return validation.VNull()
	}
	if _, ok := satisfied[status]; ok {
		return validation.VBool(true)
	}
	return validation.VBool(false)
}

// caseRow builds one per-case row (Python's dict, minus the popped cell).
// campaignID/status/gold "" is Python's None; predictedStatus "" is None.
func caseRow(caseID, campaignID, gold, status string,
	match validation.Value, note string) validation.Value {
	goldV, campV, statusV, predV, noteV :=
		validation.VNull(), validation.VNull(), validation.VNull(),
		validation.VNull(), validation.VNull()
	if gold != "" {
		goldV = validation.VStr(gold)
	}
	if campaignID != "" {
		campV = validation.VStr(campaignID)
	}
	if status != "" {
		statusV = validation.VStr(status)
		if p, ok := STATUS_TO_OUTCOME[status]; ok {
			predV = validation.VStr(p)
		}
	}
	if note != "" {
		noteV = validation.VStr(note)
	}
	return validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(caseID)},
		validation.KV{K: "gold", V: goldV},
		validation.KV{K: "campaign_id", V: campV},
		validation.KV{K: "predicted_status", V: statusV},
		validation.KV{K: "predicted_outcome", V: predV},
		validation.KV{K: "match", V: match},
		validation.KV{K: "note", V: noteV})
}
