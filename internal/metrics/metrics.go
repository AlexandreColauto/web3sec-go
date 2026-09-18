// Package metrics ports webv2.metrics: the campaign + benchmark + training
// metrics harness.
//
// WHY: the closed loop (propose/critic/reproduce) is only trustworthy when it
// is MEASURED — against its own event log (precision, dead-ends, evidence
// depth, assumption throughput) and against adjudicated gold (eval cases).
// This package is the read-only lens over campaigns: it never writes, never
// calls a model, and never raises on missing data — a torn log, an absent eval
// store, or a campaign with no findings yields Null fields plus a notes entry,
// never an error.
//
// Eval-case linkage: CampaignMetrics/BenchmarkReport link a campaign to its
// case(s) through (in order) the raw campaign state's eval_case_id (string or
// list, read tolerantly), a campaign-local eval_link.json sidecar, and
// per-finding outcome events carrying case_id. A campaign with no linkage gets
// Null case-linked metrics, not a crash.
package metrics

import (
	"path/filepath"
	"slices"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// STATUS_TO_OUTCOME is the terminal-status -> gold-outcome enum.
var STATUS_TO_OUTCOME = map[string]string{
	"CONFIRMED":     "confirmed-exploitable",
	"CHAIN":         "confirmed-exploitable",
	"DISPROVED":     "disproved",
	"OUT_OF_SCOPE":  "out-of-scope",
	"DUPLICATE":     "duplicate",
	"INFORMATIONAL": "confirmed-not-exploitable",
}

// GOLD_TO_STATUSES is the gold outcome -> the terminal statuses satisfying it.
var GOLD_TO_STATUSES = map[string]map[string]struct{}{
	"confirmed-exploitable":     setOf("CONFIRMED", "CHAIN"),
	"confirmed-not-exploitable": setOf("DISPROVED"),
	"disproved":                 setOf("DISPROVED"),
	"out-of-scope":              setOf("OUT_OF_SCOPE"),
	"duplicate":                 setOf("DUPLICATE"),
	"economic-no-go":            setOf("INFORMATIONAL"),
}

var (
	positiveGolds      = setOf("confirmed-exploitable")
	negativeGolds      = setOf("confirmed-not-exploitable")
	exploitableGolds   = setOf("confirmed-exploitable")
	notExploitableGold = setOf("confirmed-not-exploitable", "disproved")
	predPositive       = setOf("CONFIRMED", "CHAIN")
	predNegative       = setOf("DISPROVED")
	assumptionResolved = setOf("SUPPORTED", "REFUTED")
)

// exportableStatuses is _EXPORTABLE_STATUSES = TERMINAL | {CONFIRMED, CHAIN}.
var exportableStatuses = func() map[string]struct{} {
	out := setOf("CONFIRMED", "CHAIN")
	for k := range findings.TERMINAL {
		out[k] = struct{}{}
	}
	return out
}()

const (
	heldOutReason        = "held-out case — leakage"
	trainingReason       = "training case — leakage"
	unreadableCaseReason = "case partition unreadable (fail closed)"
)

// EvalStore is the eval_store seam (the read-only lens). Absent: every
// case-linked derivation reports a note and fails closed.
type EvalStore interface {
	LoadCase(caseID string) (validation.Value, error)
}

var evalStore EvalStore

// SetEvalStore installs the eval store (nil restores the absent default).
func SetEvalStore(s EvalStore) { evalStore = s }

// ---- small guarded primitives -------------------------------------------

// rate is _rate: None when the denominator is zero.
func rate(numerator, denominator int) validation.Value {
	if denominator == 0 {
		return validation.VNull()
	}
	return validation.VFloat(float64(numerator) / float64(denominator))
}

func tierIndex(tier string) (int, bool) {
	for i, t := range findings.EVIDENCE_ORDER {
		if t == tier {
			return i, true
		}
	}
	return 0, false
}

// safeFindings is _safe_findings: reporter, never raiser.
func safeFindings(c *state.Campaign, notes *[]string) []validation.Value {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		*notes = append(*notes, "findings unreadable in "+c.CampaignID+
			": "+err.Error())
		return nil
	}
	out := []validation.Value{}
	for _, f := range all {
		if f.Kind == validation.Obj {
			out = append(out, f)
		}
	}
	return out
}

// safeEvents is _safe_events.
func safeEvents(c *state.Campaign, notes *[]string) []validation.Value {
	events, err := c.Events()
	if err != nil {
		*notes = append(*notes, "event log unreadable in "+c.CampaignID+
			": "+err.Error())
		return nil
	}
	out := []validation.Value{}
	for _, e := range events {
		if e.Kind == validation.Obj {
			out = append(out, e)
		}
	}
	return out
}

// maxTierOf is _max_tier_of: E0 when there is none or it is unreadable.
func maxTierOf(f validation.Value) string {
	tier, err := findings.FindingLevel(f)
	if err != nil {
		return "E0"
	}
	if _, ok := tierIndex(tier); !ok {
		return "E0"
	}
	return tier
}

// ---- eval-case linkage ---------------------------------------------------

// linkedCaseIDs is _linked_case_ids: case ids linked to this campaign, in
// first-seen order, deduplicated.
func linkedCaseIDs(c *state.Campaign, notes *[]string) []string {
	seen := []string{}
	add := func(items []validation.Value) {
		for _, item := range items {
			if item.Kind == validation.Str && item.S != "" &&
				!slices.Contains(seen, item.S) {
				seen = append(seen, item.S)
			}
		}
	}
	if raw, err := validation.ReadJson(c.StatePath); err == nil &&
		raw.Kind == validation.Obj {
		add(linkItems(validation.ObjAt(raw, "eval_case_id")))
	}
	sidecar, err := validation.ReadJson(filepath.Join(c.Dir, "eval_link.json"))
	if err == nil && sidecar.Kind == validation.Obj {
		link := validation.ObjAt(sidecar, "eval_case_id")
		if link.Kind == validation.Null {
			link = validation.ObjAt(sidecar, "case_id")
		}
		add(linkItems(link))
	}
	for _, event := range safeEvents(c, notes) {
		if validation.ObjStr(event, "type") != "outcome" {
			continue
		}
		data := validation.ObjAt(event, "data")
		if data.Kind != validation.Obj {
			continue
		}
		add(linkItems(validation.ObjAt(data, "case_id")))
	}
	return seen
}

// linkItems is `link if isinstance(link, list) else ([link] if link else [])`.
func linkItems(link validation.Value) []validation.Value {
	if link.Kind == validation.Arr {
		return link.A
	}
	if truthy(link) {
		return []validation.Value{link}
	}
	return nil
}

// findingCaseMap is _finding_case_map: finding_id -> case_id from outcome
// events (the per-finding link).
func findingCaseMap(c *state.Campaign, notes *[]string) map[string]string {
	mapping := map[string]string{}
	for _, event := range safeEvents(c, notes) {
		if validation.ObjStr(event, "type") != "outcome" {
			continue
		}
		data := validation.ObjAt(event, "data")
		if data.Kind != validation.Obj {
			continue
		}
		fid := validation.ObjAt(data, "finding_id")
		if !truthy(fid) {
			fid = validation.ObjAt(event, "ref")
		}
		caseID := validation.ObjAt(data, "case_id")
		if fid.Kind == validation.Str && strings.HasPrefix(fid.S, "F-") &&
			caseID.Kind == validation.Str && caseID.S != "" {
			if _, ok := mapping[fid.S]; !ok {
				mapping[fid.S] = caseID.S
			}
		}
	}
	return mapping
}

// loadCase is _load_case: one gold case, or nil with a note when the store
// cannot prove it.
func loadCase(caseID string, notes *[]string) *validation.Value {
	if evalStore == nil {
		*notes = append(*notes, "case "+caseID+
			": eval store unavailable — skipped")
		return nil
	}
	caseDoc, err := evalStore.LoadCase(caseID)
	if err != nil {
		*notes = append(*notes, "case "+caseID+": unreadable ("+err.Error()+
			") — skipped")
		return nil
	}
	if caseDoc.Kind != validation.Obj {
		*notes = append(*notes, "case "+caseID+": unexpected shape — skipped")
		return nil
	}
	return &caseDoc
}

// casePartition is _case_partition: the linked case's partition, or nil when
// it cannot be proved (fail closed).
func casePartition(caseID string) *string {
	if evalStore == nil {
		return nil
	}
	caseDoc, err := evalStore.LoadCase(caseID)
	if err != nil || caseDoc.Kind != validation.Obj {
		return nil
	}
	p := validation.ObjStr(caseDoc, "partition")
	if p == "" {
		return nil
	}
	return &p
}

// costSummary is _cost_summary: the campaign's cost.recorded amount_usd sum.
func costSummary(c *state.Campaign, notes *[]string) float64 {
	total := 0.0
	for _, event := range safeEvents(c, notes) {
		if validation.ObjStr(event, "type") != "cost.recorded" {
			continue
		}
		data := validation.ObjAt(event, "data")
		if data.Kind != validation.Obj {
			continue
		}
		amount := validation.ObjAt(data, "amount_usd")
		if amount.Kind == validation.Flt && amount.F >= 0 {
			total += amount.F
		} else if amount.Kind == validation.Int && amount.I >= 0 {
			total += float64(amount.I)
		}
	}
	return total
}

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

// ---- helpers -------------------------------------------------------------

func setOf(items ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, s := range items {
		out[s] = struct{}{}
	}
	return out
}

func inSet(s map[string]struct{}, key string) bool {
	_, ok := s[key]
	return ok
}

func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
