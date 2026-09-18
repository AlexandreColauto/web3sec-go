// metrics_linkage.go: eval-case linkage split out of metrics.go — linked
// case ids, the per-finding case map, case loading/partition and cost.
package metrics

import (
	"path/filepath"
	"slices"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

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
