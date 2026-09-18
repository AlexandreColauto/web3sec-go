// transitions_dedup.go: the dedup half of the lifecycle —
// fold_into_lineage, mark_duplicate (with its merge-pointer writers) and
// flag_possible_duplicate (webv2.findings).
package findings

import (
	"slices"
	"websec/internal/state"
	"websec/internal/validation"
)

// FoldIntoLineage is fold_into_lineage: pin the finding's lineage id.
func FoldIntoLineage(campaign *state.Campaign, findingID,
	lineageID string) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	dedup := asDict(validation.ObjAt(finding, "dedup"))
	dedup.O = validation.SetOrAppend(dedup.O, "lineage_id", validation.VStr(lineageID))
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// MarkDuplicate is mark_duplicate: transition to DUPLICATE and record which
// finding it duplicates. The recording is transition's targeted-move half, so
// the dedup sweep and `move --of` cannot drift apart.
func MarkDuplicate(campaign *state.Campaign, findingID,
	ofFindingID string) (validation.Value, error) {
	return transition(campaign, findingID, "DUPLICATE",
		"technical/root-cause duplicate of "+ofFindingID,
		transitionOpts{actor: "dedup", duplicateOf: ofFindingID})
}

// recordDuplicateOf writes dedup.duplicate_of on the finding that just became
// a DUPLICATE. It is the only writer of that field. The write is folded into
// the transition's single SaveFinding (mutate here, save in transition) — a
// merge can never land as a durable status without its target.
func recordDuplicateOf(finding *validation.Value, ofFindingID string) {
	dedup := asDict(validation.ObjAt(*finding, "dedup"))
	dedup.O = validation.SetOrAppend(dedup.O, "duplicate_of",
		validation.VStr(ofFindingID))
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
}

// clearDuplicateOf drops dedup.duplicate_of when a DUPLICATE is reopened. The
// dedup block itself stays (the schema requires it and the signatures in it
// are still true); only the merge pointer is cleared. A finding with nothing
// recorded is left untouched — not even an updated_at stamp beyond the
// transition's own single save. Mutation only; the caller saves once.
func clearDuplicateOf(finding *validation.Value) {
	dedup := asDict(validation.ObjAt(*finding, "dedup"))
	kept := make([]validation.KV, 0, len(dedup.O))
	for _, kv := range dedup.O {
		if kv.K != "duplicate_of" {
			kept = append(kept, kv)
		}
	}
	if len(kept) == len(dedup.O) {
		return
	}
	dedup.O = kept
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
}

// FlagPossibleDuplicate is flag_possible_duplicate: tier-3 (economic-effect)
// matches are flagged, never auto-merged.
func FlagPossibleDuplicate(campaign *state.Campaign, findingID,
	ofFindingID string) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	dedup := asDict(validation.ObjAt(finding, "dedup"))
	lst := validation.ObjAt(dedup, "possible_duplicate_of")
	if lst.Kind != validation.Arr {
		lst = validation.VArr()
	}
	if !slices.Contains(valueStrings(lst), ofFindingID) {
		lst.A = append(lst.A, validation.VStr(ofFindingID))
	}
	dedup.O = validation.SetOrAppend(dedup.O, "possible_duplicate_of", lst)
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(validation.KV{K: "of", V: validation.VStr(ofFindingID)})
		if _, lerr := campaign.Log("finding.possible_duplicate", &findingID,
			&data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// valueStrings is the string members of a list (Python's `in` on a list of
// ids compares by equality; non-strings never equal an id).
func valueStrings(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}
