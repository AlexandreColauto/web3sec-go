package boundary

import (
	"fmt"
	"slices"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// validateReproducerRequest is the reproducer cross-field block.
func validateReproducerRequest(payload validation.Value,
	campaign *state.Campaign) error {
	if campaign == nil {
		return nil
	}
	profile := validation.ObjStr(payload, "execution_profile")
	if !slices.Contains(sandbox.Profiles, profile) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"reproducer request names unknown execution profile %s",
			validation.PyReprStr(profile))}
	}
	fid := validation.ObjStr(payload, "finding_id")
	if _, err := findings.LoadFinding(campaign, fid); err != nil {
		return &BoundaryError{Msg: fmt.Sprintf(
			"reproducer request references unknown finding %s",
			validation.PyReprStr(fid))}
	}
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return err
	}
	if active != nil && validation.ObjStr(payload, "snapshot_id") != *active {
		return &BoundaryError{Msg: fmt.Sprintf(
			"reproducer request pins snapshot %s but the active pin is %s — "+
				"the request must not drift the deployment",
			validation.PyReprStr(validation.ObjStr(payload, "snapshot_id")),
			validation.PyReprStr(*active))}
	}
	return nil
}

// campaignMemoryIDs is _campaign_memory_ids: the memory ids a
// differs_from_memory citation is resolved against. The listing goes through
// learning.AllMemory — the ONE implementation of "the campaign's memory
// rows" — and the shared store through its one home, sharedmem.
//
// r44c: this used to re-list memory/ locally with its own os.ReadDir, folding
// every listing error into "no ids"; the shared half swallowed its error the
// same way. Both reads are fail-closed downstream (a citation of a real prior
// would be rejected as an "unknown memory row"), so the fold never let a bad
// hypothesis through — but it turned a store that could not be read into a
// false accusation, and it was a second reader of the same store with its own
// tolerance. A read error is now a refusal, named, and the caller refuses the
// response instead of judging it against an empty id set.
//
// One deliberate divergence from the twin, kept explicit: the twin keyed the
// local half on the file STEM (p.stem); these ids come from each row's
// declared memory_id. Every row the tool itself writes lands at
// memory/MEM-<memory_id>.json (QueueMemory/ApproveMemory), so stem ==
// memory_id for every store a verb can produce; the declared id is also the
// identity a citation actually names. A hand-planted row whose stem and body
// disagree is a store defect this reader does not silently privilege.
func campaignMemoryIDs(campaign *state.Campaign) (map[string]bool, error) {
	rows, err := learning.AllMemory(campaign)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, r := range rows {
		if mid := validation.ObjStr(r, "memory_id"); mid != "" {
			ids[mid] = true
		}
	}
	wrapped, err := sharedmem.LoadSharedMemory(campaign.Root)
	if err != nil {
		return nil, fmt.Errorf(
			"the shared memory store for %s cannot be read: %v",
			campaign.Root, err)
	}
	for _, w := range wrapped {
		r := w
		if w.Kind == validation.Obj {
			if row := validation.ObjAt(w, "row"); row.Kind != validation.Null {
				r = row
			}
		}
		if mid := validation.ObjStr(r, "memory_id"); mid != "" {
			ids[mid] = true
		}
	}
	return ids, nil
}
