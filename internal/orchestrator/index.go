// index.go: the STRUCTURAL_INDEX phase and its seam to webv2.structural_index
// (P3, unported).
package orchestrator

import (
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// StructuralIndexAPI is the seam to webv2.structural_index. The orchestrator
// calls exactly two of its functions:
//
//	IndexSnapshot  index_snapshot(campaign, snapshot_root) -> the index dict
//	SaveIndex      save_index(campaign, index) -> the artifact path
//
// The default is the absent-module behavior: an explicit error. Python has no
// "module missing" path, so the honest feature-absent behavior is to fail
// loudly instead of pinning a phantom index. The call sites that READ the
// index (load_protocol_model's coverage seeding) do not go through the seam
// at all: they read the artifact file when it exists, so with no index
// artifact they take exactly Python's absent-artifact branch.
type StructuralIndexAPI struct {
	IndexSnapshot func(c *state.Campaign, root string) (validation.Value, error)
	SaveIndex     func(c *state.Campaign, index validation.Value) (string, error)
}

func notWiredIndexSnapshot(*state.Campaign, string) (validation.Value, error) {
	return validation.VNull(), orchestrationError(
		"structural_index module not wired: cannot build the structural index")
}

func notWiredSaveIndex(*state.Campaign, validation.Value) (string, error) {
	return "", orchestrationError(
		"structural_index module not wired: cannot save the structural index")
}

var siAPI = StructuralIndexAPI{
	IndexSnapshot: notWiredIndexSnapshot,
	SaveIndex:     notWiredSaveIndex,
}

// SetStructuralIndex installs the structural_index implementation (P3 wires
// this). A nil argument — or a nil field — restores the absent-module default.
func SetStructuralIndex(api StructuralIndexAPI) {
	if api.IndexSnapshot == nil {
		api.IndexSnapshot = notWiredIndexSnapshot
	}
	if api.SaveIndex == nil {
		api.SaveIndex = notWiredSaveIndex
	}
	siAPI = api
}

// BuildStructuralIndex is build_structural_index(): parse the pinned snapshot
// tree into the program graph, save it, register it, and advance to
// PROTOCOL_INTELLIGENCE.
func (o *Orchestrator) BuildStructuralIndex() (validation.Value, error) {
	snapID, err := o.C.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	if snapID == nil {
		return validation.VNull(), orchestrationError(
			"pin a snapshot before the structural index")
	}
	meta, err := validation.ReadJson(filepath.Join(o.C.Dir, "snapshots", *snapID,
		"snapshot.json"))
	if err != nil {
		return validation.VNull(), err
	}
	index, err := siAPI.IndexSnapshot(o.C, strAt(objAt(meta, "source"), "root"))
	if err != nil {
		return validation.VNull(), err
	}
	out, err := siAPI.SaveIndex(o.C, index)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := o.C.RegisterArtifact("structural-index", out, "", snapID); err != nil {
		return validation.VNull(), err
	}
	if err := o.C.SetStage("structural-index", "done", validation.VNull(),
		ptr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	if err := o.C.SetPhase("PROTOCOL_INTELLIGENCE", "index built"); err != nil {
		return validation.VNull(), err
	}
	return index, nil
}
