package probes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// saveStateFunc writes campaign state (campaign._save). A package-level seam
// (the floors pattern) so the blank store is testable without a campaign
// directory.
var saveStateFunc = defaultSaveState

// SetSaveState installs the state writer; nil restores the built-in default.
func SetSaveState(f func(*state.Campaign, validation.Value) error) {
	if f == nil {
		saveStateFunc = defaultSaveState
		return
	}
	saveStateFunc = f
}

// defaultSaveState is campaign._save: updated_at is replaced in place and the
// state re-written under the campaign_state schema.
func defaultSaveState(c *state.Campaign, st validation.Value) error {
	// r14: this local _save re-implementation bypassed the campaign
	// lock (unlocked read-modify-write racing another process). The
	// twin body now lives in exactly one place: state.SaveState.
	return c.SaveState(st)
}

// CampaignSurface is campaign_surface: the campaign's
// artifacts/probe_surface.json, or nil when the artifact does not exist. A
// corrupt artifact raises — an unreadable surface must be loud.
func CampaignSurface(c *state.Campaign) (*validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "probe_surface.json")
	if !fileExists(p) {
		return nil, nil
	}
	v, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// CampaignIndex is campaign_index: the campaign's structural index artifact,
// or nil when it is absent or unreadable.
func CampaignIndex(c *state.Campaign) (*validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "structural_index.json")
	if !fileExists(p) {
		return nil, nil
	}
	v, err := validation.ReadJson(p)
	if err != nil {
		return nil, nil
	}
	return &v, nil
}

// CampaignIndexSha is campaign_index_sha: the current index's sha, or nil.
// The closure clause fails CLOSED on nil.
func CampaignIndexSha(c *state.Campaign) *string {
	idx, err := CampaignIndex(c)
	if err != nil || idx == nil {
		return nil
	}
	sha := IndexSha(*idx)
	return &sha
}

// BlankEntries is blank_entries: every persisted attestation, in decision
// order.
func BlankEntries(c *state.Campaign) []validation.Value {
	st, err := c.State()
	if err != nil {
		return nil
	}
	return vObjList(st, "probe_blanks")
}

// CampaignBlanks is campaign_blanks: probe axis name -> the attestation
// recorded for it.
func CampaignBlanks(c *state.Campaign) (map[string]validation.Value, error) {
	reg := RegisteredAxes()
	// Python builds by_lens from registered_axes(), which is SORTED by axis,
	// so the sorted-last axis carrying a lens wins the lens fallback. Ranging
	// the Go map here would make an `axis: L-01` attestation resolve to a
	// different probe axis run to run.
	byLens := map[string]string{}
	for _, axis := range sortedKeys(reg) {
		byLens[reg[axis].Lens] = axis
	}
	out := map[string]validation.Value{}
	for _, entry := range BlankEntries(c) {
		token := vStr(entry, "probe_axis")
		if token == "" {
			token = vStr(entry, "axis")
		}
		axis := ""
		if _, ok := reg[token]; ok {
			axis = token
		} else if a, ok := byLens[token]; ok {
			axis = a
		}
		if axis != "" {
			out[axis] = entry
		}
	}
	return out, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	if err == nil {
		return true
	}
	return !errors.Is(err, fs.ErrNotExist)
}
