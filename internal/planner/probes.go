package planner

import (
	"sync"

	"websec/internal/state"
	"websec/internal/validation"
)

// AxisMeta is one entry of probes.registered_axes(): axis -> {axis, probe,
// lens}. One registry read by the A3 closure clause and the A4 cockpit, so the
// axis/lens mapping cannot drift between them.
type AxisMeta struct {
	Axis  string
	Probe string
	Lens  string
}

// ProbeSpec is the slice of PROBES[probe_id] the planner reads: the probe's
// axis, its lens and the disposition anchors it can produce. Anchors is a
// pointer so "no anchors key" (Python None) is distinguishable from an empty
// list — mark_answered's rejection message renders the difference.
type ProbeSpec struct {
	Axis    string
	Lens    string
	Anchors *[]string
}

// ProbesAPI is the seam onto the probes module (P3, unported). The zero value
// of every field means "probe feature absent": no registered axes, no surface,
// no blanks, no registry — exactly the behavior a campaign with no probe
// artifact sees in Python.
//
// Installer: SetProbes. Later tasks wire the real module's functions here
// (probes.RegisteredAxes, probes.AxisSurfaceBlocker, probes.RowShapeSha,
// probes.CampaignBlanks, probes.CampaignSurface, probes.CampaignIndexSha,
// probes.PROBES, probes.AnchorAllowed, probes.RowAnchorValue,
// probes.AnchorRef, probes.CampaignIndex).
type ProbesAPI struct {
	// RegisteredAxes is probes.registered_axes(): axis name -> AxisMeta.
	RegisteredAxes func() map[string]AxisMeta
	// AxisSurfaceBlocker is probes.axis_surface_blocker(axis, blank=...):
	// "" means no surface-level blocker.
	AxisSurfaceBlocker func(axis validation.Value,
		blank *validation.Value) string
	// RowShapeSha is probes.row_shape_sha(row): sha256[:16] of the row's
	// whole coordinate set.
	RowShapeSha func(row validation.Value) string
	// CampaignBlanks is probes.campaign_blanks(campaign): probe axis ->
	// persisted attestation.
	CampaignBlanks func(c *state.Campaign) (map[string]validation.Value, error)
	// CampaignSurface is probes.campaign_surface(campaign): the campaign's
	// probe_surface.json, or nil (the grandfather case).
	CampaignSurface func(c *state.Campaign) (*validation.Value, error)
	// CampaignIndexSha is probes.campaign_index_sha(campaign): the current
	// structural index's sha, or nil.
	CampaignIndexSha func(c *state.Campaign) *string
	// CampaignBugClasses is the diversity clause's view of the campaign:
	// every canonical root_cause.class its stored findings name, deduped and
	// sorted. Unlike the surface/blanks readers this is core findings-store
	// data, not a probe artifact, so the feature-absent default still reads
	// the findings directory (a campaign with no findings yields none).
	CampaignBugClasses func(c *state.Campaign) ([]string, error)
	// Probes is the PROBES registry: probe_id -> ProbeSpec.
	Probes map[string]ProbeSpec
	// AnchorAllowed is probes.anchor_allowed(probe_id, anchor).
	AnchorAllowed func(probeID, anchor string) bool
	// RowAnchorValue is probes.row_anchor_value(row, anchor).
	RowAnchorValue func(row validation.Value,
		anchor string) (validation.Value, error)
	// AnchorRef is probes.anchor_ref(row, anchor, index).
	AnchorRef func(row validation.Value, anchor string,
		index *validation.Value) (string, error)
	// CampaignIndex is probes.campaign_index(campaign): the campaign's
	// structural index artifact, or nil.
	CampaignIndex func(c *state.Campaign) (*validation.Value, error)
}

// defaultProbesAPI is the "no probe feature" implementation: every reader
// returns the empty/absent value, so divergence_status is the pre-A3 gate and
// mark_answered's anchor path fails closed (unreachable without a registry).
func defaultProbesAPI() ProbesAPI {
	return ProbesAPI{
		RegisteredAxes: func() map[string]AxisMeta { return map[string]AxisMeta{} },
		AxisSurfaceBlocker: func(validation.Value,
			*validation.Value) string {
			return ""
		},
		RowShapeSha:   func(validation.Value) string { return "" },
		Probes:        map[string]ProbeSpec{},
		AnchorAllowed: func(string, string) bool { return false },
		CampaignBlanks: func(*state.Campaign) (map[string]validation.Value, error) {
			return map[string]validation.Value{}, nil
		},
		CampaignSurface: func(*state.Campaign) (*validation.Value, error) {
			return nil, nil
		},
		CampaignIndexSha:   func(*state.Campaign) *string { return nil },
		CampaignBugClasses: campaignBugClasses,
		RowAnchorValue: func(row validation.Value,
			anchor string) (validation.Value, error) {
			return validation.VNull(), errValue(
				"probes module is not wired: cannot resolve anchor " +
					validation.PyReprStr(anchor))
		},
		AnchorRef: func(row validation.Value, anchor string,
			index *validation.Value) (string, error) {
			return "", errValue(
				"probes module is not wired: cannot render anchor " +
					validation.PyReprStr(anchor))
		},
		CampaignIndex: func(*state.Campaign) (*validation.Value, error) {
			return nil, nil
		},
	}
}

var (
	probesMu  sync.RWMutex
	probesAPI = defaultProbesAPI()
	// probesOwnsIndexSha records whether the last SetProbes supplied its
	// own CampaignIndexSha. When it did not, PB() layers in the seam
	// installed by SetCampaignIndexSha (the structural-index port), so an
	// unrelated SetProbes call cannot silently drop the §5.7 tree hash.
	probesOwnsIndexSha bool

	indexShaMu sync.RWMutex
	indexShaFn func(*state.Campaign) *string
)

// SetCampaignIndexSha installs only the structural-index hash seam
// (probes.campaign_index_sha). Unlike a SetProbes call it cannot disturb any
// other probes hook, and it survives a later SetProbes that leaves
// CampaignIndexSha nil.
func SetCampaignIndexSha(fn func(c *state.Campaign) *string) {
	indexShaMu.Lock()
	indexShaFn = fn
	indexShaMu.Unlock()
}

// SetProbes installs the probes implementation. Nil function fields (and a nil
// Probes map) fall back to the feature-absent default, so a partial install
// can never nil-panic. Passing a fully nil ProbesAPI restores the default.
func SetProbes(p ProbesAPI) {
	ownsIndexSha := p.CampaignIndexSha != nil
	d := defaultProbesAPI()
	if p.RegisteredAxes == nil {
		p.RegisteredAxes = d.RegisteredAxes
	}
	if p.AxisSurfaceBlocker == nil {
		p.AxisSurfaceBlocker = d.AxisSurfaceBlocker
	}
	if p.RowShapeSha == nil {
		p.RowShapeSha = d.RowShapeSha
	}
	if p.CampaignBlanks == nil {
		p.CampaignBlanks = d.CampaignBlanks
	}
	if p.CampaignSurface == nil {
		p.CampaignSurface = d.CampaignSurface
	}
	if p.CampaignIndexSha == nil {
		p.CampaignIndexSha = d.CampaignIndexSha
	}
	if p.CampaignBugClasses == nil {
		p.CampaignBugClasses = d.CampaignBugClasses
	}
	if p.Probes == nil {
		p.Probes = d.Probes
	}
	if p.AnchorAllowed == nil {
		p.AnchorAllowed = d.AnchorAllowed
	}
	if p.RowAnchorValue == nil {
		p.RowAnchorValue = d.RowAnchorValue
	}
	if p.AnchorRef == nil {
		p.AnchorRef = d.AnchorRef
	}
	if p.CampaignIndex == nil {
		p.CampaignIndex = d.CampaignIndex
	}
	probesMu.Lock()
	probesAPI = p
	probesOwnsIndexSha = ownsIndexSha
	probesMu.Unlock()
}

// PB is the installed probes implementation (the Python `PB` alias). The
// structural-index hash seam is layered in unless the probes port supplied
// its own (see SetCampaignIndexSha).
func PB() ProbesAPI {
	probesMu.RLock()
	p, owns := probesAPI, probesOwnsIndexSha
	probesMu.RUnlock()
	if !owns {
		indexShaMu.RLock()
		fn := indexShaFn
		indexShaMu.RUnlock()
		if fn != nil {
			p.CampaignIndexSha = fn
		}
	}
	return p
}

// RegisteredAxes is PB.registered_axes().
func registeredAxes() map[string]AxisMeta { return PB().RegisteredAxes() }

// probeAnchors is (PB.PROBES.get(pid) or {}).get("anchors") or [].
func probeAnchors(pid string) []string {
	spec, ok := PB().Probes[pid]
	if !ok || spec.Anchors == nil {
		return nil
	}
	return *spec.Anchors
}
