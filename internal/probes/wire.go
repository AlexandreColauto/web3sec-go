// wire.go: installs this module into the two seams that expect the probes
// module — the planner's ProbesAPI (the closure clause, the cockpit and the
// disposition path) and the audit's section 13. Python has no wiring step
// (the module is just imported), so init() is the Go spelling of that import
// edge; Wire() is the explicit, idempotent form for tests.
package probes

import (
	"websec/internal/audit/sections"
	"websec/internal/planner"
)

// Wire installs the real probes implementation on every seam.
func Wire() {
	planner.SetProbes(planner.ProbesAPI{
		RegisteredAxes: func() map[string]planner.AxisMeta {
			out := map[string]planner.AxisMeta{}
			for axis, meta := range RegisteredAxes() {
				out[axis] = planner.AxisMeta{Axis: meta.Axis,
					Probe: meta.Probe, Lens: meta.Lens}
			}
			return out
		},
		AxisSurfaceBlocker: AxisSurfaceBlocker,
		RowShapeSha:        RowShapeSha,
		CampaignBlanks:     CampaignBlanks,
		CampaignSurface:    CampaignSurface,
		CampaignIndexSha:   CampaignIndexSha,
		Probes:             plannerProbes(),
		AnchorAllowed:      AnchorAllowed,
		RowAnchorValue:     RowAnchorValue,
		AnchorRef:          AnchorRef,
		CampaignIndex:      CampaignIndex,
	})
	sections.SetProbeSurfaceAudit(NewProbeSurfaceAudit())
}

// plannerProbes is the PROBES registry projected onto planner.ProbeSpec.
func plannerProbes() map[string]planner.ProbeSpec {
	out := map[string]planner.ProbeSpec{}
	for pid, spec := range probesTable {
		anchors := append([]string(nil), spec.anchors...)
		out[pid] = planner.ProbeSpec{Axis: spec.axis, Lens: spec.lens,
			Anchors: &anchors}
	}
	return out
}

func init() { Wire() }
