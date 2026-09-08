// Section 13: probe surface (A4) — the mechanical candidate plane is derived
// data, so it is audited like every other derived claim. Four checks, all
// re-derived from the artifacts (never trusted from the plan): index_sha
// staleness, plan rows == surface rows in both directions once emitted,
// blank attestations vs their probes.blank events and cited keys, and the I3
// row re-derivation.
//
// The probes + structural_index modules are not ported, so the whole
// populated branch arrives through the ProbeSurfaceAuditAPI seam. The
// default is Python's no-surface branch (probes.campaign_surface returns
// None), and an error from the seam mirrors Python's `except Exception`
// degraded entry. The 4-check logic itself belongs to the P3 probes port.
package sections

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// ProbeSurfaceAuditAPI is the probe-surface seam: AuditSurface returns the
// whole section for a campaign that HAS a probe surface artifact, or the
// no-surface dict when it does not.
type ProbeSurfaceAuditAPI interface {
	AuditSurface(c *state.Campaign) (validation.Value, error)
}

// noProbeSurface is the absent-module default: campaign_surface -> None.
type noProbeSurface struct{}

// AuditSurface is Python's `if surface is None:` branch.
func (noProbeSurface) AuditSurface(*state.Campaign) (validation.Value, error) {
	return probeSurfaceNoSurface(), nil
}

// probeSurfaceNoSurface is the exact no-surface dict, note included.
func probeSurfaceNoSurface() validation.Value {
	return validation.VObj(
		KV("checked", validation.VInt(0)),
		KV("problems", validation.VArr()),
		KV("ok", validation.VBool(true)),
		KV("note", validation.VStr("no probe surface artifact (campaign "+
			"predates or has not run `webv2 probes`)")),
	)
}

var probeSurfaceImpl ProbeSurfaceAuditAPI = noProbeSurface{}

// SetProbeSurfaceAudit installs the probe-surface seam; nil restores the
// default (no probe surface artifact = Python's grandfather case).
func SetProbeSurfaceAudit(p ProbeSurfaceAuditAPI) {
	if p == nil {
		p = noProbeSurface{}
	}
	probeSurfaceImpl = p
}

// ProbeSurface is audit.py section 13: the seam's section, or Python's
// degraded entry when the section raises.
func ProbeSurface(c *state.Campaign) (validation.Value, error) {
	sec, err := probeSurfaceImpl.AuditSurface(c)
	if err != nil {
		return validation.VObj(
			KV("checked", validation.VNull()),
			KV("problems", validation.VArr(validation.VStr(
				"probe surface section failed: "+err.Error()))),
			KV("ok", validation.VBool(false)),
		), nil
	}
	return sec, nil
}
