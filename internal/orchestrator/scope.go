// scope.go: phases 1 (SCOPE) and 2 (SNAPSHOT).
package orchestrator

import (
	"path/filepath"

	"websec/internal/bounty"
	"websec/internal/snapshot"
	"websec/internal/validation"
)

// Scope is scope(): load the bounty policy (when one is given), register it,
// record its path in the campaign state and close the scope stage. With no
// policy it returns the deterministic "load before BOUNTY_GATE" note — the
// gate itself is what refuses to run without one.
func (o *Orchestrator) Scope(policyPath string) (validation.Value, error) {
	if err := o.C.SetPhase("SCOPE", "load bounty policy"); err != nil {
		return validation.VNull(), err
	}
	policy := validation.VNull()
	if policyPath != "" {
		loaded, err := bounty.LoadPolicy(policyPath)
		if err != nil {
			return validation.VNull(), err
		}
		policy = loaded
		dest := filepath.Join(o.C.Dir, "bounty_policy.json")
		saved, err := bounty.SavePolicy(o.C, policy, &dest)
		if err != nil {
			return validation.VNull(), err
		}
		doc, err := validation.ReadJson(o.C.StatePath)
		if err != nil {
			return validation.VNull(), err
		}
		doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(saved))
		if err := validation.WriteJson(o.C.StatePath, doc, "campaign_state"); err != nil {
			return validation.VNull(), err
		}
	}
	if err := o.C.SetStage("scope", "done", validation.VNull(),
		ptr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	if policy.Kind == validation.Obj && len(policy.O) > 0 {
		return policy, nil
	}
	return validation.VObj(kvOf("note", validation.VStr(
		"no policy provided; load before BOUNTY_GATE"))), nil
}

// SnapshotOpts is snapshot()'s keyword tail (Python: deployment=None,
// chain=None, config=None).
type SnapshotOpts struct {
	Deployment *validation.Value
	Chain      *validation.Value
	Config     *validation.Value
}

// Snapshot is snapshot(): pin the audit reality (source tree, plus the
// optional deployment and chain pins) and advance to STRUCTURAL_INDEX.
func (o *Orchestrator) Snapshot(target string, opts SnapshotOpts) (validation.Value, error) {
	if err := o.C.SetPhase("SNAPSHOT", "pin audit reality"); err != nil {
		return validation.VNull(), err
	}
	snap, err := snapshot.PinSourceSnapshot(o.C, target, opts.Config, nil)
	if err != nil {
		return validation.VNull(), err
	}
	if opts.Deployment != nil && pyTruthyBigNonEmpty(*opts.Deployment) {
		snap, err = snapshot.AttachDeploymentPin(o.C, strAt(snap, "snapshot_id"),
			*opts.Deployment)
		if err != nil {
			return validation.VNull(), err
		}
	}
	if opts.Chain != nil && pyTruthyBigNonEmpty(*opts.Chain) {
		snap, err = snapshot.AttachChainPin(o.C, strAt(snap, "snapshot_id"),
			*opts.Chain)
		if err != nil {
			return validation.VNull(), err
		}
	}
	if err := o.C.SetStage("snapshot", "done", validation.VNull(),
		ptr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	if err := o.C.SetPhase("STRUCTURAL_INDEX", "snapshot pinned"); err != nil {
		return validation.VNull(), err
	}
	return snap, nil
}
