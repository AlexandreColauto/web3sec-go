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
	// R3-8 (Morph r3 defect 8): a mid-campaign policy reload used to drag
	// the phase back to SCOPE behind the stage ledger's back. Reloading a
	// policy is a policy event, not a campaign rewind: past SCOPE the
	// phase is left exactly where it is (on a fresh campaign the phase is
	// already SCOPE and SetPhase was a same-phase no-op anyway, so no
	// bytes move there either). The CLI announces the skip.
	if st, err := o.C.State(); err != nil {
		return validation.VNull(), err
	} else if validation.ObjStr(st, "phase") == "SCOPE" {
		if err := o.C.SetPhase("SCOPE", "load bounty policy"); err != nil {
			return validation.VNull(), err
		}
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
		// r14: the policy_path stamp is a read-modify-write of
		// campaign_state; it must hold the campaign lock for the whole
		// window like every other writer (state.SaveState law). Twin
		// shape kept — this write does not bump updated_at (Python's
		// scope path writes the file directly), so the lock is taken
		// explicitly around the SAME bytes, not routed through
		// SaveState.
		if err := o.C.LockProcess(); err != nil {
			return validation.VNull(), err
		}
		doc, err := validation.ReadJson(o.C.StatePath)
		if err != nil {
			o.C.UnlockProcess()
			return validation.VNull(), err
		}
		doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(saved))
		err = validation.WriteJson(o.C.StatePath, doc, "campaign_state")
		o.C.UnlockProcess()
		if err != nil {
			return validation.VNull(), err
		}
		// R3-2a (Morph r3 defect 2): the policy decides what counts as IN
		// SCOPE, so it gets the same integrity story as every other
		// campaign input — a registry row (kind "policy" is already in
		// the campaign_state enum), its sha256, and an
		// artifact.registered event, via the standard one-row-per-path
		// seam (a re-load refreshes and re-hashes, never ghosts). The
		// audit's re-hash-every-row check now covers deleting
		// exclusions from the campaign copy.
		if _, err := o.C.RegisterOrRefresh("policy", saved,
			"bounty policy (scope)", nil,
			"scope loaded the bounty policy"); err != nil {
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
