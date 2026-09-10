// Deployment/chain pins, the active-snapshot trust gate, and re-verify
// triage.
//
// Ports web3sec-final/src/webv2/snapshot.py::attach_deployment_pin,
// ::attach_chain_pin, ::assert_snapshot_compatible, ::reverify_required and
// ::SnapshotMismatch. Error-message text is contractual (Python !r
// quoting); pin_snapshot / active_snapshot themselves already live in
// internal/state/campaign.go (Task 11), so this file only consumes them.
package snapshot

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// snapPath resolves the snapshot dir + snapshot.json path, raising the
// exact Python FileNotFoundError text when the pin is absent.
func snapPath(c *state.Campaign, snapshotID string) (string, error) {
	snapDir := filepath.Join(c.Dir, "snapshots", snapshotID)
	if _, err := os.Stat(snapDir); err != nil {
		return "", fmt.Errorf("no pinned snapshot %s in this campaign",
			validation.PyReprStr(snapshotID))
	}
	return filepath.Join(snapDir, "snapshot.json"), nil
}

// AttachDeploymentPin is attach_deployment_pin: attach/replace the
// deployment pin (what is actually on-chain), refresh the manifest so it
// describes the new pin, schema-validate on write, and log
// snapshot.deployment_attached. Returns the updated snapshot.
func AttachDeploymentPin(c *state.Campaign, snapshotID string, deployment validation.Value) (validation.Value, error) {
	path, err := snapPath(c, snapshotID)
	if err != nil {
		return validation.VNull(), err
	}
	snap, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	snap.O = validation.SetOrAppend(snap.O, "deployment", deployment)
	snapDir := filepath.Dir(path)
	if snap, err = RefreshManifest(snap, snapDir); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(path, snap, "snapshot"); err != nil {
		return validation.VNull(), err
	}
	n := 0
	if contracts := sget(deployment, "contracts"); contracts.Kind == validation.Arr {
		n = len(contracts.A)
	}
	data := validation.VObj(
		validation.KV{K: "contracts", V: validation.VInt(int64(n))},
		validation.KV{K: "network", V: sget(deployment, "network")},
	)
	if _, err := c.Log("snapshot.deployment_attached", &snapshotID, &data); err != nil {
		return validation.VNull(), err
	}
	return snap, nil
}

// AttachChainPin is attach_chain_pin: attach/replace the fork/state pin,
// refresh the manifest, schema-validate on write, and log
// snapshot.chain_attached. Returns the updated snapshot.
func AttachChainPin(c *state.Campaign, snapshotID string, chain validation.Value) (validation.Value, error) {
	path, err := snapPath(c, snapshotID)
	if err != nil {
		return validation.VNull(), err
	}
	snap, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	snap.O = validation.SetOrAppend(snap.O, "chain", chain)
	snapDir := filepath.Dir(path)
	if snap, err = RefreshManifest(snap, snapDir); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(path, snap, "snapshot"); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "fork_block", V: sget(chain, "fork_block")},
	)
	if _, err := c.Log("snapshot.chain_attached", &snapshotID, &data); err != nil {
		return validation.VNull(), err
	}
	return snap, nil
}

// SnapshotMismatch is SnapshotMismatch: a finding's source pin does not
// match the campaign's active pin — re-verify instead of trusting.
type SnapshotMismatch struct {
	Message string
}

func (e *SnapshotMismatch) Error() string { return e.Message }

// valuesEqual compares two pin values the way Python `!=` compares the
// underlying JSON: canonical-form equality (key order-insensitive).
func valuesEqual(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	return Canonical(a) == Canonical(b)
}

// findingIDString renders finding.get('finding_id') the way an f-string
// str() formats it: raw for strings, None for missing, repr otherwise.
func findingIDString(finding validation.Value) string {
	v := sget(finding, "finding_id")
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "None"
	default:
		return validation.PyRepr(v)
	}
}

// AssertSnapshotCompatible is assert_snapshot_compatible: the trust gate.
// No active snapshot -> True (nothing pinned yet: verdicts permitted).
// Matching source pin -> True. Differing source pin -> SnapshotMismatch
// under strict, False under non-strict. The message is byte-exact with the
// Python f-string, !r quoting on both pins.
func AssertSnapshotCompatible(c *state.Campaign, finding validation.Value, strict bool) (bool, error) {
	active, err := c.ActiveSnapshot()
	if err != nil {
		return false, err
	}
	if active.Kind != validation.Obj || len(active.O) == 0 {
		return true, nil // nothing pinned yet: MODE-OFF, verdicts permitted
	}
	pins := sget(finding, "snapshot_ids")
	if valuesEqual(sget(pins, "source"), sget(active, "snapshot_id")) {
		return true, nil
	}
	if strict {
		return false, &SnapshotMismatch{Message: "finding " + findingIDString(finding) +
			" was discovered against " + validation.PyRepr(sget(pins, "source")) +
			" but campaign is pinned to " + validation.PyRepr(sget(active, "snapshot_id")) +
			"; re-verify instead of trusting"}
	}
	return false, nil
}

// ReverifyRequired is reverify_required: true when a finding's evidence
// must be reproduced against the active snapshot before it may be trusted.
// A nil active id (nothing pinned) never requires re-verification.
func ReverifyRequired(finding validation.Value, activeSnapshotID *string) bool {
	if activeSnapshotID == nil {
		return false
	}
	return !valuesEqual(sget(sget(finding, "snapshot_ids"), "source"),
		validation.VStr(*activeSnapshotID))
}
