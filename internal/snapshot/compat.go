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

// pinThenLog is the snapshot package's r40e UNWIND-ON-REFUSAL door for the
// post-pin attachment writers. snapshot.json is campaign TRUTH: the trust
// gate (AssertSnapshotCompatible / ReverifyRequired), coverage's
// active-deployment read and `snap` all consume it, and its `manifest` block
// is re-derived from the pin it describes. AttachDeploymentPin and
// AttachChainPin rewrite that file and then APPEND
// snapshot.deployment_attached / snapshot.chain_attached — a refused append
// (torn ledger, mirror lag or hole, held lock, unreadable ledger) used to
// leave the new deployment/chain pin on disk with no event, so the campaign
// read as pinned to reality the ledger never recorded, and the retry after
// the heal wrote a SECOND pin over the first.
//
// So the file's bytes are snapshotted before the write, the whole
// snapshot -> write -> append -> restore window is held under the campaign
// process lock the inner Log re-enters by depth, and ANY refusal restores
// those exact bytes — or removes a file that did not exist yet, never
// creating an empty one. A FAILED restore means the pin bytes are still
// AHEAD of the refused event; name both failures so no caller can report a
// clean unwind that never happened.
//
// The pin path itself (PinSourceSnapshot) does not need this door: it writes
// into a brand-new dir behind the r8 half-pin rollback (pin.go:370-397), so
// a refused snapshot.excluded removes what it installed.
func pinThenLog(c *state.Campaign, path string, write func() error,
	log func() error) error {
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	prevRaw, perr := os.ReadFile(path)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	restore := func() error {
		if had {
			return os.WriteFile(path, prevRaw, 0o644)
		}
		if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	fail := func(err error) error {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s holds "+
				"post-write bytes with no event; repair by hand before "+
				"continuing)", err, rerr, filepath.Base(path))
		}
		return err
	}
	if err := write(); err != nil {
		return fail(err)
	}
	if err := log(); err != nil {
		return fail(err)
	}
	return nil
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
	n := 0
	if contracts := sget(deployment, "contracts"); contracts.Kind == validation.Arr {
		n = len(contracts.A)
	}
	data := validation.VObj(
		validation.KV{K: "contracts", V: validation.VInt(int64(n))},
		validation.KV{K: "network", V: sget(deployment, "network")},
	)
	// r40e: the deployment pin and its event land together or not at all.
	if err := pinThenLog(c, path,
		func() error { return validation.WriteJson(path, snap, "snapshot") },
		func() error {
			_, lerr := c.Log("snapshot.deployment_attached", &snapshotID, &data)
			return lerr
		}); err != nil {
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
	data := validation.VObj(
		validation.KV{K: "fork_block", V: sget(chain, "fork_block")},
	)
	// r40e: the chain pin and its event land together or not at all.
	if err := pinThenLog(c, path,
		func() error { return validation.WriteJson(path, snap, "snapshot") },
		func() error {
			_, lerr := c.Log("snapshot.chain_attached", &snapshotID, &data)
			return lerr
		}); err != nil {
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
