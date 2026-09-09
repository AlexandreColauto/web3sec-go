// Port of tests/test_sequence_pin_gate.py — the sequence gate keys off the
// DEPLOYMENT PIN, not the step count.
package sequencepoc

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// multiStep is MULTI_STEP.
func multiStep(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{"finding_id": "F-test", "exploit_sequence": [
      {"step": 1, "actor": "attacker", "action": "donate"},
      {"step": 2, "actor": "victim", "action": "deposit"}]}`)
}

// singleStep is SINGLE_STEP.
func singleStep(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{"finding_id": "F-test2", "exploit_sequence": [
      {"step": 1, "actor": "attacker", "action": "drain"}]}`)
}

// pinGateCampaign is the `camp` fixture: a source-only pin (no deployment).
func pinGateCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c := testCampaign(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "app.py"),
		[]byte("def drain(): pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// sid is _sid.
func sid(t *testing.T, c *state.Campaign) string {
	t.Helper()
	id, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("no active snapshot")
	}
	return *id
}

func TestSnapshotHasForkTargetSourceOnlyIsFalse(t *testing.T) {
	c := pinGateCampaign(t)
	if SnapshotHasForkTarget(c) {
		t.Fatal("a source-only pin has no fork target")
	}
}

func TestSnapshotHasForkTargetTrueWithDeploymentPin(t *testing.T) {
	c := pinGateCampaign(t)
	dep := mustParse(t, `{"network": "ethereum", "contracts": [
      {"name": "Vault", "address": "0x`+repeat("1", 40)+`"}]}`)
	if _, err := snapshot.AttachDeploymentPin(c, sid(t, c), dep); err != nil {
		t.Fatal(err)
	}
	if !SnapshotHasForkTarget(c) {
		t.Fatal("deployment pin must count as a fork target")
	}
}

func TestOnchainRequiredOffchainMultistepIsFalse(t *testing.T) {
	c := pinGateCampaign(t)
	if !IsSequenceRequired(multiStep(t)) {
		t.Fatal("shape is still multi-step")
	}
	if OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("off-chain (no pin): the on-chain demand must not fire")
	}
}

func TestOnchainRequiredOnchainMultistepIsTrue(t *testing.T) {
	c := pinGateCampaign(t)
	dep := mustParse(t, `{"network": "ethereum", "contracts": [
      {"name": "Vault", "address": "0x`+repeat("2", 40)+`"}]}`)
	if _, err := snapshot.AttachDeploymentPin(c, sid(t, c), dep); err != nil {
		t.Fatal(err)
	}
	if !OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("on-chain campaign keeps the strict requirement")
	}
}

func TestOnchainRequiredSingleStepIsAlwaysFalse(t *testing.T) {
	c := pinGateCampaign(t)
	if IsSequenceRequired(singleStep(t)) {
		t.Fatal("single step must not be sequence-required")
	}
	if OnchainSequenceRequired(c, singleStep(t)) {
		t.Fatal("off-chain single step must be false")
	}
	dep := mustParse(t, `{"network": "ethereum", "contracts": [
      {"name": "Vault", "address": "0x`+repeat("3", 40)+`"}]}`)
	if _, err := snapshot.AttachDeploymentPin(c, sid(t, c), dep); err != nil {
		t.Fatal(err)
	}
	if OnchainSequenceRequired(c, singleStep(t)) {
		t.Fatal("single step stays false on chain too")
	}
}

func TestChainPinAlsoCountsAsForkTarget(t *testing.T) {
	c := pinGateCampaign(t)
	chain := mustParse(t, `{"network": "ethereum", "fork_block": 19000000}`)
	if _, err := snapshot.AttachChainPin(c, sid(t, c), chain); err != nil {
		t.Fatal(err)
	}
	if !SnapshotHasForkTarget(c) {
		t.Fatal("chain pin must count as a fork target")
	}
	if !OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("chain-pinned multi-step must be onchain-required")
	}
}

func TestNoActiveSnapshotIsFalse(t *testing.T) {
	c := testCampaign(t)
	if SnapshotHasForkTarget(c) {
		t.Fatal("no snapshot: false")
	}
	if OnchainSequenceRequired(c, multiStep(t)) {
		t.Fatal("no snapshot: onchain false")
	}
}

// repeat is Python's "c" * n.
func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
