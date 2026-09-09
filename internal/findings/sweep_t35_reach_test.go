package findings

// Port of tests/test_reachability.py's diagnostic half: a deployment pin
// clears the pin demand, the RPC demand clears when FORK_RPC_URL is set, and
// both pins clear E6 entirely.

import (
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func t35ReachCamp(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := ingestCamp(t)
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v %v", sid, err)
	}
	return c, *sid
}

func t35DeploymentPin() validation.Value {
	return validation.VObj(
		kv("network", validation.VStr("ethereum-mainnet")),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Vault")),
			kv("address", validation.VStr("0x"+
				strings.Repeat("a", 40))),
			kv("role", validation.VStr("core"))))),
		kv("verification_ratio", validation.VFloat(1.0)))
}

func t35ChainPin() validation.Value {
	return validation.VObj(
		kv("network", validation.VStr("ethereum-mainnet")),
		kv("chain_id", validation.VInt(1)),
		kv("fork_block", validation.VInt(20358000)),
		kv("rpc", validation.VStr("https://rpc")))
}

// Port of tests/test_reachability.py::test_e5_deployment_pin_only_rpc_missing.
func TestE5DeploymentPinOnlyRpcMissing(t *testing.T) {
	c, sid := t35ReachCamp(t)
	if _, err := snapshot.AttachDeploymentPin(c, sid, t35DeploymentPin()); err != nil {
		t.Fatal(err)
	}
	missing, err := ReachabilityDiagnostic(c, "E5", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range missing {
		if strings.Contains(m, "pin") {
			t.Errorf("pin still demanded with a deployment pin: %q", m)
		}
	}
	foundRPC := false
	for _, m := range missing {
		if strings.Contains(m, "FORK_RPC_URL") {
			foundRPC = true
		}
	}
	if !foundRPC {
		t.Errorf("missing = %v, want a FORK_RPC_URL demand", missing)
	}
	t.Setenv("FORK_RPC_URL", "https://mainnet.rpc")
	missing, err = ReachabilityDiagnostic(c, "E5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("E5 diagnostic = %v, want empty", missing)
	}
}

// Port of tests/test_reachability.py::test_reachability_clear_after_pins.
func TestReachabilityClearAfterPins(t *testing.T) {
	c, sid := t35ReachCamp(t)
	if _, err := snapshot.AttachDeploymentPin(c, sid, t35DeploymentPin()); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.AttachChainPin(c, sid, t35ChainPin()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FORK_RPC_URL", "https://mainnet.rpc")
	missing, err := ReachabilityDiagnostic(c, "E6", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("E6 diagnostic = %v, want empty", missing)
	}
}
