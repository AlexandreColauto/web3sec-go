// i5_test.go: Wave I Task 3 (I5a) — threshold_without_enforcement and
// relayer_single_key. Fixture files under testdata/ are canonical; the inline
// trees below pin the evidence semantics the two evaluators are allowed to
// read (same-contract scoping, guard-text co-signer evidence, authz gates).
//
// HONESTY: the structural index carries NO state-variable values and NO state
// variable types (parser.go:1059-1061 — a state-variable node is
// {id,kind,name,path,line}; its initializer is dropped by pyState at
// parser.go:87). Every match below is a NAME-AND-REFERENCE shape, never a
// value claim: "no guard mentions this threshold variable" is not "the
// threshold is wrong", and "one relayer key is consulted" is not "one key can
// move a message". HINT-only, exactly like every other archetype check.
package archetypes

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestThresholdWithoutEnforcementBuggyHits(t *testing.T) {
	idx := fixtureTree(t, "threshold", "buggy.sol")
	res, detail := evalSingleCheck(t, "multisig-threshold-single-point", idx)
	if res != "present" {
		t.Fatalf("buggy threshold: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "threshold") {
		t.Fatalf("finding detail %q does not name the state variable", detail)
	}
}

func TestThresholdWithoutEnforcementCleanMisses(t *testing.T) {
	idx := fixtureTree(t, "threshold", "clean.sol")
	res, detail := evalSingleCheck(t, "multisig-threshold-single-point", idx)
	if res != "absent" {
		t.Fatalf("clean threshold: result = %q (%s), want absent", res, detail)
	}
}

// TestThresholdWithoutEnforcementIsSameContract: the enforcement search is
// scoped to the contract that OWNS the state variable. In this file contract
// B guards its own `threshold`; contract A's unenforced `threshold` is still
// reported, because B's guard is not evidence about A's execution path.
func TestThresholdWithoutEnforcementIsSameContract(t *testing.T) {
	idx, _ := makeTree(t, `
contract A {
    uint256 public threshold;
    function setThreshold(uint256 t) external { threshold = t; }
    function execute(address target) external { target.call(""); }
}
contract B {
    uint256 public threshold;
    mapping(address => uint256) public approvals;
    function execute() external {
        require(approvals[msg.sender] >= threshold, "not enough approvals");
    }
}
`)
	res, detail := evalSingleCheck(t, "multisig-threshold-single-point", idx)
	if res != "present" {
		t.Fatalf("cross-contract guard suppressed the hit: %q (%s)", res, detail)
	}
}

// TestThresholdWithoutEnforcementReportsOnlyNames pins what the detail may
// claim: the state-variable NAME. No value, no type, no comparison.
func TestThresholdWithoutEnforcementReportsOnlyNames(t *testing.T) {
	idx, _ := makeTree(t, `
contract V {
    uint256 public quorum;
    function bump() external { quorum = 3; }
}
`)
	res, detail := evalSingleCheck(t, "multisig-threshold-single-point", idx)
	if res != "present" {
		t.Fatalf("result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "quorum") {
		t.Fatalf("detail %q does not name the state variable", detail)
	}
	if strings.Contains(detail, "3") {
		t.Fatalf("detail %q leaked a value — the index has none", detail)
	}
}

// TestThresholdWithoutEnforcementMissingNamesFailsLoud: the discriminator is
// required exactly as it is for the other name-driven checks.
func TestThresholdWithoutEnforcementMissingNamesFailsLoud(t *testing.T) {
	idx, _ := makeTree(t, "contract P { uint256 public threshold; }")
	check := validation.VObj(
		validation.KV{K: "type", V: validation.VStr("threshold_without_enforcement")})
	if _, _, err := EvaluatePrecondition(check, idx); err == nil {
		t.Fatal("a check with no 'names' must fail loud")
	} else if !strings.Contains(err.Error(), "threshold_without_enforcement") {
		t.Fatalf("error %q does not name the check type", err)
	}
}

func TestRelayerSingleKeyBuggyHits(t *testing.T) {
	idx := fixtureTree(t, "relayer", "buggy.sol")
	res, detail := evalSingleCheck(t, "relayer-single-key", idx)
	if res != "present" {
		t.Fatalf("buggy relayer: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "relayMessage") {
		t.Fatalf("finding detail %q does not name the entry point", detail)
	}
}

func TestRelayerSingleKeyCleanMisses(t *testing.T) {
	idx := fixtureTree(t, "relayer", "clean.sol")
	res, detail := evalSingleCheck(t, "relayer-single-key", idx)
	if res != "absent" {
		t.Fatalf("clean relayer: result = %q (%s), want absent", res, detail)
	}
}

// TestRelayerSingleKeyGuardTextCoSignerMisses: a second distinct signer
// reference found in the function's OWN guard text is co-signer evidence even
// when the second key is never listed in reads_storage.
func TestRelayerSingleKeyGuardTextCoSignerMisses(t *testing.T) {
	idx, _ := makeTree(t, `
contract Relay {
    address public relayer;
    address public owner;
    modifier onlyBridge() { require(msg.sender == relayer, "not relayer"); _; }
    function relayMessage(bytes32 m) external onlyBridge {
        require(owner != address(0), "no owner");
    }
}
`)
	res, detail := evalSingleCheck(t, "relayer-single-key", idx)
	if res != "absent" {
		t.Fatalf("guard-text co-signer reference missed: %q (%s)", res, detail)
	}
}

// TestRelayerSingleKeyRequiresAuthzGate: an unguarded entry point that merely
// reads a relayer variable is not a keyed gate.
func TestRelayerSingleKeyRequiresAuthzGate(t *testing.T) {
	idx, _ := makeTree(t, `
contract Relay {
    address public relayer;
    function relayMessage(bytes32 m) external {
        relayer.call("");
    }
}
`)
	res, detail := evalSingleCheck(t, "relayer-single-key", idx)
	if res != "absent" {
		t.Fatalf("unguarded entry point matched: %q (%s)", res, detail)
	}
}

// TestRelayerSingleKeyIgnoresValueFlow is the value-blindness pin: a gate
// that reads the relayer variable and compares it to nothing meaningful is
// indistinguishable from one that checks it properly — both are "present".
// The check claims a SHAPE (one consulted key), never a verdict.
func TestRelayerSingleKeyIgnoresValueFlow(t *testing.T) {
	idx, _ := makeTree(t, `
contract Relay {
    address public relayer;
    modifier onlyBridge() { relayer; _; }
    function relayMessage(bytes32 m) external onlyBridge { emit Moved(m); }
}
`)
	res, detail := evalSingleCheck(t, "relayer-single-key", idx)
	if res != "present" {
		t.Fatalf("result = %q (%s), want present (shape claim only)", res, detail)
	}
}

// TestRelayerSingleKeyMissingNamesFailsLoud mirrors the threshold check.
func TestRelayerSingleKeyMissingNamesFailsLoud(t *testing.T) {
	idx, _ := makeTree(t, "contract R { address public relayer; }")
	check := validation.VObj(
		validation.KV{K: "type", V: validation.VStr("relayer_single_key")})
	if _, _, err := EvaluatePrecondition(check, idx); err == nil {
		t.Fatal("a check with no 'names' must fail loud")
	} else if !strings.Contains(err.Error(), "relayer_single_key") {
		t.Fatalf("error %q does not name the check type", err)
	}
}
