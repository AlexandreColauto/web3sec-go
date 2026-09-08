// Port of tests/test_snapshot.py deployment/chain/trust-gate behaviors:
// attach pins, the assert_snapshot_compatible gate with its exact message,
// reverify_required, and the unpinned-campaign path.
package snapshot

import (
	"errors"
	"strings"
	"testing"

	"websec/internal/validation"
)

func testDeployment() validation.Value {
	return validation.VObj(
		validation.KV{K: "network", V: validation.VStr("ethereum-mainnet")},
		validation.KV{K: "chain_id", V: validation.VInt(1)},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Vault")},
			validation.KV{K: "address", V: validation.VStr("0xabababababababababababababababababababab")},
			validation.KV{K: "source_match", V: validation.VStr("verified")},
		))},
	)
}

func testChain() validation.Value {
	return validation.VObj(
		validation.KV{K: "network", V: validation.VStr("ethereum-mainnet")},
		validation.KV{K: "chain_id", V: validation.VInt(1)},
		validation.KV{K: "fork_block", V: validation.VInt(23456789)},
	)
}

func TestAttachDeploymentAndChainPins(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-compatpins11")
	snap := mustPin(t, c, target, nil, nil)
	sid := strField(t, snap, "snapshot_id")

	snap2, err := AttachDeploymentPin(c, sid, testDeployment())
	if err != nil {
		t.Fatal(err)
	}
	contracts := objField(t, objField(t, snap2, "deployment"), "contracts")
	if len(contracts.A) != 1 || strField(t, contracts.A[0], "source_match") != "verified" {
		t.Fatalf("deployment contracts = %v, want the verified Vault", contracts)
	}
	snap3, err := AttachChainPin(c, sid, testChain())
	if err != nil {
		t.Fatal(err)
	}
	if got := intField(t, objField(t, snap3, "chain"), "fork_block"); got != 23456789 {
		t.Fatalf("fork_block = %d, want 23456789", got)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStrOf(t, st, "active_snapshot_id"); got != sid {
		t.Fatalf("active_snapshot_id = %q, want %q", got, sid)
	}
}

func TestAttachMissingSnapshotErrors(t *testing.T) {
	root, _ := pinTarget(t)
	c := pinCampaign(t, root, "C-compatmiss11")
	if _, err := AttachDeploymentPin(c, "bogus", testDeployment()); err == nil ||
		err.Error() != "no pinned snapshot 'bogus' in this campaign" {
		t.Fatalf("deployment attach err = %v, want exact FileNotFoundError text", err)
	}
	if _, err := AttachChainPin(c, "bogus", testChain()); err == nil ||
		err.Error() != "no pinned snapshot 'bogus' in this campaign" {
		t.Fatalf("chain attach err = %v, want exact FileNotFoundError text", err)
	}
}

func TestSnapshotTrustGate(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-compattrust1")
	s1 := mustPin(t, c, target, nil, nil)
	sid1 := strField(t, s1, "snapshot_id")
	finding := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr("F-aaaaaaaaaaaa")},
		validation.KV{K: "snapshot_ids", V: validation.VObj(
			validation.KV{K: "source", V: validation.VStr(sid1)},
		)},
	)
	ok, err := AssertSnapshotCompatible(c, finding, true)
	if err != nil || !ok {
		t.Fatalf("compatible = %v, %v; want true, nil", ok, err)
	}

	writeFiles(t, target, map[string]string{"src/Vault.sol": "contract Vault2 {}"})
	s2 := mustPin(t, c, target, nil, nil)
	sid2 := strField(t, s2, "snapshot_id")
	if sid1 == sid2 {
		t.Fatal("re-pin after edit kept the same id")
	}
	if !ReverifyRequired(finding, &sid2) {
		t.Fatal("ReverifyRequired = false after re-pin, want true")
	}
	if ReverifyRequired(finding, &sid1) {
		t.Fatal("ReverifyRequired = true for the matching pin, want false")
	}
	_, err = AssertSnapshotCompatible(c, finding, true)
	if err == nil {
		t.Fatal("strict mismatch: no error")
	}
	var mm *SnapshotMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("strict mismatch err type = %T, want *SnapshotMismatch", err)
	}
	want := "finding F-aaaaaaaaaaaa was discovered against " +
		validation.PyReprStr(sid1) + " but campaign is pinned to " +
		validation.PyReprStr(sid2) + "; re-verify instead of trusting"
	if err.Error() != want {
		t.Fatalf("mismatch message = %q, want %q", err.Error(), want)
	}
	ok, err = AssertSnapshotCompatible(c, finding, false)
	if err != nil || ok {
		t.Fatalf("non-strict mismatch = %v, %v; want false, nil", ok, err)
	}
}

func TestUnpinnedCampaignAllowsVerdicts(t *testing.T) {
	root, _ := pinTarget(t)
	c := pinCampaign(t, root, "C-compatunpin1")
	finding := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr("F-aaaaaaaaaaaa")},
		validation.KV{K: "snapshot_ids", V: validation.VObj(
			validation.KV{K: "source", V: validation.VStr("unpinned")},
		)},
	)
	ok, err := AssertSnapshotCompatible(c, finding, true)
	if err != nil || !ok {
		t.Fatalf("unpinned compatible = %v, %v; want true, nil", ok, err)
	}
	if ReverifyRequired(finding, nil) {
		t.Fatal("ReverifyRequired with nil active = true, want false")
	}
}

func TestMismatchWithMissingSourcePinUsesNone(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-compatnone11")
	s1 := mustPin(t, c, target, nil, nil)
	sid1 := strField(t, s1, "snapshot_id")
	// No snapshot_ids at all: pins.get("source") is None -> repr "None".
	finding := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr("F-bbbbbbbbbbbb")},
	)
	_, err := AssertSnapshotCompatible(c, finding, true)
	if err == nil || !strings.Contains(err.Error(), "was discovered against None but campaign is pinned to "+validation.PyReprStr(sid1)) {
		t.Fatalf("missing-pin message = %v, want None repr + active id", err)
	}
	if !ReverifyRequired(finding, &sid1) {
		t.Fatal("ReverifyRequired with missing pin = false, want true")
	}
}

func objStrOf(t *testing.T, v validation.Value, key string) string {
	t.Helper()
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	t.Fatalf("object has no key %q", key)
	return ""
}
