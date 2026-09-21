package findings

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func factCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Attacker drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("economic-invariant")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("f")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
	)
	f, err := IngestHypothesis(c, payload, "code", "discovery", "")
	if err != nil {
		t.Fatal(err)
	}
	return c, validation.ObjStr(f, "finding_id")
}

func TestFactReadIsRecordedWithItsBlock(t *testing.T) {
	c, fid := factCampaign(t)
	f, err := RecordFactRead(c, fid,
		"cast call 0xC0FFEE 'cap()(uint256)' --block 21000000",
		"1000000000000000000000", "ethereum", "operator", 21000000, false)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	facts := validation.ObjAt(f, "deployment_facts")
	if len(facts.A) != 1 {
		t.Fatalf("deployment_facts = %d rows, want 1", len(facts.A))
	}
	if got := validation.ObjStr(facts.A[0], "value"); got != "1000000000000000000000" {
		t.Fatalf("value = %q", got)
	}
	if got := validation.ObjAt(facts.A[0], "block").I; got != 21000000 {
		t.Fatalf("block = %d", got)
	}
}

func TestFactReadRefusesAnUnpinnedOrMutatingCommand(t *testing.T) {
	c, fid := factCampaign(t)
	if _, err := RecordFactRead(c, fid, "cast call 0xC0FFEE 'cap()(uint256)'",
		"1", "ethereum", "operator", 0, false); err == nil ||
		!strings.Contains(err.Error(), "pinned block") {
		t.Fatalf("err = %v, want the pinned-block refusal", err)
	}
	if _, err := RecordFactRead(c, fid, "cast send 0xC0FFEE 'drain()'",
		"0x1", "ethereum", "operator", 21000000, false); err == nil ||
		!strings.Contains(err.Error(), "is a write") {
		t.Fatalf("err = %v, want the mutating-verb refusal", err)
	}
	// An unrecognized read is recordable, but only with the attestation —
	// a non-EVM chain must not force the operator to skip or fake the read.
	if _, err := RecordFactRead(c, fid, "solana account 0xC0FFEE",
		"1", "solana", "operator", 21000000, false); err == nil ||
		!strings.Contains(err.Error(), "--read-only") {
		t.Fatalf("err = %v, want the attestation refusal", err)
	}
	if _, err := RecordFactRead(c, fid, "solana account 0xC0FFEE",
		"1", "solana", "operator", 21000000, true); err != nil {
		t.Fatalf("attested non-EVM read refused: %v", err)
	}
}
