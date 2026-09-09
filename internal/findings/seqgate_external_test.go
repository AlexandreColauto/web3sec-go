// Port of the gate half of tests/test_sequence_coverage.py: the sequence-
// coverage clause fails closed on malformed on-disk shapes (never raises),
// and a non-sequence finding's gate output is byte-identical to the
// pre-change behavior.
//
// This lives in the external test package because it installs the REAL
// sequence_poc implementation (internal/sequencepoc imports internal/findings,
// so an in-package test could not import it).
package findings_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/sequencepoc"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func gkv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func gset(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, gkv(key, v))
}

func gstr(v validation.Value, key string) string {
	if v.Kind != validation.Obj {
		return ""
	}
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Str {
			return kv.V.S
		}
	}
	return ""
}

// seqGateWire installs the real sequence_poc implementation the gate reads
// (cmd/webv2/main.go wires the same functions at boot).
func seqGateWire(t *testing.T) {
	t.Helper()
	findings.SetOnchainSequenceRequired(sequencepoc.OnchainSequenceRequired)
	findings.SetVerifySequenceCoverage(sequencepoc.VerifySequenceCoverage)
	t.Cleanup(func() {
		// restore the package defaults (the setters reject nil)
		findings.SetOnchainSequenceRequired(
			func(*state.Campaign, validation.Value) bool { return false })
		findings.SetVerifySequenceCoverage(
			func(*state.Campaign, validation.Value,
				validation.Value) (bool, []string) {
				return false, nil
			})
	})
}

// seqGateCampaign is _finding_with_seq: a sequence-required finding in an
// ON-CHAIN campaign (deployment pin attached) — the strict multi-tx
// requirement only fires when a fork target is pinned.
func seqGateCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	onchain := filepath.Join(root, "onchain")
	if err := os.MkdirAll(onchain, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(onchain, "V.sol"),
		[]byte("contract V { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, onchain, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	dep := validation.VObj(
		gkv("network", validation.VStr("ethereum")),
		gkv("contracts", validation.VArr(validation.VObj(
			gkv("name", validation.VStr("V")),
			gkv("address", validation.VStr("0x"+strings.Repeat("aa", 20)))))))
	if _, err := snapshot.AttachDeploymentPin(c, *sid, dep); err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		gkv("title", validation.VStr("seq bug with multi-tx exploit")),
		gkv("root_cause", validation.VObj(
			gkv("class", validation.VStr("access-control")),
			gkv("description", validation.VStr("missing check across two calls")))),
		gkv("affected", validation.VArr(validation.VObj(
			gkv("path", validation.VStr("src/V.sol")),
			gkv("contract", validation.VStr("V")),
			gkv("function", validation.VStr("claim"))))),
		gkv("attacker", validation.VObj(
			gkv("profile", validation.VStr("arbitrary EOA")),
			gkv("capabilities", validation.VArr()))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := gstr(f, "finding_id")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = gset(f.O, "exploit_sequence", validation.VArr(
		validation.VObj(
			gkv("step", validation.VInt(1)),
			gkv("actor", validation.VStr("attacker")),
			gkv("action", validation.VStr("deposit"))),
		validation.VObj(
			gkv("step", validation.VInt(2)),
			gkv("actor", validation.VStr("victim")),
			gkv("action", validation.VStr("drain")))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return c, fid
}

// seqGateIDs is the ordered check_id list the gate reports.
func seqGateIDs(t *testing.T, c *state.Campaign, f validation.Value) []string {
	t.Helper()
	detail, err := findings.ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatalf("confirmation_gate_detail raised: %v", err)
	}
	out := []string{}
	for _, d := range detail {
		out = append(out, d.CheckID)
	}
	return out
}

func ghasID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestGateMalformedAttemptsFailClosed(t *testing.T) {
	// attempts=None / non-dict entries degrade to sequence-coverage, never
	// raise.
	seqGateWire(t)
	attempts := []validation.Value{
		validation.VNull(),
		validation.VStr("EXEC-1"),
		validation.VArr(validation.VStr("EXEC-1")),
		validation.VArr(validation.VObj(gkv("nope", validation.VInt(1)))),
		validation.VObj(gkv("a", validation.VInt(1))),
	}
	for i, a := range attempts {
		c, fid := seqGateCampaign(t)
		f, err := findings.LoadFinding(c, fid)
		if err != nil {
			t.Fatal(err)
		}
		f.O = gset(f.O, "verification", validation.VObj(
			gkv("reproduction", validation.VObj(
				gkv("status", validation.VStr("reproduced")),
				gkv("tier_reached", validation.VStr("T4")),
				gkv("attempts", a)))))
		if ids := seqGateIDs(t, c, f); !ghasID(ids, "sequence-coverage") {
			t.Errorf("case %d: ids = %v, want sequence-coverage", i, ids)
		}
	}
}

func TestGateMalformedBlocksFailClosed(t *testing.T) {
	// Round-2 Important R1: non-dict verification / reproduction /
	// root_cause (and the neighboring provenance / invariant / economic /
	// title blocks) fail closed — the gate returns a list, never raises.
	seqGateWire(t)
	cases := []validation.KV{
		gkv("verification", validation.VStr("confirmed")),
		gkv("verification", validation.VObj(
			gkv("reproduction", validation.VStr("reproduced")))),
		gkv("verification", validation.VObj(
			gkv("reproduction", validation.VObj(
				gkv("status", validation.VStr("reproduced")),
				gkv("tier_reached", validation.VStr("T4")),
				gkv("attempts", validation.VNull()))))),
		gkv("root_cause", validation.VStr("oops")),
		gkv("root_cause", validation.VNull()),
		gkv("provenance", validation.VStr("x")),
		gkv("provenance", validation.VObj(
			gkv("rag_refs", validation.VStr("negative")))),
		gkv("provenance", validation.VObj(
			gkv("rag_refs", validation.VArr(validation.VStr("negative"))))),
		gkv("invariant", validation.VStr("INV-1")),
		gkv("security_invariants", validation.VStr("INV-1")),
		gkv("security_invariants", validation.VArr(validation.VStr("INV-1"))),
		gkv("economic_impact", validation.VStr("high")),
		gkv("title", validation.VNull()),
	}
	for i, mutation := range cases {
		c, fid := seqGateCampaign(t)
		f, err := findings.LoadFinding(c, fid)
		if err != nil {
			t.Fatal(err)
		}
		f.O = gset(f.O, mutation.K, mutation.V)
		_ = seqGateIDs(t, c, f) // must not raise
		if i < 0 {
			t.Fatal("unreachable")
		}
	}
}

// TestReachabilityMentionsSequencePOCs is test_reachability_mentions_
// sequence_pocs: the fork-unreachable text names sequence PoCs.
func TestReachabilityMentionsSequencePOCs(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	missing, err := findings.ReachabilityDiagnostic(c, "E5", nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range missing {
		if strings.Contains(m, "sequence") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing = %v, want a sequence mention", missing)
	}
}

func TestNonSequenceFindingUnaffected(t *testing.T) {
	// Isolation: a single-step finding's gate output is byte-identical to
	// the pre-change behavior (no sequence-coverage check at all).
	seqGateWire(t)
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		gkv("title", validation.VStr("solo bug with single-call exploit")),
		gkv("root_cause", validation.VObj(
			gkv("class", validation.VStr("reentrancy")),
			gkv("description", validation.VStr("reentrant withdraw drains the vault")))),
		gkv("affected", validation.VArr(validation.VObj(
			gkv("path", validation.VStr("src/V.sol")),
			gkv("contract", validation.VStr("V")),
			gkv("function", validation.VStr("withdraw"))))),
		gkv("attacker", validation.VObj(
			gkv("profile", validation.VStr("arbitrary EOA")),
			gkv("capabilities", validation.VArr()))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := gstr(f, "finding_id")
	loaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if ids := seqGateIDs(t, c, loaded); ghasID(ids, "sequence-coverage") {
		t.Fatalf("ids = %v, want no sequence-coverage", ids)
	}
}
