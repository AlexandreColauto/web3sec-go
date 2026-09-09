// Port of the fork-PoC half of tests/test_sequence_coverage.py — the
// sequence-coverage extension of fork_poc_evidence: a multi-tx exploit on an
// on-chain campaign demands a T4 sequence PoC; non-sequence findings keep
// today's exact behavior.
package forkpoc

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

// wireSequence installs the sequence_poc implementation (cmd/webv2/main.go
// does this at boot; the package tests drive the modules directly).
func wireSequence(t *testing.T) {
	t.Helper()
	prevReq, prevVer := onchainSequenceRequiredFunc, verifySequenceCoverageFunc
	SetOnchainSequenceRequired(sequencepoc.OnchainSequenceRequired)
	SetVerifySequenceCoverage(sequencepoc.VerifySequenceCoverage)
	t.Cleanup(func() {
		onchainSequenceRequiredFunc, verifySequenceCoverageFunc = prevReq, prevVer
	})
}

// seqCoverageCampaign is _finding_with_seq: a sequence-required finding in
// an ON-CHAIN campaign (deployment pin attached) — the strict multi-tx
// requirement only fires when a fork target is pinned.
func seqCoverageCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := fixtureCampaign(t)
	target := filepath.Join(t.TempDir(), "onchain")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	dep := validation.VObj(
		kv("network", validation.VStr("ethereum")),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("V")),
			kv("address", validation.VStr("0x"+strings.Repeat("aa", 20)))))))
	if _, err := snapshot.AttachDeploymentPin(c, *sid, dep); err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		kv("title", validation.VStr("seq bug with multi-tx exploit")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("missing check across two calls")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("V")),
			kv("function", validation.VStr("claim"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = setOrAppendValue(f.O, "exploit_sequence", validation.VArr(
		validation.VObj(
			kv("step", validation.VInt(1)),
			kv("actor", validation.VStr("attacker")),
			kv("action", validation.VStr("deposit"))),
		validation.VObj(
			kv("step", validation.VInt(2)),
			kv("actor", validation.VStr("victim")),
			kv("action", validation.VStr("drain")))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return c, fid
}

// stageSequence writes the spec + result pair into the exec output dir.
func stageSequence(t *testing.T, rec validation.Value) {
	t.Helper()
	spec := validation.VObj(
		kv("spec_id", validation.VStr("SEQ-FORK-01")),
		kv("finding_id", validation.VStr("F-fork1")),
		kv("actors", validation.VObj(
			kv("attacker", validation.VStr("anvil:0")),
			kv("victim", validation.VStr("0x"+strings.Repeat("bb", 20))))),
		kv("steps", validation.VArr(
			validation.VObj(
				kv("step", validation.VInt(1)),
				kv("actor", validation.VStr("attacker")),
				kv("target", validation.VStr("0x"+strings.Repeat("cd", 20))),
				kv("function", validation.VStr("deposit(uint256)"))),
			validation.VObj(
				kv("step", validation.VInt(2)),
				kv("actor", validation.VStr("victim")),
				kv("target", validation.VStr("0x"+strings.Repeat("cd", 20))),
				kv("function", validation.VStr("drain()"))))),
		kv("final_assertions", validation.VArr()))
	out := filepath.Dir(objStr(rec, "stdout_path"))
	if err := os.WriteFile(filepath.Join(out, "spec.json"),
		sequencepoc.CanonicalJSON(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	result := validation.VObj(
		kv("spec_hash", validation.VStr(sequencepoc.SpecHash(spec))),
		kv("steps", validation.VArr(
			validation.VObj(
				kv("step", validation.VInt(1)),
				kv("actor", validation.VStr("attacker")),
				kv("status", validation.VStr("success"))),
			validation.VObj(
				kv("step", validation.VInt(2)),
				kv("actor", validation.VStr("victim")),
				kv("status", validation.VStr("success"))))),
		kv("final_assertions", validation.VArr()),
		kv("overall", validation.VStr("pass")),
		kv("generated_at", validation.VStr("2026-07-15T00:00:00Z")))
	if err := os.WriteFile(filepath.Join(out, "sequence_result.json"),
		[]byte(validation.DumpIndented(result)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// forkEvidence adds one E5 fork-test evidence item tracing to rec.
func forkEvidence(t *testing.T, c *state.Campaign, fid string, rec validation.Value,
	desc string) {
	t.Helper()
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E5",
		"fork-test", desc, "EV-fork")); err != nil {
		t.Fatal(err)
	}
}

func TestForkPocRequiresCoverageForSequenceFindings(t *testing.T) {
	wireSequence(t)
	c, fid := seqCoverageCampaign(t)
	// a single-call fork exec: succeeds, fork-runner profile, but no
	// sequence result staged -> must NOT prove the fork PoC
	rec := execRecord(t, c, "EXEC-single", ForkProfile, fid, "forge test", 0,
		"PASS: test_single\n")
	forkEvidence(t, c, fid, rec, "single-call fork PoC")
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	item, reason, err := ForkPocEvidence(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if item.Kind != validation.Null {
		t.Errorf("item = %v, want null", item)
	}
	if reason == nil || !strings.Contains(*reason, "sequence") {
		t.Errorf("reason = %v, want a sequence-coverage refusal", reason)
	}
}

func TestForkPocPassesWithCoveredExec(t *testing.T) {
	wireSequence(t)
	c, fid := seqCoverageCampaign(t)
	rec := execRecord(t, c, "EXEC-covered", ForkProfile, fid, "forge test", 0,
		"PASS: test_sequence\n")
	stageSequence(t, rec)
	forkEvidence(t, c, fid, rec, "sequence fork PoC")
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	item, reason, err := ForkPocEvidence(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if item.Kind == validation.Null || reason != nil {
		t.Fatalf("item = %v reason = %v, want proven", item, reason)
	}
}

func TestForkPocSingleCallStillPassesForNonSequence(t *testing.T) {
	// Isolation: non-sequence findings keep today's exact behavior.
	wireSequence(t)
	c := fixtureCampaign(t)
	payload := validation.VObj(
		kv("title", validation.VStr("solo bug with single-call exploit")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr("reentrant withdraw drains the vault")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("V")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	rec := execRecord(t, c, "EXEC-solo", ForkProfile, fid, "forge test", 0,
		"PASS: test_single\n")
	forkEvidence(t, c, fid, rec, "single-call fork PoC")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	item, reason, err := ForkPocEvidence(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if item.Kind == validation.Null || reason != nil {
		t.Fatalf("item = %v reason = %v, want proven", item, reason)
	}
}
