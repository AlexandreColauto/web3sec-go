// Port of tests/test_sequence_coverage.py — verify_sequence_coverage and
// the structural sufficiency rule (the CONFIRMED-gate and fork-PoC halves
// of that file live in internal/findings and internal/forkpoc).
package sequencepoc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// forkCmd is FORK_CMD.
const forkCmd = "forge test --fork-url http://127.0.0.1:8545 " +
	"--fork-block-number 20000000 --match-test test_sequence"

// coverageSpec is SPEC from test_sequence_coverage.py.
func coverageSpec(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{
  "spec_id": "SEQ-TEST-03", "finding_id": "F-cov1",
  "actors": {"attacker": "anvil:0", "victim": "`+addr("aa")+`"},
  "steps": [
    {"step": 1, "actor": "attacker", "target": "`+addr("cd")+`",
     "function": "deposit(uint256)", "args": ["1"]},
    {"step": 2, "actor": "victim", "target": "`+addr("cd")+`",
     "function": "claim()", "expect_revert": true}
  ],
  "final_assertions": [
    {"id": "A1", "kind": "balance", "account": "attacker",
     "op": ">=", "value": "2"}
  ]
}`)
}

// goodResult is GOOD_RESULT (spec_hash is filled in by the caller).
func goodResult(t *testing.T, spec validation.Value) validation.Value {
	t.Helper()
	return mustParse(t, `{
  "spec_hash": "`+SpecHash(spec)+`",
  "steps": [
    {"step": 1, "actor": "attacker", "tx_hash": "0x`+strings.Repeat("11", 32)+
		`", "status": "success", "revert_reason": null},
    {"step": 2, "actor": "victim", "tx_hash": null, "status": "revert",
     "revert_reason": "execution reverted: no"}
  ],
  "final_assertions": [
    {"id": "A1", "kind": "balance", "observed": "5", "expected": ">= 2",
     "passed": true}
  ],
  "overall": "pass", "generated_at": "2026-07-15T00:00:00Z"
}`)
}

// seqFinding is SEQ_FINDING.
func seqFinding(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{
  "finding_id": "F-cov1",
  "exploit_sequence": [
    {"step": 1, "actor": "attacker", "action": "deposit"},
    {"step": 2, "actor": "victim", "action": "claim (reverts)"}
  ]
}`)
}

// stage registers a real fork-runner ledger exec and stages the sequence
// artifacts into its output tree; returns the exec record.
func stage(t *testing.T, c *state.Campaign, result, spec validation.Value,
	findingID *string) validation.Value {
	t.Helper()
	if spec.Kind != validation.Obj {
		spec = coverageSpec(t)
	}
	if result.Kind != validation.Obj {
		result = goodResult(t, spec)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "fork-runner", Command: forkCmd, ReportedBy: "pytest-harness",
		FindingID: findingID, StdoutText: "PASS: test_sequence\n"})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Dir(validation.ObjStr(rec, "stdout_path"))
	if err := os.WriteFile(filepath.Join(out, "spec.json"),
		CanonicalJSON(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "sequence_result.json"),
		[]byte(validation.DumpIndented(result)), 0o644); err != nil {
		t.Fatal(err)
	}
	return rec
}

// verify runs VerifySequenceCoverage over a staged campaign.
func verify(t *testing.T, c *state.Campaign, finding, rec validation.Value) (bool, []string) {
	t.Helper()
	return VerifySequenceCoverage(c, finding, rec)
}

func TestVacuousPassForNonSequenceFinding(t *testing.T) {
	c := testCampaign(t)
	rec := stage(t, c, validation.VNull(), validation.VNull(), nil)
	ok, reasons := verify(t, c, mustParse(t, `{"finding_id": "F-x"}`), rec)
	if !ok || len(reasons) != 0 {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestFullPass(t *testing.T) {
	c := testCampaign(t)
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c,
		validation.VNull(), validation.VNull(), nil))
	if !ok || len(reasons) != 0 {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestMissingResult(t *testing.T) {
	c := testCampaign(t)
	rec := stage(t, c, validation.VNull(), validation.VNull(), nil)
	if err := os.Remove(filepath.Join(filepath.Dir(validation.ObjStr(rec, "stdout_path")),
		"sequence_result.json")); err != nil {
		t.Fatal(err)
	}
	ok, reasons := verify(t, c, seqFinding(t), rec)
	if ok || !anyContains(reasons, "sequence_result") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestMalformedResultDegradesNotCrashes(t *testing.T) {
	c := testCampaign(t)
	rec := stage(t, c, validation.VNull(), validation.VNull(), nil)
	if err := os.WriteFile(filepath.Join(filepath.Dir(validation.ObjStr(rec, "stdout_path")),
		"sequence_result.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, reasons := verify(t, c, seqFinding(t), rec)
	if ok || len(reasons) == 0 {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestHashMismatchRejected(t *testing.T) {
	c := testCampaign(t)
	bad := setKey(goodResult(t, coverageSpec(t)), "spec_hash",
		validation.VStr("sha256:"+strings.Repeat("0", 64)))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad,
		validation.VNull(), nil))
	if ok || !anyContains(reasons, "bind") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestStepCountGapRejected(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	bad := setKey(goodResult(t, spec), "steps", validation.VArr(
		listOf(validation.ObjAt(goodResult(t, spec), "steps"))[0]))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad, spec, nil))
	if ok || !anyContainsFold(reasons, "step") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestActorCountGapRejected(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	bad := setPath(t, goodResult(t, spec), []string{"steps", "1", "actor"},
		validation.VStr("attacker"))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad, spec, nil))
	if ok || !anyContainsFold(reasons, "actor") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

// TestActorGapReasonNamesMissingActor: a coverage refusal names the
// declared actor the single-account PoC never used, appended to the
// existing sentence so the prefix and counts stay byte-identical.
func TestActorGapReasonNamesMissingActor(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	single := setPath(t, goodResult(t, spec), []string{"steps", "1", "actor"},
		validation.VStr("attacker"))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, single, spec, nil))
	want := "executed steps use 1 distinct actor(s) but the declared " +
		"exploit needs 2 — a single-account PoC cannot cover a " +
		"multi-actor exploit; missing: victim"
	if ok {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
	if !anyContains(reasons, want) {
		t.Fatalf("reasons=%v", reasons)
	}
}

// TestActorGapReasonSortsAndKeepsLabelsVerbatim: the missing labels are
// sorted and are the finding's own actor strings, prose included.
func TestActorGapReasonSortsAndKeepsLabelsVerbatim(t *testing.T) {
	c := testCampaign(t)
	finding := mustParse(t, `{"finding_id": "F-cov1",
      "exploit_sequence": [
        {"step": 1, "actor": "zeta", "action": "deposit"},
        {"step": 2, "actor": "victim (or protocol)", "action": "claim"},
        {"step": 3, "actor": "attacker", "action": "sweep"}]}`)
	spec := coverageSpec(t)
	single := setPath(t, goodResult(t, spec), []string{"steps", "1", "actor"},
		validation.VStr("attacker"))
	ok, reasons := verify(t, c, finding, stage(t, c, single, spec, nil))
	if ok {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
	if !anyContains(reasons, "; missing: victim (or protocol), zeta") {
		t.Fatalf("reasons=%v", reasons)
	}
}

// TestActorCoverageMetYieldsNoActorReason: every declared actor executed
// means the actor reason is not emitted at all.
func TestActorCoverageMetYieldsNoActorReason(t *testing.T) {
	c := testCampaign(t)
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c,
		validation.VNull(), validation.VNull(), nil))
	if !ok {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
	if anyContainsFold(reasons, "actor") {
		t.Fatalf("reasons=%v", reasons)
	}
}

// TestExecutedActorSupersetYieldsNoActorReason: extra executed actors are
// not a coverage failure — only missing ones are.
func TestExecutedActorSupersetYieldsNoActorReason(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	res := goodResult(t, spec)
	steps := append(listOf(validation.ObjAt(res, "steps")), mustParse(t,
		`{"step": 3, "actor": "arbiter", "tx_hash": null, "status": "revert",
          "revert_reason": "execution reverted: no"}`))
	res = setKey(res, "steps", validation.VArr(steps...))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, res, spec, nil))
	if !ok {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
	if anyContainsFold(reasons, "actor") {
		t.Fatalf("reasons=%v", reasons)
	}
}

func TestUnexpectedSuccessOnExpectRevertStep(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	bad := setPath(t, goodResult(t, spec), []string{"steps", "1", "status"},
		validation.VStr("success"))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad, spec, nil))
	if ok || !anyContainsFold(reasons, "revert") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestEmptyRevertReasonRejected(t *testing.T) {
	for _, empty := range []validation.Value{validation.VStr(""),
		validation.VNull()} {
		c := testCampaign(t)
		spec := coverageSpec(t)
		bad := setPath(t, goodResult(t, spec),
			[]string{"steps", "1", "revert_reason"}, empty)
		ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad, spec, nil))
		if ok || !anyContainsFold(reasons, "revert") {
			t.Fatalf("empty=%v ok=%v reasons=%v", empty, ok, reasons)
		}
	}
}

func TestNonDictDeclaredEntriesDoNotCrash(t *testing.T) {
	c := testCampaign(t)
	finding := mustParse(t, `{"finding_id": "F-x",
      "exploit_sequence": ["deposit-then-claim",
                           {"step": 2, "actor": "victim", "action": "claim"}]}`)
	if !IsSequenceRequired(finding) {
		t.Fatal("len >= 2 must be sequence-required")
	}
	ok, _ := verify(t, c, finding, stage(t, c, validation.VNull(),
		validation.VNull(), nil))
	if !ok {
		t.Fatal("string entry contributes no actor; coverage holds")
	}
}

func TestExecWithoutStdoutPathFailsClosed(t *testing.T) {
	c := testCampaign(t)
	ok, reasons := verify(t, c, seqFinding(t),
		mustParse(t, `{"exec_id": "EXEC-x"}`))
	if ok || !anyContains(reasons, "stdout_path") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestExecOutsideCampaignTreeRejected(t *testing.T) {
	c := testCampaign(t)
	ok, reasons := verify(t, c, seqFinding(t),
		mustParse(t, `{"exec_id": "EXEC-x",
                       "stdout_path": "/tmp/evil/stdout.log"}`))
	if ok || !anyContains(reasons, "outside") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestMissingSpecWithResultPresent(t *testing.T) {
	c := testCampaign(t)
	rec := stage(t, c, validation.VNull(), validation.VNull(), nil)
	if err := os.Remove(filepath.Join(filepath.Dir(validation.ObjStr(rec, "stdout_path")),
		"spec.json")); err != nil {
		t.Fatal(err)
	}
	ok, reasons := verify(t, c, seqFinding(t), rec)
	if ok || !anyContainsFold(reasons, "spec") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestAssertionPassedFalseRejectedEvenWhenOverallPass(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	bad := setPath(t, goodResult(t, spec),
		[]string{"final_assertions", "0", "passed"}, validation.VBool(false))
	bad = setKey(bad, "overall", validation.VStr("pass"))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad, spec, nil))
	if ok || !anyContainsFold(reasons, "assertion") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestOverallFailRejectedEvenWhenAssertionsPass(t *testing.T) {
	c := testCampaign(t)
	spec := coverageSpec(t)
	bad := setKey(goodResult(t, spec), "overall", validation.VStr("fail"))
	ok, reasons := verify(t, c, seqFinding(t), stage(t, c, bad, spec, nil))
	if ok || !anyContainsFold(reasons, "overall") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestNonListExploitSequenceFailsClosed(t *testing.T) {
	c := testCampaign(t)
	ok, reasons := verify(t, c, mustParse(t, `{"finding_id": "F-x",
      "exploit_sequence": "deposit then claim"}`), stage(t, c,
		validation.VNull(), validation.VNull(), nil))
	if ok || !anyContains(reasons, "not a list") {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestNonDictFindingFailsClosed(t *testing.T) {
	c := testCampaign(t)
	ok, reasons := verify(t, c, validation.VStr("nope"), stage(t, c,
		validation.VNull(), validation.VNull(), nil))
	if ok || len(reasons) == 0 {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

// anyContainsFold is any(sub.lower() in s.lower() for s in reasons).
func anyContainsFold(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(strings.ToLower(r), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// anyContains is any(sub in s for s in reasons).
func anyContains(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}
