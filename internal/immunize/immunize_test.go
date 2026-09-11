// Port of tests/test_fork_poc_immunize.py — the immunization half plus the
// wiring assertions the new stage closes: the bounty gate's two hard checks
// (mainnet-fork-poc, immunization), the stage's place in the pipeline, the
// proof-driven auto-completion and the operator waiver.
//
// The fixture modules Python's `make_submission_ready` also needs (the variant
// ladder, the price table) are P2 seams here; the assertions below are the
// Python test's own, which never read those checks.
package immunize

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/pipeline"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// policy is the POLICY dict of the Python test (literal order).
func policy() validation.Value {
	return validation.VObj(
		kv("program", validation.VStr("Acme Program")),
		kv("program_url", validation.VStr("https://immunefi.com/acme")),
		kv("platform", validation.VStr("immunefi")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("scope", validation.VArr(validation.VObj(
			kv("target", validation.VStr("V")),
			kv("kind", validation.VStr("contract"))))),
		kv("exclusions", validation.VArr()),
		kv("severity_rules", validation.VArr(validation.VObj(
			kv("severity", validation.VStr("high")),
			kv("match", validation.VObj(kv("bug_classes",
				validation.VArr(validation.VStr("access-control")))))))),
		kv("poc_requirements", validation.VObj(
			kv("min_evidence_level", validation.VStr("E4")),
			kv("require_fork_repro", validation.VBool(false)))),
		kv("reporting", validation.VObj(
			kv("contact", validation.VStr("acme")))),
	)
}

// muts is MUTS: the three boundary mutations.
func muts() []string {
	return []string{
		"delegatecall variant of the exploit path",
		"same exploit re-issued from a second account in one block",
		"revert-retry with modified calldata padding",
	}
}

// fixtureCampaign is the `camp` fixture.
func fixtureCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "t")
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "src", "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// execRecord writes a finished EXEC record and returns it.
func execRecord(t *testing.T, c *state.Campaign, execID, profile,
	findingID, command string, exitStatus int64,
	stdoutText string) validation.Value {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout, []byte(stdoutText), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderr, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr(profile)),
		kv("finding_id", validation.VStr(findingID)),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr(command)),
		kv("exit_status", validation.VInt(exitStatus)),
		kv("stdout_path", validation.VStr(stdout)),
		kv("stderr_path", validation.VStr(stderr)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// evidenceItem is conftest.evidence_item.
func evidenceItem(rec validation.Value, level, typ, desc, eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr(desc)),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")),
	)
}

// seedGlobalMemory is conftest.seed_global_memory_row.
func seedGlobalMemory(t *testing.T) {
	t.Helper()
	row := validation.VObj(
		kv("memory_id", validation.VStr("MEM-shared01")),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Shared memory pattern")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Seeded incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	wrapper := validation.VArr(validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global"))))
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return wrapper.A, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
	})
}

// confirmUnitOnly is _confirm_unit_only.
func confirmUnitOnly(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(
			"Rescue function drains user balances without role check")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("cwe", validation.VStr("CWE-284")),
			kv("description", validation.VStr("rescue() sends every token "+
				"to the caller, no role check")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("V")),
			kv("function", validation.VStr("rescue"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	rec := execRecord(t, c, "EXEC-0000000001", "docker-networkless", fid,
		"forge test --match-test test_exploit", 0, "PASS: test_exploit\n")
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E4",
		"foundry-test", "unit harness repro", "EV-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"no role check found"); err != nil {
		t.Fatal(err)
	}
	seedGlobalMemory(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T1")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "unit gate passed",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

// forkExec is _fork_exec.
func forkExec(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	return execRecord(t, c, "EXEC-0000000002", "fork-runner", fid,
		"forge test --fork-url http://127.0.0.1:8545 "+
			"--fork-block-number 20000000 --match-test test_exploit", 0,
		"PASS: test_exploit\n")
}

// mintedFork is the fixture step: fork exec + E5 evidence.
func mintedFork(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	rec := forkExec(t, c, fid)
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E5",
		"fork-test", "fork repro", "EV-f")); err != nil {
		t.Fatal(err)
	}
	return rec
}

// gateCheck is by_id[check] over the gate result.
func gateCheck(t *testing.T, c *state.Campaign, fid,
	check string) validation.Value {
	t.Helper()
	r, err := bounty.EvaluateBountyGate(c, fid, policy(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range listAt(r, "policy_checks") {
		if objStr(row, "check") == check {
			return row
		}
	}
	t.Fatalf("no %q check row in %s", check, validation.PyRepr(r))
	return validation.VNull()
}

// test_immunize_rejects_unit_test_basis.
func TestImmunizeRejectsUnitTestBasis(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := execRecord(t, c, "EXEC-0000000003", "docker-networkless", fid,
		"forge test --match-test test_exploit", 0, "PASS: test_exploit\n")
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E4",
		"foundry-test", "unit repro", "EV-1b")); err != nil {
		t.Fatal(err)
	}
	_, err := Immunize(c, fid, Options{Patch: "add the missing role check",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor"})
	if err == nil {
		t.Fatal("a unit-test basis must be refused")
	}
	if !strings.Contains(err.Error(), "FORK PoC, not a unit test") {
		t.Fatalf("error = %q, want 'FORK PoC, not a unit test'", err.Error())
	}
}

// test_immunize_requires_minted_fork_evidence.
func TestImmunizeRequiresMintedForkEvidence(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := forkExec(t, c, fid) // ran, but never minted on the finding
	_, err := Immunize(c, fid, Options{Patch: "add the missing role check",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor"})
	if err == nil {
		t.Fatal("an unminted fork exec must be refused")
	}
	if !strings.Contains(err.Error(), "not minted") {
		t.Fatalf("error = %q, want 'not minted'", err.Error())
	}
}

// test_immunize_requires_exactly_three_mutations.
func TestImmunizeRequiresExactlyThreeMutations(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := mintedFork(t, c, fid)
	for _, n := range []int{1, 2, 4} {
		m := muts()[:min(n, 3)]
		if n == 4 {
			m = append(muts(), "xxxxx")
		}
		_, err := Immunize(c, fid, Options{
			Patch:     "add the missing role check",
			POCExecID: objStr(rec, "exec_id"), Mutations: m,
			Actor: "auditor"})
		if err == nil {
			t.Fatalf("n=%d: must be refused", n)
		}
		if !strings.Contains(err.Error(), "exactly 3 boundary") {
			t.Fatalf("n=%d: error = %q", n, err.Error())
		}
	}
}

// test_immunize_success_records_the_fork_basis.
func TestImmunizeSuccessRecordsTheForkBasis(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := mintedFork(t, c, fid)
	f, err := Immunize(c, fid, Options{
		Patch:     "add the missing role check to rescue()",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if !IsImmunized(f) {
		t.Fatal("the recorded verification must read as immunized")
	}
	stateName, detail := ImmunizationDetail(f)
	if stateName != "immunized" ||
		!strings.Contains(detail, objStr(rec, "exec_id")) {
		t.Fatalf("detail = %q %q", stateName, detail)
	}
	pv := objAt(objAt(f, "verification"), "patch_verified")
	if !isTrue(objAt(pv, "patch_blocks_poc")) ||
		!intEq(objAt(pv, "boundary_mutations_tested"), 3) ||
		!isFalse(objAt(pv, "boundary_bypass_found")) ||
		objStr(pv, "artifact_id") != objStr(rec, "exec_id") {
		t.Fatalf("patch_verified = %s", validation.PyRepr(pv))
	}
	if got := listAt(pv, "mutations"); len(got) != 3 {
		t.Fatalf("mutations = %s, want the 3 MUTS", validation.PyRepr(pv))
	} else {
		for i, want := range muts() {
			if got[i].Kind != validation.Str || got[i].S != want {
				t.Fatalf("mutations[%d] = %s, want %q", i,
					validation.PyRepr(got[i]), want)
			}
		}
	}
}

// test_immunize_bypass_fails_the_gate.
func TestImmunizeBypassFailsTheGate(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := mintedFork(t, c, fid)
	bypass := "delegatecall variant still drains 2.1M"
	if _, err := Immunize(c, fid, Options{
		Patch:     "add the missing role check to rescue()",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor", Bypass: &bypass}); err != nil {
		t.Fatal(err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if IsImmunized(f) {
		t.Fatal("a recorded bypass must not read as immunized")
	}
	stateName, detail := ImmunizationDetail(f)
	if stateName != "bypass" || !strings.Contains(detail, "delegatecall") {
		t.Fatalf("detail = %q %q", stateName, detail)
	}
	row := gateCheck(t, c, fid, "immunization")
	if objStr(row, "result") != "fail" {
		t.Fatalf("immunization result = %q, want fail",
			objStr(row, "result"))
	}
	if !strings.Contains(objStr(row, "detail"), "bypass") {
		t.Fatalf("detail = %q, want 'bypass'", objStr(row, "detail"))
	}
}

// test_gate_blocks_without_fork_poc_and_immunization.
func TestGateBlocksWithoutForkPocAndImmunization(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	r, err := bounty.EvaluateBountyGate(c, fid, policy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !isFalse(objAt(r, "submission_ready")) {
		t.Fatalf("submission_ready = %s, want false",
			validation.PyRepr(objAt(r, "submission_ready")))
	}
	for _, tc := range []struct {
		cid      string
		template bool
	}{
		{"mainnet-fork-poc", true},
		{"immunization", false},
	} {
		cid := tc.cid
		row := gateCheck(t, c, fid, cid)
		if objStr(row, "result") != "fail" {
			t.Fatalf("%s result = %q, want fail", cid, objStr(row, "result"))
		}
		ex, err := bounty.GateExplain(cid)
		if err != nil {
			t.Fatal(err)
		}
		if objStr(ex, "gate") != "bounty" {
			t.Fatalf("%s gate = %q, want bounty", cid, objStr(ex, "gate"))
		}
		if len(objStr(ex, "remediation")) < 10 {
			t.Fatalf("%s remediation too short", cid)
		}
		// gate explain is the campaign-less catalog; the gate itself names
		// the campaign in hand, so it is the catalog with the id substituted.
		// The raw catalog row must really carry the placeholder — building
		// the expectation by substituting into an already-rendered string
		// would compare that string with itself. Each row is asserted on its
		// own, so one row silently losing the metavariable cannot lean on
		// another's.
		rawRem := objStr(ex, "remediation")
		if got := strings.Contains(rawRem, campaignToken); got != tc.template {
			t.Fatalf("%s catalog carries the campaign metavariable = %v, "+
				"want %v", cid, got, tc.template)
		}
		wantRem := rawRem
		if tc.template {
			wantRem = strings.ReplaceAll(rawRem, campaignToken, c.CampaignID)
		}
		if objStr(row, "remediation") != wantRem {
			t.Fatalf("%s remediation differs from gate explain", cid)
		}
		if strings.Contains(objStr(row, "remediation"), campaignToken) {
			t.Fatalf("%s remediation still carries the metavariable", cid)
		}
	}
}

// campaignToken is the campaign metavariable the campaign-less catalogs
// carry; the renderer substitutes the campaign in hand for it.
const campaignToken = "<campaign>"

// test_gate_passes_with_fork_poc_and_immunization.
func TestGatePassesWithForkPocAndImmunization(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := mintedFork(t, c, fid)
	if _, err := Immunize(c, fid, Options{
		Patch:     "add the missing role check to rescue()",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor"}); err != nil {
		t.Fatal(err)
	}
	fork := gateCheck(t, c, fid, "mainnet-fork-poc")
	if objStr(fork, "result") != "pass" {
		t.Fatalf("mainnet-fork-poc result = %q, want pass",
			objStr(fork, "result"))
	}
	imm := gateCheck(t, c, fid, "immunization")
	if objStr(imm, "result") != "pass" {
		t.Fatalf("immunization result = %q, want pass", objStr(imm, "result"))
	}
}

// test_stage_order_and_phase: the stage is the LAST required step before the
// bounty gate. The adapter prompt row (AD.STAGES) is not ported yet — that
// assertion is the one deviation from the Python test.
func TestStageOrderAndPhase(t *testing.T) {
	idx := map[string]int{}
	for i, sid := range pipeline.StageIDs {
		idx[sid] = i
	}
	if !(idx["risk-calibration"] < idx["mainnet-fork-poc"] &&
		idx["mainnet-fork-poc"] < idx["bounty-gate"]) {
		t.Fatalf("stage order: risk-calibration=%d fork=%d gate=%d",
			idx["risk-calibration"], idx["mainnet-fork-poc"],
			idx["bounty-gate"])
	}
	join := pipeline.StageJoins["bounty-gate"]
	if join.Kind != pipeline.JoinAll {
		t.Fatalf("bounty-gate join kind = %q, want %q", join.Kind,
			pipeline.JoinAll)
	}
	if len(join.Deps) != 1 || join.Deps[0] != "mainnet-fork-poc" {
		t.Fatalf("bounty-gate deps = %v, want [mainnet-fork-poc]", join.Deps)
	}
	phase := map[string]int{}
	for i, p := range state.Phases {
		phase[p] = i
	}
	if phase["MAINNET_FORK_POC"] != phase["RISK_CALIBRATION"]+1 ||
		phase["MAINNET_FORK_POC"] != phase["BOUNTY_GATE"]-1 {
		t.Fatalf("phase order: RISK=%d FORK=%d GATE=%d",
			phase["RISK_CALIBRATION"], phase["MAINNET_FORK_POC"],
			phase["BOUNTY_GATE"])
	}
	if !completion.HasProof("mainnet-fork-poc") {
		t.Fatal("the model stage must have an authoritative completion proof")
	}
}

// handlersExceptFork is _handlers_except_fork: a handler for every stage but
// the fork stage, so the fork proof decides.
func handlersExceptFork() map[string]pipeline.Handler {
	out := map[string]pipeline.Handler{}
	for _, sid := range pipeline.StageIDs {
		if sid == "mainnet-fork-poc" {
			continue
		}
		out[sid] = func(*state.Campaign) (validation.Value, error) {
			return validation.VStr("ok"), nil
		}
	}
	return out
}

// test_pipeline_blocks_on_missing_fork_poc.
func TestPipelineBlocksOnMissingForkPoc(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	summary, err := pipeline.New(c, nil, handlersExceptFork()).Run(
		pipeline.RunOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if objStr(summary, "status") != "needs-model" {
		t.Fatalf("status = %q, want needs-model", objStr(summary, "status"))
	}
	if objStr(objAt(summary, "needs_model"), "stage") != "mainnet-fork-poc" {
		t.Fatalf("needs_model.stage = %q", objStr(objAt(summary,
			"needs_model"), "stage"))
	}
	blocked := false
	for _, s := range listAt(summary, "blocked_stages") {
		if s.Kind == validation.Str && s.S == "mainnet-fork-poc" {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("blocked_stages = %s, want mainnet-fork-poc",
			validation.PyRepr(objAt(summary, "blocked_stages")))
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	note := objStr(objAt(objAt(st, "stages"), "mainnet-fork-poc"), "note")
	if !strings.Contains(note, fid) {
		t.Fatalf("stage note = %q, want the finding id %s", note, fid)
	}
}

// test_pipeline_auto_completes_fork_stage.
func TestPipelineAutoCompletesForkStage(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := mintedFork(t, c, fid)
	if _, err := Immunize(c, fid, Options{
		Patch:     "add the missing role check to rescue()",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor"}); err != nil {
		t.Fatal(err)
	}
	summary, err := pipeline.New(c, nil, handlersExceptFork()).Run(
		pipeline.RunOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if objStr(summary, "status") != "complete" {
		t.Fatalf("status = %q, want complete", objStr(summary, "status"))
	}
	done := false
	for _, s := range listAt(summary, "auto_completed") {
		if s.Kind == validation.Str && s.S == "mainnet-fork-poc" {
			done = true
		}
	}
	if !done {
		t.Fatalf("auto_completed = %s, want mainnet-fork-poc",
			validation.PyRepr(objAt(summary, "auto_completed")))
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	entry := objAt(objAt(st, "stages"), "mainnet-fork-poc")
	if objStr(entry, "status") != "done" ||
		objStr(entry, "executor") != "derived" {
		t.Fatalf("stage = %s", validation.PyRepr(entry))
	}
}

// test_waiver_satisfies_the_stage_proof.
func TestWaiverSatisfiesTheStageProof(t *testing.T) {
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	if _, err := completion.Waive(c, "mainnet-fork-poc", fid,
		"no RPC access to the pinned fork from this environment",
		"operator"); err != nil {
		t.Fatal(err)
	}
	proof, err := completion.ProofStatus(c, "mainnet-fork-poc")
	if err != nil {
		t.Fatal(err)
	}
	if !isTrue(objAt(proof, "done")) {
		t.Fatalf("done = %s, want true",
			validation.PyRepr(objAt(proof, "done")))
	}
	row := gateCheck(t, c, fid, "mainnet-fork-poc")
	if objStr(row, "result") != "pass" {
		t.Fatalf("mainnet-fork-poc result = %q, want pass",
			objStr(row, "result"))
	}
	if !strings.Contains(objStr(row, "detail"), "waived") {
		t.Fatalf("detail = %q, want 'waived'", objStr(row, "detail"))
	}
}

// --- docker e2e (WEBV2_DOCKER_TESTS=1) -------------------------------------

// TestDockerImmunizeAgainstTheForkPoc runs the real forge fork test twice in
// the foundry image: unpatched (the PoC PASSES — the basis) and patched (the
// PoC FAILS — the patch blocks it), then records the immunization against
// that exec and asserts the gate's immunization check passes.
func TestDockerImmunizeAgainstTheForkPoc(t *testing.T) {
	if os.Getenv("WEBV2_DOCKER_TESTS") == "" {
		t.Skip("WEBV2_DOCKER_TESTS=1 to run")
	}
	out, err := runForkTest(t, nil)
	if err != nil || !strings.Contains(out, "[PASS] test_exploit") {
		t.Fatalf("unpatched fork run must pass: %v\n%s", err, out)
	}
	patched, err := runForkTest(t, []byte(patchedCounter))
	if err == nil {
		t.Fatalf("the patched PoC must fail:\n%s", patched)
	}
	if !strings.Contains(patched, "[FAIL") {
		t.Fatalf("patched run must report a failing test:\n%s", patched)
	}
	c := fixtureCampaign(t)
	fid := confirmUnitOnly(t, c)
	rec := execRecord(t, c, "EXEC-0000000005", "fork-runner", fid,
		"forge test --fork-url http://127.0.0.1:8545 "+
			"--match-test test_exploit", 0, out)
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E5",
		"fork-test", "real fork repro", "EV-docker")); err != nil {
		t.Fatal(err)
	}
	f, err := Immunize(c, fid, Options{
		Patch:     "add the missing role check to rescue()",
		POCExecID: objStr(rec, "exec_id"), Mutations: muts(),
		Actor: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if !IsImmunized(f) {
		t.Fatal("the docker-backed verification must read as immunized")
	}
	row := gateCheck(t, c, fid, "immunization")
	if objStr(row, "result") != "pass" {
		t.Fatalf("immunization result = %q, want pass", objStr(row, "result"))
	}
}

// patchedCounter is the fix under test: the setter now checks the caller.
const patchedCounter = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Counter {
    uint256 public number;
    address public admin = address(0xdead);

    function setNumber(uint256 newNumber) public {
        require(msg.sender == admin, "rescue: not admin");
        number = newNumber;
    }
}
`

// runForkTest streams the shared fork-poc fixture into the foundry image and
// runs the fork test there (the container cannot see the Go temp dirs).
func runForkTest(t *testing.T, patch []byte) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", "run", "-i", "--rm",
		"ghcr.io/foundry-rs/foundry:latest",
		"mkdir -p /tmp/w && tar -x -C /tmp/w && cd /tmp/w && "+
			"(anvil --silent >/tmp/anvil.log 2>&1 &) && sleep 2 && "+
			"forge test --fork-url http://127.0.0.1:8545 "+
			"--match-test test_exploit -vv")
	cmd.Stdin = forkFixtureTar(t, patch)
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}

// forkFixtureTar builds the tar stream for ../forkpoc/testdata/fork-poc-e2e
// (one shared fixture, so the two docker e2e tests exercise the same tree).
func forkFixtureTar(t *testing.T, patch []byte) *bytes.Buffer {
	t.Helper()
	root := filepath.Join("..", "forkpoc", "testdata", "fork-poc-e2e")
	files := map[string][]byte{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if patch != nil {
		files[filepath.Join("src", "Counter.sol")] = patch
	}
	names := make([]string, 0, len(files))
	for rel := range files {
		names = append(names, rel)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, rel := range names {
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o644,
			Size: int64(len(files[rel]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[rel]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}
