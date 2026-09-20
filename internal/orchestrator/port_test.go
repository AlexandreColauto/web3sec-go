// port_test.go: 1:1 port of tests/test_orchestrator.py.
//
// The three Python tests are transcribed step for step. Where a step calls a
// module that has no Go port yet, the test uses the seam that module's Go
// consumer already exposes and says so in place:
//
//   - sandbox.register_exec (P1) — portExecRecord writes the same ledger row
//     tests/conftest.py's sandboxed_exec does, through validation.WriteJson.
//   - maximization.load_ladder / fork_poc.fork_poc_status /
//     immunize.immunization_detail (P1) — installed as the values
//     conftest.py's make_submission_ready produces, via the bounty seams.
//   - shared_memory.load_shared_memory (P1) — seeded through findings'
//     loader seam with the row conftest.py's seed_global_memory_row writes.
//   - learning / report (P1) — steps 15-16 have no Go port; the tail asserts
//     the same end-state through the orchestrator (status / next_actions).
package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/coverage"
	"websec/internal/dedup"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"

	// init() side effects, exactly like cmd/webv2/main.go: completion wires
	// pipeline.SetCompletion + bounty.SetWaivers, floors wires
	// findings.SetEffectiveFloor.
	_ "websec/internal/completion"
	_ "websec/internal/floors"
)

// portWireSeams mirrors cmd/webv2/main.go's init(): Python's import-time
// cross-module connections, installed once for this test binary.
func portWireSeams(t *testing.T) {
	t.Helper()
	dedup.SetMarkDuplicate(findings.MarkDuplicate)
	dedup.SetFlagPossibleDuplicate(findings.FlagPossibleDuplicate)
	dedup.SetFoldIntoLineage(findings.FoldIntoLineage)
	taxonomy.SetCompatClasses(func() []string {
		out := []string{}
		for _, g := range dedup.EconomicCompatGroups {
			out = append(out, g...)
		}
		for _, names := range dedup.AssetClassHints {
			out = append(out, names...)
		}
		return out
	})
	findings.SetInvariantGuard(invariants.AssertInvariantsVerified)
	// invariants -> findings (Python: findings imports INV and calls it
	// directly; the orchestrator does the same in production).
	findings.SetNormalizeInvID(invariants.NormalizeInvID)
	findings.SetLoadInvariantLinks(invariants.LoadLinks)
	findings.SetDocumentedInvariants(portDocMap)
	findings.SetInvariantVerified(invariants.IsVerified)
	findings.SetIntentClaims(portIntentMap)
	t.Cleanup(func() {
		dedup.SetMarkDuplicate(nil)
		dedup.SetFlagPossibleDuplicate(nil)
		dedup.SetFoldIntoLineage(nil)
		taxonomy.SetCompatClasses(nil)
	})
}

// portDocMap adapts invariants.DocumentedInvariants to findings' seam shape.
func portDocMap(c *state.Campaign) (map[string]validation.Value, error) {
	doc, err := invariants.DocumentedInvariants(c, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]validation.Value, len(doc.O))
	for _, e := range doc.O {
		out[e.K] = e.V
	}
	return out, nil
}

// portIntentMap adapts invariants.IntentClaims to findings' seam shape.
func portIntentMap(c *state.Campaign) (map[string]validation.Value, error) {
	claims, err := invariants.IntentClaims(c, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]validation.Value, len(claims.O))
	for _, e := range claims.O {
		out[e.K] = e.V
	}
	return out, nil
}

// portExecSeq mirrors conftest.py's monotonically minted EXEC ids.
var portExecSeq int

// portExecRecord is conftest.sandboxed_exec: register a container-profile
// EXEC record (sandbox.register_exec is a P1 port; the ledger row is written
// directly, exactly as the helper does through the real function).
func portExecRecord(t *testing.T, c *state.Campaign, findingID, profile,
	command, reportedBy string) validation.Value {
	t.Helper()
	portExecSeq++
	execID := "EXEC-" + pad10(portExecSeq)
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir exec: %v", err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout, []byte("PASS: test_exploit\n"), 0o644); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if err := os.WriteFile(stderr, nil, 0o644); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	rec := validation.VObj(
		kvOf("exec_id", validation.VStr(execID)),
		kvOf("campaign_id", validation.VStr(c.CampaignID)),
		kvOf("profile", validation.VStr(profile)),
		kvOf("finding_id", validation.VStr(findingID)),
		kvOf("artifact_id", validation.VNull()),
		kvOf("command", validation.VStr(command)),
		kvOf("workdir", validation.VNull()),
		kvOf("policy_verdict", validation.VObj(
			kvOf("allowed", validation.VBool(true)),
			kvOf("violations", validation.VArr()),
			kvOf("checked_rules", validation.VArr()))),
		kvOf("environment", validation.VObj(
			kvOf("tool_versions", validation.VObj()),
			kvOf("env_keys", validation.VArr()),
			kvOf("network_access", validation.VStr(
				portNetworkAccess(profile))),
			kvOf("filesystem", validation.VStr("sandbox-tmp")))),
		kvOf("container", validation.VNull()),
		kvOf("origin", validation.VStr("externally-reported")),
		kvOf("reported_by", validation.VStr(reportedBy)),
		kvOf("input_hashes", validation.VObj()),
		kvOf("started_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvOf("finished_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvOf("exit_status", validation.VInt(0)),
		kvOf("stdout_path", validation.VStr(stdout)),
		kvOf("stderr_path", validation.VStr(stderr)),
		kvOf("artifact_hashes", validation.VObj()),
	)
	path := filepath.Join(dir, "exec_record.json")
	if err := validation.WriteJson(path, rec, "sandbox_execution"); err != nil {
		t.Fatalf("write exec record: %v", err)
	}
	return rec
}

// portNetworkAccess is sandbox._PROFILE_NETWORK.
func portNetworkAccess(profile string) string {
	if profile == "fork-runner" {
		return "bridge-host-gateway"
	}
	return "none"
}

func pad10(n int) string {
	s := itoa(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}

// portEvidenceItem is conftest.evidence_item.
func portEvidenceItem(execRec validation.Value, level, typ, description,
	eid string) validation.Value {
	return validation.VObj(
		kvOf("evidence_id", validation.VStr(eid)),
		kvOf("level", validation.VStr(level)),
		kvOf("type", validation.VStr(typ)),
		kvOf("description", validation.VStr(description)),
		kvOf("sandbox_profile", validation.ObjAt(execRec, "profile")),
		kvOf("artifact_id", validation.ObjAt(execRec, "exec_id")),
	)
}

// portManualSeq mints unique manual-evidence ids for the port fixtures (the
// Python twin hard-codes EV-9/EV-10, but the status floors make an extra item
// necessary, so ids must not collide).
var portManualSeq int

// portManualEvidence records a plain manual evidence item at the given level.
// STATUS_FLOOR makes POSSIBLE need E2, so a fixture advance that is not about
// refusing the move must carry real ledger evidence before the transition.
func portManualEvidence(t *testing.T, c *state.Campaign, findingID, level,
	description string) {
	t.Helper()
	portManualSeq++
	if _, err := findings.AddEvidence(c, findingID, validation.VObj(
		kvOf("evidence_id", validation.VStr("EV-M"+pad10(portManualSeq))),
		kvOf("level", validation.VStr(level)),
		kvOf("type", validation.VStr("manual")),
		kvOf("description", validation.VStr(description)),
	)); err != nil {
		t.Fatalf("add %s manual evidence: %v", level, err)
	}
}

// portMaximalAxes is maximization.maximalAxes: the five axes a closed ladder
// must have explored.
var portMaximalAxes = []string{"capital-minimization", "precondition-removal",
	"role-conflation", "ordering-permutation", "cap-saturation"}

// portLadderComplete is the closed variant ladder make_submission_ready
// builds (mirrors internal/bounty's own fixture).
func portLadderComplete() validation.Value {
	axes := []validation.Value{}
	for _, a := range portMaximalAxes {
		axes = append(axes, validation.VStr(a))
	}
	return validation.VObj(
		kvOf("disposition", validation.VObj(
			kvOf("state", validation.VStr("complete")),
			kvOf("reason", validation.VNull()))),
		kvOf("maximal_rung_id", validation.VStr("R-amplified")),
		kvOf("axes_explored", validation.VArr(axes...)),
		kvOf("variants", validation.VArr()),
	)
}

// portMakeSubmissionReady is conftest.make_submission_ready: close the full
// submission chain for a CONFIRMED finding so the bounty gate can pass. The
// fork exec and the E5 evidence are real ledger writes; the ladder, the
// proven-fork status and the immunization record come from the three P1
// seams (their modules are unported) with the values the Python helper
// produces.
func portMakeSubmissionReady(t *testing.T, c *state.Campaign, findingID,
	actor string) validation.Value {
	t.Helper()
	forkRec := portExecRecord(t, c, findingID, "fork-runner",
		"forge test --fork-url http://127.0.0.1:8545 "+
			"--fork-block-number 20000000 --match-test test_exploit", actor)
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	haveFork := false
	for _, e := range listAt(f, "evidence") {
		if strAt(e, "artifact_id") == strAt(forkRec, "exec_id") {
			haveFork = true
		}
	}
	if !haveFork {
		if _, err := findings.AddEvidence(c, findingID, portEvidenceItem(
			forkRec, "E5", "fork-test",
			"mainnet fork repro on pinned state", "EV-fork")); err != nil {
			t.Fatalf("add fork evidence: %v", err)
		}
	}
	bounty.SetLoadLadder(func(*state.Campaign, string) (validation.Value, error) {
		return portLadderComplete(), nil
	})
	bounty.SetForkPocStatus(func(_ *state.Campaign, fid string) (bool, string,
		error) {
		if fid != findingID {
			return false, "no fork PoC proven", nil
		}
		return true, "fork PoC proven: E5 fork-test from " +
			strAt(forkRec, "exec_id") + " (fork-runner, exit 0)", nil
	})
	bounty.SetImmunizationDetail(func(validation.Value) (string, string) {
		return "immunized", "patch blocks the fork PoC and all 3 boundary " +
			"mutations (basis: " + strAt(forkRec, "exec_id") + ")"
	})
	// 3. price basis: the USD figures name their row.
	row := validation.VObj(
		kvOf("price_id", validation.VStr("PRC-acme01")),
		kvOf("asset", validation.VStr("ACME")),
		kvOf("usd", validation.VFloat(1.0)),
		kvOf("source", validation.VStr("fixture: fixed reference price")),
	)
	bounty.SetPriceRow(func(*state.Campaign, string) (validation.Value, error) {
		return row, nil
	})
	f, err = findings.LoadFinding(c, findingID)
	if err != nil {
		t.Fatalf("reload finding: %v", err)
	}
	ei := validation.ObjAt(f, "economic_impact")
	if ei.Kind != validation.Obj {
		ei = validation.VObj()
	}
	ei.O = validation.SetOrAppend(ei.O, "price_basis", validation.VStr("PRC-acme01"))
	f.O = validation.SetOrAppend(f.O, "economic_impact", ei)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	// A4: the submission chain answers "who pays, and why" — the gate's
	// paid-exploitability check (check14) demands it on every CONFIRMED
	// extractable finding.
	if _, err := findings.SetExploitability(c, findingID, true,
		"Who pays: the protocol itself — the vault treasury is the "+
			"counterparty funding every unbacked withdrawal, and the stale "+
			"spot read mints value the pool never held. The E5 fork repro "+
			"measured $1,500,000 extractable against the pinned ACME price "+
			"(PRC-acme01), above the program's high-band floor for "+
			"protocol-solvency impact, so the bug makes the protocol pay by "+
			"turning each price update into an unbacked withdrawal right"); err != nil {
		t.Fatalf("set exploitability: %v", err)
	}
	return forkRec
}

// portSeedSharedMemoryRow is conftest.seed_global_memory_row: one approved
// row in the user-global shared-memory tier (loaded through findings' seam).
func portSeedSharedMemoryRow(t *testing.T, c *state.Campaign) {
	t.Helper()
	row := validation.VObj(
		kvOf("memory_id", validation.VStr("MEM-shared01")),
		kvOf("campaign_id", validation.VStr("ingest:test:case")),
		kvOf("finding_id", validation.VNull()),
		kvOf("snapshot_id", validation.VNull()),
		kvOf("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kvOf("kind", validation.VStr("confirmed")),
		kvOf("status", validation.VStr("CONFIRMED")),
		kvOf("pattern", validation.VStr("Shared memory pattern")),
		kvOf("bug_class", validation.VStr("logic-error")),
		kvOf("cwe", validation.VNull()),
		kvOf("evidence_summary", validation.VStr("Seeded incident.")),
		kvOf("partition", validation.VStr("dev")),
		kvOf("schema_version", validation.VInt(2)),
		kvOf("rejection_class", validation.VNull()),
		kvOf("deciding_propositions", validation.VArr()),
		kvOf("promotion_status", validation.VStr("promoted")),
		kvOf("approved_by", validation.VStr("operator")),
		kvOf("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return []validation.Value{validation.VObj(
			kvOf("program_key", validation.VStr("test|other|-")),
			kvOf("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
			kvOf("row", row),
			kvOf("scope", validation.VStr("global")),
		)}, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(func(string) (
			[]validation.Value, error) {
			return nil, nil
		})
	})
	_ = c
}

// portJSON parses an embedded JSON literal into the ordered value model.
func portJSON(t *testing.T, raw string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(raw))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return v
}

// portPhase reads the campaign phase.
func portPhase(t *testing.T, c *state.Campaign) string {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	return strAt(st, "phase")
}

// portFindings is findings.load_all_findings keyed by finding_id.
func portFindings(t *testing.T, c *state.Campaign) map[string]validation.Value {
	t.Helper()
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatalf("load findings: %v", err)
	}
	out := map[string]validation.Value{}
	for _, f := range all {
		out[strAt(f, "finding_id")] = f
	}
	return out
}

// TestPortFullPipelineEndToEnd is test_full_pipeline_end_to_end: the whole
// facade against a real campaign on disk. The phases are separate helpers so
// each one stays readable and short; the step numbers match the Python test.
func TestPortFullPipelineEndToEnd(t *testing.T) {
	portWireSeams(t)
	root := t.TempDir()
	c, err := state.Init(root, "Acme Protocol Immunefi", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	o := New(c)
	portInstallIndex(t)

	target := portStepScope(t, o, c, root) // 1. scope
	portStepSnapshot(t, o, c, target)      // 2. snapshot
	index := portStepIndex(t, o, c)        // 3. structural index
	model := portStepModel(t, o, c)        // 4. protocol model
	portStepPlan(t, o, c)                  // 5. plan + work queue
	h1, h3 := portStepDiscovery(t, o)      // 6. discovery / ingest
	portStepTriage(t, o, c, h1, h3)        // 7. triage ordering
	portStepDedup(t, o, c)                 // 8. dedup
	fid := portStepConfirm(t, c, h3)       // 9. review -> CONFIRMED
	portStepQueues(t, o, fid)              // 10/11. queues + chaining
	portStepCalibration(t, o, c, fid)      // 12. calibration
	portStepGate(t, o, fid)                // 13. bounty gate
	portStepCoverage(t, c, index, model)   // 14. coverage projection
	portStepEndState(t, o)                 // 15/16. end state
}

// portStepScope is step 1: write the policy, scope the program, and return
// the target directory the snapshot phase will pin.
func portStepScope(t *testing.T, o *Orchestrator, c *state.Campaign,
	root string) string {
	t.Helper()
	policyFile := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyFile, []byte(portPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if _, err := o.Scope(policyFile); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if got := portPhase(t, c); got != "SCOPE" {
		t.Fatalf("phase after scope = %s, want SCOPE", got)
	}
	return filepath.Join(root, "target")
}

// portStepSnapshot is step 2: pin the target tree.
func portStepSnapshot(t *testing.T, o *Orchestrator, c *state.Campaign,
	target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	writeFile(t, filepath.Dir(target), filepath.Join("target", "src",
		"Vault.sol"), "contract Vault { uint256 public totalAssets; "+
		"function deposit() external {} }")
	cfg := validation.VObj(kvOf("compiler", validation.VStr("solc 0.8.24")))
	if _, err := o.Snapshot(target, SnapshotOpts{Config: &cfg}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := portPhase(t, c); got != "STRUCTURAL_INDEX" {
		t.Fatalf("phase after snapshot = %s, want STRUCTURAL_INDEX", got)
	}
}

// portStepIndex is step 3: build the structural index.
func portStepIndex(t *testing.T, o *Orchestrator,
	c *state.Campaign) validation.Value {
	t.Helper()
	index, err := o.BuildStructuralIndex()
	if err != nil {
		t.Fatalf("build_structural_index: %v", err)
	}
	stats := validation.ObjAt(index, "stats")
	if intAt(stats, "functions") < 1 {
		t.Fatalf("stats.functions = %d, want >= 1", intAt(stats, "functions"))
	}
	if intAt(stats, "entry_points") < 1 {
		t.Fatalf("stats.entry_points = %d, want >= 1",
			intAt(stats, "entry_points"))
	}
	if got := portPhase(t, c); got != "PROTOCOL_INTELLIGENCE" {
		t.Fatalf("phase after index = %s, want PROTOCOL_INTELLIGENCE", got)
	}
	return index
}

// portStepModel is step 4: load the protocol model and its invariants.
func portStepModel(t *testing.T, o *Orchestrator,
	c *state.Campaign) validation.Value {
	t.Helper()
	model := portJSON(t, portModel)
	result, err := o.LoadProtocolModel(model)
	if err != nil {
		t.Fatalf("load_protocol_model: %v", err)
	}
	if n := len(listAt(result, "transforms")); n < 5 {
		t.Fatalf("transforms = %d, want >= 5", n)
	}
	invCov, err := invariants.Coverage(c)
	if err != nil {
		t.Fatalf("invariants.coverage: %v", err)
	}
	// the liveness template is synthesized by design (task 9 behavior)
	if intAt(invCov, "total") != 3 {
		t.Fatalf("invariant coverage total = %d, want 3",
			intAt(invCov, "total"))
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatalf("invariants.load_links: %v", err)
	}
	liveness := 0
	for _, kv := range validation.ObjAt(links, "invariants").O {
		e := kv.V
		if strAt(e, "kind") != "liveness" {
			continue
		}
		for _, a := range listAt(e, "applies_to") {
			if a.Kind == validation.Str && a.S == "vault-lifecycle" {
				liveness++
			}
		}
	}
	if liveness != 1 {
		t.Fatalf("liveness invariants = %d, want 1", liveness)
	}
	return model
}

// portStepPlan is step 5: the bootstrap plan and its work queue.
func portStepPlan(t *testing.T, o *Orchestrator, c *state.Campaign) {
	t.Helper()
	planned, err := o.Plan(validation.VNull(), validation.VNull(), false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(listAt(planned, "work_queue")) == 0 {
		t.Fatal("bootstrap plan must yield priorities")
	}
	if got := portPhase(t, c); got != "DISCOVERY" {
		t.Fatalf("phase after plan = %s, want DISCOVERY", got)
	}
}

// portStepDiscovery is step 6: ingest one dup pair and one unique hypothesis.
func portStepDiscovery(t *testing.T, o *Orchestrator) (validation.Value,
	validation.Value) {
	t.Helper()
	h1 := portIngest(t, o, "First depositor steals rounding dust from next "+
		"users", "precision-rounding",
		"share minting rounds down in attacker favor", "INV-001",
		"share redeem value is fully backed by vault assets", "code", "11")
	// morph §7.5: the second claim must be DISTINCT — an identical payload
	// (same title + root_cause + affected) is answered with the first
	// finding's twin at the ingest door. The technical signature
	// (class/path/function) is unchanged, so tier 1 still merges the pair.
	portIngest(t, o, "First depositor steals rounding dust from next users",
		"precision-rounding",
		"share minting rounds down in attacker favor (economic restatement)",
		"INV-001",
		"share redeem value is fully backed by vault assets", "economic", "05")
	h3 := portIngest(t, o, "Unguarded rescue function drains user staking "+
		"balance", "access-control",
		"rescue transfers all tokens to caller without role check", "INV-002",
		"only governor can upgrade the implementation", "attacker", "06")
	return h1, h3
}

// portStepTriage is step 7: deterministic prior risk ordering (all three
// findings are still open because dedup has not run yet).
func portStepTriage(t *testing.T, o *Orchestrator, c *state.Campaign,
	h1, h3 validation.Value) {
	t.Helper()
	triage, err := o.TriageAll()
	if err != nil {
		t.Fatalf("triage_all: %v", err)
	}
	all := portFindings(t, c)
	if len(triage.A) != len(all) {
		t.Fatalf("triage rows = %d, want %d", len(triage.A), len(all))
	}
	prios := map[string]float64{}
	for _, row := range triage.A {
		fid := strAt(row, "finding_id")
		if _, ok := all[fid]; !ok {
			t.Fatalf("triage row %s is not a live finding", fid)
		}
		prios[fid] = numAt(validation.ObjAt(row, "prior"), "score")
	}
	h1id := strAt(h1, "finding_id")
	h3id := strAt(h3, "finding_id")
	// access-control outranks rounding
	if !(prios[h3id] > prios[h1id]) {
		t.Fatalf("prior scores: access-control %.4f <= rounding %.4f",
			prios[h3id], prios[h1id])
	}
}

// portStepDedup is step 8: the two identical hypotheses merge to one
// DUPLICATE.
func portStepDedup(t *testing.T, o *Orchestrator, c *state.Campaign) {
	t.Helper()
	report, err := o.RunDedup()
	if err != nil {
		t.Fatalf("run_dedup: %v", err)
	}
	if n := len(listAt(report, "tier1_merges")); n != 1 {
		t.Fatalf("tier1_merges = %d, want 1", n)
	}
	if got := portPhase(t, c); got != "CANDIDATE_INTEL" {
		t.Fatalf("phase after dedup = %s, want CANDIDATE_INTEL", got)
	}
}

// portStepConfirm is step 9: hostile review, evidence, and the CONFIRMED
// transition for the access-control finding.
func portStepConfirm(t *testing.T, c *state.Campaign,
	h3 validation.Value) string {
	t.Helper()
	fid := strAt(h3, "finding_id")
	// The invariant statement is verified before any level-raising evidence
	// (task H guardrail), and the POSSIBLE floor now needs E2 in the ledger.
	portStepInvariant(t, c, fid)
	portManualEvidence(t, c, fid, "E2",
		"triage: unguarded rescue path confirmed by reading the code")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "",
		"", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	rec := portExecRecord(t, c, fid, "docker-networkless",
		"forge test --match-test test_exploit", "pytest-harness")
	if _, err := findings.AddEvidence(c, fid, portEvidenceItem(rec, "E4",
		"foundry-test", "local PoC drains vault", "EV-9")); err != nil {
		t.Fatalf("add E4 evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"controls checked, none found"); err != nil {
		t.Fatalf("set_critic_verdict: %v", err)
	}
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kvOf("evidence_id", validation.VStr("EV-10")),
		kvOf("level", validation.VStr("E1")),
		kvOf("type", validation.VStr("manual")),
		kvOf("description", validation.VStr(
			"negative-mode: no prior safe shape")),
	)); err != nil {
		t.Fatalf("add E1 evidence: %v", err)
	}
	portStepMemory(t, c, fid)
	portStepVerdict(t, c, fid)
	portStepSubmission(t, c, fid)
	return fid
}

// portStepInvariant verifies the model-derived invariant statement before
// level-raising evidence (task H guardrail).
func portStepInvariant(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	invCheck := filepath.Join(c.ArtifactsDir, "inv-002-check.md")
	if err := os.WriteFile(invCheck,
		[]byte("INV-002 checked against src/Vault.sol\n"), 0o644); err != nil {
		t.Fatalf("write inv check: %v", err)
	}
	invArt, err := c.RegisterOrRefresh("other", invCheck, "", nil, "")
	if err != nil {
		t.Fatalf("register inv check: %v", err)
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-002",
		invArt); err != nil {
		t.Fatalf("verify_invariant_statement: %v", err)
	}
}

// portStepMemory records the negative-mode shared-memory check.
func portStepMemory(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	portSeedSharedMemoryRow(t, c)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(kvOf("memory_ids", validation.VArr(
			validation.VStr("MEM-shared01"))),
			kvOf("mode", validation.VStr("negative"))),
	}); err != nil {
		t.Fatalf("record_memory_check: %v", err)
	}
}

// portStepVerdict fills the verification block and transitions to CONFIRMED.
func portStepVerdict(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kvOf("tier_reached", validation.VStr("T1")),
		kvOf("status", validation.VStr("reproduced")),
		kvOf("attempts", validation.VArr()),
	))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	vf.O = validation.SetOrAppend(vf.O, "economic_impact", validation.VObj(
		kvOf("blast_radius", validation.VStr("protocol-solvency")),
		kvOf("extractable_usd", validation.VInt(50000000)),
	))
	inv := validation.ObjAt(vf, "invariant")
	if inv.Kind != validation.Obj {
		inv = validation.VObj()
	}
	inv.O = validation.SetOrAppend(inv.O, "violation_demonstrated", validation.VBool(true))
	vf.O = validation.SetOrAppend(vf.O, "invariant", inv)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gates passed", "",
		"", false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
}

// portStepSubmission links the finding to its invariant and closes the
// submission chain: mainnet fork PoC (the latest required step), variant
// ladder, price basis, immunization - the gate re-checks every one of them.
func portStepSubmission(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	if _, err := invariants.LinkFinding(c, "INV-002", fid, true); err != nil {
		t.Fatalf("link_finding: %v", err)
	}
	portMakeSubmissionReady(t, c, fid, "pytest-harness")
}

// portStepQueues is steps 10/11: the reproduction queue excludes the
// confirmed finding and the capability graph still yields no chains.
func portStepQueues(t *testing.T, o *Orchestrator, fid string) {
	t.Helper()
	rq, err := o.ReproductionQueue()
	if err != nil {
		t.Fatalf("reproduction_queue: %v", err)
	}
	for _, q := range rq.A {
		if strAt(q, "finding_id") == fid {
			t.Fatalf("reproduction queue still holds confirmed %s", fid)
		}
	}
	chains, err := o.Chaining()
	if err != nil {
		t.Fatalf("chaining: %v", err)
	}
	if len(listAt(chains, "proposals")) != 0 ||
		len(listAt(chains, "materialized")) != 0 {
		t.Fatalf("chaining = %s", validation.DumpIndented(chains))
	}
}

// portStepCalibration is step 12: the validated risk band.
func portStepCalibration(t *testing.T, o *Orchestrator, c *state.Campaign,
	fid string) {
	t.Helper()
	if _, err := o.CalibrateAll(); err != nil {
		t.Fatalf("calibrate_all: %v", err)
	}
	calibrated, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("reload calibrated: %v", err)
	}
	band := strAt(validation.ObjAt(validation.ObjAt(calibrated, "risk"), "validated"), "band")
	if band != "critical" && band != "high" {
		t.Fatalf("validated band = %s, want critical|high", band)
	}
}

// portStepGate is step 13: the bounty gate row for the confirmed finding.
func portStepGate(t *testing.T, o *Orchestrator, fid string) {
	t.Helper()
	gates, err := o.BountyGateAll()
	if err != nil {
		t.Fatalf("bounty_gate_all: %v", err)
	}
	g := validation.VNull()
	for _, row := range gates.A {
		if strAt(row, "finding_id") == fid {
			g = row
		}
	}
	if g.Kind != validation.Obj {
		t.Fatalf("gate has no row for %s", fid)
	}
	if !boolAt(g, "eligible") {
		t.Fatalf("gate not eligible: %s", validation.DumpIndented(g))
	}
	if !boolAt(g, "submission_ready") {
		t.Fatalf("gate not submission_ready: %s", validation.DumpIndented(g))
	}
}

// portStepCoverage is step 14: the coverage projection after the Vault sweep.
func portStepCoverage(t *testing.T, c *state.Campaign, index,
	model validation.Value) {
	t.Helper()
	if _, err := coverage.Load(c); err != nil {
		t.Fatalf("coverage.load: %v", err)
	}
	if _, err := coverage.RecordSweep(c, "Vault.sol", "code",
		coverage.SweepOpts{EntryPointsReviewed: 1, Complete: true}); err != nil {
		t.Fatalf("record_sweep: %v", err)
	}
	if _, err := coverage.UpdateFunnel(c); err != nil {
		t.Fatalf("update_funnel: %v", err)
	}
	summary, err := coverage.BuildSummary(c, index, model)
	if err != nil {
		t.Fatalf("build_summary: %v", err)
	}
	// Vault swept, proxy out of model scope
	if intAt(summary, "contracts_unknown") != 0 {
		t.Fatalf("contracts_unknown = %d, want 0",
			intAt(summary, "contracts_unknown"))
	}
}

// portStepEndState is steps 15/16: learning memory + reflection + report have
// no Go port (P1); the end-state the Python test asserts at the orchestrator
// surface is checked here instead.
func portStepEndState(t *testing.T, o *Orchestrator) {
	t.Helper()
	st, err := o.Status(false)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	counts := validation.ObjAt(st, "findings")
	if intAt(counts, "CONFIRMED") != 1 {
		t.Fatalf("status CONFIRMED = %d, want 1", intAt(counts, "CONFIRMED"))
	}
	if intAt(counts, "DUPLICATE") != 1 {
		t.Fatalf("status DUPLICATE = %d, want 1", intAt(counts, "DUPLICATE"))
	}
}

// portInstallIndex stands in for webv2.structural_index (P3, unported): it
// walks the pinned snapshot and counts Solidity functions and entry points,
// so the test's stats assertions still describe the target tree.
func portInstallIndex(t *testing.T) {
	t.Helper()
	SetStructuralIndex(StructuralIndexAPI{
		IndexSnapshot: func(c *state.Campaign, root string) (validation.Value,
			error) {
			nodes, functions, entryPoints, err := portIndexNodes(root)
			if err != nil {
				return validation.VNull(), err
			}
			snapID, err := c.ActiveSnapshotIDOrNone()
			if err != nil {
				return validation.VNull(), err
			}
			return validation.VObj(
				kvOf("campaign_id", validation.VStr(c.CampaignID)),
				kvOf("snapshot_id", validation.VStr(*snapID)),
				kvOf("backend", validation.VStr("regex")),
				kvOf("parse_version", validation.VStr("1")),
				kvOf("created_at", validation.VStr("2026-03-04T05:06:07+00:00")),
				kvOf("entry_count", validation.VInt(int64(entryPoints))),
				kvOf("nodes", validation.VArr(nodes...)),
				kvOf("edges", validation.VArr()),
				kvOf("stats", validation.VObj(
					kvOf("functions", validation.VInt(int64(functions))),
					kvOf("entry_points", validation.VInt(
						int64(entryPoints))))),
			), nil
		},
		SaveIndex: func(c *state.Campaign,
			index validation.Value) (string, error) {
			out := filepath.Join(c.ArtifactsDir, "structural_index.json")
			if err := validation.WriteJson(out, index, "structural_index"); err != nil {
				return "", err
			}
			return out, nil
		},
	})
	t.Cleanup(func() { SetStructuralIndex(StructuralIndexAPI{}) })
}

// portIndexNodes walks the target tree and returns its index nodes plus the
// function / entry-point counts.
func portIndexNodes(root string) ([]validation.Value, int, int, error) {
	nodes := []validation.Value{}
	functions, entryPoints := 0, 0
	err := filepath.Walk(root, func(path string, info os.FileInfo,
		err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".sol") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		nodes = append(nodes, validation.VObj(
			kvOf("id", validation.VStr(rel+"#Vault")),
			kvOf("kind", validation.VStr("contract")),
			kvOf("name", validation.VStr("Vault")),
			kvOf("path", validation.VStr(rel)),
			kvOf("line", validation.VInt(1)),
		))
		for _, name := range portFunctions(string(raw)) {
			functions++
			isEntry := strings.Contains(name, "external") ||
				strings.Contains(name, "public")
			if isEntry {
				entryPoints++
			}
			nodes = append(nodes, portFunctionNode(rel, name, isEntry))
		}
		return nil
	})
	return nodes, functions, entryPoints, err
}

// portFunctionNode is one function node of the stand-in index.
func portFunctionNode(rel, name string, isEntry bool) validation.Value {
	vis := "internal"
	if isEntry {
		vis = "external"
	}
	return validation.VObj(
		kvOf("id", validation.VStr(rel+"#Vault."+portFuncName(name))),
		kvOf("kind", validation.VStr("function")),
		kvOf("name", validation.VStr(portFuncName(name))),
		kvOf("path", validation.VStr(rel)),
		kvOf("line", validation.VInt(1)),
		kvOf("visibility", validation.VStr(vis)),
		kvOf("is_entry_point", validation.VBool(isEntry)),
	)
}

// portFunctions splits a Solidity body into its function signatures.
func portFunctions(body string) []string {
	out := []string{}
	for _, part := range strings.Split(body, "function ") {
		head := strings.TrimSpace(strings.SplitN(part, "{", 2)[0])
		if head == "" || strings.HasPrefix(head, "//") {
			continue
		}
		out = append(out, head)
	}
	return out
}

// portFuncName is the identifier of a signature head.
func portFuncName(head string) string {
	return strings.TrimSpace(strings.SplitN(head, "(", 2)[0])
}

// portIngest is the ingest call of the Python test, with the shared
// hypothesis shape.
func portIngest(t *testing.T, o *Orchestrator, title, class, description,
	invID, invStatement, trajectory, stage string) validation.Value {
	t.Helper()
	payload := validation.VObj(
		kvOf("title", validation.VStr(title)),
		kvOf("root_cause", validation.VObj(
			kvOf("class", validation.VStr(class)),
			kvOf("description", validation.VStr(description)))),
		kvOf("affected", validation.VArr(validation.VObj(
			kvOf("path", validation.VStr("src/Vault.sol")),
			kvOf("contract", validation.VStr("Vault")),
			kvOf("function", validation.VStr("deposit"))))),
		kvOf("attacker", validation.VObj(
			kvOf("profile", validation.VStr("arbitrary EOA")),
			kvOf("capabilities", validation.VArr()))),
		kvOf("invariant", validation.VObj(
			kvOf("id", validation.VStr(invID)),
			kvOf("statement", validation.VStr(invStatement)))),
	)
	f, err := o.Ingest(payload, IngestOpts{Trajectory: trajectory,
		Stage: stage})
	if err != nil {
		t.Fatalf("ingest %q: %v", title, err)
	}
	return f
}

// TestPortNextActionsGuidance is test_next_actions_guidance.
func TestPortNextActionsGuidance(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	acts, err := NextActions(c)
	if err != nil {
		t.Fatalf("next_actions: %v", err)
	}
	if !portAnyContains(acts, "scope") {
		t.Fatalf("no scope guidance: %s", validation.DumpIndented(acts))
	}
	if err := c.SetPhase("REPRODUCTION", "test"); err != nil {
		t.Fatalf("set_phase: %v", err)
	}
	acts, err = NextActions(c)
	if err != nil {
		t.Fatalf("next_actions (REPRODUCTION): %v", err)
	}
	if !portAnyContains(acts, "repro") {
		t.Fatalf("no reproduction guidance: %s",
			validation.DumpIndented(acts))
	}
}

// portAnyContains is Python's any(needle in a for a in acts).
func portAnyContains(acts validation.Value, needle string) bool {
	for _, a := range acts.A {
		if a.Kind == validation.Str && strings.Contains(a.S, needle) {
			return true
		}
	}
	return false
}

// TestPortBountyGateRequiresPolicy is test_bounty_gate_requires_policy.
func TestPortBountyGateRequiresPolicy(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	o := New(c)
	if _, err := o.BountyGateAll(); err == nil {
		t.Fatal("bounty_gate_all without a policy: want OrchestrationError")
	} else if _, ok := err.(*OrchestrationError); !ok {
		t.Fatalf("bounty_gate_all error = %T (%v), want *OrchestrationError",
			err, err)
	}
}
