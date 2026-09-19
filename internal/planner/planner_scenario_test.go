package planner

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/invariants"
	"websec/internal/protocolgraph"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// This file ports the 8 scenario tests the planner slice was missing:
// tests/test_plan_lenses.py::{test_anchor_added_on_confirmed_high,
// test_anchor_drops_non_canonical_bug_class,
// test_anchor_is_idempotent_and_severity_gated,
// test_divergence_counts_a_reasonless_answer_as_open,
// test_divergence_status_closed_plan, test_divergence_status_open_plan},
// tests/test_answered.py::test_not_applicable_is_a_valid_status and
// tests/test_lens_exhaustive.py::
// test_confirmed_finding_reopens_the_lens_whose_family_it_hit.
//
// The expected artifacts are NOT hand-transcribed: they are recorded from the
// live Python twin by gen.py [untracked], which drives the very test bodies
// (helpers imported out of tests/) and writes
// testdata/scenario_oracles.json. The Go fixtures below replay the same
// scenario steps with the same pinned clock (WEBV2_NOW) and the same
// deterministic finding-id sequence.

// scnOracle is testdata/scenario_oracles.json.
func scnOracle(t *testing.T) validation.Value {
	t.Helper()
	v, err := validation.ReadJson("testdata/scenario_oracles.json")
	if err != nil {
		t.Fatalf("read scenario oracles: %v", err)
	}
	return v
}

// scnPinNow pins the clock the oracle was recorded under (state.now_iso's
// WEBV2_NOW hook), so generated timestamps are byte-comparable.
func scnPinNow(t *testing.T) {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
}

// scnModelArtifact is test_plan_lenses._campaign_with_model's schema-valid
// protocol_model artifact (MODEL plus the required model collections).
func scnModelArtifact(t *testing.T) validation.Value {
	t.Helper()
	return jsonValue(t, `{"protocol_id":"morph-l2","name":"Morph L2",
		"contracts":[{"name":"Rollup","path":"contracts/l2/Rollup.sol",
			"role":"core","in_scope":true,
			"entry_points":["commitBatch","finalizeBatch"]}],
		"actors":[],"assets":[],"relations":[],
		"state_machines":[{"name":"rollup-lifecycle",
			"states":[{"id":"open"}],
			"transitions":[{"from":"open","to":"finalized",
				"trigger":"finalize"}]}]}`)
}

// scnCampaignWithModel is test_plan_lenses._campaign_with_model: the round-4
// campaign fixture (C-lens1234) with the model artifact on disk.
func scnCampaignWithModel(t *testing.T) *state.Campaign {
	t.Helper()
	camp := portCampaign(t, "Morph L2")
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	art := filepath.Join(camp.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(art, scnModelArtifact(t), "protocol_model"); err != nil {
		t.Fatalf("write model artifact: %v", err)
	}
	return camp
}

// scnFindingIDs installs the deterministic finding-id minter the oracle was
// generated with (Python's new_finding_id is a raw uuid4; gen.py patches the
// same sequence into the live twin).
func scnFindingIDs(t *testing.T) {
	t.Helper()
	n := 0
	findings.SetFindingIDSource(func() string {
		n++
		return fmt.Sprintf("F-%012d", n)
	})
	t.Cleanup(func() { findings.SetFindingIDSource(nil) })
}

// scnOpts is test_plan_lenses._confirmed_finding's keyword tail.
type scnOpts struct {
	title    string
	severity string
	contract string
	class    string
	fn       string
}

// scnFindingOpts applies the Python defaults: Rollup / logic-error /
// commitBatch.
func scnFindingOpts(o scnOpts) scnOpts {
	if o.contract == "" {
		o.contract = "Rollup"
	}
	if o.class == "" {
		o.class = "logic-error"
	}
	if o.fn == "" {
		o.fn = "commitBatch"
	}
	return o
}

// scnMemoryRow is conftest.seed_global_memory_row's row (MEM-shared01).
func scnMemoryRow() validation.Value {
	return validation.VObj(
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
}

// scnSeedMemory is conftest.seed_global_memory_row: one approved row in the
// user-global tier, handed to findings through the store seam.
func scnSeedMemory(t *testing.T) {
	t.Helper()
	row := scnMemoryRow()
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return []validation.Value{validation.VObj(kv("row", row))}, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(func(string) ([]validation.Value,
			error) {
			return nil, nil
		})
	})
}

var scnExecSeq int

// scnExec is conftest.sandboxed_exec: register_exec lands an EXEC record in
// the campaign ledger with the container profile and captured output the
// evidence gate verifies.
func scnExec(t *testing.T, camp *state.Campaign,
	findingID string) validation.Value {
	t.Helper()
	scnExecSeq++
	execID := fmt.Sprintf("EXEC-%010x", scnExecSeq)
	dir := filepath.Join(camp.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir exec dir: %v", err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout, []byte("PASS: test_exploit\n"), 0o644); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if err := os.WriteFile(stderr, []byte(""), 0o644); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(camp.CampaignID)),
		kv("profile", validation.VStr("docker-networkless")),
		kv("finding_id", validation.VStr(findingID)),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr("forge test --match-test test_exploit")),
		kv("exit_status", validation.VInt(0)),
		kv("stdout_path", validation.VStr(stdout)),
		kv("stderr_path", validation.VStr(stderr)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatalf("write exec record: %v", err)
	}
	return rec
}

// scnEvidenceItem is conftest.evidence_item.
func scnEvidenceItem(rec validation.Value, level, typ, desc,
	eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr(desc)),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id")),
	)
}

// floorEvidenceSeq mints unique evidence ids for the manual floor items the
// fixtures attach before a status whose evidence floor is above E0.
var floorEvidenceSeq int

// addFloorEvidence attaches a manual (non-exec) evidence item at *level*: the
// reachability evidence a status floor demands before the status stamp. It is
// the finding's first rise above E0, so it pays the discovery slot once — the
// exec-backed evidence the fixtures attach afterwards rides that same rise for
// free, keeping the campaign's slot spend unchanged.
func addFloorEvidence(t *testing.T, camp *state.Campaign, fid, level string) {
	t.Helper()
	floorEvidenceSeq++
	if _, err := findings.AddEvidence(camp, fid, validation.VObj(
		kv("evidence_id", validation.VStr(
			fmt.Sprintf("EV-manual-%04d", floorEvidenceSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"manual reachability note: the path to the sink is reachable")))); err != nil {
		t.Fatalf("add floor evidence %s: %v", level, err)
	}
}

// scnRewrite is `finding[key] = value; save_finding(camp, finding)`.
func scnRewrite(t *testing.T, camp *state.Campaign, fid, key, raw string) {
	t.Helper()
	f, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	f.O = validation.SetOrAppend(f.O, key, jsonValue(t, raw))
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatalf("save finding: %v", err)
	}
}

// scnSetAnchorShape is the tests' `finding["affected"]/["root_cause"] = ...`
// rewrite for the Rollup fixture.
func scnSetAnchorShape(t *testing.T, camp *state.Campaign, fid, fn, class,
	desc string) {
	t.Helper()
	scnRewrite(t, camp, fid, "affected",
		`[{"path":"contracts/l2/Rollup.sol","contract":"Rollup",
		  "function":"`+fn+`"}]`)
	scnRewrite(t, camp, fid, "root_cause",
		`{"class":"`+class+`","description":"`+desc+`"}`)
}

// scnReconfirm is the test's
// `save_finding(camp, load_finding(camp, fid)); transition(..., "CONFIRMED")`
// re-confirmation of an already-CONFIRMED finding.
func scnReconfirm(t *testing.T, camp *state.Campaign, fid string) {
	t.Helper()
	again, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	if err := findings.SaveFinding(camp, &again); err != nil {
		t.Fatalf("re-save finding: %v", err)
	}
	if _, err := findings.Transition(camp, fid, "CONFIRMED",
		"re-confirmed on the second snapshot", "pytest", "", false); err != nil {
		t.Fatalf("re-confirm: %v", err)
	}
}

// scnAnchors is `[q for q in plan["priorities"] if q.get("anchor_of") == fid]`.
func scnAnchors(plan validation.Value, fid string) []validation.Value {
	out := []validation.Value{}
	for _, q := range listOf(plan, "priorities") {
		if validation.ObjStr(q, "anchor_of") == fid {
			out = append(out, q)
		}
	}
	return out
}

// scnConfirmedFinding is test_plan_lenses._confirmed_finding: it drives the
// REAL ladder (ingest -> POSSIBLE -> E4 exec evidence -> critic verdict ->
// graph-memory check -> reproduction) and returns the finding one legal
// transition(..., "CONFIRMED") away from the anchor hook.
func scnConfirmedFinding(t *testing.T, camp *state.Campaign,
	raw scnOpts) validation.Value {
	t.Helper()
	o := scnFindingOpts(raw)
	payload := validation.VObj(
		kv("title", validation.VStr(o.title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(o.class)),
			kv("description", validation.VStr(o.class+" reproduced through "+
				o.fn)))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("contracts/l2/"+o.contract+".sol")),
			kv("contract", validation.VStr(o.contract)),
			kv("function", validation.VStr(o.fn))))),
		kv("reported_severity", validation.VStr(o.severity)),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	)
	f, err := findings.IngestHypothesis(camp, payload, "code", "06", "")
	if err != nil {
		t.Fatalf("ingest_hypothesis: %v", err)
	}
	fid := validation.ObjStr(f, "finding_id")
	// R3-3: the POSSIBLE floor is E2, so the fixture earns the reachability
	// evidence BEFORE the status stamp (evidence floors gate every status).
	addFloorEvidence(t, camp, fid, "E2")
	if _, err := findings.Transition(camp, fid, "POSSIBLE",
		"triage (anchor-rescan fixture)", "", "", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	rec := scnExec(t, camp, fid)
	if _, err := findings.AddEvidence(camp, fid, scnEvidenceItem(rec, "E4",
		"foundry-test", "unit repro under container", "EV-anchor")); err != nil {
		t.Fatalf("add_evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(camp, fid, "confirmed",
		"checked"); err != nil {
		t.Fatalf("set_critic_verdict: %v", err)
	}
	scnSeedMemory(t)
	if _, err := findings.RecordMemoryCheck(camp, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("record_memory_check: %v", err)
	}
	got, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	ver := validation.ObjAt(got, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T1")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	got.O = validation.SetOrAppend(got.O, "verification", ver)
	if err := findings.SaveFinding(camp, &got); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	out, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("reload finding: %v", err)
	}
	return out
}

// TestAnchorAddedOnConfirmedHigh is
// test_plan_lenses.py::test_anchor_added_on_confirmed_high.
func TestAnchorAddedOnConfirmedHigh(t *testing.T) {
	want := at(t, scnOracle(t), "anchor_added_on_confirmed_high")
	scnFindingIDs(t)
	camp := scnCampaignWithModel(t)
	plan, err := DefaultPlanFromModel(camp, portLensModel(t))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	f := scnConfirmedFinding(t, camp, scnOpts{
		title: "commitBatch never validates prevStateRoot", severity: "high"})
	fid := validation.ObjStr(f, "finding_id")
	requireJSON(t, "finding_id", validation.VStr(fid),
		validation.ObjAt(want, "finding_id"))
	scnSetAnchorShape(t, camp, fid, "commitBatch", "logic-error",
		"prevStateRoot unvalidated")
	if _, err := findings.Transition(camp, fid, "CONFIRMED",
		"sandbox repro: chain reorg after commitBatch", "pytest", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	plan2, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	requireJSON(t, "plan", plan2, validation.ObjAt(want, "plan"))
	anchors := scnAnchors(plan2, fid)
	if len(anchors) != 1 {
		t.Fatalf("expected 1 anchor priority, got %d", len(anchors))
	}
	requireJSON(t, "anchors", validation.VArr(anchors...), validation.ObjAt(want, "anchors"))
	requireJSON(t, "anchor status", validation.ObjAt(anchors[0], "status"),
		validation.VStr("open"))
	requireJSON(t, "anchor bug_class", validation.ObjAt(anchors[0], "bug_class"),
		validation.VStr("logic-error"))
}

// TestAnchorIsIdempotentAndSeverityGated is
// test_plan_lenses.py::test_anchor_is_idempotent_and_severity_gated.
func TestAnchorIsIdempotentAndSeverityGated(t *testing.T) {
	want := at(t, scnOracle(t), "anchor_is_idempotent_and_severity_gated")
	scnFindingIDs(t)
	camp := scnCampaignWithModel(t)
	plan, err := DefaultPlanFromModel(camp, portLensModel(t))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	// low severity: no anchor
	f := scnConfirmedFinding(t, camp, scnOpts{title: "low-sev stub",
		severity: "low"})
	fid := validation.ObjStr(f, "finding_id")
	requireJSON(t, "fid_low", validation.VStr(fid), validation.ObjAt(want, "fid_low"))
	if _, err := findings.Transition(camp, fid, "CONFIRMED",
		"sandbox repro of the stub path", "pytest", "", false); err != nil {
		t.Fatalf("transition CONFIRMED low: %v", err)
	}
	plan2, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	requireJSON(t, "plan_after_low", plan2, validation.ObjAt(want, "plan_after_low"))
	low := scnAnchors(plan2, fid)
	if len(low) != 0 {
		t.Fatalf("low severity added an anchor: %v", low)
	}
	requireJSON(t, "anchors_low", validation.VArr(low...),
		validation.ObjAt(want, "anchors_low"))
	// high severity, confirmed twice via re-save: still one anchor
	f2 := scnConfirmedFinding(t, camp, scnOpts{
		title: "high-sev finalization finding", severity: "high",
		fn: "finalizeBatch"})
	fid2 := validation.ObjStr(f2, "finding_id")
	requireJSON(t, "fid_high", validation.VStr(fid2), validation.ObjAt(want, "fid_high"))
	scnSetAnchorShape(t, camp, fid2, "finalizeBatch", "logic-error",
		"finalization stuck without challenge")
	if _, err := findings.Transition(camp, fid2, "CONFIRMED",
		"sandbox repro: finalization stuck", "pytest", "", false); err != nil {
		t.Fatalf("transition CONFIRMED high: %v", err)
	}
	scnReconfirm(t, camp, fid2)
	plan3, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	requireJSON(t, "plan", plan3, validation.ObjAt(want, "plan"))
	high := scnAnchors(plan3, fid2)
	if len(high) != 1 {
		t.Fatalf("re-confirmed finding must keep exactly 1 anchor, got %d",
			len(high))
	}
	requireJSON(t, "anchors_high", validation.VArr(high...),
		validation.ObjAt(want, "anchors_high"))
}

// TestAnchorDropsNonCanonicalBugClass is
// test_plan_lenses.py::test_anchor_drops_non_canonical_bug_class.
func TestAnchorDropsNonCanonicalBugClass(t *testing.T) {
	want := at(t, scnOracle(t), "anchor_drops_non_canonical_bug_class")
	scnFindingIDs(t)
	camp := scnCampaignWithModel(t)
	plan, err := DefaultPlanFromModel(camp, portLensModel(t))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	if _, ok := taxonomy.KnownClasses()["price-oracle-stale"]; ok {
		t.Fatalf("price-oracle-stale must not be a canonical class")
	}
	if _, err := floors.SetFloorPolicy(camp, "price-oracle-stale", "E4",
		"pytest", "impact fully determined by code semantics"); err != nil {
		t.Fatalf("set_floor_policy: %v", err)
	}
	f := scnConfirmedFinding(t, camp, scnOpts{
		title: "stale price oracle over-mints shares", severity: "high",
		class: "price-oracle-stale"})
	fid := validation.ObjStr(f, "finding_id")
	requireJSON(t, "finding_id", validation.VStr(fid),
		validation.ObjAt(want, "finding_id"))
	scnSetAnchorShape(t, camp, fid, "commitBatch", "price-oracle-stale",
		"price feed never re-read")
	if _, err := findings.Transition(camp, fid, "CONFIRMED",
		"sandbox repro: mint cap priced off a stale feed", "pytest", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	// CONFIRMED is durable — the anchor rescan must neither raise nor leave
	// the transition half-done
	reloaded, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	requireJSON(t, "status", validation.ObjAt(reloaded, "status"),
		validation.ObjAt(want, "status"))
	plan2, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	requireJSON(t, "plan", plan2, validation.ObjAt(want, "plan"))
	anchors := scnAnchors(plan2, fid)
	if len(anchors) != 1 {
		t.Fatalf("expected 1 anchor priority, got %d", len(anchors))
	}
	requireJSON(t, "anchors", validation.VArr(anchors...), validation.ObjAt(want, "anchors"))
	// the advisory class rides in the question text, never in bug_class
	if hasKey(anchors[0], "bug_class") {
		t.Fatalf("non-canonical class leaked into bug_class")
	}
	if !strings.Contains(validation.ObjStr(anchors[0], "question"), "price-oracle-stale") {
		t.Fatalf("question misses the advisory class: %q",
			validation.ObjStr(anchors[0], "question"))
	}
}

// TestDivergenceCountsAReasonlessAnswerAsOpen is
// test_plan_lenses.py::test_divergence_counts_a_reasonless_answer_as_open.
func TestDivergenceCountsAReasonlessAnswerAsOpen(t *testing.T) {
	want := at(t, scnOracle(t),
		"divergence_counts_a_reasonless_answer_as_open")
	scnPinNow(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, portLensModel(t))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	// plan["lenses"][0]["status"] = "answered" — closed without reason/actor
	lenses := listOf(plan, "lenses")
	lenses[0].O = validation.SetOrAppend(lenses[0].O, "status", validation.VStr("answered"))
	plan.O = validation.SetOrAppend(plan.O, "lenses", validation.VArr(lenses...))
	div := DivergenceStatus(plan, DivergenceOpts{})
	requireJSON(t, "div", div, validation.ObjAt(want, "div"))
	requireJSON(t, "closed", validation.ObjAt(div, "closed"), validation.VBool(false))
	subjects := []string{}
	for _, m := range listOf(div, "missing") {
		subjects = append(subjects, validation.ObjStr(m, "subject"))
	}
	if !slices.Contains(subjects, "L-01") {
		t.Fatalf("a reasonless answer must count as open: %v", subjects)
	}
}

// TestDivergenceStatusClosedPlan is
// test_plan_lenses.py::test_divergence_status_closed_plan.
func TestDivergenceStatusClosedPlan(t *testing.T) {
	want := at(t, scnOracle(t), "divergence_status_closed_plan")
	scnPinNow(t)
	camp := portCampaign(t, "Morph L2")
	// FIX-8: the L-04 closure demands the recon stamps on record; the
	// oracle-pinned plan bytes are unaffected by the state-side stamp.
	reconOnRecord(t, camp)
	plan, err := DefaultPlanFromModel(camp, portLensModel(t))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	reason := "single-module fixture; nothing to check here"
	checked := []string{"none-applicable"}
	for _, lid := range []string{"L-01", "L-02", "L-03", "L-04"} {
		plan, err = MarkLens(camp, plan, lid, "not-applicable", LensOpts{
			Reason: &reason, Actor: "pytest", FamiliesChecked: &checked})
		if err != nil {
			t.Fatalf("mark_lens %s: %v", lid, err)
		}
	}
	classes := []string{"reentrancy", "logic-error", "oracle-manipulation",
		"access-control"}
	for i, cls := range classes {
		prios := append(listOf(plan, "priorities"), validation.VObj(
			kv("id", validation.VStr(qid(i+1))),
			kv("question", validation.VStr(fmt.Sprintf(
				"shape %d: canonical bug class named", i+1))),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", validation.StrArr([]string{"code"})),
			kv("status", validation.VStr("open")),
			kv("bug_class", validation.VStr(cls))))
		plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(prios...))
	}
	div := DivergenceStatus(plan, DivergenceOpts{})
	requireJSON(t, "div", div, validation.ObjAt(want, "div"))
	requireJSON(t, "plan", plan, validation.ObjAt(want, "plan"))
	requireJSON(t, "closed", validation.ObjAt(div, "closed"), validation.VBool(true))
	requireJSON(t, "named_classes", validation.ObjAt(div, "named_classes"), jsonValue(t,
		`["access-control","logic-error","oracle-manipulation","reentrancy"]`))
}

// TestDivergenceStatusOpenPlan is
// test_plan_lenses.py::test_divergence_status_open_plan.
func TestDivergenceStatusOpenPlan(t *testing.T) {
	want := at(t, scnOracle(t), "divergence_status_open_plan")
	scnPinNow(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, portLensModel(t))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	div := DivergenceStatus(plan, DivergenceOpts{})
	requireJSON(t, "div", div, validation.ObjAt(want, "div"))
	requireJSON(t, "closed", validation.ObjAt(div, "closed"), validation.VBool(false))
	subjects := map[string]struct{}{}
	for _, m := range listOf(div, "missing") {
		subjects[validation.ObjStr(m, "subject")] = struct{}{}
	}
	for _, lid := range []string{"L-01", "L-02", "L-03", "L-04", "diversity"} {
		if _, ok := subjects[lid]; !ok {
			t.Fatalf("missing[] must name %s: %v", lid, subjects)
		}
	}
	requireJSON(t, "named_classes", validation.ObjAt(div, "named_classes"),
		validation.VArr())
}

// scnGatewayModelArtifact is test_lens_exhaustive._gateway_model_artifact.
func scnGatewayModelArtifact(t *testing.T, camp *state.Campaign) {
	t.Helper()
	model := jsonValue(t, `{"protocol_id":"gw","name":"Gateways",
		"contracts":[
			{"name":"L1ERC20Gateway","path":"contracts/L1ERC20Gateway.sol",
			 "role":"core","in_scope":true,
			 "entry_points":["deposit","finalizeWithdrawal"]},
			{"name":"L1ERC20GatewayReverse",
			 "path":"contracts/L1ERC20GatewayReverse.sol",
			 "role":"core","in_scope":true,
			 "entry_points":["withdraw","drop"]}],
		"actors":[{"id":"sequencer","kind":"EOA"}],
		"assets":[],"relations":[],
		"state_machines":[{"name":"rollup",
			"states":[{"id":"open"}],
			"transitions":[{"from":"open","to":"done",
				"trigger":"withdraw"}]}]}`)
	art := filepath.Join(camp.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(art, model, "protocol_model"); err != nil {
		t.Fatalf("write gateway model: %v", err)
	}
}

// TestConfirmedFindingReopensTheLensWhoseFamilyItHit is
// test_lens_exhaustive.py::test_confirmed_finding_reopens_the_lens_whose_family_it_hit.
// scnReopenPlan is the plan dict of
// test_lens_exhaustive.py::test_confirmed_finding_reopens_the_lens_whose_family_it_hit.
func scnReopenPlan(t *testing.T, camp *state.Campaign) validation.Value {
	t.Helper()
	return validation.VObj(
		kv("campaign_id", validation.VStr(camp.CampaignID)),
		kv("created_at", validation.VStr("2026-09-07T00:00:00Z")),
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-04")),
			kv("lens", validation.VStr("primitive-symmetry")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("status", validation.VStr("answered")),
			kv("families", validation.StrArr([]string{"withdraw", "mint"})),
			kv("families_checked", validation.StrArr([]string{"withdraw", "mint"})),
			kv("closed_reason", validation.VStr("compared both")),
			kv("closed_by", validation.VStr("tester"))))),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", validation.StrArr([]string{"code"})),
			kv("bug_class", validation.VStr("logic-error"))))),
	)
}

func TestConfirmedFindingReopensTheLensWhoseFamilyItHit(t *testing.T) {
	want := at(t, scnOracle(t),
		"confirmed_finding_reopens_the_lens_whose_family_it_hit")
	scnFindingIDs(t)
	camp := portCampaign(t, "Morph L2")
	scnPinNow(t)
	scnGatewayModelArtifact(t, camp)
	if _, err := SavePlan(camp, scnReopenPlan(t, camp)); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	f := scnConfirmedFinding(t, camp, scnOpts{
		title: "gateway withdraw drains the escrow", severity: "high",
		contract: "L1ERC20Gateway", class: "logic-error",
		fn: "finalizeWithdrawal"})
	fid := validation.ObjStr(f, "finding_id")
	requireJSON(t, "finding_id", validation.VStr(fid),
		validation.ObjAt(want, "finding_id"))
	scnRewrite(t, camp, fid, "affected",
		`[{"path":"contracts/L1ERC20Gateway.sol","contract":"L1ERC20Gateway",
		   "function":"finalizeWithdrawal"},
		  {"path":"contracts/L1ERC20GatewayReverse.sol",
		   "contract":"L1ERC20GatewayReverse","function":"withdraw"}]`)
	if _, err := findings.Transition(camp, fid, "CONFIRMED",
		"sandbox repro: withdraw path drains escrow", "pytest", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	planAfter, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	requireJSON(t, "plan", planAfter, validation.ObjAt(want, "plan"))
	reopened := validation.VNull()
	for _, l := range listOf(planAfter, "lenses") {
		if validation.ObjStr(l, "id") == "L-04" {
			reopened = l
		}
	}
	if reopened.Kind != validation.Obj {
		t.Fatalf("L-04 missing from the plan")
	}
	requireJSON(t, "reopened", reopened, validation.ObjAt(want, "reopened"))
	requireJSON(t, "status", validation.ObjAt(reopened, "status"),
		validation.VStr("open"))
	if !strings.Contains(validation.ObjStr(reopened, "reopen_reason"), "withdraw") {
		t.Fatalf("reopen_reason misses the family: %q",
			validation.ObjStr(reopened, "reopen_reason"))
	}
}

// scnAnsweredModel is tests/test_answered.py MODEL.
func scnAnsweredModel(t *testing.T) validation.Value {
	t.Helper()
	return jsonValue(t, `{"protocol_id":"vault","name":"Vault",
		"snapshot_id":"unpinned","chains":["ethereum"],
		"subsystems":["defi-vault"],
		"contracts":[{"name":"Vault","path":"Vault.sol","role":"core",
			"in_scope":true,"entry_points":["deposit"],
			"state_variables":[{"name":"totalAssets","kind":"balance",
				"accounting":true}]}],
		"actors":[{"id":"user","kind":"EOA","trust":"externally-owned"}],
		"assets":[{"id":"share","kind":"share","erc":"4626",
			"decimals":18}],
		"liabilities":[],"privileges":[],
		"trust_boundaries":[{"from":"user","to":"Vault",
			"crossing":"user-supplied token","validated":false}],
		"relations":[],"state_machines":[],"economic_relations":[],
		"invariants":[{"id":"INV-1",
			"statement":"the exchange rate must not move for existing shares",
			"applies_to":["Vault"],"kind":"economic",
			"severity_if_broken":"critical"}],
		"oracles":[]}`)
}

// scnAnsweredCampaign is tests/test_answered.py's `camp` fixture body: init,
// pin the target snapshot and load the protocol model (the orchestrator call
// is spelled out here because orchestrator imports planner).
func scnAnsweredCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	root := t.TempDir()
	camp, err := state.Init(root, "answered", state.InitOpts{
		CampaignID: "C-answered01"})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte("contract Vault { uint256 public totalAssets; }"),
		0o644); err != nil {
		t.Fatalf("write Vault.sol: %v", err)
	}
	if _, err := snapshot.PinSourceSnapshot(camp, target, nil, nil); err != nil {
		t.Fatalf("pin_source_snapshot: %v", err)
	}
	model := scnAnsweredModel(t)
	path, err := protocolgraph.SaveModel(camp, model, "")
	if err != nil {
		t.Fatalf("save_model: %v", err)
	}
	loaded, err := protocolgraph.LoadModel(camp, path)
	if err != nil {
		t.Fatalf("load_model: %v", err)
	}
	if _, err := invariants.SeedFromModel(camp, loaded); err != nil {
		t.Fatalf("seed_from_model: %v", err)
	}
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if len(listOf(plan, "priorities")) == 0 {
		t.Fatalf("bootstrap plan must yield priorities")
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	return camp
}

// TestNotApplicableIsAValidStatus is
// test_answered.py::test_not_applicable_is_a_valid_status: the CLI's library
// call (cmd_answered -> mark_answered with actor="cli"), no CLI dependency.
func TestNotApplicableIsAValidStatus(t *testing.T) {
	want := at(t, scnOracle(t), "not_applicable_is_a_valid_status")
	camp := scnAnsweredCampaign(t)
	plan, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	q := validation.ObjStr(listOf(plan, "priorities")[0], "id")
	requireJSON(t, "qid", validation.VStr(q), validation.ObjAt(want, "qid"))
	reason := "target has no bridge; cross-chain replay cannot apply"
	plan, err = MarkAnswered(camp, plan, q, "not-applicable", AnsweredOpts{
		Reason: &reason, Actor: "cli"})
	if err != nil {
		t.Fatalf("mark_answered: %v", err)
	}
	p := probePriority(t, plan, q)
	requireJSON(t, "priority", p, validation.ObjAt(want, "priority"))
	if n := len(listOf(plan, "priorities")); n != int(at(t, want,
		"priorities").I) {
		t.Fatalf("priorities = %d, want %d", n, at(t, want, "priorities").I)
	}
	// the closure is durable on disk
	onDisk, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load_plan_readonly (disk): %v", err)
	}
	requireJSON(t, "on-disk priority", probePriority(t, onDisk, q),
		validation.ObjAt(want, "on_disk_priority"))
}
