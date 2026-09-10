// Port of tests/test_briefing.py (all 9 test functions). The Python twin was retired 2026-09-09; this package is the source of truth.
//
// DEVIATION (declared, same as the relations/chainengine harnesses): the
// Python `camp` fixture seeds the global memory row by writing the shared
// store's data file directly; the Go harness installs the same row through
// the findings.SetSharedMemoryRows seam. No gate is bypassed.
package briefing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/chainengine"
	"websec/internal/costs"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/learning"
	"websec/internal/pipeline"
	"websec/internal/planner"
	"websec/internal/relations"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

var testPolicy = validation.VObj(
	kv("program", validation.VStr("Acme Protocol Immunefi")),
	kv("program_url", validation.VStr("https://immunefi.com/acme")),
	kv("platform", validation.VStr("immunefi")),
	kv("chains", validation.VArr(validation.VStr("ethereum"))),
	kv("asset_weight_usd", validation.VInt(50_000_000)),
	kv("scope", validation.VArr(validation.VObj(
		kv("target", validation.VStr("Vault")),
		kv("kind", validation.VStr("contract"))))),
	kv("exclusions", validation.VArr()),
	kv("severity_rules", validation.VArr(validation.VObj(
		kv("severity", validation.VStr("critical")),
		kv("match", validation.VObj(
			kv("bug_classes", validation.VArr(validation.VStr("access-control"))),
			kv("require_invariant_violation", validation.VBool(true))))))),
	kv("poc_requirements", validation.VObj(
		kv("min_evidence_level", validation.VStr("E4")),
		kv("require_fork_repro", validation.VBool(false)))),
	kv("reporting", validation.VObj(
		kv("contact", validation.VStr("immunefi")),
		kv("required_fields", validation.VArr(
			validation.VStr("PoC"), validation.VStr("impact"))))))

// newCamp is the test_briefing.camp fixture.
func newCamp(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatalf("pin source snapshot: %v", err)
	}
	return c
}

// hypo is test_briefing.hypo.
func hypo(t *testing.T, c *state.Campaign, class string, granted, required []string,
	title string) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", strArr(granted)),
			kv("required", strArr(required)))),
	), "code", "test", "")
	if err != nil {
		t.Fatalf("ingest hypothesis: %v", err)
	}
	return f
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
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")))
	wrapper := []validation.Value{validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global")))}
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return wrapper, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
	})
}

// confirmSimple is test_briefing.confirm_simple.
func confirmSimple(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+tail(fid))),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")))
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
		t.Fatalf("set critic verdict: %v", err)
	}
	seedGlobalMemory(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("record memory check: %v", err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gate", "", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("reload finding: %v", err)
	}
	return out
}

func tail(id string) string {
	if len(id) <= 6 {
		return id
	}
	return id[len(id)-6:]
}

func build(t *testing.T, c *state.Campaign, deep bool) validation.Value {
	t.Helper()
	b, err := BuildBrief(c, deep, nil)
	if err != nil {
		t.Fatalf("build brief: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// the view discipline
// ---------------------------------------------------------------------------

func TestBriefIsAPureView(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	f := hypo(t, camp, "access-control", []string{"withdraw_unbacked_assets"},
		nil, "Brief view finding one")
	confirmSimple(t, camp, objStr(f, "finding_id"))
	stateBefore, err := os.ReadFile(camp.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	logBefore, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	findingPath := filepath.Join(camp.FindingsDir,
		objStr(f, "finding_id")+".json")
	findingBefore, err := os.ReadFile(findingPath)
	if err != nil {
		t.Fatal(err)
	}

	build(t, camp, true) // even the deep variant

	stateAfter, err := os.ReadFile(camp.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stateAfter) != string(stateBefore) {
		t.Errorf("brief mutated the state file")
	}
	logAfter, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(logAfter) != len(logBefore) {
		t.Errorf("brief logged events: %d -> %d", len(logBefore), len(logAfter))
	}
	findingAfter, err := os.ReadFile(findingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(findingAfter) != string(findingBefore) {
		t.Errorf("brief mutated the finding on disk")
	}
	// the gate ran with save=False: the finding on disk gained no bounty block
	reloaded, err := findings.LoadFinding(camp, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if hasKey(reloaded, "bounty") {
		t.Errorf("the view wrote a bounty block: %s",
			validation.DumpIndented(objAt(reloaded, "bounty")))
	}
}

// TestBriefStageCountIgnoresSubStages pins feedback-triage A5: the stage
// ledger carries sub-stage rows (discovery-specialist, hypothesis-triage,
// ...) that are not among the canonical pipeline stages. The cockpit's
// "stages N/M" must count the top-level set on both sides — before the fix
// a campaign with all 17 stages done plus two done sub-stages reported
// "stages 19/17".
func TestBriefStageCountIgnoresSubStages(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	for _, id := range pipeline.StageIDs {
		if err := camp.SetStage(id, "done", validation.VNull(), nil); err != nil {
			t.Fatalf("set stage %s: %v", id, err)
		}
	}
	for _, sub := range []string{"discovery-specialist", "hypothesis-triage"} {
		if err := camp.SetStage(sub, "done", validation.VNull(), nil); err != nil {
			t.Fatalf("set sub-stage %s: %v", sub, err)
		}
	}
	b := build(t, camp, false)
	campSec := objAt(b, "campaign")
	done := intField(campSec, "stages_done")
	total := intField(campSec, "stages_total")
	if done != int64(len(pipeline.StageIDs)) ||
		total != int64(len(pipeline.StageIDs)) {
		t.Fatalf("stages %d/%d, want %d/%d (sub-stages excluded)",
			done, total, len(pipeline.StageIDs), len(pipeline.StageIDs))
	}
}

func TestBriefJSONRoundtrip(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	f := hypo(t, camp, "access-control", []string{"withdraw_unbacked_assets"},
		nil, "Brief json finding")
	confirmSimple(t, camp, objStr(f, "finding_id"))
	b := build(t, camp, false)
	dumped := validation.DumpIndented(b) // must be plain JSON-safe types
	back, err := validation.ParseOrdered([]byte(dumped))
	if err != nil {
		t.Fatalf("json roundtrip: %v", err)
	}
	if objStr(objAt(back, "campaign"), "campaign_id") !=
		objStr(objAt(b, "campaign"), "campaign_id") {
		t.Errorf("campaign_id changed across the roundtrip")
	}
	if !hasKey(back, "next_actions") {
		t.Errorf("next_actions missing from the roundtripped brief")
	}
}

func TestBriefEmptyCampaignDoesNotCrash(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Empty Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	b := build(t, c, false)
	if got := intField(objAt(b, "findings"), "total"); got != 0 {
		t.Errorf("findings.total = %d, want 0", got)
	}
	if v := objAt(objAt(b, "campaign"), "active_snapshot"); v.Kind != validation.Null {
		t.Errorf("active_snapshot = %s, want None", validation.PyRepr(v))
	}
	actions := listAt(b, "next_actions")
	if len(actions) == 0 {
		t.Fatalf("an empty campaign still says what to do next")
	}
	found := false
	for _, a := range actions {
		if a.Kind == validation.Str && stringsContains(a.S, "scope") {
			found = true
		}
	}
	if !found {
		t.Errorf("no next action mentions scope: %s", validation.DumpIndented(b))
	}
}

// ---------------------------------------------------------------------------
// the synthesis
// ---------------------------------------------------------------------------

func TestBriefFlagsAMaterializableChain(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	f1 := hypo(t, camp, "access-control", []string{"control_perceived_asset_price"},
		nil, "Brief chain step one")
	f2 := hypo(t, camp, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price"}, "Brief chain step two")
	confirmSimple(t, camp, objStr(f1, "finding_id"))
	confirmSimple(t, camp, objStr(f2, "finding_id"))

	b := build(t, camp, false)
	mats := listAt(objAt(b, "findings"), "materializable_chains")
	if len(mats) != 1 {
		t.Fatalf("materializable_chains = %d, want 1", len(mats))
	}
	members := strListOf(objAt(mats[0], "members"))
	want := map[string]bool{objStr(f1, "finding_id"): true,
		objStr(f2, "finding_id"): true}
	if len(members) != 2 || !want[members[0]] || !want[members[1]] {
		t.Errorf("members = %v, want the two findings", members)
	}
	found := false
	for _, a := range listAt(b, "next_actions") {
		if a.Kind == validation.Str && stringsContains(a.S, "materialize chain") &&
			stringsContains(a.S, objStr(f2, "finding_id")) {
			found = true
		}
	}
	if !found {
		t.Errorf("no materialize-chain action in %v",
			validation.PyRepr(objAt(b, "next_actions")))
	}

	// once materialized, it is no longer materializable
	if _, err := chainengine.MaterializeChain(camp, []string{
		objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"Brief two-step chain", "", nil, nil); err != nil {
		t.Fatalf("materialize chain: %v", err)
	}
	b2 := build(t, camp, false)
	if got := len(listAt(objAt(b2, "findings"), "materializable_chains")); got != 0 {
		t.Errorf("materializable_chains after materialize = %d, want 0", got)
	}
}

func TestBriefListsTheE6QueueAndGateDeficits(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	c1 := objStr(confirmSimple(t, camp, objStr(hypo(t, camp, "access-control",
		[]string{"withdraw_unbacked_assets"}, nil,
		"Brief E6 queue finding"), "finding_id")), "finding_id")
	// an alive, unconfirmed finding: the deficit names what is missing
	p := hypo(t, camp, "logic-error", []string{"some_capability"}, nil,
		"Brief deficit finding")
	if _, err := findings.Transition(camp, objStr(p, "finding_id"), "POSSIBLE",
		"triage", "triage", "", false); err != nil {
		t.Fatalf("transition: %v", err)
	}

	b := build(t, camp, false)
	queue := listAt(b, "independent_verification_queue")
	foundC1 := false
	for _, x := range queue {
		if objStr(x, "finding_id") == c1 {
			foundC1 = true
			if got := objStr(x, "evidence_level"); got != "E4" {
				t.Errorf("queue evidence_level = %s, want E4", got)
			}
		}
	}
	if !foundC1 {
		t.Errorf("%s missing from the E6 queue", c1)
	}
	foundAction := false
	for _, a := range listAt(b, "next_actions") {
		if a.Kind == validation.Str &&
			stringsContains(a.S, "independently verify") &&
			stringsContains(a.S, c1) {
			foundAction = true
		}
	}
	if !foundAction {
		t.Errorf("no independently-verify action for %s", c1)
	}

	deficits := listAt(objAt(b, "findings"), "gate_deficits")
	foundP := false
	for _, d := range deficits {
		if objStr(d, "finding_id") == objStr(p, "finding_id") {
			foundP = true
			if objStr(d, "deficit") == "" {
				t.Errorf("bare E0 finding has an empty deficit")
			}
		}
	}
	if !foundP {
		t.Errorf("%s missing from gate_deficits", objStr(p, "finding_id"))
	}
}

func TestBriefBountyGateIsAView(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if _, err := bounty.SavePolicy(camp, testPolicy, &policyPath); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	doc, err := validation.ReadJson(camp.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(policyPath))
	if err := validation.WriteJson(camp.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}

	f := confirmSimple(t, camp, objStr(hypo(t, camp, "access-control",
		[]string{"withdraw_unbacked_assets"}, nil,
		"Brief gate finding"), "finding_id"))
	b := build(t, camp, false)
	if got := objStr(objAt(b, "bounty"), "policy"); got != "policy.json" {
		t.Errorf("bounty.policy = %q, want policy.json", got)
	}
	ev := map[string]validation.Value{}
	for _, x := range listAt(objAt(b, "bounty"), "evaluated") {
		ev[objStr(x, "finding_id")] = x
	}
	entry, ok := ev[objStr(f, "finding_id")]
	if !ok {
		t.Fatalf("%s missing from bounty.evaluated", objStr(f, "finding_id"))
	}
	if !objBool(entry, "eligible") {
		t.Errorf("eligible = false, want true")
	}
	if objBool(entry, "submission_ready") {
		t.Errorf("submission_ready = true, want false")
	}
	if len(listAt(entry, "blocking_reasons")) == 0 {
		t.Errorf("blocking_reasons is empty")
	}
}

func TestBriefPendingMemoryAndRelations(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	f := hypo(t, camp, "access-control", []string{"withdraw_unbacked_assets"},
		nil, "Brief memory finding")
	confirmSimple(t, camp, objStr(f, "finding_id"))
	fid := objStr(f, "finding_id")
	if _, err := learning.QueueMemory(camp, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern:   "brief pattern that is intended behavior",
		FindingID: &fid}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	if _, err := relations.MintDisprovedBy(camp, objStr(f, "finding_id"),
		nil, nil); err != nil {
		t.Fatalf("mint disproved_by: %v", err)
	}

	b := build(t, camp, false)
	foundPending := false
	for _, m := range listAt(b, "pending_memory") {
		if objStr(m, "finding_id") == objStr(f, "finding_id") {
			foundPending = true
		}
	}
	if !foundPending {
		t.Errorf("pending_memory lacks %s", objStr(f, "finding_id"))
	}
	foundAction := false
	for _, a := range listAt(b, "next_actions") {
		if a.Kind == validation.Str && stringsContains(a.S, "human decision") {
			foundAction = true
		}
	}
	if !foundAction {
		t.Errorf("no human-decision action in next_actions")
	}
	rel := objAt(b, "relations")
	if got := intField(objAt(rel, "by_kind"), "disproved_by"); got != 1 {
		t.Errorf("relations.by_kind.disproved_by = %d, want 1", got)
	}
	if got := len(listAt(rel, "drift_problems")); got != 0 {
		t.Errorf("relations.drift_problems = %d, want 0", got)
	}
}

func TestBriefDeepFoldsInTheAudit(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	f := hypo(t, camp, "access-control", []string{"withdraw_unbacked_assets"},
		nil, "Brief deep finding")
	confirmSimple(t, camp, objStr(f, "finding_id"))
	fast := build(t, camp, false)
	fastInteg := objAt(fast, "integrity")
	if !objBool(fastInteg, "ok") {
		t.Errorf("fast integrity.ok = %s, want True",
			validation.PyRepr(objAt(fastInteg, "ok")))
	}
	if intField(fastInteg, "events_checked") < 1 {
		t.Errorf("fast integrity.events_checked = %d, want >= 1",
			intField(fastInteg, "events_checked"))
	}
	deep := build(t, camp, true)
	deepInteg := objAt(deep, "integrity")
	if !objBool(deepInteg, "ok") {
		t.Errorf("deep integrity.ok = %s, want True",
			validation.PyRepr(objAt(deepInteg, "ok")))
	}
	if !stringsContains(objStr(deepInteg, "summary"), "audit") {
		t.Errorf("deep integrity.summary = %q, want it to mention audit",
			objStr(deepInteg, "summary"))
	}
}

func TestBriefTerminalAndEconomicsSections(t *testing.T) {
	camp := newCamp(t, "Acme Program")
	confirmSimple(t, camp, objStr(hypo(t, camp, "access-control",
		[]string{"withdraw_unbacked_assets"}, nil,
		"Brief terminal finding"), "finding_id"))
	traj := "code"
	if _, err := costs.RecordCost(camp, costs.RecordOpts{Kind: "model",
		AmountUSD: 10.0, Trajectory: &traj, Actor: "harness"}); err != nil {
		t.Fatalf("record cost: %v", err)
	}

	b := build(t, camp, false)
	foundTerminal := false
	for _, term := range listAt(b, "terminals") {
		if objStr(term, "terminal_capability") == "withdraw_unbacked_assets" {
			foundTerminal = true
		}
	}
	if !foundTerminal {
		t.Errorf("no withdraw_unbacked_assets terminal: %s",
			validation.PyRepr(objAt(b, "terminals")))
	}
	foundAction := false
	for _, a := range listAt(b, "next_actions") {
		if a.Kind == validation.Str && stringsContains(a.S,
			"terminal state reachable") {
			foundAction = true
		}
	}
	if !foundAction {
		t.Errorf("no terminal-state action in next_actions")
	}
	totals := objAt(objAt(b, "economics"), "totals")
	if got := floatOf(objAt(totals, "total_cost_usd")); got != 10.0 {
		t.Errorf("total_cost_usd = %v, want 10.0", got)
	}
	if got := floatOf(objAt(totals, "yield_usd_per_usd")); got != 0.0 {
		t.Errorf("yield_usd_per_usd = %v, want 0.0", got)
	}
}

func stringsContains(haystack, needle string) bool {
	return len(needle) == 0 || indexOfStr(haystack, needle) >= 0
}

func indexOfStr(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// test_briefing_memory.py (the 3 non-CLI functions)
// ---------------------------------------------------------------------------

// oneGateFromConfirmed is test_briefing_memory.one_gate_from_confirmed.
func oneGateFromConfirmed(t *testing.T, camp *state.Campaign) validation.Value {
	t.Helper()
	f := hypo(t, camp, "access-control", nil, nil,
		"vault drain via unguarded sweep")
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(camp, fid, "POSSIBLE", "triage",
		"triage", "", false); err != nil {
		t.Fatalf("transition: %v", err)
	}
	rec, err := sandbox.RegisterExec(camp, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")))
	if _, err := findings.AddEvidence(camp, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(camp, fid, "confirmed", "ok"); err != nil {
		t.Fatalf("set critic verdict: %v", err)
	}
	vf, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(camp, &vf); err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBriefingKeyIsMemoryRecallPending(t *testing.T) {
	camp := newCamp(t, "test-program")
	f := oneGateFromConfirmed(t, camp)
	b := build(t, camp, false)
	findingsBlock := objAt(b, "findings")
	if !hasKey(findingsBlock, "memory_recall_pending") {
		t.Fatalf("memory_recall_pending missing from findings block")
	}
	listed := false
	for _, fid := range strListOf(objAt(findingsBlock, "memory_recall_pending")) {
		if fid == objStr(f, "finding_id") {
			listed = true
		}
	}
	if !listed {
		t.Errorf("%s missing from memory_recall_pending",
			objStr(f, "finding_id"))
	}
	if hasKey(findingsBlock, "negative_rag_pending") {
		t.Errorf("the retired negative_rag_pending key is still present")
	}
}

func TestBriefingWordingNamesTheAction(t *testing.T) {
	camp := newCamp(t, "test-program")
	f := oneGateFromConfirmed(t, camp)
	b := build(t, camp, false)
	found := false
	for _, a := range listAt(b, "next_actions") {
		if a.Kind != validation.Str {
			continue
		}
		if stringsContains(a.S, objStr(f, "finding_id")) &&
			stringsContains(a.S, "memory recall pending") &&
			stringsContains(a.S, "webv2 recall") {
			found = true
		}
	}
	if !found {
		t.Errorf("no recall wording in next_actions: %s",
			validation.PyRepr(objAt(b, "next_actions")))
	}
	recall := 0
	for _, a := range objStringList(t, b, "next_actions") {
		if stringsContains(a, "memory recall pending") {
			recall++
		}
		if stringsContains(a, "negative-mode RAG") {
			t.Errorf("the retired RAG check is still suggested: %q", a)
		}
	}
	if recall != 1 {
		t.Errorf("recall actions = %d, want exactly 1", recall)
	}
}

func TestVerifiedCheckClearsThePendingFlag(t *testing.T) {
	camp := newCamp(t, "test-program")
	f := oneGateFromConfirmed(t, camp)
	seedGlobalMemory(t)
	if _, err := findings.RecordMemoryCheck(camp, objStr(f, "finding_id"),
		[]validation.Value{validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("record memory check: %v", err)
	}
	b := build(t, camp, false)
	for _, fid := range strListOf(objAt(objAt(b, "findings"),
		"memory_recall_pending")) {
		if fid == objStr(f, "finding_id") {
			t.Errorf("%s still pending after a verified check",
				objStr(f, "finding_id"))
		}
	}
	if got := len(listAt(objAt(b, "findings"), "memory_recall_pending")); got != 0 {
		t.Errorf("memory_recall_pending = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// test_noop_reporting.py — the brief half (B5b/D6)
// ---------------------------------------------------------------------------

// hypoWithStatus is test_noop_reporting.hypo.
func hypoWithStatus(t *testing.T, camp *state.Campaign, title, class,
	status string) validation.Value {
	t.Helper()
	f := hypo(t, camp, class, []string{"withdraw_unbacked_assets"}, nil, title)
	if status != "" {
		if _, err := findings.Transition(camp, objStr(f, "finding_id"),
			status, "test fixture", "test fixture", "", false); err != nil {
			t.Fatalf("transition %s: %v", status, err)
		}
	}
	out, err := findings.LoadFinding(camp, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func problemsContain(t *testing.T, b validation.Value, needle string) bool {
	t.Helper()
	for _, p := range listAt(b, "problems") {
		if p.Kind == validation.Str && stringsContains(p.S, needle) {
			return true
		}
	}
	return false
}

func TestBriefProblemsNamesTheUnwrittenGraph(t *testing.T) {
	camp := newCamp(t, "noop-program")
	hypoWithStatus(t, camp, "unwritten graph finding", "access-control", "")
	b := build(t, camp, false)
	if got := intField(objAt(b, "relations"), "edge_count"); got != 0 {
		t.Errorf("edge_count = %d, want 0", got)
	}
	found := false
	for _, p := range listAt(b, "problems") {
		if p.Kind == validation.Str && stringsContains(p.S,
			"graph was never written") {
			found = true
			if !stringsContains(p.S, "webv2 relations "+camp.CampaignID+
				" --rebuild") {
				t.Errorf("problem line lacks the rebuild command: %s", p.S)
			}
		}
	}
	if !found {
		t.Errorf("no unwritten-graph problem line: %s",
			validation.PyRepr(objAt(b, "problems")))
	}
}

func TestBriefHasNoProblemLineWithoutFindings(t *testing.T) {
	c, err := state.Init(t.TempDir(), "empty-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	b := build(t, c, false)
	if got := intField(objAt(b, "findings"), "total"); got != 0 {
		t.Errorf("findings.total = %d, want 0", got)
	}
	if got := len(listAt(b, "problems")); got != 0 {
		t.Errorf("problems = %d, want 0", got)
	}
}

func TestBriefHasNoProblemLineWhenTheGraphHasEdges(t *testing.T) {
	camp := newCamp(t, "noop-program")
	a := hypoWithStatus(t, camp, "edge finding one", "access-control", "")
	b := hypoWithStatus(t, camp, "edge finding two", "access-control", "")
	if _, err := relations.MintCausation(camp, objStr(a, "finding_id"),
		objStr(b, "finding_id"), "operator", "attested"); err != nil {
		t.Fatalf("mint causation: %v", err)
	}
	brief := build(t, camp, false)
	if got := intField(objAt(brief, "relations"), "edge_count"); got != 1 {
		t.Errorf("edge_count = %d, want 1", got)
	}
	if problemsContain(t, brief, "graph was never written") {
		t.Errorf("closed graph still reports the unwritten-graph problem")
	}
}

func TestBriefHasNoProblemLineOnAClosedCampaign(t *testing.T) {
	camp := newCamp(t, "noop-program")
	hypoWithStatus(t, camp, "closed campaign finding", "access-control", "")
	if _, err := camp.Complete("alice", "pass closed: report generated, "+
		"findings filed"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	b := build(t, camp, false)
	if !objBool(objAt(b, "campaign"), "closed") {
		t.Errorf("campaign.closed = false, want true")
	}
	if got := intField(objAt(b, "relations"), "edge_count"); got != 0 {
		t.Errorf("edge_count = %d, want 0", got)
	}
	if problemsContain(t, b, "graph was never written") {
		t.Errorf("closed campaign reports the unwritten-graph problem")
	}
}

func TestBriefHasNoProblemLineWhenOnlyJunkFindingsExist(t *testing.T) {
	camp := newCamp(t, "noop-program")
	hypoWithStatus(t, camp, "duplicate finding", "access-control", "DUPLICATE")
	b := build(t, camp, false)
	if got := intField(objAt(b, "findings"), "total"); got != 1 {
		t.Errorf("findings.total = %d, want 1", got)
	}
	if problemsContain(t, b, "graph was never written") {
		t.Errorf("junk-only campaign reports the unwritten-graph problem")
	}
}

// ---------------------------------------------------------------------------
// test_attention_ledger.py — the ledger half (B4/D7)
// ---------------------------------------------------------------------------

const (
	ledgerNow = "2026-09-08T12:00:00+00:00"
	planT0    = "2026-09-08T08:48:00+00:00" // NOW - 3h12m
)

// prioOpts is the `**over` of test_attention_ledger._prio.
type prioOpts struct {
	status       string
	t0           *string
	invariantIDs []string
	probe        *validation.Value
}

// prio is test_attention_ledger._prio.
func prio(i int, o prioOpts) validation.Value {
	status := o.status
	if status == "" {
		status = "open"
	}
	kvs := []validation.KV{
		kv("id", validation.VStr(pyID("Q-", i))),
		kv("question", validation.VStr(fmtQuestion(i))),
		kv("risk", validation.VFloat(0.5)),
		kv("components", validation.VArr(validation.VStr("Vault"))),
		kv("trajectories", validation.VArr(validation.VStr("code"))),
		kv("status", validation.VStr(status)),
	}
	if o.t0 != nil {
		kvs = append(kvs, kv("created_at", validation.VStr(*o.t0)))
	}
	if len(o.invariantIDs) > 0 {
		kvs = append(kvs, kv("invariant_ids", strArr(o.invariantIDs)))
	}
	if o.probe != nil {
		kvs = append(kvs, kv("probe", *o.probe))
	}
	return validation.VObj(kvs...)
}

func pyID(prefix string, i int) string {
	if i < 10 {
		return prefix + "00" + itoa(i)
	}
	if i < 100 {
		return prefix + "0" + itoa(i)
	}
	return prefix + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}

func fmtQuestion(i int) string {
	return "Does invariant " + itoa(i) +
		" hold under the vault's conditions?"
}

// probePrio is test_attention_ledger._probe_prio.
func probePrio(i int, o prioOpts) validation.Value {
	p := validation.VObj(
		kv("row_id", validation.VStr("a1b2c3d4e5")),
		kv("probe_id", validation.VStr("assertion-strength")),
		kv("axis", validation.VStr("L-01")),
		kv("surface_sha", validation.VStr("deadbeefdeadbeef")),
		kv("shape_sha", validation.VStr("0123456789abcdef")))
	o.probe = &p
	return prio(i, o)
}

// writePlan is test_attention_ledger._write_plan.
func writePlan(t *testing.T, camp *state.Campaign,
	priorities []validation.Value, createdAt string, lenses []validation.Value,
	validate bool) validation.Value {
	t.Helper()
	if createdAt == "" {
		createdAt = planT0
	}
	if lenses == nil {
		lenses = []validation.Value{}
	}
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(camp.CampaignID)),
		kv("created_at", validation.VStr(createdAt)),
		kv("strategy_note", validation.VStr("attention-ledger fixture")),
		kv("priorities", validation.VArr(priorities...)),
		kv("lenses", validation.VArr(lenses...)),
		kv("trajectory_matrix", validation.VObj()),
		kv("coverage_targets", validation.VObj()))
	if validate {
		if _, err := planner.ValidatePlan(camp, plan); err != nil {
			t.Fatalf("validate plan: %v", err)
		}
	}
	// Python's write_json is schema-less; the fixture's write-time checks are
	// the explicit planner.ValidatePlan call above.
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return plan
}

// inv is test_attention_ledger._inv.
func inv(t *testing.T, camp *state.Campaign, iid, kind, severity, status,
	updatedAt string) {
	t.Helper()
	if kind == "" {
		kind = "security"
	}
	if severity == "" {
		severity = "high"
	}
	if status == "" {
		status = "UNVERIFIED"
	}
	if updatedAt == "" {
		updatedAt = planT0
	}
	links, err := invariants.LoadLinks(camp)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	if reg.Kind != validation.Obj {
		reg = validation.VObj()
	}
	reg.O = validation.SetOrAppend(reg.O, iid, validation.VObj(
		kv("statement", validation.VStr(iid+" statement")),
		kv("kind", validation.VStr(kind)),
		kv("severity_if_broken", validation.VStr(severity)),
		kv("applies_to", validation.VArr(validation.VStr("Vault"))),
		kv("test_status", validation.VStr("untested")),
		kv("status", validation.VStr(status)),
		kv("source", validation.VStr("model")),
		kv("model_belief", validation.VNull()),
		kv("depends_on", validation.VArr()),
		kv("modified_by", validation.VNull()),
		kv("findings", validation.VArr()),
		kv("tests", validation.VArr()),
		kv("detectors", validation.VArr()),
		kv("updated_at", validation.VStr(updatedAt))))
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(camp, links); err != nil {
		t.Fatal(err)
	}
}

// ledger is test_attention_ledger._ledger.
func ledger(t *testing.T, camp *state.Campaign) (validation.Value, validation.Value) {
	t.Helper()
	now := ledgerNow
	b, err := BuildBrief(camp, false, &now)
	if err != nil {
		t.Fatalf("build brief: %v", err)
	}
	return b, objAt(b, "attention")
}

func attQueue(t *testing.T, att validation.Value) validation.Value {
	t.Helper()
	return objAt(att, "queue")
}

func attInvariants(t *testing.T, att validation.Value) validation.Value {
	t.Helper()
	return objAt(att, "invariants")
}

func objStringList(t *testing.T, v validation.Value, key string) []string {
	t.Helper()
	out := []string{}
	for _, x := range listAt(v, key) {
		if x.Kind == validation.Str {
			out = append(out, x.S)
		}
	}
	return out
}

func TestQueueDebtLineShapeAndCommand(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	priorities := []validation.Value{}
	for i := 1; i < 59; i++ {
		switch {
		case i <= 4:
			priorities = append(priorities, prio(i, prioOpts{status: "answered"}))
		case i == 5:
			priorities = append(priorities, prio(i,
				prioOpts{invariantIDs: []string{"INV-1"}}))
		default:
			priorities = append(priorities, prio(i, prioOpts{}))
		}
	}
	writePlan(t, camp, priorities, "", nil, true)
	inv(t, camp, "INV-1", "", "critical", "", "")

	_, att := ledger(t, camp)
	q := attQueue(t, att)
	if objInt(q, "worked") != 4 || objInt(q, "total") != 58 ||
		objInt(q, "untouched") != 54 {
		t.Errorf("(worked, total, untouched) = (%d, %d, %d), want (4, 58, 54)",
			objInt(q, "worked"), objInt(q, "total"), objInt(q, "untouched"))
	}
	oldest := objAt(q, "oldest")
	if objStr(oldest, "priority_id") != "Q-005" {
		t.Errorf("oldest = %q, want Q-005", objStr(oldest, "priority_id"))
	}
	if objStr(oldest, "age") != "3h12m" {
		t.Errorf("age = %q, want 3h12m", objStr(oldest, "age"))
	}
	cmd := "webv2 answered " + camp.CampaignID +
		" Q-005 answered --reason R --actor A"
	wantLine := "questions worked 4/58 — oldest untouched: Q-005 " +
		"(3h12m, INV-1 critical) — " + cmd
	if objStr(q, "line") != wantLine {
		t.Errorf("line = %q\nwant %q", objStr(q, "line"), wantLine)
	}
	if objStr(oldest, "command") != cmd {
		t.Errorf("command = %q, want %q", objStr(oldest, "command"), cmd)
	}
	found := false
	for _, l := range objStringList(t, att, "lines") {
		if l == objStr(q, "line") {
			found = true
		}
	}
	if !found {
		t.Errorf("queue line missing from attention.lines")
	}
}

func TestOldestUntouchedTiesBreakOnTheLowestID(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	plan := writePlan(t, camp, []validation.Value{
		prio(1, prioOpts{status: "answered"}), prio(7, prioOpts{}),
		prio(3, prioOpts{}), prio(5, prioOpts{})}, "", nil, false)
	if _, err := planner.ValidatePlan(camp, plan); err != nil {
		t.Fatalf("fixture must be writable as-is: %v", err)
	}
	for _, p := range listAt(plan, "priorities") {
		if hasKey(p, "created_at") {
			t.Errorf("fixture carries a forbidden created_at")
		}
	}
	_, att := ledger(t, camp)
	if got := objStr(objAt(attQueue(t, att), "oldest"),
		"priority_id"); got != "Q-003" {
		t.Errorf("oldest = %q, want Q-003", got)
	}
}

func TestAFuturePerPriorityTimestampWouldBeatThePlanClock(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	t0a, t0b := "2026-09-08T10:00:00+00:00", "2026-09-08T11:00:00+00:00"
	writePlan(t, camp, []validation.Value{
		prio(2, prioOpts{t0: &t0a}), prio(1, prioOpts{t0: &t0b})},
		"", nil, false)
	_, att := ledger(t, camp)
	oldest := objAt(attQueue(t, att), "oldest")
	if got := objStr(oldest, "priority_id"); got != "Q-002" {
		t.Errorf("oldest = %q, want Q-002", got)
	}
	// the per-priority stamp is what the age is measured against
	if got := objStr(oldest, "age"); got != "2h0m" {
		t.Errorf("age = %q, want 2h0m (the per-priority stamp)", got)
	}
}

func TestProbeRowQueueCommandCarriesTheRequiredAnchorFlag(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{probePrio(1, prioOpts{})},
		"", nil, true)
	_, att := ledger(t, camp)
	q := attQueue(t, att)
	cmd := "webv2 answered " + camp.CampaignID + " Q-001 answered " +
		"--reason R --actor A --anchor FIELD"
	if objStr(objAt(q, "oldest"), "command") != cmd {
		t.Errorf("command = %q, want %q",
			objStr(objAt(q, "oldest"), "command"), cmd)
	}
	if !stringsHasSuffix(objStr(q, "line"), cmd) {
		t.Errorf("line does not end with the command: %q", objStr(q, "line"))
	}
	if !stringsHasSuffix(objStr(objAt(q, "oldest"), "action"), cmd) {
		t.Errorf("action does not end with the command: %q",
			objStr(objAt(q, "oldest"), "action"))
	}
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestInvariantDebtLineShapeAndCommand(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1, prioOpts{status: "answered"})},
		"", nil, true)
	inv(t, camp, "INV-008", "liveness", "critical", "", "")
	inv(t, camp, "INV-002", "", "low", "", "2026-09-01T00:00:00+00:00")
	inv(t, camp, "INV-003", "", "", "CHECKED_AGAINST_CODE", "")

	_, att := ledger(t, camp)
	iv := attInvariants(t, att)
	if objInt(iv, "total") != 3 || objInt(iv, "unverified") != 2 ||
		objInt(iv, "high_consequence") != 1 {
		t.Errorf("(total, unverified, high_consequence) = (%d, %d, %d), "+
			"want (3, 2, 1)", objInt(iv, "total"), objInt(iv, "unverified"),
			objInt(iv, "high_consequence"))
	}
	cmd := "webv2 invariant-verify " + camp.CampaignID + " INV-008 --exec EXEC-*"
	wantLine := "invariants: 2 UNVERIFIED (liveness/critical first, with age) " +
		"— verify INV-008 (unverified 3h12m): " + cmd
	if objStr(iv, "line") != wantLine {
		t.Errorf("line = %q\nwant %q", objStr(iv, "line"), wantLine)
	}
	items := listAt(iv, "items")
	if len(items) < 2 {
		t.Fatalf("items = %d, want >= 2", len(items))
	}
	if objStr(items[0], "invariant_id") != "INV-008" {
		t.Errorf("items[0] = %q, want INV-008", objStr(items[0], "invariant_id"))
	}
	if objStr(items[0], "line") != "verify INV-008 (unverified 3h12m): "+cmd {
		t.Errorf("items[0].line = %q", objStr(items[0], "line"))
	}
	if objStr(items[1], "invariant_id") != "INV-002" {
		t.Errorf("items[1] = %q, want INV-002", objStr(items[1], "invariant_id"))
	}
	if objBool(items[1], "high_consequence") {
		t.Errorf("items[1].high_consequence = true, want false")
	}
}

func TestInvariantTotalCountsOnlyDictEntries(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1, prioOpts{status: "answered"})},
		"", nil, true)
	inv(t, camp, "INV-008", "liveness", "critical", "", "")
	links, err := invariants.LoadLinks(camp)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	reg.O = validation.SetOrAppend(reg.O, "INV-BROKEN", validation.VStr("not an entry"))
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(camp, links); err != nil {
		t.Fatal(err)
	}
	_, att := ledger(t, camp)
	if got := objInt(attInvariants(t, att), "total"); got != 1 {
		t.Errorf("total = %d, want 1", got)
	}
	if got := objInt(attInvariants(t, att), "unverified"); got != 1 {
		t.Errorf("unverified = %d, want 1", got)
	}
}

// TestContradictedModelInvariantIsNotUnverified (B3): a CONTRADICTED model
// invariant is a CONFIRMING verdict (the invariant is falsified by code — the
// attack works), so ChInvariants must not list it under unverified_model. An
// UNVERIFIED model invariant must still be listed.
func TestContradictedModelInvariantIsNotUnverified(t *testing.T) {
	camp := newCamp(t, "Contradicted Model")
	inv(t, camp, "INV-CONTRA", "security", "critical", "CONTRADICTED", "")
	inv(t, camp, "INV-UNVER", "security", "high", "UNVERIFIED", "")
	inv(t, camp, "INV-CHK", "security", "high", "CHECKED_AGAINST_CODE", "")
	problems := []string{}
	section := ChInvariants(camp, &problems)
	var unverified []string
	for _, v := range listAt(section, "unverified_model") {
		if v.Kind == validation.Str {
			unverified = append(unverified, v.S)
		}
	}
	has := func(id string) bool {
		for _, u := range unverified {
			if u == id {
				return true
			}
		}
		return false
	}
	if has("INV-CONTRA") {
		t.Errorf("unverified_model = %v; a CONTRADICTED model invariant is "+
			"confirming and must not be listed", unverified)
	}
	if has("INV-CHK") {
		t.Errorf("unverified_model = %v; a CHECKED_AGAINST_CODE invariant "+
			"must not be listed", unverified)
	}
	if !has("INV-UNVER") {
		t.Errorf("unverified_model = %v; an UNVERIFIED model invariant "+
			"must be listed", unverified)
	}
}

func TestNoDebtLinesWhenNothingIsUntouched(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{
		prio(1, prioOpts{status: "answered"}),
		prio(2, prioOpts{status: "not-applicable"}),
		prio(3, prioOpts{status: "deprioritized"}),
		prio(4, prioOpts{status: "answered"})}, "", nil, true)
	inv(t, camp, "INV-1", "", "", "CHECKED_AGAINST_CODE", "")
	b, att := ledger(t, camp)
	if got := len(listAt(att, "lines")); got != 0 {
		t.Errorf("lines = %d, want 0", got)
	}
	if v := objAt(attQueue(t, att), "line"); v.Kind != validation.Null {
		t.Errorf("queue.line = %s, want None", validation.PyRepr(v))
	}
	if got := objInt(attQueue(t, att), "worked"); got != 4 {
		t.Errorf("queue.worked = %d, want 4", got)
	}
	if v := objAt(attInvariants(t, att), "line"); v.Kind != validation.Null {
		t.Errorf("invariants.line = %s, want None", validation.PyRepr(v))
	}
	if got := objInt(attInvariants(t, att), "unverified"); got != 0 {
		t.Errorf("invariants.unverified = %d, want 0", got)
	}
	if got := len(listAt(att, "ranked")); got != 0 {
		t.Errorf("ranked = %d, want 0", got)
	}
	_ = b
}

func TestBlockedIsNotADisposition(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{
		prio(1, prioOpts{status: "answered"}),
		prio(4, prioOpts{status: "blocked"})}, "", nil, true)
	_, att := ledger(t, camp)
	q := attQueue(t, att)
	if got := objInt(q, "worked"); got != 1 {
		t.Errorf("worked = %d, want 1", got)
	}
	if got := objStr(objAt(q, "oldest"), "priority_id"); got != "Q-004" {
		t.Errorf("oldest = %q, want Q-004", got)
	}
	if !stringsHasPrefix(objStr(q, "line"),
		"questions worked 1/2 — oldest untouched: Q-004 (3h12m)") {
		t.Errorf("line = %q", objStr(q, "line"))
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestAgeFormatBranches(t *testing.T) {
	cases := []struct {
		seconds  float64
		expected string
	}{
		{3*86400 + 5*3600, "3d5h"},
		{86400, "1d0h"},
		{3*3600 + 12*60, "3h12m"},
		{3600, "1h0m"},
		{5*60 + 7, "5m"},
		{42, "42s"},
		{0, "0s"},
		{-10, "0s"},
	}
	for _, c := range cases {
		if got := FormatAge(c.seconds); got != c.expected {
			t.Errorf("FormatAge(%v) = %q, want %q", c.seconds, got, c.expected)
		}
		if got := FormatAge(c.seconds); stringsHasPrefix(got, "-") {
			t.Errorf("FormatAge(%v) rendered negative: %q", c.seconds, got)
		}
	}
}

func TestAgeUsesTheBriefsOwnGeneratedAt(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1, prioOpts{})},
		"2026-09-06T06:48:00+00:00", nil, true)
	inv(t, camp, "INV-1", "", "critical", "",
		"2026-09-08T11:59:00+00:00")
	b, att := ledger(t, camp)
	if got := objStr(b, "generated_at"); got != ledgerNow {
		t.Errorf("generated_at = %q, want %q", got, ledgerNow)
	}
	if got := objStr(objAt(attQueue(t, att), "oldest"), "age"); got != "2d5h" {
		t.Errorf("queue age = %q, want 2d5h", got)
	}
	if got := objStr(listAt(attInvariants(t, att), "items")[0], "age"); got != "1m" {
		t.Errorf("invariant age = %q, want 1m", got)
	}
}

func TestTwoHighestConsequenceItemsLeadTheDivergenceGate(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1,
		prioOpts{invariantIDs: []string{"INV-008"}})}, "", nil, true)
	inv(t, camp, "INV-008", "liveness", "critical", "", "")
	b, att := ledger(t, camp)
	div := objAt(b, "divergence")
	if !pyTruthy(div) || objBool(div, "closed") {
		t.Fatalf("the fixture must keep the divergence gate open")
	}
	lead := map[string]bool{}
	for i, r := range listAt(att, "ranked") {
		if i >= 2 {
			break
		}
		lead[objStr(r, "action")] = true
	}
	acts := objStringList(t, b, "next_actions")
	leadIdx, divIdx := []int{}, []int{}
	for i, a := range acts {
		if lead[a] {
			leadIdx = append(leadIdx, i)
		}
		if stringsHasPrefix(a, "divergence gate open — ") {
			divIdx = append(divIdx, i)
		}
	}
	if len(divIdx) == 0 {
		t.Fatalf("divergence items must be present")
	}
	if len(leadIdx) != 2 {
		t.Fatalf("lead actions found = %d, want 2", len(leadIdx))
	}
	maxLead, minDiv := leadIdx[0], divIdx[0]
	for _, i := range leadIdx {
		if i > maxLead {
			maxLead = i
		}
	}
	for _, i := range divIdx {
		if i < minDiv {
			minDiv = i
		}
	}
	if maxLead >= minDiv {
		t.Errorf("lead at %d does not precede divergence at %d", maxLead, minDiv)
	}
}

func TestTheQueueLeadsBothKindsWhenItIsHighConsequence(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1,
		prioOpts{invariantIDs: []string{"INV-008"}})}, "", nil, true)
	inv(t, camp, "INV-008", "liveness", "critical", "", "")
	inv(t, camp, "INV-002", "", "low", "", "2026-09-01T00:00:00+00:00")
	b, att := ledger(t, camp)
	want := []string{"queue/INV-008", "invariant/INV-008", "invariant/INV-002"}
	got := []string{}
	for _, r := range listAt(att, "ranked") {
		got = append(got, objStr(r, "kind")+"/"+objStr(r, "invariant_id"))
	}
	if len(got) != len(want) {
		t.Fatalf("ranked = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ranked[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	acts := objStringList(t, b, "next_actions")
	if acts[0] != objStr(objAt(attQueue(t, att), "oldest"), "action") {
		t.Errorf("acts[0] = %q, want the queue action", acts[0])
	}
	if acts[1] != objStr(listAt(attInvariants(t, att), "items")[0], "action") {
		t.Errorf("acts[1] = %q, want the INV-008 action", acts[1])
	}
	for _, a := range acts {
		if stringsContains(a, "INV-002") {
			t.Errorf("a low-severity invariant reached the lead: %q", a)
		}
	}
}

func TestADisplacedQueueActionIsReEmittedRightAfterTheLead(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1, prioOpts{})}, "", nil, true)
	for _, iid := range []string{"INV-001", "INV-002", "INV-003"} {
		inv(t, camp, iid, "liveness", "critical", "", "")
	}
	b, att := ledger(t, camp)
	kinds := []string{}
	for i, r := range listAt(att, "ranked") {
		if i >= 3 {
			break
		}
		kinds = append(kinds, objStr(r, "kind"))
	}
	if len(kinds) != 3 {
		t.Fatalf("ranked = %v, want 3 invariants", kinds)
	}
	for i, k := range kinds {
		if k != "invariant" {
			t.Errorf("ranked[%d].kind = %q, want invariant", i, k)
		}
	}
	q := objStr(objAt(attQueue(t, att), "oldest"), "action")
	acts := objStringList(t, b, "next_actions")
	if acts[0] != objStr(listAt(attInvariants(t, att), "items")[0], "action") {
		t.Errorf("acts[0] = %q", acts[0])
	}
	if acts[1] != objStr(listAt(attInvariants(t, att), "items")[1], "action") {
		t.Errorf("acts[1] = %q", acts[1])
	}
	if acts[2] != q {
		t.Errorf("acts[2] = %q, want the displaced queue action %q", acts[2], q)
	}
	count := 0
	for _, a := range acts {
		if a == q {
			count++
		}
	}
	if count != 1 {
		t.Errorf("queue action emitted %d times, want exactly 1", count)
	}
	third := objStr(listAt(attInvariants(t, att), "items")[2], "action")
	found := false
	for _, a := range acts {
		if a == third {
			found = true
		}
	}
	if !found {
		t.Errorf("items[2] action missing from next_actions")
	}
}

func TestTheCriticalInvariantLeadsAnOpenLensLine(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1,
		prioOpts{status: "answered"})}, "", nil, true)
	inv(t, camp, "INV-008", "liveness", "critical", "", "")
	b, att := ledger(t, camp)
	acts := objStringList(t, b, "next_actions")
	lens := []int{}
	for i, a := range acts {
		if stringsHasPrefix(a, "divergence gate open — L-") {
			lens = append(lens, i)
		}
	}
	if len(lens) == 0 {
		t.Fatalf("the fixture must keep an open lens line")
	}
	lead := objStr(listAt(att, "ranked")[0], "action")
	if !stringsHasPrefix(lead, "verify INV-008 (unverified ") {
		t.Errorf("lead = %q", lead)
	}
	leadAt := -1
	for i, a := range acts {
		if a == lead {
			leadAt = i
			break
		}
	}
	if leadAt < 0 || leadAt >= lens[0] {
		t.Errorf("lead at %d does not precede lens at %d", leadAt, lens[0])
	}
}

func TestAStaleLensNeverOutranksACriticalUnverifiedInvariant(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1,
		prioOpts{status: "answered"})}, "", nil, true)
	inv(t, camp, "INV-002", "", "low", "", "2026-09-01T00:00:00+00:00")
	inv(t, camp, "INV-008", "liveness", "critical", "",
		"2026-09-08T11:00:00+00:00")
	_, att := ledger(t, camp)
	ids := []string{}
	for _, r := range listAt(att, "ranked") {
		ids = append(ids, objStr(r, "invariant_id"))
	}
	if len(ids) != 2 || ids[0] != "INV-008" || ids[1] != "INV-002" {
		t.Errorf("ranked ids = %v, want [INV-008 INV-002]", ids)
	}
	want := "verify INV-008 (unverified 1h0m): webv2 invariant-verify " +
		camp.CampaignID + " INV-008 --exec EXEC-*"
	if got := objStr(listAt(att, "ranked")[0], "action"); got != want {
		t.Errorf("ranked[0].action = %q\nwant %q", got, want)
	}
}

func TestClosedCampaignHasNoDebtLines(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1,
		prioOpts{invariantIDs: []string{"INV-008"}})}, "", nil, true)
	inv(t, camp, "INV-008", "liveness", "critical", "", "")
	if _, err := camp.Complete("operator", "pass closed for the fixture"); err != nil {
		t.Fatal(err)
	}
	b, att := ledger(t, camp)
	if !objBool(objAt(b, "campaign"), "closed") {
		t.Errorf("campaign.closed = false, want true")
	}
	if got := len(listAt(att, "lines")); got != 0 {
		t.Errorf("lines = %d, want 0", got)
	}
	if v := objAt(attQueue(t, att), "line"); v.Kind != validation.Null {
		t.Errorf("queue.line = %s, want None", validation.PyRepr(v))
	}
	if v := objAt(attInvariants(t, att), "line"); v.Kind != validation.Null {
		t.Errorf("invariants.line = %s, want None", validation.PyRepr(v))
	}
	for _, a := range objStringList(t, b, "next_actions") {
		if stringsContains(a, "untouched") {
			t.Errorf("closed campaign still suggests untouched work: %q", a)
		}
		if stringsHasPrefix(a, "verify INV-") {
			t.Errorf("closed campaign still suggests verification: %q", a)
		}
	}
}

func TestBriefJSONIsAdditive(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	writePlan(t, camp, []validation.Value{prio(1, prioOpts{})}, "", nil, true)
	b := build(t, camp, false)
	preWaveB := map[string]bool{"campaign": true, "findings": true,
		"terminals": true, "independent_verification_queue": true,
		"bounty": true, "pending_memory": true, "relations": true,
		"economics": true, "critical_hunt": true, "integrity": true,
		"divergence": true, "probe_surface": true, "next_actions": true}
	preB4 := map[string]bool{}
	for k := range preWaveB {
		preB4[k] = true
	}
	preB4["corpus_recall"] = true
	present := map[string]bool{}
	for _, pair := range b.O {
		present[pair.K] = true
	}
	for k := range preWaveB {
		if !present[k] {
			t.Errorf("pre-Wave-B key %q vanished", k)
		}
	}
	delta := map[string]bool{}
	for k := range present {
		if !preWaveB[k] {
			delta[k] = true
		}
	}
	want := map[string]bool{"corpus_recall": true, "generated_at": true,
		"attention": true, "problems": true}
	if len(delta) != len(want) {
		t.Errorf("Wave-B delta = %v, want %v", delta, want)
	}
	for k := range want {
		if !delta[k] {
			t.Errorf("Wave-B key %q missing", k)
		}
	}
	deltaB4 := map[string]bool{}
	for k := range present {
		if !preB4[k] {
			deltaB4[k] = true
		}
	}
	for k := range map[string]bool{"generated_at": true, "attention": true,
		"problems": true} {
		if !deltaB4[k] {
			t.Errorf("post-B4 key %q missing", k)
		}
	}
	if len(deltaB4) != 3 {
		t.Errorf("post-B4 delta = %v, want exactly 3 keys", deltaB4)
	}
}

func TestBriefWithoutPlanOrInvariantsHasNoDebtLine(t *testing.T) {
	camp := newCamp(t, "Attention Program")
	now := ledgerNow
	b, err := BuildBrief(camp, false, &now)
	if err != nil {
		t.Fatal(err)
	}
	att := objAt(b, "attention")
	if got := len(listAt(att, "lines")); got != 0 {
		t.Errorf("lines = %d, want 0", got)
	}
	if got := objInt(attQueue(t, att), "total"); got != 0 {
		t.Errorf("queue.total = %d, want 0", got)
	}
	if got := objInt(attInvariants(t, att), "unverified"); got != 0 {
		t.Errorf("invariants.unverified = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// test_campaign_complete.py — the cockpit half
// ---------------------------------------------------------------------------

func TestBriefStopsSuggestingWorkWhenClosed(t *testing.T) {
	camp := newCamp(t, "Closure Program")
	f := hypo(t, camp, "access-control", nil, nil, "Closure finding one")
	fid := objStr(confirmSimple(t, camp, objStr(f, "finding_id")), "finding_id")
	before := build(t, camp, false)
	foundWork := false
	for _, a := range objStringList(t, before, "next_actions") {
		if stringsContains(a, fid) || stringsContains(a, "orchestrator.") {
			foundWork = true
		}
	}
	if !foundWork {
		t.Fatalf("premise: an open campaign has work to suggest")
	}
	if _, err := camp.Complete("alice",
		"pass closed: report generated, findings filed"); err != nil {
		t.Fatal(err)
	}
	after := build(t, camp, false)
	cb := objAt(after, "campaign")
	if !objBool(cb, "closed") {
		t.Errorf("campaign.closed = false, want true")
	}
	if got := objStr(cb, "completed_by"); got != "alice" {
		t.Errorf("completed_by = %q, want alice", got)
	}
	meta := []string{"campaign marked COMPLETE", "FIX INTEGRITY FIRST",
		"(open completion proof"}
	work := []string{}
	for _, a := range objStringList(t, after, "next_actions") {
		skip := false
		for _, m := range meta {
			if stringsHasPrefix(a, m) {
				skip = true
			}
		}
		if !skip {
			work = append(work, a)
		}
	}
	joined := strings.Join(work, "\n")
	if stringsContains(joined, fid) {
		t.Errorf("closed campaign still names %s in work items:\n%s",
			fid, joined)
	}
	if stringsContains(joined, "orchestrator.") {
		t.Errorf("closed campaign still suggests stages:\n%s", joined)
	}
	stated := false
	for _, a := range objStringList(t, after, "next_actions") {
		if stringsContains(a, "COMPLETE") && stringsContains(a, "alice") {
			stated = true
		}
	}
	if !stated {
		t.Errorf("the closure itself is not stated in next_actions")
	}
}
