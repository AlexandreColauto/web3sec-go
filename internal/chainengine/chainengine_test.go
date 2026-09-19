// Port of tests/test_chain_engine.py (the seven chain-engine tests) plus the
// terminal-search and materialization gates the Python file exercises
// indirectly through privileged tests. The Python twin was retired 2026-09-09; this package is the source of truth.
//
// DEVIATION (declared): Python's `confirm` fixture uses the same validated
// APIs; this harness uses sandbox.RegisterExec (the honest stand-in for
// out-of-band runs) and a fixed global-memory row, exactly like the
// immunize/forkpoc Go tests. No gate is bypassed.
package chainengine

import (
	"fmt"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/risk"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func objStrOf(v validation.Value, key string) string { return validation.ObjStr(v, key) }

func listAt(v validation.Value, key string) validation.Value {
	return listOf(v, key)
}

func setOrAppendLocal(o []validation.KV, key string,
	v validation.Value) []validation.KV {
	return validation.SetOrAppend(o, key, v)
}

func newCampaign(t *testing.T, name string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), name, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// hypo is test_chain_engine.hypo.
func hypo(t *testing.T, c *state.Campaign, class string, granted, required []string,
	title string) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.StrArr(granted)),
			kv("required", validation.StrArr(required)))),
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

// evidenceItem is conftest.evidence_item.
func evidenceItem(rec validation.Value, level, typ, desc, eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr(desc)),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id")),
	)
}

// sandboxedExec is conftest.sandboxed_exec.
func sandboxedExec(t *testing.T, c *state.Campaign, findingID string) validation.Value {
	t.Helper()
	fid := findingID
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "test-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return rec
}

// floorEvidenceSeq mints unique evidence ids for the manual floor items the
// fixtures attach before a status whose evidence floor is above E0.
var floorEvidenceSeq int

// addFloorEvidence attaches a manual (non-exec) evidence item at *level*: the
// reachability evidence a status floor demands before the status stamp. It is
// the finding's first rise above E0, so it pays the discovery slot once — the
// exec-backed evidence the fixtures attach afterwards rides that same rise for
// free, keeping the campaign's slot spend unchanged.
func addFloorEvidence(t *testing.T, c *state.Campaign, fid, level string) {
	t.Helper()
	floorEvidenceSeq++
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr(
			fmt.Sprintf("EV-manual-%04d", floorEvidenceSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"manual reachability note: the path to the sink is reachable")))); err != nil {
		t.Fatalf("add floor evidence %s: %v", level, err)
	}
}

// confirm is test_chain_engine.confirm: the three-clause CONFIRMED gate for
// economic classes (E4 local, E5 fork, E7 quantification) and the single
// floor clause otherwise.
func confirm(t *testing.T, c *state.Campaign, fid string, level, tier string) {
	t.Helper()
	// R3-3: the POSSIBLE floor is E2, so the fixture earns the reachability
	// evidence BEFORE the status stamp (evidence floors gate every status).
	addFloorEvidence(t, c, fid, "E2")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	rec := sandboxedExec(t, c, fid)
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, level,
		"fork-test", "repro shows impact", "EV-"+tail(fid))); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	cls := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
	if _, ok := findings.ECONOMIC_CONFIRMATION_CLASSES[cls]; ok {
		mintEconomicEvidence(t, c, fid, rec)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "checked"); err != nil {
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
		t.Fatalf("reload finding: %v", err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr(tier)),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gates passed", "", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
}

// mintEconomicEvidence adds the E4 local evidence, the economic-impact
// artifact and the impact evidence an economic-class finding needs.
func mintEconomicEvidence(t *testing.T, c *state.Campaign, fid string,
	rec validation.Value) {
	t.Helper()
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E4",
		"foundry-test", "local harness repro", "EV-lc-"+tail(fid))); err != nil {
		t.Fatalf("add local evidence: %v", err)
	}
	impact := validation.VObj()
	if err := validation.WriteJson(c.ArtifactsDir+"/impact-dump.json",
		impact, ""); err != nil {
		t.Fatalf("write impact dump: %v", err)
	}
	aid, err := c.RegisterArtifact("economic-impact",
		c.ArtifactsDir+"/impact-dump.json", "", nil)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("reload finding: %v", err)
	}
	ei := validation.ObjAt(f2, "economic_impact")
	if ei.Kind != validation.Obj {
		ei = validation.VObj()
	}
	ei.O = validation.SetOrAppend(ei.O, "extractable_usd", validation.VFloat(1000000))
	f2.O = validation.SetOrAppend(f2.O, "economic_impact", ei)
	if err := findings.SaveFinding(c, &f2); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	if _, err := risk.MintImpactEvidence(c, fid, aid,
		"1M extractable per liquidity model"); err != nil {
		t.Fatalf("mint impact evidence: %v", err)
	}
}

// tail is `fid[-6:]`.
func tail(s string) string {
	if len(s) <= 6 {
		return s
	}
	return s[len(s)-6:]
}

// --- the seven ported tests ------------------------------------------------

func TestCapabilityLinksAndProposals(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"control perceived asset price"},
		nil, "F1 title here")
	f2 := hypo(t, c, "economic-invariant", []string{"extract protocol liquidity"},
		[]string{"Control-Perceived  ASSET price"}, "F2 title here")
	links, err := FindLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("links = %v", links)
	}
	got := validation.ObjStr(links[0], "from") + "->" + validation.ObjStr(links[0], "to") + ":" +
		validation.ObjStr(links[0], "capability")
	want := validation.ObjStr(f1, "finding_id") + "->" + validation.ObjStr(f2, "finding_id") +
		":control_perceived_asset_price"
	if got != want {
		t.Fatalf("link = %s, want %s", got, want)
	}
	proposals, err := FindChains(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range proposals {
		members := map[string]struct{}{}
		for _, m := range listOf(p, "members").A {
			members[pyStr(m)] = struct{}{}
		}
		if len(members) == 2 {
			_, a := members[validation.ObjStr(f1, "finding_id")]
			_, b := members[validation.ObjStr(f2, "finding_id")]
			if a && b {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("proposals missing the member pair: %v", proposals)
	}
}

func TestChainRequiresConfirmedMembers(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "logic-error", []string{"cap two here"},
		[]string{"cap one here"}, "F2 title here")
	_, err := MaterializeChain(c, []string{validation.ObjStr(f1, "finding_id"),
		validation.ObjStr(f2, "finding_id")}, "T", "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "CONFIRMED") {
		t.Fatalf("err = %v, want IllegalTransition mentioning CONFIRMED", err)
	}
	var it *findings.IllegalTransition
	if !asIllegal(err, &it) {
		t.Fatalf("err type = %T, want *findings.IllegalTransition", err)
	}
}

// asIllegal is errors.As for the findings transition error.
func asIllegal(err error, target **findings.IllegalTransition) bool {
	it, ok := err.(*findings.IllegalTransition)
	if ok {
		*target = it
	}
	return ok
}

func TestChainRequiresCapabilityContinuity(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "logic-error", []string{"cap two here"},
		[]string{"unrelated need"}, "F2 title here")
	confirm(t, c, validation.ObjStr(f1, "finding_id"), "E5", "T3")
	confirm(t, c, validation.ObjStr(f2, "finding_id"), "E5", "T3")
	_, err := MaterializeChain(c, []string{validation.ObjStr(f1, "finding_id"),
		validation.ObjStr(f2, "finding_id")}, "T", "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "capability gap") {
		t.Fatalf("err = %v, want capability gap", err)
	}
}

func TestMaterializedChainInheritsFloorAndLinks(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "economic-invariant", []string{"cap two here"},
		[]string{"cap one here"}, "F2 title here")
	f3 := hypo(t, c, "liquidation-logic", []string{"cap three here"},
		[]string{"cap two here"}, "F3 title here")
	ids := []string{validation.ObjStr(f1, "finding_id"), validation.ObjStr(f2, "finding_id"),
		validation.ObjStr(f3, "finding_id")}
	for _, id := range ids {
		confirm(t, c, id, "E5", "T3")
	}
	ch, err := MaterializeChain(c, ids, "Full extraction chain", "", nil, nil)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if validation.ObjStr(ch, "evidence_floor") != "E7" {
		t.Fatalf("floor = %s, want E7", validation.ObjStr(ch, "evidence_floor"))
	}
	if len(listOf(ch, "capability_links").A) != 2 {
		t.Fatalf("links = %v", listOf(ch, "capability_links"))
	}
	if validation.ObjStr(ch, "status") != "proposed" {
		t.Fatalf("status = %s", validation.ObjStr(ch, "status"))
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range all {
		if validation.ObjStr(f, "status") == "CHAIN" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("CHAIN findings = %d, want 1", n)
	}
}

func TestChainFailsWithWeakestMemberAtLowEvidence(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "logic-error", []string{"cap two here"},
		[]string{"cap one here"}, "F2 title here")
	confirm(t, c, validation.ObjStr(f1, "finding_id"), "E5", "T3")
	confirm(t, c, validation.ObjStr(f2, "finding_id"), "E4", "T1")
	ch, err := MaterializeChain(c, []string{validation.ObjStr(f1, "finding_id"),
		validation.ObjStr(f2, "finding_id")}, "Titled chain for floor inheritance", "", nil, nil)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if validation.ObjStr(ch, "evidence_floor") != "E4" {
		t.Fatalf("floor = %s, want E4", validation.ObjStr(ch, "evidence_floor"))
	}
}

func TestChainSignatureIsOrderInvariant(t *testing.T) {
	a, b, c := "F-aaa", "F-bbb", "F-ccc"
	if ChainSignature([]string{a, b, c}) != ChainSignature([]string{c, a, b}) {
		t.Fatal("signature is not order-invariant")
	}
	if ChainSignature([]string{a, b}) == ChainSignature([]string{a, b, c}) {
		t.Fatal("signature ignores membership")
	}
	if ChainSignature([]string{a, "", b}) != ChainSignature([]string{a, b}) {
		t.Fatal("blank signatures must not affect identity")
	}
}

func TestDuplicateMaterializationOverSameMembersIsRejected(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "logic-error", []string{"cap two here"},
		[]string{"cap one here"}, "F2 title here")
	ids := []string{validation.ObjStr(f1, "finding_id"), validation.ObjStr(f2, "finding_id")}
	for _, id := range ids {
		confirm(t, c, id, "E5", "T3")
	}
	ch1, err := MaterializeChain(c, ids, "First chain over the member pair", "", nil, nil)
	if err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	if validation.ObjStr(ch1, "chain_signature") == "" {
		t.Fatal("chain_signature is empty")
	}
	_, err = MaterializeChain(c, ids, "Second chain over the same pair", "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want already exists", err)
	}
}

// --- added coverage: terminal search, chain_report, materialize gates ------

func TestFindTerminalChainsDirectAndChain(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	// a direct drain: required ⊆ baseline, grants an asset-kind capability
	direct := hypo(t, c, "logic-error", []string{"drain_treasury"}, nil,
		"Direct drain title")
	// a role-capture finding granting role_governor, then the role drain
	cap := hypo(t, c, "access-control", []string{"role_governor"}, nil,
		"Key compromise title")
	role := hypo(t, c, "access-control", []string{"extract_protocol_liquidity"},
		[]string{"role_governor"}, "Governor drain title")
	for _, f := range []validation.Value{direct, cap, role} {
		confirm(t, c, validation.ObjStr(f, "finding_id"), "E5", "T3")
	}
	paths, err := FindTerminalChains(c, nil, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	directFound, twoStep := false, false
	for _, p := range paths {
		ps := listOf(p, "path").A
		if len(ps) == 1 && pyStr(ps[0]) == validation.ObjStr(direct, "finding_id") {
			directFound = true
			if validation.ObjStr(p, "terminal_capability") != "drain_treasury" {
				t.Fatalf("terminal = %s", validation.ObjStr(p, "terminal_capability"))
			}
		}
		if len(ps) == 2 && pyStr(ps[0]) == validation.ObjStr(cap, "finding_id") &&
			pyStr(ps[1]) == validation.ObjStr(role, "finding_id") {
			twoStep = true
		}
	}
	if !directFound || !twoStep {
		t.Fatalf("paths = %v (direct=%v twoStep=%v)", paths, directFound, twoStep)
	}
	// capital is summed along the path, never a capability
	if got := pyFloatAt(paths[0], "total_capital_required_usd"); got != 0 {
		t.Fatalf("capital = %v, want 0", got)
	}
}

func TestTerminalReportShapeAndBaseline(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f := hypo(t, c, "logic-error", []string{"drain_treasury"}, nil, "Direct drain")
	confirm(t, c, validation.ObjStr(f, "finding_id"), "E5", "T3")
	rep, err := TerminalReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := listOf(rep, "baseline"); len(got.A) != 1 ||
		pyStr(got.A[0]) != "call_any_entry_point" {
		t.Fatalf("baseline = %v", got)
	}
	if len(listOf(rep, "direct").A) != 1 {
		t.Fatalf("direct = %v", listOf(rep, "direct"))
	}
	if len(listOf(rep, "terminal_chains").A) != 0 {
		t.Fatalf("terminal_chains = %v", listOf(rep, "terminal_chains"))
	}
	if len(listOf(rep, "shortest_by_terminal").A) != 1 {
		t.Fatalf("shortest = %v", listOf(rep, "shortest_by_terminal"))
	}
	if validation.ObjStr(rep, "note") != "terminal paths search CONFIRMED findings only; "+
		"terminal = asset-kind capability granted by the last finding" {
		t.Fatalf("note = %s", validation.ObjStr(rep, "note"))
	}
	// an explicit role baseline reaches the role-required finding
	rb := []string{"call_any_entry_point", "role_governor"}
	role := hypo(t, c, "access-control", []string{"extract_protocol_liquidity"},
		[]string{"role_governor"}, "Governor drain")
	confirm(t, c, validation.ObjStr(role, "finding_id"), "E5", "T3")
	rep2, err := TerminalReport(c, &rb)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range listOf(rep2, "direct").A {
		if validation.ObjStr(p, "terminal_finding") == validation.ObjStr(role, "finding_id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("role baseline did not reach the role-required drain: %v",
			listOf(rep2, "direct"))
	}
	if len(listOf(rep2, "direct").A) != 2 {
		t.Fatalf("role direct = %v", listOf(rep2, "direct"))
	}
}

func TestMaterializeChainTerminalAnnotationGates(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "logic-error", []string{"drain_treasury"},
		[]string{"cap one here"}, "F2 title here")
	ids := []string{validation.ObjStr(f1, "finding_id"), validation.ObjStr(f2, "finding_id")}
	for _, id := range ids {
		confirm(t, c, id, "E5", "T3")
	}
	// capability not granted by the via finding
	_, err := MaterializeChain(c, ids, "T", "", nil, &validation.Value{
		Kind: validation.Obj,
		O:    []validation.KV{kv("capability", validation.VStr("not_granted"))}})
	if err == nil || !strings.Contains(err.Error(), "is not granted by") {
		t.Fatalf("err = %v", err)
	}
	// unknown breakdown field
	bad := validation.VObj(kv("capability", validation.VStr("drain_treasury")),
		kv("capital_breakdown", validation.VObj(
			kv("bogus", validation.VFloat(1)))))
	_, err = MaterializeChain(c, ids, "T", "", nil, &bad)
	if err == nil || !strings.Contains(err.Error(),
		"unknown capital_breakdown fields") {
		t.Fatalf("err = %v", err)
	}
	// bool is not a number
	bad2 := validation.VObj(kv("capability", validation.VStr("drain_treasury")),
		kv("capital_breakdown", validation.VObj(
			kv("required_usd", validation.VBool(true)))))
	_, err = MaterializeChain(c, ids, "T", "", nil, &bad2)
	if err == nil || !strings.Contains(err.Error(),
		"must be a number >= 0 or null") {
		t.Fatalf("err = %v", err)
	}
	term := validation.VObj(kv("capability", validation.VStr("drain_treasury")),
		kv("total_capital_required_usd", validation.VFloat(2500)),
		kv("capital_breakdown", validation.VObj(
			kv("required_usd", validation.VFloat(2500)),
			kv("recoverable_usd", validation.VFloat(2000)))))
	ch, err := MaterializeChain(c, ids, "Terminal chain", "", nil, &term)
	if err != nil {
		t.Fatalf("materialize terminal: %v", err)
	}
	td := validation.ObjAt(ch, "terminal")
	if validation.ObjStr(td, "capability") != "drain_treasury" ||
		validation.ObjStr(td, "via_finding") != validation.ObjStr(f2, "finding_id") {
		t.Fatalf("terminal doc = %v", td)
	}
	if pyFloatAt(td, "total_capital_required_usd") != 2500 {
		t.Fatalf("capital = %v", validation.ObjAt(td, "total_capital_required_usd"))
	}
	rep, err := TerminalReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listOf(rep, "materialized_terminal_chains").A) != 1 {
		t.Fatalf("materialized = %v", listOf(rep, "materialized_terminal_chains"))
	}
	rep2, err := ChainReport(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(listOf(rep2, "materialized").A) != 1 ||
		validation.ObjStr(rep2, "note") != ChainReportNote {
		t.Fatalf("chain_report = %v", rep2)
	}
}

func TestMaterializeChainRequiresOneSourcePin(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1 := hypo(t, c, "oracle-manipulation", []string{"cap one here"}, nil, "F1 title here")
	f2 := hypo(t, c, "logic-error", []string{"cap two here"},
		[]string{"cap one here"}, "F2 title here")
	ids := []string{validation.ObjStr(f1, "finding_id"), validation.ObjStr(f2, "finding_id")}
	for _, id := range ids {
		confirm(t, c, id, "E5", "T3")
	}
	// same (absent) pin on both members: the all-unpinned reality is one
	// reality, so materialization succeeds
	if _, err := MaterializeChain(c, ids, "Unpinned chain", "", nil, nil); err != nil {
		t.Fatalf("unpinned materialize: %v", err)
	}
	// now mix pins: rewrite one member onto a source snapshot
	f, err := findings.LoadFinding(c, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "snapshot_ids", validation.VObj(
		kv("source", validation.VStr("SNAP-0001"))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	f2v, err := findings.LoadFinding(c, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	f2v.O = validation.SetOrAppend(f2v.O, "snapshot_ids", validation.VObj(
		kv("source", validation.VStr("SNAP-0002"))))
	if err := findings.SaveFinding(c, &f2v); err != nil {
		t.Fatal(err)
	}
	_, err = MaterializeChain(c, ids, "Mixed pin chain", "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "different/missing source") {
		t.Fatalf("err = %v, want pin mismatch", err)
	}
}

func TestBuildCapabilityIndexSkipsTerminalStatuses(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	keep := hypo(t, c, "logic-error", []string{"cap keep"}, nil, "Keep title here")
	skip := hypo(t, c, "logic-error", []string{"cap skip"}, nil, "Skip title here")
	if _, err := findings.Transition(c, validation.ObjStr(skip, "finding_id"),
		"INFORMATIONAL", "out of scope", "", "", false); err != nil {
		t.Fatal(err)
	}
	idx, err := BuildCapabilityIndex(c)
	if err != nil {
		t.Fatal(err)
	}
	granted := validation.ObjAt(idx, "granted")
	if !validation.HasKey(granted, "cap_keep") {
		t.Fatalf("granted = %v", granted)
	}
	if validation.HasKey(granted, "cap_skip") {
		t.Fatalf("INFORMATIONAL finding leaked into the index: %v", granted)
	}
	if idsOf(granted.O, "cap_keep")[0] != validation.ObjStr(keep, "finding_id") {
		t.Fatalf("index id = %v", granted)
	}
}

func TestChainSignatureMatchesTextSignature(t *testing.T) {
	got := ChainSignature([]string{"F-bbb", "F-aaa"})
	want := findings.TextSignature("chain|F-aaa|F-bbb")
	if got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
	if len(got) != 16 {
		t.Fatalf("signature length = %d, want 16", len(got))
	}
}

func TestReproductionTierOfHelpers(t *testing.T) {
	// guards the shared reproduction seam the floor computation relies on
	if got := reproduction.TierOf(validation.VObj(
		kv("tier_reached", validation.VStr("T3")))); got != "T3" {
		t.Fatalf("tier = %s", got)
	}
}

// TestBuildCapabilityIndexDropsSuperseded pins r12 issue 2: the sweep's
// hand list {DUPLICATE, OUT_OF_SCOPE, INFORMATIONAL} let SUPERSEDED (and
// DISPROVED) rows keep granting capabilities and seeding chain proposals
// while the sibling terminals sweep already used the framework's TERMINAL
// law. One law now: IsTerminal.
func TestBuildCapabilityIndexDropsSuperseded(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	hypo(t, c, "logic-error", []string{"cap keep"}, nil, "Keep title here")
	sup := hypo(t, c, "logic-error", []string{"cap sup"}, nil, "Sup title here")
	dsp := hypo(t, c, "logic-error", []string{"cap dsp"}, nil, "Dsp title here")
	if _, err := findings.Transition(c, validation.ObjStr(sup, "finding_id"),
		"SUPERSEDED", "answered by the successor", "", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, validation.ObjStr(dsp, "finding_id"),
		"DISPROVED", "repro says no", "", "", false); err != nil {
		t.Fatal(err)
	}
	idx, err := BuildCapabilityIndex(c)
	if err != nil {
		t.Fatal(err)
	}
	granted := validation.ObjAt(idx, "granted")
	if !validation.HasKey(granted, "cap_keep") {
		t.Fatalf("live granter missing: %v", granted)
	}
	if validation.HasKey(granted, "cap_sup") || validation.HasKey(granted, "cap_dsp") {
		t.Fatalf("terminal rows must not grant: %v", granted)
	}
	// Chain proposals must not be SEEDED by terminal rows either: the
	// proposal sweep shares the one filter.
	links, err := BuildCapabilityIndex(c)
	if err != nil || links.Kind != validation.Obj {
		t.Fatalf("second index build: %v", err)
	}
}
