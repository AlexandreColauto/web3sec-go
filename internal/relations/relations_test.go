// Port of tests/test_relations.py (all 18 test functions). The Python twin was retired 2026-09-09; this package is the source of truth.
//
// DEVIATION (declared): the Python `camp` fixture seeds the global memory
// row by writing the shared store's data file directly; the Go harness
// installs the same row through the findings.SetSharedMemoryRows seam
// (identical to the chainengine/immunize test harnesses). No gate is
// bypassed.
package relations

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/audit"
	"websec/internal/audit/sections"
	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/histmining"
	"websec/internal/learning"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

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

// hypo is test_relations.hypo.
func hypo(t *testing.T, c *state.Campaign, class string, granted, required []string,
	title string, affected *validation.Value) validation.Value {
	t.Helper()
	aff := validation.VArr(validation.VObj(
		kv("path", validation.VStr("src/V.sol")),
		kv("function", validation.VStr("f"))))
	if affected != nil {
		aff = *affected
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", aff),
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

// confirmSimple is test_relations.confirm_simple.
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

// tail is fid[-6:].
func tail(id string) string {
	if len(id) <= 6 {
		return id
	}
	return id[len(id)-6:]
}

// ---- the edge store itself -------------------------------------------------

// test_relation_vocabulary_is_closed
func TestRelationVocabularyIsClosed(t *testing.T) {
	c := newCamp(t, "Acme Program")
	fn := func(a, b string) (validation.Value, validation.Value) {
		return node("finding", a), node(b, "b")
	}
	if _, err := MintRelation(c, "adjacent_to", node("finding", "a"),
		node("finding", "b"), nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "unknown relation kind") {
		t.Fatalf("unknown kind error = %v", err)
	}
	if _, err := MintRelation(c, "resembles", node("finding", "a"),
		node("finding", "b"), nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "never stored") {
		t.Fatalf("derived error = %v", err)
	}
	if _, err := MintRelation(c, "caused_by", node("finding", "a"),
		node("finding", "b"), nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "human-gated") {
		t.Fatalf("human-gated error = %v", err)
	}
	if _, err := MintRelation(c, "observed_in", node("finding", "a"),
		node("snapshot", strings.Repeat("s", 10)), nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "support anchor") {
		t.Fatalf("support error = %v", err)
	}
	sup := validation.VObj(kv("chain_id", validation.VStr("x")))
	if _, err := MintRelation(c, "chained_with", node("finding", "a"),
		node("exec", "e"), &sup, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "requires") {
		t.Fatalf("node type error = %v", err)
	}
	_ = fn
}

// test_edge_is_log_anchored_and_idempotent
func TestEdgeIsLogAnchoredAndIdempotent(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f1 := hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"Causal source finding", nil)
	f2 := hypo(t, c, "logic-error", []string{"beta_cap"}, nil,
		"Causal target finding", nil)
	actor := "judge"
	e1, err := MintCausation(c, objStr(f1, "finding_id"),
		objStr(f2, "finding_id"), actor, "")
	if err != nil {
		t.Fatalf("mint causation: %v", err)
	}
	e2, err := MintCausation(c, objStr(f1, "finding_id"),
		objStr(f2, "finding_id"), actor, "")
	if err != nil {
		t.Fatalf("mint causation again: %v", err)
	}
	if validation.CanonCompact(e1) != validation.CanonCompact(e2) {
		t.Fatal("re-minting returned a different edge")
	}
	rels, err := LoadRelations(c)
	if err != nil {
		t.Fatalf("load relations: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("edges = %d", len(rels))
	}
	refs := []string{}
	events, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, ev := range events {
		if objStr(ev, "type") == "relation.minted" {
			refs = append(refs, objStr(ev, "ref"))
		}
	}
	if len(refs) != 1 || refs[0] != objStr(e1, "relation_id") {
		t.Fatalf("refs = %v", refs)
	}
}

// test_causation_is_human_gated_and_audited
func TestCausationIsHumanGatedAndAudited(t *testing.T) {
	c := newCamp(t, "Acme Program")
	sections.SetRelations(API{})
	audit.Setup()
	t.Cleanup(func() { sections.SetRelations(nil) })
	f1 := hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"Causal source finding", nil)
	f2 := hypo(t, c, "logic-error", []string{"beta_cap"}, nil,
		"Causal target finding", nil)
	if _, err := MintCausation(c, objStr(f1, "finding_id"),
		objStr(f2, "finding_id"), "", ""); err == nil ||
		!strings.Contains(err.Error(), "actor") {
		t.Fatalf("empty actor error = %v", err)
	}
	if _, err := MintCausation(c, objStr(f1, "finding_id"),
		objStr(f2, "finding_id"), "judge", "same root mechanism"); err != nil {
		t.Fatalf("mint causation: %v", err)
	}
	sec, err := VerifyRelations(c)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !objAt(sec, "ok").B || objAt(sec, "checked").I != 1 {
		t.Fatalf("section = %s", validation.CanonCompact(sec))
	}
	full, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !objAt(objAt(objAt(full, "sections"), "relations"), "ok").B {
		t.Fatalf("audit relations section not ok: %s",
			validation.CanonCompact(objAt(objAt(full, "sections"), "relations")))
	}
}

// ---- deterministic minters -------------------------------------------------

// test_chained_with_requires_a_real_chain
func TestChainedWithRequiresARealChain(t *testing.T) {
	c := newCamp(t, "Acme Program")
	if _, err := MintChainedWith(c, "CHAIN-doesnotexist", nil); err == nil ||
		!strings.Contains(err.Error(), "no materialized chain") {
		t.Fatalf("missing chain error = %v", err)
	}
	f1 := hypo(t, c, "access-control", []string{"control_perceived_asset_price"},
		nil, "Chain step one here", nil)
	f2 := hypo(t, c, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price"}, "Chain step two here", nil)
	f3 := hypo(t, c, "access-control", []string{"retain_extracted_funds"},
		[]string{"withdraw_unbacked_assets"}, "Chain step three here", nil)
	for _, f := range []validation.Value{f1, f2, f3} {
		confirmSimple(t, c, objStr(f, "finding_id"))
	}
	ch, err := chainengine.MaterializeChain(c, []string{
		objStr(f1, "finding_id"), objStr(f2, "finding_id"),
		objStr(f3, "finding_id")}, "three-step drain", "", nil, nil)
	if err != nil {
		t.Fatalf("materialize chain: %v", err)
	}
	edges, err := MintChainedWith(c, objStr(ch, "chain_id"), nil)
	if err != nil {
		t.Fatalf("mint chained_with: %v", err)
	}
	pairs := map[string]struct{}{}
	for _, e := range edges {
		pairs[objStr(objAt(e, "src"), "id")+"->"+objStr(objAt(e, "dst"), "id")] = struct{}{}
	}
	want := []string{
		objStr(f1, "finding_id") + "->" + objStr(f2, "finding_id"),
		objStr(f2, "finding_id") + "->" + objStr(f3, "finding_id"),
	}
	if len(pairs) != 2 {
		t.Fatalf("pairs = %v", pairs)
	}
	for _, w := range want {
		if _, ok := pairs[w]; !ok {
			t.Fatalf("missing pair %s in %v", w, pairs)
		}
	}
	again, err := MintChainedWith(c, objStr(ch, "chain_id"), nil)
	if err != nil {
		t.Fatalf("re-mint: %v", err)
	}
	if len(again) != len(edges) {
		t.Fatalf("re-mint returned %d edges, want %d", len(again), len(edges))
	}
	for i := range again {
		if validation.CanonCompact(again[i]) != validation.CanonCompact(edges[i]) {
			t.Fatalf("edge %d changed on re-mint", i)
		}
	}
}

// test_validated_by_only_for_e4_plus_with_an_exec
func TestValidatedByOnlyForE4PlusWithAnExec(t *testing.T) {
	c := newCamp(t, "Acme Program")
	fid := objStr(hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"Validated finding", nil), "finding_id")
	f := confirmSimple(t, c, fid)
	edges, err := MintValidatedBy(c, fid, nil, nil)
	if err != nil {
		t.Fatalf("mint validated_by: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("edges = %d", len(edges))
	}
	if got := objStr(objAt(edges[0], "dst"), "type"); got != "exec" {
		t.Fatalf("dst type = %q", got)
	}
	ev0 := objAt(objAt(f, "evidence").A[0], "evidence_id")
	if got := objStr(objAt(edges[0], "support"), "evidence_id"); got != ev0.S {
		t.Fatalf("support evidence_id = %q want %q", got, ev0.S)
	}
	g := hypo(t, c, "logic-error", []string{"beta_cap"}, nil, "unvalidated", nil)
	none, err := MintValidatedBy(c, objStr(g, "finding_id"), nil, nil)
	if err != nil {
		t.Fatalf("mint validated_by (no exec): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("edges for unvalidated finding = %d", len(none))
	}
}

// test_observed_in_covers_every_pin
func TestObservedInCoversEveryPin(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f := hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"Pinned finding", nil)
	edges, err := MintObservedIn(c, objStr(f, "finding_id"), nil)
	if err != nil {
		t.Fatalf("mint observed_in: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("edges = %d", len(edges))
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatalf("active snapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("no active snapshot")
	}
	if got := objStr(objAt(edges[0], "dst"), "id"); got != *snap {
		t.Fatalf("dst id = %q want %q", got, *snap)
	}
	if got := objStr(objAt(edges[0], "support"), "pin"); got != "source" {
		t.Fatalf("pin = %q", got)
	}
}

// test_disproved_by_only_from_disproved_memory
func TestDisprovedByOnlyFromDisprovedMemory(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f := hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"memory subject", nil)
	fid := objStr(f, "finding_id")
	if _, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "CONFIRMED",
		Pattern:   "oracle price is still real after check",
		FindingID: &fid}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	edges, err := MintDisprovedBy(c, fid, nil, nil)
	if err != nil {
		t.Fatalf("mint disproved_by: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("edges from a CONFIRMED row = %d", len(edges))
	}
	if _, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern:   "turns out intended behavior",
		FindingID: &fid}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	edges, err = MintDisprovedBy(c, fid, nil, nil)
	if err != nil {
		t.Fatalf("mint disproved_by: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("edges = %d", len(edges))
	}
	if got := objStr(objAt(edges[0], "dst"), "type"); got != "memory" {
		t.Fatalf("dst type = %q", got)
	}
	if got := objStr(objAt(edges[0], "support"), "status"); got != "DISPROVED" {
		t.Fatalf("support status = %q", got)
	}
}

// gitTarget is test_relations.git_target.
func gitTarget(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "gitrepo")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(date string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", d}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
			"GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date,
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(d, "Vault.sol"),
			[]byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("contract Vault {}")
	git("2025-01-01T00:00:00", "init", "-q")
	git("2025-01-01T00:00:00", "add", "-A")
	git("2025-01-01T00:00:00", "-c", "user.email=t@t", "-c", "user.name=t",
		"commit", "-qm", "init")
	write("contract Vault { modifier guard() { _; } }")
	git("2025-02-01T00:00:00", "add", "-A")
	git("2025-02-01T00:00:00", "-c", "user.email=t@t", "-c", "user.name=t",
		"commit", "-qm", "fix: reentrancy guard in withdraw")
	write("contract Vault { modifier guard() { _; } function backdoor() external {} }")
	git("2025-03-01T00:00:00", "add", "-A")
	git("2025-03-01T00:00:00", "-c", "user.email=t@t", "-c", "user.name=t",
		"commit", "-qm", "fix: remove backdoor regression")
	return d
}

// commitBySubject is _commit_by_subject.
func commitBySubject(t *testing.T, c *state.Campaign, fragment string) validation.Value {
	t.Helper()
	rep, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"history_mining.json"))
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	for _, cm := range objAt(rep, "security_relevant_commits").A {
		if strings.Contains(objStr(cm, "subject"), fragment) {
			return cm
		}
	}
	t.Fatalf("no commit matching %q", fragment)
	return validation.VNull()
}

// test_fixed_by_requires_a_mined_commit_on_the_affected_path
func TestFixedByRequiresAMinedCommitOnTheAffectedPath(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f := hypo(t, c, "access-control", []string{"reenter_victim"}, nil,
		"Reentrancy in withdraw", &validation.Value{Kind: validation.Arr,
			A: []validation.Value{validation.VObj(
				kv("path", validation.VStr("Vault.sol")),
				kv("function", validation.VStr("withdraw")))}})
	if _, err := MintFixedBy(c, objStr(f, "finding_id"), "abc1234"); err == nil ||
		!strings.Contains(err.Error(), "does not touch") {
		t.Fatalf("no-history error = %v", err)
	}
	if _, err := histmining.MineGitHistory(c, gitTarget(t), 500); err != nil {
		t.Fatalf("mine history: %v", err)
	}
	fix := commitBySubject(t, c, "reentrancy guard")
	edge, err := MintFixedBy(c, objStr(f, "finding_id"), objStr(fix, "commit"))
	if err != nil {
		t.Fatalf("mint fixed_by: %v", err)
	}
	if got := objStr(objAt(edge, "dst"), "type"); got != "commit" {
		t.Fatalf("dst type = %q", got)
	}
	if got := objAt(objAt(edge, "support"), "matched_files"); validation.CanonCompact(got) != `["Vault.sol"]` {
		t.Fatalf("matched_files = %s", validation.CanonCompact(got))
	}
	other := commitBySubject(t, c, "backdoor")
	f2 := hypo(t, c, "logic-error", []string{"beta_cap"}, nil, "Somewhere else",
		&validation.Value{Kind: validation.Arr, A: []validation.Value{
			validation.VObj(kv("path", validation.VStr("src/Other.sol")),
				kv("function", validation.VStr("g")))}})
	if _, err := MintFixedBy(c, objStr(f2, "finding_id"),
		objStr(other, "commit")); err == nil ||
		!strings.Contains(err.Error(), "does not touch") {
		t.Fatalf("unrelated path error = %v", err)
	}
}

// test_reintroduced_by_requires_date_order
func TestReintroducedByRequiresDateOrder(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f := hypo(t, c, "access-control", []string{"reenter_victim"}, nil,
		"Reentrancy in withdraw", &validation.Value{Kind: validation.Arr,
			A: []validation.Value{validation.VObj(
				kv("path", validation.VStr("Vault.sol")),
				kv("function", validation.VStr("withdraw")))}})
	if _, err := histmining.MineGitHistory(c, gitTarget(t), 500); err != nil {
		t.Fatalf("mine history: %v", err)
	}
	fix := commitBySubject(t, c, "reentrancy guard")
	later := commitBySubject(t, c, "backdoor")
	if _, err := MintFixedBy(c, objStr(f, "finding_id"),
		objStr(fix, "commit")); err != nil {
		t.Fatalf("mint fixed_by: %v", err)
	}
	edge, err := MintReintroducedBy(c, objStr(f, "finding_id"),
		objStr(later, "commit"), objStr(fix, "commit"))
	if err != nil {
		t.Fatalf("mint reintroduced_by: %v", err)
	}
	if got := objStr(edge, "kind"); got != "reintroduced_by" {
		t.Fatalf("kind = %q", got)
	}
	if got := objStr(objAt(edge, "support"), "after_commit"); got != objStr(fix, "commit") {
		t.Fatalf("after_commit = %q", got)
	}
	if _, err := MintReintroducedBy(c, objStr(f, "finding_id"),
		objStr(fix, "commit"), objStr(later, "commit")); err == nil ||
		!strings.Contains(err.Error(), "not dated after") {
		t.Fatalf("reversed order error = %v", err)
	}
}

// test_mint_all_deterministic_is_idempotent
func TestMintAllDeterministicIsIdempotent(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f1 := hypo(t, c, "access-control", []string{"control_perceived_asset_price"},
		nil, "Simple step one here", nil)
	f2 := hypo(t, c, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price"}, "Simple step two here", nil)
	for _, f := range []validation.Value{f1, f2} {
		confirmSimple(t, c, objStr(f, "finding_id"))
	}
	if _, err := chainengine.MaterializeChain(c, []string{
		objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"Two-step drain chain", "", nil, nil); err != nil {
		t.Fatalf("materialize chain: %v", err)
	}
	fid1 := objStr(f1, "finding_id")
	if _, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern:   "pattern is intended behavior, no impact",
		FindingID: &fid1}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	first, err := MintAllDeterministic(c)
	if err != nil {
		t.Fatalf("mint all: %v", err)
	}
	if first < 5 {
		t.Fatalf("first mint = %d, want >= 5", first)
	}
	second, err := MintAllDeterministic(c)
	if err != nil {
		t.Fatalf("mint all again: %v", err)
	}
	if second != 0 {
		t.Fatalf("second mint = %d, want 0", second)
	}
	sec, err := VerifyRelations(c)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !objAt(sec, "ok").B {
		t.Fatalf("verify problems = %s",
			validation.CanonCompact(objAt(sec, "problems")))
	}
}

// ---- the query worth more than vector retrieval ----------------------------

// twoSnapshotWorld is _two_snapshot_world.
func twoSnapshotWorld(t *testing.T) (*state.Campaign, validation.Value, validation.Value) {
	t.Helper()
	c := newCamp(t, "Acme Program")
	old := filepath.Join(t.TempDir(), "old")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, old, nil, nil); err != nil {
		t.Fatalf("pin old: %v", err)
	}
	p := hypo(t, c, "access-control", []string{"withdraw_unbacked_assets"},
		[]string{"call_any_entry_point", "move_spot_price",
			"access_flash_liquidity"},
		"Confirmed price-manipulation drain (pre-patch)", nil)
	confirmSimple(t, c, objStr(p, "finding_id"))
	hypo(t, c, "market", []string{"move_spot_price"}, nil,
		"Spot price is manipulable", nil)
	hypo(t, c, "economics", []string{"access_flash_liquidity"}, nil,
		"Flash liquidity available", nil)
	newDir := filepath.Join(t.TempDir(), "new")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "V.sol"),
		[]byte("contract V { /* patched */ }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, newDir, nil, nil); err != nil {
		t.Fatalf("pin new: %v", err)
	}
	q := hypo(t, c, "access-control", []string{"withdraw_unbacked_assets"},
		[]string{"call_any_entry_point", "move_spot_price"},
		"Candidate price-manipulation drain (post-patch)", nil)
	hypo(t, c, "market", []string{"move_spot_price"}, nil,
		"Spot price still manipulable", nil)
	return c, p, q
}

// test_resemblance_capability_delta_flagship
func TestResemblanceCapabilityDeltaFlagship(t *testing.T) {
	c, p, q := twoSnapshotWorld(t)
	rep, err := ResemblanceReport(c, objStr(q, "finding_id"))
	if err != nil {
		t.Fatalf("resemblance report: %v", err)
	}
	matches := objAt(rep, "matches").A
	if len(matches) != 1 {
		t.Fatalf("matches = %d", len(matches))
	}
	m := matches[0]
	if got := objStr(m, "primitive_id"); got != objStr(p, "finding_id") {
		t.Fatalf("primitive_id = %q", got)
	}
	if !objAt(m, "class_match").B {
		t.Fatal("class_match = false")
	}
	if got := validation.CanonCompact(objAt(m, "primitive_depended_on")); got != `["access_flash_liquidity","move_spot_price"]` {
		t.Fatalf("primitive_depended_on = %s", got)
	}
	if got := validation.CanonCompact(objAt(m, "missing")); got != `["access_flash_liquidity"]` {
		t.Fatalf("missing = %s", got)
	}
	if got := validation.CanonCompact(objAt(m, "still_provided")); got != `["move_spot_price"]` {
		t.Fatalf("still_provided = %s", got)
	}
	if !objAt(m, "candidate_reaches_terminal").B {
		t.Fatal("candidate_reaches_terminal = false")
	}
	adv := objStr(m, "advisory")
	if !strings.Contains(adv, "access_flash_liquidity") ||
		!strings.Contains(adv, "terminal") {
		t.Fatalf("advisory = %q", adv)
	}
}

// test_resemblance_excludes_unrelated_findings
func TestResemblanceExcludesUnrelatedFindings(t *testing.T) {
	c, _, _ := twoSnapshotWorld(t)
	other := hypo(t, c, "timing", []string{"act_within_cooldown"}, nil,
		"Cooldown gaming, unrelated", nil)
	rep, err := ResemblanceReport(c, objStr(other, "finding_id"))
	if err != nil {
		t.Fatalf("resemblance report: %v", err)
	}
	if got := len(objAt(rep, "matches").A); got != 0 {
		t.Fatalf("matches = %d", got)
	}
}

// test_resemblance_is_never_stored
func TestResemblanceIsNeverStored(t *testing.T) {
	c, _, q := twoSnapshotWorld(t)
	if _, err := ResemblanceReport(c, objStr(q, "finding_id")); err != nil {
		t.Fatalf("resemblance report: %v", err)
	}
	rels, err := LoadRelations(c)
	if err != nil {
		t.Fatalf("load relations: %v", err)
	}
	for _, r := range rels {
		if objStr(r, "kind") == "resembles" {
			t.Fatal("a resembles edge was stored")
		}
	}
	if len(rels) != 0 {
		t.Fatalf("the report wrote %d edges", len(rels))
	}
}

// test_capability_delta_survives_a_materialized_chain
func TestCapabilityDeltaSurvivesAMaterializedChain(t *testing.T) {
	c := newCamp(t, "Acme Program")
	old := filepath.Join(t.TempDir(), "old")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, old, nil, nil); err != nil {
		t.Fatalf("pin old: %v", err)
	}
	f1 := hypo(t, c, "access-control", []string{"control_perceived_asset_price"},
		nil, "Chain step one here", nil)
	f2 := hypo(t, c, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price", "access_flash_liquidity"},
		"Chain step two here", nil)
	hypo(t, c, "economics", []string{"access_flash_liquidity"}, nil,
		"Flash liquidity available", nil)
	for _, f := range []validation.Value{f1, f2} {
		confirmSimple(t, c, objStr(f, "finding_id"))
	}
	if _, err := chainengine.MaterializeChain(c, []string{
		objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"two-step drain", "", nil, nil); err != nil {
		t.Fatalf("materialize chain: %v", err)
	}
	newDir := filepath.Join(t.TempDir(), "new")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "V.sol"),
		[]byte("contract V { /* patched */ }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, newDir, nil, nil); err != nil {
		t.Fatalf("pin new: %v", err)
	}
	q := hypo(t, c, "logic-error", []string{"withdraw_unbacked_assets"}, nil,
		"Candidate unbacked withdrawal (post-patch)", nil)
	cov, err := CapabilityCoverage(c, objStr(q, "finding_id"),
		objStr(f2, "finding_id"))
	if err != nil {
		t.Fatalf("capability coverage: %v", err)
	}
	if got := validation.CanonCompact(objAt(cov, "missing")); got != `["access_flash_liquidity","control_perceived_asset_price"]` {
		t.Fatalf("missing = %s", got)
	}
}

// test_delta_ignores_exogenous_attacker_held_caps
func TestDeltaIgnoresExogenousAttackerHeldCaps(t *testing.T) {
	c := newCamp(t, "Acme Program")
	old := filepath.Join(t.TempDir(), "old")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, old, nil, nil); err != nil {
		t.Fatalf("pin old: %v", err)
	}
	p := hypo(t, c, "access-control", []string{"withdraw_unbacked_assets"},
		[]string{"access_flash_liquidity", "move_spot_price"},
		"Drain needing external flash loans and a manipulable price", nil)
	confirmSimple(t, c, objStr(p, "finding_id"))
	hypo(t, c, "market", []string{"move_spot_price"}, nil,
		"Spot price is manipulable", nil)
	newDir := filepath.Join(t.TempDir(), "new")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "V.sol"),
		[]byte("contract V { /* patched */ }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, newDir, nil, nil); err != nil {
		t.Fatalf("pin new: %v", err)
	}
	q := hypo(t, c, "access-control", []string{"withdraw_unbacked_assets"},
		[]string{"access_flash_liquidity", "move_spot_price"},
		"Candidate drain, same class, post-patch", nil)
	cov, err := CapabilityCoverage(c, objStr(q, "finding_id"),
		objStr(p, "finding_id"))
	if err != nil {
		t.Fatalf("capability coverage: %v", err)
	}
	if got := validation.CanonCompact(objAt(cov, "missing")); got != `["move_spot_price"]` {
		t.Fatalf("missing = %s", got)
	}
	if strings.Contains(objStr(cov, "advisory"), "access_flash_liquidity") {
		t.Fatalf("advisory claims the exogenous cap was removed: %q",
			objStr(cov, "advisory"))
	}
}

// ---- audit drift -----------------------------------------------------------

// test_audit_flags_a_drifted_edge
func TestAuditFlagsADriftedEdge(t *testing.T) {
	c := newCamp(t, "Acme Program")
	sections.SetRelations(API{})
	audit.Setup()
	t.Cleanup(func() { sections.SetRelations(nil) })
	f1 := hypo(t, c, "access-control", []string{"control_perceived_asset_price"},
		nil, "Drift step one here", nil)
	f2 := hypo(t, c, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price"}, "Drift step two here", nil)
	for _, f := range []validation.Value{f1, f2} {
		confirmSimple(t, c, objStr(f, "finding_id"))
	}
	ch, err := chainengine.MaterializeChain(c, []string{
		objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"Drift check chain", "", nil, nil)
	if err != nil {
		t.Fatalf("materialize chain: %v", err)
	}
	if _, err := MintChainedWith(c, objStr(ch, "chain_id"), nil); err != nil {
		t.Fatalf("mint chained_with: %v", err)
	}
	sec, err := VerifyRelations(c)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !objAt(sec, "ok").B {
		t.Fatalf("verify not ok: %s", validation.CanonCompact(sec))
	}
	if err := os.Remove(filepath.Join(c.ChainsDir,
		objStr(ch, "chain_id")+".json")); err != nil {
		t.Fatalf("remove chain: %v", err)
	}
	full, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	rs := objAt(objAt(full, "sections"), "relations")
	if objAt(rs, "ok").B {
		t.Fatal("audit still ok after the anchor disappeared")
	}
	found := false
	for _, p := range objAt(rs, "problems").A {
		if strings.Contains(p.S, "drifted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %s", validation.CanonCompact(objAt(rs, "problems")))
	}
}

// test_audit_flags_a_forged_edge
func TestAuditFlagsAForgedEdge(t *testing.T) {
	c := newCamp(t, "Acme Program")
	sections.SetRelations(API{})
	audit.Setup()
	t.Cleanup(func() { sections.SetRelations(nil) })
	f := hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"forged anchor", nil)
	forged := validation.VObj(
		kv("relation_id", validation.VStr("REL-aaaaaaaa")),
		kv("kind", validation.VStr("observed_in")),
		kv("src", validation.VObj(
			kv("type", validation.VStr("finding")),
			kv("id", objAt(f, "finding_id")))),
		kv("dst", validation.VObj(
			kv("type", validation.VStr("snapshot")),
			kv("id", validation.VStr("src-forged-000000000000")))),
		kv("support", validation.VObj(
			kv("pin", validation.VStr("source")))),
		kv("actor", validation.VNull()),
		kv("note", validation.VNull()),
		kv("created_at", validation.VStr("2025-01-01T00:00:00Z")))
	if err := validation.WriteJson(RelationsPath(c),
		validation.VArr(forged), ""); err != nil {
		t.Fatalf("write forged: %v", err)
	}
	full, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	rs := objAt(objAt(full, "sections"), "relations")
	if objAt(rs, "ok").B {
		t.Fatal("audit accepted a forged edge")
	}
	found := false
	for _, p := range objAt(rs, "problems").A {
		if strings.Contains(p.S, "drifted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %s", validation.CanonCompact(objAt(rs, "problems")))
	}
}

// test_relations_schema_rejects_unknown_fields
func TestRelationsSchemaRejectsUnknownFields(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f := hypo(t, c, "access-control", []string{"alpha_cap"}, nil,
		"schema check", nil)
	bad := validation.VObj(
		kv("relation_id", validation.VStr("REL-bbbbbbbb")),
		kv("kind", validation.VStr("observed_in")),
		kv("src", validation.VObj(
			kv("type", validation.VStr("finding")),
			kv("id", objAt(f, "finding_id")))),
		kv("dst", validation.VObj(
			kv("type", validation.VStr("snapshot")),
			kv("id", validation.VStr(strings.Repeat("x", 12))))),
		kv("support", validation.VObj(
			kv("pin", validation.VStr("source")))),
		kv("actor", validation.VNull()),
		kv("note", validation.VNull()),
		kv("created_at", validation.VStr("2025-01-01T00:00:00Z")),
		kv("confidence", validation.VFloat(0.9)))
	err := validation.Validate(bad, "relation", 1)
	if err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("validate error = %v", err)
	}
	rels, err := LoadRelations(c)
	if err != nil {
		t.Fatalf("load relations: %v", err)
	}
	rels = append(rels, bad)
	if err := SaveRelations(c, rels); err == nil {
		t.Fatal("_save accepted an unvalidatable edge")
	}
}
