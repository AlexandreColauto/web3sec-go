// Port of tests/test_shared_memory.py (all 27 test functions) and
// tests/test_shared_memory_migration.py (all 3). The Python twin was retired 2026-09-09; this package is the source of truth.
//
// conftest's autouse isolate_global_memory_store fixture is reproduced by
// newRoot: every test points $WEBV2_GLOBAL_MEMORY_DIR at a per-test
// directory, so the real ~/.webv2 tier is never touched.
package sharedmem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// Policy is the test module's POLICY.
func policyDoc(program string) validation.Value {
	return validation.VObj(
		kv("program", validation.VStr(program)),
		kv("program_url", validation.VStr("https://x")),
		kv("platform", validation.VStr("immunefi")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("asset_weight_usd", validation.VInt(50000000)),
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
			kv("required_fields", validation.VArr(validation.VStr("PoC"),
				validation.VStr("impact"))))))
}

// PrimitiveGranted / PrimitiveRequired are the module constants.
var primitiveGranted = []string{"control_perceived_asset_price",
	"move_spot_price", "withdraw_unbacked_assets"}

var primitiveRequired = []string{"access_flash_liquidity"}

// newRoot is the `root` fixture + the autouse global-store isolation, plus
// the production seam wiring (findings.visible_memory_rows consults the
// campaign's learning rows and the shared store).
func newRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR",
		filepath.Join(root, "global-shared-memory"))
	findings.SetLearningAllMemory(learning.AllMemory)
	findings.SetSharedMemoryRows(LoadSharedMemory)
	return root
}

// makeCampaign is make_campaign: a campaign with a pinned source snapshot
// and a loaded bounty policy (so it has a program identity).
func makeCampaign(t *testing.T, root, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(root, program, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	target := filepath.Join(c.Dir, "target")
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
	pol := policyDoc(program)
	pp := filepath.Join(c.Dir, "policy.json")
	if _, err := bounty.SavePolicy(c, pol, &pp); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	doc, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(pp))
	if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
		t.Fatalf("write state: %v", err)
	}
	return c
}

// bareCampaign is Campaign.init + a pinned snapshot, no policy.
func bareCampaign(t *testing.T, root, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(root, program, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	target := filepath.Join(c.Dir, "target")
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

// hypo is the test module's hypo.
func hypo(t *testing.T, c *state.Campaign, granted, required []string,
	title, class string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("target/V.sol")),
			kv("contract", validation.VStr("Vault")),
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
	return validation.ObjStr(f, "finding_id")
}

// evSeq makes the manual-evidence ids unique across a test binary run.
var evSeq int

// addManualEvidence attaches the one manual item a PLAIN fixture advance needs
// to clear a status's evidence floor (E1 for PROVISIONALLY_VALID, E2 for
// POSSIBLE). The first item above the E0 baseline is the finding's rise, so it
// pays the discovery slot exactly once per finding; the exec-backed E4 item
// confirm adds later then rides that already-paid promotion (risesAboveBaseline
// sees the E2 and charges nothing more).
func addManualEvidence(t *testing.T, c *state.Campaign, fid, level string) {
	t.Helper()
	evSeq++
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr(fmt.Sprintf("EV-manual-%d", evSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("code reading at triage")),
	)); err != nil {
		t.Fatalf("add %s manual evidence: %v", level, err)
	}
}

// earnPossible is the shared advance to POSSIBLE: earn the E2 floor, then make
// the move. Every fixture whose subject is something OTHER than the floor
// funnels through here.
func earnPossible(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	addManualEvidence(t, c, fid, "E2")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
}

// confirm is the test module's confirm: the single-clause CONFIRMED gate
// with a campaign-LOCAL (pending) memory row for the memory check, so the
// consulted row never touches the shared store.
func confirm(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	earnPossible(t, c, fid)
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "test-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+tail(fid))),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id")))
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
		t.Fatalf("set critic verdict: %v", err)
	}
	bugClass := "logic-error"
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern:   "memory-check consult pattern",
		FindingID: &fid, BugClass: &bugClass})
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.ObjAt(mem, "memory_id"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("record memory check: %v", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	ver := validation.ObjAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
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

// ---- publish discipline ----------------------------------------------------

// test_publish_requires_an_actor
func TestPublishRequiresAnActor(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, c, hypo(t, c, primitiveGranted, primitiveRequired,
		"Actor gate primitive finding", "access-control"))
	if _, err := PublishCampaign(c, "", false); err == nil ||
		!strings.Contains(err.Error(), "actor") {
		t.Fatalf("error = %v", err)
	}
}

// test_publish_requires_a_policy
func TestPublishRequiresAPolicy(t *testing.T) {
	root := newRoot(t)
	c := bareCampaign(t, root, "No Policy Program")
	f := hypo(t, c, primitiveGranted, primitiveRequired,
		"No policy primitive finding", "access-control")
	confirm(t, c, f)
	if _, err := PublishCampaign(c, "operator", false); err == nil ||
		!strings.Contains(err.Error(), "policy") {
		t.Fatalf("error = %v", err)
	}
}

// test_publish_only_confirmed_and_approved
func TestPublishOnlyConfirmedAndApproved(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, c, hypo(t, c, primitiveGranted, primitiveRequired,
		"Will be published finding", "access-control"))
	p := hypo(t, c, []string{"some_other_capability"}, nil,
		"Not yet confirmed finding", "access-control")
	earnPossible(t, c, p)
	bugClass := "logic-error"
	if _, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern:   "a pattern that is intended behavior here",
		FindingID: &p, BugClass: &bugClass}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	pub, err := PublishCampaign(c, "operator", false)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if validation.ObjAt(pub, "signatures_added").I != 1 {
		t.Fatalf("signatures_added = %v", validation.ObjAt(pub, "signatures_added"))
	}
	if validation.ObjAt(pub, "memory_added").I != 0 {
		t.Fatalf("memory_added = %v", validation.ObjAt(pub, "memory_added"))
	}
	sigs, err := LoadSignatures(root)
	if err != nil {
		t.Fatalf("load signatures: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("signatures = %d", len(sigs))
	}
	mems, err := LoadSharedMemory(root)
	if err != nil {
		t.Fatalf("load memory: %v", err)
	}
	if len(mems) != 0 {
		t.Fatalf("shared memory = %d rows", len(mems))
	}
}

// test_publish_second_campaign_with_approved_memory
func TestPublishSecondCampaignWithApprovedMemory(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "a confirmed pattern from campaign A here"}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rows, err := learning.AllMemory(a)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	memA := validation.ObjStr(rows[0], "memory_id")
	if _, err := learning.ApproveMemory(a, memA, "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	first, err := PublishCampaign(a, "operator", false)
	if err != nil {
		t.Fatalf("publish a: %v", err)
	}
	if validation.ObjAt(first, "memory_added").I != 1 {
		t.Fatalf("first memory_added = %v", validation.ObjAt(first, "memory_added"))
	}
	b := makeCampaign(t, root, "Program B")
	if _, err := learning.QueueMemory(b, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "a confirmed pattern from campaign B here"}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rowsB, err := learning.AllMemory(b)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	memB := validation.ObjStr(rowsB[0], "memory_id")
	if _, err := learning.ApproveMemory(b, memB, "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	second, err := PublishCampaign(b, "operator", false)
	if err != nil {
		t.Fatalf("publish b: %v", err)
	}
	if validation.ObjAt(second, "memory_added").I != 1 {
		t.Fatalf("second memory_added = %v", validation.ObjAt(second, "memory_added"))
	}
	shared, err := LoadSharedMemory(root)
	if err != nil {
		t.Fatalf("load shared memory: %v", err)
	}
	ids := map[string]struct{}{}
	keys := map[string]struct{}{}
	for _, r := range shared {
		ids[validation.ObjStr(validation.ObjAt(r, "row"), "memory_id")] = struct{}{}
		keys[validation.ObjStr(r, "program_key")] = struct{}{}
	}
	if _, ok := ids[memA]; !ok {
		t.Fatalf("missing memA in %v", ids)
	}
	if _, ok := ids[memB]; !ok {
		t.Fatalf("missing memB in %v", ids)
	}
	if _, ok := keys["Program A|immunefi|ethereum"]; !ok {
		t.Fatalf("missing program A key in %v", keys)
	}
	if _, ok := keys["Program B|immunefi|ethereum"]; !ok {
		t.Fatalf("missing program B key in %v", keys)
	}
	third, err := PublishCampaign(a, "operator", false)
	if err != nil {
		t.Fatalf("republish a: %v", err)
	}
	if validation.ObjAt(third, "memory_added").I != 0 {
		t.Fatalf("third memory_added = %v", validation.ObjAt(third, "memory_added"))
	}
	shared, err = LoadSharedMemory(root)
	if err != nil {
		t.Fatalf("load shared memory: %v", err)
	}
	if len(shared) != 2 {
		t.Fatalf("shared rows = %d", len(shared))
	}
}

// test_publish_is_idempotent
func TestPublishIsIdempotent(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, c, hypo(t, c, primitiveGranted, primitiveRequired,
		"Idempotent publish finding", "access-control"))
	first, err := PublishCampaign(c, "operator", false)
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	second, err := PublishCampaign(c, "operator", false)
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if validation.ObjAt(first, "signatures_added").I != 1 {
		t.Fatalf("first signatures_added = %v", validation.ObjAt(first, "signatures_added"))
	}
	if validation.ObjAt(second, "signatures_added").I != 0 {
		t.Fatalf("second signatures_added = %v", validation.ObjAt(second, "signatures_added"))
	}
	sigs, err := LoadSignatures(root)
	if err != nil {
		t.Fatalf("load signatures: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("signatures = %d", len(sigs))
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(manifest) != 2 {
		t.Fatalf("manifest records = %d", len(manifest))
	}
}

// test_signature_is_derived_not_raw
func TestSignatureIsDerivedNotRaw(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, c, hypo(t, c, primitiveGranted, primitiveRequired,
		"Derived not raw finding", "access-control"))
	if _, err := PublishCampaign(c, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	sigs, err := LoadSignatures(root)
	if err != nil {
		t.Fatalf("load signatures: %v", err)
	}
	sig := sigs[0]
	if _, ok := fieldAt(sig, "evidence"); ok {
		t.Fatal("signature carries evidence")
	}
	if _, ok := fieldAt(sig, "economic_impact"); ok {
		t.Fatal("signature carries economic_impact")
	}
	if got := validation.CanonCompact(validation.ObjAt(sig, "granted")); got != `["control_perceived_asset_price","move_spot_price","withdraw_unbacked_assets"]` {
		t.Fatalf("granted = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(sig, "required")); got != `["access_flash_liquidity"]` {
		t.Fatalf("required = %s", got)
	}
	if got := len(validation.ObjAt(sig, "code_sourced_required").A); got != 0 {
		t.Fatalf("code_sourced_required = %d entries", got)
	}
	if got := validation.ObjStr(sig, "terminal"); got != "withdraw_unbacked_assets" {
		t.Fatalf("terminal = %q", got)
	}
	if got := validation.ObjStr(validation.ObjAt(sig, "source"), "campaign_id"); got != c.CampaignID {
		t.Fatalf("source campaign = %q", got)
	}
	if !strings.HasPrefix(validation.ObjStr(validation.ObjAt(sig, "source"), "finding_id"), "F-") {
		t.Fatalf("source finding = %q",
			validation.ObjStr(validation.ObjAt(sig, "source"), "finding_id"))
	}
	if got := validation.ObjStr(sig, "program_key"); got != "Acme Immunefi|immunefi|ethereum" {
		t.Fatalf("program_key = %q", got)
	}
}

// ---- recall ----------------------------------------------------------------

// test_recall_finds_a_cross_campaign_primitive
func TestRecallFindsACrossCampaignPrimitive(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Campaign A confirmed primitive", "access-control"))
	hypo(t, a, []string{"access_flash_liquidity"}, nil,
		"Protocol flash liquidity source", "access-control")
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	b := makeCampaign(t, root, "Acme Immunefi")
	cand := hypo(t, b, []string{"move_spot_price", "withdraw_unbacked_assets"},
		primitiveRequired, "Campaign B post-patch candidate", "access-control")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if got := validation.ObjStr(res, "program_key"); got != "Acme Immunefi|immunefi|ethereum" {
		t.Fatalf("program_key = %q", got)
	}
	matches := validation.ObjAt(res, "shared_signatures").A
	if len(matches) != 1 {
		t.Fatalf("matches = %d", len(matches))
	}
	m := matches[0]
	if !validation.ObjAt(m, "class_match").B {
		t.Fatal("class_match = false")
	}
	if got := validation.ObjStr(validation.ObjAt(m, "source"), "campaign_id"); got != a.CampaignID {
		t.Fatalf("source campaign = %q", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(m, "primitive_depended_on")); got != `["access_flash_liquidity"]` {
		t.Fatalf("primitive_depended_on = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(m, "missing")); got != `["access_flash_liquidity"]` {
		t.Fatalf("missing = %s", got)
	}
	if _, ok := fieldAt(m, "still_provided"); !ok {
		t.Fatal("no still_provided field")
	}
}

// test_recall_ignores_exogenous_required_caps
func TestRecallIgnoresExogenousRequiredCaps(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Campaign A exogenous-cap primitive", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	sigs, err := LoadSignatures(root)
	if err != nil {
		t.Fatalf("load signatures: %v", err)
	}
	if got := len(validation.ObjAt(sigs[0], "code_sourced_required").A); got != 0 {
		t.Fatalf("code_sourced_required = %d entries", got)
	}
	b := makeCampaign(t, root, "Acme Immunefi")
	cand := hypo(t, b, []string{"move_spot_price", "withdraw_unbacked_assets"},
		primitiveRequired, "Campaign B candidate, exogenous cap", "access-control")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	matches := validation.ObjAt(res, "shared_signatures").A
	if len(matches) != 1 {
		t.Fatalf("matches = %d", len(matches))
	}
	m := matches[0]
	if got := len(validation.ObjAt(m, "primitive_depended_on").A); got != 0 {
		t.Fatalf("primitive_depended_on = %d entries", got)
	}
	if got := len(validation.ObjAt(m, "missing").A); got != 0 {
		t.Fatalf("missing = %d entries", got)
	}
}

// test_recall_excludes_the_candidates_own_campaign
func TestRecallExcludesTheCandidatesOwnCampaign(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Own campaign primitive finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cand := hypo(t, a, []string{"move_spot_price"}, primitiveRequired,
		"Same campaign second finding", "access-control")
	earnPossible(t, a, cand)
	res, err := Recall(a, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if got := len(validation.ObjAt(res, "shared_signatures").A); got != 0 {
		t.Fatalf("matches = %d", got)
	}
}

// test_recall_filters_by_program
func TestRecallFiltersByProgram(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Program A primitive finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	other := makeCampaign(t, root, "Different Program")
	cand := hypo(t, other, primitiveGranted, primitiveRequired,
		"Different program candidate finding", "access-control")
	earnPossible(t, other, cand)
	res, err := Recall(other, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if got := len(validation.ObjAt(res, "shared_signatures").A); got != 0 {
		t.Fatalf("matches = %d", got)
	}
}

// test_recall_without_a_policy_is_honest
func TestRecallWithoutAPolicyIsHonest(t *testing.T) {
	root := newRoot(t)
	c := bareCampaign(t, root, "No Policy Program")
	f := hypo(t, c, primitiveGranted, primitiveRequired,
		"No policy candidate finding", "access-control")
	res, err := Recall(c, f)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if validation.ObjAt(res, "program_key").Kind != validation.Null {
		t.Fatalf("program_key = %s",
			validation.CanonCompact(validation.ObjAt(res, "program_key")))
	}
	if got := len(validation.ObjAt(res, "shared_signatures").A); got != 0 {
		t.Fatalf("matches = %d", got)
	}
	if !strings.Contains(strings.ToLower(validation.ObjStr(res, "note")), "policy") {
		t.Fatalf("note = %q", validation.ObjStr(res, "note"))
	}
}

// test_recall_surfaces_approved_memory
func TestRecallSurfacesApprovedMemory(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	fid := hypo(t, a, primitiveGranted, primitiveRequired,
		"Memory source primitive finding", "access-control")
	confirm(t, a, fid)
	bugClass := "access-control"
	mem, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern:   "flash loan price skew is confirmed live",
		FindingID: &fid, BugClass: &bugClass})
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	if _, err := learning.ApproveMemory(a, validation.ObjStr(mem, "memory_id"),
		"operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	b := makeCampaign(t, root, "Acme Immunefi")
	cand := hypo(t, b, []string{"move_spot_price"}, primitiveRequired,
		"Memory recall candidate finding", "access-control")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	found := false
	for _, m := range validation.ObjAt(res, "shared_memory").A {
		if validation.ObjStr(m, "memory_id") == validation.ObjStr(mem, "memory_id") &&
			validation.ObjStr(m, "status") == "CONFIRMED" &&
			validation.ObjStr(m, "source_campaign") == a.CampaignID {
			found = true
		}
	}
	if !found {
		t.Fatalf("shared_memory = %s",
			validation.CanonCompact(validation.ObjAt(res, "shared_memory")))
	}
}

// test_recall_is_advisory_and_writes_nothing
func TestRecallIsAdvisoryAndWritesNothing(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Write-free recall source finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	b := makeCampaign(t, root, "Acme Immunefi")
	cand := hypo(t, b, []string{"move_spot_price"}, primitiveRequired,
		"Write-free recall candidate", "access-control")
	earnPossible(t, b, cand)
	sigsBefore := readBytes(t, filepath.Join(StoreDir(root), "signatures.json"))
	memBefore := readBytes(t, filepath.Join(StoreDir(root), "memory.json"))
	stateBefore := readBytes(t, b.StatePath)
	for i := 0; i < 3; i++ {
		if _, err := Recall(b, cand); err != nil {
			t.Fatalf("recall: %v", err)
		}
	}
	if got := readBytes(t, filepath.Join(StoreDir(root), "signatures.json")); got != sigsBefore {
		t.Fatal("recall rewrote signatures.json")
	}
	if got := readBytes(t, filepath.Join(StoreDir(root), "memory.json")); got != memBefore {
		t.Fatal("recall rewrote memory.json")
	}
	if got := readBytes(t, b.StatePath); got != stateBefore {
		t.Fatal("recall rewrote the campaign state")
	}
}

func readBytes(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// ---- store verification ----------------------------------------------------

// test_verify_passes_on_a_clean_store
func TestVerifyPassesOnACleanStore(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Clean store verify finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !validation.ObjAt(rep, "ok").B || len(validation.ObjAt(rep, "problems").A) != 0 {
		t.Fatalf("report = %s", validation.CanonCompact(rep))
	}
	if validation.ObjAt(rep, "signature_count").I != 1 {
		t.Fatalf("signature_count = %v", validation.ObjAt(rep, "signature_count"))
	}
}

// test_verify_reports_a_missing_store_as_ok
func TestVerifyReportsAMissingStoreAsOk(t *testing.T) {
	root := newRoot(t)
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validation.ObjAt(rep, "exists").B || !validation.ObjAt(rep, "ok").B {
		t.Fatalf("report = %s", validation.CanonCompact(rep))
	}
}

// test_verify_flags_a_hand_edit
func TestVerifyFlagsAHandEdit(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Hand edit detect finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	sp := filepath.Join(StoreDir(root), "signatures.json")
	sigs, err := validation.ReadJson(sp)
	if err != nil {
		t.Fatalf("read signatures: %v", err)
	}
	granted := validation.ObjAt(sigs.A[0], "granted")
	granted.A = append(granted.A, validation.VStr("sneaked_in_capability"))
	sigs.A[0].O = validation.SetOrAppend(sigs.A[0].O, "granted", granted)
	writeRaw(t, sp, validation.DumpIndented(sigs)+"\n")
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validation.ObjAt(rep, "ok").B {
		t.Fatal("verify passed a hand-edited store")
	}
	found := false
	for _, p := range validation.ObjAt(rep, "problems").A {
		if strings.Contains(p.S, "signatures.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %s", validation.CanonCompact(validation.ObjAt(rep, "problems")))
	}
}

// test_store_is_at_the_root_level
func TestStoreIsAtTheRootLevel(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Acme Immunefi")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Root level store finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := StoreDir(root); got != filepath.Join(root, "shared-memory") {
		t.Fatalf("store_dir = %q", got)
	}
	if _, err := os.Stat(filepath.Join(a.Dir, "shared-memory")); err == nil {
		t.Fatal("the store is inside the campaign dir")
	}
}

// ---- global tier + global scope --------------------------------------------

// test_publish_to_global_tier_is_visible_from_another_root
func TestPublishToGlobalTierIsVisibleFromAnotherRoot(t *testing.T) {
	base := newRoot(t)
	rootA := filepath.Join(base, "repo-a")
	rootB := filepath.Join(base, "repo-b")
	a := makeCampaign(t, rootA, "Program A")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "a confirmed pattern shared globally here"}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rows, err := learning.AllMemory(a)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	memA := validation.ObjStr(rows[0], "memory_id")
	if _, err := learning.ApproveMemory(a, memA, "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	pub, err := PublishCampaign(a, "operator", true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := validation.ObjStr(pub, "tier"); got != "global" {
		t.Fatalf("tier = %q", got)
	}
	if validation.ObjAt(pub, "memory_added").I != 1 {
		t.Fatalf("memory_added = %v", validation.ObjAt(pub, "memory_added"))
	}
	if _, err := os.Stat(StoreDir(rootA)); err == nil {
		t.Fatal("the root tier of repo-a was written")
	}
	shared, err := LoadSharedMemory(rootB)
	if err != nil {
		t.Fatalf("load shared memory: %v", err)
	}
	if len(shared) != 1 ||
		validation.ObjStr(validation.ObjAt(shared[0], "row"), "memory_id") != memA {
		t.Fatalf("shared = %s", validation.CanonCompact(validation.VArr(shared...)))
	}
	if got := validation.ObjStr(shared[0], "program_key"); got != "Program A|immunefi|ethereum" {
		t.Fatalf("program_key = %q", got)
	}
}

// test_global_scope_row_is_recalled_for_any_program
func TestGlobalScopeRowIsRecalledForAnyProgram(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern:  "arbitrary user input real-world exploit pattern",
		BugClass: strPtr("logic-error")}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rows, err := learning.AllMemory(a)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	memA := validation.ObjStr(rows[0], "memory_id")
	if _, err := learning.ApproveMemory(a, memA, "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	b := makeCampaign(t, root, "Program B")
	cand := hypo(t, b, nil, nil, "logic error candidate", "logic-error")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if got := len(validation.ObjAt(res, "shared_memory").A); got != 0 {
		t.Fatalf("pre-scope hits = %d", got)
	}
	if _, err := SetScope(root, "global", "operator", "", "root"); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	res, err = Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	hits := validation.ObjAt(res, "shared_memory").A
	if len(hits) != 1 || validation.ObjStr(hits[0], "memory_id") != memA {
		t.Fatalf("hits = %s", validation.CanonCompact(validation.VArr(hits...)))
	}
}

// test_global_scope_signatures_are_recalled_for_any_program
func TestGlobalScopeSignaturesAreRecalledForAnyProgram(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Globally scoped primitive finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := SetScope(root, "global", "operator", "", "root"); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	b := makeCampaign(t, root, "Totally Other Program")
	cand := hypo(t, b, []string{"move_spot_price", "withdraw_unbacked_assets"},
		primitiveRequired, "Other-program candidate", "access-control")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if got := validation.ObjStr(res, "program_key"); got != "Totally Other Program|immunefi|ethereum" {
		t.Fatalf("program_key = %q", got)
	}
	matches := validation.ObjAt(res, "shared_signatures").A
	if len(matches) != 1 {
		t.Fatalf("matches = %d", len(matches))
	}
	if got := validation.ObjStr(validation.ObjAt(matches[0], "source"), "campaign_id"); got != a.CampaignID {
		t.Fatalf("source campaign = %q", got)
	}
}

// test_recall_without_policy_still_returns_global_rows
func TestRecallWithoutPolicyStillReturnsGlobalRows(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern:  "known-safe pattern from the seed dataset",
		BugClass: strPtr("reentrancy")}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rows, err := learning.AllMemory(a)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	memA := validation.ObjStr(rows[0], "memory_id")
	if _, err := learning.ApproveMemory(a, memA, "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := SetScope(root, "global", "operator", "", "root"); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	b := bareCampaign(t, root, "No Policy Program")
	cand := hypo(t, b, nil, nil, "reentrancy candidate", "reentrancy")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if validation.ObjAt(res, "program_key").Kind != validation.Null {
		t.Fatalf("program_key = %s",
			validation.CanonCompact(validation.ObjAt(res, "program_key")))
	}
	if !strings.Contains(validation.ObjStr(res, "note"), "no program identity") {
		t.Fatalf("note = %q", validation.ObjStr(res, "note"))
	}
	hits := validation.ObjAt(res, "shared_memory").A
	if len(hits) != 1 || validation.ObjStr(hits[0], "memory_id") != memA {
		t.Fatalf("hits = %s", validation.CanonCompact(validation.VArr(hits...)))
	}
}

// test_set_scope_is_manifest_logged_and_keeps_verify_green
func TestSetScopeIsManifestLoggedAndKeepsVerifyGreen(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"Scope-change audit finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish: %v", err)
	}
	rep, err := SetScope(root, "global", "operator", "", "root")
	if err != nil {
		t.Fatalf("set scope: %v", err)
	}
	if validation.ObjAt(rep, "memory_updated").I != 0 ||
		validation.ObjAt(rep, "signatures_updated").I != 1 {
		t.Fatalf("report = %s", validation.CanonCompact(rep))
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	last := manifest[len(manifest)-1]
	if validation.ObjStr(last, "record_id") != validation.ObjStr(rep, "record_id") {
		t.Fatalf("last record_id = %q", validation.ObjStr(last, "record_id"))
	}
	if validation.ObjStr(last, "action") != "scope.changed" {
		t.Fatalf("action = %q", validation.ObjStr(last, "action"))
	}
	if validation.ObjStr(last, "actor") != "operator" {
		t.Fatalf("actor = %q", validation.ObjStr(last, "actor"))
	}
	ver, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !validation.ObjAt(ver, "ok").B {
		t.Fatalf("verify problems = %s",
			validation.CanonCompact(validation.ObjAt(ver, "problems")))
	}
	sp := filepath.Join(StoreDir(root), "signatures.json")
	sigs, err := validation.ReadJson(sp)
	if err != nil {
		t.Fatalf("read signatures: %v", err)
	}
	granted := validation.ObjAt(sigs.A[0], "granted")
	granted.A = append(granted.A, validation.VStr("sneaked_in_capability"))
	sigs.A[0].O = validation.SetOrAppend(sigs.A[0].O, "granted", granted)
	writeRaw(t, sp, validation.DumpIndented(sigs)+"\n")
	ver, err = VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validation.ObjAt(ver, "ok").B {
		t.Fatal("verify passed a hand edit after the scope change")
	}
}

// test_set_scope_requires_an_actor
func TestSetScopeRequiresAnActor(t *testing.T) {
	root := newRoot(t)
	if _, err := SetScope(root, "global", "", "", "root"); err == nil ||
		!strings.Contains(err.Error(), "actor") {
		t.Fatalf("error = %v", err)
	}
}

// test_merged_tiers_dedupe_and_union_visibility
func TestMergedTiersDedupeAndUnionVisibility(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern:  "row published into both tiers",
		BugClass: strPtr("logic-error")}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rows, err := learning.AllMemory(a)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	memA := validation.ObjStr(rows[0], "memory_id")
	if _, err := learning.ApproveMemory(a, memA, "operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish root: %v", err)
	}
	if _, err := PublishCampaign(a, "operator", true); err != nil {
		t.Fatalf("publish global: %v", err)
	}
	shared, err := LoadSharedMemory(root)
	if err != nil {
		t.Fatalf("load shared memory: %v", err)
	}
	if len(shared) != 1 ||
		validation.ObjStr(validation.ObjAt(shared[0], "row"), "memory_id") != memA {
		t.Fatalf("shared = %s", validation.CanonCompact(validation.VArr(shared...)))
	}
	if _, ok := fieldAt(shared[0], "scope"); ok {
		t.Fatal("scope present before globalize")
	}
	if _, err := SetScope(root, "global", "operator", "", "global"); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	shared, err = LoadSharedMemory(root)
	if err != nil {
		t.Fatalf("load shared memory: %v", err)
	}
	if len(shared) != 1 || validation.ObjStr(shared[0], "scope") != "global" {
		t.Fatalf("shared = %s", validation.CanonCompact(validation.VArr(shared...)))
	}
	b := makeCampaign(t, root, "Program B")
	cand := hypo(t, b, nil, nil, "logic candidate for merged view", "logic-error")
	earnPossible(t, b, cand)
	res, err := Recall(b, cand)
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	hits := validation.ObjAt(res, "shared_memory").A
	if len(hits) != 1 || validation.ObjStr(hits[0], "memory_id") != memA {
		t.Fatalf("hits = %s", validation.CanonCompact(validation.VArr(hits...)))
	}
}

// test_store_view_reports_both_tiers
func TestStoreViewReportsBothTiers(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Program A")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "view tier breakdown row here"}); err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	rows, err := learning.AllMemory(a)
	if err != nil {
		t.Fatalf("all memory: %v", err)
	}
	if _, err := learning.ApproveMemory(a, validation.ObjStr(rows[0], "memory_id"),
		"operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := PublishCampaign(a, "operator", true); err != nil {
		t.Fatalf("publish: %v", err)
	}
	v, err := StoreView(root)
	if err != nil {
		t.Fatalf("store view: %v", err)
	}
	tiers := map[string]validation.Value{}
	for _, t2 := range validation.ObjAt(v, "tiers").A {
		tiers[validation.ObjStr(t2, "tier")] = t2
	}
	if validation.ObjAt(tiers["root"], "exists").B {
		t.Fatal("root tier exists")
	}
	if !validation.ObjAt(tiers["global"], "exists").B {
		t.Fatal("global tier missing")
	}
	if validation.ObjAt(tiers["global"], "memory_count").I != 1 {
		t.Fatalf("global memory_count = %v",
			validation.ObjAt(tiers["global"], "memory_count"))
	}
	if validation.ObjAt(v, "memory_count").I != 1 {
		t.Fatalf("memory_count = %v", validation.ObjAt(v, "memory_count"))
	}
}

// ---- manifest chain integrity ----------------------------------------------

// twoPublishManifest is _two_publish_manifest.
func twoPublishManifest(t *testing.T, root string) (string, []validation.Value) {
	t.Helper()
	a := makeCampaign(t, root, "Program A")
	confirm(t, a, hypo(t, a, primitiveGranted, primitiveRequired,
		"First publish finding", "access-control"))
	if _, err := PublishCampaign(a, "operator", false); err != nil {
		t.Fatalf("publish a: %v", err)
	}
	b := makeCampaign(t, root, "Program B")
	confirm(t, b, hypo(t, b, primitiveGranted, primitiveRequired,
		"Second publish finding", "access-control"))
	if _, err := PublishCampaign(b, "operator", false); err != nil {
		t.Fatalf("publish b: %v", err)
	}
	mpath := filepath.Join(StoreDir(root), "manifest.json")
	doc, err := validation.ReadJson(mpath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	m := doc.A
	if len(m) != 2 {
		t.Fatalf("manifest records = %d", len(m))
	}
	for i, r := range m {
		if _, ok := fieldAt(r, "record_hash"); !ok {
			t.Fatalf("record %d has no record_hash", i)
		}
		if _, ok := fieldAt(r, "prev_hash"); !ok {
			t.Fatalf("record %d has no prev_hash", i)
		}
	}
	if validation.ObjStr(m[1], "prev_hash") != validation.ObjStr(m[0], "record_hash") {
		t.Fatal("the chain does not link")
	}
	return mpath, m
}

// test_manifest_chain_catches_a_deleted_publish
func TestManifestChainCatchesADeletedPublish(t *testing.T) {
	root := newRoot(t)
	mpath, m := twoPublishManifest(t, root)
	m = m[1:]
	writeRaw(t, mpath, validation.DumpIndented(validation.VArr(m...))+"\n")
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validation.ObjAt(rep, "ok").B {
		t.Fatal("verify passed a manifest with a deleted publish")
	}
	found := false
	for _, p := range validation.ObjAt(rep, "problems").A {
		if strings.Contains(p.S, "prev_hash breaks the chain") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %s", validation.CanonCompact(validation.ObjAt(rep, "problems")))
	}
}

// test_manifest_chain_catches_an_edited_record
func TestManifestChainCatchesAnEditedRecord(t *testing.T) {
	root := newRoot(t)
	mpath, m := twoPublishManifest(t, root)
	m[0].O = validation.SetOrAppend(m[0].O, "actor", validation.VStr("someone-else"))
	writeRaw(t, mpath, validation.DumpIndented(validation.VArr(m...))+"\n")
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validation.ObjAt(rep, "ok").B {
		t.Fatal("verify passed an edited manifest record")
	}
	found := false
	for _, p := range validation.ObjAt(rep, "problems").A {
		if strings.Contains(p.S, "record_hash does not recompute") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %s", validation.CanonCompact(validation.ObjAt(rep, "problems")))
	}
}

// ---- migration (tests/test_shared_memory_migration.py) ---------------------

// seedGlobalRow is _seed_global_row: one wrapped row with the dead field in
// the global tier.
func seedGlobalRow(t *testing.T, base string) string {
	t.Helper()
	gdir := filepath.Join(base, "global-shared-memory")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	row := validation.VObj(
		kv("memory_id", validation.VStr("MEM-test1234")),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Test Pattern for migration seed")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Test incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("rag_doc_id", validation.VNull()))
	wrapper := validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global")))
	writeRaw(t, filepath.Join(gdir, "memory.json"),
		validation.DumpIndented(validation.VArr(wrapper))+"\n")
	return gdir
}

// test_migration_strips_field_and_appends_manifest
func TestMigrationStripsFieldAndAppendsManifest(t *testing.T) {
	root := newRoot(t)
	seedGlobalRow(t, root)
	c, err := state.Init(filepath.Join(root, "camp"), "test-program",
		state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	out, err := MigrateStripField(c.Root, "rag_doc_id", "operator",
		"RAG retired; field always null")
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdir := filepath.Join(root, "global-shared-memory")
	rows, err := validation.ReadJson(filepath.Join(gdir, "memory.json"))
	if err != nil {
		t.Fatalf("read memory: %v", err)
	}
	if _, ok := fieldAt(validation.ObjAt(rows.A[0], "row"), "rag_doc_id"); ok {
		t.Fatal("rag_doc_id still present")
	}
	manifest, err := validation.ReadJson(filepath.Join(gdir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	strips := []validation.Value{}
	for _, r := range manifest.A {
		if validation.ObjStr(r, "op") == "field-strip" {
			strips = append(strips, r)
		}
	}
	if len(strips) != 1 {
		t.Fatalf("field-strip records = %d", len(strips))
	}
	if validation.ObjStr(strips[0], "field") != "rag_doc_id" {
		t.Fatalf("field = %q", validation.ObjStr(strips[0], "field"))
	}
	if validation.ObjStr(strips[0], "actor") != "operator" {
		t.Fatalf("actor = %q", validation.ObjStr(strips[0], "actor"))
	}
	if _, ok := fieldAt(strips[0], "record_hash"); !ok {
		t.Fatal("no record_hash")
	}
	if _, ok := fieldAt(strips[0], "prev_hash"); !ok {
		t.Fatal("no prev_hash")
	}
	if validation.ObjAt(validation.ObjAt(out, "tiers").A[0], "rows_stripped").I != 1 {
		t.Fatalf("rows_stripped = %v",
			validation.ObjAt(validation.ObjAt(out, "tiers").A[0], "rows_stripped"))
	}
}

// test_migration_is_idempotent
func TestMigrationIsIdempotent(t *testing.T) {
	root := newRoot(t)
	seedGlobalRow(t, root)
	c, err := state.Init(filepath.Join(root, "camp"), "test-program",
		state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	first, err := MigrateStripField(c.Root, "rag_doc_id", "operator",
		"RAG retired")
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	second, err := MigrateStripField(c.Root, "rag_doc_id", "operator",
		"RAG retired")
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if validation.ObjAt(validation.ObjAt(first, "tiers").A[0], "rows_stripped").I != 1 {
		t.Fatalf("first rows_stripped = %v",
			validation.ObjAt(validation.ObjAt(first, "tiers").A[0], "rows_stripped"))
	}
	if validation.ObjAt(validation.ObjAt(second, "tiers").A[0], "rows_stripped").I != 0 {
		t.Fatalf("second rows_stripped = %v",
			validation.ObjAt(validation.ObjAt(second, "tiers").A[0], "rows_stripped"))
	}
	gdir := filepath.Join(root, "global-shared-memory")
	manifest, err := validation.ReadJson(filepath.Join(gdir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	strips := 0
	for _, r := range manifest.A {
		if validation.ObjStr(r, "op") == "field-strip" {
			strips++
		}
	}
	if strips != 1 {
		t.Fatalf("field-strip records = %d", strips)
	}
}

// test_migration_verifies_after_rewrite
func TestMigrationVerifiesAfterRewrite(t *testing.T) {
	root := newRoot(t)
	seedGlobalRow(t, root)
	c, err := state.Init(filepath.Join(root, "camp"), "test-program",
		state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	if _, err := MigrateStripField(c.Root, "rag_doc_id", "operator", "x"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	view, err := VerifySharedStore(c.Root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if validation.ObjAt(view, "ok").B {
		return
	}
	for _, tier := range validation.ObjAt(view, "tiers").A {
		if !validation.ObjAt(tier, "ok").B {
			t.Fatalf("tier not ok: %s", validation.CanonCompact(tier))
		}
	}
}

func writeRaw(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func strPtr(s string) *string { return &s }

// TestRecordHashMatchesPython pins _record_hash against values computed by
// the Python twin (cross-twin manifest-chain parity: the verifier recomputes
// the hash of records either twin wrote).
func TestRecordHashMatchesPython(t *testing.T) {
	pub := validation.VObj(
		kv("record_id", validation.VStr("PUB-abc12345")),
		kv("campaign_id", validation.VStr("C-1")),
		kv("program_key", validation.VStr("P|immunefi|ethereum")),
		kv("actor", validation.VStr("op")),
		kv("at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("tier", validation.VStr("root")),
		kv("signatures_added", validation.VInt(1)),
		kv("memory_added", validation.VInt(0)),
		kv("signatures_sha256", validation.VStr("aa")),
		kv("memory_sha256", validation.VStr("bb")))
	if got, want := recordHash(pub),
		"46999e4bba0024b252eca655606b28f5fad085ed13927e9d2626896ed110358c"; got != want {
		t.Fatalf("publish record hash = %s want %s", got, want)
	}
	strip := validation.VObj(
		kv("op", validation.VStr("field-strip")),
		kv("field", validation.VStr("rag_doc_id")),
		kv("actor", validation.VStr("operator")),
		kv("reason", validation.VStr("x")),
		kv("rows_stripped", validation.VInt(2)),
		kv("at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("file_hashes", validation.VObj(
			kv("memory.json", validation.VStr("cc")))),
		kv("signatures_sha256", validation.VStr("aa")),
		kv("memory_sha256", validation.VStr("bb")))
	if got, want := recordHash(strip),
		"2b0f17468fe2554374eca45dfcae87b5ddd686ea738c59fab75d260d49a428e2"; got != want {
		t.Fatalf("strip record hash = %s want %s", got, want)
	}
}

// ---- leakage-partition guard (tests/test_partition_guards.py, part c) ------

// queuePartitioned is queue_partitioned: queue a negative row and stamp its
// leakage partition the way ingestion does.
func queuePartitioned(t *testing.T, c *state.Campaign,
	partition string) validation.Value {
	t.Helper()
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "a pattern partitioned for the leakage guard"})
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	path := filepath.Join(c.MemoryDir, validation.ObjStr(mem, "memory_id")+".json")
	row, err := validation.ReadJson(path)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	row.O = validation.SetOrAppend(row.O, "partition", validation.VStr(partition))
	if err := validation.WriteJson(path, row, "memory"); err != nil {
		t.Fatalf("write row: %v", err)
	}
	return row
}

// handApprove is hand_approve: force human-approved without approve_memory.
func handApprove(t *testing.T, path, partition string) {
	t.Helper()
	mem, err := validation.ReadJson(path)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	mem.O = validation.SetOrAppend(mem.O, "partition", validation.VStr(partition))
	mem.O = validation.SetOrAppend(mem.O, "promotion_status",
		validation.VStr("human-approved"))
	mem.O = validation.SetOrAppend(mem.O, "approved_by", validation.VStr("hand-edit"))
	mem.O = validation.SetOrAppend(mem.O, "approved_at",
		validation.VStr("2026-09-04T00:00:00+00:00"))
	if err := validation.WriteJson(path, mem, "memory"); err != nil {
		t.Fatalf("write row: %v", err)
	}
}

// test_publish_rejects_non_dev_row_without_store_entry
func TestPublishRejectsNonDevRowWithoutStoreEntry(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	held := queuePartitioned(t, c, "held-out")
	handApprove(t, filepath.Join(c.MemoryDir,
		validation.ObjStr(held, "memory_id")+".json"), "held-out")
	if _, err := PublishCampaign(c, "operator", false); err == nil ||
		!strings.Contains(err.Error(), "held-out") {
		t.Fatalf("error = %v", err)
	}
	mems, err := tierMemory(StoreDir(root))
	if err != nil {
		t.Fatalf("tier memory: %v", err)
	}
	if len(mems) != 0 {
		t.Fatalf("tier memory = %d rows", len(mems))
	}
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !validation.ObjAt(rep, "ok").B {
		t.Fatalf("verify problems = %s",
			validation.CanonCompact(validation.ObjAt(rep, "problems")))
	}
}

// test_publish_rejects_training_row
func TestPublishRejectsTrainingRow(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	training := queuePartitioned(t, c, "training")
	handApprove(t, filepath.Join(c.MemoryDir,
		validation.ObjStr(training, "memory_id")+".json"), "training")
	if _, err := PublishCampaign(c, "operator", false); err == nil ||
		!strings.Contains(err.Error(), "training") {
		t.Fatalf("error = %v", err)
	}
	mems, err := tierMemory(StoreDir(root))
	if err != nil {
		t.Fatalf("tier memory: %v", err)
	}
	if len(mems) != 0 {
		t.Fatalf("tier memory = %d rows", len(mems))
	}
}

// test_publish_allows_dev_row
func TestPublishAllowsDevRow(t *testing.T) {
	root := newRoot(t)
	c := makeCampaign(t, root, "Acme Immunefi")
	dev := queuePartitioned(t, c, "dev")
	if _, err := learning.ApproveMemory(c, validation.ObjStr(dev, "memory_id"),
		"operator"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	pub, err := PublishCampaign(c, "operator", false)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if validation.ObjAt(pub, "memory_added").I != 1 {
		t.Fatalf("memory_added = %v", validation.ObjAt(pub, "memory_added"))
	}
	mems, err := tierMemory(StoreDir(root))
	if err != nil {
		t.Fatalf("tier memory: %v", err)
	}
	if len(mems) != 1 ||
		validation.ObjStr(validation.ObjAt(mems[0], "row"), "memory_id") != validation.ObjStr(dev, "memory_id") {
		t.Fatalf("tier memory = %s",
			validation.CanonCompact(validation.VArr(mems...)))
	}
	for _, w := range mems {
		p := validation.ObjStr(validation.ObjAt(w, "row"), "partition")
		if p == "" {
			p = "dev"
		}
		if p != "dev" {
			t.Fatalf("partition = %q", p)
		}
	}
	rep, err := VerifySharedStore(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !validation.ObjAt(rep, "ok").B {
		t.Fatalf("verify problems = %s",
			validation.CanonCompact(validation.ObjAt(rep, "problems")))
	}
}
