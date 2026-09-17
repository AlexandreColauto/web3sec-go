package roles

// Port of the role-isolation half of tests/test_role_isolation.py: role
// context isolation is structural. The critic must not receive the
// proposer's reasoning — not as hidden fields, not as renamed keys, not as
// bytes inside a string: the context bundle is built from an explicit
// allow-list and then byte-checked for any proposer-reasoning field name.
// Same discipline, adapted, for the reproducer (no critic verdicts, no
// bounty) and the proposer (no critic reasoning, no bounty).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/archetypes"
	"websec/internal/findings"
	"websec/internal/forkdiff"
	"websec/internal/histmining"
	"websec/internal/invariants"
	"websec/internal/playbooks"
	"websec/internal/sharedmem"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const snapID = "SNAP-0001"

func pin(t *testing.T, c *state.Campaign) {
	t.Helper()
	if _, err := c.PinSnapshot(validation.VObj(
		kv("snapshot_id", validation.VStr(snapID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00Z")),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("artifact")),
			kv("content_hash", validation.VStr(strings.Repeat("a", 64))))))); err != nil {
		t.Fatal(err)
	}
}

func newCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// seedGlobalMemoryRow is conftest.seed_global_memory_row against an
// isolated user-global store: one live-verifiable memory row.
func seedGlobalMemoryRow(t *testing.T, memoryID, pattern string) {
	t.Helper()
	row := validation.VObj(
		kv("memory_id", validation.VStr(memoryID)),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr(pattern)),
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
	gdir := sharedmem.GlobalStoreDir()
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global")))
	if err := validation.WriteJson(filepath.Join(gdir, "memory.json"),
		validation.VArr(wrapper), ""); err != nil {
		t.Fatal(err)
	}
}

// auditMemoryCheck is _audit_memory_check: the same distinctive consult
// identity the old rag_refs fixture carried (the "audit-1" bytes).
func auditMemoryCheck(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(t.TempDir(), "gmem"))
	seedGlobalMemoryRow(t, "MEM-audit-1", "audit-trail memory pattern")
	rows, err := findings.VisibleMemoryRows(c)
	if err != nil {
		t.Fatal(err)
	}
	return validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-audit-1"))),
		kv("mode", validation.VStr("negative")),
		kv("row_digest", validation.VStr(
			findings.ComputeRowDigest([]string{"MEM-audit-1"}, rows))),
		kv("note", validation.VStr("negative consult of prior audit-1: no "+
			"contradiction found")))
}

// fullyLoadedFinding is fully_loaded_finding: a finding with EVERY
// proposer-reasoning field populated with distinctive non-empty values.
func fullyLoadedFinding(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	pin(t, c)
	check := auditMemoryCheck(t, c)
	payload := validation.VObj(
		kv("title", validation.VStr("TWAP oracle manipulation via flash-loan "+
			"price push")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("cwe", validation.VStr("CWE-20")),
			kv("description", validation.VStr("The vault prices redemptions "+
				"against a 5-minute spot TWAP that a flash loan can push 40 "+
				"percent inside one block, letting a redeemer withdraw "+
				"shares above NAV.")),
			kv("mechanism", validation.VStr("flash-borrow USDC -> swap into "+
				"pool -> redeem shares at manipulated price -> unwind; the "+
				"profit is the NAV delta times position size")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("redeem"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr(
				validation.VStr("deploy contracts"))),
			kv("required_capital_usd", validation.VInt(1000000)))),
		kv("exploit_sequence", validation.VArr(
			validation.VObj(
				kv("step", validation.VInt(1)),
				kv("actor", validation.VStr("attacker")),
				kv("action", validation.VStr("flash-borrow 1,000,000 USDC "+
					"from the lending market")),
				kv("state_effect", validation.VStr("attacker controls 1M "+
					"USDC for one tx")),
				kv("calls", validation.VArr(
					validation.VStr("lender.flashLoan")))),
			validation.VObj(
				kv("step", validation.VInt(2)),
				kv("actor", validation.VStr("attacker")),
				kv("action", validation.VStr("swap the borrowed USDC into "+
					"the pool, pushing spot +40%")),
				kv("state_effect", validation.VStr("5m TWAP now reflects "+
					"the pushed price")),
				kv("calls", validation.VArr(
					validation.VStr("pool.swap")))))),
		kv("invariant", validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr("The vault's NAV per share cannot "+
				"decrease for an unprivileged caller in a single "+
				"transaction.")),
			kv("documented_ref", validation.VStr(
				"docs/README.md#nav-guarantee")))),
		kv("preconditions", validation.VArr(validation.VObj(
			kv("kind", validation.VStr("market")),
			kv("description", validation.VStr("pool TVL below the "+
				"manipulation horizon"))))),
		kv("economic_impact", validation.VObj(
			kv("asset", validation.VStr("ACME")),
			kv("max_loss_usd", validation.VInt(1000000)),
			kv("extractable_usd", validation.VInt(500000)),
			kv("blast_radius", validation.VStr("protocol-solvency")),
			kv("mechanism", validation.VStr("price impact scales with "+
				"attacker position")),
			kv("confidence", validation.VFloat(0.8)),
			kv("extraction_ratio", validation.VFloat(0.5)))),
		kv("risk", validation.VObj(
			kv("prior", validation.VObj(
				kv("score", validation.VFloat(0.7)),
				kv("factors", validation.VArr(validation.VStr(
					"historical TWAP manipulation class"))))),
			kv("validated", validation.VObj(
				kv("score", validation.VInt(6)),
				kv("band", validation.VStr("high")),
				kv("rationale", validation.VStr(
					"analog campaigns paid out")))),
			kv("bounty_score", validation.VFloat(7.5)))),
		kv("provenance", validation.VObj(
			kv("discovered_by", validation.VStr("model")),
			kv("model", validation.VStr("qwen3-14b")),
			kv("prompt_stage", validation.VStr("05")),
			kv("memory_checks", validation.VArr(check)))),
		kv("dedup_meta", validation.VObj(
			kv("critic_reasoning", validation.VStr("the proposer believes the "+
				"path is reachable because redeem() has no modifier and the "+
				"oracle read is inline")))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	// the prior critic verdict is set the legitimate way (writes both
	// verification.critic_verdict and dedup_meta.critic_reasoning)
	if _, err := findings.SetCriticVerdict(c, fid, "possible",
		"prior critic: reachable, profit unverified"); err != nil {
		t.Fatal(err)
	}
	// the invariant guardrail is fail-closed: this finding hangs off INV-1,
	// so the fixture verifies the statement against code first.
	if _, err := invariants.SeedFromModel(c, validation.VObj(
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr("The vault's NAV per share cannot "+
				"decrease for an unprivileged caller in a single "+
				"transaction.")),
			kv("severity_if_broken", validation.VStr("critical"))))))); err != nil {
		t.Fatal(err)
	}
	checkPath := filepath.Join(c.ArtifactsDir, "inv-1-check.md")
	if err := os.WriteFile(checkPath,
		[]byte("INV-1 checked against src/Vault.sol\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artID, err := c.RegisterOrRefresh("other", checkPath, "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-1", artID); err != nil {
		t.Fatal(err)
	}
	one := int64(1)
	if _, err := findings.SetAssumptions(c, fid, []validation.Value{
		validation.VObj(
			kv("id", validation.VStr("A1")),
			kv("type", validation.VStr("reachability")),
			kv("claim", validation.VStr(
				"redeem() is callable by any EOA with no modifier")),
			kv("status", validation.VStr("UNKNOWN")),
			kv("model_belief", validation.VFloat(0.9)),
			kv("blocking", validation.VBool(true)),
			kv("verification_options", validation.VArr(
				validation.VStr("callgraph"), validation.VStr("fork")))),
		validation.VObj(
			kv("id", validation.VStr("A2")),
			kv("type", validation.VStr("economic")),
			kv("claim", validation.VStr("the flash-loan round trip is "+
				"profitable at current TVL")),
			kv("status", validation.VStr("UNKNOWN")),
			kv("model_belief", validation.VFloat(0.6)),
			kv("blocking", validation.VBool(true)),
			kv("dependencies", validation.VArr(validation.VStr("A1"))),
			kv("verification_options", validation.VArr(
				validation.VStr("balance-delta")))),
	}, &one, "proposer"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	loaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

// blob is _blob: json.dumps(bundle, sort_keys=True, ensure_ascii=True).
func blob(v validation.Value) string { return validation.CanonSpaced(v) }

// allKeys is _all_keys: every dict key at every nesting depth.
func allKeys(node validation.Value, out *[]string) {
	switch node.Kind {
	case validation.Obj:
		for _, pair := range node.O {
			*out = append(*out, pair.K)
			allKeys(pair.V, out)
		}
	case validation.Arr:
		for _, item := range node.A {
			allKeys(item, out)
		}
	}
}

func assertNoForbiddenKeys(t *testing.T, bundle validation.Value, role string) {
	t.Helper()
	keys := []string{}
	allKeys(bundle, &keys)
	leaked := map[string]bool{}
	for _, k := range keys {
		if contains(ForbiddenKeys[role], k) {
			leaked[k] = true
		}
	}
	if len(leaked) > 0 {
		names := []string{}
		for k := range leaked {
			names = append(names, k)
		}
		t.Errorf("%s bundle leaks field(s) %v", role, names)
	}
}

// ---------------------------------------------------------------------------
// allow-list isolation
// ---------------------------------------------------------------------------

func TestCriticBundleExcludesAllProposerReasoning(t *testing.T) {
	c := newCamp(t)
	f := fullyLoadedFinding(t, c)
	fid := objStr(f, "finding_id")
	bundle, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	b := blob(bundle)

	// 1) the allow-list itself: no forbidden field name anywhere
	assertNoForbiddenKeys(t, bundle, "critic")

	// 2) the distinctive VALUES must also be absent — a renamed leak would
	//    pass the key check but not this
	for _, fragment := range []string{"flash-borrow USDC",
		"analog campaigns paid out", "believes the path is reachable",
		"prior critic: reachable, profit unverified", "qwen3-14b",
		"audit-1", "7.5"} {
		if strings.Contains(b, fragment) {
			t.Errorf("critic bundle leaks value %q", fragment)
		}
	}

	// 3) the critic sees the claim skeleton — class and cwe, NOT the
	//    proposer's description of the claim
	rc := objAt(objAt(bundle, "claim"), "root_cause")
	if !objEq(rc, validation.VObj(
		kv("class", validation.VStr("oracle-manipulation")),
		kv("cwe", validation.VStr("CWE-20")))) {
		t.Errorf("claim.root_cause = %s", validation.CanonCompact(rc))
	}
	ids := []string{}
	for _, a := range objAt(objAt(bundle, "claim"), "assumptions").A {
		ids = append(ids, objStr(a, "id"))
	}
	if !sameSet(ids, []string{"A1", "A2"}) {
		t.Errorf("assumption ids = %v", ids)
	}
	if got := objStr(objAt(objAt(bundle, "claim"), "invariant"), "id"); got != "INV-1" {
		t.Errorf("claim.invariant.id = %s", got)
	}
	if ev := objAt(bundle, "evidence"); ev.Kind != validation.Arr || len(ev.A) != 0 {
		t.Errorf("evidence = %s", validation.CanonCompact(ev))
	}
	if !objEq(objAt(bundle, "attacker_baseline"), objAt(f, "attacker")) {
		t.Error("attacker_baseline mismatch")
	}
	perm := objAt(bundle, "permitted_checks")
	if !arrContains(perm, "callgraph") || !arrContains(perm, "balance-delta") {
		t.Errorf("permitted_checks = %s", validation.CanonCompact(perm))
	}
	if got := objStr(objAt(bundle, "snapshot_ids"), "source"); got != snapID {
		t.Errorf("snapshot_ids.source = %s", got)
	}
}

func TestCriticBundleIncludesMinimalEvidenceOnly(t *testing.T) {
	c := newCamp(t)
	f := fullyLoadedFinding(t, c)
	fid := objStr(f, "finding_id")
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("static-analysis")),
		kv("description", validation.VStr(
			"callgraph: redeem() has no access modifier")))); err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	evs := objAt(bundle, "evidence")
	if evs.Kind != validation.Arr || len(evs.A) != 1 {
		t.Fatalf("evidence = %s", validation.CanonCompact(evs))
	}
	ev := evs.A[0]
	if got := objStr(ev, "evidence_id"); got != "EV-1" {
		t.Errorf("evidence_id = %s", got)
	}
	if got := objStr(ev, "level"); got != "E1" {
		t.Errorf("level = %s", got)
	}
	if got := objStr(ev, "type"); got != "static-analysis" {
		t.Errorf("type = %s", got)
	}
	if got := objStr(ev, "description"); got !=
		"callgraph: redeem() has no access modifier" {
		t.Errorf("description = %s", got)
	}
	// minimal: nothing beyond the evidence item's own identity fields
	allowed := map[string]bool{"evidence_id": true, "level": true,
		"type": true, "description": true, "artifact_id": true,
		"command": true, "sandbox_profile": true, "snapshot_id": true,
		"produced_at": true}
	for _, pair := range ev.O {
		if !allowed[pair.K] {
			t.Errorf("evidence carries extra field %s", pair.K)
		}
	}
}

func TestProposerBundleExcludesCriticReasoningAndBounty(t *testing.T) {
	c := newCamp(t)
	fullyLoadedFinding(t, c)
	cls := "oracle-manipulation"
	bundle, err := BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	b := blob(bundle)
	assertNoForbiddenKeys(t, bundle, "proposer")
	// the existing-finding summary carries class + status, not reasoning
	existing := objAt(bundle, "existing_findings")
	if existing.Kind != validation.Arr || len(existing.A) == 0 {
		t.Fatalf("existing_findings = %s", validation.CanonCompact(existing))
	}
	summary := existing.A[0]
	if got := objStr(summary, "bug_class"); got != "oracle-manipulation" {
		t.Errorf("bug_class = %s", got)
	}
	if got := objStr(summary, "status"); got != "POSSIBLE" {
		t.Errorf("status = %s", got)
	}
	if objAt(summary, "description").Kind != validation.Null {
		t.Error("summary carries description")
	}
	// the finding's own mechanism narrative must not leak — but the class
	// playbook MAY mention the same words, so pin the exact fixture fragment
	if strings.Contains(b, "flash-borrow USDC") {
		t.Error("proposer bundle leaks the mechanism narrative")
	}
	if strings.Contains(b, "believes the path is reachable") {
		t.Error("proposer bundle leaks critic reasoning")
	}
	nm := objAt(bundle, "negative_memory")
	if objAt(nm, "authoritative").Kind != validation.Bool ||
		objAt(nm, "authoritative").B {
		t.Errorf("negative_memory.authoritative = %s",
			validation.CanonCompact(objAt(nm, "authoritative")))
	}
	if objAt(nm, "override_rule").Kind == validation.Null {
		t.Error("negative_memory has no override_rule")
	}
}

func TestReproducerBundleHasClaimButNoVerdictOrBounty(t *testing.T) {
	c := newCamp(t)
	f := fullyLoadedFinding(t, c)
	fid := objStr(f, "finding_id")
	bundle, err := BuildReproducerContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	b := blob(bundle)
	assertNoForbiddenKeys(t, bundle, "reproducer")
	// the reproducer legitimately sees the full claim
	mech := objStr(objAt(objAt(bundle, "claim"), "root_cause"), "mechanism")
	if !strings.HasPrefix(mech, "flash-borrow") {
		t.Errorf("claim.root_cause.mechanism = %s", mech)
	}
	seq := objAt(objAt(bundle, "claim"), "exploit_sequence")
	if seq.Kind != validation.Arr || len(seq.A) == 0 {
		t.Fatalf("exploit_sequence = %s", validation.CanonCompact(seq))
	}
	if got := objInt(seq.A[0], "step"); got != 1 {
		t.Errorf("exploit_sequence[0].step = %d", got)
	}
	if strings.Contains(b, "believes the path is reachable") {
		t.Error("reproducer bundle leaks proposer reasoning")
	}
	if strings.Contains(b, "prior critic: reachable, profit unverified") {
		t.Error("reproducer bundle leaks critic reasoning")
	}
	if rs := objAt(bundle, "reproduction_state"); rs.Kind != validation.Obj ||
		len(rs.O) != 0 {
		t.Errorf("reproduction_state = %s", validation.CanonCompact(rs))
	}
	if objAt(objAt(bundle, "success_criteria"), "min_evidence_level").Kind !=
		validation.Str {
		t.Error("success_criteria.min_evidence_level is not a string")
	}
}

func TestReproducerContextRefusesHypotheticalStatus(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("a plain hypothesis that cannot be "+
			"reproduced yet")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"missing access check on a public path")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr())))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildReproducerContext(c, objStr(f, "finding_id"))
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "POSSIBLE") &&
		!strings.Contains(msg, "CONFIRMED") &&
		!strings.Contains(msg, "HYPOTHESIS") {
		t.Errorf("err = %v", err)
	}
}

func TestAssertCleanCatchesInjectedField(t *testing.T) {
	bundle := validation.VObj(kv("claim", validation.VObj(
		kv("root_cause", validation.VObj(kv("class", validation.VStr("x")))))))
	if err := AssertClean(bundle, "critic"); err != nil {
		t.Fatalf("clean bundle rejected: %v", err)
	}
	rc := objAt(objAt(bundle, "claim"), "root_cause")
	rc.O = append(rc.O, kv("bounty", validation.VFloat(9.9)))
	bundle = setKey(bundle, "claim", setKey(objAt(bundle, "claim"), "root_cause", rc))
	err := AssertClean(bundle, "critic")
	if err == nil || !strings.Contains(err.Error(), "bounty") {
		t.Errorf("err = %v", err)
	}
	bundle2 := validation.VObj(kv("dedup_meta", validation.VObj(
		kv("critic_reasoning", validation.VStr(strings.Repeat("x", 10))))))
	err = AssertClean(bundle2, "proposer")
	if err == nil || !strings.Contains(err.Error(), "critic_reasoning") {
		t.Errorf("err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// tier1 context blocks + staleness serve rule
// ---------------------------------------------------------------------------

// makeHuntArtifacts is _make_hunt_artifacts: all four analysis artifacts
// against the ACTIVE pin.
func makeHuntArtifacts(t *testing.T, c *state.Campaign, src string) {
	t.Helper()
	wireIndex(t)
	if _, err := structidx.ValueFlowReport(c, src); err != nil {
		t.Fatal(err)
	}
	if _, err := archetypes.Prescreen(c, src, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := forkdiff.ForkdiffReport(c, src); err != nil {
		t.Fatal(err)
	}
	// no git repo -> all-zero scores
	if _, err := histmining.RecencyScores(c, src, src); err != nil {
		t.Fatal(err)
	}
}

func writeSource(t *testing.T, c *state.Campaign, body string) string {
	t.Helper()
	src := filepath.Join(c.Dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "V.sol"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	return src
}

func activeSnap(t *testing.T, c *state.Campaign) string {
	t.Helper()
	id, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		return ""
	}
	return *id
}

func TestProposerBundleCarriesFreshBlocks(t *testing.T) {
	c := newCamp(t)
	src := writeSource(t, c, "contract V { uint256 public totalAssets; "+
		"function sweep(address to) external { totalAssets = 0; } }\n")
	makeHuntArtifacts(t, c, src)
	b, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"value_flow", "archetype_prescreen",
		"fork_diff", "recency"} {
		block := objAt(b, key)
		if block.Kind != validation.Obj {
			t.Errorf("proposer bundle missing %s: %s", key,
				validation.CanonCompact(block))
			continue
		}
		if got := objStr(block, "snapshot_id"); got != activeSnap(t, c) {
			t.Errorf("%s.snapshot_id = %s, want %s", key, got, activeSnap(t, c))
		}
	}
}

func TestStructuralStatsFollowStalenessRule(t *testing.T) {
	c := newCamp(t)
	src := writeSource(t, c, "contract V { uint256 public totalAssets; }\n")
	makeHuntArtifacts(t, c, src)
	fresh, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := objAt(fresh, "structural_index_stats")
	if stats.Kind != validation.Obj {
		t.Fatalf("structural_index_stats = %s", validation.CanonCompact(stats))
	}
	if objAt(stats, "contracts").Kind == validation.Null {
		t.Error("stats have no contracts key")
	}
	// re-pin on a changed tree: every block, stats included, goes stale
	if err := os.WriteFile(filepath.Join(src, "V.sol"),
		[]byte("contract V { uint256 public totalAssets; function x() "+
			"external {} }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	stale, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(stale, "structural_index_stats").Kind != validation.Null {
		t.Error("stale stats served")
	}
	for _, key := range []string{"value_flow", "archetype_prescreen",
		"fork_diff", "recency"} {
		if objAt(stale, key).Kind != validation.Null {
			t.Errorf("stale block %s served", key)
		}
	}
	names := staleArtifactNames(t, c)
	if !names["structural_index.json"] {
		t.Errorf("stale artifacts = %v", names)
	}
}

func TestStaleBlocksAreOmittedAndFlagged(t *testing.T) {
	c := newCamp(t)
	src := writeSource(t, c, "contract V { uint256 public totalAssets; }\n")
	makeHuntArtifacts(t, c, src)
	// the target changes and is re-pinned: a new snapshot id becomes active
	if err := os.WriteFile(filepath.Join(src, "V.sol"),
		[]byte("contract V { uint256 public totalAssets; function x() "+
			"external {} }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	b, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"value_flow", "archetype_prescreen",
		"fork_diff", "recency"} {
		if objAt(b, key).Kind != validation.Null {
			t.Errorf("stale block %s must not be served", key)
		}
	}
	stale, err := StaleArtifacts(c)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range stale {
		names[objStr(s, "artifact")] = true
		reRun := objStr(s, "re_run")
		if reRun == "" {
			t.Errorf("no re_run for %s", objStr(s, "artifact"))
		}
		// the brief tells the operator which command restores the artifact:
		// it must name the campaign, not the <campaign> metavariable.
		if strings.Contains(reRun, "<campaign>") {
			t.Errorf("re_run for %s still carries the metavariable: %q",
				objStr(s, "artifact"), reRun)
		}
		if !strings.Contains(reRun, c.CampaignID) {
			t.Errorf("re_run for %s does not name the campaign: %q",
				objStr(s, "artifact"), reRun)
		}
	}
	for _, want := range []string{"value_flow.json",
		"archetype_prescreen.json", "fork_diff.json", "recency.json"} {
		if !names[want] {
			t.Errorf("stale artifacts %v missing %s", names, want)
		}
	}
}

func TestCriticBundleSeesInvariantVerification(t *testing.T) {
	c := newCamp(t)
	writeSource(t, c, "contract V {}\n")
	if _, err := invariants.SeedFromModel(c, validation.VObj(
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"totalAssets monotone except withdraw"))))))); err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("sweep drains the pool")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"unguarded setter lets anyone drain the pool")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("sweep"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr())))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	f = setKey(f, "security_invariants", validation.VArr(validation.VObj(
		kv("id", validation.VStr("INV-1")),
		kv("statement", validation.VStr(
			"totalAssets monotone except withdraw")))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	b, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	iv := objAt(b, "invariant_verification")
	if iv.Kind != validation.Arr || len(iv.A) == 0 {
		t.Fatalf("invariant_verification = %s", validation.CanonCompact(iv))
	}
	if got := objStr(iv.A[0], "status"); got != "UNVERIFIED" {
		t.Errorf("status = %s", got)
	}
	p := filepath.Join(c.ArtifactsDir, "inv-check.md")
	if err := os.WriteFile(p, []byte("INV-1 checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterOrRefresh("other", p, "", nil, ""); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	artID := ""
	for _, a := range objAt(st, "artifacts").A {
		if strings.HasSuffix(objStr(a, "path"), "inv-check.md") {
			artID = objStr(a, "artifact_id")
		}
	}
	if artID == "" {
		t.Fatal("registered artifact not found")
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-1", artID); err != nil {
		t.Fatal(err)
	}
	b2, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	iv2 := objAt(b2, "invariant_verification")
	if got := objStr(iv2.A[0], "status"); got != "CHECKED_AGAINST_CODE" {
		t.Errorf("status = %s", got)
	}
}

func TestCriticBundleStatementLessLegacyEntry(t *testing.T) {
	c := newCamp(t)
	writeSource(t, c, "contract V {}\n")
	if _, err := invariants.SeedFromModel(c, validation.VObj(
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-9")),
			kv("statement", validation.VStr(
				"placeholder replaced below"))))))); err != nil {
		t.Fatal(err)
	}
	linksPath := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	links, err := validation.ReadJson(linksPath)
	if err != nil {
		t.Fatal(err)
	}
	invs := objAt(links, "invariants")
	entry := removeKey(objAt(invs, "INV-9"), "statement")
	if err := validation.WriteJson(linksPath,
		setKey(links, "invariants", setKey(invs, "INV-9", entry)), ""); err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("sweep drains the pool")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"unguarded setter lets anyone drain")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("sweep"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr())))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	f = setKey(f, "security_invariants", validation.VArr(validation.VObj(
		kv("id", validation.VStr("INV-9")),
		kv("statement", validation.VStr("finding-side copy")))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	b, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	rows := objAt(b, "invariant_verification")
	if rows.Kind != validation.Arr || len(rows.A) != 1 {
		t.Fatalf("invariant_verification = %s", validation.CanonCompact(rows))
	}
	row := rows.A[0]
	if got := objStr(row, "id"); got != "INV-9" {
		t.Errorf("id = %s", got)
	}
	statement := objStr(row, "statement")
	if statement == "" {
		t.Fatal("degraded form must still carry a statement field")
	}
	if !strings.Contains(statement, "legacy") &&
		!strings.Contains(statement, "not recorded") {
		t.Errorf("statement = %s", statement)
	}
	if got := objStr(row, "status"); got != "UNVERIFIED" {
		t.Errorf("status = %s", got)
	}
}

// --- Tier 3 / 3.2: simulation directive + benign-actor audit ----------------

const simPB = `
bug_class: share-price-inflation
title: Simulation-mode fixture playbook
description: >-
  Fixture playbook for adversarial-simulation loader checks; not a real prior.
investigation_mode: adversarial-simulation
invariants:
  - id: INV-SPI-PRORATA
    statement: Depositors receive shares pro-rata to assets at entry.
assumption_templates:
  - id: AT-SIM-FIXTURE
    type: economic
    statement: >-
      The direct inflow of {inflow} before {victim_deposit} inflates the
      share price captured by the victim deposit.
    blocking: true
hunt_order:
  - step: 1
    tool_id: fork
    purpose: >-
      Fixture hunt step for the simulation-mode loader check playbook.
simulation:
  actors:
    - name: attacker
      behavior_class: adversarial
      capital: dust entry plus large off-path inflow
      behavior: profit-maximizing
    - name: victim
      behavior_class: benign-rational
      capital: real deposit at documented terms
      behavior: deposits because the mechanism is documented as fair
  action_space: deposit, withdraw, redeem, direct ERC20 transfer to vault
  ordering_freedoms: cross-tx order of entry, inflow, deposit, redemption
  expectation_violated: INV-SPI-PRORATA
`

// simPlaybooksDir is the sim_playbooks_dir fixture.
func simPlaybooksDir(t *testing.T) {
	t.Helper()
	d := filepath.Join(t.TempDir(), "playbooks")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "share-price-inflation.yaml"),
		[]byte(simPB), 0o644); err != nil {
		t.Fatal(err)
	}
	playbooks.SetPlaybooksDir(d)
	t.Cleanup(func() { playbooks.SetPlaybooksDir("") })
}

func TestProposerBundleCarriesSimulationDirective(t *testing.T) {
	c := newCamp(t)
	simPlaybooksDir(t)
	cls := "share-price-inflation"
	b, err := BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	d := objAt(b, "simulation_directive")
	if d.Kind != validation.Obj {
		t.Fatalf("simulation_directive = %s", validation.CanonCompact(d))
	}
	if got := objStr(d, "mode"); got != "adversarial-simulation" {
		t.Errorf("mode = %s", got)
	}
	if got := objStr(d, "stage_prompt"); got !=
		"prompts/50_adversarial_simulation.md" {
		t.Errorf("stage_prompt = %s", got)
	}
	if got := objStr(objAt(d, "simulation"), "expectation_violated"); got !=
		"INV-SPI-PRORATA" {
		t.Errorf("expectation_violated = %s", got)
	}
	// resolved expectation — the model never re-derives the statement
	exp := objAt(d, "expectation")
	if got := objStr(exp, "id"); got != "INV-SPI-PRORATA" {
		t.Errorf("expectation.id = %s", got)
	}
	if !strings.Contains(strings.ToLower(objStr(exp, "statement")), "pro-rata") {
		t.Errorf("expectation.statement = %s", objStr(exp, "statement"))
	}
}

func TestProposerBundleOmitsDirectiveForCodeReading(t *testing.T) {
	c := newCamp(t)
	// legacy class: byte-stable bundle shape — the key must be ABSENT
	cls := "reentrancy"
	b, err := BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	if hasKeyOf(b, "simulation_directive") {
		t.Error("simulation_directive present for a code-reading class")
	}
	b2, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasKeyOf(b2, "simulation_directive") {
		t.Error("simulation_directive present for a nil class")
	}
}

func TestCriticBundleBenignActorAuditFlagsEcho(t *testing.T) {
	c := newCamp(t)
	simPlaybooksDir(t)
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("first-depositor inflation via direct "+
			"transfer")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("share-price-inflation")),
			kv("description", validation.VStr("vault reads live balance for "+
				"rate while totalAssets is stale")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("deposit"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))), "model",
		"discovery-specialist", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	// attach a multi-actor sequence with a value echo (the audit reads the
	// finding's exploit_sequence directly)
	f = setKey(f, "exploit_sequence", validation.VArr(
		validation.VObj(
			kv("step", validation.VInt(1)),
			kv("actor", validation.VStr("attacker")),
			kv("target", validation.VStr("0xVault")),
			kv("function", validation.VStr("deposit")),
			kv("args", validation.VArr(validation.VInt(1000000000000000)))),
		validation.VObj(
			kv("step", validation.VInt(2)),
			kv("actor", validation.VStr("attacker")),
			kv("target", validation.VStr("0xVault")),
			kv("function", validation.VStr("transfer")),
			kv("args", validation.VArr(validation.VStr("0xVault"),
				validation.VBigInt("10000000000000000000000000")))),
		validation.VObj(
			kv("step", validation.VInt(3)),
			kv("actor", validation.VStr("victim")),
			kv("target", validation.VStr("0xVault")),
			kv("function", validation.VStr("deposit")),
			kv("args", validation.VArr(
				validation.VBigInt("10000000000000000000000000"))))))
	// Python rewrites the finding file directly (the schema has no
	// exploit_sequence step fields), so the Go twin writes the JSON too.
	if err := validation.WriteJson(filepath.Join(c.FindingsDir, fid+".json"),
		f, ""); err != nil {
		t.Fatal(err)
	}
	b, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	flags := objAt(b, "benign_actor_audit")
	if flags.Kind != validation.Arr || len(flags.A) != 1 {
		t.Fatalf("benign_actor_audit = %s", validation.CanonCompact(flags))
	}
	if got := objInt(flags.A[0], "step"); got != 3 {
		t.Errorf("step = %d", got)
	}
	if got := objInt(flags.A[0], "echoes_attacker_step"); got != 2 {
		t.Errorf("echoes_attacker_step = %d", got)
	}
}

func TestCriticBundleNoAuditForCodeReadingClass(t *testing.T) {
	c := newCamp(t)
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("reentrancy hypothesis")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr(
				"external call before state finalized")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))), "model",
		"discovery-specialist", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildCriticContext(c, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if objAt(b, "benign_actor_audit").Kind != validation.Null {
		t.Errorf("benign_actor_audit = %s",
			validation.CanonCompact(objAt(b, "benign_actor_audit")))
	}
}

// ---- test-local helpers ---------------------------------------------------

func staleArtifactNames(t *testing.T, c *state.Campaign) map[string]bool {
	t.Helper()
	stale, err := StaleArtifacts(c)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, s := range stale {
		out[objStr(s, "artifact")] = true
	}
	return out
}

// wireIndex installs the structural-index seams the recency/forkdiff reports
// read (Python: import-time module access; cli.ensureSeams is the production
// twin but is unexported).
func wireIndex(t *testing.T) {
	t.Helper()
	structidx.Wire()
	forkdiff.Wire()
	histmining.SetIndexAPI(histmining.IndexAPI{
		EnsureFreshIndex: structidx.EnsureFreshIndex,
		SinkFunctions:    structidx.SinkFunctions,
	})
	t.Cleanup(func() { histmining.SetIndexAPI(histmining.IndexAPI{}) })
}

// hasKeyOf is Python's `"k" in bundle` — key presence, not nullness.
func hasKeyOf(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return true
		}
	}
	return false
}

func setKey(obj validation.Value, key string, val validation.Value) validation.Value {
	out := validation.VObj()
	done := false
	for _, pair := range obj.O {
		if pair.K == key {
			out.O = append(out.O, kv(key, val))
			done = true
			continue
		}
		out.O = append(out.O, pair)
	}
	if !done {
		out.O = append(out.O, kv(key, val))
	}
	return out
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func objInt(v validation.Value, key string) int64 {
	if x := objAt(v, key); x.Kind == validation.Int {
		return x.I
	}
	return 0
}

func arrContains(arr validation.Value, want string) bool {
	if arr.Kind != validation.Arr {
		return false
	}
	for _, x := range arr.A {
		if x.Kind == validation.Str && x.S == want {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}

func objEq(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, pair := range a.O {
			other := objAt(b, pair.K)
			if !objEq(pair.V, other) {
				return false
			}
		}
		return true
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !objEq(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I
	case validation.Flt:
		return a.F == b.F
	case validation.Bool:
		return a.B == b.B
	case validation.Null:
		return true
	}
	return false
}

var _ = json.Marshal
