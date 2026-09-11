package bounty

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/pricing"
	"websec/internal/risk"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// kv is the vet-clean keyed KV constructor (unkeyed cross-package literals
// are rejected by go vet).
func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// testPolicy is the POLICY dict of tests/test_bounty_policy.py, in literal
// order (the bounty_policy schema accepts it as-is).
func testPolicy() validation.Value {
	return validation.VObj(
		kv("program", validation.VStr("Acme Protocol Immunefi")),
		kv("program_url", validation.VStr("https://immunefi.com/acme")),
		kv("platform", validation.VStr("immunefi")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("asset_weight_usd", validation.VInt(50000000)),
		kv("scope", validation.VArr(
			validation.VObj(kv("target", validation.VStr("Vault")),
				kv("kind", validation.VStr("contract"))),
			validation.VObj(kv("target", validation.VStr(
				"0x1111111111111111111111111111111111111111")),
				kv("kind", validation.VStr("address"))),
		)),
		kv("exclusions", validation.VArr(
			validation.VObj(kv("pattern", validation.VStr("rounding dust")),
				kv("kind", validation.VStr("known-issue")),
				kv("reference", validation.VStr("program page known-issues section"))),
			validation.VObj(kv("pattern", validation.VStr("government seizure")),
				kv("kind", validation.VStr("intended-behavior"))),
		)),
		kv("severity_rules", validation.VArr(
			validation.VObj(kv("severity", validation.VStr("critical")),
				kv("match", validation.VObj(
					kv("bug_classes", validation.VArr(validation.VStr("access-control"))),
					kv("require_invariant_violation", validation.VBool(true))))),
			validation.VObj(kv("severity", validation.VStr("high")),
				kv("match", validation.VObj(
					kv("bug_classes", validation.VArr(validation.VStr("economic-invariant"),
						validation.VStr("oracle-manipulation"))),
					kv("min_extractable_usd", validation.VInt(100000))))),
		)),
		kv("poc_requirements", validation.VObj(
			kv("min_evidence_level", validation.VStr("E5")),
			kv("require_fork_repro", validation.VBool(true)))),
		kv("reporting", validation.VObj(
			kv("contact", validation.VStr("immunefi")),
			kv("required_fields", validation.VArr(validation.VStr("PoC"),
				validation.VStr("impact"))))),
	)
}

// policyWithEconomicFloor is POLICY with an economic-quantification clause
// (require_economic_quantification + min_extractable_usd).
func policyWithEconomicFloor(floor int64) validation.Value {
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "poc_requirements", validation.VObj(
		kv("min_evidence_level", validation.VStr("E5")),
		kv("require_fork_repro", validation.VBool(true)),
		kv("require_economic_quantification", validation.VBool(true)),
		kv("min_extractable_usd", validation.VInt(floor))))
	return p
}

// baseFinding is the gate-vector fixture (the Python generator's BASE dict).
func baseFinding() validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr("F-abc123")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("snapshot_ids", validation.VObj(
			kv("source", validation.VStr("SNAP-11111111")),
			kv("deployment", validation.VNull()),
			kv("chain", validation.VNull()))),
		kv("title", validation.VStr("Attacker withdraws unbacked funds via price skew")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("cwe", validation.VStr("CWE-682")),
			kv("description", validation.VStr(
				"spot price read lets attacker trade against own price")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("borrow"))))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("protocol-solvency")),
			kv("extractable_usd", validation.VInt(1500000)),
			kv("price_basis", validation.VStr("PRICE-0001")))),
		kv("evidence", validation.VArr(
			validation.VObj(kv("evidence_id", validation.VStr("EV-l")),
				kv("level", validation.VStr("E4")),
				kv("type", validation.VStr("foundry-test")),
				kv("description", validation.VStr("local harness repro")),
				kv("sandbox_profile", validation.VStr("docker-networkless")),
				kv("artifact_id", validation.VStr("EXEC-0000000001"))),
			validation.VObj(kv("evidence_id", validation.VStr("EV-1")),
				kv("level", validation.VStr("E5")),
				kv("type", validation.VStr("fork-test")),
				kv("description", validation.VStr("fork repro extracts 1.5M")),
				kv("sandbox_profile", validation.VStr("fork-runner")),
				kv("artifact_id", validation.VStr("EXEC-0000000002"))),
			validation.VObj(kv("evidence_id", validation.VStr("EV-2")),
				kv("level", validation.VStr("E1")),
				kv("type", validation.VStr("manual")),
				kv("description", validation.VStr("negative-mode checked"))))),
		kv("verification", validation.VObj(kv("reproduction", validation.VObj(
			kv("tier_reached", validation.VStr("T3")),
			kv("status", validation.VStr("reproduced")),
			kv("attempts", validation.VArr()))))),
		kv("preconditions", validation.VArr()),
		kv("exploitability", exploitabilityObj()),
	)
}

// withField replaces one top-level key of a finding copy.
func withField(f validation.Value, key string, v validation.Value) validation.Value {
	out := validation.Value{Kind: validation.Obj, O: append([]validation.KV(nil), f.O...)}
	out.O = validation.SetOrAppend(out.O, key, v)
	return out
}

// withoutField drops one top-level key from a finding copy.
func withoutField(f validation.Value, key string) validation.Value {
	out := validation.Value{Kind: validation.Obj, O: []validation.KV{}}
	for _, k := range f.O {
		if k.K != key {
			out.O = append(out.O, k)
		}
	}
	return out
}

// testExploitabilityArgument is the A4 answer the submission-ready fixtures
// record: who pays (the protocol treasury) and why the bug makes them pay
// (unbacked withdrawals priced against a stale spot read). It clears the
// 200-char floor findings.ExploitabilityArgumentMin enforces.
const testExploitabilityArgument = "Who pays: the protocol itself — the vault " +
	"treasury is the counterparty funding every unbacked withdrawal. Why the " +
	"bug makes them pay: the spot-price read lets an arbitrary EOA trade " +
	"against its own price impact, so each borrow priced at the stale value " +
	"mints what the pool never held; the E5 fork repro measured $1,500,000 " +
	"extractable against the pinned ACME price (PRICE-0001), above the " +
	"program's $100,000 high-band floor for protocol-solvency impact, and the " +
	"loss lands on protocol solvency rather than on any single user's " +
	"balance."

// exploitabilityObj is the A4 record baseFinding carries (paid, argument).
func exploitabilityObj() validation.Value {
	return validation.VObj(
		kv("paid", validation.VBool(true)),
		kv("argument", validation.VStr(testExploitabilityArgument)))
}

// withNested replaces f[outer][inner] (an absent outer object is created).
func withNested(f validation.Value, outer, inner string, v validation.Value) validation.Value {
	o := objAt(f, outer)
	if o.Kind != validation.Obj {
		o = validation.VObj()
	}
	o.O = validation.SetOrAppend(o.O, inner, v)
	return withField(f, outer, o)
}

// anyContains is any(substring in reason for reason in blocking_reasons).
func anyContains(list validation.Value, sub string) bool {
	for _, r := range list.A {
		if r.Kind == validation.Str && strings.Contains(r.S, sub) {
			return true
		}
	}
	return false
}

// strValues wraps strings as a JSON array value.
func strValues(items []string) []validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return out
}

// seamStub is the fixed answer of the unported-module seams.
type seamStub struct {
	ladder    validation.Value
	price     validation.Value
	forkOK    bool
	forkWhy   string
	waivers   []validation.Value
	immState  string
	immDetail string
	// B4: contract-name → source-path map for the scope check's resolver seam.
	contractPaths map[string]string
}

// installSeams wires the five seams to the stub and restores the defaults on
// cleanup.
func installSeams(t *testing.T, s seamStub) {
	t.Helper()
	SetLoadLadder(func(*state.Campaign, string) (validation.Value, error) {
		return s.ladder, nil
	})
	SetPriceRow(func(*state.Campaign, string) (validation.Value, error) {
		return s.price, nil
	})
	SetForkPocStatus(func(*state.Campaign, string) (bool, string, error) {
		return s.forkOK, s.forkWhy, nil
	})
	// Stage-aware: mirrors completion.Waivers(c, stage), which filters rows
	// by exact stage match. (B1: check12 now consults the "immunization"
	// stage, so a fork-PoC waiver must not leak into it.)
	SetWaivers(func(_ *state.Campaign, stage string) ([]validation.Value, error) {
		var out []validation.Value
		for _, w := range s.waivers {
			if objStr(w, "stage") == stage {
				out = append(out, w)
			}
		}
		return out, nil
	})
	SetImmunizationDetail(func(validation.Value) (string, string) {
		return s.immState, s.immDetail
	})
	// B4: contract-name → source-path resolver. Empty map (or absent key)
	// yields "", the pre-B4 name-only behaviour.
	SetContractPathResolver(func(_ *state.Campaign, name string) string {
		return s.contractPaths[name]
	})
	t.Cleanup(func() {
		SetLoadLadder(nil)
		SetPriceRow(nil)
		SetForkPocStatus(nil)
		SetWaivers(nil)
		SetImmunizationDetail(nil)
		SetContractPathResolver(nil)
	})
}

// ladderComplete is the closed variant ladder make_submission_ready builds.
func ladderComplete() validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr("F-abc123")),
		kv("disposition", validation.VObj(
			kv("state", validation.VStr("complete")),
			kv("reason", validation.VNull()))),
		kv("maximal_rung_id", validation.VStr("R-abc123")),
		kv("axes_explored", validation.VArr(strValues(maximalAxes)...)),
		kv("variants", validation.VArr()),
	)
}

// priceRowFor is the price row PR.set_price records in the fixture (price
// ids are PRC-<6+ lowercase alnum>, which the finding schema enforces).
func priceRowFor(priceID string) validation.Value {
	return validation.VObj(
		kv("price_id", validation.VStr(priceID)),
		kv("asset", validation.VStr("ACME")),
		kv("usd", validation.VFloat(1.0)),
		kv("source", validation.VStr("fixture: fixed reference price")),
	)
}

// submissionReadySeamsFor is the seam state make_submission_ready produces
// for a finding priced against priceID.
func submissionReadySeamsFor(priceID string) seamStub {
	return seamStub{
		ladder:   ladderComplete(),
		price:    priceRowFor(priceID),
		forkOK:   true,
		forkWhy:  "fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)",
		immState: "immunized",
		immDetail: "patch blocks the fork PoC and all 3 boundary mutations " +
			"(basis: EXEC-0000000002)",
	}
}

// submissionReadySeams is the vector-flavor seam state (the vector fixtures
// are written raw, so they keep the generator's PRICE-0001 id).
func submissionReadySeams() seamStub { return submissionReadySeamsFor("PRICE-0001") }

var execSeq int

// execRecord writes the EXEC ledger row of a sandboxed run
// (sandbox.register_exec lands in P1+).
func execRecord(t *testing.T, c *state.Campaign, profile, findingID,
	command string) validation.Value {
	t.Helper()
	execSeq++
	execID := fmt.Sprintf("EXEC-%010x", execSeq)
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout, []byte("PASS: test_exploit\n"), 0o644); err != nil {
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
		kv("exit_status", validation.VInt(0)),
		kv("stdout_path", validation.VStr(stdout)),
		kv("stderr_path", validation.VStr(stderr)),
	)
	path := filepath.Join(dir, "exec_record.json")
	if err := validation.WriteJson(path, rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// evidenceItem is conftest.evidence_item: an E4+ item that traces to rec.
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

// fixtureCampaign is the `camp` fixture: a campaign with a pinned target.
func fixtureCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "t")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// fixturePayload is the ingest payload of camp_with_confirmed.
func fixturePayload() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr("Attacker withdraws unbacked funds via price skew")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("cwe", validation.VStr("CWE-682")),
			kv("description", validation.VStr(
				"spot price read lets attacker trade against own price")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("borrow"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("protocol-solvency")),
			kv("extractable_usd", validation.VInt(1500000)))),
	)
}

// fixtureConfirmed records the local + fork PoCs and forces the CONFIRMED
// state the Python fixture reaches through findings.transition() and
// risk.mint_impact_evidence().
func fixtureConfirmed(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, fixturePayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	local := execRecord(t, c, "docker-networkless", fid,
		"forge test --match-test test_exploit")
	fork := execRecord(t, c, "fork-runner", fid,
		"forge test --fork-url http://127.0.0.1:8545 --match-test test_exploit")
	if _, err := findings.AddEvidence(c, fid,
		evidenceItem(local, "E4", "foundry-test", "local harness repro", "EV-l")); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, fid,
		evidenceItem(fork, "E5", "fork-test", "fork repro extracts 1.5M", "EV-1")); err != nil {
		t.Fatal(err)
	}
	manual := validation.VObj(
		kv("evidence_id", validation.VStr("EV-2")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("negative-mode checked")))
	if _, err := findings.AddEvidence(c, fid, manual); err != nil {
		t.Fatal(err)
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f = withField(f, "status", validation.VStr("CONFIRMED"))
	f = withNested(f, "verification", "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T3")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	ei := objAt(f, "economic_impact")
	ei.O = validation.SetOrAppend(ei.O, "price_basis", validation.VStr("PRC-abc123"))
	f = withField(f, "economic_impact", ei)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	// A4: the submission chain answers "who pays, and why" — without it the
	// gate's paid-exploitability check (check14) blocks every CONFIRMED
	// extractable finding.
	if _, err := findings.SetExploitability(c, fid, true,
		testExploitabilityArgument); err != nil {
		t.Fatal(err)
	}
	return fid
}

// bountyFixture is the camp_with_confirmed fixture of
// tests/test_bounty_policy.py: a campaign with a pinned target and a
// CONFIRMED finding whose ladder carries the E4 local PoC and the E5 fork
// PoC, plus the submission chain the gate's last checks read.
//
// PORT-NOTE: the Python fixture closes that chain through
// maximization/pricing/immunize/fork_poc/completion and moves the status
// through findings.transition() + risk.mint_impact_evidence(); the Go fixture
// records the exec/evidence rows directly and installs the seams with the
// values make_submission_ready would produce. Its evidence tops out at E5
// (Python mints an E7 impact row through risk.mint_impact_evidence), which no
// ported assertion depends on: the program floor is E5 either way. The gate
// assertions themselves are ported 1:1.
func bountyFixture(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	installSeams(t, submissionReadySeamsFor("PRC-abc123"))
	return c, fid
}

// wantBadPolicyError is str(SchemaError) for the policy {"program": "Acme"},
// generated from the Python twin (validation.validate default max_errors).
const wantBadPolicyError = "bounty_policy validation failed at <root>: 'program_url' is a required property (+4 more errors)"

// wantPolicyFile is the exact file save_policy writes for POLICY:
// json.dumps(policy, indent=2, ensure_ascii=False) + "\n".
const wantPolicyFile = "{\n  \"program\": \"Acme Protocol Immunefi\",\n  \"program_url\": \"https://immunefi.com/acme\",\n  \"platform\": \"immunefi\",\n  \"chains\": [\n    \"ethereum\"\n  ],\n  \"asset_weight_usd\": 50000000,\n  \"scope\": [\n    {\n      \"target\": \"Vault\",\n      \"kind\": \"contract\"\n    },\n    {\n      \"target\": \"0x1111111111111111111111111111111111111111\",\n      \"kind\": \"address\"\n    }\n  ],\n  \"exclusions\": [\n    {\n      \"pattern\": \"rounding dust\",\n      \"kind\": \"known-issue\",\n      \"reference\": \"program page known-issues section\"\n    },\n    {\n      \"pattern\": \"government seizure\",\n      \"kind\": \"intended-behavior\"\n    }\n  ],\n  \"severity_rules\": [\n    {\n      \"severity\": \"critical\",\n      \"match\": {\n        \"bug_classes\": [\n          \"access-control\"\n        ],\n        \"require_invariant_violation\": true\n      }\n    },\n    {\n      \"severity\": \"high\",\n      \"match\": {\n        \"bug_classes\": [\n          \"economic-invariant\",\n          \"oracle-manipulation\"\n        ],\n        \"min_extractable_usd\": 100000\n      }\n    }\n  ],\n  \"poc_requirements\": {\n    \"min_evidence_level\": \"E5\",\n    \"require_fork_repro\": true\n  },\n  \"reporting\": {\n    \"contact\": \"immunefi\",\n    \"required_fields\": [\n      \"PoC\",\n      \"impact\"\n    ]\n  }\n}\n"

// ---- ported tests (tests/test_bounty_policy.py) ----

func TestFullSubmissionReady(t *testing.T) {
	c, fid := bountyFixture(t)
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || !got.B {
		t.Errorf("submission_ready = %s, want True", validation.PyRepr(got))
	}
	if got := objAt(result, "eligible"); got.Kind != validation.Bool || !got.B {
		t.Errorf("eligible = %s, want True", validation.PyRepr(got))
	}
	if br := objAt(result, "blocking_reasons"); br.Kind != validation.Arr || len(br.A) != 0 {
		t.Errorf("blocking_reasons = %s, want []", validation.CanonCompact(br))
	}
	if checks := objAt(result, "policy_checks"); len(checks.A) != 16 {
		t.Errorf("policy_checks = %d rows, want 16", len(checks.A))
	}
}

// TestImmunizationWaiverUnblocks (B1): a CONFIRMED finding that is NOT
// immunized is still submission_ready when an explicit immunization waiver
// covers it (mirroring the fork-PoC waiver); without the waiver the same
// finding is blocked by "not immunized".
func TestImmunizationWaiverUnblocks(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.immState = "missing"
	stub.immDetail = "no patch recorded"
	stub.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("immunization")),
		kv("subject", validation.VStr("*")),
		kv("reason", validation.VStr(
			"patch lands in a follow-up PR; fork PoC waived for the same submission")),
		kv("actor", validation.VStr("alice")),
	)}
	installSeams(t, stub)
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || !got.B {
		t.Errorf("submission_ready = %s, want True (waiver unblocks immunization)",
			validation.PyRepr(got))
	}
	if anyContains(objAt(result, "blocking_reasons"), "not immunized") {
		t.Errorf("unexpected immunization blocker in %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
	found := false
	for _, ck := range objAt(result, "policy_checks").A {
		if objStr(ck, "check") == "immunization" {
			found = true
			if objStr(ck, "result") != "pass" {
				t.Errorf("immunization result = %s, want pass",
					objStr(ck, "result"))
			}
			if !strings.Contains(objStr(ck, "detail"), "waived by alice") {
				t.Errorf("immunization detail = %q, want 'waived by alice'",
					objStr(ck, "detail"))
			}
		}
	}
	if !found {
		t.Error("no immunization row in policy_checks")
	}

	// No waiver: the same finding is blocked on immunization.
	c2 := fixtureCampaign(t)
	fid2 := fixtureConfirmed(t, c2)
	stub2 := submissionReadySeamsFor("PRC-abc123")
	stub2.immState = "missing"
	stub2.immDetail = "no patch recorded"
	installSeams(t, stub2)
	result2, err := EvaluateBountyGate(c2, fid2, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result2, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False (no waiver)",
			validation.PyRepr(got))
	}
	if !anyContains(objAt(result2, "blocking_reasons"), "not immunized") {
		t.Errorf("expected 'not immunized' blocker in %s",
			validation.CanonCompact(objAt(result2, "blocking_reasons")))
	}
}

func TestOutOfScopeTargetBlocks(t *testing.T) {
	c, fid := bountyFixture(t)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	aff := objAt(f, "affected")
	aff.A[0].O = validation.SetOrAppend(aff.A[0].O, "contract", validation.VStr("RandomToken"))
	f = withField(f, "affected", aff)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False", validation.PyRepr(got))
	}
	if !anyContains(objAt(result, "blocking_reasons"), "scope") {
		t.Errorf("no scope blocker in %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
}

// B4: a name-carrying finding matches a path-based scope entry only if the
// contract name resolves to its source path via the structural index. The
// campaign's false "everything is out of scope" was the name never resolving
// to the path the scope named.
func TestScopeResolvesContractNameToPath(t *testing.T) {
	f := baseFinding()
	// A name-only affected component (no path) — the shape that previously
	// could never match a path-based scope entry.
	f = withField(f, "affected", validation.VArr(
		validation.VObj(kv("contract", validation.VStr("Vault")))))
	// A path-based scope entry: only the resolved path can match it.
	policy := testPolicy()
	policy.O = validation.SetOrAppend(policy.O, "scope", validation.VArr(
		validation.VObj(kv("target", validation.VStr("src/Vault.sol")),
			kv("kind", validation.VStr("path")))))

	scopeResult := func(t *testing.T, seams seamStub) string {
		t.Helper()
		installSeams(t, seams)
		c := vectorCamp(t, "")
		g := &gate{campaign: c, policy: policy, f: f}
		if err := g.check3(); err != nil {
			t.Fatal(err)
		}
		return objStr(g.checks[0], "result")
	}

	t.Run("name_only_without_resolver_is_out_of_scope", func(t *testing.T) {
		if got := scopeResult(t, seamStub{}); got != "fail" {
			t.Errorf("in-scope = %s, want fail (pre-B4 name-only behaviour)", got)
		}
	})
	t.Run("resolver_maps_name_to_path_is_in_scope", func(t *testing.T) {
		got := scopeResult(t, seamStub{
			contractPaths: map[string]string{"Vault": "src/Vault.sol"}})
		if got != "pass" {
			t.Errorf("in-scope = %s, want pass (B4 resolves the name to the path)", got)
		}
	})
}

func TestKnownIssueBlocks(t *testing.T) {
	c, fid := bountyFixture(t)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	rc := objAt(f, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "description", validation.VStr(
		objStr(rc, "description")+" — effectively rounding dust accounting"))
	f = withField(f, "root_cause", rc)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False", validation.PyRepr(got))
	}
	if !anyContains(objAt(result, "blocking_reasons"), "excluded") {
		t.Errorf("no exclusion blocker in %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
}

func TestEvidenceFloorBlocks(t *testing.T) {
	c, fid := bountyFixture(t)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	var kept []validation.Value
	for _, e := range objAt(f, "evidence").A {
		lvl := objStr(e, "level")
		if lvl < "E5" || lvl == "E1" {
			kept = append(kept, e)
		}
	}
	f = withField(f, "evidence", validation.Value{Kind: validation.Arr, A: kept})
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False", validation.PyRepr(got))
	}
	if !anyContains(objAt(result, "blocking_reasons"), "evidence") {
		t.Errorf("no evidence blocker in %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
}

func TestMissingForkReproBlocks(t *testing.T) {
	c, fid := bountyFixture(t)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(f, "verification")
	repro := objAt(ver, "reproduction")
	repro.O = validation.SetOrAppend(repro.O, "tier_reached", validation.VStr("T1"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", repro)
	f = withField(f, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False", validation.PyRepr(got))
	}
	if !anyContains(objAt(result, "blocking_reasons"), "fork") {
		t.Errorf("no fork blocker in %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
}

func TestUnconfirmedNeverReady(t *testing.T) {
	c, fid := bountyFixture(t)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f = withField(f, "status", validation.VStr("HYPOTHESIS")) // force
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "eligible"); got.Kind != validation.Bool || got.B {
		t.Errorf("eligible = %s, want False", validation.PyRepr(got))
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False", validation.PyRepr(got))
	}
}

func TestSeverityRuleMatching(t *testing.T) {
	policy := testPolicy()
	sev, why, err := SeverityFor(policy, validation.VObj(
		kv("root_cause", validation.VObj(kv("class", validation.VStr("access-control")))),
		kv("invariant", validation.VObj(kv("violation_demonstrated", validation.VBool(true)))),
		kv("economic_impact", validation.VObj())))
	if err != nil {
		t.Fatal(err)
	}
	if sev != "critical" {
		t.Errorf("sev = %q, want critical", sev)
	}
	if why != "matched severity rule for critical" {
		t.Errorf("why = %q", why)
	}
	sev2, _, err := SeverityFor(policy, validation.VObj(
		kv("root_cause", validation.VObj(kv("class", validation.VStr("oracle-manipulation")))),
		kv("economic_impact", validation.VObj(kv("extractable_usd", validation.VInt(200000))))))
	if err != nil {
		t.Fatal(err)
	}
	if sev2 != "high" {
		t.Errorf("sev2 = %q, want high", sev2)
	}
	sev3, why3, err := SeverityFor(policy, validation.VObj(
		kv("root_cause", validation.VObj(kv("class", validation.VStr("dos-griefing")))),
		kv("economic_impact", validation.VObj())))
	if err != nil {
		t.Fatal(err)
	}
	if sev3 != "" {
		t.Errorf("sev3 = %q, want None", sev3)
	}
	if why3 != "no severity rule matched" {
		t.Errorf("why3 = %q", why3)
	}
}

// ---- byte-exact vectors (every golden below is generated by the Python
// twin: .scratch/bounty/gen_go.py emits the CanonSpaced bounty dict, the
// gate_explain catalog and the predicate vectors from webv2.bounty_policy) ----

// vectorCase is one gate vector: the fixture plus the fixed answers of the
// five unported-module seams.
type vectorCase struct {
	policy  validation.Value
	finding validation.Value
	active  string // "" = no active snapshot pin
	seams   seamStub
}

// vectorCamp is a campaign whose active snapshot id is active ("" = none).
func vectorCamp(t *testing.T, active string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if active == "" {
		return c
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "active_snapshot_id", validation.VStr(active))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	return c
}

// writeFinding writes a raw finding row (the vector tests never save through
// the schema-validating writer).
func writeFinding(t *testing.T, c *state.Campaign, f validation.Value) {
	t.Helper()
	path := filepath.Join(c.FindingsDir, objStr(f, "finding_id")+".json")
	if err := validation.WriteJson(path, f, ""); err != nil {
		t.Fatal(err)
	}
}

// ladderOpen is the half-explored ladder: two axes missing, one rung that
// removed the staking precondition.
func ladderOpen() validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr("F-abc123")),
		kv("disposition", validation.VObj(
			kv("state", validation.VStr("open")),
			kv("reason", validation.VNull()))),
		kv("maximal_rung_id", validation.VStr("R-abc123")),
		kv("axes_explored", validation.VArr(
			validation.VStr("capital-minimization"),
			validation.VStr("role-conflation"),
			validation.VStr("cap-saturation"))),
		kv("variants", validation.VArr(validation.VObj(
			kv("rung_id", validation.VStr("R-1")),
			kv("removed_preconditions", validation.VArr(
				validation.VStr("victim must stake before the attack")))))),
	)
}

// vectorCases is the gate-vector table, keyed by gateVectorOrder.
func vectorCases() map[string]vectorCase {
	cases := map[string]vectorCase{}
	vectorPassCases(cases)
	vectorLadderCases(cases)
	vectorUnconfirmedCases(cases)
	vectorFlagCases(cases)
	vectorExploitabilityCases(cases)
	vectorAdversarialCases(cases)
	vectorAckCases(cases)
	return cases
}

// vectorExploitabilityCases is the A4 (paid-exploitability, check14)
// matrix: the missing answer blocks, a hand-edited short argument blocks,
// the named waiver clears the block, and a reasoned not-payable decision
// passes.
func vectorExploitabilityCases(cases map[string]vectorCase) {
	// exploitability_missing: full_pass minus the answer — CONFIRMED +
	// extractable + no exploitability.
	cases["exploitability_missing"] = vectorCase{
		policy:  testPolicy(),
		finding: withoutField(baseFinding(), "exploitability"),
		active:  "SNAP-11111111", seams: submissionReadySeams(),
	}

	// exploitability_short: a hand-edited paid=true with a stub argument
	// (below the 200-char floor) — the gate re-validates stored values.
	cases["exploitability_short"] = vectorCase{
		policy: testPolicy(),
		finding: withField(baseFinding(), "exploitability", validation.VObj(
			kv("paid", validation.VBool(true)),
			kv("argument", validation.VStr("users lose funds")))),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}

	// exploitability_waived: the missing answer is waived per-finding —
	// the row passes, the blocker is gone, the finding stays submittable.
	ew := submissionReadySeams()
	ew.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("paid-exploitability")),
		kv("subject", validation.VStr("F-abc123")),
		kv("reason", validation.VStr(
			"argument deferred to the report body; payer is the treasury")),
		kv("actor", validation.VStr("carol")))}
	cases["exploitability_waived"] = vectorCase{
		policy:  testPolicy(),
		finding: withoutField(baseFinding(), "exploitability"),
		active:  "SNAP-11111111", seams: ew,
	}

	// exploitability_unpaid: a reasoned decision that the finding is NOT
	// payable — allowed, the gate does not demand a payer for no-payer
	// findings.
	cases["exploitability_unpaid"] = vectorCase{
		policy: testPolicy(),
		finding: withField(baseFinding(), "exploitability", validation.VObj(
			kv("paid", validation.VBool(false)),
			kv("argument", validation.VStr(
				"the skew is bounded by the TWAP window; no counterparty "+
					"pays beyond normal price risk — documented below the "+
					"program's de-minimis line")))),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
}

// livenessFinding is baseFinding re-typed as a liveness finding (the
// check15 trigger, economic_impact.kind == "liveness" — the B1
// materialized-chain shape): the gate then owes the adversarial-game
// clause. The class stays oracle-manipulation so the severity rule still
// matches — the matrix isolates check15, and the class/capability
// triggers are covered by TestIsLivenessFinding in internal/findings.
func livenessFinding() validation.Value {
	ei := objAt(baseFinding(), "economic_impact")
	ei.O = validation.SetOrAppend(ei.O, "kind", validation.VStr("liveness"))
	return withField(baseFinding(), "economic_impact", ei)
}

// adversarialClause is a complete adversarial_game clause: every field
// clears the 20-rune floor with an actual incentive argument.
func adversarialClause() validation.Value {
	return validation.VObj(
		kv("who_profits", validation.VStr(
			"the sequencer operator — every frozen hour pays their uptime "+
				"fees while rival bridges lose the deposits in transit")),
		kv("profit_mechanism", validation.VStr(
			"freezing withdrawals lets the operator's own staked position "+
				"absorb the fee flow while the halted bridge bleeds TVL "+
				"to competitors")),
		kv("challenge_interplay", validation.VStr(
			"the timelock challenge path expires into a no-op once the "+
				"upgrade queue is blocked, so the freeze cannot be voted "+
				"away before the challenge window closes")))
}

// vectorAdversarialCases is the B2 (adversarial-game, check15) matrix: the
// missing clause blocks a liveness finding, a hand-edited short field
// blocks, the named waiver clears the block, and the complete clause
// passes.
func vectorAdversarialCases(cases map[string]vectorCase) {
	// adversarial_missing: a liveness finding with no clause — the
	// incentive question was never answered.
	cases["adversarial_missing"] = vectorCase{
		policy: testPolicy(), finding: livenessFinding(),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}

	// adversarial_short: a hand-edited clause with a stub
	// profit_mechanism (below the 20-char floor) — the gate re-validates
	// the stored value.
	cases["adversarial_short"] = vectorCase{
		policy: testPolicy(),
		finding: withField(livenessFinding(), "adversarial_game",
			validation.VObj(
				kv("who_profits", objAt(adversarialClause(), "who_profits")),
				kv("profit_mechanism", validation.VStr("short")),
				kv("challenge_interplay", objAt(adversarialClause(),
					"challenge_interplay")))),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}

	// adversarial_waived: the missing clause is waived per-finding — a
	// named, recorded decision that the incentive answer lives elsewhere
	// (the chain narrative).
	aw := submissionReadySeams()
	aw.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("adversarial-game")),
		kv("subject", validation.VStr("F-abc123")),
		kv("reason", validation.VStr(
			"the incentive argument lives in the chain narrative: C-0002 "+
				"pays the operator per frozen hour")),
		kv("actor", validation.VStr("carol")))}
	cases["adversarial_waived"] = vectorCase{
		policy: testPolicy(), finding: livenessFinding(),
		active: "SNAP-11111111", seams: aw,
	}

	// adversarial_complete: the clause answers all three questions —
	// check15 passes and the finding stays submittable.
	cases["adversarial_complete"] = vectorCase{
		policy: testPolicy(),
		finding: withField(livenessFinding(), "adversarial_game",
			adversarialClause()),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
}

// vectorAckCases is the A2 (in-code acknowledgement) advisory vector: the
// full pass carries a dedup_meta.in_code_ack record, so the gate result
// gains the advisory — it never blocks.
func vectorAckCases(cases map[string]vectorCase) {
	cases["ack_advisory"] = vectorCase{
		policy: testPolicy(),
		finding: withField(baseFinding(), "dedup_meta", validation.VObj(
			kv("in_code_ack", validation.VObj(
				kv("file", validation.VStr("src/Vault.sol")),
				kv("line", validation.VInt(42)),
				kv("phrase", validation.VStr("todo")),
				kv("window", validation.VStr("12")))))),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
}

// vectorPassCases is full_pass + ladder_missing.
func vectorPassCases(cases map[string]vectorCase) {
	cases["full_pass"] = vectorCase{
		policy: testPolicy(), finding: baseFinding(),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}

	// ladder_missing: a CONFIRMED finding with no ladder row and no price
	// basis for its USD figure.
	lm := submissionReadySeams()
	lm.ladder, lm.price = validation.VNull(), validation.VNull()
	cases["ladder_missing"] = vectorCase{
		policy: testPolicy(),
		finding: withField(baseFinding(), "economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("protocol-solvency")),
			kv("extractable_usd", validation.VInt(1500000)))),
		active: "SNAP-11111111", seams: lm,
	}
}

// vectorLadderCases is ladder_open + ladder_waived, the two ladder
// dispositions that reach the precondition audit.
func vectorLadderCases(cases map[string]vectorCase) {
	// ladder_open: open ladder, two unexplored axes, an unaddressed
	// code-unenforced precondition, no price basis, and a claim/measurement
	// drift in the title.
	lo := submissionReadySeams()
	lo.ladder, lo.price = ladderOpen(), validation.VNull()
	pre := validation.VArr(
		validation.VObj(kv("description", validation.VStr("victim must stake before the attack")),
			kv("enforced_by_poc", validation.VStr("false"))),
		validation.VObj(kv("description", validation.VStr("pool must hold at least one wei of dust")),
			kv("enforced_by_poc", validation.VStr("false"))),
		validation.VObj(kv("description", validation.VStr("attacker holds an EOA")),
			kv("enforced_by_poc", validation.VStr("true"))))
	loFinding := withField(baseFinding(), "title", validation.VStr(
		"Attacker drains 50% of the vault via price skew"))
	loFinding = withField(loFinding, "economic_impact", validation.VObj(
		kv("blast_radius", validation.VStr("protocol-solvency")),
		kv("extractable_usd", validation.VInt(1500000)),
		kv("extraction_ratio", validation.VFloat(1.0))))
	loFinding = withField(loFinding, "preconditions", pre)
	cases["ladder_open"] = vectorCase{
		policy: testPolicy(), finding: loFinding,
		active: "SNAP-11111111", seams: lo,
	}

	// ladder_waived: the named waiver closes the ladder, so the two
	// code-unenforced preconditions are covered by it.
	lw := submissionReadySeams()
	lw.ladder = validation.VObj(
		kv("finding_id", validation.VStr("F-abc123")),
		kv("disposition", validation.VObj(
			kv("state", validation.VStr("waived")),
			kv("reason", validation.VStr("the operator decided that this rung is "+
				"out of reach for the campaign budget and closed the ladder by waiver")),
			kv("actor", validation.VStr("pytest-harness")))),
		kv("maximal_rung_id", validation.VStr("R-abc123")),
		kv("axes_explored", validation.VArr(strValues(maximalAxes)...)),
		kv("variants", validation.VArr()))
	cases["ladder_waived"] = vectorCase{
		policy: testPolicy(),
		finding: withField(baseFinding(), "preconditions", validation.VArr(
			pre.A[0], pre.A[1])),
		active: "SNAP-11111111", seams: lw,
	}
}

// vectorUnconfirmedCases is not_confirmed: every unknown / human-review
// / waiver branch at once.
func vectorUnconfirmedCases(cases map[string]vectorCase) {
	// not_confirmed: every unknown / human-review / waiver branch at once.
	nc := submissionReadySeams()
	nc.ladder, nc.price = validation.VNull(), validation.VNull()
	nc.forkOK, nc.forkWhy = false, "no fork PoC proven"
	nc.immState = "missing"
	nc.immDetail = "no patch verification recorded (webv2 immunize ... against the FORK PoC)"
	nc.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("mainnet-fork-poc")),
		kv("subject", validation.VStr("*")),
		kv("reason", validation.VStr("the pinned RPC was retired by the provider "+
			"and the archive node is offline for this campaign")),
		kv("actor", validation.VStr("pytest-harness")),
		kv("at", validation.VStr("2026-01-01T00:00:00+00:00")))}
	ncFinding := baseFinding()
	ncFinding = withField(ncFinding, "status", validation.VStr("HYPOTHESIS"))
	ncFinding = withField(ncFinding, "root_cause", validation.VObj(
		kv("class", validation.VStr("dos-griefing")),
		kv("description", validation.VStr("attacker blocks withdrawals — "+
			"effectively rounding dust accounting"))))
	ncFinding = withField(ncFinding, "affected", validation.VArr())
	ncFinding = withField(ncFinding, "economic_impact", validation.VObj(
		kv("extractable_usd", validation.VInt(1000))))
	ncFinding = withField(ncFinding, "evidence", validation.VArr(
		validation.VObj(kv("evidence_id", validation.VStr("EV-1")),
			kv("level", validation.VStr("E1")),
			kv("type", validation.VStr("manual")),
			kv("description", validation.VStr("note")))))
	ncFinding = withNested(ncFinding, "verification", "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T1")),
		kv("status", validation.VStr("attempted")),
		kv("attempts", validation.VArr())))
	cases["not_confirmed"] = vectorCase{
		policy: policyWithEconomicFloor(100000), finding: ncFinding,
		active: "", seams: nc,
	}
}

// vectorFlagCases is the single-flag vectors.
func vectorFlagCases(cases map[string]vectorCase) {
	// no_usd_no_affected: the price-basis check is skipped and scope is
	// unknown.
	cases["no_usd_no_affected"] = vectorCase{
		policy: testPolicy(),
		finding: withField(withField(baseFinding(), "economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("protocol-solvency")))), "affected",
			validation.VArr()),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
	// evidence_floor: the E5 fork evidence is gone, so the finding sits at E4.
	var kept []validation.Value
	for _, e := range objAt(baseFinding(), "evidence").A {
		if objStr(e, "level") < "E5" || objStr(e, "level") == "E1" {
			kept = append(kept, e)
		}
	}
	cases["evidence_floor"] = vectorCase{
		policy: testPolicy(),
		finding: withField(baseFinding(), "evidence",
			validation.Value{Kind: validation.Arr, A: kept}),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
	// fork_tier: the recorded reproduction tier is T1.
	cases["fork_tier"] = vectorCase{
		policy: testPolicy(),
		finding: withNested(baseFinding(), "verification", "reproduction",
			validation.VObj(kv("tier_reached", validation.VStr("T1")),
				kv("status", validation.VStr("reproduced")),
				kv("attempts", validation.VArr()))),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
	// out_of_scope: the affected component is not in the program scope.
	oos := baseFinding()
	aff := objAt(oos, "affected")
	aff.A[0].O = validation.SetOrAppend(aff.A[0].O, "contract", validation.VStr("RandomToken"))
	cases["out_of_scope"] = vectorCase{
		policy: testPolicy(), finding: withField(oos, "affected", aff),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
	// known_issue: the description trips the "rounding dust" exclusion.
	ki := baseFinding()
	rc := objAt(ki, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "description", validation.VStr(
		objStr(rc, "description")+" — effectively rounding dust accounting"))
	cases["known_issue"] = vectorCase{
		policy: testPolicy(), finding: withField(ki, "root_cause", rc),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
	// economic_below_floor: the program requires E7 quantification at $2M.
	cases["economic_below_floor"] = vectorCase{
		policy: policyWithEconomicFloor(2000000), finding: baseFinding(),
		active: "SNAP-11111111", seams: submissionReadySeams(),
	}
	// immunization_bypass: the patch does not hold at the boundary.
	ib := submissionReadySeams()
	ib.immState = "bypass"
	ib.immDetail = "boundary bypass found: calling via delegatecall from a " +
		"proxy skips the check — the patch does not hold"
	cases["immunization_bypass"] = vectorCase{
		policy: testPolicy(), finding: baseFinding(),
		active: "SNAP-11111111", seams: ib,
	}
}
func TestGateVectorsByteExact(t *testing.T) {
	cases := vectorCases()
	if len(cases) != len(gateVectorOrder) {
		t.Fatalf("vector cases = %d, order = %d", len(cases), len(gateVectorOrder))
	}
	if len(gateGolden) != len(gateVectorOrder) {
		t.Fatalf("goldens = %d, order = %d", len(gateGolden), len(gateVectorOrder))
	}
	for _, name := range gateVectorOrder {
		tc, ok := cases[name]
		if !ok {
			t.Fatalf("missing vector case %q", name)
		}
		t.Run(name, func(t *testing.T) {
			c := vectorCamp(t, tc.active)
			writeFinding(t, c, tc.finding)
			installSeams(t, tc.seams)
			got, err := EvaluateBountyGate(c, objStr(tc.finding, "finding_id"),
				tc.policy, false)
			if err != nil {
				t.Fatal(err)
			}
			gotJSON := validation.CanonSpaced(got)
			// The recorded capture is the Python twin's — its remediation
			// carries the <campaign> metavariable. The port names the
			// campaign in hand, so the metavariable must be gone and the id
			// present; mask the id back for the byte comparison so the rest
			// of the capture stays pinned.
			if strings.Contains(gateGolden[name], "<campaign>") {
				if strings.Contains(gotJSON, "<campaign>") {
					t.Errorf("bounty dict still carries the campaign "+
						"metavariable:\n%s", gotJSON)
				}
				gotJSON = strings.ReplaceAll(gotJSON, c.CampaignID, "<campaign>")
			}
			if gotJSON != gateGolden[name] {
				t.Errorf("bounty dict\n got %s\nwant %s", gotJSON, gateGolden[name])
			}
			if checks := objAt(got, "policy_checks"); len(checks.A) < 12 {
				t.Errorf("policy_checks = %d rows, want >= 12", len(checks.A))
			}
		})
	}
}

// TestWaivedCheckClearsSubmissionReady pins the 2026-09-10 fix. addWaived
// appends its pass row *behind* the fail row it answers, so policy_checks
// holds two rows for one check; before the fix the raw list was read as two
// verdicts and a waived check left submission_ready false with
// blocking_reasons empty — "not submittable", no reason, no way forward
// (the same class as the B1 immunization waiver, whose fix left this shape
// in check14/check15).
//
// Both halves matter: the verdict clears, and the fail row stays in the
// record as the audit trail of what the waiver answered.
func TestWaivedCheckClearsSubmissionReady(t *testing.T) {
	cases := vectorCases()
	for _, name := range []string{"exploitability_waived", "adversarial_waived"} {
		tc, ok := cases[name]
		if !ok {
			t.Fatalf("missing vector case %q", name)
		}
		t.Run(name, func(t *testing.T) {
			c := vectorCamp(t, tc.active)
			writeFinding(t, c, tc.finding)
			installSeams(t, tc.seams)
			got, err := EvaluateBountyGate(c, objStr(tc.finding, "finding_id"),
				tc.policy, false)
			if err != nil {
				t.Fatal(err)
			}
			if ready := objAt(got, "submission_ready"); !pyTruthyBigNonEmpty(ready) {
				t.Errorf("submission_ready = %s, want True (the waiver "+
					"answered the blocking check)", validation.PyRepr(ready))
			}
			if br := objAt(got, "blocking_reasons"); len(br.A) != 0 {
				t.Errorf("blocking_reasons = %s, want []",
					validation.PyRepr(br))
			}
			// The waived check keeps both rows: the fail it answered and
			// the pass that supersedes it.
			rows := objAt(got, "policy_checks")
			byCheck := map[string][]string{}
			for _, row := range rows.A {
				byCheck[objStr(row, "check")] = append(
					byCheck[objStr(row, "check")], objStr(row, "result"))
			}
			waived := ""
			for chk, res := range byCheck {
				if len(res) == 2 && res[0] == "fail" && res[1] == "pass" {
					waived = chk
				}
			}
			if waived == "" {
				t.Errorf("no check carries the fail+waived-pass pair: %v",
					byCheck)
			}
		})
	}
}

// TestEffectiveChecksLastRowWins pins the collapse rule: the last row for a
// check name supersedes, its position is kept, and a list with no duplicate
// check names is returned untouched (so unwaived rows are never reordered).
func TestEffectiveChecksLastRowWins(t *testing.T) {
	row := func(check, result string) validation.Value {
		return validation.VObj(kv("check", validation.VStr(check)),
			kv("result", validation.VStr(result)))
	}
	unique := []validation.Value{
		row("a", "pass"), row("b", "fail"), row("c", "unknown")}
	if got := effectiveChecks(unique); len(got) != 3 ||
		objStr(got[0], "check") != "a" || objStr(got[2], "check") != "c" {
		t.Errorf("unique list must survive verbatim: %v", got)
	}
	dup := []validation.Value{
		row("a", "pass"), row("b", "fail"), row("b", "pass"), row("c", "pass")}
	got := effectiveChecks(dup)
	if len(got) != 3 {
		t.Fatalf("effectiveChecks = %d rows, want 3", len(got))
	}
	if objStr(got[0], "check") != "a" || objStr(got[1], "check") != "b" ||
		objStr(got[2], "check") != "c" {
		t.Errorf("order = %s,%s,%s want a,b,c", objStr(got[0], "check"),
			objStr(got[1], "check"), objStr(got[2], "check"))
	}
	if objStr(got[1], "result") != "pass" {
		t.Errorf("b = %q, want the later pass row to win",
			objStr(got[1], "result"))
	}
	// A fail that nobody superseded stays a fail.
	if got := effectiveChecks([]validation.Value{
		row("a", "fail"), row("b", "pass")}); objStr(got[0], "result") != "fail" {
		t.Errorf("unsuperseded fail = %q, want fail", objStr(got[0], "result"))
	}
}

// TestGateStoresAcceptanceScore is the A3 wiring: the gate computes the
// deterministic acceptance score and stores it on the finding's risk object
// (the report and `webv2 rank` recompute it live, so the stored number is
// the gate's audit trail). The gate's BOUNTY result — the byte-exact
// surface above — must not move.
func TestGateStoresAcceptanceScore(t *testing.T) {
	c := vectorCamp(t, "SNAP-11111111")
	// A minimal, fully schema-valid CONFIRMED finding carrying every
	// acceptance component: high band (2.0) + E5 (2.5) + confirmed (1.5)
	// + irreversible (1.0) − ack (1.0) = 6.0. (baseFinding is a raw vector
	// row that never round-trips the schema validator, so it cannot use
	// the gate's save path.)
	ts := "2026-09-10T00:00:00+00:00"
	f := validation.VObj(
		kv("finding_id", validation.VStr("F-0a0b0c0d0e01")),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("snapshot_ids", validation.VObj(
			kv("source", validation.VStr("SNAP-11111111")),
			kv("deployment", validation.VNull()),
			kv("chain", validation.VNull()))),
		kv("title", validation.VStr("unbacked withdrawal via price skew")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr(
				"spot price read lets the attacker trade against their own price")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("borrow"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("evidence", validation.VArr(validation.VObj(
			kv("evidence_id", validation.VStr("EV-1")),
			kv("level", validation.VStr("E5")),
			kv("type", validation.VStr("fork-test")),
			kv("description", validation.VStr("fork repro extracts the funds")),
			kv("sandbox_profile", validation.VStr("fork-runner"))))),
		kv("risk", validation.VObj(
			kv("validated", validation.VObj(
				kv("score", validation.VFloat(7.5)),
				kv("band", validation.VStr("high")),
				kv("rationale", validation.VStr("fixture")))),
			kv("reversibility", validation.VStr("irreversible")))),
		kv("verification", validation.VObj(
			kv("critic_verdict", validation.VStr("confirmed")))),
		kv("dedup", validation.VObj()),
		kv("dedup_meta", validation.VObj(
			kv("in_code_ack", validation.VObj(
				kv("file", validation.VStr("src/Vault.sol")),
				kv("line", validation.VInt(42)),
				kv("phrase", validation.VStr("todo")),
				kv("window", validation.VStr("12")))))),
		kv("history", validation.VArr(validation.VObj(
			kv("at", validation.VStr(ts)),
			kv("from", validation.VStr("NEW")),
			kv("to", validation.VStr("CONFIRMED")),
			kv("reason", validation.VStr("a3 fixture")),
			kv("actor", validation.VStr("test"))))),
		kv("created_at", validation.VStr(ts)),
		kv("updated_at", validation.VStr(ts)),
	)
	writeFinding(t, c, f)
	installSeams(t, submissionReadySeams())
	want, _ := risk.AcceptanceScore(f)
	if want != 6.0 {
		t.Fatalf("fixture precondition: score = %v, want 6.0", want)
	}
	got, err := EvaluateBountyGate(c, objStr(f, "finding_id"), testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	// the gate result is the bounty object — acceptance_score must not leak in
	if objAt(got, "acceptance_score").Kind != validation.Null {
		t.Error("acceptance_score must not leak into the bounty result")
	}
	// read the file directly: the vector fixture is a raw row (the vector
	// tests never round-trip it through the schema-validating loader)
	storedPath := filepath.Join(c.FindingsDir, objStr(f, "finding_id")+".json")
	stored, err := validation.ReadJson(storedPath)
	if err != nil {
		t.Fatal(err)
	}
	gotScore := objAt(objAt(stored, "risk"), "acceptance_score")
	if gotScore.Kind != validation.Flt && gotScore.Kind != validation.Int {
		t.Fatalf("stored score kind = %v: %v", gotScore.Kind,
			validation.CanonSpaced(gotScore))
	}
	if gotScore.F != validation.PythonRound(want, 2) {
		t.Fatalf("stored score = %v, want %v", gotScore.F,
			validation.PythonRound(want, 2))
	}
}

func TestBountyRemediationCatalogByteExact(t *testing.T) {
	if len(BountyRemediation) != len(bountyRemediationGolden) {
		t.Fatalf("BountyRemediation = %d ids, golden = %d",
			len(BountyRemediation), len(bountyRemediationGolden))
	}
	for _, id := range bountyRemediationOrder {
		want, ok := bountyRemediationGolden[id]
		if !ok {
			t.Fatalf("golden missing check id %q", id)
		}
		if got := BountyRemediation[id]; got != want {
			t.Errorf("BountyRemediation[%q]\n got %q\nwant %q", id, got, want)
		}
	}
	for id := range BountyRemediation {
		if _, ok := bountyRemediationGolden[id]; !ok {
			t.Errorf("unexpected check id %q", id)
		}
	}
}

func TestGateExplainCatalogByteExact(t *testing.T) {
	SetConfirmedGateRemediation(confirmedRemediationGolden)
	t.Cleanup(func() { SetConfirmedGateRemediation(nil) })
	union := map[string]struct{}{}
	for id := range bountyRemediationGolden {
		union[id] = struct{}{}
	}
	for id := range confirmedRemediationGolden {
		union[id] = struct{}{}
	}
	if len(explainGolden) != len(union) {
		t.Fatalf("catalog = %d ids, want %d", len(explainGolden), len(union))
	}
	for id, golden := range explainGolden {
		got, err := GateExplain(id)
		if err != nil {
			t.Fatalf("GateExplain(%q): %v", id, err)
		}
		if gotJSON := validation.CanonSpaced(got); gotJSON != golden {
			t.Errorf("GateExplain(%q)\n got %s\nwant %s", id, gotJSON, golden)
		}
	}
	// The default catalog is findings.GATE_REMEDIATION: the wired module must
	// stay byte-exact with the Python catalog (11 ids, same order).
	if len(findings.GATE_REMEDIATION) != len(confirmedRemediationGolden) {
		t.Errorf("findings.GATE_REMEDIATION = %d ids, want %d",
			len(findings.GATE_REMEDIATION), len(confirmedRemediationGolden))
	}
	for id, want := range confirmedRemediationGolden {
		if got := findings.GATE_REMEDIATION[id]; got != want {
			t.Errorf("findings.GATE_REMEDIATION[%q]\n got %q\nwant %q", id, got, want)
		}
	}
	_, err := GateExplain("no-such-check")
	if err == nil {
		t.Fatal("expected a KeyError for an unknown check id")
	}
	if err.Error() != wantUnknownCheck {
		t.Errorf("unknown-check text\n got %s\nwant %s", err.Error(), wantUnknownCheck)
	}
}

func TestInScopeVectors(t *testing.T) {
	policy := testPolicy()
	if len(inScopeGolden) == 0 {
		t.Fatal("empty in_scope vector set")
	}
	for _, want := range inScopeGolden {
		ok, why, err := InScope(policy, want.Target)
		if err != nil {
			t.Fatalf("InScope(%q): %v", want.Target, err)
		}
		if ok != want.Ok {
			t.Errorf("InScope(%q) ok = %v, want %v", want.Target, ok, want.Ok)
		}
		if why != want.Why {
			t.Errorf("InScope(%q) why\n got %q\nwant %q", want.Target, why, want.Why)
		}
	}
}

func TestSeverityForVectors(t *testing.T) {
	policy := testPolicy()
	if len(severityGolden) == 0 {
		t.Fatal("empty severity vector set")
	}
	for _, want := range severityGolden {
		finding, err := validation.ParseOrdered([]byte(want.Finding))
		if err != nil {
			t.Fatalf("parse %q: %v", want.Finding, err)
		}
		sev, why, err := SeverityFor(policy, finding)
		if err != nil {
			t.Fatalf("SeverityFor(%s): %v", want.Finding, err)
		}
		if sev != want.Sev {
			t.Errorf("SeverityFor(%s) sev = %q, want %q", want.Finding, sev, want.Sev)
		}
		if why != want.Why {
			t.Errorf("SeverityFor(%s) why\n got %q\nwant %q", want.Finding, why, want.Why)
		}
	}
}

func TestExclusionHitVectors(t *testing.T) {
	policy := testPolicy()
	if len(exclusionGolden) == 0 {
		t.Fatal("empty exclusion vector set")
	}
	for _, want := range exclusionGolden {
		finding, err := validation.ParseOrdered([]byte(want.Finding))
		if err != nil {
			t.Fatalf("parse %q: %v", want.Finding, err)
		}
		hit, err := ExclusionHit(policy, finding)
		if err != nil {
			t.Fatalf("ExclusionHit(%s): %v", want.Finding, err)
		}
		if want.Hit == "" {
			if hit.Kind != validation.Null {
				t.Errorf("ExclusionHit(%s) = %s, want None",
					want.Finding, validation.CanonCompact(hit))
			}
			continue
		}
		if got := validation.CanonSpaced(hit); got != want.Hit {
			t.Errorf("ExclusionHit(%s)\n got %s\nwant %s", want.Finding, got, want.Hit)
		}
	}
}

// ---- added tests (policy IO + the save/log side effects) ----

func TestLoadSavePolicyRoundTrip(t *testing.T) {
	c := vectorCamp(t, "")
	policy := testPolicy()
	path, err := SavePolicy(c, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(c.Dir, "bounty_policy.json"); path != want {
		t.Errorf("default path = %q, want %q", path, want)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != wantPolicyFile {
		t.Errorf("policy file bytes\n got %q\nwant %q", string(raw), wantPolicyFile)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(got) != validation.CanonSpaced(policy) {
		t.Errorf("round trip\n got %s\nwant %s",
			validation.CanonSpaced(got), validation.CanonSpaced(policy))
	}
	explicit := filepath.Join(t.TempDir(), "explicit.json")
	p2, err := SavePolicy(c, policy, &explicit)
	if err != nil {
		t.Fatal(err)
	}
	if p2 != explicit {
		t.Errorf("explicit path = %q, want %q", p2, explicit)
	}
	if _, err := os.Stat(explicit); err != nil {
		t.Errorf("explicit policy not written: %v", err)
	}
}

func TestPolicyValidationIsEnforced(t *testing.T) {
	c := vectorCamp(t, "")
	bad := validation.VObj(kv("program", validation.VStr("Acme")))
	_, err := SavePolicy(c, bad, nil)
	if err == nil {
		t.Fatal("expected a schema error for an incomplete policy")
	}
	if err.Error() != wantBadPolicyError {
		t.Errorf("save error\n got %q\nwant %q", err.Error(), wantBadPolicyError)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "bounty_policy.json")); !os.IsNotExist(err) {
		t.Errorf("invalid policy reached the disk: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{\"program\": \"Acme\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPolicy(path)
	if err == nil {
		t.Fatal("expected a schema error for an incomplete policy")
	}
	if err.Error() != wantBadPolicyError {
		t.Errorf("load error\n got %q\nwant %q", err.Error(), wantBadPolicyError)
	}
}

// keyOrder is the object's key sequence (the setdefault/assign order is
// contractual for the on-disk finding).
func keyOrder(v validation.Value) string {
	keys := make([]string, 0, len(v.O))
	for _, kv := range v.O {
		keys = append(keys, kv.K)
	}
	return strings.Join(keys, ",")
}

func TestEvaluateSavesFindingAndLogs(t *testing.T) {
	c, fid := bountyFixture(t)
	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || !got.B {
		t.Errorf("submission_ready = %s, want True", validation.PyRepr(got))
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	sb := objAt(stored, "bounty")
	if got := keyOrder(sb); got != "eligible,submission_ready,blocking_reasons,policy_checks" {
		t.Errorf("bounty key order = %q", got)
	}
	if checks := objAt(sb, "policy_checks"); len(checks.A) != 16 {
		t.Errorf("stored policy_checks = %d rows, want 16", len(checks.A))
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if got := objStr(last, "type"); got != "bounty.gate" {
		t.Errorf("event type = %q, want bounty.gate", got)
	}
	if got := objStr(last, "ref"); got != fid {
		t.Errorf("event ref = %q, want %q", got, fid)
	}
	wantData := validation.VObj(
		kv("eligible", validation.VBool(true)),
		kv("submission_ready", validation.VBool(true)),
		kv("blockers", validation.VArr()))
	if got := validation.CanonSpaced(objAt(last, "data")); got != validation.CanonSpaced(wantData) {
		t.Errorf("event data\n got %s\nwant %s", got, validation.CanonSpaced(wantData))
	}
}

// ---- gate goldens (Python twin, json.dumps sort_keys=True) ----
var gateGolden = map[string]string{
	"ack_advisory":           "{\"advisories\": [\"in_code_ack present: acceptance likelihood demoted\"], \"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"adversarial_complete":   "{\"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"incentive clause complete (who_profits / profit_mechanism / challenge_interplay)\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"adversarial_missing":    "{\"blocking_reasons\": [\"liveness finding has no adversarial_game clause (who profits, how, and why the challenge path cannot undo it)\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"liveness finding is missing the adversarial_game clause\", \"remediation\": \"webv2 adversarial-game <campaign> <fid> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (each field >= 20 chars; or: webv2 waive <campaign> adversarial-game --subject <fid> --reason '...' if the incentive argument lives elsewhere, e.g. the chain narrative)\", \"result\": \"fail\"}], \"submission_ready\": false}",
	"adversarial_short":      "{\"blocking_reasons\": [\"liveness finding has no adversarial_game clause (who profits, how, and why the challenge path cannot undo it)\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"adversarial_game.profit_mechanism is missing or too short (>= 20 chars required)\", \"remediation\": \"webv2 adversarial-game <campaign> <fid> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (each field >= 20 chars; or: webv2 waive <campaign> adversarial-game --subject <fid> --reason '...' if the incentive argument lives elsewhere, e.g. the chain narrative)\", \"result\": \"fail\"}], \"submission_ready\": false}",
	"adversarial_waived":     "{\"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"liveness finding is missing the adversarial_game clause\", \"remediation\": \"webv2 adversarial-game <campaign> <fid> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (each field >= 20 chars; or: webv2 waive <campaign> adversarial-game --subject <fid> --reason '...' if the incentive argument lives elsewhere, e.g. the chain narrative)\", \"result\": \"fail\"}, {\"check\": \"adversarial-game\", \"detail\": \"waived by carol: the incentive argument lives in the chain narrative: C-0002 pays the operator pe\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"economic_below_floor":   "{\"blocking_reasons\": [\"economic impact not quantified to program floor\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"economic-quantified\", \"detail\": \"extractable_usd missing or below floor\", \"remediation\": \"set economic_impact.extractable_usd from a MEASURED PoC run, priced against the campaign price table (webv2 price set ...)\", \"result\": \"fail\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"evidence_floor":         "{\"blocking_reasons\": [\"evidence E4 below program floor E5\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E4 < required E5\", \"remediation\": \"webv2 mint <fid> --exec <EXEC>   (reproduce at the required tier)\", \"result\": \"fail\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"exploitability_missing": "{\"blocking_reasons\": [\"no paid-exploitability argument on an extractable finding\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"CONFIRMED/CHAIN finding with extractable_usd > 0 has no exploitability argument \\u2014 answer: who pays, and why does this bug make them pay?\", \"remediation\": \"webv2 exploit <campaign> <fid> --paid --arg 'who pays, and why this bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable' \\u2014 a reasoned not-payable decision is a legitimate answer; or: webv2 waive <campaign> paid-exploitability --subject <fid> --reason '...' to record a named decision)\", \"result\": \"fail\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"exploitability_short":   "{\"blocking_reasons\": [\"paid exploitability argument missing or too short\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid=true but the argument is missing or too short (16 < 200 chars) \\u2014 say who pays, and why the bug makes them pay\", \"remediation\": \"webv2 exploit <campaign> <fid> --paid --arg 'who pays, and why this bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable' \\u2014 a reasoned not-payable decision is a legitimate answer; or: webv2 waive <campaign> paid-exploitability --subject <fid> --reason '...' to record a named decision)\", \"result\": \"fail\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"exploitability_unpaid":  "{\"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"not payable \\u2014 argument records why (134 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"exploitability_waived":  "{\"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"CONFIRMED/CHAIN finding with extractable_usd > 0 has no exploitability argument \\u2014 answer: who pays, and why does this bug make them pay?\", \"remediation\": \"webv2 exploit <campaign> <fid> --paid --arg 'who pays, and why this bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable' \\u2014 a reasoned not-payable decision is a legitimate answer; or: webv2 waive <campaign> paid-exploitability --subject <fid> --reason '...' to record a named decision)\", \"result\": \"fail\"}, {\"check\": \"paid-exploitability\", \"detail\": \"waived by carol: argument deferred to the report body; payer is the treasury\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"fork_tier":              "{\"blocking_reasons\": [\"program requires fork-based reproduction\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"repro tier T1, program requires T3+\", \"remediation\": \"webv2 mint <fid> --exec <EXEC>   (a T3/T4 fork reproduction)\", \"result\": \"fail\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"full_pass":              "{\"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"immunization_bypass":    "{\"blocking_reasons\": [\"not immunized (bypass) \\u2014 the patch must block the FORK PoC and its 3 boundary mutations\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"bypass: boundary bypass found: calling via delegatecall from a proxy skips the check \\u2014 the patch does not hold\", \"remediation\": \"webv2 immunize <fid> --poc-exec <FORK-EXEC-ID> --patch '<the fix>' --mutations 'm1;m2;m3'   (the patch must block the FORK PoC and all 3 boundary mutations \\u2014 a unit-test patch is not a patch; if a bypass is real, fix the patch and re-verify)\", \"result\": \"fail\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"known_issue":            "{\"blocking_reasons\": [\"excluded: known-issue \\u2014 rounding dust\"], \"eligible\": false, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"matches exclusion 'rounding dust' (known-issue)\", \"remediation\": \"read the matched exclusion on the program page \\u2014 if it truly does not apply, record the reasoning in the report; if it does, drop the finding (webv2 status <fid> OUT_OF_SCOPE ...)\", \"result\": \"fail\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"ladder_missing":         "{\"blocking_reasons\": [\"variant ladder missing for a CONFIRMED finding\", \"USD figures without a resolvable price basis\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"no variant ladder \\u2014 the claim may still be a base-rung artifact (run-1: 50% at $2.5k claimed; 100% at 1 wei true)\", \"remediation\": \"webv2 ladder start <fid> ... webv2 ladder complete <fid>   (or: webv2 ladder waive <fid> --reason '...' \\u2014 the named escape hatch)\", \"result\": \"fail\"}, {\"check\": \"e7-price-basis\", \"detail\": \"USD figures ['extractable_usd'] carry no resolvable price_basis None\", \"remediation\": \"webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \\u2014 no unattributed $)\", \"result\": \"fail\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"ladder_open":            "{\"blocking_reasons\": [\"variant ladder not closed (complete or waived)\", \"USD figures without a resolvable price basis\", \"claim contradicts measured extraction_ratio\", \"unaudited preconditions unaddressed by the ladder\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder open; unexplored axes: ['precondition-removal', 'ordering-permutation']\", \"remediation\": \"webv2 ladder start <fid> ... webv2 ladder complete <fid>   (or: webv2 ladder waive <fid> --reason '...' \\u2014 the named escape hatch)\", \"result\": \"fail\"}, {\"check\": \"e7-price-basis\", \"detail\": \"USD figures ['extractable_usd'] carry no resolvable price_basis None\", \"remediation\": \"webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \\u2014 no unattributed $)\", \"result\": \"fail\"}, {\"check\": \"claim-drift\", \"detail\": \"claim says 50% extraction (closest figure in the title) but measured extraction_ratio is 100% \\u2014 make the claim and the measurement agree\", \"remediation\": \"make the claim and the measurement agree: fix the title, or re-run the PoC and re-measure extraction_ratio\", \"result\": \"fail\"}, {\"check\": \"precondition-audit\", \"detail\": \"precondition(s) the code never enforces, unaddressed by any ladder rung: pool must hold at least one wei of dust\", \"remediation\": \"webv2 ladder add <fid> ... --removes '<precondition>' then webv2 ladder repro <fid> <rung> --exec <EXEC>   (or: webv2 shield the precondition as code-enforced if the PoC assumption was wrong)\", \"result\": \"fail\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"ladder_waived":          "{\"blocking_reasons\": [], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"matched scope entry 'Vault'\", \"result\": \"pass\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder waived: the operator decided that this rung is out of reach for the campaign budget and \", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"2 code-unenforced precondition(s) covered by the ladder waiver\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": true}",
	"no_usd_no_affected":     "{\"blocking_reasons\": [\"no affected component to scope-check\", \"severity not established by policy rules\"], \"eligible\": true, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"no affected component recorded\", \"remediation\": \"re-check the target against the program scope; if it is a different component, re-aim the hypothesis\", \"result\": \"unknown\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"no deterministic severity rule matched \\u2014 read program terms\", \"remediation\": \"quantify the impact (economic_impact) so a severity rule matches, or read the program's terms for the band\", \"result\": \"human-review\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"not_confirmed":          "{\"blocking_reasons\": [\"finding is not CONFIRMED\", \"no active snapshot pin\", \"no affected component to scope-check\", \"excluded: known-issue \\u2014 rounding dust\", \"severity not established by policy rules\", \"evidence E1 below program floor E5\", \"program requires fork-based reproduction\", \"economic impact not quantified to program floor\", \"USD figures without a resolvable price basis\", \"not immunized (missing) \\u2014 the patch must block the FORK PoC and its 3 boundary mutations\"], \"eligible\": false, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"status is HYPOTHESIS\", \"remediation\": \"webv2 verdict <fid> confirmed ... + webv2 recall <campaign> --finding <fid> + webv2 mint <fid> --exec <EXEC>  (see `webv2 gate explain` for the full CONFIRMED checklist)\", \"result\": \"fail\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"campaign has no active snapshot\", \"remediation\": \"webv2 snap   (re-pin, then re-run the gate)\", \"result\": \"unknown\"}, {\"check\": \"in-scope\", \"detail\": \"no affected component recorded\", \"remediation\": \"re-check the target against the program scope; if it is a different component, re-aim the hypothesis\", \"result\": \"unknown\"}, {\"check\": \"known-issue-check\", \"detail\": \"matches exclusion 'rounding dust' (known-issue)\", \"remediation\": \"read the matched exclusion on the program page \\u2014 if it truly does not apply, record the reasoning in the report; if it does, drop the finding (webv2 status <fid> OUT_OF_SCOPE ...)\", \"result\": \"fail\"}, {\"check\": \"severity-floor\", \"detail\": \"no deterministic severity rule matched \\u2014 read program terms\", \"remediation\": \"quantify the impact (economic_impact) so a severity rule matches, or read the program's terms for the band\", \"result\": \"human-review\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E1 < required E5\", \"remediation\": \"webv2 mint <fid> --exec <EXEC>   (reproduce at the required tier)\", \"result\": \"fail\"}, {\"check\": \"fork-repro\", \"detail\": \"repro tier T1, program requires T3+\", \"remediation\": \"webv2 mint <fid> --exec <EXEC>   (a T3/T4 fork reproduction)\", \"result\": \"fail\"}, {\"check\": \"economic-quantified\", \"detail\": \"extractable_usd missing or below floor\", \"remediation\": \"set economic_impact.extractable_usd from a MEASURED PoC run, priced against the campaign price table (webv2 price set ...)\", \"result\": \"fail\"}, {\"check\": \"e7-price-basis\", \"detail\": \"USD figures ['extractable_usd'] carry no resolvable price_basis None\", \"remediation\": \"webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \\u2014 no unattributed $)\", \"result\": \"fail\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"waived by pytest-harness: the pinned RPC was retired by the provider and the archive node is offline for t\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"missing: no patch verification recorded (webv2 immunize ... against the FORK PoC)\", \"remediation\": \"webv2 immunize <fid> --poc-exec <FORK-EXEC-ID> --patch '<the fix>' --mutations 'm1;m2;m3'   (the patch must block the FORK PoC and all 3 boundary mutations \\u2014 a unit-test patch is not a patch; if a bypass is real, fix the patch and re-verify)\", \"result\": \"fail\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
	"out_of_scope":           "{\"blocking_reasons\": [\"target 'RandomToken' out of scope\"], \"eligible\": false, \"policy_checks\": [{\"check\": \"security-confirmed\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"snapshot-pinned\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"in-scope\", \"detail\": \"'RandomToken' matches no scope entry\", \"remediation\": \"re-check the target against the program scope; if it is a different component, re-aim the hypothesis\", \"result\": \"fail\"}, {\"check\": \"known-issue-check\", \"detail\": \"no exclusion pattern matched\", \"result\": \"pass\"}, {\"check\": \"severity-floor\", \"detail\": \"matched severity rule for high\", \"result\": \"pass\"}, {\"check\": \"evidence-sufficient\", \"detail\": \"E5 >= required E5\", \"result\": \"pass\"}, {\"check\": \"fork-repro\", \"detail\": \"tier T3\", \"result\": \"pass\"}, {\"check\": \"maximal-exploitation\", \"detail\": \"ladder closed (maximal: R-abc123)\", \"result\": \"pass\"}, {\"check\": \"e7-price-basis\", \"detail\": \"PRICE-0001 -> ACME @ $1.0 (fixture: fixed reference price)\", \"result\": \"pass\"}, {\"check\": \"claim-drift\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"precondition-audit\", \"detail\": \"\", \"result\": \"pass\"}, {\"check\": \"mainnet-fork-poc\", \"detail\": \"fork PoC proven: E5 fork-test from EXEC-0000000002 (fork-runner, exit 0)\", \"result\": \"pass\"}, {\"check\": \"immunization\", \"detail\": \"patch blocks the fork PoC and all 3 boundary mutations (basis: EXEC-0000000002)\", \"result\": \"pass\"}, {\"check\": \"accepted-risk\", \"detail\": \"no accepted-risk pattern matched\", \"result\": \"pass\"}, {\"check\": \"paid-exploitability\", \"detail\": \"paid \\u2014 argument recorded (535 chars)\", \"result\": \"pass\"}, {\"check\": \"adversarial-game\", \"detail\": \"not a liveness finding\", \"result\": \"pass\"}], \"submission_ready\": false}",
}

// ---- gate_explain catalog goldens (id -> CanonSpaced dict) ----
var explainGolden = map[string]string{
	"security-confirmed":         "{\"check\": \"security-confirmed\", \"gate\": \"bounty\", \"remediation\": \"webv2 verdict <fid> confirmed ... + webv2 recall <campaign> --finding <fid> + webv2 mint <fid> --exec <EXEC>  (see `webv2 gate explain` for the full CONFIRMED checklist)\"}",
	"snapshot-pinned":            "{\"check\": \"snapshot-pinned\", \"gate\": \"bounty\", \"remediation\": \"webv2 snap   (re-pin, then re-run the gate)\"}",
	"in-scope":                   "{\"check\": \"in-scope\", \"gate\": \"bounty\", \"remediation\": \"re-check the target against the program scope; if it is a different component, re-aim the hypothesis\"}",
	"known-issue-check":          "{\"check\": \"known-issue-check\", \"gate\": \"bounty\", \"remediation\": \"read the matched exclusion on the program page \\u2014 if it truly does not apply, record the reasoning in the report; if it does, drop the finding (webv2 status <fid> OUT_OF_SCOPE ...)\"}",
	"severity-floor":             "{\"check\": \"severity-floor\", \"gate\": \"bounty\", \"remediation\": \"quantify the impact (economic_impact) so a severity rule matches, or read the program's terms for the band\"}",
	"evidence-sufficient":        "{\"check\": \"evidence-sufficient\", \"gate\": \"bounty\", \"remediation\": \"webv2 mint <fid> --exec <EXEC>   (reproduce at the required tier)\"}",
	"fork-repro":                 "{\"check\": \"fork-repro\", \"gate\": \"bounty\", \"remediation\": \"webv2 mint <fid> --exec <EXEC>   (a T3/T4 fork reproduction)\"}",
	"economic-quantified":        "{\"check\": \"economic-quantified\", \"gate\": \"bounty\", \"remediation\": \"set economic_impact.extractable_usd from a MEASURED PoC run, priced against the campaign price table (webv2 price set ...)\"}",
	"maximal-exploitation":       "{\"check\": \"maximal-exploitation\", \"gate\": \"bounty\", \"remediation\": \"webv2 ladder start <fid> ... webv2 ladder complete <fid>   (or: webv2 ladder waive <fid> --reason '...' \\u2014 the named escape hatch)\"}",
	"e7-price-basis":             "{\"check\": \"e7-price-basis\", \"gate\": \"bounty\", \"remediation\": \"webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \\u2014 no unattributed $)\"}",
	"claim-drift":                "{\"check\": \"claim-drift\", \"gate\": \"confirmed\", \"remediation\": \"make the claim and the measurement agree: fix the title, or re-run the PoC and re-measure extraction_ratio\"}",
	"precondition-audit":         "{\"check\": \"precondition-audit\", \"gate\": \"bounty\", \"remediation\": \"webv2 ladder add <fid> ... --removes '<precondition>' then webv2 ladder repro <fid> <rung> --exec <EXEC>   (or: webv2 shield the precondition as code-enforced if the PoC assumption was wrong)\"}",
	"mainnet-fork-poc":           "{\"check\": \"mainnet-fork-poc\", \"gate\": \"bounty\", \"remediation\": \"webv2 exec <campaign> --profile fork-runner --command 'forge test --fork-url <pinned-rpc> --fork-block-number <pin> --match-test test_exploit' --finding <fid>   then webv2 mint <fid> --exec <EXEC-ID> --type fork-test   (unit tests prove semantics; only the fork proves mainnet)\"}",
	"immunization":               "{\"check\": \"immunization\", \"gate\": \"bounty\", \"remediation\": \"webv2 immunize <fid> --poc-exec <FORK-EXEC-ID> --patch '<the fix>' --mutations 'm1;m2;m3'   (the patch must block the FORK PoC and all 3 boundary mutations \\u2014 a unit-test patch is not a patch; if a bypass is real, fix the patch and re-verify)\"}",
	"accepted-risk":              "{\"check\": \"accepted-risk\", \"gate\": \"bounty\", \"remediation\": \"the program documented this as an accepted risk \\u2014 not a payable vulnerability as written. If this particular finding IS payable despite the acceptance, record the decision: webv2 waive <campaign> accepted-risk --subject <fid> --reason 'why this one is payable' --actor <who>   (or: drop the finding \\u2014 webv2 status <fid> OUT_OF_SCOPE \\u2014 if it is genuinely the accepted behavior)\"}",
	"paid-exploitability":        "{\"check\": \"paid-exploitability\", \"gate\": \"bounty\", \"remediation\": \"webv2 exploit <campaign> <fid> --paid --arg 'who pays, and why this bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable' \\u2014 a reasoned not-payable decision is a legitimate answer; or: webv2 waive <campaign> paid-exploitability --subject <fid> --reason '...' to record a named decision)\"}",
	"adversarial-game":           "{\"check\": \"adversarial-game\", \"gate\": \"bounty\", \"remediation\": \"webv2 adversarial-game <campaign> <fid> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (each field >= 20 chars; or: webv2 waive <campaign> adversarial-game --subject <fid> --reason '...' if the incentive argument lives elsewhere, e.g. the chain narrative)\"}",
	"critic-verdict":             "{\"check\": \"critic-verdict\", \"gate\": \"confirmed\", \"remediation\": \"webv2 verdict <fid> confirmed '<reasoning>' --actor <you>\"}",
	"memory-check":               "{\"check\": \"memory-check\", \"gate\": \"confirmed\", \"remediation\": \"webv2 recall <campaign> --finding <fid>   (records a graph-memory consultation)\"}",
	"reproduction-reproduced":    "{\"check\": \"reproduction-reproduced\", \"gate\": \"confirmed\", \"remediation\": \"webv2 mint <fid> --exec <EXEC-ID>   (a reproduced attempt, sandboxed)\"}",
	"evidence-floor":             "{\"check\": \"evidence-floor\", \"gate\": \"confirmed\", \"remediation\": \"webv2 mint <fid> --exec <EXEC-ID>   (or, for a NAMED decision: webv2 floors set \\u2014 an override, logged, never a silent edit). Economic-class E7: when no USD figure is defensible, record the decision instead \\u2014 webv2 impact <campaign> <fid> --unpriceable --ceiling '<capacity basis>' --reason '<why>' --actor <you>\"}",
	"evidence-floor-unreachable": "{\"check\": \"evidence-floor-unreachable\", \"gate\": \"confirmed\", \"remediation\": \"webv2 snap / export FORK_RPC_URL   (make the evidence reachable) \\u2014 or webv2 floors set to record the override as a decision\"}",
	"snapshot-compatible":        "{\"check\": \"snapshot-compatible\", \"gate\": \"confirmed\", \"remediation\": \"webv2 snap   (re-pin the target and re-verify the finding against it)\"}",
	"shield-adjudication":        "{\"check\": \"shield-adjudication\", \"gate\": \"confirmed\", \"remediation\": \"webv2 shield <fid> --extraction --reason '<why the effect is still extraction despite being documented as intended>' --actor <you>\"}",
	"reproduction-tier":          "{\"check\": \"reproduction-tier\", \"gate\": \"confirmed\", \"remediation\": \"webv2 mint <campaign> <fid> --exec <fork exec> --description '...' --tier T3   (record the fork-tier attempt the evidence is based on)\"}",
	"invariant-unverified":       "{\"check\": \"invariant-unverified\", \"gate\": \"confirmed\", \"remediation\": \"webv2 invariant-verify <campaign> <INV-ID> --artifact <ART-ID>   (check the statement against code; the artifact must be registered)\"}",
	"sequence-coverage":          "{\"check\": \"sequence-coverage\", \"gate\": \"confirmed\", \"remediation\": \"webv2 sequence run <spec-file> --finding <fid>   (a T4 sequence PoC covering the declared exploit_sequence)\"}",
}

// ---- bounty remediation golden (BOUNTY_REMEDIATION) ----
var bountyRemediationGolden = map[string]string{
	"security-confirmed":   "webv2 verdict <fid> confirmed ... + webv2 recall <campaign> --finding <fid> + webv2 mint <fid> --exec <EXEC>  (see `webv2 gate explain` for the full CONFIRMED checklist)",
	"snapshot-pinned":      "webv2 snap   (re-pin, then re-run the gate)",
	"in-scope":             "re-check the target against the program scope; if it is a different component, re-aim the hypothesis",
	"known-issue-check":    "read the matched exclusion on the program page \u2014 if it truly does not apply, record the reasoning in the report; if it does, drop the finding (webv2 status <fid> OUT_OF_SCOPE ...)",
	"severity-floor":       "quantify the impact (economic_impact) so a severity rule matches, or read the program's terms for the band",
	"evidence-sufficient":  "webv2 mint <fid> --exec <EXEC>   (reproduce at the required tier)",
	"fork-repro":           "webv2 mint <fid> --exec <EXEC>   (a T3/T4 fork reproduction)",
	"economic-quantified":  "set economic_impact.extractable_usd from a MEASURED PoC run, priced against the campaign price table (webv2 price set ...)",
	"maximal-exploitation": "webv2 ladder start <fid> ... webv2 ladder complete <fid>   (or: webv2 ladder waive <fid> --reason '...' \u2014 the named escape hatch)",
	"e7-price-basis":       "webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \u2014 no unattributed $)",
	"claim-drift":          "make the claim and the measurement agree: fix the title, or re-run the PoC and re-measure extraction_ratio",
	"precondition-audit":   "webv2 ladder add <fid> ... --removes '<precondition>' then webv2 ladder repro <fid> <rung> --exec <EXEC>   (or: webv2 shield the precondition as code-enforced if the PoC assumption was wrong)",
	"mainnet-fork-poc":     "webv2 exec <campaign> --profile fork-runner --command 'forge test --fork-url <pinned-rpc> --fork-block-number <pin> --match-test test_exploit' --finding <fid>   then webv2 mint <fid> --exec <EXEC-ID> --type fork-test   (unit tests prove semantics; only the fork proves mainnet)",
	"immunization":         "webv2 immunize <fid> --poc-exec <FORK-EXEC-ID> --patch '<the fix>' --mutations 'm1;m2;m3'   (the patch must block the FORK PoC and all 3 boundary mutations \u2014 a unit-test patch is not a patch; if a bypass is real, fix the patch and re-verify)",
	"accepted-risk":        "the program documented this as an accepted risk \u2014 not a payable vulnerability as written. If this particular finding IS payable despite the acceptance, record the decision: webv2 waive <campaign> accepted-risk --subject <fid> --reason 'why this one is payable' --actor <who>   (or: drop the finding \u2014 webv2 status <fid> OUT_OF_SCOPE \u2014 if it is genuinely the accepted behavior)",
	"paid-exploitability":  "webv2 exploit <campaign> <fid> --paid --arg 'who pays, and why this bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable' \u2014 a reasoned not-payable decision is a legitimate answer; or: webv2 waive <campaign> paid-exploitability --subject <fid> --reason '...' to record a named decision)",
	"adversarial-game":     "webv2 adversarial-game <campaign> <fid> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (each field >= 20 chars; or: webv2 waive <campaign> adversarial-game --subject <fid> --reason '...' if the incentive argument lives elsewhere, e.g. the chain narrative)",
}

// ---- bounty remediation key order ----
var bountyRemediationOrder = []string{"security-confirmed", "snapshot-pinned", "in-scope", "known-issue-check", "severity-floor", "evidence-sufficient", "fork-repro", "economic-quantified", "maximal-exploitation", "e7-price-basis", "claim-drift", "precondition-audit", "mainnet-fork-poc", "immunization", "accepted-risk", "paid-exploitability", "adversarial-game"}

// ---- unknown-check error (str(KeyError(msg))) ----
const wantUnknownCheck = "\"unknown check id 'no-such-check' (known: ['accepted-risk', 'adversarial-game', 'claim-drift', 'critic-verdict', 'e7-price-basis', 'economic-quantified', 'evidence-floor', 'evidence-floor-unreachable', 'evidence-sufficient', 'fork-repro', 'immunization', 'in-scope', 'invariant-unverified', 'known-issue-check', 'mainnet-fork-poc', 'maximal-exploitation', 'memory-check', 'paid-exploitability', 'precondition-audit', 'reproduction-reproduced', 'reproduction-tier', 'security-confirmed', 'sequence-coverage', 'severity-floor', 'shield-adjudication', 'snapshot-compatible', 'snapshot-pinned'])\""

// ---- confirmed gate remediation (findings.GATE_REMEDIATION) ----
var confirmedRemediationGolden = map[string]string{
	"critic-verdict":             "webv2 verdict <fid> confirmed '<reasoning>' --actor <you>",
	"memory-check":               "webv2 recall <campaign> --finding <fid>   (records a graph-memory consultation)",
	"reproduction-reproduced":    "webv2 mint <fid> --exec <EXEC-ID>   (a reproduced attempt, sandboxed)",
	"evidence-floor":             "webv2 mint <fid> --exec <EXEC-ID>   (or, for a NAMED decision: webv2 floors set \u2014 an override, logged, never a silent edit). Economic-class E7: when no USD figure is defensible, record the decision instead \u2014 webv2 impact <campaign> <fid> --unpriceable --ceiling '<capacity basis>' --reason '<why>' --actor <you>",
	"evidence-floor-unreachable": "webv2 snap / export FORK_RPC_URL   (make the evidence reachable) \u2014 or webv2 floors set to record the override as a decision",
	"snapshot-compatible":        "webv2 snap   (re-pin the target and re-verify the finding against it)",
	"shield-adjudication":        "webv2 shield <fid> --extraction --reason '<why the effect is still extraction despite being documented as intended>' --actor <you>",
	"claim-drift":                "make the claim and the measurement agree: fix the title, or re-run the PoC and re-measure extraction_ratio",
	"reproduction-tier":          "webv2 mint <campaign> <fid> --exec <fork exec> --description '...' --tier T3   (record the fork-tier attempt the evidence is based on)",
	"invariant-unverified":       "webv2 invariant-verify <campaign> <INV-ID> --artifact <ART-ID>   (check the statement against code; the artifact must be registered)",
	"sequence-coverage":          "webv2 sequence run <spec-file> --finding <fid>   (a T4 sequence PoC covering the declared exploit_sequence)",
}

// ---- in_scope goldens ----
var inScopeGolden = []struct {
	Target, Why string
	Ok          bool
}{
	{"Vault", "matched scope entry 'Vault'", true},
	{"src/Vault.sol", "matched scope entry 'Vault'", true},
	{"vault", "matched scope entry 'Vault'", true},
	{"VAULT", "matched scope entry 'Vault'", true},
	{"0x1111111111111111111111111111111111111111", "matched scope entry '0x1111111111111111111111111111111111111111'", true},
	{"0x1111111111111111111111111111111111111112", "'0x1111111111111111111111111111111111111112' matches no scope entry", false},
	{"", "'' matches no scope entry", false},
	{"RandomToken", "'RandomToken' matches no scope entry", false},
	{"0X1111111111111111111111111111111111111111", "matched scope entry '0x1111111111111111111111111111111111111111'", true},
}

// ---- severity_for goldens (finding JSON, severity (” = None), why) ----
var severityGolden = []struct{ Finding, Sev, Why string }{
	{"{\"economic_impact\": {}, \"invariant\": {\"violation_demonstrated\": true}, \"root_cause\": {\"class\": \"access-control\"}}", "critical", "matched severity rule for critical"},
	{"{\"economic_impact\": {}, \"root_cause\": {\"class\": \"access-control\"}}", "", "no severity rule matched"},
	{"{\"economic_impact\": {\"extractable_usd\": 200000}, \"root_cause\": {\"class\": \"oracle-manipulation\"}}", "high", "matched severity rule for high"},
	{"{\"economic_impact\": {\"extractable_usd\": 99999}, \"root_cause\": {\"class\": \"oracle-manipulation\"}}", "", "no severity rule matched"},
	{"{\"economic_impact\": {\"extractable_usd\": 100000}, \"root_cause\": {\"class\": \"oracle-manipulation\"}}", "high", "matched severity rule for high"},
	{"{\"economic_impact\": {}, \"root_cause\": {\"class\": \"dos-griefing\"}}", "", "no severity rule matched"},
	{"{\"economic_impact\": {\"blast_radius\": \"protocol-solvency\", \"extractable_usd\": 1500000}, \"root_cause\": {\"class\": \"oracle-manipulation\"}}", "high", "matched severity rule for high"},
}

// ---- exclusion_hit goldens (finding JSON, matched exclusion JSON or ”) ----
var exclusionGolden = []struct{ Finding, Hit string }{
	{"{\"root_cause\": {\"class\": \"oracle-manipulation\", \"description\": \"spot price read\"}, \"title\": \"Attacker withdraws\"}", ""},
	{"{\"root_cause\": {\"class\": \"oracle-manipulation\", \"description\": \"spot price read \\u2014 effectively rounding dust accounting\"}, \"title\": \"Attacker withdraws\"}", "{\"kind\": \"known-issue\", \"pattern\": \"rounding dust\", \"reference\": \"program page known-issues section\"}"},
	{"{\"root_cause\": {\"class\": \"oracle-manipulation\", \"description\": \"x\", \"mechanism\": \"Government Seizure of funds\"}, \"title\": \"t\"}", "{\"kind\": \"intended-behavior\", \"pattern\": \"government seizure\"}"},
	{"{\"title\": \"rounding DUST in the vault\"}", "{\"kind\": \"known-issue\", \"pattern\": \"rounding dust\", \"reference\": \"program page known-issues section\"}"},
	{"{}", ""},
}

// ---- gate vector case order ----
var gateVectorOrder = []string{"full_pass", "ladder_missing", "ladder_open", "not_confirmed", "ladder_waived", "no_usd_no_affected", "evidence_floor", "fork_tier", "out_of_scope", "known_issue", "economic_below_floor", "immunization_bypass", "exploitability_missing", "exploitability_short", "exploitability_waived", "exploitability_unpaid", "adversarial_missing", "adversarial_short", "adversarial_waived", "adversarial_complete", "ack_advisory"}

// TestExistingBountyKeepsKeyOrder pins the dict-assignment emulation: a
// finding that already carries a bounty object keeps its key order (Python's
// setdefault + in-place assignment), and the values are refreshed.
func TestExistingBountyKeepsKeyOrder(t *testing.T) {
	c, fid := bountyFixture(t)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f = withField(f, "bounty", validation.VObj(
		kv("policy_checks", validation.VArr()),
		kv("blocking_reasons", validation.VArr()),
		kv("submission_ready", validation.VBool(false)),
		kv("eligible", validation.VBool(false))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateBountyGate(c, fid, testPolicy(), true); err != nil {
		t.Fatal(err)
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	sb := objAt(stored, "bounty")
	if got := keyOrder(sb); got != "policy_checks,blocking_reasons,submission_ready,eligible" {
		t.Errorf("bounty key order = %q, want the pre-existing order", got)
	}
	if got := objAt(sb, "submission_ready"); got.Kind != validation.Bool || !got.B {
		t.Errorf("stored submission_ready = %s, want True", validation.PyRepr(got))
	}
}

// TestDefaultPriceSeamReadsPriceTable pins the pricing wiring: with the
// price-row override cleared, the gate resolves price_basis through the
// ported pricing module (and not through a stub).
func TestDefaultPriceSeamReadsPriceTable(t *testing.T) {
	c, fid := bountyFixture(t)
	SetPriceRow(nil) // default: internal/pricing.PriceRow
	row, err := pricing.SetPrice(c, "ACME", 1.0,
		"fixture: fixed reference price", "", "pytest-harness")
	if err != nil {
		t.Fatal(err)
	}
	priceID := objStr(row, "price_id")
	if priceID == "" {
		t.Fatal("pricing.SetPrice returned a row without a price_id")
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ei := objAt(f, "economic_impact")
	ei.O = validation.SetOrAppend(ei.O, "price_basis", validation.VStr(priceID))
	f = withField(f, "economic_impact", ei)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateBountyGate(c, fid, testPolicy(), false)
	if err != nil {
		t.Fatal(err)
	}
	var detail string
	found := false
	for _, c := range objAt(result, "policy_checks").A {
		if objStr(c, "check") == "e7-price-basis" {
			found = true
			detail = objStr(c, "result") + " " + objStr(c, "detail")
		}
	}
	if !found {
		t.Fatal("no e7-price-basis row in the gate output")
	}
	if !strings.HasPrefix(detail, "pass ") {
		t.Errorf("e7-price-basis = %q, want pass", detail)
	}
	if !strings.Contains(detail, priceID) {
		t.Errorf("e7-price-basis detail %q does not name %q", detail, priceID)
	}
}
