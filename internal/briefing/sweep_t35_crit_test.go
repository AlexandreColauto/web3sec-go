package briefing

// Port of tests/test_criticality.py's brief half: an untouched
// consensus-critical contract is flagged, and the divergence gate line never
// displaces it.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35CritCampaign writes a protocol model (and optional plan) into a fresh
// campaign.
func t35CritCampaign(t *testing.T, program string, contracts []validation.Value,
	stateMachines []validation.Value, plan *validation.Value) *state.Campaign {
	t.Helper()
	c := newCamp(t, program)
	model := validation.VObj(
		kv("protocol_id", validation.VStr("m")),
		kv("name", validation.VStr(program)),
		kv("state_machines", validation.VArr(stateMachines...)),
		kv("contracts", validation.VArr(contracts...)),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), model, "protocol_model"); err != nil {
		t.Fatal(err)
	}
	if plan != nil {
		if _, err := planner.SavePlan(c, *plan); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func t35Contract(name, path string, entries ...string) validation.Value {
	eps := []validation.Value{}
	for _, e := range entries {
		eps = append(eps, validation.VStr(e))
	}
	return validation.VObj(
		kv("name", validation.VStr(name)),
		kv("path", validation.VStr(path)),
		kv("entry_points", validation.VArr(eps...)))
}

func t35StateMachine(name string) validation.Value {
	return validation.VObj(
		kv("name", validation.VStr(name)),
		kv("states", validation.VArr()),
		kv("transitions", validation.VArr()))
}

// Port of tests/test_criticality.py::test_brief_flags_untouched_consensus_critical.
func TestBriefFlagsUntouchedConsensusCritical(t *testing.T) {
	c := t35CritCampaign(t, "Morph L2",
		[]validation.Value{
			t35Contract("Rollup", "Rollup.sol", "commitBatch", "finalize"),
			t35Contract("Vault", "Vault.sol", "deposit", "withdraw"),
			t35Contract("Utils", "Utils.sol", "version")},
		[]validation.Value{t35StateMachine("rollup")}, nil)
	b := build(t, c, false)
	found := false
	for _, a := range objAt(b, "next_actions").A {
		if strings.Contains(a.S, "consensus-critical") &&
			strings.Contains(a.S, "Rollup") {
			found = true
		}
	}
	if !found {
		t.Errorf("no untouched consensus-critical line in %v",
			objAt(b, "next_actions"))
	}
}

// Port of tests/test_criticality.py::test_brief_coverage_vault_not_covered_by_vaultproxy.
func TestBriefCoverageVaultNotCoveredByVaultProxy(t *testing.T) {
	plan := validation.VObj(
		kv("campaign_id", validation.VStr("")),
		kv("created_at", validation.VStr("2026-09-07T00:00:00Z")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question", validation.VStr("proxy upgrade surface review")),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", validation.VArr(validation.VStr("historical"))),
			kv("components", validation.VArr(
				validation.VStr("VaultProxy")))))),
		kv("lenses", validation.VArr()))
	c := t35CritCampaign(t, "Vault protocol",
		[]validation.Value{
			t35Contract("Vault", "Vault.sol", "deposit", "withdraw"),
			t35Contract("VaultProxy", "VaultProxy.sol", "upgradeTo")},
		[]validation.Value{t35StateMachine("Vault")}, &plan)
	// the plan's campaign_id must be the real one.
	saved, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	saved.O = setOrAppend(saved.O, "campaign_id", validation.VStr(c.CampaignID))
	if _, err := planner.SavePlan(c, saved); err != nil {
		t.Fatal(err)
	}
	b := build(t, c, false)
	crit := objAt(b, "criticality")
	if cov := objAt(crit, "coverage"); objAt(cov, "Vault").Kind != validation.Bool ||
		objAt(cov, "Vault").B {
		t.Errorf("coverage[Vault] = %v, want false", objAt(cov, "Vault"))
	}
	uncovered := false
	for _, u := range objAt(crit, "uncovered_consensus_critical").A {
		if u.S == "Vault" {
			uncovered = true
		}
	}
	if !uncovered {
		t.Errorf("Vault missing from uncovered_consensus_critical: %v",
			objAt(crit, "uncovered_consensus_critical"))
	}

	// regression guard: divergence gate OPEN and Rollup untouched — both
	// lines appear, criticality first.
	divPlan := validation.VObj(
		kv("campaign_id", validation.VStr("")),
		kv("created_at", validation.VStr("2026-09-07T00:00:00Z")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question", validation.VStr(
				"history mining patterns overview")),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", validation.VArr(
				validation.VStr("historical")))))),
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-01")),
			kv("lens", validation.VStr("liveness")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr("liveness probe question here")),
			kv("status", validation.VStr("open"))))))
	c2 := t35CritCampaign(t, "Morph L2",
		[]validation.Value{
			t35Contract("Rollup", "Rollup.sol", "commitBatch", "finalize"),
			t35Contract("Vault", "Vault.sol", "deposit", "withdraw"),
			t35Contract("Utils", "Utils.sol", "version")},
		[]validation.Value{t35StateMachine("rollup")}, &divPlan)
	saved2, err := validation.ReadJson(filepath.Join(c2.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	saved2.O = setOrAppend(saved2.O, "campaign_id",
		validation.VStr(c2.CampaignID))
	if _, err := planner.SavePlan(c2, saved2); err != nil {
		t.Fatal(err)
	}
	b2 := build(t, c2, false)
	acts := objAt(b2, "next_actions")
	critI, divI := -1, -1
	for i, a := range acts.A {
		if strings.Contains(a.S, "consensus-critical") &&
			strings.Contains(a.S, "Rollup") {
			critI = i
		}
		if strings.Contains(a.S, "divergence gate open") {
			divI = i
		}
	}
	if critI < 0 {
		t.Errorf("no consensus-critical line in %v", acts)
	}
	if divI < 0 {
		t.Errorf("no divergence-gate line in %v", acts)
	}
	if critI >= 0 && divI >= 0 && critI > divI {
		t.Errorf("criticality line (%d) must precede divergence (%d)", critI,
			divI)
	}
}

// Port of tests/test_lens_exhaustive.py::test_brief_next_action_names_unattested_family.
func TestBriefNextActionNamesUnattestedFamily(t *testing.T) {
	plan := validation.VObj(
		kv("campaign_id", validation.VStr("")),
		kv("created_at", validation.VStr("2026-09-07T00:00:00Z")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", validation.VArr(validation.VStr("code"))),
			kv("bug_class", validation.VStr("logic-error"))))),
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-04")),
			kv("lens", validation.VStr("primitive-symmetry")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("status", validation.VStr("answered")),
			kv("families", validation.VArr(validation.VStr("withdraw"),
				validation.VStr("mint"))),
			kv("families_checked", validation.VArr(
				validation.VStr("withdraw"))),
			kv("closed_reason", validation.VStr("compared withdraw only")),
			kv("closed_by", validation.VStr("tester"))))))
	c := t35CritCampaign(t, "Lens Program",
		[]validation.Value{t35Contract("Vault", "Vault.sol", "deposit")},
		[]validation.Value{t35StateMachine("vault")}, &plan)
	saved, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	saved.O = setOrAppend(saved.O, "campaign_id", validation.VStr(c.CampaignID))
	if _, err := planner.SavePlan(c, saved); err != nil {
		t.Fatal(err)
	}
	b := build(t, c, false)
	divLines := []string{}
	for _, a := range objAt(b, "next_actions").A {
		if strings.Contains(a.S, "divergence") {
			divLines = append(divLines, a.S)
		}
	}
	if len(divLines) == 0 {
		t.Fatalf("no divergence line in %v", objAt(b, "next_actions"))
	}
	named := false
	for _, l := range divLines {
		if strings.Contains(l, "mint") {
			named = true
		}
	}
	if !named {
		t.Errorf("divergence lines %v do not name the unattested family", divLines)
	}
}
