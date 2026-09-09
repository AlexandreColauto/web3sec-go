package briefing

// T36 testmap: tests/test_disproof_sibling.py::test_brief_surfaces_open_sibling_priority
// — the brief must surface an OPEN plan priority that carries sibling_of as a
// `work sibling of <fid>: <question>` next action, exactly once.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// siblingModel is tests/test_disproof_sibling.py's MODEL.
func siblingModel() validation.Value {
	l1 := validation.VObj(
		kv("name", validation.VStr("L1Gateway")),
		kv("path", validation.VStr("a.sol")),
		kv("entry_points", validation.VArr(validation.VStr("deposit"),
			validation.VStr("finalizeWithdrawal"))))
	l2 := validation.VObj(
		kv("name", validation.VStr("L2Gateway")),
		kv("path", validation.VStr("b.sol")),
		kv("entry_points", validation.VArr(validation.VStr("withdraw"),
			validation.VStr("drop"))))
	sm := validation.VObj(
		kv("name", validation.VStr("rollup")),
		kv("states", validation.VArr(validation.VObj(
			kv("id", validation.VStr("open"))))),
		kv("transitions", validation.VArr(validation.VObj(
			kv("from", validation.VStr("open")),
			kv("to", validation.VStr("fin")),
			kv("trigger", validation.VStr("finalize"))))))
	return validation.VObj(
		kv("protocol_id", validation.VStr("sib")),
		kv("name", validation.VStr("Sib Fixture")),
		kv("contracts", validation.VArr(l1, l2)),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("state_machines", validation.VArr(sm)))
}

// TestBriefSurfacesOpenSiblingPriority is
// test_brief_surfaces_open_sibling_priority.
func TestBriefSurfacesOpenSiblingPriority(t *testing.T) {
	camp, err := state.Init(t.TempDir(), "Morph L2", state.InitOpts{
		CampaignID: "C-lens1234"})
	if err != nil {
		t.Fatal(err)
	}
	model := siblingModel()
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"protocol_model.json"), model, "protocol_model"); err != nil {
		t.Fatal(err)
	}
	plan, err := planner.DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatal(err)
	}
	prios := append(append([]validation.Value{}, listAt(plan,
		"priorities")...), validation.VObj(
		kv("id", validation.VStr("Q-900")),
		kv("question", validation.VStr("Check the adjacent unchecked property: "+
			"the other root in the struct")),
		kv("risk", validation.VFloat(0.6)),
		kv("trajectories", validation.VArr(validation.VStr("lifecycle"))),
		kv("status", validation.VStr("open")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("sibling_of", validation.VStr("F-001"))))
	plan.O = bfSet(plan.O, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(camp, plan); err != nil {
		t.Fatal(err)
	}
	b, err := BuildBrief(camp, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	acts := strListOf(objAt(b, "next_actions"))
	found := false
	for _, a := range acts {
		if strings.HasPrefix(a, "work sibling of F-001:") &&
			strings.Contains(a, "other root") &&
			strings.Count(strings.ToLower(a), "sibling of f-001") == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no single-marker sibling action in %q", acts)
	}
}
