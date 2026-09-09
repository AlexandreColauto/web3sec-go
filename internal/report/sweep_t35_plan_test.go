package report

// T35 testmap re-triage: tests/test_plan_lenses.py's report rows — the
// hypothesis-lens block renders for a closed divergence gate and stays absent
// when the campaign has no plan.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

func rpMorphModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("morph-l2")),
		kv("name", validation.VStr("Morph L2")),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Rollup")),
			kv("path", validation.VStr("contracts/l2/Rollup.sol")),
			kv("role", validation.VStr("core")),
			kv("in_scope", validation.VBool(true)),
			kv("entry_points", validation.VArr(validation.VStr("commitBatch"),
				validation.VStr("finalizeBatch")))))),
		kv("state_machines", validation.VArr(validation.VObj(
			kv("id", validation.VStr("rollup-lifecycle")),
			kv("transitions", validation.VArr(validation.VStr("commit"),
				validation.VStr("challenge"),
				validation.VStr("finalize")))))))
}

// rpPlanClosedExcept is test_plan_lenses._plan_closed_except.
func rpPlanClosedExcept(t *testing.T, skip string) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	installMemorySeams(t)
	c, err := state.Init(root, "Morph L2", state.InitOpts{
		CampaignID: "C-lens1234"})
	if err != nil {
		t.Fatal(err)
	}
	model := rpMorphModel()
	model.O = rpSet(model.O, "state_machines", validation.VArr(
		validation.VObj(
			kv("name", validation.VStr("rollup-lifecycle")),
			kv("states", validation.VArr(validation.VObj(
				kv("id", validation.VStr("open"))))),
			kv("transitions", validation.VArr(validation.VObj(
				kv("from", validation.VStr("open")),
				kv("to", validation.VStr("finalized")),
				kv("trigger", validation.VStr("finalize"))))))))
	model.O = append(model.O,
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), model, "protocol_model"); err != nil {
		t.Fatalf("write model: %v", err)
	}
	plan, err := planner.DefaultPlanFromModel(c, rpMorphModel())
	if err != nil {
		t.Fatal(err)
	}
	prios0 := listAt(plan, "priorities")
	for i := range prios0 {
		prios0[i].O = rpSet(prios0[i].O, "status",
			validation.VStr("answered"))
	}
	plan.O = rpSet(plan.O, "priorities", validation.VArr(prios0...))
	reason := "fixture: nothing to check"
	checked := []string{"none-applicable"}
	for _, lid := range []string{"L-01", "L-02", "L-03", "L-04"} {
		if lid == skip {
			continue
		}
		plan, err = planner.MarkLens(c, plan, lid, "not-applicable",
			planner.LensOpts{Reason: &reason, Actor: "pytest",
				FamiliesChecked: &checked})
		if err != nil {
			t.Fatalf("mark_lens %s: %v", lid, err)
		}
	}
	if skip != "diversity" {
		classes := []string{"reentrancy", "logic-error",
			"oracle-manipulation", "access-control"}
		prios := append([]validation.Value{}, listAt(plan, "priorities")...)
		for i, cls := range classes {
			prios = append(prios, validation.VObj(
				kv("id", validation.VStr(fmt.Sprintf("Q-%03d", 101+i))),
				kv("question", validation.VStr("shape: canonical bug class named")),
				kv("risk", validation.VFloat(0.5)),
				kv("trajectories", validation.VArr(validation.VStr("code"))),
				kv("status", validation.VStr("answered")),
				kv("closed_reason", validation.VStr("answered by the fixture")),
				kv("closed_by", validation.VStr("pytest")),
				kv("bug_class", validation.VStr(cls))))
		}
		plan.O = rpSet(plan.O, "priorities", validation.VArr(prios...))
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	return c
}

// rpSet replaces (or appends) one key in a KV list.
func rpSet(o []validation.KV, key string, v validation.Value) []validation.KV {
	out := make([]validation.KV, 0, len(o)+1)
	replaced := false
	for _, kv := range o {
		if kv.K == key {
			out = append(out, validation.KV{K: key, V: v})
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: v})
	}
	return out
}

func rpText(t *testing.T, c *state.Campaign) string {
	t.Helper()
	path, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestReportRendersHypothesisLenses(t *testing.T) {
	c := rpPlanClosedExcept(t, "")
	text := rpText(t, c)
	for _, want := range []string{"## Hypothesis lenses", "L-01 liveness",
		"Bug classes named: 4"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, tailLines(text, 40))
		}
	}
}

func TestReportWithoutPlanIsUnchanged(t *testing.T) {
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	installMemorySeams(t)
	c, err := state.Init(root, "Morph L2", state.InitOpts{
		CampaignID: "C-lens1234"})
	if err != nil {
		t.Fatal(err)
	}
	if text := rpText(t, c); strings.Contains(text, "## Hypothesis lenses") {
		t.Fatalf("a plan-less report gained the lens block:\n%s",
			tailLines(text, 40))
	}
}
