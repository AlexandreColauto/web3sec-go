package briefing

// T35 testmap re-triage: tests/test_plan_lenses.py's brief rows — the brief
// carries the divergence gate and a next action naming the open lens, and a
// campaign without a plan keeps divergence null.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/archetypes"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

func bfMorphModel() validation.Value {
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

// reconOnRecord runs the REAL recon verbs (prescreen + sinks) over the
// shared sink fixture tree, so the FIX-8 L-04 divergence-gate close sees
// both recon stamps on record — the same way the CLI satisfies the gate.
func reconOnRecord(t *testing.T, c *state.Campaign) {
	t.Helper()
	tree := filepath.Join("..", "structidx", "testdata", "sink")
	if _, err := archetypes.Prescreen(c, tree, nil); err != nil {
		t.Fatalf("prescreen: %v", err)
	}
	if _, err := structidx.ValueFlowReport(c, tree); err != nil {
		t.Fatalf("sinks: %v", err)
	}
}

// bfPlanClosedExcept is test_plan_lenses._plan_closed_except.
func bfPlanClosedExcept(t *testing.T, skip string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Morph L2", state.InitOpts{
		CampaignID: "C-lens1234"})
	if err != nil {
		t.Fatal(err)
	}
	reconOnRecord(t, c)
	model := bfMorphModel()
	model.O = bfSet(model.O, "state_machines", validation.VArr(
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
	plan, err := planner.DefaultPlanFromModel(c, bfMorphModel())
	if err != nil {
		t.Fatal(err)
	}
	prios0 := listAt(plan, "priorities")
	for i := range prios0 {
		prios0[i].O = bfSet(prios0[i].O, "status",
			validation.VStr("answered"))
	}
	plan.O = bfSet(plan.O, "priorities", validation.VArr(prios0...))
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
		plan.O = bfSet(plan.O, "priorities", validation.VArr(prios...))
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	return c
}

// bfSet replaces (or appends) one key in a KV list.
func bfSet(o []validation.KV, key string, v validation.Value) []validation.KV {
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

func TestBriefCarriesDivergenceAndNextAction(t *testing.T) {
	c := bfPlanClosedExcept(t, "L-01")
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	div := objAt(b, "divergence")
	if div.Kind != validation.Obj {
		t.Fatalf("divergence = %v, want an object", div)
	}
	if v := objAt(div, "closed"); v.Kind != validation.Bool || v.B {
		t.Fatalf("divergence.closed = %v, want false", v)
	}
	found := false
	for _, a := range strListOf(objAt(b, "next_actions")) {
		if strings.Contains(a, "L-01") {
			found = true
		}
	}
	if !found {
		t.Fatalf("next_actions does not name L-01: %v", listAt(b, "next_actions"))
	}
}

func TestBriefNoPlanIsUnchanged(t *testing.T) {
	c := newCamp(t, "Morph L2")
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(b, "divergence"); v.Kind != validation.Null {
		t.Fatalf("divergence = %v, want null", v)
	}
	for _, a := range strListOf(objAt(b, "next_actions")) {
		if strings.Contains(a, "divergence gate") {
			t.Fatalf("a plan-less brief gained divergence guidance: %q", a)
		}
	}
}
