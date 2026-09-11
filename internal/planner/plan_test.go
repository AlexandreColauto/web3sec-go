package planner

import (
	"path/filepath"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// pinnedCampaign is a campaign whose id and clock match a recorded plan, so
// every generated field is byte-comparable with the Python oracle.
func pinnedCampaign(t *testing.T, tag string, plan validation.Value) *state.Campaign {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	c, err := state.Init(t.TempDir(), "T9 "+tag, state.InitOpts{
		CampaignID: objStr(plan, "campaign_id")})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// TestDefaultPlanRichOracle pins the full bootstrapped plan for the rich
// model, including the invariants seeded into the campaign first.
func TestDefaultPlanRichOracle(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "default_plan", "rich")
	model, err := validation.ReadJson("testdata/rich_model.json")
	if err != nil {
		t.Fatalf("read rich model: %v", err)
	}
	camp := pinnedCampaign(t, "rich", want)
	if _, err := invariants.SeedFromModel(camp, model); err != nil {
		t.Fatalf("seed invariants: %v", err)
	}
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	requireJSON(t, "rich plan", plan, want)
	qs := []validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		qs = append(qs, objAt(p, "question"))
	}
	requireJSON(t, "rich questions", validation.VArr(qs...),
		at(t, root, "default_plan", "rich_questions"))
}

// TestDefaultPlanRankingOracle pins the plan built from the structural probe
// fixture model (no seeded invariants).
func TestDefaultPlanRankingOracle(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "default_plan", "ranking")
	model, err := validation.ReadJson("testdata/ranking_model.json")
	if err != nil {
		t.Fatalf("read ranking model: %v", err)
	}
	camp := pinnedCampaign(t, "rank", want)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	requireJSON(t, "ranking plan", plan, want)
}

// TestDefaultPlanEmptyModelOracle pins the four-priority floor for a campaign
// with no model at all.
func TestDefaultPlanEmptyModelOracle(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "default_plan", "empty_model")
	camp := pinnedCampaign(t, "empty", want)
	plan, err := DefaultPlanFromModel(camp, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	requireJSON(t, "empty-model plan", plan, want)
	if n := len(listOf(plan, "priorities")); n != 4 {
		t.Fatalf("expected 4 bootstrap priorities, got %d", n)
	}
}

// TestDefaultPlanPreExistingQuestions pins the 3.1 append rule: the D5
// role questions come AFTER every pre-3.1 question, whose text and Q-number
// are unchanged.
func TestDefaultPlanPreExistingQuestions(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "default_plan", "pre_existing")
	model, err := validation.ReadJson("testdata/rich_model.json")
	if err != nil {
		t.Fatalf("read rich model: %v", err)
	}
	rich := at(t, root, "default_plan", "rich")
	camp := pinnedCampaign(t, "rich2", rich)
	if _, err := invariants.SeedFromModel(camp, model); err != nil {
		t.Fatalf("seed invariants: %v", err)
	}
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	prios := listOf(plan, "priorities")
	if len(prios) <= len(want.A) {
		t.Fatalf("plan has %d priorities, want > %d", len(prios), len(want.A))
	}
	for i, q := range want.A {
		requireJSON(t, "pre_existing/"+itoa(i), objAt(prios[i], "question"), q)
		requireJSON(t, "pre_existing id/"+itoa(i), objAt(prios[i], "id"),
			validation.VStr(qid(i+1)))
	}
}

// TestSavePlanBadClassOracle pins the non-canonical bug_class rejection.
func TestSavePlanBadClassOracle(t *testing.T) {
	root := oracles(t)
	model := objAt(at(t, root, "seed_lenses").A[0], "model")
	camp := newCampaign(t, "sp")
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	bad := append(listOf(plan, "priorities"), jsonValue(t,
		`{"id":"Q-900","question":"bogus class: vibes-based shape","risk":0.5,
		  "trajectories":["code"],"status":"open","bug_class":"vibes-based"}`))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(bad...))
	_, err = SavePlan(camp, plan)
	requireErr(t, "bad class", err,
		campaignNamed(t, at(t, root, "save_plan_bad_class"), camp.CampaignID))
}

// TestSavePlanWritesAndRegisters pins the ok path: the file exists, the
// artifact registration is refreshed (not duplicated) and the event trail
// carries the plan saved/reloaded rows.
func TestSavePlanWritesAndRegisters(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "load_plan")
	model := objAt(at(t, root, "seed_lenses").A[0], "model")
	camp := pinnedCampaign(t, "sp2", objAt(want, "plan"))
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	bad := append(listOf(plan, "priorities"), jsonValue(t,
		`{"id":"Q-900","question":"bogus class: vibes-based shape","risk":0.5,
		  "trajectories":["code"],"status":"open","bug_class":"logic-error"}`))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(bad...))
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("second save plan: %v", err)
	}
	loaded, err := LoadPlan(camp,
		filepath.Join(camp.ArtifactsDir, "campaign_plan.json"))
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	requireJSON(t, "reloaded plan", loaded, objAt(want, "plan"))
	if n := len(listOf(loaded, "priorities")); n != int(at(t, root,
		"load_plan", "priorities").I) {
		t.Fatalf("loaded %d priorities", n)
	}
	artifacts, err := camp.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	arts := listOf(artifacts, "artifacts")
	if len(arts) != 1 {
		t.Fatalf("expected exactly 1 artifact row, got %d", len(arts))
	}
	requireJSON(t, "artifact note", objAt(arts[0], "note"),
		objAt(at(t, root, "load_plan", "artifacts").A[0], "note"))
	requireJSON(t, "artifact refresh_reason", objAt(arts[0], "refresh_reason"),
		objAt(at(t, root, "load_plan", "artifacts").A[0], "refresh_reason"))
}

// TestLoadPlanReadonlyMissing pins the FileNotFoundError text.
func TestLoadPlanReadonlyMissing(t *testing.T) {
	camp := newCampaign(t, "lpr")
	_, err := LoadPlanReadonly(camp)
	want := "no campaign plan at " +
		filepath.Join(camp.ArtifactsDir, "campaign_plan.json")
	if err == nil || err.Error() != want {
		t.Fatalf("LoadPlanReadonly error = %v, want %q", err, want)
	}
	if _, err := LoadPlan(camp, filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json")); err == nil {
		t.Fatalf("LoadPlan on a missing file must fail")
	}
}

// TestPlanBuilderStampsCanonicalBugClass: a priority derived from a source row
// that names a canonical bug class carries it, so the diversity clause counts a
// class the row actually asserted. A row that names none — or names a class the
// plan validator would reject — leaves the key off: the builder never invents
// and never propagates a class that would make the plan unsavable.
func TestPlanBuilderStampsCanonicalBugClass(t *testing.T) {
	cases := []struct {
		label string
		src   string
		want  string
	}{
		{"canonical", `{"id":"A-1","bug_class":"logic-error"}`, "logic-error"},
		{"absent", `{"id":"A-2"}`, ""},
		{"null", `{"id":"A-3","bug_class":null}`, ""},
		{"non_canonical", `{"id":"A-4","bug_class":"vibes-based"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			b := &planBuilder{}
			b.add(jsonValue(t, c.src), "is the shape exploitable?", 0.5,
				[]string{"c"}, []string{"code"}, addOpts{})
			if len(b.priorities) != 1 {
				t.Fatalf("priorities = %d", len(b.priorities))
			}
			got, ok := fieldAt(b.priorities[0], "bug_class")
			if c.want == "" {
				if ok {
					t.Fatalf("bug_class = %s; want the key absent",
						validation.CanonCompact(got))
				}
				return
			}
			if !ok || got.Kind != validation.Str || got.S != c.want {
				t.Fatalf("bug_class = %s; want %q",
					validation.CanonCompact(got), c.want)
			}
		})
	}
}

// TestDecisionRuleOracle pins decision_rule over the 108 recorded
// (prior, cost, reachability) combinations, including the default tail.
func TestDecisionRuleOracle(t *testing.T) {
	root := oracles(t)
	rows := at(t, root, "decision_rule")
	if rows.Kind != validation.Arr || len(rows.A) != 108 {
		t.Fatalf("expected 108 decision_rule rows")
	}
	for _, r := range rows.A {
		prior := numAt(jsonValue(t, `{"x":`+validation.CanonCompact(r.A[0])+
			`}`), "x")
		cost := pyStr(r.A[1])
		want := pyStr(r.A[3])
		var got string
		if r.A[2].Kind == validation.Null {
			got = DecisionRule(prior, cost)
		} else {
			got = DecisionRule(prior, cost, pyStr(r.A[2]))
		}
		if got != want {
			t.Fatalf("decision_rule(%v, %s, %s) = %s, want %s", prior, cost,
				pyStr(r.A[2]), got, want)
		}
	}
}
