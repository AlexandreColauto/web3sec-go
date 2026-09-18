package planner

import (
	"slices"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// This file ports the planner-facing tests of the Python suite 1:1:
// tests/test_plan_lenses.py, tests/test_lens_exhaustive.py,
// tests/test_planner_privileged.py, tests/test_answered.py and
// tests/test_disproof_sibling.py. Test names carry the Python name.

// portLensModel is test_plan_lenses.MODEL.
func portLensModel(t *testing.T) validation.Value {
	t.Helper()
	return jsonValue(t, `{"protocol_id":"morph-l2","name":"Morph L2",
		"contracts":[{"name":"Rollup","path":"contracts/l2/Rollup.sol",
			"role":"core","in_scope":true,
			"entry_points":["commitBatch","finalizeBatch"]}],
		"state_machines":[{"id":"rollup-lifecycle",
			"transitions":["commit","challenge","finalize"]}]}`)
}

// portExhModel is test_lens_exhaustive.MODEL.
func portExhModel(t *testing.T) validation.Value {
	t.Helper()
	return jsonValue(t, `{"state_machines":[
			{"name":"rollup","states":[],"transitions":[]},
			{"name":"staking","states":[],"transitions":[]}],
		"actors":[{"id":"sequencer","kind":"privileged"},
			{"id":"challenger","kind":"external"}],
		"contracts":[
			{"name":"L1ERC20Gateway","entry_points":["deposit","finalizeWithdrawal"]},
			{"name":"L1ERC20GatewayReverse","entry_points":["withdraw","drop"]},
			{"name":"Helper","entry_points":["version"]}]}`)
}

// portSibModel is test_disproof_sibling.MODEL.
func portSibModel(t *testing.T) validation.Value {
	t.Helper()
	return jsonValue(t, `{"protocol_id":"sib","name":"Sib Fixture",
		"contracts":[{"name":"L1Gateway","path":"a.sol",
			"entry_points":["deposit","finalizeWithdrawal"]},
			{"name":"L2Gateway","path":"b.sol",
			"entry_points":["withdraw","drop"]}],
		"actors":[],"assets":[],"relations":[],
		"state_machines":[{"name":"rollup","states":[{"id":"open"}],
			"transitions":[{"from":"open","to":"fin","trigger":"finalize"}]}]}`)
}

// portCampaign is test_plan_lenses._campaign (id C-lens1234).
func portCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{
		CampaignID: "C-lens1234"})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// ---- tests/test_plan_lenses.py ------------------------------------------

// TestPortLensConstants is test_lens_constants.
func TestPortLensConstants(t *testing.T) {
	requireJSON(t, "LENS_IDS", validation.StrArr(LensIDs), jsonValue(t,
		`["liveness","incentive-inversion","enforcement-timing",
		  "primitive-symmetry"]`))
	if MinDistinctClasses != 4 {
		t.Fatalf("MIN_DISTINCT_CLASSES = %d, want 4", MinDistinctClasses)
	}
}

// TestPortDefaultPlanSeedsFourLenses is
// test_default_plan_seeds_four_lenses.
func TestPortDefaultPlanSeedsFourLenses(t *testing.T) {
	model := portLensModel(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	ids := []string{}
	for _, l := range listOf(plan, "lenses") {
		ids = append(ids, validation.ObjStr(l, "id"))
		if validation.ObjStr(l, "status") != "open" {
			t.Fatalf("lens %s not open", validation.ObjStr(l, "id"))
		}
	}
	requireJSON(t, "lens ids", validation.StrArr(ids), jsonValue(t,
		`["L-01","L-02","L-03","L-04"]`))
	if !strings.Contains(validation.ObjStr(listOf(plan, "lenses")[0], "question"),
		"rollup-lifecycle") {
		t.Fatalf("liveness question must name the model's state machine")
	}
}

// TestPortSeedLensesIsIdempotent is test_seed_lenses_is_idempotent.
func TestPortSeedLensesIsIdempotent(t *testing.T) {
	model := portLensModel(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	again, plan := SeedLenses(plan, model)
	if len(again) != 0 {
		t.Fatalf("second seed added %d entries", len(again))
	}
	if n := len(listOf(plan, "lenses")); n != 4 {
		t.Fatalf("lens count = %d, want 4", n)
	}
}

// TestPortSeedLensesHealsPreLensPlan is
// test_seed_lenses_heals_a_pre_lens_plan.
func TestPortSeedLensesHealsPreLensPlan(t *testing.T) {
	model := portLensModel(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	plan.O = validation.SetOrAppend(plan.O, "lenses", validation.VArr())
	added, _ := SeedLenses(plan, model)
	ids := []string{}
	for _, l := range added {
		ids = append(ids, validation.ObjStr(l, "id"))
	}
	requireJSON(t, "added", validation.StrArr(ids), jsonValue(t,
		`["L-01","L-02","L-03","L-04"]`))
}

// TestPortPriorityBugClassHardValidates is
// test_priority_bug_class_hard_validates.
func TestPortPriorityBugClassHardValidates(t *testing.T) {
	model := portLensModel(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	bad := append(listOf(plan, "priorities"), jsonValue(t,
		`{"id":"Q-900","question":"bogus class: vibes-based shape","risk":0.5,
		  "trajectories":["code"],"status":"open","bug_class":"vibes-based"}`))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(bad...))
	if _, err := SavePlan(camp, plan); err == nil ||
		!strings.Contains(err.Error(), "non-canonical bug_class") {
		t.Fatalf("save_plan error = %v, want non-canonical bug_class", err)
	}
	last := bad[len(bad)-1]
	last.O = validation.SetOrAppend(last.O, "bug_class", validation.VStr("logic-error"))
	bad[len(bad)-1] = last
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(bad...))
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("canonical class rejected: %v", err)
	}
	if _, ok := taxonomy.KnownClasses()["logic-error"]; !ok {
		t.Fatalf("logic-error must be a canonical class")
	}
}

// TestPortMarkLensClosureAndReopen is test_mark_lens_closure_and_reopen.
func TestPortMarkLensClosureAndReopen(t *testing.T) {
	model := portLensModel(t)
	camp := portCampaign(t, "Morph L2")
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	reason := "no reachable state freezes finalize; challenge is always " +
		"available pre-finalize"
	ref := "contracts/l2/Rollup.sol#L210"
	plan, err = MarkLens(camp, plan, "L-01", "answered", LensOpts{Reason: &reason,
		Ref: &ref, Actor: "pytest"})
	if err != nil {
		t.Fatalf("mark_lens: %v", err)
	}
	l1 := listOf(plan, "lenses")[0]
	requireJSON(t, "status", validation.ObjAt(l1, "status"), validation.VStr("answered"))
	requireJSON(t, "closed_by", validation.ObjAt(l1, "closed_by"), validation.VStr("pytest"))
	requireJSON(t, "closed_ref", validation.ObjAt(l1, "closed_ref"),
		validation.VStr("contracts/l2/Rollup.sol#L210"))
	plan, err = MarkLens(camp, plan, "L-01", "open", LensOpts{Actor: "pytest"})
	if err != nil {
		t.Fatalf("mark_lens reopen: %v", err)
	}
	l1 = listOf(plan, "lenses")[0]
	if hasKey(l1, "closed_reason") || hasKey(l1, "closed_by") ||
		hasKey(l1, "closed_ref") || hasKey(l1, "closed_at") {
		t.Fatalf("reopen must drop the closure provenance")
	}
}

// ---- tests/test_lens_exhaustive.py --------------------------------------

// TestPortLensSchemaHasFamiliesAndReopenFields is
// test_lens_schema_has_families_and_reopen_fields.
func TestPortLensSchemaHasFamiliesAndReopenFields(t *testing.T) {
	schema, err := validation.ReadJson(
		"../../assets/schema/campaign_plan.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	props := validation.ObjAt(validation.ObjAt(validation.ObjAt(validation.ObjAt(schema, "properties"), "lenses"),
		"items"), "properties")
	for _, k := range []string{"families", "families_checked"} {
		p := validation.ObjAt(props, k)
		requireJSON(t, k+" type", validation.ObjAt(p, "type"), validation.VStr("array"))
		requireJSON(t, k+" items", validation.ObjAt(validation.ObjAt(p, "items"), "type"),
			validation.VStr("string"))
	}
	for _, k := range []string{"reopen_reason", "reopened_at"} {
		if !strings.Contains(validation.CanonCompact(validation.ObjAt(validation.ObjAt(props, k),
			"type")), "null") {
			t.Fatalf("%s must accept null", k)
		}
	}
}

// TestPortRound4LensEntryStillValidates is
// test_round4_lens_entry_still_validates_without_families.
func TestPortRound4LensEntryStillValidates(t *testing.T) {
	lens := jsonValue(t, `{"id":"L-04","lens":"primitive-symmetry",
		"surface":"protocol","question":"xxxxxxxxxxxxxxxxxxxx",
		"status":"answered",
		"closed_reason":"compared deposit/withdraw across gateways",
		"closed_ref":null,"closed_at":"2026-09-07T00:00:00Z",
		"closed_by":"tester"}`)
	plan := jsonValue(t, `{"campaign_id":"C-TEST",
		"created_at":"2026-09-07T00:00:00Z",
		"priorities":[{"id":"Q-001","question":"xxxxxxxxxxxxxxxxxxxx",
			"risk":0.5,"trajectories":["code"]}]}`)
	plan.O = validation.SetOrAppend(plan.O, "lenses", validation.VArr(lens))
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		t.Fatalf("round-4 lens entry rejected: %v", err)
	}
	if hasKey(listOf(plan, "lenses")[0], "families") {
		t.Fatalf("the round-4 fixture must stay family-free")
	}
}

// TestPortLensFamiliesDeterministic is
// test_lens_families_are_deterministic_and_per_lens.
func TestPortLensFamiliesDeterministic(t *testing.T) {
	fams := LensFamilies(portExhModel(t))
	requireJSON(t, "liveness", validation.ObjAt(fams, "liveness"), jsonValue(t,
		`["rollup","staking"]`))
	sym := []string{}
	for _, f := range listOf(fams, "primitive-symmetry") {
		sym = append(sym, validation.PyStr(f))
	}
	if slices.Contains(sym, "deposit") {
		t.Fatalf("deposit appears on only one contract: %v", sym)
	}
	if !slices.Contains(sym, "withdraw") {
		t.Fatalf("withdraw appears twice (withdraw + finalizeWithdrawal): %v", sym)
	}
	if slices.Contains(sym, "drop") {
		t.Fatalf("drop appears on only one contract: %v", sym)
	}
}

// TestPortSeedLensesBackfillsFamilies is
// test_seed_lenses_backfills_families_on_existing_entry.
func TestPortSeedLensesBackfillsFamilies(t *testing.T) {
	plan := jsonValue(t, `{"lenses":[{"id":"L-01","lens":"liveness",
		"surface":"protocol","question":"xxxxxxxxxxxxxxxxxxxx",
		"status":"open"}]}`)
	_, plan = SeedLenses(plan, portExhModel(t))
	requireJSON(t, "families", validation.ObjAt(listOf(plan, "lenses")[0], "families"),
		jsonValue(t, `["rollup","staking"]`))
	// the pre-existing entry keeps its identity; the missing three are seeded
	requireJSON(t, "id", validation.ObjAt(listOf(plan, "lenses")[0], "id"),
		validation.VStr("L-01"))
	if n := len(listOf(plan, "lenses")); n != 4 {
		t.Fatalf("expected 4 lenses after seeding, got %d", n)
	}
	requireJSON(t, "status", validation.ObjAt(listOf(plan, "lenses")[0], "status"),
		validation.VStr("open"))
}

// portPlanWithLens is test_lens_exhaustive._plan_with_lens.
func portPlanWithLens(t *testing.T, families, checked []string,
	status string) validation.Value {
	t.Helper()
	fam := []validation.Value{}
	for _, f := range families {
		fam = append(fam, validation.VStr(f))
	}
	chk := []validation.Value{}
	for _, c := range checked {
		chk = append(chk, validation.VStr(c))
	}
	prios := []validation.Value{}
	for i, c := range []string{"access-control", "logic-error", "price-error",
		"reentrancy"} {
		prios = append(prios, validation.VObj(
			kv("id", validation.VStr(qid(i+1))),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("bug_class", validation.VStr(c))))
	}
	lens := validation.VObj(
		kv("id", validation.VStr("L-04")),
		kv("lens", validation.VStr("primitive-symmetry")),
		kv("surface", validation.VStr("protocol")),
		kv("question", validation.VStr(strings.Repeat("q", 20))),
		kv("status", validation.VStr(status)),
		kv("families", validation.VArr(fam...)),
		kv("families_checked", validation.VArr(chk...)),
		kv("closed_reason", validation.VStr("compared the families carefully")),
		kv("closed_by", validation.VStr("tester")),
	)
	return validation.VObj(
		kv("lenses", validation.VArr(lens)),
		kv("priorities", validation.VArr(prios...)))
}

// missingFor reports whether a missing[] entry exists for a subject with all
// the wanted substrings in its `what`.
func missingFor(st validation.Value, subject string, subs ...string) bool {
	for _, m := range listOf(st, "missing") {
		if validation.ObjStr(m, "subject") != subject {
			continue
		}
		what := validation.ObjStr(m, "what")
		ok := true
		for _, s := range subs {
			ok = ok && strings.Contains(what, s)
		}
		if ok {
			return true
		}
	}
	return false
}

// TestPortLensOpenUntilFamiliesAttested is
// test_lens_open_until_all_seeded_families_attested.
func TestPortLensOpenUntilFamiliesAttested(t *testing.T) {
	st := DivergenceStatus(portPlanWithLens(t, []string{"withdraw", "mint"},
		[]string{"withdraw"}, "answered"), DivergenceOpts{})
	if validation.ObjAt(st, "closed").B {
		t.Fatalf("lens must stay open while mint is unattested")
	}
	if !missingFor(st, "L-04", "mint") {
		t.Fatalf("missing[] must name the unattested family: %s",
			validation.CanonCompact(st))
	}
}

// TestPortLensClosedWhenFamiliesCovered is
// test_lens_closed_when_families_covered.
func TestPortLensClosedWhenFamiliesCovered(t *testing.T) {
	st := DivergenceStatus(portPlanWithLens(t, []string{"withdraw", "mint"},
		[]string{"withdraw", "mint"}, "answered"), DivergenceOpts{})
	if !validation.ObjAt(st, "closed").B {
		t.Fatalf("lens must close: %s", validation.CanonCompact(st))
	}
	if missingFor(st, "L-04") {
		t.Fatalf("a closed lens has no missing entries: %s",
			validation.CanonCompact(st))
	}
}

// TestPortNoneApplicableClosesNoFamilyLens is
// test_none_applicable_attestation_closes_a_lens_with_no_real_families.
func TestPortNoneApplicableClosesNoFamilyLens(t *testing.T) {
	st := DivergenceStatus(portPlanWithLens(t, []string{"protocol"},
		[]string{"none-applicable"}, "answered"), DivergenceOpts{})
	if !validation.ObjAt(st, "closed").B {
		t.Fatalf("none-applicable must close a protocol-only lens: %s",
			validation.CanonCompact(st))
	}
	if missingFor(st, "L-04") {
		t.Fatalf("no family is missing: %s", validation.CanonCompact(st))
	}
}

// TestPortNoneApplicableDoesNotSkipRealFamilies is
// test_none_applicable_does_not_skip_real_families.
func TestPortNoneApplicableDoesNotSkipRealFamilies(t *testing.T) {
	st := DivergenceStatus(portPlanWithLens(t, []string{"withdraw", "mint"},
		[]string{"none-applicable"}, "answered"), DivergenceOpts{})
	if validation.ObjAt(st, "closed").B {
		t.Fatalf("none-applicable must not skip real families")
	}
	if !missingFor(st, "L-04", "mint", "withdraw") {
		t.Fatalf("missing[] must name both families: %s",
			validation.CanonCompact(st))
	}
}

// TestPortSeedLensesGrandfathersClosedLens is
// test_seed_lenses_leaves_already_closed_lens_family_free.
func TestPortSeedLensesGrandfathersClosedLens(t *testing.T) {
	plan := jsonValue(t, `{"lenses":[{"id":"L-04","lens":"primitive-symmetry",
		"surface":"protocol","question":"xxxxxxxxxxxxxxxxxxxx",
		"status":"answered",
		"closed_reason":"compared deposit/withdraw across gateways",
		"closed_by":"tester"}]}`)
	_, plan = SeedLenses(plan, portExhModel(t))
	if hasKey(listOf(plan, "lenses")[0], "families") {
		t.Fatalf("a closed lens must not gain a families key")
	}
	st := DivergenceStatus(plan, DivergenceOpts{})
	if missingFor(st, "L-04") {
		t.Fatalf("grandfathered lens must stay closed: %s",
			validation.CanonCompact(st))
	}
}

// TestPortFamiliesForFindingTokens is
// test_families_for_finding_collects_verb_and_machine_tokens.
func TestPortFamiliesForFindingTokens(t *testing.T) {
	toks := FamiliesForFinding(portExhModel(t), jsonValue(t,
		`{"affected":[{"contract":"L1ERC20Gateway"},
		  {"contract":"L1ERC20GatewayReverse"}],
		 "root_cause":{"class":"logic-error"}}`))
	if _, ok := toks["withdraw"]; !ok {
		t.Fatalf("shared lifecycle verb missing: %v", toks)
	}
	none := FamiliesForFinding(portExhModel(t), jsonValue(t,
		`{"affected":[{"contract":"Helper"}],
		  "root_cause":{"class":"logic-error"}}`))
	if len(none) != 0 {
		t.Fatalf("a non-sibling contract must yield no tokens: %v", none)
	}
}

// ---- tests/test_planner_privileged.py -----------------------------------

// portRichCampaign is test_planner_privileged._campaign.
func portRichCampaign(t *testing.T, seed bool) (*state.Campaign,
	validation.Value) {
	t.Helper()
	model, err := validation.ReadJson("testdata/rich_model.json")
	if err != nil {
		t.Fatalf("read rich model: %v", err)
	}
	camp := newCampaign(t, "acme-vault")
	if seed {
		if _, err := invariants.SeedFromModel(camp, model); err != nil {
			t.Fatalf("seed invariants: %v", err)
		}
	}
	return camp, model
}

// constraintQuestions is _constraint_questions.
func constraintQuestions(plan validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		if strings.Contains(validation.ObjStr(p, "question"),
			"Within its stated constraints (") {
			out = append(out, p)
		}
	}
	return out
}

// portPlanWithPrivileges plans the rich model with a replaced privilege table.
func portPlanWithPrivileges(t *testing.T, privileges string) validation.Value {
	t.Helper()
	camp, model := portRichCampaign(t, true)
	model.O = validation.SetOrAppend(model.O, "privileges", jsonValue(t, privileges))
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	return plan
}

// TestPortPerRoleQuestionsWithConstraints is
// test_per_role_questions_with_constraints.
func TestPortPerRoleQuestionsWithConstraints(t *testing.T) {
	camp, model := portRichCampaign(t, true)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	qs := []string{}
	for _, p := range listOf(plan, "priorities") {
		qs = append(qs, validation.ObjStr(p, "question"))
	}
	if !slices.Contains(qs, "Within its stated constraints (timelocked=no, threshold=n/a), "+
		"what can role `guardian` do via `rescue stranded funds` that "+
		"violates user expectations?") {
		t.Fatalf("guardian question missing")
	}
	if !slices.Contains(qs, "Within its stated constraints (timelocked=yes, threshold=3), "+
		"what can role `governor` do via `pause vault; upgrade implementation` "+
		"that violates user expectations?") {
		t.Fatalf("governor question missing")
	}
	cq := constraintQuestions(plan)
	if len(cq) != 2 {
		t.Fatalf("expected 2 constraint questions, got %d", len(cq))
	}
	for _, p := range cq {
		requireJSON(t, "trajectories", validation.ObjAt(p, "trajectories"),
			jsonValue(t, `["attacker"]`))
		requireJSON(t, "budget", validation.ObjAt(p, "budget_class"),
			validation.VStr("cheap"))
		requireJSON(t, "risk", validation.ObjAt(p, "risk"), validation.VFloat(0.8))
	}
}

// TestPortComponentsAreNormalizedRole is
// test_components_are_the_normalized_role.
func TestPortComponentsAreNormalizedRole(t *testing.T) {
	camp, model := portRichCampaign(t, true)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	got := []string{}
	for _, p := range constraintQuestions(plan) {
		comps := listOf(p, "components")
		if len(comps) != 1 {
			t.Fatalf("components must carry exactly the role: %s",
				validation.CanonCompact(p))
		}
		got = append(got, validation.PyStr(comps[0]))
	}
	requireJSON(t, "roles", validation.StrArr(got), jsonValue(t, `["governor","guardian"]`))
}

// TestPortQuestionsAppendAfterExistingOnes is
// test_questions_append_after_existing_ones.
func TestPortQuestionsAppendAfterExistingOnes(t *testing.T) {
	camp, model := portRichCampaign(t, true)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	pre := at(t, oracles(t), "default_plan", "pre_existing")
	firstNew := -1
	ids := []string{}
	for i, p := range listOf(plan, "priorities") {
		ids = append(ids, validation.ObjStr(p, "id"))
		if firstNew < 0 && strings.Contains(validation.ObjStr(p, "question"),
			"Within its stated constraints (") {
			firstNew = i
		}
	}
	if firstNew != len(pre.A) {
		t.Fatalf("first new question at %d, want %d", firstNew, len(pre.A))
	}
	wantIDs := []string{}
	for i := range ids {
		wantIDs = append(wantIDs, qid(i+1))
	}
	requireJSON(t, "ids continue", validation.StrArr(ids), validation.StrArr(wantIDs))
}

// TestPortPreExistingQuestionsUnchanged is
// test_pre_existing_questions_unchanged.
func TestPortPreExistingQuestionsUnchanged(t *testing.T) {
	camp, model := portRichCampaign(t, true)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	pre := at(t, oracles(t), "default_plan", "pre_existing")
	prios := listOf(plan, "priorities")
	if len(prios) < len(pre.A) {
		t.Fatalf("plan shorter than the pre-3.1 list")
	}
	for i, q := range pre.A {
		requireJSON(t, "pre_existing/"+itoa(i), validation.ObjAt(prios[i], "question"), q)
	}
}

// TestPortNoPrivilegeSurfaceAddsNothing is
// test_no_privilege_surface_adds_nothing.
func TestPortNoPrivilegeSurfaceAddsNothing(t *testing.T) {
	camp, model := portRichCampaign(t, true)
	model.O = dropKey(model.O, "privileges")
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if len(constraintQuestions(plan)) != 0 {
		t.Fatalf("no privilege surface must add no constraint questions")
	}
	pre := at(t, oracles(t), "default_plan", "pre_existing")
	qs := []validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		qs = append(qs, validation.ObjAt(p, "question"))
	}
	requireJSON(t, "questions", validation.VArr(qs...), pre)
}

// TestPortMissingConstraintFieldsRenderNo is
// test_missing_constraint_fields_render_no.
func TestPortMissingConstraintFieldsRenderNo(t *testing.T) {
	plan := portPlanWithPrivileges(t, `[{"role":"owner",
		"capability":"everything"}]`)
	qs := constraintQuestions(plan)
	if len(qs) != 1 {
		t.Fatalf("expected 1 constraint question, got %d", len(qs))
	}
	requireJSON(t, "question", validation.ObjAt(qs[0], "question"), validation.VStr(
		"Within its stated constraints (timelocked=no, threshold=n/a), "+
			"what can role `owner` do via `everything` that violates user "+
			"expectations?"))
}

// TestPortTimelockedFalseIsNoNotNa is
// test_timelocked_false_is_no_not_na.
func TestPortTimelockedFalseIsNoNotNa(t *testing.T) {
	plan := portPlanWithPrivileges(t, `[
		{"role":"guardian","capability":"rescue","timelocked":false},
		{"role":"guardian","capability":"pause","timelocked":null}]`)
	qs := constraintQuestions(plan)
	if len(qs) != 1 {
		t.Fatalf("expected 1 constraint question, got %d", len(qs))
	}
	if !strings.HasPrefix(validation.ObjStr(qs[0], "question"),
		"Within its stated constraints (timelocked=no, threshold=n/a), ") {
		t.Fatalf("timelocked=false must render no: %q",
			validation.ObjStr(qs[0], "question"))
	}
}

// TestPortThresholdTakesMaxRecorded is
// test_threshold_takes_the_max_recorded.
func TestPortThresholdTakesMaxRecorded(t *testing.T) {
	plan := portPlanWithPrivileges(t, `[
		{"role":"msa","capability":"one","multisig_threshold":2},
		{"role":"msa","capability":"two","multisig_threshold":5},
		{"role":"msa","capability":"three","multisig_threshold":null}]`)
	qs := constraintQuestions(plan)
	q := validation.ObjStr(qs[0], "question")
	if !strings.HasPrefix(q,
		"Within its stated constraints (timelocked=no, threshold=5), ") {
		t.Fatalf("threshold must be the max recorded: %q", q)
	}
	if !strings.HasSuffix(q, "what can role `msa` do via `one; three; two` "+
		"that violates user expectations?") {
		t.Fatalf("capabilities must be sorted: %q", q)
	}
}

// TestPortFloatThresholdRenders is test_float_threshold_renders.
func TestPortFloatThresholdRenders(t *testing.T) {
	plan := portPlanWithPrivileges(t, `[
		{"role":"msa","capability":"move funds","multisig_threshold":2.5},
		{"role":"nai","capability":"move funds","multisig_threshold":true}]`)
	byRole := map[string]string{}
	for _, p := range constraintQuestions(plan) {
		byRole[validation.PyStr(listOf(p, "components")[0])] = validation.ObjStr(p, "question")
	}
	if !strings.HasPrefix(byRole["msa"],
		"Within its stated constraints (timelocked=no, threshold=2.5), ") {
		t.Fatalf("float threshold must render: %q", byRole["msa"])
	}
	if !strings.HasPrefix(byRole["nai"],
		"Within its stated constraints (timelocked=no, threshold=n/a), ") {
		t.Fatalf("bool threshold must stay n/a: %q", byRole["nai"])
	}
}

// TestPortRoleSpellingVariantsMerge is test_role_spelling_variants_merge.
func TestPortRoleSpellingVariantsMerge(t *testing.T) {
	plan := portPlanWithPrivileges(t, `[
		{"role":"Owner","capability":"b-second"},
		{"role":"owner-v2","capability":"a-first"}]`)
	qs := constraintQuestions(plan)
	roles := []string{}
	for _, p := range qs {
		roles = append(roles, validation.PyStr(listOf(p, "components")[0]))
	}
	requireJSON(t, "roles", validation.StrArr(roles), jsonValue(t,
		`["owner","owner_v2"]`))
	if !strings.HasSuffix(validation.ObjStr(qs[0], "question"),
		"what can role `owner` do via `b-second` that violates user "+
			"expectations?") {
		t.Fatalf("owner question: %q", validation.ObjStr(qs[0], "question"))
	}
	if !strings.HasSuffix(validation.ObjStr(qs[1], "question"),
		"what can role `owner_v2` do via `a-first` that violates user "+
			"expectations?") {
		t.Fatalf("owner_v2 question: %q", validation.ObjStr(qs[1], "question"))
	}
}

// TestPortWorkQueueAcceptsNewRows is test_work_queue_accepts_the_new_rows.
func TestPortWorkQueueAcceptsNewRows(t *testing.T) {
	camp, model := portRichCampaign(t, true)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	queue, err := WorkQueue(camp, plan, model, false)
	if err != nil {
		t.Fatalf("work_queue: %v", err)
	}
	rows := []validation.Value{}
	for _, w := range queue {
		if strings.Contains(validation.ObjStr(w, "question"), "stated constraints") {
			rows = append(rows, w)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 role rows in the queue, got %d", len(rows))
	}
	for _, w := range rows {
		requireJSON(t, "cost", validation.ObjAt(w, "cost"), validation.VStr("cheap"))
		requireJSON(t, "risk", validation.ObjAt(w, "risk"), validation.VFloat(0.8))
		requireJSON(t, "slot", validation.ObjAt(w, "slot"), validation.VStr("now"))
		if r := validation.PyStr(listOf(w, "components")[0]); r != "governor" &&
			r != "guardian" {
			t.Fatalf("components[0] = %q", r)
		}
	}
}

// ---- tests/test_answered.py ---------------------------------------------

// TestPortMarkAnsweredUnknownPriority is
// test_api_mark_answered_unknown_priority_raises.
func TestPortMarkAnsweredUnknownPriority(t *testing.T) {
	camp := newCampaign(t, "answered")
	plan, err := DefaultPlanFromModel(camp, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	_, err = MarkAnswered(camp, plan, "Q-999", "answered", AnsweredOpts{
		Reason: strPtr("no such priority")})
	if err == nil {
		t.Fatalf("expected KeyError for an unknown priority")
	}
	if err.Error() != `"no priority 'Q-999' in the campaign plan"` {
		t.Fatalf("error = %q", err.Error())
	}
}

// ---- tests/test_disproof_sibling.py -------------------------------------

// portSibSetup is test_disproof_sibling._setup.
func portSibSetup(t *testing.T) *state.Campaign {
	t.Helper()
	camp := portCampaign(t, "Morph L2")
	model := portSibModel(t)
	writeModel(t, camp, model)
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	return camp
}

// portLCFinding is test_disproof_sibling._lc_finding.
func portLCFinding(t *testing.T) validation.Value {
	t.Helper()
	return jsonValue(t, `{"finding_id":"F-001","status":"DISPROVED",
		"affected":[{"contract":"L1Gateway"},{"contract":"L2Gateway"}],
		"root_cause":{"class":"logic-error"}}`)
}

// TestPortDisproofOfLifecycleFindingAddsSibling is
// test_disproof_of_lifecycle_finding_adds_sibling_priority.
func TestPortDisproofOfLifecycleFindingAddsSibling(t *testing.T) {
	camp := portSibSetup(t)
	pid, err := SiblingRescan(camp, portLCFinding(t), SiblingOpts{
		Adjacent: "the other root in the same struct"})
	if err != nil {
		t.Fatalf("sibling_rescan: %v", err)
	}
	if pid == "" {
		t.Fatalf("expected a new sibling priority id")
	}
	plan := mustReadPlan(t, camp)
	sibs := []validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		if validation.ObjStr(p, "sibling_of") == "F-001" {
			sibs = append(sibs, p)
		}
	}
	if len(sibs) != 1 || validation.ObjStr(sibs[0], "status") != "open" {
		t.Fatalf("expected one open sibling: %s", validation.CanonCompact(plan))
	}
}

// TestPortAdjacentClearAddsNoPriority is
// test_adjacent_clear_adds_no_priority.
func TestPortAdjacentClearAddsNoPriority(t *testing.T) {
	camp := portSibSetup(t)
	pid, err := SiblingRescan(camp, portLCFinding(t), SiblingOpts{Clear: true,
		Reason: strPtr("sibling already checked")})
	if err != nil {
		t.Fatalf("sibling_rescan clear: %v", err)
	}
	if pid != "" {
		t.Fatalf("clear returned pid %q", pid)
	}
	for _, p := range listOf(mustReadPlan(t, camp), "priorities") {
		if validation.ObjStr(p, "sibling_of") == "F-001" {
			t.Fatalf("clear must add no priority")
		}
	}
}

// TestPortLifecycleDisproofWithoutAdjacentRaises is
// test_lifecycle_disproof_without_adjacent_raises.
func TestPortLifecycleDisproofWithoutAdjacentRaises(t *testing.T) {
	camp := portSibSetup(t)
	_, err := SiblingRescan(camp, portLCFinding(t), SiblingOpts{})
	if err == nil {
		t.Fatalf("expected ValueError for a lifecycle disproof without adjacent")
	}
	if err.Error() != AdjacentRequiredMsg {
		t.Fatalf("error = %q", err.Error())
	}
}

// TestPortNonLifecycleDisproofIsNoop is
// test_non_lifecycle_disproof_is_noop.
func TestPortNonLifecycleDisproofIsNoop(t *testing.T) {
	camp := portSibSetup(t)
	before := len(listOf(mustReadPlan(t, camp), "priorities"))
	f := jsonValue(t, `{"finding_id":"F-009","status":"DISPROVED",
		"affected":[{"contract":"NoSuchContract"}],
		"root_cause":{"class":"logic-error"}}`)
	pid, err := SiblingRescan(camp, f, SiblingOpts{})
	if err != nil || pid != "" {
		t.Fatalf("non-lifecycle disproof = (%q, %v), want no-op", pid, err)
	}
	if after := len(listOf(mustReadPlan(t, camp), "priorities")); after != before {
		t.Fatalf("priority count changed %d -> %d", before, after)
	}
}

// TestPortTransitionRejectsLifecycleDisproofWithoutAdjacent is
// test_transition_rejects_lifecycle_disproof_without_adjacent, run through
// the real findings seam this package wires in init().
func TestPortTransitionRejectsLifecycleDisproofWithoutAdjacent(t *testing.T) {
	camp := portSibSetup(t)
	payload := jsonValue(t, `{
		"title":"drop and withdraw diverge in the gateway pair",
		"root_cause":{"class":"logic-error",
			"description":"two roots share the struct"},
		"affected":[{"path":"a.sol","contract":"L1Gateway"},
			{"path":"b.sol","contract":"L2Gateway"}],
		"attacker":{"profile":"EOA","capabilities":[]}}`)
	f, err := findings.IngestHypothesis(camp, payload, "lifecycle", "39", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := findings.Transition(camp, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	_, err = findings.Transition(camp, fid, "DISPROVED", "ruled out theft path",
		"", "", false)
	if err == nil || err.Error() != AdjacentRequiredMsg {
		t.Fatalf("disproof guard = %v, want %q", err, AdjacentRequiredMsg)
	}
	loaded, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	requireJSON(t, "status not persisted", validation.ObjAt(loaded, "status"),
		validation.VStr("POSSIBLE"))
}

// TestPortTransitionDisproofWithAdjacentSpawnsSibling is
// test_transition_disproof_with_adjacent_spawns_sibling.
func TestPortTransitionDisproofWithAdjacentSpawnsSibling(t *testing.T) {
	camp := portSibSetup(t)
	payload := jsonValue(t, `{
		"title":"drop and withdraw diverge in the gateway pair",
		"root_cause":{"class":"logic-error",
			"description":"two roots share the same struct"},
		"affected":[{"path":"a.sol","contract":"L1Gateway"},
			{"path":"b.sol","contract":"L2Gateway"}],
		"attacker":{"profile":"EOA","capabilities":[]}}`)
	f, err := findings.IngestHypothesis(camp, payload, "lifecycle", "39", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := findings.Transition(camp, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	if _, err := findings.Transition(camp, fid, "DISPROVED", "ruled out",
		"", "the other root in the same struct", false); err != nil {
		t.Fatalf("transition DISPROVED: %v", err)
	}
	loaded, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	requireJSON(t, "status", validation.ObjAt(loaded, "status"),
		validation.VStr("DISPROVED"))
	sibs := []validation.Value{}
	for _, p := range listOf(mustReadPlan(t, camp), "priorities") {
		if validation.ObjStr(p, "sibling_of") == fid {
			sibs = append(sibs, p)
		}
	}
	if len(sibs) != 1 {
		t.Fatalf("expected one sibling priority for %s", fid)
	}
}
