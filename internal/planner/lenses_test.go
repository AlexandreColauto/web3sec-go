package planner

import (
	"sort"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestLensFamiliesOracle pins lens_families against the Python oracle for the
// four fixture models (lens fixture, exhaustive fixture, rich model, empty).
func TestLensFamiliesOracle(t *testing.T) {
	root := oracles(t)
	rich, err := validation.ReadJson("testdata/rich_model.json")
	if err != nil {
		t.Fatalf("read rich model: %v", err)
	}
	seeds := at(t, root, "seed_lenses")
	models := map[string]validation.Value{
		"lens_model": validation.ObjAt(seeds.A[0], "model"),
		"exh_model":  validation.ObjAt(seeds.A[2], "model"),
		"rich_model": rich,
		"empty":      validation.VObj(),
	}
	for _, name := range []string{"lens_model", "exh_model", "rich_model",
		"empty"} {
		want := at(t, root, "lens_families", name)
		requireJSON(t, "lens_families/"+name, LensFamilies(models[name]), want)
	}
	if len(models) != 4 {
		t.Fatalf("expected 4 fixture models, got %d", len(models))
	}
}

// TestLensFamiliesEmptyModel checks the or-defaults: every family falls back
// to ["protocol"] and primitive-symmetry needs two contracts per verb.
func TestLensFamiliesEmptyModel(t *testing.T) {
	fams := LensFamilies(validation.VObj())
	requireJSON(t, "empty/liveness", validation.ObjAt(fams, "liveness"),
		jsonValue(t, `["protocol"]`))
	requireJSON(t, "empty/primitive-symmetry", validation.ObjAt(fams,
		"primitive-symmetry"), jsonValue(t, `["protocol"]`))
}

// TestLensFamiliesSymmetryVerbs checks the >= 2 contracts rule: a lifecycle
// verb on two contracts enters primitive-symmetry, on one contract it does not.
func TestLensFamiliesSymmetryVerbs(t *testing.T) {
	model := jsonValue(t, `{"contracts":[
		{"name":"A","entry_points":["deposit","mint"]},
		{"name":"B","entry_points":["withdraw","deposit"]}]}`)
	fams := validation.ObjAt(LensFamilies(model), "primitive-symmetry")
	requireJSON(t, "symmetry", fams, jsonValue(t, `["deposit"]`))
	// withdraw is on B only, mint on A only: neither is a sibling family.
	all := listOf(LensFamilies(model), "primitive-symmetry")
	if len(all) != 1 {
		t.Fatalf("expected exactly the deposit family, got %s",
			validation.CanonCompact(validation.ObjAt(LensFamilies(model),
				"primitive-symmetry")))
	}
}

// TestEntryPointNameAndContractToken pins the two lookup helpers the family
// derivation rests on: string entry points, {"name": ...} entry points, and
// the name-or-path-or-? contract token.
func TestEntryPointNameAndContractToken(t *testing.T) {
	requireJSON(t, "string entry point",
		validation.VStr(entryPointName(validation.VStr("deposit"))),
		validation.VStr("deposit"))
	requireJSON(t, "object entry point", validation.VStr(entryPointName(
		jsonValue(t, `{"name":"withdraw","kind":"external"}`))),
		validation.VStr("withdraw"))
	requireJSON(t, "unnamed entry point",
		validation.VStr(entryPointName(jsonValue(t, `{"kind":"fallback"}`))),
		validation.VStr(""))
	requireJSON(t, "name wins", validation.VStr(contractToken(jsonValue(t,
		`{"name":"Vault","path":"src/Vault.sol"}`))), validation.VStr("Vault"))
	requireJSON(t, "path fallback", validation.VStr(contractToken(jsonValue(t,
		`{"path":"src/Vault.sol"}`))), validation.VStr("src/Vault.sol"))
	requireJSON(t, "no name or path",
		validation.VStr(contractToken(validation.VObj())),
		validation.VStr("?"))
}

// TestFamiliesForFindingOracle pins families_for_finding over the recorded
// finding fixtures (entry-point verbs + state-machine names).
func TestFamiliesForFindingOracle(t *testing.T) {
	root := oracles(t)
	cases := at(t, root, "families_for_finding")
	if cases.Kind != validation.Arr || len(cases.A) != 5 {
		t.Fatalf("expected 5 finding cases, got %v", validation.CanonCompact(cases))
	}
	for i, c := range cases.A {
		want := []string{}
		for _, s := range listOf(c, "toks") {
			want = append(want, pyStr(s))
		}
		sort.Strings(want)
		got := sortedKeys(FamiliesForFinding(validation.ObjAt(c, "model"),
			validation.ObjAt(c, "finding")))
		requireJSON(t, "families_for_finding/"+itoa(i), validation.StrArr(got),
			validation.StrArr(want))
	}
}

// TestFamiliesForFindingNoMatch checks that an unknown contract yields no
// tokens and that a state machine named inside the finding does.
func TestFamiliesForFindingNoMatch(t *testing.T) {
	model := jsonValue(t, `{"contracts":[{"name":"A","entry_points":["deposit"]}],
		"state_machines":[{"name":"rollup"}]}`)
	none := FamiliesForFinding(model, jsonValue(t,
		`{"affected":[{"contract":"Nope"}]}`))
	if len(none) != 0 {
		t.Fatalf("unknown contract should yield no tokens, got %v", none)
	}
	hit := FamiliesForFinding(model, jsonValue(t,
		`{"affected":[{"contract":"Nope","path":"x/Rollup.sol"}]}`))
	if _, ok := hit["rollup"]; !ok {
		t.Fatalf("state machine named in the finding should match: %v", hit)
	}
}

// TestSeedLensesOracle pins seed_lenses: the added entries and the resulting
// plan for the empty, pre-lens, backfill and grandfather plans.
func TestSeedLensesOracle(t *testing.T) {
	root := oracles(t)
	cases := at(t, root, "seed_lenses")
	if cases.Kind != validation.Arr || len(cases.A) != 4 {
		t.Fatalf("expected 4 seed cases")
	}
	for _, c := range cases.A {
		name := validation.ObjStr(c, "name")
		added, plan := SeedLenses(validation.ObjAt(c, "plan_before"), validation.ObjAt(c, "model"))
		requireJSON(t, name+"/added", validation.VArr(added...),
			validation.ObjAt(c, "added"))
		requireJSON(t, name+"/plan", plan, validation.ObjAt(c, "plan_after"))
	}
}

// TestSeedLensesIdempotent checks a second call adds nothing and that only
// open lenses get the family backfill.
func TestSeedLensesIdempotent(t *testing.T) {
	model := jsonValue(t, `{"state_machines":[{"id":"sm-1"}]}`)
	_, plan := SeedLenses(validation.VObj(), model)
	again, plan2 := SeedLenses(plan, model)
	if len(again) != 0 {
		t.Fatalf("second seed added %d entries", len(again))
	}
	requireJSON(t, "idempotent plan", plan2, plan)
	closed := jsonValue(t, `{"lenses":[{"id":"L-01","lens":"liveness",
		"status":"answered"}]}`)
	_, sealed := SeedLenses(closed, model)
	requireJSON(t, "grandfathered lens untouched", validation.ObjAt(listOf(sealed,
		"lenses")[0], "families"), validation.VNull())
}

// TestMarkLensOracle pins the five recorded mark_lens calls: close, reopen,
// unknown id, symmetry attestation and families_checked.
func TestMarkLensOracle(t *testing.T) {
	root := oracles(t)
	model := validation.ObjAt(at(t, root, "seed_lenses").A[0], "model")
	// close
	c := atIdx(t, root, 0, "mark_lens")
	camp := lensCampaign(t, validation.ObjStr(atIdx(t, root, 0, "mark_lens"), "name"))
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	reason := "no reachable state freezes finalize; challenge is always " +
		"available pre-finalize"
	ref := "contracts/l2/Rollup.sol#L210"
	plan, err = MarkLens(camp, plan, "L-01", "answered", LensOpts{Reason: &reason,
		Ref: &ref, Actor: "pytest"})
	if err != nil {
		t.Fatalf("mark_lens close: %v", err)
	}
	requireJSON(t, "close", plan, validation.ObjAt(c, "plan"))
	// reopen
	c = atIdx(t, root, 1, "mark_lens")
	plan, err = MarkLens(camp, plan, "L-01", "open", LensOpts{Actor: "pytest"})
	if err != nil {
		t.Fatalf("mark_lens reopen: %v", err)
	}
	requireJSON(t, "reopen", plan, validation.ObjAt(c, "plan"))
	// unknown
	c = atIdx(t, root, 2, "mark_lens")
	if _, err := MarkLens(camp, plan, "L-99", "answered", LensOpts{Reason: &reason,
		Actor: "a"}); err == nil {
		t.Fatalf("mark_lens unknown: expected KeyError")
	} else {
		requireErr(t, "unknown", err, validation.ObjAt(c, "error"))
	}
	// symmetry
	c = atIdx(t, root, 3, "mark_lens")
	plan, err = DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	// FIX-8: the L-04 closure demands the recon stamps on record; the plan
	// bytes the oracle pins are unaffected by the state-side stamp.
	reconOnRecord(t, camp)
	sym := []validation.Value{
		jsonValue(t, `{"family":"withdraw","primitives":["burn"]}`),
		jsonValue(t, `{"family":"mint","primitives":["mint"," "]}`)}
	reason4 := "compared the families carefully"
	plan, err = MarkLens(camp, plan, "L-04", "answered", LensOpts{Reason: &reason4,
		Actor: "tester", Symmetry: &sym})
	if err != nil {
		t.Fatalf("mark_lens symmetry: %v", err)
	}
	requireJSON(t, "symmetry", plan, validation.ObjAt(c, "plan"))
	// families_checked
	c = atIdx(t, root, 4, "mark_lens")
	plan, err = DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	checked := []string{"none-applicable"}
	reason5 := "single-module fixture; nothing to check here"
	plan, err = MarkLens(camp, plan, "L-02", "answered", LensOpts{Reason: &reason5,
		Actor: "pytest", FamiliesChecked: &checked})
	if err != nil {
		t.Fatalf("mark_lens families_checked: %v", err)
	}
	requireJSON(t, "families_checked", plan, validation.ObjAt(c, "plan"))
}

// lensCampaign is a campaign whose id matches the oracle plan's campaign_id so
// timestamps and ids stay byte-identical.
func lensCampaign(t *testing.T, _ string) *state.Campaign {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	root := t.TempDir()
	c, err := state.Init(root, "T9 ml", state.InitOpts{
		CampaignID: "C-c8536e5f48"})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// TestMarkLensReasonEmptyString checks `reason is not None`: an empty string is
// recorded, a nil reason is not.
func TestMarkLensReasonEmptyString(t *testing.T) {
	camp := newCampaign(t, "ml2")
	fresh := func() validation.Value {
		plan, err := DefaultPlanFromModel(camp, validation.VObj())
		if err != nil {
			t.Fatalf("default plan: %v", err)
		}
		return plan
	}
	empty := ""
	got, err := MarkLens(camp, fresh(), "L-01", "answered",
		LensOpts{Reason: &empty, Actor: "a"})
	if err != nil {
		t.Fatalf("mark_lens: %v", err)
	}
	l := listOf(got, "lenses")[0]
	requireJSON(t, "empty reason recorded", validation.ObjAt(l, "closed_reason"),
		validation.VStr(""))
	got2, err := MarkLens(camp, fresh(), "L-01", "answered", LensOpts{Actor: "a"})
	if err != nil {
		t.Fatalf("mark_lens nil reason: %v", err)
	}
	if hasKey(listOf(got2, "lenses")[0], "closed_reason") {
		t.Fatalf("nil reason must not create closed_reason")
	}
}

// TestModelOrEmptyAbsentAndPresent checks the two arms of _model_or_empty.
func TestModelOrEmptyAbsentAndPresent(t *testing.T) {
	camp := newCampaign(t, "moe")
	requireJSON(t, "absent", ModelOrEmpty(camp), validation.VObj())
	model := jsonValue(t, `{"protocol_id":"morph-l2"}`)
	writeModel(t, camp, model)
	requireJSON(t, "present", ModelOrEmpty(camp), model)
}

// TestRowShapeShaFakeMatchesPython pins the test fake's row_shape_sha against
// the ten shapes the Python probes module produced.
func TestRowShapeShaFakeMatchesPython(t *testing.T) {
	shapes, err := validation.ReadJson("testdata/row_shapes.json")
	if err != nil {
		t.Fatalf("read row_shapes: %v", err)
	}
	surface, err := validation.ReadJson("testdata/probe_surface.json")
	if err != nil {
		t.Fatalf("read surface: %v", err)
	}
	n := 0
	for _, row := range listOf(surface, "rows") {
		rid := validation.ObjStr(row, "row_id")
		want := validation.ObjStr(shapes, rid)
		if want == "" {
			continue
		}
		if got := rowShapeSha(row); got != want {
			t.Fatalf("row_shape_sha(%s) = %s, want %s", rid, got, want)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("expected at least 10 shapes, checked %d", n)
	}
}
