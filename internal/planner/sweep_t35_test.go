package planner

// T35 testmap re-triage:
// tests/test_plan_rebuild.py::test_mark_answered_rewrites_in_place_without_archiving.
// The living-document write rewrites campaign_plan.json in place: no
// superseded archive, no plan.superseded event, and the registry row's sha256
// follows the new content.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

func TestMarkAnsweredRewritesInPlaceWithoutArchiving(t *testing.T) {
	root := oracles(t)
	model := objAt(at(t, root, "seed_lenses").A[0], "model")
	camp := pinnedCampaign(t, "ma-inplace", objAt(at(t, root, "load_plan"), "plan"))
	plan, err := DefaultPlanFromModel(camp, model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(camp.ArtifactsDir, "campaign_plan.json")
	before, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	pid := objStr(listOf(plan, "priorities")[0], "id")
	reason, ref := "first priority resolved before the query", "Rollup.sol#L45"
	if _, err := MarkAnswered(camp, plan, pid, "answered", AnsweredOpts{
		Reason: &reason, Ref: &ref, Actor: "pytest"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("mark_answered must rewrite the plan on disk")
	}
	if _, err := os.Stat(filepath.Join(camp.ArtifactsDir, "superseded")); !os.IsNotExist(err) {
		t.Fatalf("no superseded archive may be written: %v", err)
	}
	events, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if objStr(e, "type") == "plan.superseded" {
			t.Fatal("mark_answered must not log plan.superseded")
		}
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(after)
	var row validation.Value
	for _, a := range listOf(st, "artifacts") {
		if objStr(a, "kind") == "plan" {
			row = a
			break
		}
	}
	if row.Kind != validation.Obj {
		t.Fatal("no plan artifact row registered")
	}
	if got, want := objStr(row, "sha256"), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("registry sha256 = %q, want %q", got, want)
	}
}

// TestLifecycleTrajectoryIsValid ports
// tests/test_cli.py::test_lifecycle_trajectory_is_valid: the lifecycle
// trajectory is declared in the contract table, mapped to its enum, and
// accepted by both schemas that carry a trajectory enum.
func TestLifecycleTrajectoryIsValid(t *testing.T) {
	var contract validation.Value
	for _, kv := range TrajectoryContracts {
		if kv.K == "H-lifecycle" {
			contract = kv.V
		}
	}
	if contract.Kind != validation.Str || contract.S == "" {
		t.Fatalf("TRAJECTORY_CONTRACTS lacks H-lifecycle: %v", contract)
	}
	if got := TrajectoryToEnum["H-lifecycle"]; got != "lifecycle" {
		t.Fatalf("TRAJECTORY_TO_ENUM[H-lifecycle] = %q, want lifecycle", got)
	}
	for _, name := range []string{"campaign_plan", "finding"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "schema",
			name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "lifecycle") {
			t.Errorf("%s.schema.json does not carry the lifecycle enum", name)
		}
	}
}

// --- tests/test_symmetry_teeth.py: the L-04 primitive attestation ---------

// l04Plan is the Python file's _l04_plan: an answered L-04 primitive-symmetry
// lens over three families, plus four named-class priorities.
func l04Plan(symmetry []validation.Value) validation.Value {
	classes := []string{"access-control", "logic-error", "price-error",
		"reentrancy"}
	prios := make([]validation.Value, 0, len(classes))
	for i, cls := range classes {
		prios = append(prios, validation.VObj(
			kv("id", validation.VStr(fmt.Sprintf("Q-%03d", i+1))),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("bug_class", validation.VStr(cls))))
	}
	checked := []string{}
	for _, s := range symmetry {
		checked = append(checked, objStr(s, "family"))
	}
	return validation.VObj(
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-04")),
			kv("lens", validation.VStr("primitive-symmetry")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("status", validation.VStr("answered")),
			kv("families", strArr([]string{"deposit", "withdraw", "drop"})),
			kv("symmetry", validation.VArr(symmetry...)),
			kv("families_checked", strArr(checked)),
			kv("closed_reason", validation.VStr("compared the gateway primitives")),
			kv("closed_by", validation.VStr("tester"))))),
		kv("priorities", validation.VArr(prios...)))
}

func symEntry(family string, primitives ...string) validation.Value {
	return validation.VObj(
		kv("family", validation.VStr(family)),
		kv("primitives", strArr(primitives)))
}

// l04Missing returns the L-04 missing entry, or Null.
func l04Missing(st validation.Value) validation.Value {
	for _, m := range listOf(st, "missing") {
		if objStr(m, "subject") == "L-04" {
			return m
		}
	}
	return validation.VNull()
}

func TestL04OpenWhenAFamilyHasNoQuotedPrimitive(t *testing.T) {
	st := DivergenceStatus(l04Plan([]validation.Value{
		symEntry("deposit", "burn"), symEntry("withdraw", "mint")}),
		DivergenceOpts{})
	if stClosed(st) {
		t.Fatalf("L-04 must stay open: %v", listOf(st, "missing"))
	}
	m := l04Missing(st)
	if m.Kind != validation.Obj || !strings.Contains(objStr(m, "what"), "drop") {
		t.Fatalf("missing entry = %v, want it to name drop", m)
	}
}

func TestL04ClosedWhenEveryFamilyHasAPrimitive(t *testing.T) {
	st := DivergenceStatus(l04Plan([]validation.Value{
		symEntry("deposit", "burn"), symEntry("withdraw", "mint"),
		symEntry("drop", "safeTransfer")}), DivergenceOpts{})
	if !stClosed(st) {
		t.Fatalf("L-04 must close: %v", listOf(st, "missing"))
	}
}

func TestL04EmptyPrimitiveListDoesNotCount(t *testing.T) {
	st := DivergenceStatus(l04Plan([]validation.Value{
		symEntry("deposit", "burn"), symEntry("withdraw", "mint"),
		symEntry("drop", "")}), DivergenceOpts{})
	if stClosed(st) {
		t.Fatal("a blank primitive is not an attestation")
	}
	if m := l04Missing(st); m.Kind != validation.Obj ||
		!strings.Contains(objStr(m, "what"), "drop") {
		t.Fatalf("missing entry = %v, want it to name drop", m)
	}
}

func TestL04WhitespacePrimitiveDoesNotCount(t *testing.T) {
	st := DivergenceStatus(l04Plan([]validation.Value{
		symEntry("deposit", "burn"), symEntry("withdraw", "   "),
		symEntry("drop", "safeTransfer")}), DivergenceOpts{})
	if stClosed(st) {
		t.Fatal("a whitespace primitive is not an attestation")
	}
	if m := l04Missing(st); m.Kind != validation.Obj ||
		!strings.Contains(objStr(m, "what"), "withdraw") {
		t.Fatalf("missing entry = %v, want it to name withdraw", m)
	}
}

// TestReopenedL04CarriesNoStaleSymmetry ports
// test_symmetry_teeth.py::test_reopened_l04_carries_no_stale_symmetry: the
// anchor rescan reopen drops both the symmetry table and families_checked.
func TestReopenedL04CarriesNoStaleSymmetry(t *testing.T) {
	scnFindingIDs(t)
	camp := portCampaign(t, "Morph L2")
	scnPinNow(t)
	scnGatewayModelArtifact(t, camp)
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(camp.CampaignID)),
		kv("created_at", validation.VStr("2026-09-08T00:00:00Z")),
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-04")),
			kv("lens", validation.VStr("primitive-symmetry")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("status", validation.VStr("answered")),
			kv("families", strArr([]string{"withdraw", "mint"})),
			kv("families_checked", strArr([]string{"withdraw", "mint"})),
			kv("symmetry", validation.VArr(
				symEntry("withdraw", "burn", "mint"), symEntry("mint", "mint"))),
			kv("closed_reason", validation.VStr("compared both families")),
			kv("closed_by", validation.VStr("tester"))))),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question", validation.VStr(strings.Repeat("q", 20))),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", strArr([]string{"code"})),
			kv("bug_class", validation.VStr("logic-error"))))))
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	f := scnConfirmedFinding(t, camp, scnOpts{
		title: "gateway withdraw drains the escrow", severity: "high",
		contract: "L1ERC20Gateway", class: "logic-error",
		fn: "finalizeWithdrawal"})
	fid := objStr(f, "finding_id")
	scnRewrite(t, camp, fid, "affected",
		`[{"path":"contracts/L1ERC20Gateway.sol","contract":"L1ERC20Gateway",
		   "function":"finalizeWithdrawal"},
		  {"path":"contracts/L1ERC20GatewayReverse.sol",
		   "contract":"L1ERC20GatewayReverse","function":"withdraw"}]`)
	if _, err := findings.Transition(camp, fid, "CONFIRMED",
		"sandbox repro: withdraw path drains escrow", "pytest", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	after, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatal(err)
	}
	reopened := validation.VNull()
	for _, l := range listOf(after, "lenses") {
		if objStr(l, "id") == "L-04" {
			reopened = l
		}
	}
	if reopened.Kind != validation.Obj {
		t.Fatal("L-04 missing from the plan")
	}
	if got := objStr(reopened, "status"); got != "open" {
		t.Fatalf("status = %q, want open", got)
	}
	for _, key := range []string{"symmetry", "families_checked"} {
		for _, kv := range reopened.O {
			if kv.K == key {
				t.Errorf("reopened L-04 still carries %s: %v", key, kv.V)
			}
		}
	}
}

// stClosed reads divergence_status().closed.
func stClosed(st validation.Value) bool {
	v := objAt(st, "closed")
	return v.Kind == validation.Bool && v.B
}

// TestRound5LensEntryStillValidatesWithoutSymmetry ports
// test_symmetry_teeth.py::test_round5_lens_entry_still_validates_without_symmetry:
// the new symmetry field is optional, so a round-5 lens entry without it
// still validates.
func TestRound5LensEntryStillValidatesWithoutSymmetry(t *testing.T) {
	lens := jsonValue(t, `{"id":"L-04","lens":"primitive-symmetry",
		"surface":"protocol","question":"xxxxxxxxxxxxxxxxxxxx",
		"status":"answered","families":["withdraw"],
		"families_checked":["withdraw"],
		"closed_reason":"compared the gateway families",
		"closed_ref":null,"closed_at":"2026-09-08T00:00:00Z",
		"closed_by":"tester"}`)
	plan := jsonValue(t, `{"campaign_id":"C-TEST",
		"created_at":"2026-09-08T00:00:00Z",
		"priorities":[{"id":"Q-001","question":"xxxxxxxxxxxxxxxxxxxx",
			"risk":0.5,"trajectories":["code"]}]}`)
	plan.O = setOrAppend(plan.O, "lenses", validation.VArr(lens))
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		t.Fatalf("round-5 lens entry without symmetry rejected: %v", err)
	}
	if hasKey(listOf(plan, "lenses")[0], "symmetry") {
		t.Fatal("the round-5 fixture must stay symmetry-free")
	}
}
