package regression

import (
	"fmt"
	"strings"
	"testing"

	"websec/internal/validation"
)

// syntheticSnapshot mirrors the MEASURED totals of curated-2025-08-18, not
// §3a's prose about it: 31 projects and 114 high findings (measured; §3a's
// "under four per project" is a mean of 3.68, not a bound — the real median is
// 2 and the real max is 12). The CONCENTRATION here is a deliberate
// exaggeration of that distribution, not a measurement: it exists so that
// "pick the six biggest by count" is unmistakably a different pick from the
// weighted one, which is the property this fixture is here to test. The class
// distribution — the biggest projects clustered on two classes, a small
// project carrying a class no other shaped project carries — is what makes the
// weighting matter.
func syntheticSnapshot(t *testing.T) validation.Value {
	t.Helper()
	rows := []validation.Value{}
	for i := 0; i < 27; i++ {
		rows = append(rows, syntheticRows(fmt.Sprintf("filler-%02d", i),
			syntheticFiller[i%len(syntheticFiller)], 1)...)
	}
	rows = append(rows, syntheticRows("big-a", "reentrancy", 32)...)
	rows = append(rows, syntheticRows("big-b", "reentrancy", 32)...)
	rows = append(rows, syntheticRows("big-c", "precision-rounding", 20)...)
	rows = append(rows, syntheticRows("rare-oracle", "oracle-manipulation", 3)...)
	labels, err := DeriveLabels(rows, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	labels.O = validation.SetOrAppend(labels.O, "unmapped_reviewed",
		validation.VBool(true))
	return labels
}

// syntheticFiller is the class cycle of the 27 one-finding filler projects.
// Seven classes over 27 projects: the six common ones get four rows each and
// token-integration gets three.
var syntheticFiller = []string{"precision-rounding", "access-control",
	"dos-griefing", "logic-error", "unchecked-external-call",
	"upgrade-initializer", "token-integration"}

// syntheticRows mints n findings for one project, all of one class.
func syntheticRows(project, class string, n int) []validation.Value {
	out := make([]validation.Value, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, validation.VObj(
			kv("finding_id", validation.VStr(fmt.Sprintf("%s-%d", project, i))),
			kv("project", validation.VStr(project)),
			kv("severity", validation.VStr("high")),
			kv("title", validation.VStr(titleFor(class))),
			kv("description", validation.VStr("mechanism: "+class)),
		))
	}
	return out
}

// titleFor gives every class a title whose phrase the rule table matches —
// built from the rule table itself, so the fixture cannot drift from the
// classifier it is testing (the realism law, one level up).
func titleFor(class string) string {
	for _, rule := range LabelRules {
		if rule.Class == class {
			return rule.Phrases[0]
		}
	}
	return "no rule for " + class
}

func syntheticShapes() map[string]string {
	m := map[string]string{}
	for i := 0; i < 27; i++ {
		m[fmt.Sprintf("filler-%02d", i)] = []string{"vault-erc4626",
			"lending-liquidation", "bridge-messaging",
			"non-rollup-l2-or-oracle"}[i%4]
	}
	m["big-a"] = "vault-erc4626"
	m["big-b"] = "lending-liquidation"
	m["big-c"] = "bridge-messaging"
	m["rare-oracle"] = "non-rollup-l2-or-oracle"
	return m
}

// synthHeldOutA/B are the two held-out projects the greedy actually picks on
// the fixture above, so the hold-out partition is exercised rather than
// refused: filler-01 is slot 5 (access-control, weight 4 beats the rare
// class's 3) and filler-04 is slot 6.
const (
	synthHeldOutA = "filler-01"
	synthHeldOutB = "filler-04"
)

func syntheticSpec(t *testing.T) SelectSpec {
	t.Helper()
	return specWith(syntheticSnapshot(t))
}

func specWith(labels validation.Value) SelectSpec {
	return SelectSpec{
		Labels: labels, Shapes: syntheticShapes(),
		HeldOut: []string{synthHeldOutA, synthHeldOutB}, Picks: 6,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}
}

// TestSelectCoversEveryShapeAndBothPartitions pins the pick ORDER, which is
// the whole algorithm's output: the four shapes first (ScaBenchShapes order),
// then the two weighted-greedy fillers. The order is weight-dependent —
// filler-21 (lending, precision-rounding, class weight 24) takes slot 2 under
// the weighting, and an unweighted gain picks filler-01 there instead and
// big-c in slot 3 — so this literal is what kills a weight mutation.
func TestSelectCoversEveryShapeAndBothPartitions(t *testing.T) {
	sel, err := Select(syntheticSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	picks := validation.ObjAt(sel, "picks").A
	if len(picks) != 6 {
		t.Fatalf("%d picks, want 6", len(picks))
	}
	assertShapesCovered(t, picks)
	if got := countPartition(picks, "held-out"); got != 2 {
		t.Errorf("%d held-out pick(s), want 2 (§3a: 2 held out by project)", got)
	}
	want := strings.Join([]string{
		"big-a/vault-erc4626/dev/32",
		"filler-21/lending-liquidation/dev/1",
		"filler-02/bridge-messaging/dev/1",
		"filler-03/non-rollup-l2-or-oracle/dev/1",
		"filler-01/lending-liquidation/held-out/1",
		"filler-04/vault-erc4626/held-out/1",
	}, "\n")
	if got := pickLines(sel); got != want {
		t.Fatalf("the weighted pick is not the pinned one:\n got\n%s\nwant\n%s",
			got, want)
	}
	assertCoverage(t, sel, 104, 114, 6, 9)
}

// TestSelectDropsTheRareClassAndPinsCoverage records the weighting's MEASURED
// consequence, which is the opposite of what the plan's Step 2 test asserted.
//
// The plan's comment said "the rare class is exactly what the weighting exists
// to catch". Its own Step 4 gain cannot do that: the gain is the SUM OF THE
// CLASS WEIGHTS of the uncovered classes, so a class holding 3 gold findings
// loses every slot to a class holding 4, and oracle-manipulation is never
// picked. On this fixture the weighted and the unweighted greedy cover the
// SAME six classes and the SAME 104 of 114 findings — the weighting moves
// which projects are picked (a 1-finding project inherits its class's total
// weight and beats the 20-finding project that carries those findings), not
// how many classes are covered. This test pins that, so the claim is a
// measurement a later reader can re-derive, and so a change that makes the
// rare class reachable has to argue with it.
func TestSelectDropsTheRareClassAndPinsCoverage(t *testing.T) {
	sel, err := Select(syntheticSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	uncovered := validation.ObjAt(validation.ObjAt(sel, "coverage"),
		"uncovered_classes").A
	want := "oracle-manipulation,token-integration,upgrade-initializer"
	if got := strArrJoin(uncovered); got != want {
		t.Fatalf("uncovered_classes = %q, want %q — the weighted gain covers "+
			"classes by their total gold count, so the 3-finding classes lose "+
			"to the 4-finding ones", got, want)
	}
}

func TestSelectIsDeterministic(t *testing.T) {
	// The record carries created_at from the repo's deterministic-time seam,
	// so a same-input comparison must pin it (WEBV2_NOW); otherwise the two
	// runs differ by microseconds and this test measures the clock, not the
	// selector.
	t.Setenv("WEBV2_NOW", "2026-09-21T00:00:00.000000+00:00")
	spec := syntheticSpec(t)
	first, err := Select(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Select(spec)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(first) != validation.CanonSpaced(second) {
		t.Fatal("Select is not deterministic across two runs of the same input")
	}
}

func TestSelectRefusesUnreviewedLabelsAndABadComposition(t *testing.T) {
	unreviewed := syntheticSnapshot(t)
	unreviewed.O = validation.SetOrAppend(unreviewed.O, "unmapped_reviewed",
		validation.VBool(false))
	assertSelectRefuses(t, specWith(unreviewed), "unmapped_reviewed")
	base := syntheticSpec(t)
	base.HeldOut = []string{"filler-00"}
	assertSelectRefuses(t, base, "holds out exactly 2")
	base.HeldOut = []string{"filler-00", "not-a-project"}
	assertSelectRefuses(t, base, "not-a-project")
	base.HeldOut = []string{synthHeldOutA, synthHeldOutB}
	base.Shapes = syntheticShapes()
	base.Shapes["filler-00"] = "mystery-shape"
	assertSelectRefuses(t, base, "mystery-shape")
	base.Shapes = syntheticShapes()
	base.Picks = 8
	assertSelectRefuses(t, base, "4")
}

// TestSelectRefusesTwoUnknownShapesDeterministically is the shape vocabulary's
// determinism: checkHeldOutShapes walks spec.Shapes, a Go map whose iteration
// order is randomized, so an early return would name a different one of the
// invalid projects on each run. The refusal must list ALL of them, sorted.
func TestSelectRefusesTwoUnknownShapesDeterministically(t *testing.T) {
	spec := syntheticSpec(t)
	spec.Shapes = syntheticShapes()
	spec.Shapes["filler-00"] = "mystery-shape"
	spec.Shapes["filler-01"] = "bogus-shape"
	const want = `project(s) with a shape that is not one of §3a's four ScaBench ` +
		`shapes [vault-erc4626 lending-liquidation bridge-messaging ` +
		`non-rollup-l2-or-oracle]: "filler-00" has shape "mystery-shape", ` +
		`"filler-01" has shape "bogus-shape"`
	for i := 0; i < 8; i++ {
		_, err := Select(spec)
		if err == nil || err.Error() != want {
			t.Fatalf("run %d: err = %v, want the sorted refusal %q", i, err, want)
		}
	}
}

// TestSelectRefusesAnExhaustedSnapshot drives pass 2's exhaustion refusal: four
// shapes fill four of the five picks, and the only remaining shaped project
// carries nothing but an already-covered class, so the fifth slot cannot be
// filled with positive gain. (Without the pass-2 gain gate the filler would be
// taken and this would silently become a valid five-pick suite.)
func TestSelectRefusesAnExhaustedSnapshot(t *testing.T) {
	spec := syntheticSpec(t)
	spec.Picks = 5
	spec.HeldOut = []string{"big-a", "big-b"}
	spec.Shapes = map[string]string{
		"big-a": "vault-erc4626", "big-b": "lending-liquidation",
		"big-c": "bridge-messaging", "rare-oracle": "non-rollup-l2-or-oracle",
		"filler-00": "vault-erc4626",
	}
	assertSelectRefuses(t, spec, "classes are exhausted")
}

// TestSelectRefusesAHoldOutTheGreedyDidNotPick drives the POST-PICK hold-out
// refusal: exactly two projects are named, both are shaped, and the composition
// is fillable — but the greedy selects neither (four picks fill exactly the
// four shape slots) or only one (six picks, the plan's own fixture). A
// held-out target that is not in the suite is held out from nothing.
func TestSelectRefusesAHoldOutTheGreedyDidNotPick(t *testing.T) {
	none := syntheticSpec(t)
	none.Picks = 4
	none.HeldOut = []string{"filler-00", "filler-01"}
	assertSelectRefuses(t, none, "0 of the 2 held-out projects were picked")
	one := syntheticSpec(t)
	one.HeldOut = []string{"filler-00", "filler-01"}
	assertSelectRefuses(t, one, "1 of the 2 held-out projects were picked")
}

// TestSelectRefusesACompositionItCannotFill drives the two refusals that are
// about the SHAPED SET rather than the flags: too few shaped projects to fill
// the picks, and a shape with no shaped project at all. The held-out pair has
// to be shaped first — that check runs earlier and would otherwise be what
// this test measures.
func TestSelectRefusesACompositionItCannotFill(t *testing.T) {
	base := syntheticSpec(t)
	base.HeldOut = []string{"big-a", "big-b"}
	base.Shapes = map[string]string{"big-a": "vault-erc4626",
		"big-b": "lending-liquidation", "big-c": "bridge-messaging"}
	assertSelectRefuses(t, base, "fewer than the 6 picks")
	base.Picks = 4
	base.Shapes["rare-oracle"] = "vault-erc4626"
	assertSelectRefuses(t, base, "no project covers shape")
}

// TestSelectFillsAShapeWhoseClassesAreAlreadyCovered is the pass-1 rule: the
// shape slot is a CONSTRAINT, not an optimization. Here the vault pick covers
// precision-rounding and the bridge shape's only candidate (big-c) carries
// exactly that class — so a gain-gated pass 1 would refuse the whole snapshot
// with "no project covers shape bridge-messaging", which is false. This is not
// a synthetic worry: on the real 2025-08-18 snapshot the one cross-chain
// forwarder's only classified class is upgrade-initializer, which the vault
// pick covers, so the gain-gated pass 1 cannot select a suite at all.
func TestSelectFillsAShapeWhoseClassesAreAlreadyCovered(t *testing.T) {
	spec := syntheticSpec(t)
	spec.HeldOut = []string{"big-a", "big-c"}
	spec.Picks = 4
	spec.Shapes = map[string]string{"big-a": "vault-erc4626",
		"filler-21": "lending-liquidation", "big-c": "bridge-messaging",
		"rare-oracle": "non-rollup-l2-or-oracle"}
	sel, err := Select(spec)
	if err != nil {
		t.Fatal(err)
	}
	picks := validation.ObjAt(sel, "picks").A
	assertShapesCovered(t, picks)
	if got := pickLines(sel); !strings.Contains(got, "big-c/bridge-messaging/") {
		t.Fatalf("the bridge shape's only candidate was not picked:\n%s", got)
	}
}

// TestSelectPickOrderIsPinnedOnASmallComposition pins the exact order on a
// composition where every choice mutation still fills all six slots — so a
// changed greedy shows up as a changed ORDER here rather than only as a
// refused hold-out in the fixture above. Three candidates are in the map and
// never picked, and each is what a wrong gain would take: `big-b` and `big-c`
// carry only classes the shape slots already covered (a gain that ignored
// coverage takes them), and `filler-04` carries a class slot 4 covers.
func TestSelectPickOrderIsPinnedOnASmallComposition(t *testing.T) {
	spec := syntheticSpec(t)
	spec.Shapes = map[string]string{
		"big-a": "vault-erc4626", "filler-04": "vault-erc4626",
		"big-b": "lending-liquidation", "filler-21": "lending-liquidation",
		"big-c": "bridge-messaging", "filler-02": "bridge-messaging",
		"filler-06": "bridge-messaging", "filler-11": "non-rollup-l2-or-oracle",
		"rare-oracle": "non-rollup-l2-or-oracle",
	}
	spec.HeldOut = []string{"filler-02", "filler-06"}
	sel, err := Select(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"big-a/vault-erc4626/dev/32",
		"filler-21/lending-liquidation/dev/1",
		"filler-02/bridge-messaging/held-out/1",
		"filler-11/non-rollup-l2-or-oracle/dev/1",
		"filler-06/bridge-messaging/held-out/1",
		"rare-oracle/non-rollup-l2-or-oracle/dev/3",
	}, "\n")
	if got := pickLines(sel); got != want {
		t.Fatalf("the pick order moved:\n got\n%s\nwant\n%s", got, want)
	}
}

// TestSelectRecordsTheKnownUnfitInput: the selection's own record must name
// the input it was computed from AND say that input's classes are known-unfit
// (Task 3's hand review: 29 of 52 classified rows wrong, and TWO covered
// classes with no defensible row — upgrade-initializer and flash-loan, the
// latter arriving with the vault pick). Without it, the coverage numbers read
// as evidence that the classes are real.
func TestSelectRecordsTheKnownUnfitInput(t *testing.T) {
	sel, err := Select(syntheticSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	note := validation.ObjStr(sel, "input_class_fitness")
	for _, want := range []string{"unfit", "docs/gates/v16-P0.md", "lower bound",
		"upgrade-initializer", "flash-loan"} {
		if !strings.Contains(note, want) {
			t.Errorf("input_class_fitness = %q, want it to carry %q", note, want)
		}
	}
	if got := validation.ObjStr(sel, "dataset"); got != "scabench" {
		t.Errorf("dataset = %q, want the input's own provenance", got)
	}
}

// TestSelectRecordRequiresTheInputCaveatInTheSchema: input_class_fitness is
// REQUIRED by regression_selection.schema.json, not optional decoration. The
// selector's own record must validate with it, and the same record with the
// field removed must be REFUSED by the real validator — otherwise a
// hand-written or future selection without the caveat validates and its
// coverage reads as coverage of REAL classes.
func TestSelectRecordRequiresTheInputCaveatInTheSchema(t *testing.T) {
	sel, err := Select(syntheticSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(sel, "regression_selection", 1); err != nil {
		t.Fatalf("the selector's own record does not validate: %v", err)
	}
	without := sel
	without.O = nil
	for _, kvp := range sel.O {
		if kvp.K != "input_class_fitness" {
			without.O = append(without.O, kvp)
		}
	}
	err = validation.Validate(without, "regression_selection", 1)
	if err == nil {
		t.Fatal("a selection without input_class_fitness validated — the schema's " +
			"required list must include it")
	}
	if !strings.Contains(err.Error(), "input_class_fitness") {
		t.Errorf("the refusal does not name the missing caveat: %v", err)
	}
}

// assertSelectRefuses is the shared refusal assertion: a nil error, or one
// that does not name the cause, is the failure.
func assertSelectRefuses(t *testing.T, spec SelectSpec, want string) {
	t.Helper()
	_, err := Select(spec)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want a refusal naming %q", err, want)
	}
}

func assertShapesCovered(t *testing.T, picks []validation.Value) {
	t.Helper()
	shapes := map[string]bool{}
	for _, p := range picks {
		shapes[validation.ObjStr(p, "shape")] = true
	}
	for _, want := range ScaBenchShapes {
		if !shapes[want] {
			t.Errorf("shape %q is not covered by the picks", want)
		}
	}
}

func countPartition(picks []validation.Value, want string) int {
	n := 0
	for _, p := range picks {
		if validation.ObjStr(p, "partition") == want {
			n++
		}
	}
	return n
}

func pickLines(sel validation.Value) string {
	lines := []string{}
	for _, p := range validation.ObjAt(sel, "picks").A {
		lines = append(lines, fmt.Sprintf("%s/%s/%s/%d",
			validation.ObjStr(p, "project"), validation.ObjStr(p, "shape"),
			validation.ObjStr(p, "partition"),
			validation.ObjAt(p, "gold_findings").I))
	}
	return strings.Join(lines, "\n")
}

func strArrJoin(vals []validation.Value) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, v.S)
	}
	return strings.Join(parts, ",")
}

func assertCoverage(t *testing.T, sel validation.Value, want ...int64) {
	t.Helper()
	cov := validation.ObjAt(sel, "coverage")
	keys := []string{"covered_findings", "total_findings", "covered_classes",
		"total_classes"}
	for i, key := range keys {
		if got := validation.ObjAt(cov, key).I; got != want[i] {
			t.Errorf("coverage.%s = %d, want %d", key, got, want[i])
		}
	}
}
