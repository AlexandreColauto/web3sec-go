// task13_lifecycle_surfaces_test.go — plan §Task 2
// (docs/superpowers/plans/2026-09-18-gold-findings-closure.md, defect 4): the
// model's OWN adversarial lifecycle machines mint into the work queue.
//
// Law: a state machine qualifies when >= 2 DISTINCT adversarial-vocabulary
// tokens occur (left-boundary, case-insensitive) across its name and its
// transition action names combined. A lone benign verb (withdraw, claim,
// redeem, settle) is happy-path surface and must NOT mint — that is the
// cardinality rule the plan makes binding, and it is what stops the amplifier
// misweight being relocated from bridge verbs to vault-exit verbs. The stable
// handle is the machine NAME; the LC-%03d id is positional and display-only,
// so no test here pins an LC id by value.
//
// The fixture model is written to the campaign's own protocol_model.json and
// the real Plan verb is driven, so the assertions are on the operator-visible
// work_queue (the Task 10/12 pattern), not on an internal helper.
package orchestrator

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// task13Fixture is the campaign state the NEXT PlanFromModel call must build.
// Findings and the coverage ledger are campaign artifacts, not model keys, so
// fixtures that need them register them here. PlanFromModel drains the slot,
// so nothing leaks between tests (this file's tests are sequential).
var task13Fixture struct {
	findings []validation.Value
	coverage validation.Value
}

// machine builds one state-machine fixture: the name plus one transition per
// action name, each carrying that action as its schema `trigger` — the field
// the lifecycle matcher reads.
func machine(name string, actions ...string) validation.Value {
	transitions := make([]validation.Value, 0, len(actions))
	for i, action := range actions {
		transitions = append(transitions, validation.VObj(
			kvOf("from", validation.VStr(fmt.Sprintf("s%d", i))),
			kvOf("to", validation.VStr(fmt.Sprintf("s%d", i+1))),
			kvOf("trigger", validation.VStr(action)),
		))
	}
	return validation.VObj(
		kvOf("name", validation.VStr(name)),
		kvOf("states", validation.VArr(
			validation.VObj(kvOf("id", validation.VStr("s0"))),
			validation.VObj(kvOf("id", validation.VStr("s1"))))),
		kvOf("transitions", validation.VArr(transitions...)),
	)
}

// task13Model is the fixture model: one in-scope contract (so the queue's
// scoring signals have something to read) plus the state machines under test.
func task13Model(machines, openQuestions []validation.Value) validation.Value {
	return validation.VObj(
		kvOf("protocol_id", validation.VStr("lifecycle-fixture")),
		kvOf("name", validation.VStr("Lifecycle Fixture")),
		kvOf("snapshot_id", validation.VStr("unpinned")),
		kvOf("contracts", validation.VArr(validation.VObj(
			kvOf("name", validation.VStr("Rollup")),
			kvOf("path", validation.VStr("src/Rollup.sol")),
			kvOf("in_scope", validation.VBool(true))))),
		kvOf("invariants", validation.VArr()),
		kvOf("state_machines", validation.VArr(machines...)),
		kvOf("open_questions", validation.VArr(openQuestions...)),
	)
}

// modelWithMachines is the plain fixture: the machines under test, nothing else.
func modelWithMachines(t *testing.T, machines ...validation.Value) validation.Value {
	t.Helper()
	return task13Model(machines, nil)
}

// modelWithMachinesAndOpenQuestion is the dedup fixture: an open question that
// names the machine, so the open-question minter already minted a row for the
// same surface.
func modelWithMachinesAndOpenQuestion(t *testing.T, name string,
	m validation.Value) validation.Value {
	t.Helper()
	return task13Model([]validation.Value{m}, []validation.Value{validation.VObj(
		kvOf("question", validation.VStr("is the "+name+" game modeled?")),
		kvOf("blocks", validation.VArr(validation.VStr(name))))})
}

// modelWithMachineAndFinding is the finding-coverage fixture: the campaign
// PlanFromModel builds carries one live finding that already implicates the
// machine's surface, so the lifecycle row must not mint.
func modelWithMachineAndFinding(t *testing.T, name string,
	m validation.Value) validation.Value {
	t.Helper()
	task13Fixture.findings = []validation.Value{validation.VObj(
		kvOf("finding_id", validation.VStr("F-task13000001")),
		kvOf("status", validation.VStr("HYPOTHESIS")),
		kvOf("affected", validation.VArr(validation.VObj(
			kvOf("path", validation.VStr("src/Rollup.sol")),
			kvOf("contract", validation.VStr(name))))))}
	return modelWithMachines(t, m)
}

// modelWithSweptMachine is the reviewed-row fixture: the machine names an
// in-scope contract the campaign's coverage ledger already records as swept.
func modelWithSweptMachine(t *testing.T, name string,
	m validation.Value) validation.Value {
	t.Helper()
	task13Fixture.coverage = validation.VObj(
		kvOf("campaign_id", validation.VStr("C-lifecycle")),
		kvOf("snapshot_id", validation.VStr("unpinned")),
		kvOf("updated_at", validation.VStr("2026-09-18T00:00:00Z")),
		kvOf("contracts", validation.VArr(validation.VObj(
			kvOf("path", validation.VStr("src/Rollup.sol")),
			kvOf("status", validation.VStr("swept")),
			kvOf("trajectory_counts", validation.VObj(
				kvOf("code", validation.VInt(1))))))),
		kvOf("surfaces", validation.VObj()),
		kvOf("funnel", validation.VObj()),
		kvOf("gaps", validation.VArr()),
		kvOf("summary", validation.VObj()))
	return modelWithMachines(t, m)
}

// queueRow is the test's view of one work-queue row.
type queueRow struct {
	ID         string
	Slot       string
	Question   string
	Components []string
}

// namesSurface reports whether a row names the surface: in its text or in its
// components (the two spellings the minted rows and the open-question rows use).
func namesSurface(row validation.Value, name string) bool {
	if strings.Contains(strAt(row, "question"), name) {
		return true
	}
	for _, c := range listAt(row, "components") {
		if pyStr(c) == name {
			return true
		}
	}
	return false
}

// PlanFromModel drives the real Plan verb over a campaign whose model artifact
// is the given document and returns the ordered work queue. Any fixture state
// registered above is written into the campaign first.
func PlanFromModel(t *testing.T, model validation.Value) []validation.Value {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Lifecycle Fixture Program",
		state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	for i, f := range task13Fixture.findings {
		path := filepath.Join(c.FindingsDir, fmt.Sprintf("F-task13%06d.json", i))
		if err := validation.WriteJson(path, f, ""); err != nil {
			t.Fatalf("write finding: %v", err)
		}
	}
	if task13Fixture.coverage.Kind == validation.Obj {
		path := filepath.Join(c.ArtifactsDir, "coverage.json")
		if err := validation.WriteJson(path, task13Fixture.coverage, ""); err != nil {
			t.Fatalf("write coverage: %v", err)
		}
	}
	task13Fixture = struct {
		findings []validation.Value
		coverage validation.Value
	}{}
	path := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(path, model, ""); err != nil {
		t.Fatalf("write model: %v", err)
	}
	planned, err := New(c).Plan(validation.VNull(), validation.VNull(), false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return listAt(planned, "work_queue")
}

// findQueueRowByName returns the first queue row naming the surface, or nil.
func findQueueRowByName(t *testing.T, queue []validation.Value,
	name string) *queueRow {
	t.Helper()
	for _, r := range queue {
		if !namesSurface(r, name) {
			continue
		}
		comps := []string{}
		for _, c := range listAt(r, "components") {
			comps = append(comps, pyStr(c))
		}
		return &queueRow{
			ID:         strAt(r, "priority_id"),
			Slot:       strAt(r, "slot"),
			Question:   strAt(r, "question"),
			Components: comps,
		}
	}
	return nil
}

// countQueueRowsNaming counts every queue row naming the surface.
func countQueueRowsNaming(t *testing.T, queue []validation.Value,
	name string) int {
	t.Helper()
	n := 0
	for _, r := range queue {
		if namesSurface(r, name) {
			n++
		}
	}
	return n
}

func TestAdversarialLifecycleMachines(t *testing.T) {
	model := modelWithMachines(t,
		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"),
		machine("token_vault", "deposit", "transfer", "withdraw"),
		machine("message_passing", "relayMessage"))
	got := AdversarialLifecycleMachines(model)
	want := []string{"rollup_finalization"} // vault has one benign verb (withdraw); relay is asset-flow
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLifecycleVocabularyNegativeCases(t *testing.T) {
	// lone benign verb must NOT mint (cardinality rule)
	lone := modelWithMachines(t, machine("reward_pool", "claimRewards"))
	// 'prove' inside another word must NOT count (left-boundary rule)
	embed := modelWithMachines(t, machine("improvement_flow", "improveProve"))
	if got := AdversarialLifecycleMachines(lone); len(got) != 0 {
		t.Fatalf("lone-verb machine minted: %v", got)
	}
	if got := AdversarialLifecycleMachines(embed); len(got) != 0 {
		t.Fatalf("embedded-verb machine minted: %v", got)
	}
}

func TestLifecycleSurfaceMintsQueueRow(t *testing.T) {
	model := modelWithMachines(t, machine("rollup_finalization",
		"commitBatch", "challengeState", "finalizeBatch"))
	p := PlanFromModel(t, model)
	row := findQueueRowByName(t, p, "rollup_finalization")
	if row == nil {
		t.Fatal("no work-queue row minted for the adversarial lifecycle machine")
	}
	if row.Slot != "now" {
		t.Fatalf("slot = %q, want now (named-component slotting, Task 10 pattern)", row.Slot)
	}
}

func TestLifecycleSurfaceDedupAndCoverage(t *testing.T) {
	// (a) machine already covered by a minted open-question row for the same component
	m := modelWithMachinesAndOpenQuestion(t, "rollup_finalization",
		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"))
	p := PlanFromModel(t, m)
	if n := countQueueRowsNaming(t, p, "rollup_finalization"); n != 1 {
		t.Fatalf("rows naming rollup_finalization = %d, want 1 (dedup vs open questions)", n)
	}
	// (b) machine fully covered by an existing finding -> skipped entirely
	m2 := modelWithMachineAndFinding(t, "rollup_finalization",
		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"))
	p2 := PlanFromModel(t, m2)
	if findQueueRowByName(t, p2, "rollup_finalization") != nil {
		t.Fatal("covered machine must not mint a lifecycle row")
	}
}

// TestLifecycleSurfaceRanksFirst is defect 4's core claim: the adversarial
// game becomes the NEXT action through the existing scoring path (no new
// weighting) — the row is minted at risk 0.9 / cheap, so it takes the `now`
// slot ahead of the generic history-mining question.
func TestLifecycleSurfaceRanksFirst(t *testing.T) {
	model := modelWithMachines(t, machine("rollup_finalization",
		"commitBatch", "challengeState", "finalizeBatch"))
	p := PlanFromModel(t, model)
	if len(p) == 0 {
		t.Fatal("empty work queue")
	}
	if !namesSurface(p[0], "rollup_finalization") {
		t.Fatalf("action #1 = %q, want the lifecycle row: %s",
			strAt(p[0], "question"), validation.CanonCompact(validation.VArr(p...)))
	}
}

// TestLifecycleSurfaceSkipsSweptMachine is the reviewed-row half of the
// coverage law: the coverage predicate is the queue's own "untouched" test
// (coverageSwept), so a machine whose surface the ledger already marks swept
// mints nothing.
func TestLifecycleSurfaceSkipsSweptMachine(t *testing.T) {
	model := modelWithSweptMachine(t, "Rollup",
		machine("Rollup", "commitBatch", "challengeState"))
	p := PlanFromModel(t, model)
	if findQueueRowByName(t, p, "Rollup") != nil {
		t.Fatalf("a swept surface must not mint a lifecycle row: %s",
			validation.CanonCompact(validation.VArr(p...)))
	}
}

// TestLifecycleLeftBoundaryNotSubstring pins the matcher spec's boundary half:
// a vocabulary token glued to a preceding [0-9a-z_] does not count
// (`precommit`/`uncommit`/`resettle` are not the adversarial game), while the
// trailing side stays OPEN, so CamelCase action names (`commitBatch`,
// `challengeState`) do match — the same left-boundary rule Task 1 pins.
func TestLifecycleLeftBoundaryNotSubstring(t *testing.T) {
	embedded := modelWithMachines(t,
		machine("precommit_flow", "uncommit", "resettle"))
	if got := AdversarialLifecycleMachines(embedded); len(got) != 0 {
		t.Fatalf("left-boundary violations minted: %v", got)
	}
	trailing := modelWithMachines(t,
		machine("rollup_finalization", "commitBatch", "challengeState"))
	if got := AdversarialLifecycleMachines(trailing); !reflect.DeepEqual(got,
		[]string{"rollup_finalization"}) {
		t.Fatalf("CamelCase action names must match (no trailing boundary): %v", got)
	}
}

// TestLifecycleRowIdSchemeAndText pins the two operator-visible deliverables:
// the row text names the machine and its verb chain (vocabulary order), and
// the ids are the positional LC-%03d family over SORTED machine names — the
// machine name is the stable handle, so no id VALUE is pinned here.
func TestLifecycleRowIdSchemeAndText(t *testing.T) {
	model := modelWithMachines(t,
		machine("alpha_rollup", "commitBatch", "challengeState"),
		machine("beta_rollup", "finalizeBatch", "challengeState"))
	p := PlanFromModel(t, model)
	first := findQueueRowByName(t, p, "alpha_rollup")
	second := findQueueRowByName(t, p, "beta_rollup")
	if first == nil || second == nil {
		t.Fatalf("both adversarial machines must mint: %s",
			validation.CanonCompact(validation.VArr(p...)))
	}
	for _, row := range []*queueRow{first, second} {
		if !strings.HasPrefix(row.ID, "LC-") {
			t.Fatalf("row %q id = %q, want the LC- family", row.Question, row.ID)
		}
	}
	if first.ID >= second.ID {
		t.Fatalf("positional ids must follow the sorted machine names: %s, %s",
			first.ID, second.ID)
	}
	want := "review adversarial lifecycle alpha_rollup " +
		"(commit → challenge) — no covering finding"
	if first.Question != want {
		t.Fatalf("row text = %q, want %q", first.Question, want)
	}
}
