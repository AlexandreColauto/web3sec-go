# Gold Task 2 review package
## commits (55be2c2e..3c095827)
3c095827 feat(orchestrator): adversarial lifecycle machines mint into the work queue (defect 4)
## diffstat
 assets/schema/campaign_plan.schema.json            |   2 +-
 assets/testdata/asset_manifest.json                |   4 +-
 internal/orchestrator/plan.go                      |  12 +
 .../orchestrator/task13_lifecycle_surfaces_test.go | 358 +++++++++++++++++++++
 internal/planner/plan.go                           | 221 ++++++++++++-
 5 files changed, 592 insertions(+), 5 deletions(-)
## full diff (-U10)
diff --git a/assets/schema/campaign_plan.schema.json b/assets/schema/campaign_plan.schema.json
index a52197a5..4713c0b8 100644
--- a/assets/schema/campaign_plan.schema.json
+++ b/assets/schema/campaign_plan.schema.json
@@ -13,21 +13,21 @@
     "strategy_note": { "type": "string" },
 
     "priorities": {
       "type": "array",
       "minItems": 1,
       "items": {
         "type": "object",
         "additionalProperties": false,
         "required": ["id", "question", "risk", "trajectories"],
         "properties": {
-          "id":       { "type": "string", "pattern": "^Q-[0-9]{3}$" },
+          "id":       { "type": "string", "pattern": "^(Q|LC)-[0-9]{3}$" },
           "question": { "type": "string", "minLength": 15 },
           "risk":     { "type": "number", "minimum": 0, "maximum": 1 },
           "components": { "type": "array", "items": { "type": "string" } },
           "invariant_ids": { "type": "array", "items": { "type": "string" } },
           "required_context": {
             "type": "array",
             "description": "artifact ids the specialist pass must be given",
             "items": { "type": "string" }
           },
           "trajectories": {
diff --git a/assets/testdata/asset_manifest.json b/assets/testdata/asset_manifest.json
index 1a9b24b4..e3a3a361 100644
--- a/assets/testdata/asset_manifest.json
+++ b/assets/testdata/asset_manifest.json
@@ -405,22 +405,22 @@
    },
    "assumption.schema.json": {
     "sha256": "1824958e45d59224750046c1634c66226e0e7004275aefdba08fc7f658e64fd4",
     "size": 2929
    },
    "bounty_policy.schema.json": {
     "sha256": "5c97b4009e331acf8e040bc880e1a5d839d96df7592180612ed3fdc8a32dd8a7",
     "size": 7642
    },
    "campaign_plan.schema.json": {
-    "sha256": "eaadacffb17e78e87f96c92b7b468680d68cd4d5b519f0a3f59afe1f372fa235",
-    "size": 10631
+    "sha256": "3a021cb7551a74ae05aecd002a35f402bf426c8db2c178fc6fcde77667a506f1",
+    "size": 10636
    },
    "campaign_state.schema.json": {
     "sha256": "1b71da8673c16e0de7f4a6d794f17348719329e973094812e2d4bd0bbc1f8291",
     "size": 13258
    },
    "chain.schema.json": {
     "sha256": "44542248330cb6ab54788aab820785e135f4f9462ee8b046af5fb02ca0fd1530",
     "size": 7291
    },
    "class_weights.schema.json": {
diff --git a/internal/orchestrator/plan.go b/internal/orchestrator/plan.go
index 8a49ec30..0e588fd8 100644
--- a/internal/orchestrator/plan.go
+++ b/internal/orchestrator/plan.go
@@ -38,20 +38,32 @@ func (o *Orchestrator) Plan(plan, model validation.Value,
 	if existing && !rebuild {
 		return o.planReadOnly(plan, model, planPath)
 	}
 	resolved, err := o.resolvePlan(plan, model)
 	if err != nil {
 		return validation.VNull(), err
 	}
 	return o.writePlan(resolved, planPath, existing, model)
 }
 
+// AdversarialLifecycleMachines is the exported handle for the planner's
+// adversarial-lifecycle selection (Task 2, defect 4): the sorted names of the
+// model's state machines whose name + transition action names carry >= 2
+// distinct adversarial-vocabulary tokens. The MINTING lives in
+// planner.DefaultPlanFromModel (the plan builder); the planner cannot import
+// this package, so this re-export is the package-independent name the plan
+// documents for downstream consumers. Match on the machine NAME — the LC-%03d
+// row ids are positional and display-only.
+func AdversarialLifecycleMachines(model validation.Value) []string {
+	return planner.AdversarialLifecycleMachines(model)
+}
+
 // planReadOnly computes the view from the plan on disk and writes NOTHING.
 func (o *Orchestrator) planReadOnly(plan, model validation.Value,
 	planPath string) (validation.Value, error) {
 	if plan.Kind != validation.Null {
 		return validation.VNull(), orchestrationError("a campaign plan " +
 			"already exists at " + planPath + " — loading another one would " +
 			"clobber the campaign's contract; add --rebuild to regenerate " +
 			"(the current plan is archived)")
 	}
 	current, err := validation.ReadJson(planPath)
diff --git a/internal/orchestrator/task13_lifecycle_surfaces_test.go b/internal/orchestrator/task13_lifecycle_surfaces_test.go
new file mode 100644
index 00000000..405b39dd
--- /dev/null
+++ b/internal/orchestrator/task13_lifecycle_surfaces_test.go
@@ -0,0 +1,358 @@
+// task13_lifecycle_surfaces_test.go — plan §Task 2
+// (docs/superpowers/plans/2026-09-18-gold-findings-closure.md, defect 4): the
+// model's OWN adversarial lifecycle machines mint into the work queue.
+//
+// Law: a state machine qualifies when >= 2 DISTINCT adversarial-vocabulary
+// tokens occur (left-boundary, case-insensitive) across its name and its
+// transition action names combined. A lone benign verb (withdraw, claim,
+// redeem, settle) is happy-path surface and must NOT mint — that is the
+// cardinality rule the plan makes binding, and it is what stops the amplifier
+// misweight being relocated from bridge verbs to vault-exit verbs. The stable
+// handle is the machine NAME; the LC-%03d id is positional and display-only,
+// so no test here pins an LC id by value.
+//
+// The fixture model is written to the campaign's own protocol_model.json and
+// the real Plan verb is driven, so the assertions are on the operator-visible
+// work_queue (the Task 10/12 pattern), not on an internal helper.
+package orchestrator
+
+import (
+	"fmt"
+	"path/filepath"
+	"reflect"
+	"strings"
+	"testing"
+
+	"websec/internal/state"
+	"websec/internal/validation"
+)
+
+// task13Fixture is the campaign state the NEXT PlanFromModel call must build.
+// Findings and the coverage ledger are campaign artifacts, not model keys, so
+// fixtures that need them register them here. PlanFromModel drains the slot,
+// so nothing leaks between tests (this file's tests are sequential).
+var task13Fixture struct {
+	findings []validation.Value
+	coverage validation.Value
+}
+
+// machine builds one state-machine fixture: the name plus one transition per
+// action name, each carrying that action as its schema `trigger` — the field
+// the lifecycle matcher reads.
+func machine(name string, actions ...string) validation.Value {
+	transitions := make([]validation.Value, 0, len(actions))
+	for i, action := range actions {
+		transitions = append(transitions, validation.VObj(
+			kvOf("from", validation.VStr(fmt.Sprintf("s%d", i))),
+			kvOf("to", validation.VStr(fmt.Sprintf("s%d", i+1))),
+			kvOf("trigger", validation.VStr(action)),
+		))
+	}
+	return validation.VObj(
+		kvOf("name", validation.VStr(name)),
+		kvOf("states", validation.VArr(
+			validation.VObj(kvOf("id", validation.VStr("s0"))),
+			validation.VObj(kvOf("id", validation.VStr("s1"))))),
+		kvOf("transitions", validation.VArr(transitions...)),
+	)
+}
+
+// task13Model is the fixture model: one in-scope contract (so the queue's
+// scoring signals have something to read) plus the state machines under test.
+func task13Model(machines, openQuestions []validation.Value) validation.Value {
+	return validation.VObj(
+		kvOf("protocol_id", validation.VStr("lifecycle-fixture")),
+		kvOf("name", validation.VStr("Lifecycle Fixture")),
+		kvOf("snapshot_id", validation.VStr("unpinned")),
+		kvOf("contracts", validation.VArr(validation.VObj(
+			kvOf("name", validation.VStr("Rollup")),
+			kvOf("path", validation.VStr("src/Rollup.sol")),
+			kvOf("in_scope", validation.VBool(true))))),
+		kvOf("invariants", validation.VArr()),
+		kvOf("state_machines", validation.VArr(machines...)),
+		kvOf("open_questions", validation.VArr(openQuestions...)),
+	)
+}
+
+// modelWithMachines is the plain fixture: the machines under test, nothing else.
+func modelWithMachines(t *testing.T, machines ...validation.Value) validation.Value {
+	t.Helper()
+	return task13Model(machines, nil)
+}
+
+// modelWithMachinesAndOpenQuestion is the dedup fixture: an open question that
+// names the machine, so the open-question minter already minted a row for the
+// same surface.
+func modelWithMachinesAndOpenQuestion(t *testing.T, name string,
+	m validation.Value) validation.Value {
+	t.Helper()
+	return task13Model([]validation.Value{m}, []validation.Value{validation.VObj(
+		kvOf("question", validation.VStr("is the "+name+" game modeled?")),
+		kvOf("blocks", validation.VArr(validation.VStr(name))))})
+}
+
+// modelWithMachineAndFinding is the finding-coverage fixture: the campaign
+// PlanFromModel builds carries one live finding that already implicates the
+// machine's surface, so the lifecycle row must not mint.
+func modelWithMachineAndFinding(t *testing.T, name string,
+	m validation.Value) validation.Value {
+	t.Helper()
+	task13Fixture.findings = []validation.Value{validation.VObj(
+		kvOf("finding_id", validation.VStr("F-task13000001")),
+		kvOf("status", validation.VStr("HYPOTHESIS")),
+		kvOf("affected", validation.VArr(validation.VObj(
+			kvOf("path", validation.VStr("src/Rollup.sol")),
+			kvOf("contract", validation.VStr(name))))))}
+	return modelWithMachines(t, m)
+}
+
+// modelWithSweptMachine is the reviewed-row fixture: the machine names an
+// in-scope contract the campaign's coverage ledger already records as swept.
+func modelWithSweptMachine(t *testing.T, name string,
+	m validation.Value) validation.Value {
+	t.Helper()
+	task13Fixture.coverage = validation.VObj(
+		kvOf("campaign_id", validation.VStr("C-lifecycle")),
+		kvOf("snapshot_id", validation.VStr("unpinned")),
+		kvOf("updated_at", validation.VStr("2026-09-18T00:00:00Z")),
+		kvOf("contracts", validation.VArr(validation.VObj(
+			kvOf("path", validation.VStr("src/Rollup.sol")),
+			kvOf("status", validation.VStr("swept")),
+			kvOf("trajectory_counts", validation.VObj(
+				kvOf("code", validation.VInt(1))))))),
+		kvOf("surfaces", validation.VObj()),
+		kvOf("funnel", validation.VObj()),
+		kvOf("gaps", validation.VArr()),
+		kvOf("summary", validation.VObj()))
+	return modelWithMachines(t, m)
+}
+
+// queueRow is the test's view of one work-queue row.
+type queueRow struct {
+	ID         string
+	Slot       string
+	Question   string
+	Components []string
+}
+
+// namesSurface reports whether a row names the surface: in its text or in its
+// components (the two spellings the minted rows and the open-question rows use).
+func namesSurface(row validation.Value, name string) bool {
+	if strings.Contains(strAt(row, "question"), name) {
+		return true
+	}
+	for _, c := range listAt(row, "components") {
+		if pyStr(c) == name {
+			return true
+		}
+	}
+	return false
+}
+
+// PlanFromModel drives the real Plan verb over a campaign whose model artifact
+// is the given document and returns the ordered work queue. Any fixture state
+// registered above is written into the campaign first.
+func PlanFromModel(t *testing.T, model validation.Value) []validation.Value {
+	t.Helper()
+	c, err := state.Init(t.TempDir(), "Lifecycle Fixture Program",
+		state.InitOpts{})
+	if err != nil {
+		t.Fatalf("init campaign: %v", err)
+	}
+	for i, f := range task13Fixture.findings {
+		path := filepath.Join(c.FindingsDir, fmt.Sprintf("F-task13%06d.json", i))
+		if err := validation.WriteJson(path, f, ""); err != nil {
+			t.Fatalf("write finding: %v", err)
+		}
+	}
+	if task13Fixture.coverage.Kind == validation.Obj {
+		path := filepath.Join(c.ArtifactsDir, "coverage.json")
+		if err := validation.WriteJson(path, task13Fixture.coverage, ""); err != nil {
+			t.Fatalf("write coverage: %v", err)
+		}
+	}
+	task13Fixture = struct {
+		findings []validation.Value
+		coverage validation.Value
+	}{}
+	path := filepath.Join(c.ArtifactsDir, "protocol_model.json")
+	if err := validation.WriteJson(path, model, ""); err != nil {
+		t.Fatalf("write model: %v", err)
+	}
+	planned, err := New(c).Plan(validation.VNull(), validation.VNull(), false)
+	if err != nil {
+		t.Fatalf("plan: %v", err)
+	}
+	return listAt(planned, "work_queue")
+}
+
+// findQueueRowByName returns the first queue row naming the surface, or nil.
+func findQueueRowByName(t *testing.T, queue []validation.Value,
+	name string) *queueRow {
+	t.Helper()
+	for _, r := range queue {
+		if !namesSurface(r, name) {
+			continue
+		}
+		comps := []string{}
+		for _, c := range listAt(r, "components") {
+			comps = append(comps, pyStr(c))
+		}
+		return &queueRow{
+			ID:         strAt(r, "priority_id"),
+			Slot:       strAt(r, "slot"),
+			Question:   strAt(r, "question"),
+			Components: comps,
+		}
+	}
+	return nil
+}
+
+// countQueueRowsNaming counts every queue row naming the surface.
+func countQueueRowsNaming(t *testing.T, queue []validation.Value,
+	name string) int {
+	t.Helper()
+	n := 0
+	for _, r := range queue {
+		if namesSurface(r, name) {
+			n++
+		}
+	}
+	return n
+}
+
+func TestAdversarialLifecycleMachines(t *testing.T) {
+	model := modelWithMachines(t,
+		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"),
+		machine("token_vault", "deposit", "transfer", "withdraw"),
+		machine("message_passing", "relayMessage"))
+	got := AdversarialLifecycleMachines(model)
+	want := []string{"rollup_finalization"} // vault has one benign verb (withdraw); relay is asset-flow
+	if !reflect.DeepEqual(got, want) {
+		t.Fatalf("got %v, want %v", got, want)
+	}
+}
+
+func TestLifecycleVocabularyNegativeCases(t *testing.T) {
+	// lone benign verb must NOT mint (cardinality rule)
+	lone := modelWithMachines(t, machine("reward_pool", "claimRewards"))
+	// 'prove' inside another word must NOT count (left-boundary rule)
+	embed := modelWithMachines(t, machine("improvement_flow", "improveProve"))
+	if got := AdversarialLifecycleMachines(lone); len(got) != 0 {
+		t.Fatalf("lone-verb machine minted: %v", got)
+	}
+	if got := AdversarialLifecycleMachines(embed); len(got) != 0 {
+		t.Fatalf("embedded-verb machine minted: %v", got)
+	}
+}
+
+func TestLifecycleSurfaceMintsQueueRow(t *testing.T) {
+	model := modelWithMachines(t, machine("rollup_finalization",
+		"commitBatch", "challengeState", "finalizeBatch"))
+	p := PlanFromModel(t, model)
+	row := findQueueRowByName(t, p, "rollup_finalization")
+	if row == nil {
+		t.Fatal("no work-queue row minted for the adversarial lifecycle machine")
+	}
+	if row.Slot != "now" {
+		t.Fatalf("slot = %q, want now (named-component slotting, Task 10 pattern)", row.Slot)
+	}
+}
+
+func TestLifecycleSurfaceDedupAndCoverage(t *testing.T) {
+	// (a) machine already covered by a minted open-question row for the same component
+	m := modelWithMachinesAndOpenQuestion(t, "rollup_finalization",
+		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"))
+	p := PlanFromModel(t, m)
+	if n := countQueueRowsNaming(t, p, "rollup_finalization"); n != 1 {
+		t.Fatalf("rows naming rollup_finalization = %d, want 1 (dedup vs open questions)", n)
+	}
+	// (b) machine fully covered by an existing finding -> skipped entirely
+	m2 := modelWithMachineAndFinding(t, "rollup_finalization",
+		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"))
+	p2 := PlanFromModel(t, m2)
+	if findQueueRowByName(t, p2, "rollup_finalization") != nil {
+		t.Fatal("covered machine must not mint a lifecycle row")
+	}
+}
+
+// TestLifecycleSurfaceRanksFirst is defect 4's core claim: the adversarial
+// game becomes the NEXT action through the existing scoring path (no new
+// weighting) — the row is minted at risk 0.9 / cheap, so it takes the `now`
+// slot ahead of the generic history-mining question.
+func TestLifecycleSurfaceRanksFirst(t *testing.T) {
+	model := modelWithMachines(t, machine("rollup_finalization",
+		"commitBatch", "challengeState", "finalizeBatch"))
+	p := PlanFromModel(t, model)
+	if len(p) == 0 {
+		t.Fatal("empty work queue")
+	}
+	if !namesSurface(p[0], "rollup_finalization") {
+		t.Fatalf("action #1 = %q, want the lifecycle row: %s",
+			strAt(p[0], "question"), validation.CanonCompact(validation.VArr(p...)))
+	}
+}
+
+// TestLifecycleSurfaceSkipsSweptMachine is the reviewed-row half of the
+// coverage law: the coverage predicate is the queue's own "untouched" test
+// (coverageSwept), so a machine whose surface the ledger already marks swept
+// mints nothing.
+func TestLifecycleSurfaceSkipsSweptMachine(t *testing.T) {
+	model := modelWithSweptMachine(t, "Rollup",
+		machine("Rollup", "commitBatch", "challengeState"))
+	p := PlanFromModel(t, model)
+	if findQueueRowByName(t, p, "Rollup") != nil {
+		t.Fatalf("a swept surface must not mint a lifecycle row: %s",
+			validation.CanonCompact(validation.VArr(p...)))
+	}
+}
+
+// TestLifecycleLeftBoundaryNotSubstring pins the matcher spec's boundary half:
+// a vocabulary token glued to a preceding [0-9a-z_] does not count
+// (`precommit`/`uncommit`/`resettle` are not the adversarial game), while the
+// trailing side stays OPEN, so CamelCase action names (`commitBatch`,
+// `challengeState`) do match — the same left-boundary rule Task 1 pins.
+func TestLifecycleLeftBoundaryNotSubstring(t *testing.T) {
+	embedded := modelWithMachines(t,
+		machine("precommit_flow", "uncommit", "resettle"))
+	if got := AdversarialLifecycleMachines(embedded); len(got) != 0 {
+		t.Fatalf("left-boundary violations minted: %v", got)
+	}
+	trailing := modelWithMachines(t,
+		machine("rollup_finalization", "commitBatch", "challengeState"))
+	if got := AdversarialLifecycleMachines(trailing); !reflect.DeepEqual(got,
+		[]string{"rollup_finalization"}) {
+		t.Fatalf("CamelCase action names must match (no trailing boundary): %v", got)
+	}
+}
+
+// TestLifecycleRowIdSchemeAndText pins the two operator-visible deliverables:
+// the row text names the machine and its verb chain (vocabulary order), and
+// the ids are the positional LC-%03d family over SORTED machine names — the
+// machine name is the stable handle, so no id VALUE is pinned here.
+func TestLifecycleRowIdSchemeAndText(t *testing.T) {
+	model := modelWithMachines(t,
+		machine("alpha_rollup", "commitBatch", "challengeState"),
+		machine("beta_rollup", "finalizeBatch", "challengeState"))
+	p := PlanFromModel(t, model)
+	first := findQueueRowByName(t, p, "alpha_rollup")
+	second := findQueueRowByName(t, p, "beta_rollup")
+	if first == nil || second == nil {
+		t.Fatalf("both adversarial machines must mint: %s",
+			validation.CanonCompact(validation.VArr(p...)))
+	}
+	for _, row := range []*queueRow{first, second} {
+		if !strings.HasPrefix(row.ID, "LC-") {
+			t.Fatalf("row %q id = %q, want the LC- family", row.Question, row.ID)
+		}
+	}
+	if first.ID >= second.ID {
+		t.Fatalf("positional ids must follow the sorted machine names: %s, %s",
+			first.ID, second.ID)
+	}
+	want := "review adversarial lifecycle alpha_rollup " +
+		"(commit → challenge) — no covering finding"
+	if first.Question != want {
+		t.Fatalf("row text = %q, want %q", first.Question, want)
+	}
+}
diff --git a/internal/planner/plan.go b/internal/planner/plan.go
index 8da3c25a..3ed5fedc 100644
--- a/internal/planner/plan.go
+++ b/internal/planner/plan.go
@@ -1,19 +1,20 @@
 package planner
 
 import (
 	"fmt"
 	"os"
 	"path/filepath"
 	"sort"
 	"strings"
 
+	"websec/internal/findings"
 	"websec/internal/invariants"
 	"websec/internal/protocolgraph"
 	"websec/internal/state"
 	"websec/internal/taxonomy"
 	"websec/internal/validation"
 )
 
 // TrajectoryContracts is TRAJECTORY_CONTRACTS (insertion order is the plan's
 // trajectory_matrix order).
 var TrajectoryContracts = []validation.KV{
@@ -270,59 +271,72 @@ type addOpts struct {
 
 // add builds one priority: one Q-%03d row per call, keys in the Python dict's
 // order. src is the source row the question was derived from (validation.VNull
 // for the static/aggregate questions); when it names a CANONICAL bug_class the
 // row is stamped onto the priority, so the diversity clause counts a class the
 // model actually asserted. A non-canonical source class is dropped rather than
 // copied — SavePlan would reject the plan the builder just produced.
 func (b *planBuilder) add(src validation.Value, question string, risk float64,
 	components, trajectories []string, opts addOpts) {
 	b.qi++
+	b.addWithID(qid(b.qi), src, question, risk, components, trajectories, opts)
+}
+
+// addWithID is add with an explicit id: the adversarial-lifecycle rows carry
+// positional LC-%03d ids (their stable handle is the machine NAME), every
+// other row keeps the Q-%03d stream.
+func (b *planBuilder) addWithID(id string, src validation.Value, question string,
+	risk float64, components, trajectories []string, opts addOpts) {
 	budget := opts.budget
 	if budget == "" {
 		budget = "standard"
 	}
 	inv := opts.invariantIDs
 	if inv == nil {
 		inv = []string{}
 	}
 	stages := opts.stages
 	if stages == nil {
 		stages = []string{}
 	}
 	prio := validation.VObj(
-		kv("id", validation.VStr(qid(b.qi))),
+		kv("id", validation.VStr(id)),
 		kv("question", validation.VStr(question)),
 		kv("risk", validation.VFloat(risk)),
 		kv("components", strArr(components)),
 		kv("invariant_ids", strArr(inv)),
 		kv("required_context", strArr([]string{"structural_index",
 			"protocol_model"})),
 		kv("trajectories", strArr(trajectories)),
 		kv("recommended_stages", strArr(stages)),
 		kv("budget_class", validation.VStr(budget)),
 		kv("status", validation.VStr("open")),
 	)
 	if bc := objAt(src, "bug_class"); bc.Kind == validation.Str &&
 		isCanonicalClass(bc.S) {
 		prio.O = validation.SetOrAppend(prio.O, "bug_class", bc)
 	}
 	b.priorities = append(b.priorities, prio)
 }
 
 // qid is f"Q-{n:03d}".
 func qid(n int) string {
+	return "Q-" + pad3(n)
+}
+
+// pad3 is f"{n:03d}".
+func pad3(n int) string {
 	s := itoa(n)
 	for len(s) < 3 {
 		s = "0" + s
 	}
-	return "Q-" + s
+	return s
 }
 
 // DefaultPlanFromModel is default_plan_from_model: bootstrap a plan
 // deterministically from the protocol model + risk heuristics. The LLM
 // planner then refines priorities/questions — this exists so the pipeline
 // runs even before the planner stage is executed.
 func DefaultPlanFromModel(campaign *state.Campaign,
 	model validation.Value) (validation.Value, error) {
 	b := &planBuilder{}
 	bootstrapPrivileged(b, campaign, model)
@@ -335,20 +349,26 @@ func DefaultPlanFromModel(campaign *state.Campaign,
 		"protocol's design (history mining)?", 0.6, []string{},
 		[]string{"historical"}, addOpts{budget: "cheap"})
 	risky := protocolgraph.ExternalAssets(model)
 	if len(risky) > 0 {
 		bootstrapRisky(b, risky)
 	}
 	bootstrapRoles(b, model)
 	// Task 10: the model's OWN open questions compile into the queue. Last,
 	// so every pre-existing question keeps its Q-number byte-for-byte.
 	bootstrapOpenQuestions(b, model)
+	// Task 2 (defect 4): the model's own adversarial lifecycle machines mint
+	// into the same queue, through the same scoring path. Last again, so every
+	// pre-existing question keeps its Q-number byte-for-byte.
+	if err := bootstrapLifecycleSurfaces(b, campaign, model); err != nil {
+		return validation.VNull(), err
+	}
 	plan := validation.VObj(
 		kv("campaign_id", validation.VStr(campaign.CampaignID)),
 		kv("created_at", validation.VStr(nowIso())),
 		kv("snapshot_id", validation.VStr(snapshotIDOrUnpinned(campaign))),
 		kv("strategy_note", validation.VStr("bootstrapped deterministically "+
 			"from protocol model; refine via the planner stage")),
 		kv("priorities", validation.VArr(b.priorities...)),
 		kv("trajectory_matrix", validation.VObj(TrajectoryContracts...)),
 		kv("coverage_targets", coverageTargets(model)),
 	)
@@ -526,20 +546,217 @@ func openQuestionRefs(q validation.Value) []string {
 			if s == "" || seen[s] {
 				continue
 			}
 			seen[s] = true
 			out = append(out, s)
 		}
 	}
 	return out
 }
 
+// ---- Task 2: adversarial-lifecycle surfaces mint into the queue ------------
+
+// lifecycleVocabulary is the adversarial-lifecycle verb vocabulary: the verbs
+// a commit→challenge→finalize (or propose→vote→execute) game is spelled with.
+// Asset-flow verbs (deposit/transfer/relay/swap/mint/burn) are deliberately
+// absent — they are happy-path surface, not the game an adversary wins.
+var lifecycleVocabulary = []string{"commit", "challenge", "finalize", "settle",
+	"claim", "withdraw", "dispute", "prove", "refund", "liquidate", "redeem"}
+
+// lifecycleSurface is one qualifying state machine: its name (the STABLE
+// handle — see the id scheme below) and its verb chain, in vocabulary order.
+type lifecycleSurface struct {
+	name  string
+	chain string
+}
+
+// adversarialLifecycleSurfaces is the model's own state machines that carry an
+// adversarial game, sorted by machine name. The CARDINALITY RULE is binding: a
+// machine qualifies only when >= 2 DISTINCT vocabulary tokens occur across its
+// name and its transition action names combined. A lone `withdraw` (every
+// vault), lone `claim` (airdrops), lone `redeem` (receipt tokens) or lone
+// `settle` (oracle fulfillment) is benign happy-path surface, and minting rows
+// for those would recreate the very noise this task exists to remove.
+//
+// Only transition OBJECTS count, through their schema `trigger` (the action
+// name): a machine whose transitions are not schema-shaped is degenerate and
+// contributes nothing.
+func adversarialLifecycleSurfaces(model validation.Value) []lifecycleSurface {
+	out := []lifecycleSurface{}
+	for _, sm := range listOf(model, "state_machines") {
+		name := objStr(sm, "name")
+		if name == "" {
+			continue
+		}
+		toks := lifecycleMachineTokens(sm)
+		if len(toks) < 2 {
+			continue
+		}
+		out = append(out, lifecycleSurface{name: name,
+			chain: strings.Join(toks, " → ")})
+	}
+	sort.SliceStable(out, func(i, j int) bool {
+		return out[i].name < out[j].name
+	})
+	return out
+}
+
+// AdversarialLifecycleMachines is the exported handle for the selection above:
+// the sorted names of the model's adversarial lifecycle machines (Task 2).
+// Downstream consumers match on the NAME, never on a minted row id — the
+// LC-%03d ids are positional, so a later model that adds an alphabetically
+// earlier machine shifts every id after it.
+func AdversarialLifecycleMachines(model validation.Value) []string {
+	out := []string{}
+	for _, s := range adversarialLifecycleSurfaces(model) {
+		out = append(out, s.name)
+	}
+	return out
+}
+
+// lifecycleMachineTokens is the distinct vocabulary tokens the machine's NAME
+// and its transition action names carry, left-boundary and case-insensitive,
+// in vocabulary order (deterministic, independent of transition order).
+func lifecycleMachineTokens(sm validation.Value) []string {
+	hit := map[string]bool{}
+	scan := func(text string) {
+		for _, tok := range lifecycleVocabulary {
+			if tokenOccursLeftBound(text, tok) {
+				hit[tok] = true
+			}
+		}
+	}
+	scan(objStr(sm, "name"))
+	for _, tr := range listOf(sm, "transitions") {
+		if tr.Kind != validation.Obj {
+			continue
+		}
+		scan(objStr(tr, "trigger"))
+	}
+	out := []string{}
+	for _, tok := range lifecycleVocabulary {
+		if hit[tok] {
+			out = append(out, tok)
+		}
+	}
+	return out
+}
+
+// tokenOccursLeftBound reports whether text contains token starting at a left
+// boundary: the match begins the string, or the character before it is outside
+// [0-9a-z_]. Matching is case-insensitive and there is deliberately NO trailing
+// boundary — `commitBatch` and `challengeState` are action names, so a trailing
+// \b would reject exactly the machines this task must rank.
+//
+// This is the same spec as invariants' tokenOccursLeftBound (Task 1), spelled
+// out here on purpose: the invariants helper is unexported, the two packages'
+// pinned tables are independent, and neither should have to move for the
+// other. Keep the two in sync.
+func tokenOccursLeftBound(text, token string) bool {
+	if token == "" {
+		return false
+	}
+	body := strings.ToLower(text)
+	tok := strings.ToLower(token)
+	for from := 0; from < len(body); {
+		i := strings.Index(body[from:], tok)
+		if i < 0 {
+			return false
+		}
+		at := from + i
+		if at == 0 || !isLowerWordByte(body[at-1]) {
+			return true
+		}
+		from = at + 1
+	}
+	return false
+}
+
+// isLowerWordByte is the left-boundary alphabet on the lowered text: [0-9a-z_].
+func isLowerWordByte(b byte) bool {
+	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
+}
+
+// bootstrapLifecycleSurfaces mints one `now`-slotted row per adversarial
+// lifecycle machine, LAST in the plan build so no pre-existing question's
+// Q-number moves. The rows carry the machine name as their named component, so
+// the EXISTING planner scoring (untouched * 1.0 + severity * 2.0 + openQ *
+// 1.5, slot class primary) ranks them — no new scoring path.
+//
+// Skips are deliberate and run against the ENTIRE work queue minted so far
+// (every earlier minter's rows, not just one family's output), the campaign's
+// live findings, and the coverage ledger's own swept test — the same predicate
+// the queue scoring calls "untouched". A machine whose surface is already
+// covered would make the row's "no covering finding" claim false.
+func bootstrapLifecycleSurfaces(b *planBuilder, campaign *state.Campaign,
+	model validation.Value) error {
+	surfaces := adversarialLifecycleSurfaces(model)
+	if len(surfaces) == 0 {
+		return nil
+	}
+	signals, err := buildQueueSignals(campaign, model)
+	if err != nil {
+		return err
+	}
+	live, err := findings.LoadLiveFindings(campaign)
+	if err != nil {
+		return err
+	}
+	for i, s := range surfaces {
+		if lifecycleSurfaceCovered(s.name, b.priorities, signals, live) {
+			continue
+		}
+		// risk 0.9 / cheap: the adversarial game is answerable by a look at
+		// the code, and it is the highest-risk unmodeled surface — it belongs
+		// in the `now` slot (DecisionRule(0.9, "cheap")), ahead of generic
+		// index work. Positional id over the SORTED machines: a skipped
+		// machine keeps its position, and the machine NAME stays the handle.
+		b.addWithID(lifecycleID(i+1), validation.VNull(),
+			"review adversarial lifecycle "+s.name+" ("+s.chain+
+				") — no covering finding", 0.9, []string{s.name},
+			[]string{"lifecycle"}, addOpts{budget: "cheap"})
+	}
+	return nil
+}
+
+// lifecycleSurfaceCovered is the skip predicate: a queue row already names the
+// machine as one of its components, a live finding already implicates it, or
+// the coverage ledger already marks its surface swept. The component test is
+// exact (not a text search): the queue's own scoring reads `components` as the
+// row's surface identity, and a substring match would let a machine named
+// `rollup` suppress `rollup_finalization`.
+func lifecycleSurfaceCovered(name string, queue []validation.Value,
+	signals *queueSignals, live []validation.Value) bool {
+	for _, row := range queue {
+		for _, c := range listOf(row, "components") {
+			if pyStr(c) == name {
+				return true
+			}
+		}
+	}
+	for _, f := range live {
+		for _, a := range listOf(f, "affected") {
+			if objStr(a, "contract") == name || objStr(a, "path") == name {
+				return true
+			}
+		}
+	}
+	path, ok := signals.inScope[name]
+	return ok && signals.touched[path]
+}
+
+// lifecycleID is f"LC-{n:03d}" — the display-only positional id of a minted
+// lifecycle row. Never a handle: match on the machine name.
+func lifecycleID(n int) string {
+	return "LC-" + pad3(n)
+}
+
 // floatOrInt is a numeric Value as float64 (only used for presence checks).
 func floatOrInt(v validation.Value) float64 {
 	if v.Kind == validation.Flt {
 		return v.F
 	}
 	return float64(v.I)
 }
 
 // maxThresholdText is str(max(thresholds)) over the numeric multisig
 // thresholds, preserving int-vs-float rendering.
