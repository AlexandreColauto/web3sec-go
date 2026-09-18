### Task 2: adversarial-lifecycle surfaces mint into the work queue

Defect 4: "The amplifier signal was misweighted for this target — nothing pointed at the adversarial commit→challenge→finalize game" (structural diagnosis: "nothing enforces that the highest-risk unmodeled surface becomes the next action"). G-01 lives in a lifecycle game, not in a message-flow class. The hardening branch already ranks open questions and risk-weights the queue (planner `scoreRow`: `untouched*1.0 + severity*2.0 + openQ*1.5`, slot class primary); this task mints queue rows for the model's own state machines so the adversarial game reaches action #1 through the existing machinery — no new scoring path.

**Files:**
- Modify: `internal/orchestrator/plan.go` (the file holding `DefaultPlanFromModel` and `bootstrapOpenQuestions` — locate with `rg -n "bootstrapOpenQuestions" internal/orchestrator`)
- Test: `internal/orchestrator/task13_lifecycle_surfaces_test.go` (new)

**Interfaces:**
- Consumes: `DefaultPlanFromModel`'s model value (the schema-validated protocol model; state machines under the model key the Task 3 liveness gate reads — `rg -n "state_machines" internal/` to confirm the exact key); `bootstrapOpenQuestions`' mint pattern (row shape, id prefix, slotting via `DecisionRule(0.9, "cheap")`); planner `scoreRow` constants (`internal/planner/task12_queue_scoring_test.go` documents them).
- Produces: exported `orchestrator.AdversarialLifecycleMachines(model validation.Value) []string` — sorted machine names meeting the **cardinality rule** below. Later tasks (Task 5 protocol) rely on this naming. Empty/degenerate models return an empty slice.
- **Matcher:** the same left-boundary case-insensitive token rule as Task 1 (one shared spec; Task 2 may re-implement it locally in `orchestrator` rather than importing `invariants` — packages are independent; a duplicate small helper with the same pinned test table is acceptable and keeps package boundaries clean. Do NOT import `internal/invariants` from `orchestrator` just for the matcher).
- **Cardinality rule (binding — prevents relocating the amplifier-misweight defect from bridge verbs to vault-exit verbs):** a machine qualifies only when **≥ 2 distinct** adversarial-vocabulary tokens occur (left-boundary, case-insensitive) across its name and transition action names combined. The vocabulary is `commit, challenge, finalize, settle, claim, withdraw, dispute, prove, refund, liquidate, redeem`. Rationale: a true adversarial game is a commit→challenge→finalize *chain*; a lone `withdraw` (every vault), lone `claim` (airdrops), lone `redeem` (receipt tokens), lone `settle` (oracle fulfillment) is benign happy-path surface, and single-verb matching would mint spurious rows — the exact noise this task exists to remove.
- **Id scheme:** rows get positional ids `LC-001…` assigned over sorted machine names at mint time, following the Q-id pattern. **The stable handle is the machine NAME, never the id** — a later campaign adding a machine alphabetically earlier shifts every subsequent id. Pins and downstream consumers (including Task 5's protocol) must match on the machine name; the id is display-only. Any golden pin that references an LC-id by value is a review-blocking finding.

- [ ] **Step 0: Pre-flight — oracle blast radius**

Inspect `internal/orchestrator/testdata/oracles.json`'s model machines (`rg -n "commit|challenge|finalize|settle|claim|withdraw|dispute|prove|refund|liquidate|redeem" internal/orchestrator/testdata/ -i`): if any pinned fixture model carries a machine meeting the cardinality rule, the `work_queue` order moves and oracle rows will be re-recorded in Step 4. Record the count in the report.

- [ ] **Step 1: Write the failing tests**

```go
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
```

The minted row's text must name the machine and its verb chain, e.g. `review adversarial lifecycle rollup_finalization (commit → challenge → finalize) — no covering finding`, and must be command-first per the Task 7 law: `webv2 plan <cid> --json  # review adversarial lifecycle rollup_finalization (commit → challenge → finalize)`. **Dedup scope:** the skip checks run against the ENTIRE existing work queue (open-question rows AND any other already-minted rows), not just `bootstrapOpenQuestions`' output — the planner may run iteratively, and a dedup check scoped to one minter would not survive replanning. Machines fully covered by an existing finding or reviewed row are skipped — the coverage predicate is the same one Task 10 uses for "untouched". Asset-flow verbs (deposit/transfer/relay/swap/mint/burn) are deliberately NOT in the vocabulary.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/orchestrator -run "Lifecycle" -count=1`
Expected: FAIL — `AdversarialLifecycleMachines undefined`, no queue row minted.

- [ ] **Step 3: Implement**

Add the vocabulary matcher (left-boundary, case-insensitive), the ≥2-distinct-token cardinality rule, and `AdversarialLifecycleMachines` in `internal/orchestrator/plan.go`; call it from `DefaultPlanFromModel` last, after `bootstrapOpenQuestions` (stable order: sorted machine names; ids `LC-001…`). Rows carry the machine's `applies_to` contracts as named components so the existing planner slotting ranks them.

- [ ] **Step 4: Tests green, then package gates**

Run: `go test ./internal/orchestrator ./internal/planner ./internal/briefing -count=1`, then `go test ./... -count=1`, `go vet ./...`, `scripts/golden.sh`.
Expected: green. `internal/orchestrator/testdata/oracles.json` pins `planned` scenarios — if a fixture machine meets the cardinality rule (Step 0 told you), re-record those oracle rows deliberately in THIS commit with `(golden: oracles.json)` in the subject, reason in the body, leaf-diff verified as in Task 12.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/plan.go internal/orchestrator/task13_lifecycle_surfaces_test.go
git add internal/orchestrator/testdata/oracles.json   # only if re-pinned
git commit -m "feat(orchestrator): adversarial lifecycle machines mint into the work queue (defect 4)"
```

---

