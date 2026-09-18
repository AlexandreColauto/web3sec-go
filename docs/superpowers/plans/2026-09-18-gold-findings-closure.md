# Gold-Findings Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the discovery-axis gaps that produced 0/2 on `web3sec-final/targets/gold-findings.json` (Morph L2 @ `22ca805e`) — enforce evidence relevance, rank adversarial lifecycle surfaces, make evidence reachability visible, and make the benchmark score measurable and repeatable.

**Architecture:** Four framework changes (invariants gate, orchestrator queue minting, briefing reachability line, gold scorer script) plus an operator-run re-evaluation protocol. The campaign re-run itself is operator-driven work — no task automates exploit reasoning.

**What success means (read before judging any task):** this plan's deliverables are measured by **framework quality and measurement repeatability** — the exec-relevance gate refusing theater evidence, the cockpit ranking the adversarial game, reachability visible at planning time, the score reproducible by one command. **The re-run score is NOT a deliverable of this plan.** Only Task 2 plus the operator's own campaign session can plausibly move 0/2; Tasks 1/3/4 raise the honesty and measurement bar and must not be judged against score movement they were never designed to produce.

## Defect/wish mapping (single table, no dual vocabulary below this line)

`morph/FRAMEWORK_EVALUATION.md` numbers its "What it failed at" list as defects 1-7 and its closing "Wishes" list as wishes 1-6. The two schemes are offset (wish 4 = defect 6, wish 5 = defect 5). This plan uses **defect numbers only**:

| Defect (eval §"What it failed at") | Wish | Closed by |
|---|---|---|
| 1. Liveness doctrine unenforced | 1 | hardening Task 3 (per-machine gate — done) |
| 2. Cockpit ranks comfort, not risk | 2 | hardening Tasks 10/12 + **this plan Task 2** |
| 3. Cold probe surface silent | 3 | hardening Task 11 (done) |
| 4. Amplifier signal misweighted (no adversarial-game surface) | — | **this plan Task 2** |
| 5. Evidence ceiling invisible at planning time | 5 | **this plan Task 3** |
| 6. `invariant-verify` accepts execs that never exercised the invariant | 4 | **this plan Task 1** |
| 7. Bookkeeping friction | 6 | hardening Tasks 4A/5/6/7/8/16 (done) |
| Measurement loop | — | **this plan Tasks 4-5** |

**Tech Stack:** Go 1.26.2 (toolchain `go1.26.6`), stdlib only; Python 3 stdlib for the offline scorer; existing SDD flow (implementer `b-ai`/`deepseek-v4.1-flash`, reviewer `b-ai`/`glm-5.3-flash`).

## Global Constraints

- Every go command uses the repo cache convention: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`.
- Toolchain `go1.26.6` resolves via GOTOOLCHAIN auto-download — expected behavior; do NOT vendor or pin a local toolchain.
- No new Go module dependencies (stdlib only). The scorer is Python 3 stdlib only (no pip installs).
- Historical fixtures (`scripts/legacy/`, `web3sec-final/`, `morph/`) are immutable; the scorer reads them, never writes them.
- Evidence honesty laws hold: `CHECKED_AGAINST_CODE` remains an operator-attestation provenance (`operator-attestation` label from the hardening branch); the new exec-relevance gate strengthens admission, it does not claim mechanical proof of the invariant.
- No automated exploit development: no task synthesizes exploits, no CI step runs attacks. The re-run protocol is an operator session using the framework normally.
- TDD: red test first for every code task; deliberate pin updates carry the reason in the commit body; **golden re-pins are tagged in the commit subject** (`(golden: <file>)`) so a later bisect can attribute which task moved which pin.
- Exact-path staging only; never `git add -A`; work happens in the `production-readiness` worktree unless the operator moves it.
- Scoring numbers from external datasets entering framework DATA need a `provenance` row per `docs/eval-methodology.md` (claim-intake rubric). The scorer consumes the benchmark file read-only and its output is an eval artifact, not framework DATA.

---

### Task 1: invariant-verify refuses execs that did not target an applies_to contract

Defect 6 (wish 4): "I closed INV-003 (staking liveness) citing a generic full-suite exec (EXEC-5ca6c7aac3). The framework recorded `CHECKED_AGAINST_CODE` without checking any relation between the cited exec and the invariant's `applies_to`". A foundry full-suite run names every contract in its output, so output text-matching cannot enforce this — the gate must inspect what the exec *ran*, not what it printed.

**Files:**
- Modify: `internal/invariants/invariants.go` (verify path; near `VerifyInvariantStatement` and the Task 4 artifact-reference helpers)
- Modify: `internal/cli/cmd_invariant_verify.go:82-97` (`resolveExecArtifact` already resolves the cited exec)
- Test: `internal/invariants/invariants_exec_relevance_test.go` (new)
- Test: `internal/cli/cmd_invariant_verify_exec_relevance_test.go` (new)

**Interfaces:**
- Consumes: `invariants.VerifyInvariantStatement(c *state.Campaign, invID string, artifact string) (validation.Value, error)` (unchanged signature); `state.Campaign` exec record access used by `resolveExecArtifact` (`internal/cli/cmd_invariant_verify.go:116`); the Task 4 `referenceTokens` matcher family in `internal/invariants/invariants.go:832`.
- Produces: exported `invariants.ExecTouchesInvariant(c *state.Campaign, invID string, execID string) (bool, string)` — `(true, "")` when the exec's recorded command targeted one of the invariant's `applies_to` tokens under the **binding matcher semantics** below; `(false, reason)` otherwise, where `reason` is one of `"no-exec-record"`, `"no-command-record"`, `"no-target-match"`. All existing callers keep compiling (additive).
- **Matcher semantics (binding, decided after three independent plan reviews):** case-insensitive **left-boundary token match** — the lowered command contains the lowered token at a position whose preceding character is NOT `[0-9a-z_]` (start-of-string counts as a boundary); there is **no trailing boundary**. Explicitly rejected alternatives: (a) regex `\b` on both sides — `\bStaking\b` fails on `StakingTest` (no boundary between `g` and `T`), under-accepting exactly the commands the gate must accept, since Foundry's `--match-contract` is a regex/prefix filter; (b) plain case-insensitive substring — over-accepts (`Staking` would match `Unstaking`). Left-boundary accepts `--match-contract Staking`, `--match-contract StakingTest`, `--match-path src/Staking.t.sol` (`/` is a boundary) and rejects `Unstaking` (`n` precedes) — both rejections are pinned as adversarial tests, not incidental. Strip surrounding shell quotes from the recorded command before matching.
- **Matcher provenance:** before implementing, read what the Task 4 `referenceTokens` matcher (`invariants.go:832`) actually does. If it already implements left-boundary matching, reuse it; if it implements full `\b...\b`, implement the left-boundary matcher as a NEW named helper (e.g. `tokenOccursLeftBound(command, token string) bool`) — do NOT change the Task 4 matcher's behavior (that would silently move Task 4's pinned refusal semantics), and document in the new helper's comment that the two intentionally differ and why.

- [ ] **Step 0: Pre-flight — fixture blast radius**

Run: `rg -n "forge test\b" internal/ --glob '*_test.go' --glob '!*_exec_relevance_test.go' | rg -v "match-contract|match-path" | wc -l`
Expected: a count. Record it in the report: it is the number of existing test fixtures that close an invariant with an untargeted suite exec and will need targeted-exec updates in Step 4 (5-minute fix if small, a deliberate fixture-migration commit if large — if the count exceeds ~20, STOP and report before proceeding; the operator decides whether to split the task). Never a weakened gate.

- [ ] **Step 1: Write the failing tests**

In `internal/invariants/invariants_exec_relevance_test.go`, build a campaign via the existing `invCamp` helper family (see `internal/invariants/invariants_test.go:1167` for the Task 4A fixtures). Invariant with `applies_to: ["Staking"]`. Exec records written with the same helper the Task 4 tests use to register exec artifacts:

```go
func TestExecTouchesInvariant(t *testing.T) {
	c := invCamp(t)
	registerInv(t, c, "INV-3", "staking liveness", []string{"Staking"})
	// command naming the contract directly
	direct := registerExec(t, c, "forge test --match-contract Staking")
	// CamelCase test-contract glob — Foundry prefix-filter form, must match
	camel := registerExec(t, c, "forge test --match-contract StakingTest")
	// path-scoped form — token preceded by '/', must match
	path := registerExec(t, c, "forge test --match-path src/Staking.t.sol")
	for _, ex := range []state.Exec{direct, camel, path} {
		if ok, reason := ExecTouchesInvariant(c, "INV-3", ex.ID); !ok || reason != "" {
			t.Fatalf("targeted exec %s: ok=%v reason=%q, want true/\"\"", ex.ID, ok, reason)
		}
	}
	// adversarial near-miss: token present as substring but inside another word
	un := registerExec(t, c, "forge test --match-contract Unstaking")
	// disjoint contract
	other := registerExec(t, c, "forge test --match-contract OracleTest")
	// whole-suite run: no token anywhere in the command
	suite := registerExec(t, c, "forge test")
	for _, ex := range []state.Exec{un, other, suite} {
		if ok, reason := ExecTouchesInvariant(c, "INV-3", ex.ID); ok || reason != "no-target-match" {
			t.Fatalf("untargeted exec %s: ok=%v reason=%q, want false/no-target-match", ex.ID, ok, reason)
		}
	}
	if ok, reason := ExecTouchesInvariant(c, "INV-3", "EXEC-missing"); ok || reason != "no-exec-record" {
		t.Fatalf("missing exec: ok=%v reason=%q", ok, reason)
	}
}

func TestExecTouchesInvariantEmptyAppliesTo(t *testing.T) {
	c := invCamp(t)
	registerInv(t, c, "INV-9", "unbound invariant", nil) // applies_to: []
	ex := registerExec(t, c, "forge test --match-contract Staking")
	if ok, reason := ExecTouchesInvariant(c, "INV-9", ex.ID); ok || reason != "no-target-match" {
		t.Fatalf("empty applies_to: ok=%v reason=%q, want false/no-target-match", ok, reason)
	}
}
```

Adapt the exact constructor names to the real helpers (`registerExec` above stands for however Task 4's tests materialize an EXEC record with a command line — read them first; if the exec record has no command field, the field name discovered there governs, and this test pins it).

Ruling on empty `applies_to` (deliberate, matches the hardening branch): Task 4's pinned rule is that an empty `applies_to` does NOT bypass the artifact-reference refusal — empty means **unbound → unverifiable**, never wildcard. This task is consistent with that: an invariant bound to nothing cannot be exec-verified.

In `internal/cli/cmd_invariant_verify_exec_relevance_test.go`: happy path (targeted exec) still verifies; refusal path prints the exact new refusal text and leaves the registry untouched — assert ALL of: exit 2, stderr text, status stays `UNVERIFIED`, **zero new `invariant.verified` events** (explicit event-absence loop over the event list, not just the status), no attestation label:

```go
func TestInvariantVerifyRefusesUntargetedExec(t *testing.T) {
	// fixture: INV-3 applies_to [Staking]; cite the `forge test` suite exec
	code, out, errOut := runInvariantVerify(t, "INV-3", suiteExecID)
	if code != 2 { t.Fatalf("exit = %d, want 2", code) }
	if !strings.Contains(errOut, "does not target any applies_to contract of INV-3") {
		t.Fatalf("stderr missing refusal text: %q", errOut)
	}
	if got := objStr(invEntry(t, c, "INV-3"), "status"); got != "UNVERIFIED" {
		t.Fatalf("status = %q, want UNVERIFIED", got)
	}
	for _, ev := range events(t, c) {
		if objStr(ev, "type") == "invariant.verified" {
			t.Fatal("refusal must emit no invariant.verified event")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod go test ./internal/invariants ./internal/cli -run ExecTouches -count=1` (and the CLI test)
Expected: FAIL — `ExecTouchesInvariant undefined`, CLI test fails because verify currently accepts the suite exec.

- [ ] **Step 3: Implement the gate**

In `internal/invariants/invariants.go`, next to the Task 4 helpers: `ExecTouchesInvariant` reads the exec record the same way `resolveExecArtifact` does, extracts the recorded command, strips surrounding quotes, and applies the binding left-boundary matcher against the invariant's `applies_to` tokens. Empty `applies_to` → refuse with `"no-target-match"`. In `cmd_invariant_verify.go` after artifact resolution, call the gate; on refusal print `invariant verify failed: cited exec <ID> does not target any applies_to contract of <invID> (<reason>)` and return 2. The check runs *before* `VerifyInvariantStatement` writes anything.

- [ ] **Step 4: Run the tests to verify they pass, then the package gates**

Run: focused tests (expect PASS), then `go test ./internal/invariants ./internal/cli -count=1`.
Expected: PASS. If existing fixtures close invariants with suite execs and now fail, that is the law working — update those fixtures to targeted execs (deliberate, reason in commit body, count from Step 0), never weaken the gate.

- [ ] **Step 5: Full gates and commit**

Run: `go test ./... -count=1`; `go vet ./...`; `scripts/golden.sh`.
Expected: all exit 0 (golden pins should not move — no stdout change on the happy path; if a pin does move, re-pin in THIS commit with `(golden: <file>)` in the subject and the reason in the body).

```bash
git add internal/invariants/invariants.go internal/invariants/invariants_exec_relevance_test.go internal/cli/cmd_invariant_verify.go internal/cli/cmd_invariant_verify_exec_relevance_test.go
git commit -m "fix(invariants): exec-relevance gate for invariant-verify (defect 6)"
```

---

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

### Task 3: brief renders evidence-reachability per bug class (class floor vs box ceiling)

Defect 5, re-derived against current code: the eval claimed "G-01's accepted classes floor at E6 (economic-invariant)" — but `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR` pins `dos-griefing: E4` and `logic-error: E4`, and the eval box reached E4. So CONFIRMED for G-01's accepted classes was **locally reachable**; the cockpit simply never said so. This task makes reachability visible so the ceiling is a planning input, not a post-hoc discovery. No new status is added (rejected: the benchmark's own pass bar already accepts `HYPOTHESIS + correct root cause + working PoC draft`, and `CONFIRMED@E4` is legal for the accepted classes — a new status would be a cross-gate state-machine change for no scoring gain).

**Files:**
- Modify: `internal/findings/levels.go` (export accessors; no map changes)
- Modify: the brief builder — `rg -n "func NextActions" internal/briefing/briefing.go` (the mint Task 7/fix1 converted)
- Test: `internal/findings/levels_reachability_test.go` (new)
- Test: `internal/briefing/task14_reachability_test.go` (new)

**Interfaces:**
- Consumes: `findings.STATUS_FLOOR`, `findings.CLASS_CONFIRM_FLOOR`, `findings.EVIDENCE_ORDER` (all package-level in `internal/findings/levels.go:30-60`); the box's E-cap recorded by the environment ceiling (`rg -n "E4|e4_capable" internal/envgo/env.go` for the accessor name).
- Produces (all three are part of the contract, pinned by tests):
  - `findings.ClassConfirmFloor(class string) string` — the class's floor id from `CLASS_CONFIRM_FLOOR`, or `"E5"` (the `STATUS_FLOOR["CONFIRMED"]` default) for unknown classes.
  - `findings.ReachableLocally(class, cap string) bool` — true when the class floor's evidence level ≤ cap in `EVIDENCE_ORDER`.
  - `briefing.ReachabilityLine(classes []string, cap string) string` (in package `briefing`) — rendering rules: reachable classes first, fork-required classes second, each group alphabetized; reachable clause `evidence reachability: CONFIRMED locally reachable for <c1> (floor <F1>); fork required for <c2> (floor <F2> > <cap>)` — **one class per clause with its own floor value** (this exact form is what the test pins; the earlier prose with comma-joined classes and `floor ≤ E4` was inconsistent and is superseded). Edge cases: all classes reachable → omit the fork clause entirely; all classes fork-required → omit the reachable clause and start the line with `evidence reachability: fork required for ...`. Empty class list → empty string (no line rendered).

- [ ] **Step 0: Pre-flight — floor-map facts**

Read `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR` and record: does a key with floor `E6` exist (the comment names `share-price-inflation`)? Copy the REAL key and value into the test below — if no E6 key exists, pin the default-`E5` path with an unknown class instead and say so in the report. Never pin an assumed key.

- [ ] **Step 1: Write the failing tests**

```go
func TestClassConfirmFloor(t *testing.T) {
	if got := ClassConfirmFloor("dos-griefing"); got != "E4" {
		t.Fatalf("dos-griefing floor = %q, want E4", got)
	}
	// share-price-inflation's real value comes from Step 0's read of levels.go
	if got := ClassConfirmFloor("share-price-inflation"); got != "E6" {
		t.Fatalf("share-price-inflation floor = %q, want the map's real value", got)
	}
	if got := ClassConfirmFloor("nonexistent-class"); got != "E5" {
		t.Fatalf("unknown class floor = %q, want E5 (CONFIRMED default)", got)
	}
}

func TestReachabilityLine(t *testing.T) {
	got := ReachabilityLine([]string{"economic-invariant", "dos-griefing"}, "E4")
	want := "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
		"(floor E4); fork required for economic-invariant (floor E6 > E4)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if all := ReachabilityLine([]string{"dos-griefing", "logic-error"}, "E4"); strings.Contains(all, "fork required") {
		t.Fatalf("all-reachable line must omit the fork clause: %q", all)
	}
	if forkOnly := ReachabilityLine([]string{"economic-invariant"}, "E4"); strings.Contains(forkOnly, "locally reachable") {
		t.Fatalf("all-fork line must omit the reachable clause: %q", forkOnly)
	}
}
```

(The `share-price-inflation` expected value above is a placeholder for whatever Step 0 found — the committed test pins the map's real value.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/findings ./internal/briefing -run "Reachab|ClassConfirmFloor" -count=1`
Expected: FAIL — accessors undefined.

- [ ] **Step 3: Implement the accessors and the brief line**

Accessors in `levels.go` are pure map reads (no behavior change to any gate). `ReachabilityLine` lives in package `briefing` (it is a rendering concern; `findings` stays data-only). The brief renders the line once per brief when the campaign's findings carry at least one open finding class, **positioned immediately after the cold-probe warning line (Task 11) — pin that ordering in the briefing test by asserting the reachability line's index is exactly one greater than the cold-probe warning's index** in a fixture that has both. Advisory only: no gate, proof, or phase transition reads it. If any minted line embeds a command it must lead with `webv2 ` per the Task 7 law; this line is pure prose so no command is embedded.

- [ ] **Step 4: Tests green, then gates**

Run: `go test ./internal/findings ./internal/briefing -count=1`; `go test ./... -count=1`; `go vet ./...`; `scripts/golden.sh`; `scripts/runbook-walkthrough.sh`.
Expected: green; brief-shape pins move only if a pinned fixture has open findings with classes (deliberate re-pin with `(golden: <file>)` in the subject if so).

- [ ] **Step 5: Commit**

```bash
git add internal/findings/levels.go internal/findings/levels_reachability_test.go internal/briefing/briefing.go internal/briefing/task14_reachability_test.go
git commit -m "feat(briefing): evidence reachability line (class confirm floor vs box cap) (defect 5)"
```

---

### Task 4: offline gold scorer (`scripts/eval-gold.py`)

The 0/2 score was produced by hand. This task makes it a repeatable command with hermetic tests, honoring the benchmark's own `match_criteria`, `pass`, `bonus`, and `false_positive_budget` strings verbatim (read from `web3sec-final/targets/gold-findings.json`, never re-typed). The scorer is offline analysis of a finished campaign record — it never runs tooling against a target.

**Files:**
- Create: `scripts/eval-gold.py`
- Test: `scripts/eval_gold_test.py` (Python unittest, stdlib only)

**Interfaces:**
- Consumes: `web3sec-final/targets/gold-findings.json` schema: top-level `gold_findings[]` each with `gold_id`, `bug_class_accept`, `match_criteria`, `expected_severity`, `primary_functions`; top-level `scoring` with `pass`, `bonus`, `false_positive_budget`.
- Consumes (pinned campaign-dir contract — the implementer does NOT reverse-engineer it mid-task): a campaign dir containing
  - `findings/F-<id>.json` — ONE finding object per file, not a `findings.json` array. CORRECTED 2026-09-18 at Step 0 from the real record: the store is `internal/state.Campaign.FindingsDir` = `<root>/campaigns/<id>/findings`, listed as `F-*.json` by `internal/findings.LoadAllFindings` via `validation.ListPrefixedOptional(dir, "F-", ".json")` (`internal/findings/storage.go`), e.g. `scripts/legacy/campaigns/C-45488bdaf5/findings/F-df01bb454ed5.json`. Field spellings are the finding schema's (`assets/schema/finding.schema.json`), not the plan's: `finding_id` (not `id`), `status`, `root_cause.class` (not `bug_class`), `title` + `root_cause.description` (not `text`), `affected[].function` (not `primary_functions`), `evidence[].artifact_id` (not `artifacts`);
  - `events.jsonl` — one JSON object per line (parse line-by-line; `json.load` on the whole file WILL fail).
  (The Step 0 grep's `links.json` is really `artifacts/invariant_links.json` — `internal/invariants.SaveLinks` — and is not part of this scoring contract.)
  The exact real file names and field spellings are confirmed in Step 0 (`rg -n "links.json|events.jsonl|findings" internal/state` and one real campaign fixture) and pinned in a schema comment block at the top of `eval-gold.py` referencing the Go structs (`internal/state`) they mirror. The test harness builds synthetic campaign dirs with exactly this layout; if the real names differ from these two, the fixtures follow the REAL names (discovered in Step 0) and this plan's names are corrected in the same commit.
- Produces: `python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir> [--confirm G-ID ...]` — exit 0 on any well-formed scoring run (scoring is not a gate); exit 2 with a clean stderr message (no raw traceback) when inputs are missing/malformed (gold file absent, campaign dir absent, either pinned file absent, unparseable JSON/JSONL, or a `--confirm` id that names no gold finding). Stdout is one JSON object with EXACTLY this schema (the full decision table the tests pin):

  | field | type | semantics |
  |---|---|---|
  | `found` | array of gold ids | gold findings whose `match_criteria` keywords and `primary_functions` match a campaign finding (word-boundary keyword match, `(?i)\b<tok>\b` here — finding TEXT is natural language prose, where `\b` IS correct; this deliberately differs from Task 1's command matcher, which operates on shell commands) at an accepted evidence state |
  | `missed` | array of gold ids | the complement |
  | `false_positives` | int | count of campaign findings at `CONFIRMED` that match no gold's criteria |
  | `pass` | bool | true iff G-01 is in `found`. **Independent of FP count and of operator confirmation.** |
  | `bonus` | bool | true iff `pass` AND G-02 in `found` |
  | `verdict` | string | `PASS_WITH_BONUS` if bonus; `PASS` if pass AND `false_positives < 10`; `PARTIAL_RESULT` if pass AND `false_positives >= 10` (the benchmark's own words: "buries it under 10+ FPs is a partial result" — the budget is verdict-affecting at that boundary, read from `scoring.false_positive_budget` at runtime, not hardcoded); `FAIL` otherwise |
  | `verdict_note` | string | non-empty exactly when: `verdict == "PARTIAL_RESULT"` (contains `partial result` plus the FP count) OR any found gold lacks operator confirmation (`operator semantic confirmation pending for: G-01`); empty string otherwise |
  | `operator_confirmed` | object keyed by gold id | `--confirm G-01` sets `true`; default `false` for every found gold. Advisory only — it never changes `pass`/`bonus`/`verdict`; it exists so a human semantic judgment is not silently laundered into the machine verdict |

- [ ] **Step 1: Write the failing tests**

`scripts/eval_gold_test.py` builds synthetic campaign dirs in `tempfile.mkdtemp()` with the pinned layout and asserts the decision table:

```python
class TestGoldScorer(unittest.TestCase):
    def test_empty_campaign_scores_fail(self):
        out = run_scorer(FIXTURE_CAMPAIGN_EMPTY)
        self.assertEqual(out["found"], [])
        self.assertFalse(out["pass"])
        self.assertEqual(out["verdict"], "FAIL")

    def test_g01_confirmed_scores_pass_pending_confirmation(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01)
        self.assertEqual(out["found"], ["G-01"])
        self.assertTrue(out["pass"])                       # pass is independent of confirmation
        self.assertEqual(out["verdict"], "PASS")
        self.assertFalse(out["operator_confirmed"]["G-01"])
        self.assertIn("operator semantic confirmation pending", out["verdict_note"])
        confirmed = run_scorer(FIXTURE_CAMPAIGN_G01, confirm=["G-01"])
        self.assertTrue(confirmed["operator_confirmed"]["G-01"])
        self.assertEqual(confirmed["verdict_note"], "")

    def test_fp_budget_is_verdict_affecting_at_boundary(self):
        under = run_scorer(FIXTURE_CAMPAIGN_G01_AND_9_FPS)
        self.assertEqual(under["verdict"], "PASS")
        over = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
        self.assertEqual(over["false_positives"], 11)
        self.assertEqual(over["verdict"], "PARTIAL_RESULT")
        self.assertIn("partial result", over["verdict_note"])

    def test_missing_campaign_file_exits_cleanly(self):
        rc, err = run_scorer_raw(MISSING_DIR)
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)

    def test_unknown_confirm_id_exits_cleanly(self):
        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, confirm=["G-99"])
        self.assertEqual(rc, 2)
        self.assertIn("no gold finding", err)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 scripts/eval_gold_test.py`
Expected: FAIL — `eval-gold.py` does not exist.

- [ ] **Step 3: Implement the scorer**

Pure stdlib: `argparse`, `json`, `re`, `pathlib`, `sys`. Before parsing anything, verify every input file exists and print `eval-gold: <path> not found` to stderr with `sys.exit(2)` on absence — never a raw `FileNotFoundError` traceback. Parse `events.jsonl` line-by-line (`for line in f`). Schema-drift guard: the file's top comment block pins the campaign-dir contract with the Go struct names it mirrors, and the scorer asserts the expected top-level keys exist in the findings JSON before scoring, failing loudly with `eval-gold: campaign findings schema mismatch (expected keys: ...)` on drift instead of silently mis-scoring. Keyword matching over finding text uses `(?i)\b<tok>\b` (correct here: natural-language prose). The scorer never mutates the campaign or the benchmark file.

- [ ] **Step 4: Tests pass, then wire the invocation into the docs ONLY**

Run: `python3 scripts/eval_gold_test.py` (PASS) and `python3 -m unittest scripts.eval_gold_test` if the scripts dir is importable — pin whichever invocation works without path hacks in the Task 5 protocol. Do NOT add it to `verify-full.sh` (the 13-step pin is deliberate; a python step would add an interpreter dependency to the release gate — YAGNI).

- [ ] **Step 5: Commit**

```bash
git add scripts/eval-gold.py scripts/eval_gold_test.py
git commit -m "feat(eval): offline gold scorer honoring benchmark match criteria"
```

---

### Task 5: re-run protocol document (the measurement loop)

The score only moves when a fresh operator campaign runs against the pinned target on the hardened binary. This task ships the protocol; executing it is the operator's session (explicitly out of CI and out of this plan's automation).

**Files:**
- Create: `docs/eval/morph-rerun-protocol.md`

**Interfaces:**
- Consumes: `scripts/eval-gold.py` (Task 4); `web3sec-final/targets/gold-findings.json` (benchmark, read-only); the contamination check recorded in the benchmark (`contamination_check.checked: 2026-09-07` — the protocol re-runs it); `docs/eval-methodology.md` (claim-intake rubric for anything the re-run learns).
- Produces: the canonical re-run checklist.

- [ ] **Step 1: Write the protocol document**

Content (all sections mandatory, no placeholders):

1. **Pinned target**: Morph L2 @ vulnerable commit `22ca805e` (verify the checkout hash before starting; record the actual hash). **A fresh `bash scripts/release.sh` on THIS checkout is required before discovery starts and must print `RELEASE OK`** — an archived log from a different commit (`docs/sdd/release-final.log` @ `10182b5c`) proves a different checkout was clean and is cited only as evidence the script itself works, never as a substitute for the fresh run. Repeatability is the point of the measurement loop.
2. **Contamination re-check**: the global store it reads (`~/.webv2/shared-memory`) is machine-global, not repo-local — run the check FIRST, before any campaign work populates the store, on a clean environment; record the date + result in the campaign record. Note for CI: runners with persistent home dirs will fail this check by design — that is the check working, not a bug. Re-run against the benchmark's `contamination_check` keyword list (copy it verbatim from the JSON).
3. **Campaign protocol**: fresh campaign; model the protocol including `rollup_finalization` as a state machine (the hardening branch's per-machine liveness gate now refuses the model without it — that gate firing is expected and is itself a test of the hardening work); run the lifecycle machines' probes (`probes run --emit`) while discovery is open (the Task 11 cold-probe warning will nag until this happens — expected); close invariants only with execs that target `applies_to` (Task 1 gate now refuses suite-run citations — expected).
4. **Scoring**: `python3 scripts/eval-gold.py --gold web3sec-final/targets/gold-findings.json --campaign <dir>` (invocation pinned exactly as Task 4 Step 4 verified); operator semantic confirmation via `--confirm G-01` after reading the match evidence; record the JSON verdict and the FP count in the campaign record. FP-budget language comes from the benchmark's `scoring.false_positive_budget` verbatim. The scorer's own gate, from the repo root with no path hacks: `python3 -m unittest scripts.eval_gold_test` (also runnable as `python3 scripts/eval_gold_test.py`; both verified green 2026-09-18, 25 tests).
5. **Honesty rules**: no score pressure on the record; a miss is recorded as a miss with the failure analysis (the 0/2 eval's diagnosis is the template); numbers learned during the re-run enter framework DATA only through the `docs/eval-methodology.md` provenance rubric.
6. **Out of scope**: no exploit development automation, no CI execution of the protocol, no benchmark edits (the benchmark file is read-only evidence; changing it invalidates the comparison to 0/2).

- [ ] **Step 2: Verify the protocol's commands actually exist**

Run every command the protocol names with `--help` or against a scratch campaign (never against the pinned target): `webv2 probes run --emit`, `python3 scripts/eval-gold.py --help`, and confirm `scripts/release.sh` exists and is runnable on a scratch checkout (the canonical green full-run evidence remains `docs/sdd/release-final.log`; Task 5 does not re-run a full release — the protocol itself requires the operator's fresh run at execution time).
Expected: all commands resolve; any drift is fixed in the doc before commit.

- [ ] **Step 3: Commit**

```bash
git add docs/eval/morph-rerun-protocol.md
git commit -m "docs(eval): Morph gold re-run protocol (operator-driven measurement loop)"
```

---

## Self-Review Record

- Spec coverage: eval defects 1-7 mapped (single table in the header, wish numbers retired): defect 1 → hardening Task 3; defect 2 → hardening Tasks 10/12 + Task 2; defect 3 → hardening Task 11; defect 4 → Task 2; defect 5 → Task 3; defect 6 → Task 1; defect 7 → hardening bookkeeping tasks; measurement → Tasks 4-5.
- Review round incorporated: three independent external reviews were applied — the matching-semantics contradiction (all three) is resolved by the binding left-boundary token rule with adversarial near-miss pins; missing dedup/coverage/empty-applies_to tests added; cardinality rule added against lone-benign-verb false positives; `ReachabilityLine` and the full scorer decision table (pass/bonus/verdict/verdict_note/operator_confirmed and the FP budget's verdict-affecting boundary) are now specified interfaces; campaign-dir schema is pinned with a drift guard; golden re-pins are subject-tagged for bisectability; the Task 5 release-run contradiction is resolved in favor of a fresh run with the archived log demoted to script-works evidence; contamination check gets the machine-global caveat; toolchain auto-download note added; the intro states what this plan's success is and is not measured by.
- Placeholder scan: Task 1's `registerExec`/Task 2's `modelWithMachines*` constructors are bounded adaptations of named existing helpers (location given), not TBDs; Task 3's `share-price-inflation` value is read from the map in Step 0 before pinning (the map is the source of truth; copying it into the plan would risk staleness). No other TBD/TODO patterns.
- Type consistency: `ExecTouchesInvariant(c, invID, execID) (bool, string)` (Task 1 tests + implementation + CLI caller); `AdversarialLifecycleMachines(model) []string` (Task 2); `ClassConfirmFloor(class) string` / `ReachableLocally(class, cap) bool` (findings) / `ReachabilityLine(classes, cap) string` (briefing) (Task 3); scorer CLI + JSON schema table (Task 4 tests ↔ implementation ↔ Task 5 protocol).
