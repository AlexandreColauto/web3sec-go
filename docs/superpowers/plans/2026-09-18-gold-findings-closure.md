# Gold-Findings Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the discovery-axis gaps that produced 0/2 on `web3sec-final/targets/gold-findings.json` (Morph L2 @ `22ca805e`) — enforce evidence relevance, rank adversarial lifecycle surfaces, make evidence reachability visible, and make the benchmark score measurable and repeatable.

**Architecture:** Four framework changes (invariants gate, orchestrator queue minting, briefing reachability line, gold scorer script) plus an operator-run re-evaluation protocol. Each framework change maps 1:1 to a verified defect in `morph/FRAMEWORK_EVALUATION.md` (its "wishes" 1, 2, 3, 6 are already closed by the trust-boundary-hardening branch; this plan closes the remaining 4 and 5, and adds the measurement loop). The campaign re-run itself is operator-driven work — no task automates exploit reasoning.

**Tech Stack:** Go 1.26.2 (toolchain `go1.26.6`), stdlib only; Python 3 stdlib for the offline scorer; existing SDD flow (implementer `b-ai`/`deepseek-v4.1-flash`, reviewer `b-ai`/`glm-5.3-flash`).

## Global Constraints

- Every go command uses the repo cache convention: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`.
- No new Go module dependencies (stdlib only). The scorer is Python 3 stdlib only (no pip installs).
- Historical fixtures (`scripts/legacy/`, `web3sec-final/`, `morph/`) are immutable; the scorer reads them, never writes them.
- Evidence honesty laws hold: `CHECKED_AGAINST_CODE` remains an operator-attestation provenance (`operator-attestation` label from the hardening branch); the new exec-relevance gate strengthens admission, it does not claim mechanical proof of the invariant.
- No automated exploit development: no task synthesizes exploits, no CI step runs attacks. The re-run protocol is an operator session using the framework normally.
- TDD: red test first for every code task; deliberate pin updates carry the reason in the commit body.
- Exact-path staging only; never `git add -A`; work happens in the `production-readiness` worktree unless the operator moves it.
- Scoring numbers from external datasets entering framework DATA need a `provenance` row per `docs/eval-methodology.md` (claim-intake rubric). The scorer consumes the benchmark file read-only and its output is an eval artifact, not framework DATA.

---

### Task 1: invariant-verify refuses execs that did not target an applies_to contract

Evaluation defect: "I closed INV-003 (staking liveness) citing a generic full-suite exec (EXEC-5ca6c7aac3). The framework recorded `CHECKED_AGAINST_CODE` without checking any relation between the cited exec and the invariant's `applies_to`" (wish 4). A foundry full-suite run names every contract in its output, so output text-matching cannot enforce this — the gate must inspect what the exec *ran*, not what it printed.

**Files:**
- Modify: `internal/invariants/invariants.go` (verify path; near `VerifyInvariantStatement` and the Task 4 artifact-reference helpers)
- Modify: `internal/cli/cmd_invariant_verify.go:82-97` (`resolveExecArtifact` already resolves the cited exec)
- Test: `internal/invariants/invariants_exec_relevance_test.go` (new)
- Test: `internal/cli/cmd_invariant_verify_exec_relevance_test.go` (new)

**Interfaces:**
- Consumes: `invariants.VerifyInvariantStatement(c *state.Campaign, invID string, artifact string) (validation.Value, error)` (unchanged signature); `state.Campaign` exec record access used by `resolveExecArtifact` (`internal/cli/cmd_invariant_verify.go:116`); Task 4 helpers `artifactReferencesInvariant` / `referenceTokens` / word-boundary matcher in `internal/invariants/invariants.go:832`.
- Produces: exported `invariants.ExecTouchesInvariant(c *state.Campaign, invID string, execID string) (bool, string)` — `(true, "")` when the exec's recorded command targeted one of the invariant's `applies_to` tokens (word-boundary match, same matcher family as Task 4); `(false, reason)` otherwise, where `reason` is one of `"no-exec-record"`, `"no-command-record"`, `"no-target-match"`. All existing callers keep compiling (additive).

- [ ] **Step 1: Write the failing tests**

In `internal/invariants/invariants_exec_relevance_test.go`, build a campaign via the existing `invCamp` helper family (see `internal/invariants/invariants_test.go:1167` for the Task 4A fixtures). Invariant with `applies_to: ["Staking"]`. Three exec records written with the same helper the Task 4 tests use to register exec artifacts:

```go
func TestExecTouchesInvariant(t *testing.T) {
	c := invCamp(t)
	registerInv(t, c, "INV-3", "staking liveness", []string{"Staking"})
	// exec whose recorded command names the contract
	touch := registerExec(t, c, "forge test --match-contract StakingTest")
	// exec that ran the whole suite, no contract named in the command
	suite := registerExec(t, c, "forge test")
	// exec for an unrelated contract
	other := registerExec(t, c, "forge test --match-contract OracleTest")
	if ok, reason := ExecTouchesInvariant(c, "INV-3", touch.ID); !ok || reason != "" {
		t.Fatalf("targeted exec: ok=%v reason=%q, want true/\"\"", ok, reason)
	}
	for _, ex := range []state.Exec{suite, other} {
		if ok, reason := ExecTouchesInvariant(c, "INV-3", ex.ID); ok || reason != "no-target-match" {
			t.Fatalf("untargeted exec %s: ok=%v reason=%q, want false/no-target-match", ex.ID, ok, reason)
		}
	}
	if ok, reason := ExecTouchesInvariant(c, "INV-3", "EXEC-missing"); ok || reason != "no-exec-record" {
		t.Fatalf("missing exec: ok=%v reason=%q", ok, reason)
	}
}
```

Adapt the exact constructor names to the real helpers (`registerExec` above stands for however Task 4's tests materialize an EXEC record with a command line — read them first; if the exec record has no command field, the field name discovered there governs, and this test pins it). The match must be word-boundary over the command string against every `applies_to` token, reusing the Task 4 matcher (`referenceTokens` family) — `--match-contract StakingTest` matches token `Staking`; `--match-contract OracleTest` does not.

In `internal/cli/cmd_invariant_verify_exec_relevance_test.go`: happy path (targeted exec) still verifies; refusal path prints the exact new refusal text and leaves the registry untouched (status stays `UNVERIFIED`, no `invariant.verified` event, no attestation label):

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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod go test ./internal/invariants ./internal/cli -run ExecTouches -count=1` (and the CLI test)
Expected: FAIL — `ExecTouchesInvariant undefined`, CLI test fails because verify currently accepts the suite exec.

- [ ] **Step 3: Implement the gate**

In `internal/invariants/invariants.go`, next to the Task 4 helpers: `ExecTouchesInvariant` reads the exec record the same way `resolveExecArtifact` does, extracts the recorded command, and word-boundary-matches it against the invariant's `applies_to` tokens (plus the `NormalizeInvID`-style spelling variants the Task 4 matcher already tolerates). Empty `applies_to` → refuse with `"no-target-match"` (an invariant bound to nothing cannot be exec-verified — consistent with the Task 4 empty-applies_to rule). In `cmd_invariant_verify.go` after artifact resolution, call the gate; on refusal print `invariant verify failed: cited exec <ID> does not target any applies_to contract of <invID> (<reason>)` and return 2. The check runs *before* `VerifyInvariantStatement` writes anything.

- [ ] **Step 4: Run the tests to verify they pass, then the package gates**

Run: focused tests (expect PASS), then `go test ./internal/invariants ./internal/cli -count=1`.
Expected: PASS. If existing fixtures close invariants with suite execs and now fail, that is the law working — update those fixtures to targeted execs (deliberate, reason in commit body), never weaken the gate.

- [ ] **Step 5: Full gates and commit**

Run: `go test ./... -count=1`; `go vet ./...`; `scripts/golden.sh`.
Expected: all exit 0 (golden pins should not move — no stdout change on the happy path).

```bash
git add internal/invariants/invariants.go internal/invariants/invariants_exec_relevance_test.go internal/cli/cmd_invariant_verify.go internal/cli/cmd_invariant_verify_exec_relevance_test.go
git commit -m "fix(invariants): exec-relevance gate for invariant-verify (wish 4)"
```

---

### Task 2: adversarial-lifecycle surfaces mint into the work queue

Evaluation defect: "The amplifier signal was misweighted for this target — nothing pointed at the adversarial commit→challenge→finalize game" (structural diagnosis: "nothing enforces that the highest-risk unmodeled surface becomes the next action"). G-01 lives in a lifecycle game, not in a message-flow class. The hardening branch already ranks open questions and risk-weights the queue (planner `scoreRow`: `untouched*1.0 + severity*2.0 + openQ*1.5`, slot class primary); this task mints queue rows for the model's own state machines so the adversarial game reaches action #1 through the existing machinery — no new scoring path.

**Files:**
- Modify: `internal/orchestrator/plan.go` (the file holding `DefaultPlanFromModel` and `bootstrapOpenQuestions` — locate with `rg -n "bootstrapOpenQuestions" internal/orchestrator`)
- Test: `internal/orchestrator/task13_lifecycle_surfaces_test.go` (new)

**Interfaces:**
- Consumes: `DefaultPlanFromModel`'s model value (the schema-validated protocol model; state machines under the model key the Task 3 liveness gate reads — `rg -n "state_machines" internal/` to confirm the exact key); `bootstrapOpenQuestions`' mint pattern (row shape, Q-id prefix, slotting via `DecisionRule(0.9, "cheap")`); planner `scoreRow` constants (`internal/planner/task12_queue_scoring_test.go` documents them).
- Produces: exported `orchestrator.AdversarialLifecycleMachines(model validation.Value) []string` — sorted machine names whose transition verbs match the adversarial-lifecycle vocabulary (case-insensitive word match on machine name and transition action names): `commit, challenge, finalize, settle, claim, withdraw, dispute, prove, refund, liquidate, redeem`. Later tasks (Task 5 protocol) rely on this naming. Empty/degenerate models return an empty slice.

- [ ] **Step 1: Write the failing test**

```go
func TestAdversarialLifecycleMachines(t *testing.T) {
	model := modelWithMachines(t,
		machine("rollup_finalization", "commitBatch", "challengeState", "finalizeBatch"),
		machine("token_vault", "deposit", "transfer"),
		machine("message_passing", "relayMessage"))
	got := AdversarialLifecycleMachines(model)
	want := []string{"rollup_finalization"} // deposit/transfer/relay are asset-flow, not adversarial-game verbs
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLifecycleSurfaceMintsQueueRow(t *testing.T) {
	// rollup-like model, machine untouched by any finding/artifact
	model := modelWithMachines(t, machine("rollup_finalization",
		"commitBatch", "challengeState", "finalizeBatch"))
	p := PlanFromModel(t, model)
	row := findQueueRow(t, p, "rollup_finalization")
	if row == nil {
		t.Fatal("no work-queue row minted for the adversarial lifecycle machine")
	}
	if row.Slot != "now" {
		t.Fatalf("slot = %q, want now (named-component slotting, Task 10 pattern)", row.Slot)
	}
}
```

The minted row's text must name the machine and its verb chain, e.g. `review adversarial lifecycle rollup_finalization (commit → challenge → finalize) — no covering finding`, and must be command-first per the Task 7 law: `webv2 plan <cid> --json  # review adversarial lifecycle rollup_finalization (commit → challenge → finalize)`. Follow `bootstrapOpenQuestions` verbatim for row shape and dedup (a machine already named by a minted open-question row for the same component is not minted twice). Machines fully covered by an existing finding or reviewed rows are skipped — the coverage predicate is the same one Task 10 uses for "untouched".

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/orchestrator -run "Lifecycle" -count=1`
Expected: FAIL — `AdversarialLifecycleMachines undefined`, no queue row minted.

- [ ] **Step 3: Implement**

Add the exported vocabulary matcher and `AdversarialLifecycleMachines` in `internal/orchestrator/plan.go`; call it from `DefaultPlanFromModel` last, after `bootstrapOpenQuestions` (stable order: sorted machine names; ids `LC-001…` following the Q-id pattern). Rows carry the machine's `applies_to` contracts as named components so the existing planner slotting ranks them. Asset-flow verbs (deposit/transfer/relay/swap/mint/burn) are deliberately NOT in the vocabulary — the eval showed the bridge-message amplifier over-boosted; this signal exists to surface the adversarial game specifically.

- [ ] **Step 4: Tests green, then package gates**

Run: `go test ./internal/orchestrator ./internal/planner ./internal/briefing -count=1`, then `go test ./... -count=1`, `go vet ./...`, `scripts/golden.sh`.
Expected: green. `internal/orchestrator/testdata/oracles.json` pins `planned` scenarios — if the fixture model carries machines matching the vocabulary, the `work_queue` order moves: re-record those oracle rows deliberately (reason in commit body), leaf-diff verified as in Task 12.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/plan.go internal/orchestrator/task13_lifecycle_surfaces_test.go
git add internal/orchestrator/testdata/oracles.json   # only if re-pinned
git commit -m "feat(orchestrator): adversarial lifecycle machines mint into the work queue"
```

---

### Task 3: brief renders evidence-reachability per bug class (class floor vs box ceiling)

Evaluation defect 5, re-derived against current code: the eval claimed "G-01's accepted classes floor at E6 (economic-invariant)" — but `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR` pins `dos-griefing: E4` and `logic-error: E4`, and the eval box reached E4. So CONFIRMED for G-01's accepted classes was **locally reachable**; the cockpit simply never said so, and the operator spent no thought on it. This task makes reachability visible so the ceiling is a planning input, not a post-hoc discovery. No new status is added (rejected: the benchmark's own pass bar already accepts `HYPOTHESIS + correct root cause + working PoC draft`, and `CONFIRMED@E4` is legal for the accepted classes — a new status would be a cross-gate state-machine change for no scoring gain).

**Files:**
- Modify: `internal/findings/levels.go` (export one accessor; no map changes)
- Modify: the brief builder — `rg -n "func NextActions" internal/briefing/briefing.go` (the mint Task 7/fix1 converted)
- Test: `internal/findings/levels_reachability_test.go` (new)
- Test: `internal/briefing/task14_reachability_test.go` (new)

**Interfaces:**
- Consumes: `findings.STATUS_FLOOR`, `findings.CLASS_CONFIRM_FLOOR`, `findings.EVIDENCE_ORDER` (all package-level in `internal/findings/levels.go:30-60`); the box's E-cap recorded by the hardening branch's environment ceiling (`rg -n "E4|e4_capable" internal/envgo/env.go` for the accessor name).
- Produces: `findings.ClassConfirmFloor(class string) string` (floor id or `"E5"` default, mirroring `STATUS_FLOOR["CONFIRMED"]`); `findings.ReachableLocally(class, cap string) bool` — true when the class floor's evidence level ≤ cap in `EVIDENCE_ORDER`. The brief's reachability line: `evidence reachability: CONFIRMED locally reachable for dos-griefing, logic-error (floor ≤ E4); fork required for economic-invariant, oracle-manipulation (floor > E4)`.

- [ ] **Step 1: Write the failing tests**

```go
func TestClassConfirmFloor(t *testing.T) {
	if got := ClassConfirmFloor("dos-griefing"); got != "E4" {
		t.Fatalf("dos-griefing floor = %q, want E4", got)
	}
	if got := ClassConfirmFloor("share-price-inflation"); got != "E6" {
		t.Fatalf("share-price-inflation floor = %q, want E6", got)
	}
	if got := ClassConfirmFloor("nonexistent-class"); got != "E5" {
		t.Fatalf("unknown class floor = %q, want E5 (CONFIRMED default)", got)
	}
}

func TestReachabilityLine(t *testing.T) {
	// box ceiling E4, model findings classes dos-griefing + economic-invariant
	got := ReachabilityLine([]string{"dos-griefing", "economic-invariant"}, "E4")
	want := "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
		"(floor E4); fork required for economic-invariant (floor E6 > E4)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
```

(The exact `share-price-inflation` floor value is read from `levels.go` at implementation time — the test above pins whatever the map actually says; read it first and copy the real value.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/findings ./internal/briefing -run "Reachab|ClassConfirmFloor" -count=1`
Expected: FAIL — accessors undefined.

- [ ] **Step 3: Implement the accessors and the brief line**

Accessors in `levels.go` are pure map reads (no behavior change to any gate). The brief line renders once per brief when the campaign's findings carry at least one open finding class, appended after the cold-probe warning (Task 11 pattern: advisory, no gate reads it). Command-first law holds: the line is evidence-planning prose with the class names — if any minted line embeds a command, it must lead with `webv2 ` per the Task 7 law; this line is pure prose so no command is embedded.

- [ ] **Step 4: Tests green, then gates**

Run: `go test ./internal/findings ./internal/briefing -count=1`; `go test ./... -count=1`; `go vet ./...`; `scripts/golden.sh`; `scripts/runbook-walkthrough.sh`.
Expected: green; brief-shape pins move only if a pinned fixture has open findings with classes (deliberate re-pin with reason if so).

- [ ] **Step 5: Commit**

```bash
git add internal/findings/levels.go internal/findings/levels_reachability_test.go internal/briefing/briefing.go internal/briefing/task14_reachability_test.go
git commit -m "feat(briefing): evidence reachability line (class confirm floor vs box cap)"
```

---

### Task 4: offline gold scorer (`scripts/eval-gold.py`)

The 0/2 score was produced by hand. This task makes it a repeatable command with hermetic tests, honoring the benchmark's own `match_criteria`, `pass`, `bonus`, and `false_positive_budget` strings verbatim (read from `web3sec-final/targets/gold-findings.json`, never re-typed). The scorer is offline analysis of a finished campaign record — it never runs tooling against a target.

**Files:**
- Create: `scripts/eval-gold.py`
- Test: `scripts/eval_gold_test.py` (Python unittest, stdlib only)

**Interfaces:**
- Consumes: `web3sec-final/targets/gold-findings.json` schema: top-level `gold_findings[]` each with `gold_id`, `bug_class_accept`, `match_criteria`, `expected_severity`, `primary_functions`; top-level `scoring` with `pass`, `bonus`, `false_positive_budget`. Campaign record layout: the campaign dir the CLI produces (findings registry JSON + events JSONL; locate the exact file names with `rg -n "links.json|events.jsonl" internal/state` — the scorer reads those two files only).
- Produces: `python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir>` → exit 0 always (scoring is not a gate); stdout JSON: `{"found": ["G-01"], "missed": ["G-02"], "false_positives": 0, "pass": false, "bonus": false, "verdict": "FAIL"}`, plus a human summary block. `verdict` is `PASS` iff the `scoring.pass` condition holds (G-01 found per its `match_criteria` at an accepted evidence state), `PASS_WITH_BONUS` iff G-02 also found, else `FAIL`. A finding counts as FOUND only when its recorded status is `CONFIRMED` or `HYPOTHESIS` with a registered root-cause/PoC-draft artifact linked (the benchmark's two accepted states), and its text/`primary_functions` match `match_criteria` keywords (the scorer checks the keywords from the JSON; the semantic "correct root cause" judgment stays with the operator — the scorer prints `match_evidence` per gold and the operator confirms; the JSON output flags `operator_confirmed: false` until `--confirm G-01` is passed).

- [ ] **Step 1: Write the failing tests**

`scripts/eval_gold_test.py` builds two synthetic campaign dirs in `tempfile.mkdtemp()` — one where a finding matches G-01's criteria (status CONFIRMED, primary function `commitBatch` named, `prevStateRoot` in the finding text) and one empty campaign — then asserts the JSON verdicts:

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
        self.assertTrue(out["pass"])
        self.assertFalse(out["operator_confirmed"]["G-01"])
        self.assertTrue(run_scorer(FIXTURE_CAMPAIGN_G01, confirm=["G-01"])
                        ["operator_confirmed"]["G-01"])

    def test_fp_budget_counts_other_confirmed(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
        self.assertEqual(out["false_positives"], 11)
        self.assertIn("partial result", out["verdict_note"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 scripts/eval_gold_test.py`
Expected: FAIL — `eval-gold.py` does not exist.

- [ ] **Step 3: Implement the scorer**

Pure stdlib: `argparse`, `json`, `re`, `pathlib`. Word-boundary keyword match (same `(?i)\b<tok>\b` discipline as the framework). The campaign findings file is read read-only; malformed inputs produce a clear error and exit 2. `--confirm` takes gold ids the operator has semantically verified. The scorer never mutates the campaign or the benchmark file.

- [ ] **Step 4: Tests pass, then wire the self-test into the Go gate ONLY as documentation**

Run: `python3 scripts/eval_gold_test.py` (PASS). Do NOT add it to `verify-full.sh` (the 13-step pin is deliberate; a python step would add an interpreter dependency to the release gate — YAGNI). Instead add one line to `scripts/eval-gold.py --help` and to the Task 5 protocol doc.

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

1. **Pinned target**: Morph L2 @ vulnerable commit `22ca805e` (verify the checkout hash before starting; record the actual hash). Build the framework binary fresh: `bash scripts/release.sh` must print `RELEASE OK` first (the strict scan is part of the run's provenance).
2. **Contamination re-check**: re-run the global-store check against `~/.webv2/shared-memory` for the benchmark's `contamination_check` keywords (Sherlock morphl2 audit, ScaBench, `prevSt...` — copy the full keyword list from the JSON) and record the date + result in the campaign record before discovery starts.
3. **Campaign protocol**: fresh campaign; model the protocol including `rollup_finalization` as a state machine (the hardening branch's per-machine liveness gate now refuses the model without it — that gate firing is expected and is itself a test of the hardening work); run the lifecycle machines' probes (`probes run --emit`) while discovery is open (the Task 11 cold-probe warning will nag until this happens — expected); close invariants only with execs that target `applies_to` (Task 1 gate now refuses suite-run citations — expected).
4. **Scoring**: `python3 scripts/eval-gold.py --gold web3sec-final/targets/gold-findings.json --campaign <dir>`; operator semantic confirmation via `--confirm`; record the JSON verdict and the FP count in the campaign record. FP budget language comes from the benchmark's `scoring.false_positive_budget` verbatim.
5. **Honesty rules**: no score pressure on the record; a miss is recorded as a miss with the failure analysis (the 0/2 eval's diagnosis is the template); numbers learned during the re-run enter framework DATA only through the `docs/eval-methodology.md` provenance rubric.
6. **Out of scope**: no exploit development automation, no CI execution of the protocol, no benchmark edits (the benchmark file is read-only evidence; changing it invalidates the comparison to 0/2).

- [ ] **Step 2: Verify the protocol's commands actually exist**

Run every command the protocol names with `--help` or against a scratch campaign (never against the pinned target): `webv2 probes run --emit`, `scripts/eval-gold.py --help`, `bash scripts/release.sh` on a scratch checkout is NOT required — release was already run green at `10182b5c` (archived `docs/sdd/release-final.log`); cite that log instead of re-running.
Expected: all commands resolve; any drift is fixed in the doc before commit.

- [ ] **Step 3: Commit**

```bash
git add docs/eval/morph-rerun-protocol.md
git commit -m "docs(eval): Morph gold re-run protocol (operator-driven measurement loop)"
```

---

## Self-Review Record

- Spec coverage: eval defects 1-7 mapped — defect 1 (liveness doctrine) → closed by hardening Task 3 (per-machine gate, critic-verified); defect 2 (cockpit comfort) → hardening Tasks 10/12 + this plan Task 2; defect 3 (cold probe) → hardening Task 11; defect 4 (amplifier misweight) → this plan Task 2; defect 5 (evidence ceiling invisible) → this plan Task 3; defect 6 (unrelated exec evidence) → this plan Task 1; defect 7 (bookkeeping friction) → hardening Tasks 4A/5/6/7/8/16. Measurement loop → Tasks 4-5.
- Placeholder scan: Task 1 Step 1 explicitly instructs adapting constructor names to the real helpers (bounded, named location — not a TBD); Task 3 pins the real floor value by reading `levels.go` first (the map is the source of truth; copying it into the plan would risk staleness). No other TBD/TODO patterns.
- Type consistency: `ExecTouchesInvariant(c, invID, execID) (bool, string)` used in Task 1 tests and implementation; `AdversarialLifecycleMachines(model) []string` Task 2; `ClassConfirmFloor(class) string` / `ReachableLocally(class, cap) bool` Task 3; scorer CLI contract Task 4 ↔ Task 5.
