# Task 2 report — adversarial-lifecycle surfaces mint into the work queue (defect 4)

- **Branch:** `production-readiness` (worktree `.worktrees/production-readiness`)
- **BASE:** `55be2c2e9ab279b13d57926502e00fd7e75d2094`
- **Commit:** `3c095827ddb967bf08fcf676bc64a4950a2f1f3f`
  (`feat(orchestrator): adversarial lifecycle machines mint into the work queue (defect 4)`)
- **STATUS:** complete, all gates green, no push/merge/delegate performed.
- **Logs:** `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-2-logs/`
- **Ponytail:** loaded and applied (ladder + "one runnable check" + `ponytail:`-style
  ceiling notes in comments); nothing unrequested was built.

## Files changed (exact paths)

| Path | Change |
|---|---|
| `internal/planner/plan.go` | matcher, `AdversarialLifecycleMachines`, `bootstrapLifecycleSurfaces`, `addWithID`/`pad3`, call from `DefaultPlanFromModel` |
| `internal/orchestrator/plan.go` | re-export `AdversarialLifecycleMachines` (the brief's named interface) |
| `internal/orchestrator/task13_lifecycle_surfaces_test.go` | new: the brief's test table verbatim + 4 extra pins |
| `assets/schema/campaign_plan.schema.json` | priority `id` pattern `^Q-[0-9]{3}$` → `^(Q|LC)-[0-9]{3}$` (**required**, see deviations) |
| `assets/testdata/asset_manifest.json` | re-synced embedded-schema hash (only the `campaign_plan` entry moves) |

`internal/orchestrator/testdata/oracles.json` and `internal/planner/testdata/oracles.json`
are **untouched** (no re-pin was needed — Step 0). Historical fixtures
(`scripts/legacy/`, `web3sec-final/`, `morph/`) untouched.

## Step 0 — pre-flight, oracle blast radius

Command (from the brief): `rg -n -i "commit|challenge|finalize|settle|claim|withdraw|dispute|prove|refund|liquidate|redeem" internal/orchestrator/testdata/`
→ 53 raw text hits, but **0 machines meet the cardinality rule**.

The pinned `task13-orchestrator` fixture (`internal/orchestrator/testdata/oracles.json`,
scenarios `model`/`planned`/`queues`) carries exactly one machine:

    {"name": "vault-lifecycle",
     "transitions": [{"from": "active", "to": "paused", "trigger": "pause()", "actor": "governor"}],
     "suspect_properties": ["unpause without delay"]}

Tokens in name + transition action names = **0** (`pause` is not vocabulary), so the
`planned`/`queues` oracle rows cannot move. **Recorded count: 0 qualifying machines.**

Repo-wide cross-check (same rule over every `state_machines` block in `*.go`/`*.json`/`*.py`):
the only machines with >= 2 vocabulary hits are *loose* fixtures whose `transitions` are
bare strings or whose machine carries an `id` instead of a `name`
(`internal/planner/ports_test.go`, `internal/briefing/sweep_t35*`, `internal/report/sweep_t35*`,
`internal/completion/sweep_t35*`, `internal/probes/emit_test.go`,
`internal/planner/testdata/oracles.json`). They do **not** mint, because the matcher reads
the schema shape (machine `name` + transition-object `trigger`) — see concerns. That is why
`go test ./...` and `scripts/golden.sh` are green without a single pin moving.

## Step 1–2 — TDD red (log: `task-2-logs/red.txt`)

`GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod go test ./internal/orchestrator -run "Lifecycle" -count=1`

    # websec/internal/orchestrator [websec/internal/orchestrator.test]
    internal/orchestrator/task13_lifecycle_surfaces_test.go:229:9: undefined: AdversarialLifecycleMachines
    ... (5 sites)
    FAIL	websec/internal/orchestrator [build failed]
    FAIL
    RED EXIT: 1

## Step 3 — implementation

- `lifecycleVocabulary` = the brief's 11 tokens; `lifecycleMachineTokens` collects the
  **distinct** tokens occurring left-boundary, case-insensitive, across the machine `name`
  and each transition object's `trigger`, returned in vocabulary order (so the chain text
  is deterministic and transition order cannot change it).
- `tokenOccursLeftBound` + `isLowerWordByte`: the Task 1 spec, duplicated locally
  (left boundary = start-of-string or a preceding byte outside `[0-9a-z_]`; **no** trailing
  boundary), documented as an intentional duplicate.
- `adversarialLifecycleSurfaces`: cardinality rule `len(tokens) >= 2`, sorted by machine
  name; empty/degenerate models → empty slice.
- `bootstrapLifecycleSurfaces` is called from `DefaultPlanFromModel` **last**, after
  `bootstrapOpenQuestions`, so every pre-existing Q-number stays byte-for-byte.
  Row shape: `risk 0.9`, `budget_class cheap` → `DecisionRule(0.9,"cheap") = "now"`,
  `components = [machine name]`, `trajectories = ["lifecycle"]`, id `LC-%03d`
  positional over the sorted machine list (a skipped machine keeps its position).
  No new scoring path: the existing `scoreRow` (`untouched*1.0 + severity*2.0 + openQ*1.5`,
  slot class primary) does the ranking.
- Skip predicate `lifecycleSurfaceCovered`: (a) any row already minted into the queue
  carries the machine name as a **component** (the whole queue built so far — every earlier
  minter's rows), (b) any **live** finding's `affected[].contract`/`.path` equals the name,
  (c) the coverage ledger marks the machine's in-scope contract **swept**
  (`buildQueueSignals`' own `inScope`/`touched` maps — the same "untouched" predicate the
  queue scoring uses).
- `add` was split into `add` + `addWithID` (one id argument) and `qid` into `qid` + `pad3`;
  both are the smallest possible refactors — no behavior change for Q- rows.
- `orchestrator.AdversarialLifecycleMachines(model)` re-exports the planner selection
  (the planner cannot import `orchestrator`, so the mint site cannot live there).

## Step 4 — green + gates

Focused (log `task-2-logs/green-focused.txt`), `go test ./internal/orchestrator -run "Lifecycle|Adversarial" -count=1 -v`:

    --- PASS: TestAdversarialLifecycleMachines
    --- PASS: TestLifecycleVocabularyNegativeCases
    --- PASS: TestLifecycleSurfaceMintsQueueRow
    --- PASS: TestLifecycleSurfaceDedupAndCoverage
    --- PASS: TestLifecycleSurfaceRanksFirst
    --- PASS: TestLifecycleSurfaceSkipsSweptMachine
    --- PASS: TestLifecycleLeftBoundaryNotSubstring
    --- PASS: TestLifecycleRowIdSchemeAndText
    PASS  ok  websec/internal/orchestrator  0.030s          EXIT: 0

The brief's four test functions are verbatim (only the fixture helpers around them are
mine). Four extra pins were added: the action-#1 witness (defect 4's core claim), the
swept-machine coverage half, the left-boundary table, and the id-scheme/row-text pin.

| Gate | Command | Exit | Log |
|---|---|---|---|
| packages | `go test ./internal/orchestrator ./internal/planner ./internal/briefing -count=1` | **0** | `gate-packages.txt` |
| full | `go test ./... -count=1` | **0** (71 `ok`, 0 `FAIL`) | `gate-all.txt` |
| vet | `go vet ./...` | **0** (no output) | `gate-vet.txt` |
| golden | `scripts/golden.sh` | **0** — `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)`, 196 steps, campaign `C-34c0ce6f4b`, 179 events chain intact | `gate-golden.txt` |
| gofmt | `gofmt -l internal cmd` | clean | — |

All go commands used the repo cache convention
`GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`
(the golden script exports its own).

## The exact minted row (evidence: `task-2-logs/minted-row.json`, `cli-operator-path.txt`)

Real CLI, scratch campaign `C-8b8fdab6d5`, model with `rollup_finalization`
(`commitBatch`/`challengeState`/`finalizeBatch`) plus a `token_vault` with a lone `withdraw`:

    $ webv2 --root .scratch/t13 plan C-8b8fdab6d5 --json     # work_queue[0]
    {
     "priority_id": "LC-001",
     "question": "review adversarial lifecycle rollup_finalization (commit → challenge → finalize) — no covering finding",
     "risk": 0.9, "cost": "cheap", "slot": "now",
     "trajectories": ["code"],
     "components": ["rollup_finalization"],
     "invariant_ids": [],
     "required_context": ["structural_index", "protocol_model"]
    }

    all queue rows: ['LC-001', 'Q-001', 'Q-002', 'Q-003', 'Q-004']
    token_vault minted? False        # lone benign verb: cardinality rule holds in the real path

So the adversarial game is **action #1**, and the row's command-first operator line is
`webv2 plan <cid> --json  # review adversarial lifecycle rollup_finalization (commit → challenge → finalize)`
(the Task 10 / Task 7 rendering pattern; see concerns). Closure also works with no new code:

    $ webv2 --root .scratch/t13 answered C-8b8fdab6d5 LC-001 answered --reason ... --actor operator --ref src/Rollup.sol#L1
    LC-001: status -> answered (ref: src/Rollup.sol#L1)          # exit 0
    after answering: LC rows still queued = [] (4 rows), LC-001 status = answered

## Id-scheme law audit

- Rows get positional `LC-%03d` ids over the **sorted** machine names; the machine NAME is
  the component and the handle. Nothing in this commit pins an LC id **by value**: the
  tests assert the `LC-` prefix, the positional ordering, the slot, and the text
  (`TestLifecycleRowIdSchemeAndText`); before this change `rg -rn "LC-" --glob '!*.md'` over
  the repo returned zero hits (no pre-existing pin to worry about). No golden file was
  re-pinned, so no golden pin can reference an LC id.
- Other id consumers were audited and skip non-`Q-` ids explicitly, so LC rows cannot corrupt
  their numbering: `planner/answered.go:nextPriorityID` (only ever fed its own `qid(...)`),
  `probes/emit.go:nextPrioritySeq`, `findings/transitions.go:nextPriorityNumber`.

## Deviations from the brief (all deliberate, all reported)

1. **Mint-site file path.** The brief says "Modify `internal/orchestrator/plan.go` (the file
   holding `DefaultPlanFromModel` and `bootstrapOpenQuestions` — locate with
   `rg -n "bootstrapOpenQuestions" internal/orchestrator`)". That `rg` finds **nothing**:
   both symbols live in `internal/planner/plan.go` (Task 10's commit `cbdd93d5` did the same
   thing, and the hardening plan's Task 10/12 "Files: internal/orchestrator" line has the same
   drift). The mint therefore lives in `internal/planner/plan.go`; `internal/orchestrator/plan.go`
   still changed, as the brief's Files list expects, to carry the exported
   `AdversarialLifecycleMachines` re-export (planner cannot import orchestrator, so the
   exported name cannot be the implementation).
2. **`assets/schema/campaign_plan.schema.json` + `assets/testdata/asset_manifest.json` added.**
   The plan schema pinned `"id": {"pattern": "^Q-[0-9]{3}$"}`, so an `LC-001` row failed the
   plan's own validation inside `DefaultPlanFromModel` — the id-scheme law is unimplementable
   without widening it. Proof (log `schema-widening-required.txt`), with the old pattern
   temporarily restored:

       task13_lifecycle_surfaces_test.go:252: plan: campaign_plan validation failed at
       priorities/4/id: 'LC-001' does not match '^Q-[0-9]{3}$' (+0 more errors)

   Fix: `^(Q|LC)-[0-9]{3}$`, then `python3 scripts/sync-asset-manifest.py` (embedded schemas are
   `//go:embed schema/*.schema.json`, and `assets/manifest_test.go` verifies the manifest, so
   the re-sync is mandatory). Only the `campaign_plan` manifest entry moves
   (`eaadacff…` → `3a021cb7…`, 10631 → 10636 bytes). `"X-001"`-style ids still fail, so no
   validation laxity was added beyond the mandated family.
3. **Matcher location.** The brief allows a local duplicate matcher "in `orchestrator`"; the
   mint path lives in `planner`, so the duplicate lives there (`tokenOccursLeftBound`,
   `isLowerWordByte`) with the same spec as Task 1's unexported helper, and its table is pinned
   through the exported surface (`TestLifecycleLeftBoundaryNotSubstring`) instead of a second
   new test file. `internal/invariants` is not imported *for the matcher*.

## Concerns / judgement calls for the reviewer

1. **Queue `trajectories` renders `["code"]` for a `["lifecycle"]` plan row** (visible in the
   evidence above). `WorkQueue` maps trajectories through `enumTrajectory`, whose table keys are
   the LONG spellings (`H-lifecycle`), while the plan schema's enum holds the SHORT ones — so
   every short-named plan row collapses to `code`. This is **pre-existing** (the pinned
   `internal/planner/testdata/oracles.json` shows `"trajectories": ["code","code"]` for a row
   whose plan priorities say `["attacker","code"]`, and Task 10's `drift/code` rows behave the
   same). Fixing it would move that pinned oracle and change every row's rendering, so it is
   out of Task 2's scope — but it does blunt defect 4's *routing* intent (the row is ranked
   #1 and labelled `lifecycle` in the plan, yet the queue tag reads `code`).
2. **Only schema-shaped transitions count.** `transitions` entries that are bare strings (or a
   machine with `id` instead of `name`) contribute no tokens, so such a "machine" never mints.
   That is what keeps the loose pre-existing fixtures and all golden pins still (Step 0), and
   the production path is schema-validated, so a real model always has `trigger` objects — but
   a hand-written degenerate model will silently get no lifecycle row.
3. **Dedup is component-exact, not a text search.** The brief's "(a) machine already covered by
   a minted open-question row for the same component" is implemented as exact component equality
   (a row whose `question` merely mentions the machine name does not suppress it). This avoids a
   machine named `rollup` suppressing `rollup_finalization`. Consequence: a hypothetical future
   minter that names a machine only in prose would not suppress the lifecycle row.
4. **The brief does not reach the brief's next-actions line.** The lifecycle row is rendered by
   `webv2 plan <cid> --json` (and via the attention ledger), but `briefing.NextActions` only
   emits `webv2 plan <cid> --json  # <text>` lines for rows prefixed `resolve open question `
   (Task 10) and for sibling rows. Task 2's Files list does not include `internal/briefing`, so
   I did not add a briefing branch (it would also collide with Task 3's briefing work); the
   row's text is minted exactly as the brief's "minted row's text" example, and the command-first
   form quoted in the plan is the standard wrapper this row will use if/when the briefing branch
   is added. Flagging in case the reviewer reads "must be command-first" as a briefing change.
5. **`AdversarialLifecycleMachines` exists twice** (planner implementation + orchestrator
   re-export). It is required by the brief's stated interface and by Task 5's naming; the
   alternative (moving the mint into orchestrator) is impossible without an import cycle.

## Test summary (one line)

8/8 focused lifecycle tests pass; `./...` 71 packages ok, `go vet` clean, `GOLDEN GREEN` — all exit 0.
