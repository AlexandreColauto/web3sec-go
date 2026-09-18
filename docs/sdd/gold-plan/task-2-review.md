# Task 2 review — adversarial-lifecycle surfaces mint into the work queue

- **Reviewer:** independent read-only review (commit `55be2c2e..3c095827`, single commit `3c095827`)
- **Inputs:** task-2-brief.md (plan §Task 2, verbatim), task-2-report.md, task-2-review-package.md (full diff)
- **Independent verification performed:** ran `go test ./internal/orchestrator -run "Lifecycle|Adversarial" -count=1 -v` (8/8 PASS), `go test ./internal/orchestrator ./internal/planner ./internal/briefing ./assets/... -count=1` (all ok), `go vet` on both changed packages (clean), matcher logic traced line-by-line against the brief's test table, schema/state_machines/briefing/queue sources read directly.

## Verdict summary

| Item | Verdict |
|---|---|
| **Spec compliance** | **YES** (all binding laws met; deviations declared and justified — see findings for one undeclared but correct substitution) |
| **Task quality** | **APPROVED** — 2 minor findings, both non-blocking, neither requires code change before merge |
| Golden pins | No golden file touched in the commit (diffstat: 5 files, none under `testdata/`); no LC-id pinned by value anywhere (repo grep: only the code definition, one comment, and one prefix assertion) |
| Historical fixtures | Untouched ✓ |

## Global constraints — one by one

1. **No golden pin references an LC-id by value** — **PASS.** `git diff 55be2c2e..3c095827 --stat` touches no `testdata/` file; `rg '"LC-' internal/ assets/` finds only `lifecycleID`'s definition (plan.go:750) and the test's `strings.HasPrefix(row.ID, "LC-")` (test:345). `TestLifecycleRowIdSchemeAndText` asserts ordering and the family prefix, never a value. The strongest form of the law holds: **no pin exists to violate.**
2. **Asset-flow verbs excluded** — **PASS.** `lifecycleVocabulary` (plan.go) is exactly the brief's 11 tokens; deposit/transfer/relay/swap/mint/burn absent. `message_passing`/`relayMessage` negative case passes.
3. **Lone-benign-verb machines must not mint** — **PASS** (verified independently, see matcher trace below).
4. **Embedded-verb words must not count** — **PASS** (`improveProve`/`improvement_flow` → 0 tokens; see trace).
5. **No automated exploit development** — **PASS.** The minted row is a review task (`review adversarial lifecycle … — no covering finding`); no exploit artifact is produced anywhere in the diff.
6. **Historical fixtures untouched** — **PASS** (not in the diff).

## Independent matcher/cardinality trace (against the brief's test table)

`tokenOccursLeftBound` (plan.go): lowers both strings; scans every occurrence of the token; a hit counts only at `at == 0` or when the preceding byte is outside `[0-9a-z_]`. **No trailing boundary** — correct per the Task 1 shared spec, and `TestLifecycleLeftBoundaryNotSubstring` pins both halves (`uncommit`/`resettle` rejected; `commitBatch` accepted). `lifecycleMachineTokens` scans the machine `name` plus each transition object's `trigger`, collects **distinct** tokens, returns them in vocabulary order (deterministic, transition-order-independent — also what makes the row-text pin stable). `adversarialLifecycleSurfaces` gates on `len(toks) >= 2` and sorts by name.

| Brief case | Tokens found | Verdict |
|---|---|---|
| `rollup_finalization` + commitBatch/challengeState/finalizeBatch | commit, challenge, finalize (3 ≥ 2) | mints ✓ |
| `token_vault` + deposit/transfer/withdraw | withdraw (1) | skipped ✓ |
| `message_passing` + relayMessage | none (relay not vocabulary) | skipped ✓ |
| `reward_pool` + claimRewards | claim (1) | skipped ✓ |
| `improvement_flow` + improveProve | none (`prove` preceded by `e` in both name and action) | skipped ✓ |

The chain text is vocabulary-order (`commit → challenge → finalize`), matching the brief's example byte-for-byte. All four brief test functions are present verbatim; the four extra pins (rank-first, swept-skip, left-boundary table, id-scheme/text) all assert name-based or shape-based properties — none pins an id value.

**Dedup scope:** `lifecycleSurfaceCovered` receives `b.priorities` — the entire queue minted so far (privileged, risky, roles, open questions, and prior lifecycle rows) — re-read on every loop iteration, so same-minter replanning survives. This is the brief's "ENTIRE existing work queue" requirement, met. The coverage predicate reuses `buildQueueSignals`' in-scope/touched maps (the same "untouched" test the queue scoring uses) and live findings' `affected[].contract/.path`.

## Adjudication of the five implementer concerns

**(1) Queue `trajectories` renders `["code"]` for a `["lifecycle"]` plan row — DEFERRED MINOR, agreed.** Verified from source: `TrajectoryToEnum` (plan.go:43-48) keys are the long spellings (`"H-lifecycle"`), `enumTrajectory` (queue.go:386-392) is documented as a faithful port of Python's `TRAJECTORY_TO_ENUM.get(t, "code")`, and `queue.go` is untouched by this diff — the quirk is pre-existing by construction and affects every short-named plan row equally. Fixing it would move pinned oracle rendering across the repo. The defect-4 substance (rank #1, `now` slot) is carried by score/slot, not the tag. Agree: out of scope; worth a line in a future task.

**(2) Schema widening `^(Q|LC)-[0-9]{3}$` + manifest resync — ACCEPTED (necessary, minimal, documented).** The plan's own id-scheme law mandates `LC-%03d` rows; the plan schema pinned `^Q-[0-9]{3}$`, so the feature was unimplementable without the widening (the implementer proved it with a temporary-revert log). The new pattern is strictly additive — `"X-001"` and bare ids still fail; no other keyword relaxed. The manifest resync is mandatory, not incidental: schemas are `//go:embed`ed and `assets/manifest_test.go` verifies hashes — I re-ran `go test ./assets/...` (PASS). The change is documented as deviation 2 in the report. One nit: the schema's `id` property carries no description noting the LC family (only `Q-` was self-describing); non-blocking.

**(3) Lifecycle row reaches action #1 via plan --json/attention but not the brief's next-actions — RULED: COMPLIANT; no briefing line is required by this task.** The plan §Task 2 text requires (a) the row's *text* to name machine + verb chain, and (b) the row to be "command-first per the Task 7 law", quoting the `webv2 plan <cid> --json  # …` form. It does **not** amend the Files list to include `internal/briefing`, and the Step 1 test table contains no briefing assertion — compare Task 10, whose own law ended "brief shows it" and which therefore *did* add a briefing branch (the precedent comment at briefing.go:2255-2262 cites exactly that review finding). The plan law for defect 4 — "the highest-risk unmodeled surface becomes the next action" — is satisfied by the row being `work_queue[0]`, which `TestLifecycleSurfaceRanksFirst` asserts and I verified passing. The `# comment` payload of the quoted command-first form *is* the minted row text, so the Task 7 shape is met at the level the plan section governs. The operator-facing gap (next-actions renders only `resolve open question`-prefixed and sibling rows — confirmed at briefing.go:2266-2268) is real but belongs to Task 3's briefing work; recorded as a deferred minor, not a finding against this commit.

**(4) Only schema-shaped transitions count — MOOT on the production path, minor elsewhere.** `protocol_model.schema.json` requires each transition to be an object with `from`/`to`/`trigger` (`required`, `additionalProperties: false`), and the model is schema-validated before planning, so a real model can never present bare-string transitions. The behavior only affects hand-written degenerate values passed directly to the exported helper, which returns an empty slice — the documented degenerate-model contract. Accept as reported.

**(5) `AdversarialLifecycleMachines` exists twice (planner impl + orchestrator re-export) — ACCEPTED.** The plan's Interfaces section names `orchestrator.AdversarialLifecycleMachines` as the produced symbol; orchestrator already imports planner, so the mint cannot live in orchestrator without an import cycle. The re-export is documented with the name-as-handle warning. This is the only shape that satisfies both the interface and Go's package graph.

## Findings (non-blocking)

- **[minor] Undeclared deviation — `applies_to` substitution not reported.** Brief Step 3: "Rows carry the machine's `applies_to` contracts as named components." The protocol-model schema gives state machines only `name`/`states`/`transitions`/`suspect_properties` (no `applies_to` — that field exists on *invariants*), so the brief's instruction was unimplementable as written. The implementation uses the machine name as the single component (plan.go, the `addWithID` call with `[]string{s.name}`), which is the coherent choice and is what makes the named-component slotting, the dedup, and the coverage predicate work. **Fix:** none in code — add one bullet to the report's deviations list so the substitution is on record like the other three.
- **[minor] Report's Step-0 "0 qualifying machines" accepted on the report's quote + golden green, not a full independent recount.** The pinned fixture machine (`vault-lifecycle`, trigger `pause`) visibly carries 0 vocabulary tokens and the diff leaves every oracle file untouched, so the conclusion cannot be wrong without a pin moving — but the 53-hit → 0-qualifying sweep over loose repo fixtures was not independently replayed. Covered by `scripts/golden.sh` re-run (see verification log below).

## Cannot-verify items

- Full-suite and golden re-run results are appended from this review session's own run (see below); the report's logged exits (71 ok, GOLDEN GREEN, 196 steps) were reproduced, not merely trusted. CLI operator-path evidence (`minted-row.json`, `cli-operator-path.txt`) was not re-executed — the orchestrator tests already drive the real Plan verb end-to-end, which covers the same surface.
- The Step 0 repo-wide cross-check over *loose* fixtures (bare-string transitions, `id`-keyed machines) was not independently replayed; its conclusion is corroborated by the untouched golden pins.

## Verification log (this review session, worktree `.worktrees/production-readiness`)

```
go test ./internal/orchestrator -run "Lifecycle|Adversarial" -count=1 -v   → 8/8 PASS
go test ./internal/orchestrator ./internal/planner ./internal/briefing    → ok ×3
go test ./assets/... -count=1                                             → ok
go vet ./internal/planner ./internal/orchestrator                          → clean
go test ./... -count=1                                                     → exit 0, 71 packages ok, 0 FAIL
scripts/golden.sh                                                          → exit 0, "GOLDEN GREEN" (reproduced)
```
