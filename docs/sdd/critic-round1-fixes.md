# Critic round 1 — fix wave (F1, F5, F4 + the F3 ruling)

- **Branch:** `production-readiness`, worktree `.worktrees/production-readiness`.
- **Range:** critic round 1 (`.scratch/sdd/critic-round-1.md`, verdict 7/10) → this wave.
- **Scope taken:** F1 (Critical), F5 (Minor), F4 (Minor), plus the F3 ruling. F2
  (persist the missing independent-review reports for Tasks 1/2/3/4/8/14/15) was
  NOT taken — it is a routing/delegation task, not a code fix, and this wave was
  scoped to F1/F5/F4+F3 by the operator. F6's residuals stay parked and listed.
- **Files in this directory are the evidence for every claim below** (all of them
  are copied to `docs/sdd/` by the `docs(sdd): record SDD ledger and review
  trail` commit, so the trail survives worktree cleanup — that is F4).

---

## F1 (Critical) — `verify-full.sh` red at step 4: the `-race` lock budget

### Symptom (red, reproduced three times on the pristine tree)

`go test -race ./internal/state` failed deterministically in
`TestConcurrentLoadModifyWritesLoseNothing`
(`internal/state/processlock_r13_test.go:156,185`):

```
--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (5.09s)
    processlock_r13_test.go:156: worker 1: exit status 1
        campaign C-lmwrace001 is locked by another process (waited 5s; holder:
        954077 .../state.test -test.run=TestConcurrentLoadModifyWritesLoseNothing)
        — let the running webv2 finish and retry; do NOT edit the ledger or state by hand
    processlock_r13_test.go:185: ledger lost a class: 5 of 6
```

Full log: `f1-red-race.log`. Same failure non-race: **passes in 0.114s**.

### Diagnosis (measured, not assumed)

Per-stage timestamps written from inside the worker processes (raw logs and the
full reading: `f1-race-diagnosis.txt`) showed that the critical section is
*milliseconds* and the wait is not:

| worker | locked at | last write at | next worker acquires |
| --- | --- | --- | --- |
| 2 | +0.25ms | +7.2ms | +1.004s |
| 4 | +1.010s | +1.019s | +2.024s |
| 3 | +2.024s | +2.033s | +3.036s |
| 1 | +3.040s | +3.048s | +4.046s |
| 5 | +4.048s | +4.057s | +5.066s |
| 0 | +5.066s | +5.075s | — |

The work (`lock → State → edit → SaveState → Log`) is 7ms; each worker then
holds the campaign lock for **~1.004s more**, i.e. until the process dies:
`lmwWorker` ends in `os.Exit(0)`, so the `defer c.UnlockProcess()` never runs and
the kernel releases the flock at process teardown. The decisive measurement, on
the *logger* worker (which does not hold the lock past its write):

```
worker-start        pid=956376 07:25:32.772157
worker-before-exit  pid=956376 07:25:32.778994   # 7ms of work
parent reaped it    07:25:33.780988              # +1.002s of teardown
```

Under `-race`, teardown of this test binary costs ~1.0s (race runtime finalize).
Six workers therefore serialize at ~1s each; the sixth needs >5s of wall-clock
budget and the production deadline fires. **The budget, not the lock hold, is
the contended resource — the r13/r14/r15 law was never violated, and no update
was lost for a concurrency reason.** This is exactly the "test-infrastructure
fragility, not demonstrated production data loss" the critic described; the fix
is to stop the harness from spending a production budget on detector overhead.

### Fix (commit `1130e324`, `fix(state): race-detector-aware lock budget in concurrent test`)

The standard library's `internal/race` pattern, applied inside `internal/state`:

- `raceenabled_race.go` (`//go:build race`) → `const raceEnabled = true`;
  `raceenabled_norace.go` (`//go:build !race`) → `const raceEnabled = false`.
  A compile-time constant: the false branch costs nothing and cannot be
  observed by a shipped binary.
- `lockBudget` becomes a `var` (documented) holding the same
  `5 * time.Second`; nothing outside test code ever assigns it.
- `processlock_racebudget_test.go` (test code only) scales it by
  `raceLockBudgetFactor = 10` when `raceEnabled` — `init()`, so it applies to
  the worker subprocesses too, which are the same test binary re-executed.
- `TestLockBudgetMatchesBuild` pins **both** directions: exactly 5s in a normal
  build, exactly 50s under `-race`. "Production behavior is byte-identical" is
  therefore a checked claim, not a comment.
- The fail-loud law is untouched: the timeout error still names the budget
  actually waited, a real stuck holder still fails after five seconds, and no
  test is skipped under `-race`.

### The test still catches a real lost update (mutation proof, both directions)

| mutation | expected | observed |
| --- | --- | --- |
| drop one worker's `SaveState` write | FAIL | `state lost an update: 5 rows, want 6` — `f1-mutation-race.log` |
| remove `LockProcess` from the worker (r14's original P0 shape) | FAIL | `state lost an update: 1 rows, want 6` — `f1-mutation-nolock-race.log` |

Both mutations were reverted (`git checkout -- internal/state/processlock_r13_test.go`);
the committed test file is byte-identical to its pre-wave content.

### Green evidence

```
go test -race ./internal/state -count=3   →  ok  websec/internal/state  195.626s   (exit 0)
go test ./internal/state -count=2         →  ok  (non-race path unchanged)
```

Full logs: `f1-green-race.txt` (`-count=3`), `verify-full-final.log` (step 4,
whole repo under `-race`).

### verify-full.sh, run to completion (commit 2 of the wave — no commit, verification only)

`bash scripts/verify-full.sh` was run to completion at `1130e324` with the repo
cache env (`GOCACHE=.scratch/gocache`, `GOPATH=.scratch/gomod`,
`GOMODCACHE=.scratch/gomod/pkg/mod`). Full log: `verify-full-final.log`
(6m13.9s wall). Verdict: **RED at step 12** — but step 4, the step F1 broke, is
green:

| step | result |
| --- | --- |
| 1 vet / 2 build / 3 go test | green |
| **4 `go test -race ./...`** | **green — `ok: race clean` (was the F1 failure)** |
| 5 determinism ×2 / 6 asset manifest / 7 golden / 8 crash smoke | green |
| 9 legacy cross-audit / 10 P1 smoke (21 commands) / 11 P2 smoke | green |
| **12 P3 CLI smoke** | **RED: `P3 smoke audit: 15 sections, want 14`** |
| 13 runbook walkthrough | never reached (step 12 exits non-zero) |

The failure is the pre-existing mismatch the Task 4 report disclosed on clean
BASE; this run is the first to reach it, so its status is now exact rather than
unknown. Re-derived by hand against the smoke campaign the step left behind:

```
$ .scratch/verify-p1/webv2 --root .scratch/verify-p1/smoke3 audit C-10ab2d8738 --json
count: 15
extra: ['price_table']   # every one of the 14 reference sections is present, in order
order: [event_log, artifacts, execs, findings, projection, snapshots, relations,
        floor_policy, stage_completions, baselines, invariant_verification,
        sequence_coverage, probe_surface, unpriceable, price_table]
```

**Diagnosis: the gate's assertion is stale for step 12, not the audit.** The
registry has 16 sections (`internal/audit/audit_test.go:85` pins
`len(SectionNames()) == 16` with `price_table` last); `eval` and `price_table`
are the two presence-gated sections appended past the reference's 14
(`internal/audit/sections/register.go:43`). Step 12 itself runs
`price C-… set ETH 3000 …`, which is what makes `price_table` render; step 11's
P2 smoke never prices anything, which is why the same helper passes there. The
helper `p2_sections_ok` hard-asserts `len(secs) == 14` and so cannot describe a
campaign that legitimately carries the presence-gated tail.

**Not fixed here, deliberately.** The instruction for this wave was to run
verify-full to completion, report a failure exactly and stop — and a DoD gate
must not be edited green as part of the wave it judges. The critic's own fix text
allows either "fix the step-12 mismatch or get an operator ruling recorded in the
ledger": this document plus the ledger line is the ruling request, with the exact
section list above. One-line options for the operator: (a) teach `p2_sections_ok`
to assert the 14 reference sections in order and allow the presence-gated tail,
or (b) rule the step-12 assertion correct and treat `price_table`'s rendering as
a product bug.

**Option (a) is already this repo's own convention**, so the ruling is close to
mechanical: `scripts/check-golden.py` — the independent golden checker, green in
the same wave — does exactly that for the same section, with the rationale
written out at `EXPECTED_SECTIONS` ("The registry carries 16 … price_table (r4)
DOES render here, because the P4 recipe sets a price … this list is not a copy of
the registry and must not be 'completed' to 16") and in the comparison itself
("The rendered surface is EXPECTED_SECTIONS, optionally TRUNCATED after its 14
unconditional members: presence-gated sections … render exactly when their
precondition holds — the s2 campaign prices nothing and must not fake the row.
What stays hard-failed: any unexpected name, and the ORDER of what does
render."). The golden gate prints both shapes in one run: `step 164
audit-json-final: 15 audit sections` (that campaign prices) and `step 194
audit-json-s2: 14 audit sections` (that one does not) — precisely the two cases
`p2_sections_ok`'s `len(secs) == 14` cannot express.

### Second run at the final code HEAD (`91437a44`) — same verdict, so the F1 and F5 fixes cost nothing

`verify-full-final-head.log`, 5m35.7s: steps 1–11 green again (step 4
`ok: race clean` after the planner change), step 13 never reached, and step 12
fails with the identical assertion — `AssertionError: P3 smoke audit: 15
sections, want 14`. The two runs therefore differ only in HEAD and wall time:
the F1 fix (step 4) and the F5 fix (steps 1/3/5/7/9/10/11 + golden) hold, and
step 12 is the single remaining red in the gate.

---

## Gates at the final code HEAD (`91437a44`) — all green

`final-gates.log`:

| gate | result | wall |
| --- | --- | --- |
| `go test ./... -count=1` | exit 0 | 53.9s |
| `go test -race ./internal/state ./internal/cli -count=1` | exit 0 | 2m58.8s |
| `go vet ./...` | exit 0 | — |
| `scripts/golden.sh` | exit 0 (196 steps, `GOLDEN GREEN`) | 8.7s |
| `scripts/runbook-walkthrough.sh` | exit 0 (150 passed / 0 failed) | 1m3.4s |

`scripts/legacy` untouched: `git diff --stat b0006c4a..HEAD -- scripts/legacy`
and `git diff --stat 16b3bc3a..HEAD -- scripts/legacy` are both empty.

---

## F5 (Minor) — one open question naming two components of one row

### Finding

`internal/planner/queue.go` `scoreRow` added `openQ[ref]` once per component of
the row, so one unresolved open question whose `blocks`/`applies_to` list named
two components of the same row contributed W3 **twice**. Direction was
conservative (rank higher, never lower), but the score was counting
(question, component) pairs, not questions.

### Red first (`.scratch/sdd/f5-red.txt`)

```
--- FAIL: TestQueueOpenQuestionCountedOncePerRow
    one question naming TWO components of one row scored openQ=2, want 1
--- FAIL: TestQueueMultiComponentQuestionDoesNotInflateRank
    queue order = [Q-002 Q-001] — a row whose single open question names two
    components must not outrank the one-component spelling of the same question
```

### Fix (commit `91437a44`, `test(planner): pin open-question row counting`)

- `queueSignals.openQ` is now `map[string][]int` — contract reference → the
  **ordinals** of the unresolved questions naming it, in model declaration order.
  Identity, not a tally, is what makes a once-per-row count possible.
- `scoreRow` unions those ordinals across the row's components and takes
  `len()`: one model entry is one question however many components it names; two
  questions naming the same row still count twice.
- No map is ranged (the union set is only measured, the per-reference slices are
  ordered), so the module's determinism guarantee is unchanged.
- Direction documented at the law comment: the count-once rule can only LOWER a
  weight relative to the per-component sum — **no row is ever promoted by it** —
  which is the conservative direction for a cockpit that must not rank work on a
  duplicated signal.

### Tests added (`internal/planner/task12_queue_scoring_test.go`)

`task12OpenQModel` is the new test fixture row: one question naming Rollup **and**
Zeta (both in scope; the coverage ledger marks Zeta swept and Rollup untouched).

- `TestQueueOpenQuestionCountedOncePerRow` — the two-component spelling scores
  `openQ=1`, weighs exactly the same as the one-component spelling, and leaves
  the other two score parts alone (`untouched=1`, `severity=3`).
- `TestQueueMultiComponentQuestionDoesNotInflateRank` — through the real
  `WorkQueue`: the two rows tie and fall back to alphabetical order, stable
  across 25 runs.

### No pin churn (checked)

Only one committed fixture anywhere in the repo has a multi-reference open
question (`internal/coverage/testdata/golden_replay.json`: `blocks:
["INV-3","ORC-1"]` — invariant ids, not in-scope contracts, so it contributes
nothing to `openQ` either way). Every other fixture names at most one contract
per question, so no row's `openQ` changes and no oracle needed re-pinning.
`scripts/golden.sh` re-run after the fix: exit 0 (`f5-golden.txt`).

---

## F4 (Minor) — the SDD evidence trail is now durable

`.scratch/` is gitignored (`.gitignore:3`), so the branch's whole audit trail
would have died with the worktree. The key artifacts are now committed under
`docs/sdd/` by the `docs(sdd): record SDD ledger and review trail` commit:

- `progress.md` (the ledger, including the F3 ruling line below),
- every `task-*-report.md` (20 files), every `task-*-review.md` /
  `task-*-fix1-review.md` (14 files, incl. `task-10-12-review.md`,
  `task-14-15-review.md`, `task-2-3-review.md`),
- `critic-round-1.md` (the critic's own report),
- `critic-round1-fixes.md` (this file),
- `verify-full-final.log` (the post-F1 run) and `verify-full-final-head.log`
  (the final-code-HEAD run), plus `final-gates.log` and the per-fix evidence:
  `f1-red-race.log`, `f1-green-race.txt`, `f1-mutation-race.log`,
  `f1-mutation-nolock-race.log`, `f1-race-diagnosis.txt`, `f5-red.txt`,
  `f5-golden.txt` — the red/green/mutation/diagnosis evidence every claim above
  cites, so the citations do not dangle.

`.scratch` itself was **not** force-added — the copies are the deliverable.

**Manifest check (F4's second half):** `rg docs/ assets/testdata/asset_manifest.json`
returns no matches, so no asset pin names a `docs/` path and no resync was owed
or performed. Checked as well that no gate reads the directory: every `docs/`
reference in `internal/`, `cmd/` and `scripts/` is a comment or a test *string*,
never a directory walk, so committing markdown under `docs/sdd/` is inert to
`go test`, `golden.sh`, `runbook-walkthrough.sh` and `verify-full.sh`.

---

## F3 (Important) — the plan-mandated whole-branch final review: ruling

The plan's execution order promises "Final whole-branch review: union-alpha over
MERGE_BASE..HEAD, pointed at the ledger's deferred minors; ONE fix wave then one
scoped re-review". The critic found no artifact for it and offered two ways to
close the gap.

**Ruling (recorded in the ledger as well): the critic loop IS that review.**
`.scratch/sdd/critic-round-1.md` is an independent, read-only sweep over
`b0006c4a..16b3bc3a` — the same range the plan names — that re-derived every gate
itself, re-ran the DoD gate, audited `scripts/legacy`, and reported findings
against the ledger's deferred minors; this wave is the "ONE fix wave" the plan
promises, and the F1/F5 re-verification above is its scoped re-review. No
separate artifact is needed, and none is claimed: the plan text now has its
artifact, `critic-round-1.md`, plus this closure record.

---

## Honest limits of this wave

- **F2 was not addressed.** Persisting/re-running independent reviews for Tasks
  1/2/3/4/8/14/15 is a routing/delegation task (b-ai/glm-5.3-flash), not a code
  fix, and this wave was scoped to F1/F5/F4+F3 by the operator. Note for the
  record: `.scratch/sdd/` **does** contain `task-1-review.md`,
  `task-2-3-review.md`, `task-4-review.md`, `task-8-review.md` and
  `task-14-15-review.md`, so part of F2's "no review recorded" claim looks like a
  search gap rather than a missing review — the operator should re-check F2
  against `docs/sdd/` before dispatching re-reviews.
- **F6 stays parked** (unbounded YAML alias traversal, `shellAbsentRe`
  colon-widening, govulncheck PASS semantics) — all already disclosed.
- **verify-full is still RED at step 12** in both runs (post-F1 and final code
  HEAD; pre-existing, now exactly characterized above). F1's own step-4 failure
  is closed; the DoD checkbox cannot be checked until the step-12 assertion is
  ruled on. Nothing was skipped or weakened to make a gate green: no test is
  skipped under `-race`, and `scripts/legacy` is untouched.
- The F1 fix scales the budget in `-race` test builds only; the underlying ~1s
  race-teardown cost is untouched (it is the detector's, not the product's), and
  the workers still hold the campaign lock until they exit — which is what the
  test intends to exercise.
- No push, no merge, no delegation was performed in this wave.
