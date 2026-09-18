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

---

# Wave 2 — the step-12 RED and the two SECURITY.md minors

- **Branch:** `production-readiness`, worktree `.worktrees/production-readiness`.
- **Base:** `4382e586`. **Commits added by this wave:** `2e9ff576`, `656d2e4b`.
- **Scope:** the DoD's last red gate (verify-full step 12) and the two minor
  findings the Task 14/15 review filed against SECURITY.md. No push, no merge,
  no delegation.

## Commit `2e9ff576` — fix(release): verify-full step 12 accepts presence-gated sections.

### Symptom (reproduced on the pristine tree, then fixed)

Step 12 went RED fail-fast, before step 13 could run:

```
AssertionError: P3 smoke audit: 15 sections, want 14
FAIL [step 12: smoke audit --json sections]
```

Steps 9 and 11 were GREEN at 14 in the same run. The committed
`docs/sdd/verify-full-final.log` (pre-fix) recorded exactly that, and the
fresh reproduction is `.scratch/sdd/verify-full-before.log`.

### Root cause verified from the audit code FIRST (not inferred from the message)

| claim | evidence |
| --- | --- |
| `price_table` is genuinely presence-gated | `pricetable.go:40` — `return validation.Value{}, ErrSkip // never priced anything`; pinned by `pricetable_test.go:27` |
| `eval` is gated the same way | `eval.go:140` — `return validation.Value{}, ErrSkip` |
| a skipped section is omitted from the report | `audit.go:88` — `if errors.Is(err, sections.ErrSkip) { continue }` |
| the 14 base sections are order-pinned | `register.go:26-39` registers them in reference order; registration order IS report order (`RegisterAuditSection` → `SectionNames`); `audit_test.go:85` and `p1_sections_test.go:236` pin the registry tail (`eval`, then `price_table`, appended past the 14) |
| step 12 is what makes the price registry non-empty | its own body runs `price <C> set ETH 3000 …` before `audit --json` |

So the assertion was stale, not the product: 15 is the CORRECT render for a
campaign that priced, and 14 is the correct render for one that did not.

### Measured on the live surface (the binary verify-full built, against the three campaigns it leaves behind)

| report | sections | price_table | eval |
| --- | --- | --- | --- |
| step 12 `C-10ab2d8738` (priced) | **15** | yes | no |
| step 11 `C-50abeacbb3` (never priced) | **14** | no | no |
| step 9 legacy `C-45488bdaf5` (never priced) | **14** | no | no |

and the rendered order is exactly registry order (… `unpriceable`,
`price_table`). Raw captures: `.scratch/sdd/step{9,11,12}-*sections.json`.

### The fix

`p2_sections_ok` (shared by steps 9/11/12) now asserts the **14 unconditional
sections, in registration order, plus any of the documented presence-gated
extras** (`eval`, `price_table`) that render — and nothing else. It is
deliberately NOT relaxed to a count of 15: a bare 15 would let a never-priced
campaign that silently grew a fake row pass. It mirrors the allowance
`scripts/check-golden.py`'s `check_audit` already makes (EXPECTED_SECTIONS =
the 14 unconditional rows + the optional presence-gated tail; its own run shows
15 at step 164 and 14 at step 194) — the helper comment cites it, and the
hard failures stay hard: missing base row, unknown name, and the order of
whatever renders.

### Proof the gate still bites — 10/10 mutation cases

Run with the python body extracted verbatim from the script
(`.scratch/sdd/p2_sections_ok_mutation_test.py`, `.scratch/sdd/p2_sections_ok_body.py`):

- PASS as required: 14 base; base+`price_table` (the real step-12 capture);
  base+`eval`; base+`eval`+`price_table`.
- FAIL as required: missing base row; **unknown 15th name at count==15**;
  base reorder; gated tail out of order; gated row spliced into the base run;
  empty report.

### verify-full to COMPLETION

`VERIFY-FULL GREEN: all 13 steps pass` — step 12 now reports
`ok P3 smoke audit: 15 audit sections = 14 base + presence-gated
['price_table']`, step 11 `14 audit sections = 14 base (no presence-gated
section rendered)`, step 13 walkthrough green. The green log is committed at
`docs/sdd/verify-full-final.log` (byte-identical to
`.scratch/sdd/verify-full-final.log`), replacing the step-12 RED the previous
wave committed.

**Same-pass honesty fix:** the four stale "(15 registered; `eval` is
presence-gated)" comments in verify-full.sh (the registry carries **16**:
14 base + `eval` + `price_table`) and the step-12 row claiming "all 14 rendered
sections" are corrected in the same commit.

## Commit `656d2e4b` — docs: correct fork RPC env var and vm-snapshot availability note.

Both findings were re-verified against the code before editing; the review's
line numbers were checked, not trusted.

**(1) The phantom `WEBV2_FORK_RPC_URL`.** `rg WEBV2_FORK_RPC_URL` returns zero
hits in code — it exists only in prose (SECURITY.md, RUNBOOK.md,
runbook-go-notes.md). The code reads `FORK_RPC_URL` only: `envgo/env.go:266`
(`ForkRPCProbe`), `sandbox/profiles.go:341` (the fork-runner container env),
`findings/gate.go:408` (the E5/E6 reachability demand). The `WEBV2_` prefix is
real only for `WEBV2_SOLC_DIR`. SECURITY.md now names the one variable that
exists and cites the outbound call site: `http.NewRequest` at
`envgo/env.go:241` is the **only** non-test outbound HTTP call site in
`internal/` (the non-test `http.*` hits are exactly 2, both on that one
request: `NewRequest` at :241 and the `http.Client` at :246).

**(2) `vm-snapshot`.** `ProfileAvailable` returns false for it
**unconditionally** (`profiles.go:282`, `// vm-snapshot requires external VM
infrastructure`), so it can never execute; and `BuildContainerArgv` has no
`vm-snapshot` branch — were it ever reached it would take the fork-runner
`else` arm (bridge + host-gateway), contradicting its recorded
`profileNetwork: none`. One honest clause added: the profile is declared, no
container execution is available for it in this build, and it is carried for
forward-compatibility only. The `Is:` paragraph no longer implies a
`docker run` for it.

**Left out on purpose (flagged, not silently skipped).** The same phantom name
still appears in `assets/runbook/RUNBOOK.md` (lines 44 and 1692) and
`docs/runbook-go-notes.md:257`. RUNBOOK.md is manifest-pinned — correcting it
requires an `assets` manifest resync (verify-full step 6), which is a different
change than the SECURITY.md minor this task scoped. `scripts/p2-docker-e2e.sh`
(comment at :319, assertion at :330) also still says "15 registered"; its
14-section assertion remains CORRECT because that campaign never prices (the
script contains no `price`/`cost` invocation), and that script is not part of
the 13-step gate.

## Gates after both commits — all green

Evidence: `.scratch/sdd/gates-after-both.log`.

| gate | result |
| --- | --- |
| `go test ./... -count=1` | exit 0 — 127 packages `ok`, 0 `FAIL` |
| `go vet ./...` | exit 0 — no output |
| `scripts/golden.sh` | exit 0 — `GOLDEN GREEN` (196 steps, 179 events, chain intact; audit surface 14/15/14 at steps 07/164/194, i.e. the presence-gated tail behaving exactly as documented) |
| `bash scripts/security-check-test.sh` | exit 0 — `56 passed, 0 failed` |

## Honest limits of this wave

- `scripts/legacy` is untouched: no diff, no fixture edit.
- The **tracked** `docs/sdd/critic-round1-fixes.md` copy of this report is NOT
  updated by this wave. The task scoped the report to `.scratch/sdd/` and
  pinned the two commits to exact paths, so the committed copy still ends with
  the previous wave's "verify-full is still RED at step 12 … the DoD checkbox
  cannot be checked" limit — which is now FALSE. Everything else in that copy
  remains true; the operator should re-run the SDD copy step (or ask) so the
  durable trail carries this closure.
- The step-12 change is a **gate** fix, not a product change: no section, no
  registry entry, no audit output changed. The product behaviour it encodes
  (presence gating) was already pinned by Go unit tests; the gate now agrees
  with them instead of contradicting them.
- `p2_sections_ok` stays a surface-shape check. It does not re-derive WHY
  `price_table` rendered — the Go tests own that — so a campaign that priced
  nothing yet somehow produced a prices.json row is caught by
  `PriceTable`'s own reconciliation (and its tests), not here.
- No push, no merge, no delegation.

---

# Wave 2 addendum — 2026-09-18: the two flagged leftovers are closed, verify-full GREEN

Everything above stands as written except the two limits this addendum names
and closes. Both were flagged rather than silently skipped by the Wave-2
section; this is the wave that closes them.

## Commit `64b6eefa` — docs: correct fork RPC env var in runbook and notes.

Closes "Left out on purpose" (Wave 2). The phantom `WEBV2_FORK_RPC_URL` is
gone from both prose files, so the correction `656d2e4b` made in SECURITY.md
now holds in prose repo-wide.

| file:line | before | after |
| --- | --- | --- |
| `assets/runbook/RUNBOOK.md:44` | `` `FORK_RPC_URL` / `WEBV2_FORK_RPC_URL` `` | `` `FORK_RPC_URL` `` |
| `assets/runbook/RUNBOOK.md:1692` (env table) | `` `FORK_RPC_URL` / `WEBV2_FORK_RPC_URL` `` | `` `FORK_RPC_URL` `` |
| `docs/runbook-go-notes.md:257` | `` (`WEBV2_FORK_RPC_URL`) `` | `` (`FORK_RPC_URL`) `` |

`rg WEBV2_FORK_RPC_URL assets/runbook/RUNBOOK.md docs/runbook-go-notes.md` now
exits 1 (no hits). The name survives only in the review records that FILED the
finding (`.scratch/sdd/task-14-15-review.md`, `docs/sdd/task-14-15-review.md`),
which quote it as the defect — not in prose asserting the variable exists.

**Manifest resync.** RUNBOOK.md is manifest-pinned, so the fix needed the
asset resync the previous wave deferred: `python3 scripts/sync-asset-manifest.py`
— the documented equivalent of verify-full step 6's
`go test ./assets -run TestAssetPackManifest -count=1` (there is no Makefile;
verify-full.sh invokes that test directly). The diff is exactly the one
`RUNBOOK.md` entry: sha256 `f1843f46…943b807` -> `41e40478…52de53`, size
110383 -> 110337 bytes. `--check` reports "asset manifest is current" and
`go test ./assets/... -count=1` is `ok websec/assets` (exit 0). No other pack's
bytes changed.

## The tracked trail copy — refreshed

`.scratch/sdd/critic-round1-fixes.md` is the live copy; the tracked
`docs/sdd/critic-round1-fixes.md` was a byte-prefix of it (first 329 lines,
17195 bytes — `cmp` confirmed the prefix before the refresh), i.e. it ended at
the Wave-1 limits and never received the Wave-2 section at all. It is now
copied over, byte-identical (`cmp` clean), and committed by exact path.

**Superseded claim, called out so no reader is misled:** the Wave-1 bullet
above that says "verify-full is still RED at step 12 … the DoD checkbox cannot
be checked" is HISTORICAL — true of the tree before `2e9ff576`. That commit
fixed the stale assertion; verify-full is **GREEN, all 13 steps**
(`VERIFY-FULL GREEN: all 13 steps pass`, step 12 reporting `15 audit sections =
14 base + presence-gated ['price_table']`), evidence committed by `2e9ff576` at
`docs/sdd/verify-full-final.log`, byte-identical to
`.scratch/sdd/verify-full-final.log` (re-checked with `cmp` in this wave).

## Final gates at this HEAD — all green

Run at `64b6eefa`; the only commit after it is docs-only, so the numbers carry
unchanged to the refreshed-tree HEAD. Raw logs: `.scratch/sdd/wave3-*.log`
(untracked).

| gate | result |
| --- | --- |
| `go test ./... -count=1` | exit 0 — **71 packages `ok`, 0 `FAIL`** (73 packages total; 2 report `[no test files]`) |
| `go vet ./...` | exit 0 — no output |
| `scripts/golden.sh` | exit 0 — `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)` |
| `scripts/runbook-walkthrough.sh` | exit 0 — **`walkthrough: 150 passed, 0 failed`** |
| `bash scripts/security-check-test.sh` | exit 0 — **`56 passed, 0 failed`** |

**Correction to the Wave-2 gate table above.** Its "127 packages `ok`" line is
a counting artifact, not a package count: 127 is the number of `ok`-prefixed
lines in `.scratch/sdd/gates-after-both.log`, which concatenates the `go test`
section with `scripts/golden.sh`'s and `security-check-test.sh`'s own `ok`
lines (the security-check suite alone contributes 56). The repo has **73** Go
packages; the real `go test ./... -count=1` result is 71 `ok` + 2
`[no test files]`, 0 `FAIL`, exit 0 — the line the table above records from a
clean, single-command capture.

## Honest limits of this addendum

- `scripts/legacy` is untouched: no diff, no fixture edit.
- No push, no merge, no delegation.
- `scripts/p2-docker-e2e.sh` still says "15 registered" (comment :321,
  assertion :330, re-measured in this wave — the Wave-2 text's ":319" was the
  block start). Its 14-section assertion remains CORRECT for a campaign that
  never prices, and the script is not part of the 13-step gate — left as found,
  still disclosed.
- verify-full itself was not re-run in this wave; its committed green log
  (`docs/sdd/verify-full-final.log`, from `2e9ff576`) is the evidence, and the
  five gates above were re-run green at `64b6eefa` on this tree.
