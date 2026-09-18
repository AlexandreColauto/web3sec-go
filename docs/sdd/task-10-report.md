# Task 10 — open questions rank into the work queue

- **BASE** `eb44603a` (worktree `.worktrees/production-readiness`, branch
  `production-readiness`)
- **COMMIT** `cbdd93d5 feat(orchestrator): open questions rank into the work queue`
- **STATUS** complete, green

## Law implemented

Every `open_questions` entry that names a contract reference produces a
work-queue entry `resolve open question <id>: <text>`, ranked in the top 3 when
it names consensus-critical or untouched contracts; an empty `open_questions`
list leaves the queue unchanged.

## What changed

`internal/planner/plan.go` (only file touched, +61):

- `bootstrapOpenQuestions(b, model)` — called last inside
  `DefaultPlanFromModel`, i.e. after the role/economic bootstrap and before the
  queue is ranked. It skips entries that are `resolved=true`, have an empty
  `question`, or name no reference at all (those leave the queue alone, which
  is what the "empty list is a no-op" law requires).
- `openQuestionRefs(q)` — reads the schema field `blocks` first and the
  tolerated `applies_to` alias second, deduped in declaration order, so the
  minted text is deterministic.
- The minted row uses the derived-bootstrap shape the queue already ranks:
  `risk 0.8`, `budget_class standard`, `components` = the named references,
  `required_context ["structural_index","protocol_model"]`, question
  `resolve open question Q-00N: <text>`. Because the row names contracts, the
  existing `rankQueue` slotting puts it above generic index work.
- The bootstrap only ever *extends* a derived plan. A plan supplied by the
  operator is a contract and is never rewritten (the code path that reads a
  supplied plan does not call the bootstrap).

## Red → green (evidence)

Red (`bootstrapOpenQuestions` call removed; `.scratch/sdd/task-10-red.txt`):

```
--- FAIL: TestOpenQuestionsCompileIntoWorkQueue (0.00s)
    task10_open_questions_test.go:127: the open question never reached the work queue: [... Q-001..Q-005, no "resolve open question" row ...]
FAIL	websec/internal/orchestrator	0.021s
```

Green (same command, implementation in place):

```
ok  	websec/internal/orchestrator	1.186s
```

Tests: `internal/orchestrator/task10_open_questions_test.go`

- `TestOpenQuestionsCompileIntoWorkQueue` — a template model with two blocked
  open questions (`blocks` and the tolerated `applies_to`) mints two rows whose
  questions are `resolve open question Q-00N: <text>`; both sit in the top 3 of
  the queue.
- `TestNoOpenQuestionsLeavesQueueUnchanged` — the same model with
  `open_questions: []` produces a byte-identical queue.

## Brief visibility (probe, `.scratch/sdd/task-10-brief-probe.txt`)

A scratch probe (written, run, deleted — not committed) bootstrapped a campaign
whose model carries one blocked open question and rendered the brief:

- the plan's `work_queue` carries
  `Q-005 | resolve open question Q-005: is the rollup sequencer permissionless?`;
- the brief's attention block counts it as queue debt
  (`attention.queue = {"total":5,"untouched":5,"worked":0,...}`);
- the brief's printable attention line names only the **oldest** untouched
  priority (`Q-001`), so the open question's own text is not rendered as its
  own brief line. It is visible through `webv2 plan --json` and through the
  queue-debt accounting. Recorded as a residual gap in the final report.

## Gates

- `go test ./internal/orchestrator ./internal/briefing ./internal/cli ./internal/planner -count=1` — green
- full `go test ./... -count=1` — green (`TEST EXIT 0`)
- `go vet ./...` — green (`VET EXIT 0`)
- `scripts/golden.sh` — green, no pin changes (`GOLDEN EXIT 0`)
- `scripts/runbook-walkthrough.sh` — 150 passed / 0 failed (`RUNBOOK EXIT 0`)
- Existing queue oracles and every `scripts/legacy` fixture untouched.

## Corrections

- **2026-09-17 — the minted row's shape (risk/budget), correction not
  rewrite.** The "What changed" bullet above says the minted row uses
  "`risk 0.8`, `budget_class standard`". The landed code is
  `risk 0.9` / `budget_class cheap` (`internal/planner/plan.go`,
  `bootstrapOpenQuestions`: `b.add(q, "resolve open question "+id+": "+text,
  0.9, refs, []string{"drift", "code"}, addOpts{budget: "cheap"})`). The
  `0.8`/`standard` text was carried over from the plan's draft shape, not read
  back from the implementation. The conclusion is unaffected — 0.9/cheap and
  0.8/standard both land in the `now` slot via `DecisionRule(risk, budget)` —
  but the recorded shape was wrong. (Independent Phase C review,
  `.scratch/sdd/task-10-12-review.md`, Task 10 finding 3.)
