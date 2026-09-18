# Task 12 — additive risk-weighted queue ordering

- **BASE** `eb44603a` (worktree `.worktrees/production-readiness`, branch
  `production-readiness`)
- **COMMIT** `1a03c8ca feat(orchestrator): additive risk-weighted queue ordering`
- **STATUS** complete, green (golden pin re-pinned deliberately)

## Law implemented

Ordering weight is `(untouchedCount * W1) + (severityScore * W2) +
(openQuestionCount * W3)`; severity `critical=3 / high=2 / medium=1 / low=0`;
named constants with a `ponytail:` comment; **never** multiplicative; ties
alphabetical; fully deterministic.

## What changed

`internal/planner/queue.go` (+225):

- `queueWeightUntouched = 1.0`, `queueWeightSeverity = 2.0`,
  `queueWeightOpenQ = 1.5`, each documented, under one `ponytail:` comment that
  states why the weight is additive and that there is no config key.
- `queueSeverityBands` (the model's own vocabulary), `queueScore{untouched,
  severity, openQ}` and `queueScore.weight()`.
- `queueSignals` + `buildQueueSignals` build the per-campaign lookups from the
  model and the coverage ledger: in-scope contracts (name *and* path),
  coverage `path -> swept`, contract -> max severity band, invariant id ->
  severity band, contract reference -> count of unresolved open questions
  naming it.
- `rankQueue` sorts by slot class first (the `DecisionRule` contract stays the
  primary key), then the additive score descending, then `priority_id`, then
  `question` — the deliberate replacement of the old risk-descending tiebreak.
  Every map is read by key and never ranged, so map order cannot leak in.
- The coverage ledger is read as the artifact it is (`validation.ReadJson` on
  `artifacts/coverage.json`): importing `internal/coverage` from `planner`
  closes a test-binary cycle (`coverage -> audit/sections -> completion ->
  planner`). A campaign with no ledger has swept nothing, so every in-scope
  contract counts as untouched; a ledger that exists but cannot be read is an
  error, never a silent re-rank.

`internal/orchestrator/plan.go` (+36): `planQueueModel()` scores the write path
and the read-back path against the same model (the campaign's own
`protocol_model.json` when no model argument is supplied). Before, a plan read
back with no model scored every row at zero and could return a different order
than the write that produced it.

## Red → green (evidence)

Red (`internal/planner/queue.go` restored to its pre-commit content;
`.scratch/sdd/task-12-red.txt`):

```
--- FAIL: TestQueueAdditiveRiskOrdering (0.00s)
    task12_queue_scoring_test.go:92: queue order = [Q-001 Q-002], want Q-002 (consensus-critical, untouched) first: [...]
--- FAIL: TestQueueScoreIsAdditiveNotMultiplicative (0.00s)
    task12_queue_scoring_test.go:127: queue order = [Q-001 Q-002] — a zero-untouched, zero-question critical contract must still outrank a zero-signal one (additive, never multiplicative)
FAIL	websec/internal/planner	0.009s
--- orchestrator ---
--- FAIL: TestPlanQueueOrdersByAdditiveRisk (0.01s)
    task12_orchestrator_test.go:72: first queue row = Q-001, want Q-002 (consensus-critical, untouched): [...]
FAIL	websec/internal/orchestrator	0.013s
```

Green (same commands, implementation in place):

```
ok  	websec/internal/planner	0.458s
ok  	websec/internal/orchestrator	1.186s
```

Tests:

- `internal/planner/task12_queue_scoring_test.go`
  - `TestQueueAdditiveRiskOrdering` — the untouched critical row leads; equal
    scores fall back to alphabetical `priority_id`; the ordering is stable
    across 25 runs (determinism).
  - `TestQueueScoreIsAdditiveNotMultiplicative` — a row with a critical
    invariant but zero untouched contracts and zero open questions still
    outranks a zero-signal row (a product would have zeroed it).
- `internal/orchestrator/task12_orchestrator_test.go`
  - `TestPlanQueueOrdersByAdditiveRisk` — through the real `Plan` entry point,
    and the read-only path returns the same order as the write path (the
    `planQueueModel` bridge).

## Golden pin update (deliberate)

`internal/orchestrator/testdata/oracles.json` — the `planned` scenario's three
plan snapshots (steps 0, 3, 6) re-pinned to the new `work_queue` order:

```
before: Q-001 Q-002 Q-013 | Q-003 Q-004 Q-005 Q-006 Q-007 Q-008 Q-009 Q-010 Q-012 Q-011
after:  Q-001 Q-002 Q-013 | Q-003 Q-009 Q-010 Q-004 Q-005 Q-006 Q-007 Q-008 Q-011 Q-012
```

`Q-003`/`Q-009` (Vault, critical invariant, untouched) and `Q-010` (VaultProxy,
named critical invariant) now lead the `next` slot; the zero-signal rows follow
alphabetically. The re-pin was verified leaf-by-leaf before writing: only the
three `oracle` strings changed, the rows are the same rows with the same
content, only their order moved. `scripts/golden.sh` and
`scripts/runbook-walkthrough.sh` needed no pin changes.

## Gates

- `go test ./internal/orchestrator ./internal/briefing ./internal/cli ./internal/planner -count=1` — green
- full `go test ./... -count=1` — green (`TEST EXIT 0`)
- `go vet ./...` — green (`VET EXIT 0`)
- `scripts/golden.sh` — green (`GOLDEN EXIT 0`)
- `scripts/runbook-walkthrough.sh` — 150 passed / 0 failed (`RUNBOOK EXIT 0`)
- Logs: `.scratch/sdd/task-10-12-{full-test,vet,golden,runbook}.txt`,
  `.scratch/sdd/task-1{0,1,2}-red.txt`
