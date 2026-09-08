# P1 Plan — Findings and Gates (Python → Go)

Spec: `web3sec-final/docs/GO_REWRITE_SPEC.md` §14 (P1 bullet) + §6 (Finding
domain), §7 (pipeline/orchestration/completion).

**P1 scope (spec-verbatim):** findings (IR, transitions, gate bundle,
evidence, assumptions, memory checks), floors, taxonomy, capabilities,
dedup, risk, pricing, bounty policy, invariants, protocol graph,
economics, planner, coverage, orchestrator, pipeline, completion.
**CLI:** ingest, model, plan, answered, floors, budget, dedup,
resolve-candidate, prioritize, repro-queue, verdict, recall, gate
(+`--explain`), prove, waive, invariant-verify, invariant-contradict,
artifact-register, artifact-list, hint, scope.

**Gate (spec §14):** a deterministic walkthrough (ported) reproduces
Python's artifact bytes; gate dry-run outputs identical. Concretized:
the golden recipe grows a P1 section (ingest → plan → answered →
dedup → gate dry-run → prove) whose campaign artifacts and command
outputs are byte-identical after the KNOWN_DIVERGENCES normalizations;
`verify-full.sh` grows the P1 steps and stays green.

## Testmap phase retag (done 2026-09-08)

The original testmap phase tags were file-guesses and contradicted
spec §14's module ownership (e.g. structural-index tests tagged P1,
bounty-policy tests tagged P2). All 1096 rows were re-tagged from a
per-file import scan against the spec's module→phase map:

- **P1 slice: 473 functions in 41 files** (was 524 — the excess was
  P2/P3/P4 module tests: chain-engine, corpus surface, sft, datasets,
  structural index, relations, archetypes, playbooks, briefing,
  doctor, metrics, …)
- P2: 182 · P3: 266 · P4: 112
- **P0 addendum: 7** (tests/test_living_artifacts.py — register_or_
  refresh behavior that P0 already implements in state/artifacts.go;
  ported as Task 0 below; check-testmap enforces it)

Mixed-subject files (e.g. test_cli.py covers P2 `exec` commands,
test_review_fixes touches chain_engine) keep their dominant-subject
tag; function-level splits are noted in the task that ports them.

## Rules (inherited from P0, unchanged)

- **TigerStyle / Ponytail:** YAGNI → stdlib → native → existing dep →
  one-liner → minimum viable. Functions ≤70 lines, ~2+ assertions per
  test function, 4-space indent, hard-wrap 100 cols.
- **Approach A:** phase-serial, module-level TDD. Tests first,
  implementation second.
- **PYTHON WINS:** where the spec and the Python code disagree, the
  Python code is the source of truth.
- **Fast tests are a hard gate:** `go test ./...` < 2s, `-race` < 2s.
  No flood loops >50 items.
- **Every task ends with a parity probe:** the same op-sequence through
  the Python and Go twins produces byte-identical state/events/artifacts
  (volatile fields normalized per KNOWN_DIVERGENCES).
- **testmap.json discipline:** every ported Python test function gets a
  real row (1:1 or noted merge); no silent drops.
- **Delegation:** subagents only via `workflow` agent() with
  `provider:"openrouter", model:"meta/muse-spark-1.3-contributor"`;
  fallback `openrouter/deepseek/deepseek-v4-flash-0731`. Never the local
  model.
- **Reference is live (user directive 2026-09-09):** web3sec-final is
  developed in parallel. Baseline at P1 start: `e6cbff6`. Before each
  task: `git -C web3sec-final log e6cbff6..HEAD` — if new code touches
  the module being ported, fold it in (PYTHON WINS = the *current*
  Python); bump the baseline in this file. Before any gate: full
  `src/`+`tests/`+`schema/` diff since baseline, Python suite re-run
  (the 1146 baseline count moves when tests are added).
- **End state (user directive 2026-09-09):** the parity tooling
  (`scripts/*.py`, verify-full's Python steps) is provisional. At P4
  cutover it moves to the Python repo (it guards the archived
  reference); the shipped Go repo is pure Go: `cmd/ internal/ assets/
  docs/`.
- **Byte-exact contracts in P1** (transcribe exactly, golden-vector
  each): `findings.technical_signature`, `findings.text_signature`,
  `findings._canonical_row_hash`/`compute_row_digest`,
  `dedup.lineage_id_for`, `invariants.normalize_inv_id`,
  `planner` Q/L id numbering (counter continuation),
  `economics` EQ/TR numbering.

## Module inventory (measured)

| module | lines | Go package | byte-exact contracts |
|---|---|---|---|
| findings | 1476 | internal/findings | signatures, row digests |
| planner | 578 | internal/planner | Q-/L- id numbering |
| invariants | 504 | internal/invariants | normalize_inv_id |
| orchestrator | 499 | internal/orchestrator | — |
| pipeline | 472 | internal/pipeline | — |
| completion | 469 | internal/completion | — |
| bounty_policy | 405 | internal/bounty | check ids (contract) |
| risk | 318 | internal/risk | rounding (pythonRound) |
| dedup | 271 | internal/dedup | lineage_id_for |
| taxonomy | 243 | internal/taxonomy | class normalization regex |
| coverage | 231 | internal/coverage | 'n/m' counters |
| floors | 168 | internal/floors | kebab-case regex |
| economics | 141 | internal/economics | EQ/TR numbering |
| protocol_graph | 124 | internal/protocolgraph | — |
| capabilities | 126 | internal/capabilities | label normalization |
| pricing | 72 | internal/pricing | PRC- ids |
| costs | (P1 slice) | internal/state (extend) | budget formatting |

Total ≈ 5.9k lines Python → Go.

## New dependency (P1, YAGNI-checked)

`gopkg.in/yaml.v3` — `taxonomy.load_maps`/`validate_map_file` parse
YAML map files with PyYAML error semantics. This was deferred from P0
on purpose; P1 is the phase that needs it. (No other new dependency:
risk/bounty formatting is hand-rolled, no regexp2 — P1's regexes are
ASCII-class compatible with RE2; verify per-pattern when porting,
record any divergence in KNOWN_DIVERGENCES.)

## Task order (dependency-driven)

```
1  findings core (IR, levels, signatures, save/load)
2  findings transitions + gate bundle + evidence + assumptions + memory
3  taxonomy + capabilities + floors
4  dedup
5  protocol graph + economics
6  risk + pricing
7  bounty policy
8  invariants
9  planner
10 coverage
11 pipeline
12 completion
13 orchestrator (facade)
14 CLI P1a: scope, model, plan, answered, ingest, floors, budget, hint
15 CLI P1b: dedup, resolve-candidate, prioritize, repro-queue, verdict,
            recall, gate(+--explain), prove, waive, invariant-*, artifact-*
16 testmap P1 (473 functions → real rows)
17 golden suite v2 (P1 recipe extension)
18 verify-full P1 (cross-audit + P1 steps)
19 P1 gate report + KNOWN_DIVERGENCES additions
```

Each task: tests first (ported from the named Python test files),
implementation, parity probe, commit. Tasks 1-13 are module ports;
14-15 are CLI; 16-19 are the gate work.

## Task 0: P0 addendum — living-artifacts tests (7)

tests/test_living_artifacts.py exercises P0 behavior (register_or_
refresh + audit) that the original P0 slice missed; already implemented
in Go (state/artifacts.go, audit/sections/artifacts.go). Port the 7
tests 1:1:
- 5 state-side → `internal/state/living_artifacts_test.go`
  (reuses-row, updates-hash, requires-reason, log old/new hashes,
  different-kind-same-path)
- 2 audit-side → `internal/audit/living_artifacts_test.go`
  (audit green after sanctioned refresh; audit flags hand-edit with
  "hash mismatch" after refresh)
Flip the 7 testmap rows to real (go_file/go_func). check-testmap is
currently RED on exactly these 7 — it goes green when this lands.
- [ ] Step 1: port the 7 tests (they must pass against the EXISTING
      implementation — any failure is a real P0 bug, stop and fix)
- [ ] Step 2: testmap rows → real; check-testmap green
- [ ] Step 3: commit ("P0 addendum: port test_living_artifacts (7)")

## Task 1: findings core

**Files:** create `internal/findings/{findings.go,levels.go,
signatures.go,storage.go}` + tests; extend `assets/schema` (finding
schema already embedded in P0).
**Port (findings.py, first half):** `required_level_for`,
`required_level_for_campaign`, `level_index`, `gate_requirements`,
`finding_level`, `is_execution_level`, `technical_signature`,
`text_signature`, `finding_path`, `save_finding`, `load_finding`,
`load_all_findings`, `load_live_findings`, `new_finding_id`,
`ingest_hypothesis`, `add_evidence`, `evidence_deficit`,
`intake_checkpoint`, `claim_drift_problems`.
**Ported tests:** tests/test_findings.py (core slice, 20),
tests/test_evidence_integrity.py (10 — note: imports reproduction/
sandbox; split the P2-touching functions at port time),
tests/test_dedup_determinism.py (signature slice, 3).
(tests/test_criticality.py is P3 — structural-index only.)
**Parity probe:** ingest the same 3 hypotheses (Python + Go, pinned
clock/uuid via WEBV2_NOW/WEBV2_UUID) → findings/*.json + events.jsonl
byte-identical; signatures match committed vectors.
- [ ] Step 1: signature vectors (generate from Python twin, commit as
      Go test vectors) + failing tests
- [ ] Step 2: implement core until green
- [ ] Step 3: parity probe green; commit

## Task 2: findings transitions + gate bundle

**Port (findings.py, second half):** `transition` (state machine,
adjacent/adjacent_clear), `confirmation_gate_detail` (the CONFIRMED
gate bundle — ordered checks, ids are contract, spec §6.4),
`set_assumptions`, `assumption_transition`, `set_critic_verdict`,
`set_shield_adjudication`, `mark_precondition`, `visible_memory_rows`,
`compute_row_digest`, `record_memory_check`, `memory_check_fails`,
`fold_into_lineage`, `mark_duplicate`, `flag_possible_duplicate`.
**Ported tests:** tests/test_findings.py (transition slice),
tests/test_assumptions.py, tests/test_memory_check_gate.py (P1 slice),
tests/test_answered.py (the finding-facing parts),
tests/test_cli_e2e_confirm.py (defer the CLI parts to Task 14, port the
state effects here).
**Parity probe:** the full status lifecycle on one finding
(pending→confirmed→disproved→duplicate fold) → events.jsonl +
campaign_state.json byte-identical; `confirmation_gate_detail` JSON
byte-identical.
- [ ] Step 1: failing tests (gate bundle ids as vectors)
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 3: taxonomy + capabilities + floors

**Port:** taxonomy.py (all 7 publics; YAML maps via yaml.v3;
`normalize_class` regex must match Python's `re.sub` on the test
corpus), capabilities.py (all 10; label normalization), floors.py
(all 7; kebab-case regex; E4-E7 levels).
**New dep:** `gopkg.in/yaml.v3` (go.mod + tidy).
**Ported tests:** tests/test_taxonomy.py,
tests/test_taxonomy_seed_alignment.py, tests/test_capabilities.py
(+test_cap_role_labels.py), tests/test_floors.py.
**Parity probe:** same taxonomy map file + same floor ops →
floor_policy.json + events byte-identical; normalize_class on the
full label corpus matches Python output.
- [ ] Step 1: add yaml.v3; failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 4: dedup

**Port:** dedup.py (all 6 publics; `lineage_id_for` byte-exact:
`LIN-` + text_signature('lineage|...'); tier-1/2/3 merge ordering +
earliest-kept tiebreak).
**Ported tests:** tests/test_dedup_determinism.py (full),
tests/test_partition_guards.py (dedup slice).
**Parity probe:** same finding set through `run_dedup` → identical
report JSON, same lineage ids, same events.
- [ ] Step 1: lineage id vectors + failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 5: protocol graph + economics

**Port:** protocol_graph.py (all 11 publics — pure dict traversal over
the protocol_model schema), economics.py (all 4; EQ-%03d / TR-%03d
numbering byte-identical).
**Ported tests:** tests/test_lens_exhaustive.py (protocol slice),
tests/test_economics_transforms.py.
**Parity probe:** same protocol_model.json through both twins →
`who_can`/`trust_boundary_gaps`/`critical_edges`/... outputs and the
equation/transform lists byte-identical.
- [ ] Step 1: failing tests (model fixture from Python tests)
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 6: risk + pricing

**Port:** risk.py (all 10; **pythonRound** for round(x,2)/round(x,3);
`${usd:,.0f}` and `:.0%` formatting helpers — Go needs a
`usdCompact`/`pct0` equivalent; case-insensitive band regexes),
pricing.py (all 4; PRC- + new_id('x',8)).
**Ported tests:** tests/test_privileged_bands.py? (no — that's P2),
tests/test_risk* if present, tests/test_pricing* if present, plus the
risk/pricing slices of tests/test_budget.py and tests/test_metrics.py
deferred rows.
**Parity probe:** same finding → `calibrate` output +
`record_economic_impact` events byte-identical (rounded floats via
PythonFloat).
- [ ] Step 1: rounding/formatting vectors from Python + failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 7: bounty policy

**Port:** bounty_policy.py (all 7; check ids are contract —
`gate_explain` catalog text identical; `evaluate_bounty_gate`).
**Ported tests:** tests/test_bounty_policy.py.
**Parity probe:** same finding + policy file → `evaluate_bounty_gate`
JSON byte-identical; gate-explain lines identical.
- [ ] Step 1: failing tests (catalog text as vectors)
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 8: invariants

**Port:** invariants.py (all 14; `normalize_inv_id` regex
`INV-(\d+)` zero-pad; round(x,3) coverage; doc scans with
OSError-swallowing semantics).
**Ported tests:** tests/test_invariants.py,
tests/test_invariants_structured.py, tests/test_invariants_doc.py.
**Parity probe:** same model + links → `coverage`/`reconcile`/
`documented_invariants` outputs byte-identical.
- [ ] Step 1: failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 9: planner

**Port:** planner.py (all 14 publics; **Q-%03d / L-%02d counter
continuation byte-identical** — the Q counter continues across
replans; lens question `.format()` templates; decision_rule;
work_queue ordering; mark_answered validation incl.
families_checked/symmetry attestation).
**Ported tests:** tests/test_plan_lenses.py, tests/test_answered.py,
tests/test_sequence_guidance.py? (no — P2), tests/test_promotion.py.
**Parity probe:** default_plan_from_model on the P1 fixture model →
plan JSON byte-identical; a 3-answer sequence → identical plan +
events.
- [ ] Step 1: Q/L numbering vectors + failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 10: coverage

**Port:** coverage.py (all 9; 'n/m' counter formatting; round(x,3)).
**Ported tests:** the coverage slices of tests/test_lens_exhaustive.py
+ tests/test_sequence_coverage.py (P1 portion).
**Parity probe:** same index + model → coverage.json byte-identical.
- [ ] Step 1: failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 11: pipeline

**Port:** pipeline.py (STAGES DAG — 17 canonical stages, join specs
transcribed exactly per spec §7.2 🔒; `join`/`join_satisfied` incl.
quorum + predicate; `topological_order`; `Pipeline.completed/
next_stage/ready_stages/run`; cost-ceiling halt with `${spent:,.2f}`
formatting; error-text-becomes-data semantics).
**Ported tests:** tests/test_pipeline.py.
**Parity probe:** a scripted stage run (deterministic stages only) →
campaign_state phase_history + stage artifacts byte-identical.
- [ ] Step 1: DAG/join vectors from the Python constants + failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 12: completion

**Port:** completion.py (waivers/waive; has_proof/proof_status/
all_proof_status; audit_stage_ledger; the 13-stage proof bundle,
[:5]/[:80] truncations exact).
**Ported tests:** tests/test_completion_proof.py.
**Parity probe:** waive + prove on a half-done campaign → outputs
byte-identical.
- [ ] Step 1: failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 13: orchestrator

**Port:** orchestrator.py (the deterministic facade — every method
that P1's CLI commands call; next_actions; status; STATUS_NOTE_CAP=200
truncation; OrchestrationError flow).
**Ported tests:** tests/test_orchestrator.py.
**Parity probe:** the deterministic half of the walkthrough (scope →
snapshot → plan → triage → dedup → gate) → campaign_state.json +
events.jsonl byte-identical.
- [ ] Step 1: failing tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 14: CLI P1a

**Port (cli.py handlers):** scope, model, plan, answered, ingest
(+`--example`), floors (list/set/unset), budget (--set/--clear/
--set-discovery), hint. Shared helpers: the global error handler
(SchemaError/FileNotFoundError/PermissionError/ValueError →
`error: ...` exit 1 + not-in-workspace hint), --actor defaulting
('cli'), --json mode convention.
**Ported tests:** the P1 slices of tests/test_cli.py +
tests/test_cli_gate_dryrun.py (gate parts) + tests/test_ingest.py +
tests/test_cli_e2e_confirm.py (state effects now covered).
**Parity probe:** the P1a command sequence on a fresh twin campaign →
stdout/stderr/exit + campaign artifacts byte-identical (pinned
clock/uuid).
- [ ] Step 1: failing CLI tests (usage text + error handler first)
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 15: CLI P1b

**Port (cli.py handlers):** dedup, resolve-candidate, prioritize,
repro-queue, verdict, recall, gate (+`--explain`, single-finding
dry-run mode exits 1 while checks fail), prove (--stage), waive,
invariant-verify, invariant-contradict, artifact-register,
artifact-list.
**Ported tests:** tests/test_cli_recall.py,
tests/test_cli_privileged.py? (P2 — verify split), the remaining
tests/test_cli_gate_dryrun.py, tests/test_cli_e2e_confirm.py (CLI
parts).
**Parity probe:** the gate dry-run walkthrough (spec gate: "gate
dry-run outputs identical") → byte-identical.
- [ ] Step 1: failing CLI tests
- [ ] Step 2: implement until green
- [ ] Step 3: parity probe green; commit

## Task 16: testmap P1

Flip the 473 `deferred-P1` rows to real rows as the modules land
(continuous from Task 1, closed out here): every P1 Python test
function maps to a Go test (1:1 or noted merge). `check-testmap.py`
extends to validate the P1 slice the same way as P0.
- [ ] Step 1: extend check-testmap.py (P1 slice fully real)
- [ ] Step 2: reconcile; commit

## Task 17: golden suite v2 (P1 recipe)

Extend `scripts/golden-run.py` recipe with the P1 deterministic
walkthrough: `scope → model → plan → answered (x2) → ingest (x3) →
dedup → floors set → gate (dry-run) → prove --stage → invariant-
verify`. Pinned clock/uuid; same target tree; both twins.
`check-golden.py` gains the P1 artifacts (findings/*.json, plan,
coverage, floor_policy, links) to the tree diff and the P1 command
outputs to the step diff.
- [ ] Step 1: extend golden-run recipe + check
- [ ] Step 2: GREEN (document any new KNOWN_DIVERGENCES row first)
- [ ] Step 3: commit

## Task 18: verify-full P1

Extend `scripts/verify-full.sh`: the Python baseline (step 7) already
covers P1 tests; add a P1 cross-audit step — audit a Python-written
P1 campaign from Go (spec gate: "Python campaign audits clean" grows
to the P1 artifact set). Keep the 10-step skeleton; renumber.
- [ ] Step 1: extend the harness
- [ ] Step 2: green end-to-end
- [ ] Step 3: commit

## Task 19: P1 gate report

`docs/gates/P1-gate.md` (same 7-item shape as P0: baseline green,
walkthrough bytes identical, fast tests, golden v2 green, testmap P1
reconciled, OQ3 unaffected (no new schemas in P1 — verify), coverage
floor unchanged-or-better). KNOWN_DIVERGENCES grows with any new rows.
Commit.
- [ ] Step 1: run everything, capture evidence
- [ ] Step 2: write the report, mark PASS/FAIL
- [ ] Step 3: commit
