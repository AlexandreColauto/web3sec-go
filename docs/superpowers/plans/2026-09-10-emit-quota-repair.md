# Plan: the audit's repair command must repair

Status: ready to execute
Date: 2026-09-10
Origin: the final whole-branch review of the P0 batch
(`docs/superpowers/plans/2026-09-10-p0-review-consumption.md`), minor finding 2,
and the D1 residual recorded in `docs/feedback-triage.md`.

## Why

The `[probe_surface]` drift section of `audit` tells the operator to repair the
artifact by running:

    webv2 probes <campaign> run --emit

Two things are wrong with that instruction.

1. **It names a command that makes the artifact worse.** A bare `probes run`
   builds with the compiled-in defaults (`per_axis 12`, `total 40`, see
   `internal/cli/cmd_probes.go:121`), while `audit` re-derives the surface with
   the quotas the artifact itself records (`internal/probes/audit.go:133-135`).
   On the operator's campaign C-21dd6a7642 the artifact records
   `per_axis 30, total 70` (70 rows); the bare re-run rebuilds 40 rows, drops
   30 of them and leaves **34** `[probe_surface]` problems where the pre-emit
   artifact had **24** — following the tool's own advice costs the operator ten
   more problems and 34 orphaned plan priorities. Run with the artifact's own
   quotas it leaves **8**.

2. **One hint is not even copy-pasteable.** The plan-priority-orphan hint
   (`internal/probes/audit.go:73-77`) prints the literal `<campaign>` where it
   means the campaign id.

The `[probe_surface]` repair is the single most-used recovery path in the
framework — it is what an operator runs when the surface and the tree have
drifted apart — and it currently redefines the surface instead of repairing it.
Fixing this closes the last actionable item the final review left open.

## What "repair" must mean

A `probes run` that did not receive an explicit `--per-axis` / `--total` must
rebuild the surface the campaign already has, not a smaller one. The rule is
per flag, and each flag falls back independently:

1. the flag was passed explicitly → use it;
2. else the existing `artifacts/probe_surface.json` records the value → use it;
3. else the compiled-in default (`--per-axis 12`, `--total 40`).

The source of each effective value is printed, so the operator can see the run
was a repair rather than a rebuild. This is what makes the audit hint correct
again: the hint keeps naming `run --emit`, and that command now repairs.

## Global Constraints

1. **Determinism.** The effective quotas are a pure function of (flags, the
   artifact's recorded knobs, the compiled-in defaults). No clocks, RNG, or
   map-iteration order anywhere in the new output.
2. **No gate weakening.** The audit's problem *set* must be unchanged by this
   plan: same problems, same order, same counts for the same inputs. Only hint
   *text* changes, and only where it is wrong today. Nothing that fails may
   start passing.
3. **Frozen assets.** Do not edit anything under `assets/` (the manifest pins
   its hashes). If `assets/runbook/RUNBOOK.md` documents the old default, note
   it in the doc task instead of editing it.
4. **CLI surface.** No new flags, no new verbs. `--per-axis` and `--total` keep
   their names and their validation; what changes is only what "not passed"
   means when a surface already exists.
5. **Tests.** Table-driven, next to the code, at least two assertions per test
   function. New tests must fail on the pre-fix code. `go build ./...` must
   pass, `gofmt -l` must be clean, and focused package tests must be green.
6. **Commits.** Prose subjects, no `feat:`/`fix:` prefix. The body says what
   changed, why, and names the reproduction. Stage files explicitly; never
   `--no-verify`. One logical change per commit.
7. **Untouchable.** Nothing under `.scratch/` (except a `GOCACHE` directory),
   nothing under `/home/xand/Projects/dsh-plugins/websec2/morph/`, no file
   outside this repo. Do not run `scripts/verify-full.sh` — the plan runs it
   once at the end.

## Task 1 — `probes run` repairs the surface it already has

Files:

- `internal/cli/cmd_probes.go` — `probesArgs` (line ~85), the parser
  (`parseProbesRun`, line ~169), the default construction (line ~121), the help
  constants (lines ~42-55), and `probesRun` (line ~289).
- `internal/probes/campaign.go` — reuse `CampaignSurface` (line ~42) to read the
  existing artifact; add a small exported helper for the recorded quotas only
  if the CLI cannot read them cleanly on its own.
- `internal/cli/cmd_probes_test.go` — tests.

Requirements:

1. Track whether each quota flag was passed (`perAxisSet`, `totalSet` or an
   equivalent), so an explicit `--per-axis 12` is respected even though 12 is
   also the default. Do not use 0 as the "unset" sentinel: `--per-axis 0` must
   keep failing validation exactly as it does now.
2. When a flag was not passed and `artifacts/probe_surface.json` exists and
   records that knob as an integer, use the recorded value. A recorded value
   that fails `ValidateKnobs` is an error naming the artifact and the value —
   loud, never silently ignored.
3. A missing or unreadable artifact behaves exactly as today: compiled-in
   defaults. (An unreadable artifact already raises through
   `probes.CampaignSurface`; keep that.)
4. Print the provenance of the effective quotas on the surface line, keeping
   the existing line's shape and the campaign's existing wrap. For example:
   `probe surface: 70 rows emitted (70 ranked, 12 sites) — index_sha 1a2b3c4d5e6f`
   followed by a line naming the quotas and where they came from, e.g.
   `quotas: --per-axis 30 --total 70 (recorded in probe_surface.json)` or
   `quotas: --per-axis 12 --total 40 (defaults; no surface artifact)`.
   Exact wording is the implementer's call; the two facts — the effective
   numbers and their source — are not.
5. The `run --help` text (`t29ProbesRunHelp`) states the rule in one line, in
   the file's existing voice and wrap, and the argparse-parity test that pins
   the help block moves with it.
6. `probes run` without `--emit` follows the same rule — it writes the
   artifact too, so it must not shrink it either.

Tests (red first):

- explicit flags win over recorded quotas;
- no flags + a surface recording 30/70 → the rebuild uses 30/70 (assert the
  written artifact's `per_axis`/`total` and its row count);
- one flag passed, the other not → the other falls back to the recorded value;
- no artifact → defaults 12/40;
- a recorded knob that is invalid (e.g. 0) → error naming the artifact, and
  nothing written;
- `--per-axis 0` on the command line still errors as it does today.

Verification: focused `go test ./internal/cli/ ./internal/probes/`, plus
`go build ./...` and `gofmt -l`.

## Task 2 — the audit hints name the command that actually repairs

Files:

- `internal/probes/audit.go` — the five hint sites (lines ~43, ~75, ~84, ~91,
  and the shared `rerun` string at line ~171).
- `internal/probes/audit_test.go` (or the existing audit-focused test file) —
  tests.

Requirements:

1. The `<campaign>` placeholder at line ~75 becomes the real campaign id, like
   every other hint in the function. That hint must be copy-pasteable.
2. Where the artifact records quotas, the hint names them, so the operator can
   see what the repair will rebuild — e.g.
   `re-run \`webv2 probes C-xxxx run --emit\` (rebuilds with the surface's
   recorded --per-axis 30 --total 70)`. Where the artifact records none, the
   hint stays in its plain form. Because Task 1 makes the bare command adopt the
   recorded quotas, the hint must not tell the operator to pass flags by hand;
   naming the numbers is information, not an instruction.
3. The problem set is untouched: same conditions, same strings except the hint
   text, same order, same count. Re-derivation knobs (`audit.go:133-135`) keep
   using the artifact's recorded values with the same 12/40 fallback.

Tests (red first):

- an artifact that records 30/70 and drifts → its problem strings name
  `--per-axis 30 --total 70`, and no problem string carries `<campaign>`;
- an artifact with no recorded knobs → the plain hint, no quota clause;
- the plan-priority-orphan hint names the campaign id;
- the problem count and order for a pinned fixture are unchanged by this task
  (pin the list, not just the length).

Verification: focused `go test ./internal/probes/`, plus `go build ./...` and
`gofmt -l`.

## Task 4 — the planner's disposition errors name the campaign too

Added after Task 2, found while implementing it. Task numbering is the order the
tasks were written, not the order they run: **this task runs before Task 3**, so
Task 3's record covers both code changes.

The same placeholder defect lives in two more places, both found by the Task 2
review and the Task 2 implementer:

- `internal/planner/answered.go:221-222` and `:227-228` tell the operator to run
  `` `webv2 probes <campaign> run` `` / `` `--emit` `` with a literal
  `<campaign>`. These are the errors an operator sees while dispositioning a
  probe row — the same moment the audit hints serve — and both are uncopyable.
- `internal/planner/probeview.go:36` falls back to the literal when
  `plan.campaign_id` is empty; `internal/planner/gates.go:293` repeats it. Both
  are reachable for a hand-loaded plan JSON.

Every operator-facing repair hint in the framework must name the campaign.

Files:

- `internal/planner/answered.go` — the two error strings.
- `internal/planner/probeview.go` and, if it repeats the literal,
  `internal/planner/gates.go`.
- the package's test file covering those errors — tests.

Requirements:

1. Both messages use the campaign id they already have in hand, like the rest of
   the framework's operator-facing errors. Nothing else about the messages
   changes: same conditions, same wording otherwise, same error type and exit
   path.
2. No problem set, gate, or artifact changes.

Tests (red first):

- a priority citing a probe row on a campaign with no probe surface, and one
  citing a row the surface does not carry → each error names the campaign id and
  contains no `<campaign>`;
- the surrounding wording is otherwise unchanged (pin it).

Verification: focused `go test ./internal/planner/`, plus `go build ./...` and
`gofmt -l`.

## Task 3 — record the change

Files: `docs/feedback-triage.md` (the `## 2026-09-10 — external review triage
(P0 batch)` section), `docs/IMPROVEMENTS.md` if it documents the emit defaults.

Requirements:

1. Move the "audit's repair hint can make the surface worse" item from the open
   list to the closed list, naming both commits and the reproduction: on a copy
   of C-21dd6a7642, bare `probes run --emit` before this plan prints
   `emit: created 12, updated 28, kept 0, reopened 0, orphaned 34` and the audit
   reports 34 `[probe_surface]` problems; after, it prints
   `emit: created 16, updated 54, kept 0, reopened 0, orphaned 8` and the audit
   reports 8 — matching the surface's own recorded quotas.
2. Update the D1 residual entry if this plan changes what it says (it must not
   silently contradict it).
3. If `docs/IMPROVEMENTS.md` describes the emit quota defaults, update that in
   the same commit. If `assets/runbook/RUNBOOK.md` documents the old bare
   default, record it as a frozen-asset follow-up rather than editing it.

Verification: no code touched; the record's numbers reproduced by the
implementer.

## Acceptance

1. `scripts/verify-full.sh` green, all 13 steps.
2. On a fresh copy of the operator's campaign C-21dd6a7642, with the binary
   built from this plan's head:
   - bare `webv2 probes C-21dd6a7642 run --emit` prints the recorded quotas and
     `orphaned 8`, not `orphaned 34`;
   - `webv2 audit C-21dd6a7642` reports 8 `[probe_surface]` problems, all
     plan-priority drift (Q-253…Q-260), and no problem string contains
     `<campaign>`;
   - the planner's two disposition errors for a missing/absent probe row name
     the campaign id instead of `<campaign>`;
   - an explicit `--per-axis 2 --total 40` still rebuilds exactly what it says.
3. No new flags or verbs; `assets/` untouched; the audit's problem set for a
   pinned fixture is unchanged.
