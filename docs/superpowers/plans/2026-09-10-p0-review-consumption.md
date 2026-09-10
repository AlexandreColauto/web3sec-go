# P0 Plan — Review Consumption Fixes (D1, D8, D6, D4, D5)

Source: two external reviews of this framework, triaged against HEAD on
2026-09-10 with live reproductions against a copy of the operator's
campaign `C-21dd6a7642` (root `.scratch/morph-eval`, binary
`.scratch/review/lead/webv3`).

- `../morph/webv2-workspace/reviews/webv2-framework-review.md`
- `../morph/webv2-workspace/reviews/eval-retro-gold-findings.md`

Five defects that are still live at HEAD, each with a one-command
reproduction. No new subsystem is introduced and no gate is relaxed.

**Out of scope (the next plan, P1 — the recall/consumption batch):**
provenance on findings (`probe_row_id`), the scoped ranked-coverage gate,
a per-row probe disposition verb, consequence-shaped row rendering,
`link --grants/--needs` (D2), a severity mutation surface (D3), budget
attempt classes (D9), tooling-vs-coverage classification (D7), and
`sequence check`.

## Global Constraints

1. **Determinism.** No new clocks, RNG, or map-iteration order in any
   output. Every new string is derived from campaign state, so the same
   inputs still produce the same bytes.
2. **No gate weakening.** Nothing here may turn a failing or
   human-review clause into a pass. Specifically: D1 is fixed in the
   emitter, *not* by widening
   `assets/schema/probe_surface.schema.json`; D8 changes wording only;
   D6 changes how one metric is computed; D4 adds a command that queues
   a row (the existing human approval step is untouched); D5 changes the
   text of a reason and a help block.
3. **Frozen assets.** Do not edit anything under `assets/` — asset
   digests are pinned by `assets/testdata/asset_manifest.json` and the
   asset tests.
4. **CLI surface.** Exactly one new flag in this plan:
   `memory <campaign> --queue-finding FINDING` (Task 4). No new
   top-level verbs. Changed `--help`/usage text keeps the file's
   existing wrap and voice.
5. **Tests.** Table-driven, next to the code, at least two assertions
   per test function. Each fix's new test must fail on the pre-fix code
   (run it before writing the fix, or `git stash` the fix and re-run).
   `go build ./...`, `gofmt -l` clean, and the focused package tests
   must all pass before reporting DONE.
6. **Commits.** Prose subject, no `feat:`/`fix:` prefix. The body says
   what changed, why, and names the reproduction. Stage files
   explicitly — never `git commit -a`. One logical change per commit.
   Never `--no-verify`.
7. **Untouchable.** Do not modify `.scratch/`, anything under
   `/home/xand/Projects/dsh-plugins/websec2/morph/` (the operator's live
   campaigns and the original review documents — read-only reference),
   or any file outside this repository.

## Acceptance (whole plan)

- `scripts/verify-full.sh` green (13/13).
- Against the campaign copy (root `.scratch/morph-eval`, campaign
  `C-21dd6a7642`), with the freshly built binary:
  - `probes C-21dd6a7642 run --emit` succeeds instead of aborting on
    `custody`, and `audit C-21dd6a7642` then reports zero
    `[probe_surface]` problems;
  - `gate C-21dd6a7642` prints the precise fork blocker (its text
    contains `sequence coverage`), not the bare
    `no proven mainnet fork PoC (the latest required step)`;
  - `report C-21dd6a7642` prints a non-negative precision ratio;
  - `memory C-21dd6a7642 --queue-finding F-6791c9aee0b5 --kind confirmed
    --pattern <text>` queues a row, and `prove C-21dd6a7642` no longer
    lists that finding under `learning`.

## Task 1 — D1: the custody label must be schema-legal

Today the only sanctioned repair for probe-surface drift aborts, so the
24 `[probe_surface]` audit problems on the operator's campaign can never
be cleared.

Reproduction (put it in the commit body):

```
cd .scratch/morph-eval
webv3 --root . probes C-21dd6a7642 run --emit
error: probe_surface validation failed at rows/5/custody: 'transfer-in'
is not one of ['burns', 'mints']
```

Files: `internal/probes/symmetry.go` (`symCustodyLabel` at ~line 590,
its call site at ~line 558), `internal/probes/collapse.go` (`idSlots`,
`RowIDFor`), tests in `internal/probes/`.

Facts to build on (verified at HEAD):

- `symCustodyLabel` maps `mint` → `"mints"`, `burn` → `"burns"`, and
  returns **any other primitive verbatim** (`transfer-in`,
  `transfer-out`, `send-native`, …). The call site writes the result to
  the row's `custody` key unconditionally.
- `assets/schema/probe_surface.schema.json` declares
  `rows[].custody` as `enum ["burns","mints"]` and does **not** list
  `custody` in `rows[].required`, whose exact list is
  `["row_id","probe","axis","lens","tier","rank","assertion_gap","gate",
  "why","siblings"]`. `assets/` is frozen (constraint 3).
- `idSlots` (collapse.go:46) returns four identity slots per probe; for
  `custody-primitive` rows the fourth is `vStr(row, "custody")`, and
  `RowIDFor` hashes `probe|join(slots,"|")` into the row id.
- The divergence row already declares `observed` (symmetry.go ~line 561)
  and `expected`/`observed` ride the extras map, so no information is
  lost by omitting `custody`.

Requirements:

1. Emit the `custody` key **only** when the expected primitive maps to a
   schema value: `mint` → `"mints"`, `burn` → `"burns"`. For every other
   primitive omit the key entirely. Do not invent a synonym, do not widen
   the schema, do not drop or reword the row: `divergence`, `expected`,
   `observed`, the `why` question and the extras map stay exactly as they
   are.
2. Row identity must survive: two rows that were distinct before stay
   distinct. Make `idSlots` fall back to `vStr(row, "observed")` for
   `custody-primitive` rows when `custody` is absent (never an empty
   fourth slot for that probe).
3. Tests, in the package's existing style:
   - a custody-primitive row whose expected primitive is `transfer-in`
     passes the real probe_surface validator (call the same validation
     entry point the emit path uses, so this cannot silently pass through
     a hand-rolled check);
   - a family with two different non-mint/burn primitives in one
     (direction, asset) column yields two different `row_id`s;
   - the mint/burn rows still carry `"mints"`/`"burns"`.
4. Full-surface check: whatever test builds rows today must now build a
   surface that validates end to end. If the package has no fixture that
   reaches this path, add one using the existing
   `internal/probes/testdata/probes/custody/` layout.

Evidence for the report: the new test failing before the fix, passing
after; `go test ./internal/probes/... ./internal/cli/...`; `gofmt -l`
clean.

## Task 2 — D8: the gate blocker must carry the precise reason

`gate` tells the operator less than `prove` already knows: the blocker is
a constant string while the same check holds the exact status.

Reproduction:

```
cd .scratch/morph-eval
webv3 --root . gate C-21dd6a7642
F-6791c9aee0b5: eligible=True submission_ready=False
  blocker: no proven mainnet fork PoC (the latest required step)
```

…while `prove C-21dd6a7642` says, for the same finding: `fork-level
evidence exists but no fork-runner exec has verified sequence coverage —
run a T4 sequence PoC (webv2 sequence run); a single-call fork PoC cannot
prove this multi-step exploit`.

Files: `internal/bounty/bounty.go` (`check11`, ~lines 1027-1056), tests
in `internal/bounty/`.

Requirements:

1. `check11` already computes `ok, why, err := forkPocStatusFunc(...)`.
   On failure, the appended blocker becomes `"no proven mainnet fork
   PoC: " + why` when `why != ""`, and stays the current constant text
   when `why` is empty. The check row itself keeps
   `g.add("mainnet-fork-poc", "fail", why, "")` — only the blocker text
   changes.
2. Keep one source of truth for the fallback constant: grep for
   `latest required step` and leave exactly one occurrence (the
   fallback), updating any test that asserts the old string.
3. Tests: a finding with fork-level evidence but no verified sequence
   coverage produces a blocker containing the `why` text verbatim; a
   finding with no fork evidence at all still produces a blocker and a
   `fail` row (never `pass`); the waived path is unchanged.
4. `gate --explain mainnet-fork-poc` output is unaffected.

## Task 3 — D6: the precision metric must not go negative

The report prints a self-contradicting metric: a negative
false-positive ratio.

Reproduction: `cd .scratch/morph-eval && webv3 --root . report
C-21dd6a7642`, then `grep precision campaigns/C-21dd6a7642/report.md`:

```
- **precision:** critic-confirmed: 4  - evidence-confirmed: 5  - false-positive ratio: -25.0%
```

Files: `internal/report/report.go` (the precision block, ~lines 354-393),
tests in `internal/report/`.

Facts to build on: the loop counts `criticN` as live findings whose
critic verdict is `confirmed`, and `evidenceN` as live findings with
`findings.EvidenceDeficit(f, "CONFIRMED", campaign) == nil`. Those are
different sets, so `(criticN-evidenceN)/criticN` is negative whenever
the second count exceeds the first (the campaign's exact shape: 4 vs 5).

Requirements:

1. Compute the quantity the label names — among the **critic-confirmed**
   live findings, the share that fails the evidence floor. Count
   `criticNoEvidenceN` as critic-confirmed **and**
   `findings.EvidenceDeficit(f, "CONFIRMED", campaign) != nil` in the
   same loop, and print
   `false-positive ratio: <criticNoEvidenceN>/<criticN>` as a percentage
   with one decimal (`%.1f%%`).
2. `criticN == 0` prints exactly `n/a (no critic-confirmed findings)`.
   The existing `critic-confirmed: N  - evidence-confirmed: M` text and
   the line prefix `- **precision:** ` keep their exact form, including
   the two-space-dash separator.
3. The ratio is never negative. Add a test with the campaign's shape
   (more evidence-confirmed than critic-confirmed) asserting the
   rendered line contains no `-` immediately before a digit in the ratio
   field, plus a test for the `criticN == 0` text.
4. Grep for `false-positive ratio` across the repo (tests, golden
   expectations, docs) and update every place that pins the old string
   or the old arithmetic.

## Task 4 — D4: a command that queues the memory row a terminal finding needs

`prove` demands a memory row per terminal finding, but nothing creates
one for a finding that never went through a ladder rung: the only
production caller of `learning.QueueMemory` is the ladder-disprove wire
in `internal/cli/cmd_t28_wire.go`.

Reproduction:

```
cd .scratch/morph-eval
webv3 --root . prove C-21dd6a7642 | grep '^learning'
learning  open  [authoritative] — F-6791c9aee0b5: no memory entry for this
terminal finding (learning.queue_memory); F-f010ea83b6ba: …; F-94e10538419b: …
```

Files: `internal/cli/cmd_memory.go`, a test alongside it
(`internal/cli/cmd_memory_learn_test.go` exists — follow its fixtures).

Facts to build on: `proofLearning` (`internal/completion/proofs2.go:261`)
counts a terminal finding as satisfied when some `MEM-*.json` in the
campaign's memory dir carries `finding_id` equal to that finding's id.
`learning.QueueMemory` takes `QueueOpts{Kind, Status, Pattern,
FindingID, BugClass, …}`; `learning.MEMORY_STATUSES` is
`["CONFIRMED","DISPROVED","DUPLICATE","OUT_OF_SCOPE","INTENDED_BEHAVIOR",
"UNREACHABLE","NON-ECONOMIC","TEST-HARNESS-ONLY"]` and
`learning.MemoryKinds` is `["confirmed","disproved","detector",
"benchmark","reflection","drift","regression"]`.

Requirements:

1. Add exactly three flags to the existing `memory` verb: `--queue-finding
   FINDING`, `--kind KIND`, `--pattern TEXT`. Usage/help text gains these
   three lines in the file's existing style and wrap; nothing else on the
   verb changes.
2. Behaviour: load the finding with the package's usual loader; require
   its `status` to be a member of `learning.MEMORY_STATUSES` (error text
   names the allowed values when it is not); call `learning.QueueMemory`
   with `Status` = the finding's status, `Kind` = `--kind` when given else
   `confirmed` for `CONFIRMED` / `disproved` for `DISPROVED` (any other
   status without `--kind` is an error naming `learning.MemoryKinds`),
   `Pattern` = `--pattern` when given else the finding's `title` when
   present, and `FindingID` = the finding id, plus `BugClass` from the
   finding when it has one. Do not re-implement QueueMemory's validation —
   call it and let its errors surface.
3. Output: one line naming the queued memory id, the finding, and the
   status, followed by the approval command in the verb's existing voice,
   e.g. `MEM-xxxx queued for F-… (CONFIRMED) — approve with: webv2 memory
   <campaign> --approve MEM-xxxx --by NAME`. Exit non-zero and write
   nothing on error. Queueing twice queues two rows (rows are
   append-only); no dedup logic.
4. Tests: a confirmed finding with no memory row gains one with
   `finding_id` and `status` set, and the `learning` completion proof
   flips from open to satisfied for it (drive `completion` the way the
   existing tests do); a status outside `MEMORY_STATUSES` errors and
   leaves the memory dir unchanged; omitting `--kind` for a `DISPROVED`
   finding derives `disproved`.
5. The human approval step is untouched: the row is queued, not
   approved, and `--approve` behaviour does not change.

## Task 5 — D5: name the actors the sequence PoC is missing, and document the rule

A coverage failure reports two counts and no names, and `sequence run`'s
help never mentions that coverage is checked at all — so the operator
learns the rule only by failing it.

Files: `internal/sequencepoc/run.go` (`coverageReasons`, ~lines 301-345),
`internal/cli/cmd_sequence.go` (the `run` help/usage text), tests in
`internal/sequencepoc/`.

Facts to build on: coverage compares `actorSet(declared)` against
`actorSet(executed)` (run.go:395), where each set holds the `actor`
strings of the finding's declared `exploit_sequence` steps and of the
executed result's steps. The reason today reads:
`executed steps use %d distinct actor(s) but the declared exploit needs
%d — a single-account PoC cannot cover a multi-actor exploit`.

Requirements:

1. Append the missing names to that reason: the actor labels present in
   `actorSet(declared)` and absent from `actorSet(executed)`, sorted,
   joined with `, `, appended after the existing sentence as
   `; missing: a, b`. Keep the existing prefix, counts and wording
   byte-identical so tests matching the prefix keep passing. When
   nothing is missing (the sets are equal) the reason is not emitted at
   all, as today.
2. The declared actors are compared as the finding writes them (the
   comparison is over the same keys `actorSet` builds) — do not
   normalise, lowercase or strip prose like `(or protocol)`.
3. `sequence run --help` gains one line stating the rule, wrapped like
   its neighbours, e.g.: `coverage: the executed steps must use every
   actor the finding's exploit_sequence declares — a declared role that
   sends no transaction still counts until that sequence drops it`.
   If the usage string is separate, it stays unchanged except for the
   line count.
4. Tests: a declared two-actor sequence executed by one actor yields a
   reason containing the missing actor's exact label; the same sequence
   with both actors present yields no actor reason; an executed result
   with a superset of actors yields no actor reason.

## Task 6 — Record what landed and what is still open

The repo keeps its open review items in `docs/feedback-triage.md`, and
the external reviews' remaining asks must not be silently dropped when
this batch merges.

Files: `docs/feedback-triage.md` (docs only, no code).

Requirements:

1. Append a section `## 2026-09-10 — external review triage (P0 batch)`
   in the file's existing item style (item, status, evidence,
   recommendation), covering:
   - **Closed by this batch** — D1 custody label, D8 gate blocker
     wording, D6 report precision, D4 memory queue command, D5 coverage
     reason + help. For each: the commit hash (`git log --oneline`
     subjects, no need to re-derive), the one-line reproduction that
     used to fail, and what now proves it fixed.
   - **Still open, with the reason each is deferred** — D2 (the
     capability graph has no writer, so `grants`/`needs` can be read but
     never recorded), D3 (the severity floor has no mutation surface;
     `blast_radius` and `require_invariant_violation` are read by the
     policy rules and written by nothing), D7 (a tooling failure and a
     genuine coverage failure produce the same reason), D9 (budget has
     no attempt classes, so an unreachable RPC burns a repro attempt).
   - **The eval-retro consumption batch** — provenance (`probe_row_id`
     on findings), a scoped ranked-coverage gate consumed by the bounty
     gate, a per-row probe disposition verb, and consequence-shaped row
     rendering; one line each on why they matter and what they cost.
   - **One correction to the external review**, stated as the evidence
     shows it: the eval retro's premise that every authoritative stage
     was green does not match `prove` on `C-21dd6a7642`, which prints
     `discovery open [authoritative]` naming Q-001/Q-143/Q-144. The real
     gap is that the bounty gate never consumes coverage, that the
     `discovery` bar is all 261 priorities, and that `brief` renders the
     probe surface as a bare count.
2. Quote the current reproduction output where it is short, exactly as
   the file's other sections do.
3. Run `scripts/verify-full.sh` after this task and report 13/13 in the
   task report.
