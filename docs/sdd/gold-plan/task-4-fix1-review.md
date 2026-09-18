# Task 4 fix round 1 review (`99e7e906..e28efeed`)

Read-only scoped re-review. Inputs: `task-4-review.md` (open findings MEDIUM-1, LOW-2, LOW-3;
INFO-4 not actionable), `task-4-report.md` fix appendix, and the diff `99e7e906..e28efeed`
(one commit, `e28efeed`, 2 files, +28/−2). All evidence below was re-derived first-hand in this
session, not taken from the report.

## Verdicts

- **MEDIUM-1 (FP-boundary unpinned) — ADDRESSED.** `FIXTURE_CAMPAIGN_G01_AND_10_FPS`
  (`campaign([g01()] + fps(10))`, built in `setUpModule`) is asserted in
  `test_fp_budget_is_verdict_affecting_at_boundary`: `false_positives == 10` **and**
  `verdict == "PARTIAL_RESULT"` — exactly at budget, which neither 9/11 pins. The budget-5
  prose test gained the mirror assertion (`fps(5)` → `5` → `PARTIAL_RESULT`), keeping 4 and 6.
  The 9/11 cases are unchanged.
- **LOW-2 (dead `INVESTIGATING` branch comment) — ADDRESSED.** `scripts/eval-gold.py` lines
  93–98 now state that `INVESTIGATING` is NOT in the schema's `status` enum, list the real
  statuses, and say the store can never emit it / it is not a live accept path; the module
  docstring's MATCHING paragraph cross-references it ("the latter is dead, see
  POC_STATUSES"). Honesty check: I parsed `assets/schema/finding.schema.json` myself — the
  `status` enum is `HYPOTHESIS, NEEDS_RESEARCH, PROVISIONALLY_VALID, POSSIBLE, CONFIRMED,
  DISPROVED, DUPLICATE, OUT_OF_SCOPE, INFORMATIONAL, CHAIN, SUPERSEDED`; `INVESTIGATING` is
  absent and the comment's list matches the enum verbatim. Comment is accurate; behavior
  unchanged (`POC_STATUSES` value identical).
- **LOW-3 (bonus short-circuit untested) — ADDRESSED.** New
  `test_bonus_short_circuits_the_fp_budget`: G-01 + G-02 both found (G-02 via
  `finding("F-000000000002", "CONFIRMED", G02_FINDING)`, no id collision with `fps()`, which
  uses `F-000000000100+`) plus `fps(10)`; asserts `found`, `false_positives == 10`,
  `bonus is True`, `verdict == "PASS_WITH_BONUS"`, `verdict_note == ""`. Running with
  `--confirm G-01 --confirm G-02` is the right call: the empty note pins the *absence of the
  partial-result note*, not merely the pending-confirmation note, so it genuinely pins the
  short-circuit ordering (bonus branch precedes the budget branch).

## Mutant evidence (reproduced myself)

Report's red-check confirmed exactly:

- Clean suite on a scratch copy: `Ran 26 tests … OK` (was 25; +1 new test).
- Mutated `elif false_positives < budget:` → `elif false_positives <= budget:` in the scratch
  copy: `FAILED (failures=2)` — precisely `test_fp_budget_is_verdict_affecting_at_boundary`
  and `test_fp_budget_boundary_comes_from_the_benchmark_string` (the new at-budget
  assertions). The bonus test does **not** fail under the mutant (the bonus branch precedes
  the budget comparison, as intended), so the failure set is exactly the boundary pair. The
  off-by-one can no longer pass the suite. Tracked files untouched (mutation done on an
  ignored `.scratch` copy; `git status` shows only the pre-existing untracked `.superpowers/`).

## New breakage in the fix diff

**None.** The diff touches only `scripts/eval-gold.py` (comment/docstring lines: the
MATCHING paragraph pointer + the `POC_STATUSES` block; `POC_STATUSES` value and all code
identical) and `scripts/eval_gold_test.py` (new fixture + global, two at-budget assertion
groups, one new test method). No fixture was modified in a way that weakens an existing
assertion, no helper changed, no Go file / plan doc / `verify-full.sh` / legacy fixture
touched, stdlib-only imports unchanged. Suite 26/26 green post-fix.

## Residual (carried, no action required this round)

- INFO-4 (hardcoded `PASS_GOLD_ID`/`BONUS_GOLD_ID`) remains as reviewed — disclosed and
  compliant with the brief; not a fix-round item.
- The keyword quorum's adequacy against real finding prose remains unverifiable offline until
  the first real campaign finding exists (unchanged from round 1).
