# Task 8 review — snapshot re-pin exclusion summary (commit bd14d44b)

Reviewer: independent read-only review (subagent). Date: 2026-09-18.
Scope: commit bd14d44b — `internal/cli/cmd_snap.go`, `internal/cli/cmd_snap_exclusions_test.go`.
Plan: docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md, "Task 8: snapshot re-pin
summarizes exclusions" (law + test lines). Reviewing head: 16b3bc3a.

## Verdicts

- **Spec: YES** — the law is implemented as stated, both clauses.
- **Quality: APPROVED** — no findings. Mutation-verified, record-side verified, no tracked
  changes made by the review.

## Law check (line-by-line)

Law: exclusion lists render as `N paths excluded (first 10): …` with N exact; full list
available in the record object, not stdout. Extended directive: ≤10 paths inline unchanged.

1. **Exact N, first 10 inline** — cmd_snap.go:180-187: when `len(names) > excludedInlineCap`
   (cap = 10, named const with a rationale comment), one line prints
   `%d paths excluded (first %d): <first 10> (+%d more — the full list is in the record's
   source.excluded)`. N = `len(names)` is the true count; the remainder `+%d` is
   `len(names)-cap`, arithmetic pinned by the test ("(+15 more" for 25/10).
2. **Full list in the record, not stdout** — the render reads from
   `source.excluded`, which pin.go:471 writes UNCAPPED, mirrored by the
   `snapshot.excluded` event at pin.go:499 (also uncapped). Verified both sites.
   `--json` is refused on the mutating path (TestSnapJSONRefusesWithoutDryRun, exit 2), so
   the summary line can never reach a machine-readable stream; the dry-run `--json`
   preview keeps the full `pruned_paths` table (asserted 25/25 in the over-cap test).
3. **≤10 inline unchanged** — else-branch (cmd_snap.go:188-193) prints the pre-change
   wording byte-for-byte; boundary test pins EXACTLY 10 as inline (no "paths excluded
   (first", no "more —"). Also verified the small-list (4 paths) test asserts every path
   named, no summary pointer.
4. **Plan test line** — "fixture with >20 pruned paths → output lines bounded, count
   exact": TestSnapRepinSummarizesExclusionsOverCap uses 25 pruned paths, asserts exact
   N=25, exactly the 10 sorted heads inline, tail (d25/build) absent, one stdout line
   carrying paths (rows==1), and re-pin (noop, same id) renders the same bounded summary.
   The order guarantee is real: pin.go `excludedNamesIn` returns `sortedKeys`.

The dry-run preview's separate pre-existing 40-row cap (Task 7a, consoleRowCap) is a
different surface with no record object; leaving it untouched is consistent with the
plan (Task 8 targets the re-pin exclusion line).

## Red→green evidence (verified, not trusted)

- `.scratch/sdd/task-8-logs/red-focused.txt` and `red-reproduced-mine.txt`: the over-cap
  test fails against the unbounded line with the full 25-path dump visible in the log —
  genuine red, correct failing assertion.
- `green-focused.txt` / `focused-finish.txt`: post-change pass, `ok websec/internal/cli`.
- **My own runs** (repo-local Go cache per 0f881e55; harness GOPATH is read-only):
  - HEAD: `go test ./internal/cli -run 'TestSnapRepin|TestSnapDryRun|...' -count=1` → ok.
  - **Cap-boundary mutation check (mine):** changed `>` → `>=` at cmd_snap.go:180 →
    `TestSnapRepinKeepsExclusionCapBoundaryInline` FAILS, printing exactly the predicted
    degenerate form `10 paths excluded (first 10): … (+0 more)`. Restored via git
    checkout; `md5sum` = 541b9f04667873e2de12d1c2f48bec8d, matching the commit message's
    stated digest. This closes the commit's one red-evidence gap: the boundary test has
    no red state against pre-change code (old code also printed 10 inline), so the
    mutation run is the correct form of red for it — the commit message claims it was
    mutation-verified and my independent run confirms.
- `golden.txt` (GOLDEN GREEN, event chain intact) and `runbook.txt` (150 passed, 0 failed)
  present in task-8-logs. Spot-checked the pinned-output claims: `cli_test.go:311` and
  `runbook-walkthrough.sh` both key on the `EXCLUDED from the pin` prefix both branches
  keep — no fixture pins the old unbounded tail.

## Notes (non-blocking, informational only)

- The summary pointer names `source.excluded` but not the `snapshot.excluded` event;
  both carry the full list. Cosmetic; the record key is the durable one.
- The inline-count assertions (`strings.Count(out, "/build")`) could in principle
  over-count if another stdout line contained "/build"; the same test pins rows==1 for
  the exclusion lines, so this is safe in practice.

## Integrity

Review was read-only plus the two declared mutation/restore edits to cmd_snap.go
(reverted, digest-verified). `git status --porcelain internal/` clean after restore.
