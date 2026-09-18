# Task 8 report — snapshot re-pin summarizes exclusions

- **Plan:** `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` §Task 8 (lines 249-252)
- **BASE:** `dae1c42f9613086d1dbd52d3d96c7294d257a6cd` (Task 7 commit, "brief next-actions are copyable webv2 commands")
- **Worktree:** `.worktrees/production-readiness` (branch unchanged; nothing pushed or merged)
- **Status:** implementation complete, all gates green, committed.

## Law under test (verbatim from the plan)

> **Law:** exclusion lists render as `N paths excluded (first 10): …` with N exact; full list
> available in the record object, not stdout.
> **Test:** fixture with >20 pruned paths → output lines bounded, count exact.

## 1. What the interrupted implementer left (measured, not assumed)

Uncommitted at hand-off (`git status --short`: `M internal/cli/cmd_snap.go`, `?? internal/cli/cmd_snap_exclusions_test.go`):

| Artifact | State at hand-off |
| --- | --- |
| `internal/cli/cmd_snap.go` | `+27/-2` — `const excludedInlineCap = 10`; `runSnap`'s EXCLUDED block branches `> cap` (exact count + first 10 + exact remainder + pointer to `source.excluded`) vs `<= cap` (whole list inline, pre-change text preserved); comments cite Task 8 |
| `internal/cli/cmd_snap_exclusions_test.go` | new, 200 lines, 2 tests: `TestSnapRepinSummarizesExclusionsOverCap` (25 pruned paths; bounded line, 10 inline, no tail, one stdout row, re-pin idempotence, full list in `source.excluded`, in the `snapshot.excluded` event, and in `--dry-run --json` `pruned_paths`) and `TestSnapRepinKeepsSmallExclusionListsInline` (4 paths inline). Reuses `pruneOverflowDirs` / `snapDryRunJSONDoc` from `cmd_snap_dryrun_test.go`; no production helper added |
| `.scratch/sdd/task-8-logs/` | `red-focused.txt` (01:56:37), `red-verbose.txt` (01:56:41), `vet.txt` (**0 bytes**), `focused-packages.txt` (01:57:32), `green-focused.txt` (01:58:10), `full-test.txt` (01:59:34), `golden.txt` (01:59:47), `runbook.txt` (02:00:53) — all green except the deliberate reds |
| **Missing** | no commit, no report, no `task-8-brief.md`, no red evidence for the *final* test revision, `vet.txt` records no exit code, and the law's `<= 10` clause is untested at the boundary |

`cmd_snap.go` mtime is 01:56:54 — **after** the red logs (01:56:37/41) and **before** the green
logs — so the interrupted agent's red→green ordering is credible. The test file's mtime is
01:58:05, i.e. the test was edited between the red run and the green run: the old red log cites
`cmd_snap_exclusions_test.go:92`, while in the handed-over file the failing `t.Fatalf` sits at
line 93. Same assertion, different revision — which is why §3 re-establishes red against the
current revision rather than resting on the inherited log.

**No production-code gap was found.** I checked the hunk against the law and against the
recording path: `internal/snapshot/pin.go:471` writes `source.excluded` from the uncapped
`prunedPaths` slice, and `pin.go:499` logs the same names in `snapshot.excluded`; `runSnap`
renders `source.excluded` only after `--json` is refused on the mutating path
(`cmd_snap.go:68-70`), so the summary line can never land in a machine-readable stream.
`excludedInlineCap` is used exactly once.

## 2. What I changed (smallest change: tests only)

The interrupted agent's production hunk was correct and is **byte-identical to hand-off**
(`md5 541b9f04667873e2de12d1c2f48bec8d` before all my experiments and after the mutation check
in §3). I changed **no production code**. Two test-only gap closures in
`internal/cli/cmd_snap_exclusions_test.go` (200 → 236 lines):

1. **Exact remainder pinned.** The over-cap summary claims "N exact" and then hides part of the
   list; the inherited test pinned the visible 10 and the absent tail but not the hidden count.
   Added `strings.Contains(out, "(+15 more")` for the first pin and the re-pin (25 pruned − 10
   named = 15). A wrong `len(names)-cap` arithmetic now fails.
2. **The `<= 10` boundary is now tested.** `TestSnapRepinKeepsExclusionCapBoundaryInline` (exactly
   10 pruned paths) asserts no summary pointer, no "more —" text, all 10 paths inline. This is
   the clause "at or under the cap the list is printed whole"; it was previously covered only at
   4 paths, so a `>` → `>=` regression (which would print `10 paths excluded (first 10): … (+0
   more)`) would have shipped silently. §3 shows the mutant is caught.

Nothing else was touched: no pins, no docs, no scripts (see §6, §7).

## 3. Red / green evidence

**Inherited red (usable, with the caveat above).** `.scratch/sdd/task-8-logs/red-focused.txt` and
`red-verbose.txt` show `TestSnapRepinSummarizesExclusionsOverCap` failing on the pre-change code
with the whole 25-path list dumped on one console line (and the small-list test already passing) —
the exact defect the law names. Caveat: produced against a one-line-earlier test revision.

**My independent red, current revision** (`.scratch/sdd/task-8-logs/red-reproduced-mine.txt`):
`git stash push -- internal/cli/cmd_snap.go` (untracked test kept), then

```
GOCACHE=$PWD/.scratch/gocache go test ./internal/cli -run 'TestSnapRepin' -count=1 -v
--- FAIL: TestSnapRepinSummarizesExclusionsOverCap (0.01s)
    cmd_snap_exclusions_test.go:93: missing the bounded exclusion summary (want N=25 exact):
      … EXCLUDED from the pin (bulk defaults + --exclude): d01/build, … d25/build — …
--- PASS: TestSnapRepinKeepsSmallExclusionListsInline (0.00s)
FAIL  websec/internal/cli  0.021s   [exit 1]
```

`git stash pop` restored the fix and `md5sum -c` confirmed `541b9f04…` unchanged.

**Mutation check for the new boundary test** (proves it is not vacuous): temporarily
`if len(names) >= excludedInlineCap {` → `TestSnapRepinKeepsExclusionCapBoundaryInline` FAILS
("exactly 10 paths must stay inline, not summarized: … 10 paths excluded (first 10): … (+0
more …)"); source restored and md5-verified identical. Command and output are in §5.

**Green, current revision** (`.scratch/sdd/task-8-logs/green-focused-verbose-mine.txt`):

```
--- PASS: TestSnapRepinSummarizesExclusionsOverCap (0.02s)
--- PASS: TestSnapRepinKeepsSmallExclusionListsInline (0.00s)
--- PASS: TestSnapRepinKeepsExclusionCapBoundaryInline (0.00s)
ok  websec/internal/cli  0.031s
```

## 4. Law conformance, clause by clause

| Law clause | Evidence |
| --- | --- |
| `N paths excluded (first 10): …`, **N exact** | `cmd_snap.go:180-188` prints `len(names)` (the count of string entries of `source.excluded`) and the literal `first %d` from `excludedInlineCap = 10`. Test asserts the substring `25 paths excluded (first 10):` and, after my change, the exact hidden remainder `(+15 more`. |
| …with the **list bounded** | Test asserts exactly 10 `/build` occurrences, first-10 membership `d01..d10`, `d25/build` absent, and that the paths occupy exactly **one** stdout row. |
| **Full list in the record object**, not stdout | `pin.go:471` writes `source.excluded` from the uncapped `prunedPaths`; `pin.go:499` logs `snapshot.excluded` with the same names. The test reads both back and requires all 25 in order (`snapExcludedFromRecord`, `snapExcludedEventNames`). The `--dry-run --json` preview keeps `pruned_paths` complete (`cmd_snap.go:258`) — also asserted. |
| **`<= 10` paths inline as today** | `cmd_snap.go:188-193` reproduces the pre-change format byte-for-byte (`git diff` shows the old single `Fprintf` text preserved in the `else`). Cover: 4 paths (inherited) and exactly 10 (added, §2.2), no summary pointer in either. |
| Machine-readable streams unpoisoned | `cmd_snap.go:68-70` refuses `--json` on the mutating pin, so the human summary cannot reach a JSON consumer; the only JSON path is the untouched dry-run preview. |
| Scope of "exclusion list" | Deliberately `runSnap` only. `snap --dry-run`'s pruned-path dump keeps its pre-existing **40**-row console cap + `--json` pointer from Task 7a (`consoleRowCap`, `cmd_probes.go:30`), pinned by the committed `TestSnapDryRunCapsPrunedPaths`. That path has no record object to point at, so the Task 8 law does not apply to it; changing it here would have rewritten a committed test and broken the dry-run's own documented contract. |

**Re-pin, not only first pin.** `runSnap` renders from the snapshot record every run, so the
second (noop) pin of the same target prints the same bounded summary; the test asserts that,
and that the last `snapshot.excluded` event still carries all 25 names.

## 5. Gates (fresh runs, this session)

The interrupted agent's original logs are **preserved untouched**; my runs are the
`*-finish.txt` files (headers carry `date -Is`, every file ends with an explicit `[exit N]` so an
empty log cannot be mistaken for a pass — the hand-off's `vet.txt` was 0 bytes with no exit code).

| Gate | Command | Result | Log |
| --- | --- | --- | --- |
| focused (required) | `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli ./internal/snapshot -count=1` | `ok websec/internal/cli 28.841s` / `ok websec/internal/snapshot 0.165s` — **exit 0** | `focused-finish.txt` |
| targeted | `go test ./internal/cli -run TestSnapRepin -count=1 -v` | 3/3 PASS — **exit 0** | `green-focused-verbose-mine.txt` |
| full suite | `go test ./... -count=1` | **71 ok, 0 FAIL** (`internal/cli 31.055s`, `internal/snapshot 0.506s`) — **exit 0** | `full-test-finish.txt` |
| vet | `go vet ./...` | no findings — **exit 0** | `vet-finish.txt` |
| golden | `bash scripts/golden.sh` | `golden run complete: campaign C-34c0ce6f4b (196 steps, Go-only)` … `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)` — **exit 0** | `golden-finish.txt` |
| runbook | `bash scripts/runbook-walkthrough.sh` | `walkthrough: 150 passed, 0 failed` … `WALKTHROUGH GREEN` — **exit 0** | `runbook-finish.txt` |

Red/negative runs:

```
# independent red, current test revision (fix stashed, untracked test kept)
git stash push -- internal/cli/cmd_snap.go
GOCACHE=$PWD/.scratch/gocache go test ./internal/cli -run 'TestSnapRepin' -count=1 -v   # exit 1
git stash pop && md5sum -c /tmp/snap-md5-before.txt        # cmd_snap.go: OK

# mutation check for the new boundary test: `>` -> `>=` on the cap comparison
sed -i 's/if len(names) > excludedInlineCap {/if len(names) >= excludedInlineCap {/' internal/cli/cmd_snap.go
go test ./internal/cli -run TestSnapRepinKeepsExclusionCapBoundaryInline -count=1        # FAIL (exit 1)
cp /tmp/cmd_snap.go.mutbak internal/cli/cmd_snap.go && md5sum -c /tmp/mut-md5.txt        # OK
```

`gofmt -l internal/cli/cmd_snap.go internal/cli/cmd_snap_exclusions_test.go` → empty.

## 6. Pins: none needed

The console shape changed only for prune sets **over 10 paths**, and no committed pin encodes that
line as text:

- `scripts/golden.sh` → `golden-run.py` + `check-golden.py` validate exit codes, the archived tree,
  the event chain and the audit surface — no stdout transcript of the pin line. Golden green (§5).
- `scripts/runbook-walkthrough.sh:213` checks `snap` with `check snap ok "toolchain:|EXCLUDED from the
  pin"` — a **substring** shared by both branches, so the walkthrough stays green without an edit.
- `assets/runbook/RUNBOOK.md:239` describes "an `EXCLUDED from the pin` console line" — still true.
- `internal/cli/cli_test.go:311,333` assert the same prefix and the excluded name — both branches
  satisfy them.

Therefore `git status` carries no pin-file changes, and I deliberately did not touch RUNBOOK prose:
documenting the cap in the runbook belongs to the plan's Task 15 docs wave (the ledger already
routes prose reconciliation there), and the finish brief scopes this commit to the two code files
plus pins only. **No pin was updated because none needed updating; this is a decision, not an
omission.**

## 7. `scripts/legacy` untouched

- `git diff HEAD -- scripts/legacy` → empty (`git diff --quiet` exits 0).
- Committed tree `git rev-parse HEAD:scripts/legacy` → `f62c95c0a947f94e15328ee0d08fc1b70ab31ec6`,
  matching the `f62c95c0` tree hash recorded in the Task 4A ledger line for the same directory.
- `git status --short scripts/` → empty.
- Whole-worktree `git status --short` at commit time lists only the two Task 8 files.

## 8. Concerns and residual risk (for the reviewer)

1. **Two caps for one concept (10 vs 40).** The pin line hides past 10 paths; the `snap
   --dry-run` preview hides past 40 rows. Both are bounded, documented in code, and pinned by
   their own tests, but a reviewer may want a ruling on unifying them. I left the dry-run alone
   because its 40-row form is a committed Task 7a contract and the Task 8 law speaks of the
   *record object*, which the dry run does not have. Flagging, not fixing.
2. **The cap is not documented in the RUNBOOK.** `assets/runbook/RUNBOOK.md:239` still describes
   the line only by its prefix. Accurate, but incompletely informative; documenting the summary
   belongs to Task 15's docs wave (and the finish brief scopes this commit to code + pins).
3. **Inherited red evidence needed replacing.** The hand-off's red log cites test line 92 while
   the handed-over test fails at line 93, i.e. it was taken against an earlier revision of the
   test file. I did not treat it as sufficient; §3 re-derives red against the committed revision.
   The inherited `vet.txt` is 0 bytes with no exit code — also superseded, not trusted.
4. **The event assertion could go vacuous later.** `snapExcludedEventNames` takes the *last*
   `snapshot.excluded` event; if a future change stopped logging a scope event on a noop re-pin,
   the assertion would silently read the first pin's event. The independent
   `source.excluded` record assertion keeps the test meaningful today; hardening the event half
   (count the events, require 2) is a follow-up, deliberately not done here to keep the change
   minimal.
5. **Only `runSnap` renders `source.excluded`** — verified by search: `cmd_snap.go:166` is the
   sole consumer of that key (other `"excluded"` hits in the tree are unrelated booleans/statuses
   in trajectory/metrics/coverage, and `internal/audit/sections/snapshots.go` only says
   `snapshot.json` is excluded from hashing). So the law's scope is exhausted by this one site.
6. **No `-race` run.** This change is pure string formatting on a value already read from the
   record; no shared state, no new goroutine. The focused/full suites ran without `-race`, as the
   finish brief specified.

## 9. Commit

- `bd14d44b73ead9b04312a59c37b0ad5f9c1076eb` — `fix(snapshot): summarize re-pin exclusions with exact count`
- 2 files: `internal/cli/cmd_snap.go` (+27/−2, the interrupted implementer's hunk, unchanged),
  `internal/cli/cmd_snap_exclusions_test.go` (new, 236 lines). No pin files, no docs, no scripts.
- Working tree clean afterwards; nothing pushed, merged, or delegated.
- `.scratch/sdd/progress.md` intentionally left to the orchestrator to update.
