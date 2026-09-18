# Task 6 report — `index` emits a registry refresh event when it rewrites artifact bytes

**Status:** DONE (production change + tests; no plan-premise correction needed —
the index command DOES rewrite a registered artifact, every run)
**Commit:** `f837a26a` — `fix(cli): index emits registry refresh events for rewritten artifacts`
**Branch/worktree:** `production-readiness` @
`/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
**Base:** `f13ae1df` (Task 16)
**Files changed:**
`internal/cli/cmd_index.go` (+17/-3), `internal/state/artifacts.go` (+75/-0),
`internal/structidx/index.go` (+38/-0), plus two new test files
(`internal/cli/cmd_index_refresh_test.go`,
`internal/state/artifacts_refresh_if_changed_test.go`).

---

## 1. The brief, verbatim (plan Task 6 + Phase B preamble)

> **Files:** the `index` command handler; `internal/state/artifacts.go` if a
> shared refresh helper is needed.
> **Law:** any artifact whose bytes the command changed gets a registry row
> update + `artifact.refreshed` event in the same lock window (rawState/unwind
> law applies). Audit section for artifacts must render the refreshed rows
> without a new section.
> **Test:** run `index` on a fixture whose index rewrite touches a registered
> file → event present, hash updated, audit clean; run on an unchanged tree →
> zero events. Plus one concurrency test: `TestIndexConcurrentRefresh` runs 10
> goroutines driving `index` over overlapping trees — the lock window must hold
> (no duplicate `artifact.refreshed` events for one rewrite, no deadlocked
> ledger, `-race` clean).

Handler located exactly as the brief said: `rg -n "func runIndex|cmd_index"
internal/cli` → `internal/cli/cmd_index.go:18` (`runIndex`), registered at
`cmd_index.go:141` (`ord: 15`).

## 2. What the command actually writes (the premise check the brief demanded)

`index` writes exactly ONE file: `artifacts/structural_index.json`, via
`structidx.SaveIndex` → `validation.WriteJson` (`internal/structidx/index.go`).
Nothing else in the handler touches the disk (`IndexSnapshot` is a read of the
`--src` tree plus the campaign's pin). That file is registered by the handler
itself since r11 (`RegisterOrRefresh("structural-index", …)`, cmd_index.go:58
at base) — so the law DOES have a subject: a registered artifact whose bytes
the command rewrites on every run. No premise correction is needed (unlike
Task 5).

But the pre-existing shape violated the law in two measurable ways, both
reproduced before the fix (`.scratch/sdd/task-6-logs/red-focused.txt`):

1. **The bytes were written OUTSIDE the lock window.** `SaveIndex` ran, and
   only then did `RegisterOrRefresh` take the campaign lock. Ten concurrent
   rebuilds of one changed tree therefore emitted **10** `artifact.refreshed`
   events for **one** rewrite (and the `old_sha256`/`new_sha256` pairs could
   interleave across goroutines — a row re-hash of somebody else's bytes).
2. **The build clock made every rebuild look like a change.** `created_at` is
   stamped by `IndexSnapshot` on every run, so an unchanged tree still produced
   different bytes and a refresh event: two `index` runs on an unchanged tree
   appended **2** events (red log, `TestIndexUnchangedTreeEmitsNoEvents`).

The codebase already declares `created_at` non-semantic: `structidx.TreeFacts`
strips `campaign_id`, `snapshot_id` and `created_at` precisely so that "the same
tree indexed twice, in two campaigns, at two times, must hash equal"
(`internal/structidx/indexsha.go:17-23`). Task 6's "unchanged tree → zero
events" is that same doctrine applied to the registry.

## 3. The fix (three pieces, no new mechanism)

1. `structidx.SaveIndexIfChanged` (+ `SameIndexContent`, `requireValidIndex`) —
   the rebuild validates the new index exactly as before, then writes the bytes
   ONLY when they differ from the index on disk modulo the build clock. Missing
   / unreadable / tampered files always differ, so the rebuild still heals them.
   `SaveIndex` keeps its old unconditional semantics for the orchestrator seam.
2. `state.RegisterOrRefreshIfChanged` (+ unexported `artifactRowCurrent`) — the
   shared refresh helper the plan allowed for. It reuses
   `RegisterOrRefreshKeptGhosts` (same resolved-path key, same "latest row"
   tie-break, same D3 kind migration, same r16 save-then-log unwind inside
   `refreshArtifact`/`RegisterArtifact`) and adds exactly one condition: when
   the row RegisterOrRefresh would have refreshed already pins the bytes on
   disk (sha256 equal AND kind equal), it does **nothing** — no row write, no
   event. `RegisterOrRefresh` itself is untouched, so the r12 pin ("a hash-equal
   refresh DOES log an event" for the explicit operator verbs) still holds.
3. `runIndex` takes the campaign lock for the whole window and calls the two
   above inside it. This is the house pattern for a multi-step unit
   (`internal/planner/plan.go`, `internal/probes/surface.go`,
   `internal/snapshot/compat.go`, `internal/floors/floors.go` all take
   `LockProcess` themselves); the lock is re-entrant (counted), so the nested
   `RegisterOrRefreshIfChanged` → `RegisterOrRefreshKeptGhosts` → `refreshArtifact`
   path is depth 2/3 of the same OS lock, never a second one.

No new event type, no new status, no new section, no new dependency. The r15
("load→edit→write is one unit") and r16 ("a refused ledger event unwinds the
state write") disciplines are reused, not re-invented: the write and the row
update now happen in one window, and the row update keeps the existing
`rawState`/`unwindState` refusal path.

**Audit section for artifacts:** untouched, and that is the point of the law's
second sentence — `internal/audit/sections/artifacts.go` already re-hashes every
registered row, so a refreshed row is rendered by the existing section
(`checked` counts it, `problems` is empty). No new section was added; the test
asserts `sections.artifacts.ok == true` and `checked == 1` after a refresh.

## 4. Red evidence (before the fix, all three tests)

```
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/cli \
    -run 'TestIndexRefreshEventOnRewrittenArtifact|TestIndexUnchangedTreeEmitsNoEvents|TestIndexConcurrentRefresh' -count=1
--- FAIL: TestIndexUnchangedTreeEmitsNoEvents (0.00s)
    cmd_index_refresh_test.go:209: unchanged rebuilds appended 2 events, want 0
--- FAIL: TestIndexConcurrentRefresh (0.13s)
    cmd_index_refresh_test.go:308: ten concurrent rebuilds of ONE changed tree
        emitted 10 artifact.refreshed events, want exactly 1
FAIL	websec/internal/cli	0.137s
```

(`TestIndexRefreshEventOnRewrittenArtifact` already passed at base — the
single-threaded refresh event was never the missing half; the missing halves
were the lock window and the unchanged-tree silence. Recorded in
`.scratch/sdd/task-6-logs/red-focused.txt`.)

## 5. Green evidence

| Gate | Command | Result | Log |
| --- | --- | --- | --- |
| Task 6 tests (red→green) | `go test ./internal/cli -run 'TestIndex…' -count=1` | ok | `red-focused.txt` |
| Concurrency under `-race` | `go test -race ./internal/cli -run TestIndexConcurrentRefresh -count=1` | ok, 1.42s | `race.txt` |
| Race repeat | `go test -race ./internal/cli -run 'TestIndex' -count=3` | ok | `race.txt` |
| Focused packages | `go test ./internal/cli ./internal/state ./internal/audit -count=1` | ok (29.0s / 10.4s / 0.18s), exit 0 | `focused-packages.txt` |
| Full suite | `go test ./... -count=1` | exit 0 | `full-test.txt` |
| Vet | `go vet ./...` | exit 0 | `vet.txt` |
| Golden + runbook | `bash scripts/golden.sh`; `bash scripts/runbook-walkthrough.sh` | golden-exit=0 (196 steps, 179 events, chain intact, 14 sections ok); walkthrough-exit=0 (150 passed, 0 failed) | `golden.txt` |
| Golden (post-refactor, = the committed content) | `bash scripts/golden.sh` | golden-exit=0 (196 steps, 179 events, chain intact, 14/15 audit sections ok) | `golden-post-refactor.txt` |

The three Task 6 tests:

- `TestIndexRefreshEventOnRewrittenArtifact` — register, move the tree, rebuild:
  exactly one `artifact.refreshed`, its `ref` is the registered row, its
  `old_sha256` is the pre-rewrite hash, its `new_sha256` == the row's new
  `sha256` == the bytes on disk, `refresh_count` == 1, and `audit --json` is
  clean with the artifacts section counting the refreshed row.
- `TestIndexUnchangedTreeEmitsNoEvents` — two further rebuilds of the same tree
  append ZERO events of any type, leave the artifact bytes byte-identical
  (`created_at` included — the file was not touched), and leave `sha256` /
  `refresh_count` alone; audit still clean.
- `TestIndexConcurrentRefresh` — 10 goroutines drive `index` through the real
  CLI (`Run`, so through `t14Open` → `state.Open` → the process lock), 90s
  deadlock watchdog. Phase 1 (one changed tree): exactly ONE
  `artifact.refreshed` for the one rewrite. Phase 2 (three overlapping trees):
  every refresh's `old_sha256` equals the previous refresh's `new_sha256`
  (nothing slipped between the bytes and the row), no refresh is a no-op
  (`old != new`), the final row `sha256` == the final bytes == the last
  refresh's `new_sha256`, `refresh_count` == the number of refresh events, all
  10 exits are 0, and the audit is clean. `-race` clean, `-count=3` clean.

## 6. Diff summary

```
$ git show --stat f837a26a
 internal/cli/cmd_index.go                          |  20 +-
 internal/cli/cmd_index_refresh_test.go             | 361 +++++++++++++++++++++
 internal/state/artifacts.go                        |  75 +++++
 internal/state/artifacts_refresh_if_changed_test.go| 189 +++++++++++
 internal/structidx/index.go                        |  56 +++-
 5 files changed, 694 insertions(+), 7 deletions(-)
```

Staged by exact path only; no `git add -A`/`.`, and no pre-existing modified
file in this worktree was touched.

## 7. Golden / runbook pins

No CLI stdout byte changed: the handler prints the same
`index: N entries (snapshot X)` / `--json` triple, and `SaveIndexIfChanged`
returns the same path. `scripts/golden.sh` (which runs
`python3 scripts/check-golden.py` itself) and `scripts/runbook-walkthrough.sh`
were both run anyway, because the golden replay and RUNBOOK §4 each invoke
`index` twice over one tree — exactly the path whose behaviour changed — and
both are green with no pin edited (the walkthrough asserts output markers, not
`refresh_count`; the golden replay asserts exit codes, chain integrity and 14
audit sections). No pin file was modified.

## 8. Concerns

1. **The orchestrator's pipeline stage still has the old shape.** 
   `orchestrator.BuildStructuralIndex` (`internal/orchestrator/index.go:59-97`)
   calls `siAPI.SaveIndex` and then `RegisterOrRefresh` — same write-then-lock
   ordering Task 6 fixes for the command. It is outside this task's file scope
   ("the `index` command handler") and it is reached through the `StructuralIndexAPI`
   seam (`internal/structidx/wire.go:30`), so I did not change it. If the law is
   meant to cover the pipeline too, that is a small follow-up: swap the two
   calls for `SaveIndexIfChanged` + `RegisterOrRefreshIfChanged` under
   `o.C.LockProcess()`. I verified no orchestrator test pins a refresh on a
   second `BuildStructuralIndex` run (`rg -n BuildStructuralIndex
   internal/orchestrator/*_test.go` → two hits, neither about refresh events),
   so the change would be low-risk — but it is a behaviour change to a seam
   Task 6 did not name, and I would rather flag it than widen scope silently.
2. **`created_at` is now "last semantic rebuild", not "last run".** That is
   the deliberate consequence of the unchanged-tree law, and it matches the
   existing doctrine (`TreeFacts`/`IndexSha` treat the clock as volatile).
   Nothing reads the index's `created_at` for freshness: report freshness is
   computed from `IndexSha` (tree facts) and from `artifact.refreshed` events.
   One consequence is honest and intended: `report → re-index (same tree) →
   prove` no longer reports "regenerate", because the index bytes did not
   change. The r12 note's hash-equal-refresh behaviour is preserved for the
   explicit operator verbs, which is where it was pinned.
3. **`RegisterOrRefreshIfChanged` returns `(id, refreshed, err)`; the CLI
   ignores `refreshed`.** It is kept because it is the honest answer to "did
   this call touch the registry?" and it is pinned by the state unit test;
   stdout must stay byte-identical, so the handler has no use for it. If the
   reviewer prefers a two-value API, dropping it is mechanical.
4. **The lock window covers the write and the row update, not the index
   build.** `IndexSnapshot` (parse the tree, read the active pin) still runs
   before the lock, as at base — a pin that moves between the build and the
   write can still stamp an index whose `snapshot_id` no longer matches the
   live pin. That is a pre-existing property of the r13 pin check, not a Task 6
   regression, and widening the window to cover a full source-tree parse would
   hold the campaign lock for the whole parse.
5. **Kept-ghost rows.** If a cited ghost row sits at the index path with a
   stale sha, `artifactRowCurrent` looks at the LATEST row (the one
   RegisterOrRefresh would refresh) and calls that current when its sha
   matches — the ghost is not re-hashed. That is exactly the pre-existing
   behaviour of the refresh path (r35 F1), so the audit's red/green verdict for
   that shape is unchanged; the new helper neither fixes nor worsens it.


## 9. How to reproduce (reviewer checklist)

```bash
cd /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness

# the law, red without the fix and green with it
git stash list                       # nothing stashed; HEAD is f837a26a
GOCACHE=$PWD/.scratch/gocache go test ./internal/cli \
  -run 'TestIndexRefreshEventOnRewrittenArtifact|TestIndexUnchangedTreeEmitsNoEvents|TestIndexConcurrentRefresh' -count=1 -v

# the concurrency contract (the brief's exact command)
GOCACHE=$PWD/.scratch/gocache go test -race ./internal/cli \
  -run TestIndexConcurrentRefresh -count=1

# the shared helper's own contract
GOCACHE=$PWD/.scratch/gocache go test ./internal/state \
  -run TestRegisterOrRefreshIfChanged -count=1 -v

# the full gate set
GOCACHE=$PWD/.scratch/gocache go test ./internal/cli ./internal/state ./internal/audit -count=1
GOCACHE=$PWD/.scratch/gocache go test ./... -count=1
GOCACHE=$PWD/.scratch/gocache go vet ./...
bash scripts/golden.sh && bash scripts/runbook-walkthrough.sh

# counterfactual: revert ONLY the handler's window and the red run returns
git show f837a26a -- internal/cli/cmd_index.go
```

To see the defect again, `git stash` the fix (or check out `f13ae1df`'s
`cmd_index.go`) and run the three tests: `TestIndexUnchangedTreeEmitsNoEvents`
fails with "unchanged rebuilds appended 2 events" and
`TestIndexConcurrentRefresh` fails with "ten concurrent rebuilds of ONE changed
tree emitted 10 artifact.refreshed events, want exactly 1".

## 10. Logs

`.scratch/sdd/task-6-logs/` — `red-focused.txt`, `race.txt`,
`focused-packages.txt`, `full-test.txt`, `vet.txt`, `golden.txt` (golden.sh +
runbook-walkthrough.sh), `golden-post-refactor.txt`.
