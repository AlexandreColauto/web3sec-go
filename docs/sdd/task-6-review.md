# Task 6 independent review — `index` emits a registry refresh event when it rewrites artifact bytes

**Range:** f13ae1df..f837a26a (single commit, 5 files, +694/-7)
**Reviewer basis:** diff read directly from git (review package verified byte-identical to `git diff -U10 f13ae1df..f837a26a`), surrounding source at HEAD, committed tests, `.scratch/sdd/task-6-logs/*`. No commands re-run (logs accepted as the green record).

## Verdicts

**Spec compliance: YES**
**Task quality: APPROVED** — 4 Minor findings, none blocking; follow-up item required (below).

## Law-by-law verification (from the diff)

1. **Row update + `artifact.refreshed` in the same lock window** — `runIndex`
   takes `c.LockProcess()` with `defer c.UnlockProcess()` at
   `internal/cli/cmd_index.go:52-55`, and both `SaveIndexIfChanged` (56) and
   `RegisterOrRefreshIfChanged` (72) run inside it. The lock is a counted
   per-`Campaign` re-entrant flock (`internal/state/processlock.go:47-94`);
   the nested acquisitions inside `RegisterOrRefreshIfChanged` (artifacts.go:997-999)
   and `RegisterOrRefreshKeptGhosts` (artifacts.go:456-461) bump depth on the
   same instance — no second OS lock, no deadlock. Separate goroutines in the
   concurrent test each open their own `Campaign` (via `Run`→`t14Open`), so
   they contend on distinct fds — flock conflicts across open file
   descriptions even within one process, so the test genuinely exercises
   mutual exclusion. `t14Open`/`t14Dispatch` (cmd_scope.go:73-97) take no
   lock of their own. Verified sound.
2. **Content-equality semantics (`SaveIndexIfChanged`, index.go:216-236)** —
   excludes ONLY the top-level `created_at`; `snapshot_id`, `campaign_id`,
   `parse_version`, `backend`, nodes/edges/stats all stay semantic, so a pin
   move or a tree change always rewrites. This is *stricter* than
   `TreeFacts` (indexsha.go:21-23), which also drops `campaign_id`/`snapshot_id`
   — the doctrine the report cites ("same tree, twice, hash equal") is real and
   predates this commit. `CanonCompact` (jval/value.go:149, sort_keys
   canonical writer) makes the comparison key-order-independent;
   `ParseOrdered` (Task 1) guarantees no duplicate-key ambiguity in the
   re-read file. Is the `created_at` exclusion masking a real change? No:
   grep of all `created_at` use shows no production reader consumes the
   index's `created_at` for freshness — `EnsureFreshIndex` keys on
   `snapshot_id`+`parse_version` (index.go:241-256), and
   `campaign_test.go:158-174` proves reuse preserves a `SENTINEL`
   `created_at`. Verdict: **sound**.
3. **`RegisterOrRefreshIfChanged` reuse of the resolved-path key + r16 unwind** —
   `artifactRowCurrent` (artifacts.go:1013-1049) mirrors
   `RegisterOrRefreshKeptGhosts`' row selection exactly: same
   `resolvePath(c.resolveArtifactPath(a)) == resolvePath(path)` key, same
   latest-by-`registered_at` with first-max-wins-ties tie-break
   (strict `>` over the same array order, artifacts.go:1024-1030 vs
   474-480). Kind mismatch (`kind != "" && != row kind`) is correctly NOT
   current so the D3 migration still lands. `RegisterOrRefresh` itself is
   untouched (diff is pure addition), so the r12 hash-equal-refresh pin for
   operator verbs holds. The refresh/mint path runs through unchanged
   `refreshArtifact`/`RegisterArtifact`, which keep the r16
   `rawState`→`save`→`Log`→`unwindState` discipline
   (artifacts.go:122/174, 227/259, 357/380). A refused event unwinds the
   row but not the already-written index bytes — same as at base, and audit
   re-hash surfaces any such straddle. Verified.
4. **Red evidence** — base code (f13ae1df cmd_index.go) wrote via unconditional
   `SaveIndex` outside any lock, then unconditional `RegisterOrRefresh`:
   10 serialized goroutines on one changed tree each minted a refresh event
   (first old≠new, nine hash-equal old==new) → the "10 duplicates" defect is
   mechanically guaranteed by the base code. BUT the saved log
   `.scratch/sdd/task-6-logs/red-focused.txt` is truncated at line 33
   (mid-JSON-dump of the unchanged-tree failure; 1528 bytes) — it does NOT
   contain the quoted `TestIndexConcurrentRefresh … emitted 10` line, and its
   trailing `exit=0` is a recording-pipeline artifact (a red run exits 1).
   See Minor 1.
5. **Unchanged tree → zero new events** —
   `TestIndexUnchangedTreeEmitsNoEvents` counts ALL events before/after two
   further rebuilds (not just refreshes), asserts bytes byte-identical
   (file untouched) and `sha256`/`refresh_count` unmoved. Correct shape.
6. **Concurrency test** — named `TestIndexConcurrentRefresh` as the brief
   demanded; 10 goroutines, real CLI path, overlapping trees, phase-1 exactly
   one event, phase-2 chain assertion (`old_sha[i] == new_sha[i-1]`, no
   no-op events, final row == final bytes == last event, `refresh_count ==`
   event count), 90s watchdog, `-race` and `-count=3` logs green (race.txt).
   `ensureSeams()` is warmed once before the fork (test line 239) — necessary,
   see Concern 6.
7. **Audit section unchanged** — no file under `internal/audit/` in the diff;
   the tests render the refreshed row through the existing artifacts section
   (`checked==1`, `problems` empty, overall `ok`). Brief's "no new section"
   honored by construction.
8. **Global constraints** — no new deps (go.mod untouched), no new event type/
   status/section, `RegisterOrRefresh` reuse via the sanctioned shared helper
   the plan allowed, stdout byte-identical (handler print paths untouched),
   golden/runbook run with zero pin edits, only task-owned files committed,
   worktree clean at f837a26a. Phase B loop (red→green→gates→commit→review)
   evidenced.

## Adjudication of the implementer's concerns

The report §8 numbers five concerns (the review brief's "(6) ensureSeams race
note" has no numbered counterpart — the underlying issue exists in code the
new test touches, so it is adjudicated here as item 6).

1. **Orchestrator `BuildStructuralIndex` still write-then-lock — ACCEPTED as
   out of scope, follow-up REQUIRED.** Confirmed genuinely unused by the CLI
   `index` path: `runIndex` calls `structidx.IndexSnapshot`/`SaveIndexIfChanged`
   directly, never the seam (`internal/structidx/wire.go`). But the seam is
   live code, not theoretical: `internal/orchestrator/index.go:59-97`
   (`siAPI.SaveIndex` outside the lock + unconditional `RegisterOrRefresh`) is
   reached from the shipped binary via `pipeline.go:1016` and
   `cli/cmd_selftest.go:391`. See also Minor 4 — the report missed a second,
   CLI-reachable same-shape caller.
2. **`created_at` = last semantic rebuild — SOUND** (analysis in Law check 2
   above). The "report → re-index (same tree) → prove no longer says
   regenerate" consequence is the plan's own unchanged-tree law applied
   honestly, not a weakening: report freshness rides `IndexSha`/events, and
   the SENTINEL tests pin that the index `created_at` is unread for freshness.
3. **Unused `refreshed` bool — ACCEPTED, keep.** It is the helper's honest
   answer, pinned by the state unit tests
   (`artifacts_refresh_if_changed_test.go:56,70,88,117`); the handler's `_`
   discard is forced by the byte-identical-stdout constraint. A two-value API
   would remove one `_` and lose the pin. No change requested.
4. **Lock window excludes the index build — ACCEPTED, pre-existing.** The
   base window started at the same point (build was always outside); the r13
   content-hash check stamps `snapshot_id` by proof, and the residual race
   (pin moves between build and write) behaves exactly as at base. Widening
   the window across a full tree parse would hold the campaign lock through
   the parse — worse operator friction, and the pin-vs-write straddle remains
   open to `EnsureFreshIndex` callers regardless.
5. **Kept-ghost rows — ACCEPTED, verified against code.** The base refresh
   path also never re-hashed ghosts (only the latest row; uncited ghosts are
   pruned, cited ghosts left as-is — r35 F1 comment, artifacts.go:416-437),
   so the audit verdict for the cited-ghost shape is unchanged. One
   consequence the report doesn't spell out: when the latest row is current,
   the early return now also skips the *opportunistic uncited-ghost prune*
   base performed on every rebuild. Extremely narrow (one-row-per-path is the
   steady state for `structural-index`; a stale ghost there is already
   audit-red) and `artifact-reconcile`/operator verbs remain the sanctioned
   cleanup — noted for the ledger, not a finding.
6. **`ensureSeams` race — REAL but pre-existing, correctly dodged here.**
   `seamsInstalled` is an unsynchronized check-then-set global
   (`internal/cli/cmd_dedup.go:259-264`); the concurrent test calling `Run`
   from 10 goroutines would have been a `-race` violation without the
   single-threaded warm-up call at `cmd_index_refresh_test.go:239`, which the
   test does. Production CLI is one goroutine per process. Not a Task 6
   regression; a `sync.Once` conversion belongs in the follow-up wave only if
   in-process concurrent `Run` is ever formalized.

## Findings (all Minor)

- **Minor 1 — red log truncated; headline red evidence not in it.**
  `.scratch/sdd/task-6-logs/red-focused.txt` (1528 B, ends line 33 mid-dump,
  spurious `exit=0`) contains only the `TestIndexUnchangedTreeEmitsNoEvents`
  failure head; the quoted `cmd_index_refresh_test.go:308: … emitted 10
  artifact.refreshed events` is absent. The defect is mechanically provable
  from the base code, so red is confirmed by construction — but the ledger's
  red evidence should be complete. **Fix:** re-record the base red run (scratch
  copy of `f13ae1df`'s `cmd_index.go`, or `git stash`) into `red-focused.txt`
  without pipeline truncation.
- **Minor 2 — the letter of the race gate not recorded.** Global Constraints
  require `-race` on `./internal/state ./internal/sandbox ./internal/harness`
  for concurrency-touching tasks; race.txt runs `-race` only on
  `./internal/cli` (stronger where the concurrency lives, but `internal/state`
  gained code here). **Fix:** append `go test -race ./internal/state -count=1`
  to the logs.
- **Minor 3 — "tampered files always differ" is overstated.**
  `internal/structidx/index.go:216-227` (doc) + report §3: a tamper that
  preserves canonical content modulo `created_at`/key order compares equal,
  so `index` no longer heals that shape (at base it silently overwrote it).
  Detection is unaffected (audit re-hash goes red; `artifact-reconcile` is
  the sanctioned heal). **Fix:** tighten the doc sentence to "a missing or
  semantically-different file is healed; byte-level tampering is caught by
  audit and reconciled."
- **Minor 4 — follow-up list incomplete: `EnsureFreshIndex` shares the
  old shape and IS CLI-reachable.** `internal/structidx/index.go:241-278`
  still writes unconditionally outside the row-update lock and refreshes
  unconditionally, and runs inside shipped commands
  (`cli/cmd_dedup.go:334`, `archetypes/prescreen.go:41`, `corpus/report.go:37`,
  `histmining/recency.go:101`, `structidx/queries.go:396`). Out of Task 6's
  letter ("the `index` command handler") — no violation here — but the
  recorded follow-up for concern 1 must name both callers: a
  `SaveIndexIfChanged` + `RegisterOrRefreshIfChanged` swap under `LockProcess`
  is the same mechanical fix at both sites.

## Cannot verify from the diff (accepted on logs / reasoning)

- Green-state claims (full suite, vet, focused packages, golden 196 steps /
  chain intact, walkthrough 150/0) rest on the `.scratch/sdd/task-6-logs/`
  artifacts, which are internally consistent and carry exit=0; re-runs were
  out of scope for this review.
- The exact red output of `TestIndexConcurrentRefresh` (10 events) — see
  Minor 1; confirmed by base-code reasoning, not by the saved log.
- `-race` timing margin: 10 serialized runs finished in 1.42 s under race vs
  the 5 s per-acquisition `lockBudget` (processlock.go:38) — ample on the
  recording machine, but a pathologically loaded box could turn a legit wait
  into a `locked by another process` exit; machine-dependent, no action.
- That no orchestrator/pipeline test pins a refresh event on a second
  `BuildStructuralIndex` (report's low-risk claim for concern 1): consistent
  with the green full-suite log against untouched orchestrator tests, not
  exhaustively re-verified here.

## Bottom line

The commit implements the Task 6 law exactly at its stated scope: the
`index` command's rewrite is now one locked unit (bytes + row + event), the
unchanged tree is honestly silent, the shared helper reuses — not duplicates —
the resolved-path key, tie-break, D3 migration and r16 unwind, and both the
plan's tests and a stronger concurrency test pin the contract with `-race`
clean. The four Minor items are evidence-completeness, one doc sentence, one
unrecorded race run, and an incomplete follow-up enumeration; none undermines
the trust boundary. **Spec compliance YES; Task quality APPROVED** with
Minors 1-4 for the ledger (Minor 4 to be recorded together with the concern-1
follow-up).
