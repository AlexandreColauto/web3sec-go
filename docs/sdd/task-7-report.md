# Task 7 report — `brief` next-actions are copyable commands

**Status:** DONE (production change + tests; no plan-premise correction needed —
the pseudo-API was real and live in `webv2 brief` output)
**Commit:** `dae1c42f` — `fix(orchestrator): brief next-actions are copyable webv2 commands`
**Branch/worktree:** `production-readiness` @
`/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
**Base:** `f837a26a` (Task 6)
**Files changed:** `internal/orchestrator/status.go` (+83/-54),
`internal/orchestrator/testdata/oracles.json` (27 oracle values re-recorded),
`internal/orchestrator/golden_test.go` (+11, provenance note), plus two new test
files (`internal/orchestrator/next_actions_cli_test.go`,
`internal/briefing/brief_next_actions_cli_test.go`) and one deliberate test
marker update (`internal/briefing/sweep_t35_probes_test.go`, +26/-2).

---

## 1. The brief, verbatim (plan Task 7 + Phase B preamble)

> ### Task 7: `brief` next-actions are copyable commands
> **Files:** `internal/briefing` (or wherever next-actions render — locate via
> `grep -rn "next_action" internal/briefing`).
> **Law:** every next-action line is a runnable `webv2 …` command; no
> `orchestrator.scope(policy_path=…)` pseudo-API. The plan/replan code that
> MINTS those strings is the fix site, not the renderer.
> **Test:** fixture campaign → `brief` output next-actions all match `^webv2 `
> and none match `\(`.
> **Pins:** update golden/runbook expectations deliberately.

Phase B preamble: *"Tasks 5-9 follow the identical TDD loop: failing test →
minimal fix → full gates → deliberate golden/runbook pin updates → commit →
union-alpha review."*

## 2. Premise check — where the strings are MINTED

`webv2 brief` renders `b.next_actions` verbatim (`internal/cli/cmd_brief.go:389`,
`  %d. %s`). The list is assembled in `internal/briefing/briefing.go`
(`NextActions`, briefing.go:2052) — and for a campaign with no probe surface and
no findings, every element comes from `orchestrator.NextActions`
(briefing.go:2446). That is where the pseudo-API lived:

```
$ webv2 brief C-15ea283407          # before
next actions:
  1. orchestrator.scope(policy_path=...)
  2. orchestrator.snapshot(target=...)
```

`orchestrator.NextActions` (internal/orchestrator/status.go) mints two families
of lines: the phase → guidance catalog (`phaseActions`) and the completion-proof
"teeth". Probing all 19 phases showed the full surface — 17 phases of
`orchestrator.*` / `adapter.build_context` / `pipeline.run()` pseudo-calls,
proof lines like `[discovery missing] campaign plan (discovery consumes its
queue)`, and `campaign complete or halted` for the two phases with no catalog
entry. None of those is a command.

The fix site is therefore `internal/orchestrator/status.go` (the mint), with the
brief-level test asserting the rendered list — not `cmd_brief.go`, which already
prints whatever it is given.

## 3. The fix (one catalog rewrite, no new mechanism)

1. **`phaseActions(phase, cid)`** — every entry is a real CLI shape with the
   campaign id interpolated, e.g. `webv2 scope <C> --policy <policy.json>`,
   `webv2 snap <C> <target>`, `webv2 index <C> --src <src>`,
   `webv2 model <C> <model.json>`, `webv2 plan <C> <plan.json>`,
   `webv2 dedup <C>`, `webv2 resolve-candidate <C> <finding> <other> --verdict
   <same|distinct> --note <note>`, `webv2 verdict …`, `webv2 repro-queue <C>`,
   `webv2 mint …`, `webv2 chains <C>`, `webv2 ladder <C> start <finding>`,
   `webv2 rank <C>`, `webv2 exec <C> --command <command> --profile <profile>`,
   `webv2 gate <C>`, `webv2 report <C>`, `webv2 memory …`.
   Two defects of the old text were fixed on the way: `webv2 gate explain
   <check>` was not a real form (the flag is `--explain`, cmd_gate.go:34), and
   `webv2 ladder start/add/explore/repro/set-maximal/complete` was a
   slash-joined pseudo-usage, now two concrete ladder commands.
   `INDEPENDENT_VERIFICATION` and `MAINNET_FORK_POC` had no entry at all
   (they fell through to `campaign complete or halted`); they now name the
   commands their proofs demand.
2. **Proof teeth** — `webv2 prove <C> --stage <stage>  # n missing` (the
   command prints the exact missing items, the comment keeps the size of the
   gap visible), `webv2 run <C>  # <stage> proof holds; the stage
   auto-completes`, and the phase-done header `webv2 prove <C>  # phase says
   done but completion proofs are open`. Proof ids are exactly pipeline stage
   ids (`internal/completion/completion.go:252`), so `--stage` accepts every
   key.
3. **Deliberate trade-off, documented in the code:** the per-item proof detail
   the old catalog inlined (`[discovery missing] Q-001: …`) is no longer
   inlined. It cannot be: a line carrying that prose is not a command (and
   carries parentheses). The command the line names prints it verbatim — this
   report's §6 shows `webv2 prove C-15ea283407 --stage protocol-model` printing
   the missing item that used to be inlined.

Everything is a `#`-commented suffix or a plain command; no line needs editing
beyond filling its `<metavariable>`, which is the house style already used by
the lens routing lines (`webv2 enforce %s <cursor-variable>`).

## 4. Red evidence (tests first, in the minting package)

Two new test files, written before the fix:

* `internal/orchestrator/next_actions_cli_test.go` (`package orchestrator_test`,
  the minting package) — four checks:
  1. `TestNextActionsAreCopyableCommands` — every phase in `state.Phases`: each
     line matches `^webv2 `, contains no `(`/`)`, names a verb in
     `cli.CommandNames()`, and every `<metavariable>` is covered by the
     substitution table (an uncovered one is a failure, not a skip);
  2. `TestNextActionsGuardCatchesMutations` — the guard is proven able to fail:
     a pseudo-API line, a prose line, an undispatched verb, an unseeded
     metavariable, and a misspelled **flag** (dispatcher must answer exit 2);
  3. `TestNextActionsConcreteFixtures` — **concrete expected commands**, not
     just the regex, for four known fixtures: fresh/SCOPE, SNAPSHOT,
     CAMPAIGN_PLANNING (plan + proof line) and REPRODUCTION (queue + mint +
     proof-holds line);
  4. `TestNextActionsCommandsParse` — each emitted line, metavariables
     substituted, is fed to the real dispatcher (`cli.Run`) against a root with
     no such campaign; exit 2 (usage error) fails the test. Exit 1 is the
     intended campaign-not-found, and nothing can do work because the campaign
     does not exist.
* `internal/briefing/brief_next_actions_cli_test.go` — the plan's literal test
  at the brief boundary: the fixture campaign's `next_actions` are all `^webv2 `
  and parenthesis-free, and are exactly the two SCOPE commands.

Red run (before the fix):

```
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/orchestrator -run TestNextActions -count=1
--- FAIL: TestNextActionsAreCopyableCommands
--- FAIL: TestNextActionsConcreteFixtures
--- FAIL: TestNextActionsCommandsParse
    next_actions_cli_test.go:120: phase SCOPE: next action "orchestrator.scope(policy_path=...)" is not a runnable `webv2 …` command
    next_actions_cli_test.go:125: phase SCOPE: next action "orchestrator.scope(policy_path=...)" carries a parenthesis — that is a Python-API pseudo-call, not a command an operator can paste
    … 131 failure lines across the 19 phases …
    next_actions_cli_test.go:290: phase BOUNTY_GATE: uncovered metavariable "<check>`" in "`webv2 gate explain <check>` for any failing check"
FAIL	websec/internal/orchestrator

$ GOCACHE=$PWD/.scratch/gocache go test ./internal/briefing -run TestBriefNextActions -count=1
--- FAIL: TestBriefNextActionsAreCopyableCommands
    brief_next_actions_cli_test.go:29: brief next action "orchestrator.scope(policy_path=...)" is not a runnable `webv2 …` command
FAIL	websec/internal/briefing
```

(`TestNextActionsGuardCatchesMutations` passed at red on purpose: the guard must
already work, and its mutation cases are what prove it is not vacuous.)

Logs: `.scratch/sdd/task-7-logs/red-orchestrator.txt`,
`.scratch/sdd/task-7-logs/red-briefing.txt`.

## 5. Green evidence

```
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/orchestrator ./internal/briefing ./internal/cli -count=1
ok  	websec/internal/orchestrator	1.204s
ok  	websec/internal/briefing	0.848s
ok  	websec/internal/cli	28.788s

$ go test ./... -count=1
71 packages ok, 0 FAIL

$ go vet ./...
(no output)

$ gofmt -l internal cmd
(no output)
```

Logs: `focused-final.txt`, `full-test-final.txt`, `vet-final.txt`,
`gofmt.txt`.

## 6. End-to-end runnability (real binary, real campaign)

The law is not "the parser tolerates it" but "an operator can paste it". Fresh
campaign in `.scratch/t7/root`, real `webv2` binary:

```
$ webv2 brief C-15ea283407
next actions:
  1. webv2 scope C-15ea283407 --policy <policy.json>
  2. webv2 snap C-15ea283407 <target>

$ webv2 scope C-15ea283407 --policy policy.json
policy loaded from policy.json — 2 scope entries, 1 exclusions          # exit 0
$ webv2 snap C-15ea283407 target
pinned src-f837a26a-f390fe545e74 (git-dirty, 1 files)                   # exit 0

$ webv2 run C-15ea283407 --max-stages 2        # phase advances to PROTOCOL_INTELLIGENCE
$ webv2 brief C-15ea283407
next actions:
  1. webv2 run C-15ea283407
  2. webv2 model C-15ea283407 <model.json>
  3. webv2 prove C-15ea283407 --stage protocol-model  # 1 missing

$ webv2 prove C-15ea283407 --stage protocol-model
protocol-model             open  [authoritative] — artifacts/protocol_model.json — run the protocol-model stage and load the model
                                                                        # exit 1 (proof open), detail preserved
```

Both emitted commands exited 0; the proof command exited 1 because the proof is
genuinely open — the point is that the line runs and names the exact missing
item.

## 7. Pins: what moved, and why (no silent drift)

| Pin | Change | Reason |
| --- | --- | --- |
| `internal/orchestrator/testdata/oracles.json` | 27 `next_actions` oracle values re-recorded from the Go twin (scenarios `fresh`, `scoped`, `snapped`, `model`, `planned`, `ingested`, `deduped`, `gates`, and all 19 steps of `phases`) | The recorded Python bytes **are** the pseudo-API this task removes; re-running the generator would restore them. Re-recorded by replaying each scenario through the harness' own `dispatchGolden` (temporary tooling, deleted before commit — the capture dump is kept at `.scratch/sdd/task-7-logs/t7-captured-oracles.json`). The 54-line diff touches only those 27 oracle values — verified by `git diff`. |
| `internal/orchestrator/golden_test.go` | provenance note only (+11) | Records the re-record and its reason, following the existing precedent documented in the same header (the `gates` bounty_gate_all snapshot, Task 4's metavariables). |
| `internal/briefing/sweep_t35_probes_test.go` | the two T35 checks that detected phase guidance by the old `"orchestrator."` prefix now test exact membership in `orchestrator.NextActions` for the campaign | The prefix no longer exists by design. The replacement is **strictly stronger**: a look-alike `webv2 …` line cannot pass it. Both assertions keep their original intent (guidance must not leak into a grandfathered brief; the fallback must survive attention debt). |
| `scripts/golden.sh`, `scripts/runbook-walkthrough.sh` | **unchanged** | No drift: `GOLDEN GREEN` and `150 passed, 0 failed`. `brief` is read-only and the runbook's brief rows assert only the `campaign` / `"` markers. |

Historical fixtures untouched: nothing under `scripts/legacy` (or any other
fixture tree) was modified; `git show --stat HEAD` lists exactly the six
task-owned files.

## 8. Scope boundary and concerns

1. **The law was applied at the minting site, not to every line `brief` can
   ever print.** `internal/briefing/briefing.go::NextActions` (2052-2486) mints
   its own prioritized lines (`work probe row …`, `L-03 open with 0/10 rows …
   — run the mechanical table: webv2 enforce …`, `verify INV-008 (unverified
   1h0m): webv2 invariant-verify …`, `lens L-01 batting average — …`). They are
   prose-first and several contain parentheses, so a strict reading of "every
   next-action line" would cover them too. I did **not** convert them, for two
   reasons: (a) the plan names the plan/replan mint and the `orchestrator.*`
   pseudo-API as the defect, and the delegation says the fix site is the
   minting work-queue assembly; (b) converting them rewrites ~20 lines whose
   text is asserted by the ported T35 parity suite
   (`sweep_t35_plan_test.go`, `sweep_t35_crit_test.go`, `lens_routing_test.go`,
   `briefing_test.go`), i.e. a much larger, separately-reviewable change.
   **Reviewer decision point:** if the law is meant to cover those lines as
   well, Task 7 should be re-opened (or a Task 7b added) — the fixture in
   `TestBriefNextActionsAreCopyableCommands` is a fresh campaign, so it would
   not catch them today. I chose not to weaken or re-pin the T35 assertions to
   make a broader claim pass.
2. **Two adjacent pseudo-API strings remain, outside this task's law** (they are
   error messages, not next-action lines): `internal/orchestrator/triage.go:220`
   (`"bounty gate requires a policy; run scope(policy_path=...) first"`, which
   is itself an oracle-pinned error string in `oracles.json`) and
   `internal/sharedmem/sharedmem.go:385` (same pseudo-call in a returned error).
   Both tell an operator to run an API that does not exist; both are follow-up
   material, deliberately not touched here to keep this diff to the task's
   scope.
3. **Metavariables are a judgement call.** Lines like
   `webv2 verdict <C> <finding> --verdict <verdict> --reason <reason>` are
   runnable *shapes*: the parser accepts them (proved by
   `TestNextActionsCommandsParse`), but the operator supplies the finding id,
   verdict and reason. This matches the existing house style
   (`webv2 ladder waive … --reason <reason>`, `webv2 enforce <C>
   <cursor-variable>`); no line names a value the tool could have known.
4. **The `# n missing` comment suffix** is a shell comment, so the line stays
   copyable. It is used only where the command alone would lose information the
   old catalog carried (proof count, "phase says done", terminal state). A
   reviewer who prefers comment-free guidance can drop it with a one-line change
   in `proofCommand`/the three call sites; the guard does not depend on it.
5. **Guidance is phase-driven, so after `scope` + `snap` the same two commands
   are still printed until `webv2 run` advances the phase** (see §6). That is
   pre-existing pipeline behavior (`state.SetPhase` moves on `run`), not
   something Task 7 changed — but it does mean the copyable list is only as
   fresh as the phase.
6. `oracles.json` is now partly Go-authored. The header note says exactly which
   27 snapshots and why; a future regeneration from the Python twin would
   revert them, and the note is the only thing that would explain the diff.

## 9. How to reproduce (reviewer checklist)

```bash
cd /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness
export GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod

# 1. the law, over all 19 phases, plus the four concrete fixtures and the
#    dispatcher parse check
go test ./internal/orchestrator -run TestNextActions -count=1 -v

# 2. the brief boundary (plan's literal test)
go test ./internal/briefing -run TestBriefNextActions -count=1 -v

# 3. the golden vectors (27 re-recorded next_actions oracles)
go test ./internal/orchestrator -run TestGoldenVectors -count=1

# 4. gates
go test ./internal/orchestrator ./internal/briefing ./internal/cli -count=1
go test ./... -count=1
go vet ./...
gofmt -l internal cmd

# 5. pins (unchanged by this task, run to confirm no drift)
bash scripts/golden.sh
bash scripts/runbook-walkthrough.sh

# 6. the operator's view, on a throwaway campaign
go build -o /tmp/webv2 ./cmd/...
mkdir -p /tmp/t7-check && cd /tmp/t7-check
/tmp/webv2 init --program Acme                 # prints the campaign id
/tmp/webv2 brief <CID>                         # every line starts with `webv2 `
```

Anti-vacuity: `TestNextActionsGuardCatchesMutations` fails if the line guard
stops reporting, and `TestNextActionsCommandsParse` fails if the dispatcher
accepts a misspelled flag (both are asserted inside the same run).

## 10. Logs

All under `.scratch/sdd/task-7-logs/`:

| File | Contents |
| --- | --- |
| `red-orchestrator.txt` | red run, 131 failure lines across 19 phases |
| `red-briefing.txt` | red run at the brief boundary |
| `focused-final.txt` | final `./internal/orchestrator ./internal/briefing ./internal/cli` |
| `full-test-final.txt` | final `go test ./... -count=1` (71 ok, 0 FAIL) |
| `vet-final.txt` | final `go vet ./...` (empty) |
| `gofmt.txt` | `gofmt -l internal cmd` (empty) |
| `golden.txt` | `GOLDEN GREEN` |
| `runbook.txt` | `150 passed, 0 failed` / `WALKTHROUGH GREEN` |
| `t7-captured-oracles.json` | the 27 new oracle values as captured from the Go twin |

## 11. Commit

```
dae1c42f fix(orchestrator): brief next-actions are copyable webv2 commands
 internal/briefing/brief_next_actions_cli_test.go |  46 ++++
 internal/briefing/sweep_t35_probes_test.go       |  28 +-
 internal/orchestrator/golden_test.go             |  11 +
 internal/orchestrator/next_actions_cli_test.go   | 324 +++++++++++++++++++++++
 internal/orchestrator/status.go                  | 137 ++++++----
 internal/orchestrator/testdata/oracles.json      |  54 ++--
 6 files changed, 517 insertions(+), 83 deletions(-)
```

Not pushed, not merged, no delegation used.
