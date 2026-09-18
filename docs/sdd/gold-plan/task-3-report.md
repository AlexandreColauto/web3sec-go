# Task 3 report — brief renders evidence reachability per bug class (defect 5)

- **Branch:** `production-readiness` (worktree `.worktrees/production-readiness`)
- **BASE:** `3c095827ddb967bf08fcf676bc64a4950a2f1f3f`
  (`feat(orchestrator): adversarial lifecycle machines mint into the work queue (defect 4)`)
- **Commit:** `280e348d965c9904177854d35389f772438b9de7`
  (`feat(briefing): evidence reachability line (class confirm floor vs box cap) (defect 5)`)
- **STATUS:** complete, all gates green, no push/merge/delegate performed.
- **Logs:** `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-3-logs/`
  (`red.txt`, `focused.log`, `reachability-verbose.log`, `gotest-all.log`, `govet.log`,
  `golden.log`, `runbook.log`)
- **Ponytail:** loaded and applied (ladder; one runnable check per non-trivial path;
  a `ponytail:` ceiling note on the cap constant). Nothing unrequested was built.

## Files changed (exact paths, committed)

| Path | Change |
|---|---|
| `internal/findings/levels.go` | `ClassConfirmFloor`, `ReachableLocally` (pure map/ladder reads) |
| `internal/findings/levels_reachability_test.go` | new: floor + reachability pins |
| `internal/briefing/briefing.go` | `ReachabilityLine`, `boxLocalCap`, `openFindingClasses`, one mint in `NextActions` |
| `internal/briefing/task14_reachability_test.go` | new: rendering rules, ordering pin, render condition |

No map values changed, no gate/proof/phase code touched, no historical fixture
touched (`scripts/legacy/`, `web3sec-final/`, `morph/`, golden fixtures all untouched).

## Step 0 — floor-map facts (read, never assumed)

`internal/findings/levels.go:52-78`, `CLASS_CONFIRM_FLOOR`, **16 keys**:

- **E4 (9):** `access-control`, `signature-replay`, `upgrade-initializer`, `authorization`,
  `reentrancy`, `logic-error`, `dos-griefing`, `token-integration`, `share-price-accounting`
- **E5 (3):** `oracle-manipulation`, `flash-loan`, `liquidation-logic`
- **E6 (6):** `share-price-inflation`, `economic-invariant`, `bridge-message`,
  `cross-chain-replay`, `frontend-injection`, `infra-boundary`

**An E6 key exists, so the plan's placeholder is the real value:** the committed test pins
`ClassConfirmFloor("share-price-inflation") == "E6"` verbatim from the map, and pins the
unknown-class default path (`"nonexistent-class"` → `"E5"` = `STATUS_FLOOR["CONFIRMED"]`).
The two classes the defect names are real: `dos-griefing: E4`, `logic-error: E4`.

**Box-cap accessor (`rg -n "E4|e4_capable" internal/envgo/env.go`):** envgo exports **no**
cap accessor. `e4_capable` is a **key of `envgo.Doctor`'s result** (`env.go:407`), and the
per-profile ceilings live in the **unexported** `profileMaxLevel` (`env.go:456`: the isolated
container profiles `E4`, `fork-runner` `E5`). `Doctor` also runs a `docker info` probe
(20s timeout) and a 5s fork-RPC probe. Resolution: `boxLocalCap = "E4"`
(`internal/briefing/briefing.go:2081`), the local container ceiling the environment records —
**read, not probed** (see concerns 1).

## Interfaces produced (exact signatures, all test-pinned)

```go
func ClassConfirmFloor(class string) string   // findings; map value, else STATUS_FLOOR["CONFIRMED"] ("E5")
func ReachableLocally(class, cap string) bool // findings; floor index <= cap index; unknown cap => false
func ReachabilityLine(classes []string, cap string) string // briefing; "" when classes is empty
```

## Rendering rules (implemented and pinned)

- Reachable classes first, fork-required classes second, **each group alphabetized**
  (`sort.Strings`), one class per clause with its own floor.
- Reachable clause: `CONFIRMED locally reachable for <c> (floor <F>)`.
- Fork clause: `fork required for <c> (floor <F> > <cap>)`.
- Line prefix `evidence reachability: `; clauses joined `"; "`.
- Edge cases pinned: all reachable → the fork clause is omitted entirely; all fork-required →
  the reachable clause is omitted and the line **starts** with `evidence reachability: fork
  required for `; empty/nil class list → `""` (no line rendered); unknown class → default E5.

## Step 1–2 — TDD red (log `task-3-logs/red.txt`)

```
go test ./internal/findings ./internal/briefing -run "Reachab|ClassConfirmFloor" -count=1
→ undefined: ReachabilityLine (7 sites), undefined: ClassConfirmFloor / ReachableLocally (9 sites)
  FAIL websec/internal/findings [build failed]
  FAIL websec/internal/briefing [build failed]
RED EXIT: 1
```

## Step 3 — implementation

- `NextActions` mint (`briefing.go:2216-2229`) sits **immediately after the Task 11 cold-probe
  warning block** (`briefing.go:2201-2214`) and before the probe-surface block.
- Classes come from `openFindingClasses` (`briefing.go:2088`): every finding that is not
  `findings.IsTerminal` (the shared dead-row predicate) and carries a non-empty
  `root_cause.class`, deduped; the findings-store read error propagates (the brief already
  fails on the same store via `Reachability`).
- Advisory only: no gate, proof, phase transition or status path reads `ReachabilityLine`,
  `ClassConfirmFloor` or `ReachableLocally`; the mint only appends a string to `next_actions`.
  The line embeds no command (pure prose), so the Task 7 `webv2 ` command-first law does not
  apply to it.

## Step 4 — gates (all exit 0)

| Gate | Result |
|---|---|
| `go test ./internal/findings ./internal/briefing -count=1` | ok (findings 0.798s, briefing 0.845s) |
| `go test ./... -count=1` | **71 packages ok**, 0 FAIL |
| `go vet ./...` | clean (empty log) |
| `scripts/golden.sh` | `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)` |
| `scripts/runbook-walkthrough.sh` | `150 passed, 0 failed` — `WALKTHROUGH GREEN` |
| `gofmt -l internal cmd` | clean (golden's own formatting gate passed) |

**No golden re-pin was needed** (the plan's `(golden: …)` clause did not trigger): `check-golden.py`
does not byte-compare `brief` stdout, and every fixture that does pin next-actions exactly —
the fresh `"Acme"` campaign, the Task 7 `lawBrief` (nil campaign) and the closed-pass campaign —
renders no line (no open class-bearing finding, or the closed branch returns early). Historical
fixtures untouched.

## The exact rendered line (real fixture, real run)

Fixture: fresh campaign in `DISCOVERY` with no probe emit on record + one `dos-griefing`
HYPOTHESIS finding. `task-3-logs/reachability-verbose.log`:

```
task14_reachability_test.go:92: cold-probe warning index 0, reachability line index 1:
  evidence reachability: CONFIRMED locally reachable for dos-griefing (floor E4)
```

The line the defect was about — CONFIRMED at E4 was locally reachable and the cockpit never
said so — is now the line the cockpit prints, at exactly `cold-probe index + 1`.

## Test summary (one line)

Focused `findings`+`briefing` green, `./...` 71 packages ok, vet clean, `GOLDEN GREEN`,
runbook 150/150 — all exit 0, no pin moved.

## Concerns / deviations

1. **The cap is a documented constant, not an envgo read** (`briefing.go:2081`). The plan's
   "Consumes … the box's E-cap recorded by the environment ceiling" has no exported accessor:
   `e4_capable` is a key inside `envgo.Doctor`'s result, whose computation shells `docker info`
   (20s timeout) and probes the fork RPC (5s). Doing that inside `NextActions` would make a
   documented PURE VIEW host-dependent, make every briefing unit test depend on the host's
   docker daemon, and hang the cockpit for up to 20s on a wedged daemon. `boxLocalCap` is
   therefore the recorded ceiling value (containers = E4), with a `ponytail:` note naming the
   upgrade path (wire `e4_capable` once the brief has a cached environment block). The value
   only moves on a box that cannot run containers at all, which `webv2 env doctor` already
   reports. Reviewer call: if the plan's intent was a live probe, that is a one-line change
   plus a `sandbox.SetDockerDaemonOK` stub in the ordering test.
2. **The line is prose, not a `webv2 …` command** (it carries parentheses). That is the plan's
   explicit carve-out ("this line is pure prose so no command is embedded"), and it is why the
   line is gated on `campaign != nil` + an open class: the Task 7 law fixtures (nil-campaign
   `lawBrief`, closed pass, fresh `"Acme"`) never render it. Any future fixture that pins a
   real campaign's next-actions **exactly** while carrying an open class-bearing finding will
   need a re-pin; that is deliberate per the plan, and no existing fixture did.
3. **"fork required" is the plan's rendering for every class above the cap**, so on a
   container-less box it also covers E4 classes (which need docker, not a fork). The text is
   advisory and the plan pins this exact form; a richer phrasing would break the pinned bytes.
4. **An unknown cap makes every class fork-required** (`ReachableLocally` refuses an
   unparseable ladder position, like `LevelIndex`). Unreachable from `NextActions` (cap is the
   constant); the behavior is pinned in the findings test so the renderer stays honest.
5. **Duplicate classes are deduped by the collector, not by `ReachabilityLine`**, keeping the
   renderer a literal function of its arguments (the contract the test pins).
