# Task 3 review — brief renders evidence-reachability per bug class (defect 5)

- **Scope:** commits `3c095827..280e348d` (single commit `280e348d`), worktree `.worktrees/production-readiness`.
- **Inputs:** plan `docs/superpowers/plans/2026-09-18-gold-findings-closure.md` §Task 3
  (mirrored in `task-3-brief.md`), `task-3-report.md`, `task-3-review-package.md` (diff),
  plus the live tree at `280e348d`.
- **Method:** read the full diff, re-derived every plan requirement against the committed
  code, then independently reproduced every gate from a clean go cache
  (`GOCACHE/GOMODCACHE` in `/tmp`, `GOTOOLCHAIN=local`). No tracked changes made.

## Verdicts

- **Spec compliance: YES** — one deviation from the plan's letter (the cap source),
  adjudicated below as compliant with the plan's intent; everything else is literal.
- **Task quality: APPROVED** — 1 LOW finding (test comment overclaims a pin), non-blocking.

## Global constraints

| Constraint | Verdict | Evidence |
|---|---|---|
| Advisory only (no gate/proof/phase transition reads the line) | PASS | `rg` over the tree: `ReachabilityLine` is called only from the `NextActions` mint (`internal/briefing/briefing.go:2227`); `ReachableLocally`/`ClassConfirmFloor` have no callers outside `briefing.go` + the two new tests. No `gate/proof/phase` package references them. |
| Task 7 command-first law carve-out for pure prose | PASS | The rendered line embeds no `webv2 ` command; it is gated on `campaign != nil` + a non-empty class list, and `TestReachabilityLineNeedsAnOpenClass` proves the Task 7 law fixtures' shapes (nil campaign / class-less) never render it. The plan's Step 3 text explicitly carves this out ("this line is pure prose so no command is embedded"). |
| No golden pin moved | PASS | The commit touches exactly the 4 planned files (diffstat); no fixture under golden coverage changed. Independently reran `scripts/golden.sh` at `280e348d`: `GOLDEN GREEN`. No golden fixture contains an open class-bearing finding that pins `next_actions` exactly, so the plan's conditional re-pin clause correctly did not trigger. |
| Historical fixtures untouched | PASS | No changes under `scripts/legacy/`, `web3sec-final/`, `morph/`, or any pinned fixture in the diff; runbook walkthrough independently rerun: `150 passed, 0 failed — WALKTHROUGH GREEN`. |
| Floor values pinned from the REAL map | PASS | Step 0 verified against `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR`: E6 keys exist — `share-price-inflation: "E6"` is the committed pin, exactly the map's value (16 keys: 9×E4 incl. `dos-griefing`/`logic-error`, 3×E5, 6×E6). Unknown class → `STATUS_FLOOR["CONFIRMED"]` = `"E5"`. Nothing assumed. |
| No map changes / `levels.go` accessors pure | PASS | The `levels.go` diff is additive only (two accessors + comments); `CLASS_CONFIRM_FLOOR`, `STATUS_FLOOR`, `EVIDENCE_ORDER` bytes unchanged. |

## Plan requirements vs diff

1. **Three accessors, exact signatures** — PASS.
   `findings.ClassConfirmFloor(class string) string` (map value, else `STATUS_FLOOR["CONFIRMED"]`),
   `findings.ReachableLocally(class, cap string) bool` (ladder-index compare via `LevelIndex`,
   refusing unknown cap/class like `LevelIndex` does), `briefing.ReachabilityLine(classes []string, cap string) string`.
   All three exported, in the packages the plan names, all test-pinned.
2. **Rendering rules + edge cases** — PASS.
   - Reachable-first, fork-second, each group `sort.Strings`-alphabetized — pinned by the
     multi-class exact-bytes assertion (`dos-griefing`, `token-integration` reachable;
     `bridge-message`, `economic-invariant` forked).
   - One class per clause with its own floor — pinned byte-exactly, superseding the plan's
     own earlier comma-joined prose, as directed.
   - All reachable → no "fork required" substring; all fork → no "locally reachable" substring
     **and** `strings.HasPrefix(..., "evidence reachability: fork required for ")` — both pinned.
   - Empty list (`nil` and `[]string{}`) → `""` — both pinned.
   - Clause text matches the plan's pinned form verbatim, including `(floor <F> > <cap>)`.
3. **Ordering pin after the cold-probe warning** — PASS.
   The mint (`briefing.go:2216-2229`) sits immediately after the Task 11 cold-probe block
   (`briefing.go:2201-2214`) and before the probe-surface block. `TestReachabilityLineFollowsColdProbeWarning`
   builds a DISCOVERY fixture with both lines and asserts `reachIdx == coldIdx+1` exactly
   (via the shared `task11HasColdLine` predicate), plus the rendered bytes.
4. **Step 0 real-floor-map rule** — PASS. See table above; the report records the full
   16-key read and the "E6 key exists → placeholder was the real value" conclusion.
5. **Render condition** — PASS (beyond the plan's minimum). `openFindingClasses` filters
   terminal rows (`findings.IsTerminal`) and empty `root_cause.class`, dedupes, and
   propagates the findings-store error (fail-soft is correctly rejected — the brief already
   fails on the same store via `Reachability`).

## Concern 1 adjudication (the cap: documented constant vs envgo read) — COMPLIANT

**Facts verified in the tree at `280e348d`:**
- The plan's Interfaces section says the cap comes from "the environment ceiling" and directs
  the implementer to `rg -n "E4|e4_capable" internal/envgo/env.go` **for the accessor name**.
  That accessor does not exist: `e4_capable` is a **key inside `envgo.Doctor`'s returned
  object** (`internal/envgo/env.go:407`), not an exported Go symbol, and the per-profile
  ceilings live in the **unexported** `profileMaxLevel` (`env.go:456`).
- The only in-repo ways to obtain the ceiling are (a) run `Doctor`, which shells
  `docker info` with a 20s timeout (`env.go:184`, `env.go:657`) and probes the fork RPC —
  a host-dependent probe inside a documented pure view — or (b) modify `env.go` to export
  an accessor, a file outside the plan's Files list.
- The constant the implementer pinned (`boxLocalCap = "E4"`, `briefing.go:2081`) **equals**
  the environment's recorded ceiling for every isolated container profile
  (`profileMaxLevel`: `docker-networkless`/`docker-gvisor`/`vm-snapshot` → E4; `fork-runner`
  → E5, which is the fork path the line's "fork required" clause already names).

**Ruling:** the documented constant with a named upgrade path **satisfies the plan**. The
plan's premise (an exported envgo cap accessor exists to consume) is factually false, so a
literal implementation is impossible within the plan's own file list and its "pure view"
architecture; the implementer chose the only reading that keeps the brief pure, and the
chosen value is the recorded ceiling, not an invention. The deviation is disclosed in the
report and carries a `ponytail:` comment at the constant naming the upgrade path. A live
probe would have been the actual spec violation (host-dependent pure view, 20s wedge).

**Follow-up (not a gap):** the cleanest literal-compliance upgrade is not a live probe but a
pure, non-probing accessor exported from `envgo` over `profileMaxLevel` (a map read, no
docker) — `briefing` already may import `envgo` without a cycle (`envgo` imports only
`findings/floors/sandbox/state/validation`). When the brief gains a cached environment
block, wire that in; the `ponytail:` note is the right hook.

## Concerns 2–5 adjudication (all accepted)

- **2 (prose line, no command):** correct per the plan's explicit carve-out; the gating on
  `campaign != nil` + open class keeps the Task 7 law fixtures clean, and the report honestly
  flags the future-fixture re-pin condition. Accepted.
- **3 ("fork required" also covers E4 on a container-less box):** the plan pins the exact
  bytes; a richer phrasing would break the pin. The advisory text is directionally right
  (E4 needs docker; E5+ needs a fork). Accepted as plan-conformant.
- **4 (unknown cap → everything fork-required):** matches `LevelIndex`'s refusal semantics;
  unreachable from `NextActions` (cap is the constant) and pinned in the findings test so the
  renderer stays honest. Accepted.
- **5 (dedupe in the collector, not the renderer):** keeps `ReachabilityLine` a pure function
  of its arguments, which is what the pinned contract tests. Accepted.

## Findings

1. **LOW — test comment overclaims a pin.** `internal/briefing/task14_reachability_test.go:245-247`
   (`TestReachabilityLineNeedsAnOpenClass`) says the test pins "no open finding carries a class
   → no line, **and a terminal finding is not open work**", but the body only exercises the
   class-less campaign; no terminal (e.g. DISPROVED) class-bearing finding is added.
   **Fix:** append a case that seeds a terminal class-bearing finding and asserts no
   `evidence reachability: ` line is rendered (or drop the clause from the comment).
   Non-blocking — the production behavior is correct; only the documented pin is missing.

## Observations (no action required)

- `boxLocalCap = "E4"` is pinned only behaviorally (the ordering test's rendered bytes imply
  cap E4 for an E4-floor class). A direct `boxLocalCap != "E4"` assert would future-proof the
  upgrade path — the same edit that wires the envgo accessor will touch it anyway.
- `ReachabilityLine`'s parameter name `cap` shadows the builtin; the plan mandates that exact
  signature, the body never uses the builtin, and `go vet` is clean. Plan-conformant, leave it.
- The reachability mint runs for every non-closed campaign regardless of phase (the cold-probe
  warning is DISCOVERY-gated); the ordering pin holds in the both-present fixture, which is all
  the plan requires.

## Cannot-verify items

None. Every gate in the plan's Step 4 was independently reproduced at `280e348d`:

| Gate | Independent result |
|---|---|
| `go test ./internal/findings ./internal/briefing -run "Reachab\|ClassConfirmFloor" -count=1` | ok |
| `go test ./... -count=1` | 71 packages ok, 0 FAIL |
| `go vet ./...` | clean |
| `scripts/golden.sh` | `GOLDEN GREEN` |
| `scripts/runbook-walkthrough.sh` | `150 passed, 0 failed — WALKTHROUGH GREEN` |

(One environmental note: the sandbox's default `GOCACHE/GOMODCACHE` are read-only; gates were
run with temp caches and `GOTOOLCHAIN=local` — go1.26.6, matching `go.mod`'s toolchain line.)
