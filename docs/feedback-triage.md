# Triage: webv2 framework feedback (campaign C-66191ec8cd) — Go port

**Inputs**

- `../morph/webv2-framework-feedback.md` — operator evaluation of the first
  full campaign (11 items: 8×P1, 9×P2, 3×P3 + prioritized recommendations).
- `../morph/webv2-eval-post-gold.md` — post-answer-key evaluation (G-01 miss,
  §5 design changes).
- Campaign artifact: `../morph/campaigns/C-66191ec8cd/`.

**Status of the twins.** The Python reference (`web3sec-final`) was the
version the campaign ran on and is now deprecated. This triage verifies
**every claim against the Go port** (`web3sec-go` HEAD); Python is cited only
to confirm a claim was not already ported away. The "Python wins" 1:1 rule is
lifted for bug fixes: every fix below is an *intentional* divergence from the
deprecated reference and needs a `KNOWN_DIVERGENCES.md` row (see Process
notes).

**Method.** Each item was re-verified against Go source (file:line below) and,
where the operator diagnosed a mechanism, the mechanism itself was checked
against code *and* the campaign artifact. One mechanism claim turned out to be
wrong (P2-7a) while its symptom was real — see Misdiagnoses.

**Cross-ref:** `docs/python-twin-issues.md` already tracked feedback-P2-2 as
its **P3** (`ladder explore` positional trap, with repro and proposed fix) and
a sibling toolchain bug as its **P1** (wrong TOML key `sol` vs `solc`).

---

## TL;DR

| bucket | count | items |
|---|---|---|
| Confirmed live in Go, small fix (< ~30 lines) | 10 | A1–A10 (P1-3, P1-6, P2-1, P2-4, P2-5, P2-6, P2-7, P2-8, P2-9) |
| Confirmed live in Go, medium fix | 5 | B1–B5 (P1-2, P1-4, P1-5, P1-7, P1-8) |
| Confirmed missing, good feature asks | 7 | C1–C7 (P1-1, P2-2, P2-3, P3×2, eval §5-6, §5-7) |
| Confirmed missing, design changes (need a call) | 2 | D1–D2 (eval §5-1, §5-2) |
| Misdiagnosed mechanism, real symptom | 1 | P2-7a (counted in A10) |
| Opinion/tuning sub-claims, not bugs | 2 | P3 "rows duplicated findings"; eval "10 FPs" |

(eval §5-3…§5-7 are not separate items: they alias P1-2/P1-1/P1-3…7 and land
in tiers B/C above; only §5-1 and §5-2 are net-new design asks — D1 and D2.)

No item is pure frustration-without-a-bug. The operator's P1 list is 100%
confirmed in Go (8/8). The single highest-value change overall is **D1, the
disposition linter** — it is the only change that would have caught the
campaign's actual failure (G-01 missed at rank 1 of the probe surface).

---

## Verdict table

| feedback item | verdict | Go evidence | tier | status (2026-09-09) |
|---|---|---|---|---|
| P1-1 no amend/supersede path | confirmed gap | no finding amend anywhere (only plan/floor supersede) | C1 | open — feature ask |
| P1-2 immunization gate, no waiver | **confirmed bug** | `bounty/bounty.go` immunization check vs waiver branch | B1 | **FIXED** — waiver branch + seam; `go test` green |
| P1-3 `not-applicable` not closed in work_queue | **confirmed bug** | `planner/queue.go:78` | A1 | **FIXED** — `not-applicable` in closed set (`queue.go:82-83`) |
| P1-4 `ladder reopen` referenced, missing | **confirmed bug** | `maximization/maximization.go:404-405`; choices `cli/cmd_t23_shared.go:47-48` | B2 | **FIXED** — `ReopenLadder` (`maximization.go:880`) + action row |
| P1-5 gate rejects `CONTRADICTED` | **confirmed bug** | `invariants/guard.go` `IsVerified` | B3 | **FIXED** — accepts `CONTRADICTED` (`guard.go:73`) |
| P1-6 mint idempotent per exec only | **confirmed bug** | `cli/cmd_mint.go:141-146` | A2 | **FIXED** — key on `(exec, type)` |
| P1-7 scope: contract name vs path entries | **confirmed bug** | `bounty/bounty.go` scope check, `scopeTargets` | B4 | **FIXED** — name→path via index (`SetContractPathResolver`) |
| P1-8 probe anchors trusted, not validated | confirmed gap | `probes/emit.go:204` passthrough | B5 | **FIXED** — `resolveAnchorToken` validates against index |
| P2-1 no `FOUNDRY_LINT_ON_BUILD` default | **confirmed bug** | string absent repo-wide; env assembly `sandbox/profiles.go` | A3 | **FIXED** — var added to foundry profile env |
| P2-2 `ladder explore` positional trap | **confirmed bug** (python-twin-issues P3) | `cli/cmd_ladder.go` | C3 | **FIXED** — trailing positional binds axis (D30) |
| P2-3 learning stage API-only | confirmed gap (half done: `hint` exists) | `cli/cmd_memory.go`; `completion/proofs2.go` | C2 | open — feature ask |
| P2-4 doctor overstates usability | **confirmed bug** (both halves) | `cli/cmd_env.go`; floor loop `envgo/env.go` | A7 | **FIXED** — doctor pre-runs floor checks |
| P2-5 silent empty `verify --queue`, raw-JSON `prove` | **confirmed bug** | `cli/cmd_verify.go`; `cli/cmd_prove.go` | A6 | **FIXED** — "queue empty" + human-readable prove |
| P2-6 adapter → legacy `protocol-model` prompt | **confirmed bug** | `adapter/adapter.go:96` (bootstrap uses `prompts/37`) | A4 | **FIXED** — constant repointed |
| P2-7 snap false exclusions + nested foundry.toml | **real symptom, mechanism misdiagnosed** + **confirmed bug** | `snapshot/pin.go`; `snapshot/toolchain.go` | A10, A9 | **FIXED** — nested `foundry.toml` walk + scope fix |
| P2-8 `stages 19/17` | **confirmed bug** (root cause: sub-stages in ledger) | `orchestrator/{discovery,triage,verify}.go` `SetStage`; `briefing.go` | A5 | **FIXED** — count distinct top-level stages |
| P2-9 report-freshness proof permanently red | **confirmed bug** | `report/report.go`; `completion/proofs2.go:199-232` | A8 | **FIXED** — freshness ⟺ log head is `report.generated` |
| P3 mint message (different type) | part of P1-6 | same lines | A2 | **FIXED** (with A2) |
| P3 probe batch disposition | feature ask | `probes` CLI = run/list/blank only | C4 | open — feature ask |
| P3 ladder `other` axis | feature ask | 5 fixed axes `maximization/maximization.go` | C5 | open — feature ask |
| eval §5-1 disposition linter | confirmed gap — **the G-01 miss** | no reason-text check in `planner/answered.go` / `probes/closure.go` | D1 | open — design change |
| eval §5-2 liveness/chain-freeze terminal | confirmed gap | no liveness terminal in `taxonomy/` or `chainengine/terminal.go` | D2 | open — design change |
| eval §5-3 waiver story | = P1-2 | — | B1 | **FIXED** (with B1) |
| eval §5-4 amend/supersede | = P1-1 | — | C1 | open — feature ask |
| eval §5-5 closure/status drift | = P1-3/4/5/6/7 | — | A1,B2,B3,A2,B4 | **FIXED** (with A1/B2/B3/A2/B4) |
| eval §5-6 high-signal dismissals section | confirmed gap | no such section in `report/report.go` | C6 | open — feature ask |
| eval §5-7 campaign severity floor | confirmed gap (per-finding gate floor exists) | `bounty/bounty.go` is per-finding only | C7 | open — feature ask |

**Bug-hunt sweep (this review):** beyond the campaign feedback above, a full
code review found and fixed 15 additional defects (below, "Bug-hunt
findings C1–C13" + the B5 anchor helper + one dedup keep-side gap). Each has a
regression test; the full `go test ./...` suite and `scripts/golden.sh` are
green. These are Go-internal bug-fixes (no Python-compat obligation — the Go
twin is the source of truth) and do not change golden bytes, so they carry no
`KNOWN_DIVERGENCES` normalization.

---

## Tier A — confirmed bugs, small fixes (< ~30 lines each)

**All of Tier A (A1–A10) is FIXED and green** as of the 2026-09-09 full
review (Go is the source of truth; the Python twin is deprecated and no
longer tracked for compatibility). Each fix carries a regression test; the
full `go test ./...` suite and `scripts/golden.sh` are green. (Separate from
the `python-twin-issues.md` P1–P8 set, which was fixed 2026-09-09 — see its
status headers.) The per-item **Fix** lines below are now the *applied* fix.

### A1 = P1-3 — `not-applicable` does not close a priority
`internal/planner/queue.go:78` skips only `answered | deprioritized`, so a
priority closed as `not-applicable` (a legitimate closing status, used by the
discovery stage) re-enters every work queue and the discovery proof can never
complete. **Fix:** add `"not-applicable"` to the closed set (1 line + test).
Campaign evidence: stage 4 blocked on a priority the operator had closed.

### A2 = P1-6 (+ P3 "mint says already minted") — mint idempotency ignores type
`internal/cli/cmd_mint.go:141-146` matches on `artifact_id == execID` only,
so minting the same exec with a *different* evidence type hits "already
minted — idempotent no-op" and the second evidence never lands; the economic
floors then demand a duplicate run. **Fix:** key the check on
`(exec, type)` and reword the message for the same-type case (~10 lines).

### A3 = P2-1 — `FOUNDRY_LINT_ON_BUILD` not defaulted
The string is absent repo-wide; `forge build` panics on first run of any
Solidity target unless the operator hand-sets
`FOUNDRY_LINT_ON_BUILD=false`. Env assembly is `internal/sandbox/profiles.go`
(foundry profile, ~L260). **Fix:** add the var to the foundry profile env
(1–2 lines) — this is also recommendation #10 in the feedback.

### A4 = P2-6 — adapter points at the legacy protocol-model prompt
`internal/adapter/adapter.go:96` still references the legacy `protocol-model`
prompt path while the bootstrap uses `prompts/37`. **Fix:** repoint the
constant (1 line + prompt-path test).

### A5 = P2-8 — `stages 19/17`
The stage counter reports 19 of 17 because sub-stages land in the stage
ledger: `internal/orchestrator/{discovery,triage,verify}.go` `SetStage`
emits sub-stages; the total is counted in `internal/orchestrator/briefing.go`
(~L1322-1326, L1411). **Fix:** count distinct top-level stages, or emit
sub-stages under a prefixed key the counter excludes (~15 lines).

### A6 = P2-5 — silent empty output
`verify --queue` prints nothing when the queue is empty
(`internal/cli/cmd_verify.go:163-180`) and `prove` dumps raw JSON
(`internal/cli/cmd_prove.go:56`). **Fix:** a one-line "queue empty — nothing
to verify" and a human-readable prove summary (~10 lines).

### A7 = P2-4 — `env doctor` overstates usability
`internal/cli/cmd_env.go:143-156` reports capabilities as usable when the
floor loop in `internal/envgo/env.go` (~L445-470) would refuse them
(both halves: the doctor's OK line and the floor's refusal text). **Fix:**
doctor should pre-run the same floor checks and mark "present, floor will
refuse" distinctly (~20 lines).

### A8 = P2-9 — report-freshness proof permanently red
`internal/report/report.go:355-365,834` stamps the event-log head *before*
logging the report-emitted event, and `internal/completion/proofs2.go:199-232`
then compares strictly — the proof can never pass. **Fix:** log first, stamp
second (or compare `>=`) — recommendation #11 in the feedback (~10 lines).

### A9 = P2-7b — nested `foundry.toml` missed
`internal/snapshot/toolchain.go:26` reads only the top-level `foundry.toml`;
a monorepo target with the config under `contracts/` gets no toolchain
line. (The `sol`-vs-`solc` half of P2-7 was fixed 2026-09-09, see
`python-twin-issues.md` P1.) **Fix:** walk the pinned tree for the first
`foundry.toml` (~15 lines + test vector).

### A10 = P2-7a — `snap` false scope loss
`internal/snapshot/pin.go:141-158` excludes paths the operator expected to be
in scope. The *symptom* is real and reproduced; the operator's *mechanism*
diagnosis was wrong — see Misdiagnoses before touching this.

---

## Tier B — confirmed bugs, medium fixes (need a small design choice)

**All of Tier B (B1–B5) is FIXED and green** as of the 2026-09-09 full
review. Each carries a regression test; the full `go test ./...` suite and
`scripts/golden.sh` are green.

### B1 = P1-2 (+ eval §5-3) — immunization gate has no waiver branch
`internal/bounty/bounty.go:915-924` requires the immunization evidence
unconditionally, while every sibling check at `bounty.go:887-911` carries a
waiver branch. With the fork waived, `submission_ready` is unreachable — the
whole submission tier of the campaign died here. **Fix:** add the waiver
branch (waiver exists → immunization check recorded as waived, not failed;
report shows it as a caveat, matching how waivers render elsewhere)
(~30–50 lines + report rendering test).

### B2 = P1-4 (+ eval §5-5) — `ladder reopen` referenced but missing
`internal/maximization/maximization.go:404-405` tells the operator to run
`webv2 ladder reopen`, but the action list in
`internal/cli/cmd_t23_shared.go:47-48` has no `reopen`. **Fix:** implement
`reopen` (ladder status → open, reason + actor logged, idempotent on an open
ladder) + add to the action list and usage text (~40 lines). Note the usage
text change is a golden byte-diff surface: add a divergence row and, if the
recipe drives `ladder --help`, normalize it.

### B3 = P1-5 (+ eval §5-5) — invariant gate rejects `CONTRADICTED`
`internal/invariants/guard.go` (`IsVerified`, ~L76) accepts exactly
`CHECKED_AGAINST_CODE`; `CONTRADICTED` — the strongest outcome (the invariant
is falsified, i.e. the attack works) — is gated out, so operators game the
status. The `invariant.contradicted` event type already exists
(`internal/invariants/invariants.go:760`). **Fix:** accept `CONTRADICTED`
as a confirming verdict alongside `CHECKED_AGAINST_CODE` (~20 lines + test).

### B4 = P1-7 (+ eval §5-5) — scope matches contract name vs path entries — **FIXED 2026-09-09**
`internal/bounty/bounty.go:205-217` (scope check) and `targetOf`
(`:518-525`) compare a finding's contract *name* against scope *path* entries,
so a path-based scope policy never matches a name-carrying finding — the
campaign saw a false "everything is out of scope". **Fix (applied):** the
scope check now matches a name-carrying finding against the name *and* the
path the name resolves to via the structural index (`structidx.ContractPath`,
wired into `bounty.SetContractPathResolver` by the CLI's `ensureSeams`, which
is the top module free of the structidx→orchestrator→bounty import cycle). A
nameless finding falls back to its recorded path, exactly as before; the
`out_of_scope` vector (name `RandomToken` + path `src/Vault.sol`) is unchanged
because the recorded path is not a candidate for a name-carrying finding.
Regression: `TestScopeResolvesContractNameToPath` (bounty). Golden green.

### B5 = P1-8 — probe anchors trusted, not validated
`internal/probes/emit.go:204` passes the operator-supplied anchor through
unchanged; 9 of 32 rows in the campaign were mis-anchored. **Fix:** validate
the anchor against the structural index and refuse (or loudly warn on) a
symbol that does not exist in the pinned snapshot (~40 lines + fixtures).

---

## Tier C — confirmed gaps, good feature asks

### C1 = P1-1 (+ eval §5-4) — no amend/supersede path for findings
Nothing in the Go tree amends a finding: the only supersede mechanism is
plan/floor supersede. The campaign's record therefore kept claims an
independent verifier had *refuted*. **Ask:** `webv2 amend C F --patch
<json> --reason R` (append to the finding's `history`, re-validate, log
`finding.amended`) plus supersede (mark the old finding `SUPERSEDED_BY`,
ingest the new one as its child). ~150 lines; touches the finding schema
(additive) — needs a divergence row only if the reference schema is frozen
against the new status.

### C2 = P2-3 — learning stage is API-only
`internal/cli/cmd_memory.go` exposes only list/approve; the learning-stage
proofs (`internal/completion/proofs2.go:288-297`) reference API entry points
that have no CLI verb. A `hint` command already exists (half the ask is
done). **Ask:** the remaining learning verbs as CLI (stage-45 surface).
~80 lines, mechanical.

### C3 = P2-2 — `ladder explore` positional trap — **FIXED 2026-09-09**
Tracked as `python-twin-issues.md` P3 and divergence **D30**. The natural
form `explore F <axis>` now works in Go; the legacy dummy-rung form is
unchanged. Pinned by `TestLadderExploreNaturalAxisForm`.

### C4 = P3 — probe disposition batch input
Per-row `--anchor` + reason across 32 rows (and 57 blind-key attestations)
was "the single largest operator-time sink". **Ask:**
`webv2 probes --file rows.json` (batch disposition) plus auto-anchoring from
the structural index (propose the anchor, operator confirms). ~120 lines;
pairs well with B5 (batch input makes anchor validation matter more).

### C5 = P3 — ladder `other` axis
The five axes are fixed (`internal/maximization/maximization.go:29-30`); the
campaign's strongest variant (`R-73cc9b`, unbacked ETH against the L1 pool)
fit only loosely. **Ask:** an `other` axis requiring a written justification
(≥ N chars, same rule as not-applicable notes) (~30 lines).

### C6 = eval §5-6 — report section for high-signal dismissals
`report.md` "hides judgment calls": it closes with "32 rows
dispositioned" and no trace of the rows that were dismissed *despite strong
reaching*. **Ask:** a "dismissed with reaching" section in
`internal/report/report.go` listing dismissed rows whose reason text exceeds
a signal threshold (or carries a blind-key attestation). ~60 lines.

### C7 = eval §5-7 — campaign severity floor
`internal/bounty/bounty.go:603-613` implements a *per-finding* gate floor;
nothing forces the *campaign* to reach a severity bar. **Ask:** a campaign
floor (`floors set --severity CRITICAL`) that `gate` reports as its own
check: "campaign has no CRITICAL finding" is a named, waivable gate output.
~50 lines.

---

## Tier D — design changes (need a call before code)

### D1 = eval §5-1 — the disposition linter (the G-01 miss)
**The only change on this list that would have caught the campaign's actual
failure.** G-01 (the gold) sat at rank 1 of the probe surface and was
discharged `answered` (safe) with an anchor + free prose; the framework
accepted it because a row is "an obligation to look, not a claim" and the
reason text is never checked. The eval's own cheapest guard, verified
against the campaign ledger: scan disposition reasons for dismissal
vocabulary (`liveness-only`, `owner-revert*`, `not exploitable`, `never
permanently`, `until the owner`, …) — in this campaign 3/32 dispositions
contained a dismissal keyword, and the set is *exactly* the three
dispositions that buried G-01. A ten-line regex plus one rule — "a tier-0 or
gap≥3 row may not be discharged `answered` on a compensating-control
argument without an exec-backed or invariant-backed refutation" — converts
the primary failure into a mandatory re-review. **Ask (layered):**
1. **linter v1 (warning, ~20 lines):** dismissal-vocabulary scan on
   tier-0/gap≥3 rows at disposition time, surfaced in `brief`/`report`.
2. **linter v2 (refusal, ~80 lines):** the rule above as a hard gate with a
   named override (`--override-dismissal --reason`).
3. **linter v3 (structural, ~150 lines):** reason text must reference a
   symbol/contract from the row's own surface entry (checkable against the
   structural index, same seam as B5); a dismissal citing another finding
   must cite a real finding id.
The call is which layer ships, and where the override lives.

### D2 = eval §5-2 — liveness as a first-class impact
The impact model has no liveness terminal: `internal/taxonomy/` and
`internal/chainengine/terminal.go` express economic outcomes but not
"the chain halts / sequencing stops". G-01's real impact (sequencer liveness)
was therefore unpriceable and under-ranked. **Ask:** a liveness impact class
(terminal `LIVENESS_LOSS` with severity mapping) in the taxonomy + chain
engine, wired into `impact` pricing as non-economic. ~200+ lines, touches
the schema (additive) — a real design item, not a patch.

---

## Bug-hunt findings C1–C13 (full-review sweep, FIXED 2026-09-09)

A whole-repo review (independent of the campaign feedback above) surfaced 15
more defects. All are Go-internal bug-fixes — the Go twin is the source of
truth, so there is no Python-compat obligation and no golden byte-diff (the
golden fixtures do not exercise these paths). Each fix has a regression test;
`go test ./...` and `scripts/golden.sh` are green. (Distinct from the Tier C
*feature asks* above — same letters, different scope.)

- **C1 — audit sections panic on a short stored hash.** `S[:12]` panics when a
  tampered/truncated hash is < 12 bytes. Fixed with the existing `trunc12`
  helper: `audit/sections/artifacts.go:48`, `audit/sections/snapshots.go:63`.
  Regression: `TestTrunc12ShortAndLong`.
- **C2 — report evidence-level 1-element blind spot.** the `badLevel` flag
  lived only in the `sort.SliceStable` comparator, which is never invoked on a
  1-element slice, so a single bad level rendered silently. Fixed: validate
  every level up front. `report/report.go:1049`. Regression:
  `TestEvidenceLevelSingleItemValidated` (+ `...ValidRenders`).
- **C3 — `closed_ref` empty string not flagged.** only a `null` ref was
  treated as "no ref"; an empty-string ref slipped through unflagged. Fixed:
  `noRef = null || (str && "")`. `report/report.go:575`. Regression:
  `TestClosedRefEmptyStringFlagged`.
- **C4 — `pyEqual` no key-set comparison.** `objAt` returns `VNull` for an
  *absent* key, so `{a:null}` vs `{b:null}` compared equal. Fixed: verify the
  key sets match before comparing values. `audit/sections/unpriceable.go:123`.
  Regression: `TestPyEqualDifferingNullKeys`.
- **C5 — `autoMergePair` asymmetric snapshot check.** only the `dup` side was
  checked for cross-snapshot; a `keep` from a different snapshot was silently
  merged. Fixed: check both sides. `dedup/dedup.go:415`. Regression:
  `TestAutoMergePairKeepSideCrossSnapshotFlags`.
- **C6 — `RunDedup` live-filter incomplete.** only `DUPLICATE`/`OUT_OF_SCOPE`
  were excluded from the sweep; `DISPROVED`/`CHAIN`/`INFORMATIONAL` entered the
  grouping and the sweep aborted on an illegal transition. Fixed: exclude all
  five non-duplicatable states. `dedup/dedup.go:238`. Regression:
  `TestRunDedupExcludesNonDuplicatableStates`.
- **C7 — `phases.Complete` duplicate keys on re-Complete.** `append` produced
  duplicate `completed_by`/`completed_reason` keys on a second `Complete`.
  Fixed with `setOrAppend`. `state/phases.go:113`. Regression:
  `TestCompleteReplacesNotDuplicatesKeys`.
- **C8 — `collectFiles` dangles on symlinks.** non-regular entries (symlinks,
  FIFOs) were appended, then `os.ReadFile` in the caller aborted the whole
  index build. Fixed: skip non-regular files. `structidx/parser.go:924`.
  Regression: `TestCollectFilesSkipsNonRegularEntries`.
- **C9 — `criticality` state objects not tokenized.** `critTokens` is
  string-only, so a state machine whose *state id* (an object) names a
  contract failed to lift that contract to consensus-critical. Fixed: tokenize
  the state `id`. `structidx/criticality.go:92`. Regression:
  `TestCriticalityTokenizesStateIDs`.
- **C10 — `surfaceAxis` filtered/unfiltered index mismatch.** the filtered
  index `i` was applied to the unfiltered list, returning the wrong axis after
  a non-object prefix. Fixed: return the matched element directly.
  `probes/blanks.go:14`. Regression: `TestSurfaceAxisSkipsNonObjectPrefix`.
- **C11 — `ListCampaigns` skips symlinked dirs.** `entry.IsDir()` reports the
  link (not the target), so a symlinked campaign dir was dropped. Fixed with
  `os.Stat`. `state/campaign.go:217`. Regression:
  `TestListCampaignsIncludesSymlinkedDirs`.
- **C12 — `AllExecs` glob metacharacters.** `filepath.Glob` treats the whole
  path as a pattern, so a `[`/`]`/`?` in the campaign root matched nothing.
  Fixed: `os.ReadDir` + prefix filter. `state/execs.go:20`. Regression:
  `TestAllExecsHandlesGlobMetacharacters`.
- **C13 — `BlankReasonMin` byte vs char count.** `len()` counted bytes, so a
  short multibyte reason (few chars, many bytes) passed the minimum. Fixed:
  `utf8.RuneCountInString`. `probes/blanks.go:110`. Regression:
  `TestBlankReasonMinCountsCharsNotBytes`.
- **B5 (anchor helper) — probe anchors trusted, not validated.** the
  `resolveAnchorToken` helper now skips a contract that resolves to no real
  path (with an index) instead of fabricating a `Name#L` citation; pathless
  nodes are omitted from `contractPaths`. `probes/util.go`, `probes/shape.go`.
  Regression: `TestResolveAnchorTokenB5`, `TestContractPathsOmitsPathlessNodes`,
  `TestRowAnchorPairsSkipsUnknownContractWithIndex`.

---

## Misdiagnoses

### P2-7a — the mechanism was wrong; the symptom was real
The operator diagnosed the false-scope-loss noise as "substring matching in
`_excluded_names_in`". It is not substring matching: `excludedNamesIn`
(`internal/snapshot/pin.go:141-158`) does an **exact-name** map lookup
(`names[d.Name()]`) and `pruneExcludes` (`pin.go:94-136`) prunes exact
name-matches **at any depth**. The noise comes from **top-level
aggregation**: both helpers report only the first path component of each
match, so a deep exact match inside an in-scope directory makes that whole
top-level directory appear "excluded" in the `snap` output. The prune set
(`internal/snapshot/hashing.go:23` + `internal/snapshot/ladder.go:19`) is
full of generic names — `out`, `build`, `data`, `dist`, `cache` — so any
monorepo project tree containing e.g. `…/out/` or `…/data/` at depth
triggers it (this campaign: `contracts/` as a nested project root).
**Correct fix for A10:** report the actual matched subpaths (or a
`top-level (deep match at …)` form) instead of the aggregated top-level
name; the prune itself stays — `out`/`build` at depth are build artifacts.
Do **not** "fix" this by changing the matching to substrings or by removing
generic names from the set; either would regress the design.

---

## What the agent was frustrated by (the G-01 miss, from the eval)

The campaign's 11 confirmed findings were all reached by the framework; the
one gold it missed (G-01, ranked critical by the eval) was missed in a
specific, structural way:

- Four probe rows triangulated G-01 (the check sits in the wrong lifecycle
  stage; the challenge validates the committed header; commit deliberately
  defers the linkage; finalization is a strictly sequential cursor). All
  four were discharged `answered` (safe) — and read in sequence, the four
  dismissal reasons **are** G-01, minus the conclusion.
- The conclusion was excluded by a single judgment: *"owner-revertable" ⇒
  not a finding*. The threat model treats owner intervention as recovery,
  and the policy exclusions make privileged-role behaviour out of scope
  "unless it causes permanent loss" — so a chain frozen until the owner
  sends a transaction read as temporary. The eval's severity model calls it
  critical; the framework had no mechanism to disagree with the operator
  here, because **nothing checks the reason text**, no invariant said
  "a committed batch is always finalizable", and the report presents
  "32 rows dispositioned, 0 open" as a clean bill of health.
- It was not operator sloppiness and not a code bug: the operator did the
  looking the rows asked for, and the discharge contract accepted what was
  written. The frustration was that the system's strongest signal
  (rank-1/tier-0/gap-4 rows) carried no more weight than a stale
  `updateGasLimitAddStaker` conjunction.

That is why D1 is ranked first: it is the only item that addresses the
actual failure mode. A2–B5 and C4–C7 are real and worth doing, but none of
them would have changed this campaign's outcome.

---

## Process notes

1. **The "Python wins" 1:1 rule is lifted for bug fixes.** The reference is
   deprecated (operator decision 2026-09-09, `docs/gates/P4-gate.md` §9.1:
   "do not touch the Python repository — the Go repository is the
   deliverable"). Every fix applied to Go for a reference bug is an
   *intentional divergence*: it needs a `KNOWN_DIVERGENCES.md` row (What was
   / Fix Go-only / Golden / Status), and the golden recipe must keep
   avoiding the fixed path so the byte-diff against the buggy reference
   stays green. Applied this way for D14 (P2) and D30 (P3); D23 was closed
   as a fixed papercut (Go was already correct).
2. **Fixed behavior gets a Go-side regression test, not a golden step.**
   `TestResolveCandidateNoteRecordsOnBothSides` (cli + dedup),
   `TestLadderExploreNaturalAxisForm`, `TestToolchainSolcKeyDetected`.
3. **Verification state of this triage:** every "confirmed" line above was
   re-checked against Go source at the cited file:line on 2026-09-09
   (binary HEAD `1254db0` + T37 working tree, before today's P1–P4 fixes).
   No item was taken on the operator's word where code could decide; the
   one place code contradicted the operator is P2-7a (above).
4. **Suggested order if/when the tiers get built:** D1-linter-v1 (20 lines,
   highest value-per-line) → A-tier in feedback priority order (A1, A2, A3
   are recommendation #3/#6/#10) → B-tier (B1 unblocks `submission_ready`
   entirely) → C4/C5 (operator-time returns) → C1/C6/C7 → D1-v2/v3, D2.
   Each B/C/D item needs its own divergence row + golden check before merge.

## Status of the python-twin-issues P1–P8 set (fixed 2026-09-09)

| item | subject | resolution |
|---|---|---|
| P1 | toolchain reads `sol`, not `solc` | **FIXED-IN-GO** — `snapshot/toolchain.go` reads `solc`, falls back to `sol`; `TestToolchainSolcKeyDetected` |
| P2 | `resolve-candidate --note` schema rejection | **FIXED-IN-GO** — schema declares `candidate_notes` as a string map; D14 documents the permanent reference divergence; 2 regression tests |
| P3 | `ladder explore` positional trap | **FIXED-IN-GO** — trailing positional binds the axis for `explore`; D30; `TestLadderExploreNaturalAxisForm` |
| P4 | bare `webv2 env` prints `sft` help | **CLOSED** — Go behavior was already correct; D23 closed as fixed papercut |
| P5 | RUNBOOK §6a skips `POSSIBLE` | RUNBOOK text in the deprecated repo — N/A here; Go-side note R1 stands |
| P6 | RUNBOOK `--mutations` example invalid | RUNBOOK text in the deprecated repo — N/A here; Go-side note R2 stands |
| P7 | RUNBOOK toolchain sentence over-promises | **true for the Go binary** after P1; Go-side note R4 updated |
| P8 | reference-only oddities (D15/D23/D24/D28) | table updated; D23 closed, D14/D30 added |

Golden suite after all fixes: **GREEN** — 179 steps × 2 twins, 68 files
byte-match (normalized per `KNOWN_DIVERGENCES.md`).
