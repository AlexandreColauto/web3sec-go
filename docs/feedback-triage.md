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
| Confirmed missing, design changes (need a call) | 0 | D1–D2 both **LANDED** 2026-09-11 (B4 v1+v2+v3, B1) |
| Misdiagnosed mechanism, real symptom | 1 | P2-7a (counted in A10) |
| Opinion/tuning sub-claims, not bugs | 2 | P3 "rows duplicated findings"; eval "10 FPs" |

(eval §5-3…§5-7 are not separate items: they alias P1-2/P1-1/P1-3…7 and land
in tiers B/C above; only §5-1 and §5-2 are net-new design asks — D1 and D2.)

No item is pure frustration-without-a-bug. The operator's P1 list is 100%
confirmed in Go (8/8). The single highest-value change overall was **D1, the
disposition linter** — the only change that would have caught the campaign's
actual failure (G-01 missed at rank 1 of the probe surface) — and it is now
fully landed, all three layers of it. **Every confirmed bug in this file is
fixed and every design ask (D1, D2) is landed.** What remains open is the
C-tier: six unscoped *feature asks* from the operator (C1, C2, C4, C5, C6,
C7) — see "Disposition of the remaining feature asks" at the end for the
recommendation on each. None of them is a defect.

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
| eval §5-1 disposition linter | confirmed gap — **the G-01 miss** | no reason-text check in `planner/answered.go` / `probes/closure.go` | D1 | **LANDED** (B4 v1+v2+v3) |
| eval §5-2 liveness/chain-freeze terminal | confirmed gap | no liveness terminal in `taxonomy/` or `chainengine/terminal.go` | D2 | **LANDED** (B1) |
| eval §5-3 waiver story | = P1-2 | — | B1 | **FIXED** (with B1) |
| eval §5-4 amend/supersede | = P1-1 | — | C1 | open — feature ask |
| eval §5-5 closure/status drift | = P1-3/4/5/6/7 | — | A1,B2,B3,A2,B4 | **FIXED** (with A1/B2/B3/A2/B4) |
| eval §5-6 high-signal dismissals section | confirmed gap | no such section in `report/report.go` | C6 | **COVERED** by B4's Disposition review (see note) |
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

### D1 = eval §5-1 — the disposition linter (the G-01 miss) — **LANDED (v1+v2+v3, as B4)**

> **Status 2026-09-11: v3 shipped — the item is closed.** All three layers are
> live. v1 (the scan, surfaced in `brief` and the report's Disposition review
> section) and v2 (the hard gate in `MarkAnswered` with the named, logged
> override) shipped earlier as **B4**; **v3, the structural layer, is now
> built too** (`RowSymbols` / `namesSymbol` / `ghostCitation` in
> `internal/planner/disposition.go`): a high-risk row's closure reason must
> quote something from the row's OWN surface entry — its contract, the
> function it is about, the base it inherits, the sibling it mirrors, the
> concept keys it asserts — or carry a refutation that runs, or take the
> logged override. A reason that names nothing ("the flow looked fine when I
> traced it") is refused with the list of symbols it would have accepted.
>
> Two properties make v3 safe to ship rather than a wall: **a row that carries
> no symbols is exempt by construction** (`RowSymbols` returns empty ⇒ the
> rule is skipped — an unclosable row would be worse than an unverified one),
> and **the converse duty runs at every tier**: any finding/exec/invariant id
> a reason or `--ref` cites must exist, so "rests on `F-1a2b3c4d5e6f`" is
> refused as fabricated. Precedence is deliberate — shape (anchorless, then
> fabricated citation, then anchor mismatch) is answered before policy (v2
> vocabulary, then v3 citation), so an author gets the message they can act
> on.
>
> Cost of shipping it honestly: six existing closures in the test corpus were
> written in exactly the style v3 refuses (including the committed Python-era
> oracle vector's `anchor_ok` case, whose reason was literally *"checked it
> thoroughly by hand"*) — each was rewritten to cite the row's own code. That
> is the migration path for real campaigns, and it is the point of the rule.
>
> The 2026-09-10 additions closed the proof gap rather than the feature gap:
> the golden recipe now drives the refusal end to end (steps
> `answered-dismissal-refused` = exit 2 with the reason text asserted,
> `answered-dismissal-override-unreasoned` = exit 2,
> `answered-dismissal-overridden` = exit 0 and announces itself), the report
> artifact is checked for both the flagged dismissal and the override with its
> actor and written reason, `check-golden.py` validates declared output markers
> (an exit code never said *why* a step refused), the override's "logged"
> signal reaches the operator (it used to be silent), and the rule is now in
> the two documents an operator and an agent actually read (`RUNBOOK.md`, and
> `AGENT_BOOTSTRAP.md` — which is the one dropped into every campaign).

### D1 (original ask, kept for the record)
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

**As built (2026-09-11):** all three, and the override lives on the v2 gate —
one escape for both rules, because two escapes are two policies. The row's
"structural index" turned out to be unnecessary: the surface row already
carries its own identity (contract/consumer/base/asserter/concept_keys/
forward/siblings), so the check reads the row, not the tree — same seam, no
new dependency, and it works for a row the index never saw.

### D2 = eval §5-2 — liveness as a first-class impact — **LANDED (as B1)**

> **Status 2026-09-10: shipped.** The capability registry is
> `internal/capabilities/` (not a taxonomy dir): `KINDS` gains `"liveness"`,
> `TERMINAL_KINDS = {asset, liveness}`, and `livenessImpact` runs at chain
> materialization — `economic_impact.kind = "liveness"`, blast radius FLOORED
> at `protocol-solvency`, `priceable: false` with a capacity ceiling (the
> freeze itself is the impact). See `docs/IMPROVEMENTS.md` B1, "As-built".
> Nothing in the original ask below is still open; it is kept for the record
> because the reasoning is what the eval's §5-2 asked for.

### D2 (original ask, kept for the record)
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

---

## Disposition of the remaining feature asks (2026-09-11)

The C-tier items are operator feature requests, not defects, and they are the
only things in this file still open. They are recorded here with a
recommendation so the list stops reading as a to-do that never moves. The
standard applied is the project's own: **a new CLI surface must buy
bug-finding power or operator-time, and it must not weaken a gate.**

| item | ask | recommendation |
|---|---|---|
| C1 | finding amend/supersede path | **Do not build as "amend".** The finding store is deliberately append-only — a finding whose thesis changed is a NEW hypothesis (ingest it; `dedup`/`merge` already link the pair), and an in-place amend would let evidence and claim drift apart with no new record. If the need is real it should be spelled as `supersede <old> --by <new>`, and it needs the same care as a status move. |
| C2 | learning stage API-only | **Low value, no action.** `hint` already exists and is the surface the pipeline uses; the remaining gap is an API-shaped convenience. Nothing in the campaign feedback depended on it. |
| C4 | probe disposition batch input | **Recommend against.** B4/D1 pushed disposition in the *opposite* direction: one row, one reason that cites the row's own code, with a refusal when it does not. A batch verb that carries one reason across rows is a machine for producing exactly the G-01 closure at scale. Batch *reading* (`probes list --json`, already there) is the right ergonomics. |
| C5 | ladder `other` axis | **Defer.** The five fixed axes are the coverage contract the ladder's proof-of-exploration rests on; a free-form sixth axis needs a rule for what "explored" means before it is a gain rather than a place to hide. |
| C6 | high-signal dismissals in the report | **Covered by B4.** The report's **Disposition review** section lists the high-risk dismissals and every override with actor and reason. The part of C6 that is NOT built is its *trigger* — a reason-length/signal threshold on low-risk rows — and D1 v3 makes that redundant where it mattered: a high-risk row can no longer be dismissed on long prose at all, and on low-risk rows a length heuristic is noise. |
| C7 | campaign severity floor | **Do not build.** `bounty` already has a per-finding severity floor, and the campaign-level version is a *reporting* knob, not a bug-finding one: it would let a campaign declare itself blocked-or-green on the strength of a number an operator set, which is the same "assert, do not check" shape the gate work has been removing. If a campaign is thin, `audit` + `report` already say so with evidence. |

None of these recommendations removes an item from the operator's reach: C1,
C2, C4, C5 and C7 can be built on request, and this table is the argument a
future implementer should answer rather than re-derive.

---

## Review sweep (2026-09-10) — silent-failure paths

A full-repo review (report kept in `.scratch/review/`, untracked) found six
defects with one shape: **a gate or a write that reports success without
having done the work.** All six are fixed, each with a regression test, and
`scripts/verify-full.sh` is green (13/13) on the result. **Correction
(2026-09-10, emit-quota repair batch):** that claim did not reproduce on re-run
at this commit (`da7200a`) — step 12 fails at the blind-axis assertion. See
**Acceptance item 1 — …** in the P0-batch record below.

| # | defect | fix |
|---|---|---|
| 1 | a `policy_checks` waiver row never cleared the fail row above it, so a waivable check still blocked `submission_ready` | `bounty.effectiveChecks` (last row per check name wins) drives `submission_ready`/`eligible`; two pinned vectors flip to `true` |
| 2 | a sandbox process that failed to start recorded exit status `0` and empty stderr | `sandbox.execute` records `-1` and puts `sandbox: <err>` on stderr |
| 3 | the event log appended after a torn write and no write was fsynced | `appendJsonlChecked` refuses a file whose last byte is not `\n`; `WriteJson` fsyncs, uses a unique temp, preserves the mode |
| 4 | a registered artifact with no `sha256` was skipped by the audit | hash-less rows are now a problem (`content unverified`) |
| 5 | the `foundry.toml` compiler pin was interpolated into the container shell and used as a host path component | `sandbox.SolcVersionPin` gates `env doctor`, preflight and the env seam; the probe passes the pin as argv |
| 6 | 36 hand-rolled flag cases consumed the next token unconditionally | `looksLikeOption` guard everywhere; `move <c> <f> DISPROVED --reason --actor` exits 2 instead of chaining the literal `"--actor"` as the reason |

Second pass (same review): campaign listings read directories instead of
`filepath.Glob` (a `--root` containing `[ ] ? *` silently read the campaign as
EMPTY — `prioritize` printed nothing, `dedup` said `untouched=0`); `ingest`
consumes the discovery slot **before** writing the finding, so a crash costs a
slot rather than granting a free one; memory ids are validated before being
joined into a path; `budget --clear --set` and
`doctor --state-only --snapshot-only` refuse instead of silently resolving;
`selftest --ful` errors instead of running the fast plan and printing PASS.

### Still open (deliberately, with reasons)

| item | why it is not in this sweep |
|---|---|
| `pyTruthy` consolidation (21 defs, 11 bodies, 4 divergent semantics) | A wrong unification silently flips gates. Needs its own pass that pins each call site's intended truthiness first. |
| corpus score cap | The cap is a policy number; changing it moves published corpus scores. Belongs with the operator, not a review. |
| structidx ↔ probes authorization vocabulary | The two tables are byte-pinned in golden vectors; unifying them is a coverage-contract change. |
| `verify` log-repair verb for torn/trailing-garbage logs | The framing guard makes the failure loud; a repair path needs a spec for what a repaired chain claims. |
| `sft` version-bump semantics on re-curation | Whether a no-op update should bump `version` is a dataset-contract call. |
| `probes` `--flag=value` parity | 23 verbs accept the `=` form; `probes` does not. Cosmetic until someone scripts it. |
| E6 queue tie-break by realised impact | The ordering is deliberate and pinned by `TestIndependentVerificationQueueOrdersMandatoryFirst`; changing the key is a contract change, not a bug fix. |

---

## 2026-09-10 — external review triage (P0 batch)

Inputs: `../morph/webv2-workspace/reviews/webv2-framework-review.md`
(defects D1–D9) and `../morph/webv2-workspace/reviews/eval-retro-gold-findings.md`
(the consumption miss). This section records what the P0 batch
(`docs/superpowers/plans/2026-09-10-p0-review-consumption.md`, commits
`2dbea50` → `b4a8397`) closed, what it deliberately left to the P1
consumption plan, and one correction to the eval retro's premise. The P0
plan's "out of scope" list *is* the P1 list, so nothing below is news to
the plan — it is recorded here so it is not dropped. It also carries the
follow-up emit-quota plan (`docs/superpowers/plans/2026-09-10-emit-quota-repair.md`,
commits `1164289` → `9a4f809`; the range also carries two plan-amendment
commits, `12da714` "Plan: name the campaign in the planner's disposition
errors too" and `3cb90d1` "Plan: widen Task 4 to every uncopyable campaign
placeholder"); the plan's entries are the audit's-repair-hint row
and the placeholder sweep below.

Reproductions below were re-run against a throwaway copy of the operator's
campaign `C-21dd6a7642` with a binary built from HEAD; see "Where the
reproductions live" at the end.

### Closed by this batch

| item | commit | reproduction that used to fail | evidence it is fixed |
|---|---|---|---|
| **D1** schema-legal custody label | `2dbea50` "Emit a schema-legal custody label and keep divergence row identity" + `10477d4` "Restrict the omitted-field rule to the custody key so other gaps still fail loudly" | `probes C-21dd6a7642 run --emit` → `error: probe_surface validation failed at rows/5/custody: 'transfer-in' is not one of ['burns', 'mints']` | the bare command now exits 0 and emits `orphaned 34` (`emit: created 12, updated 28, kept 0, reopened 0, orphaned 34`), and the surface's own quotas (`--per-axis 30 --total 70`) exit 0 and emit `orphaned 8` (`emit: created 16, updated 54, kept 0, reopened 0, orphaned 8`) — both on the copy; `symCustodyLabel` writes `custody` only for mint→`mints`/burn→`burns` and `idSlots` falls back to `observed`; tests `TestCustodyPrimitiveOmitsCustodyForNonCreditDivergences`, `TestCustodyPrimitiveIdentitySurvivesOmittedCustody`, `TestMintAndBurnCustodyLabelsSurviveTheOmission`, `TestFinalizeKeepsAbsentDeclaredFieldsExceptCustody`; the bare-command default shown here was superseded by the emit-quota plan — see the audit's-repair-hint row below |
| **D8** gate blocker wording | `53d182f` "Make the gate's fork blocker state the precise reason" | `gate C-21dd6a7642` → `blocker: no proven mainnet fork PoC (the latest required step)` | now prints `blocker: no proven mainnet fork PoC: fork-level evidence exists but no fork-runner exec has verified sequence coverage — run a T4 sequence PoC (webv2 sequence run); a single-call fork PoC cannot prove this multi-step exploit` (reproduced on the copy); `TestForkPocBlockerCarriesStatusReason`; the waiver path is unchanged (`TestForkPocWaiverBlockerUnchanged`) and only the pinned gates snapshot moved |
| **D6** report precision | `022d986` "Report a non-negative false-positive ratio over the critic-confirmed set" | `report.md` → `- **precision:** critic-confirmed: 4  - evidence-confirmed: 5  - false-positive ratio: -25.0%` | now `- **precision:** critic-confirmed: 4  - evidence-confirmed: 5  - false-positive ratio: 0.0%` (reproduced on the copy); the ratio is `criticNoEvidenceN/criticN`, bounded to [0, 100], and `n/a (no critic-confirmed findings)` when the denominator is zero (`TestReportPrecisionRatioNeverNegative`, `TestReportPrecisionRatioNoCriticConfirmed`) |
| **D4** memory queue command | `5041d54` "Queue the memory row a terminal finding needs" | `prove C-21dd6a7642 \| grep '^learning'` → `learning  open  [authoritative] — F-6791c9aee0b5: no memory entry for this terminal finding (learning.queue_memory); …` | `memory C-21dd6a7642 --queue-finding F-6791c9aee0b5 --kind confirmed` prints `MEM-5440ce05 queued for F-6791c9aee0b5 (CONFIRMED) — approve with: webv2 memory C-21dd6a7642 --approve MEM-5440ce05 --by NAME`, and `prove` then drops that finding from the `learning` line (both reproduced on the copy); tests `TestMemoryQueueFindingSatisfiesLearningProof`, `TestMemoryQueueFindingRejectsNonMemoryStatus`, `TestMemoryQueueFindingKindDerivation` |
| **D5** coverage reason + help | `b4a8397` "Name the actors a sequence PoC is missing and document the coverage rule" | `sequence verify` on a two-actor `exploit_sequence` executed by one actor printed only `executed steps use 1 distinct actor(s) but the declared exploit needs 2 — a single-account PoC cannot cover a multi-actor exploit`, and `sequence run --help` never mentioned coverage | the reason now ends `; missing: <declared label>` (sorted, verbatim, nothing appended when coverage is met or exceeded), and the help states the rule; tests `TestActorGapReasonNamesMissingActor`, `TestActorGapReasonSortsAndKeepsLabelsVerbatim`, `TestActorCoverageMetYieldsNoActorReason`, `TestExecutedActorSupersetYieldsNoActorReason`, plus the `run --help` line in `internal/cli/cmd_sequence_test.go` |
| **the audit's repair hint** (the suggested bare `probes run --emit` rebuilt the surface with default quotas and made the audit worse) | `1164289` "Let a bare probes run repair the surface it already has" + `0df62af` "Name the surface artifact when a bare probes run cannot read it" + `d818150` "Make the recorded-quota case discriminate on what the fixture can show" + `3ba046a` "Name the campaign and the recorded quotas in the audit's repair hints" + `e9c1f67` "Name the recorded quotas at the blank attestation's last repair hint" | on the copy, bare `probes C-21dd6a7642 run --emit` printed `emit: created 12, updated 28, kept 0, reopened 0, orphaned 34` (40 rows emitted against the original 62 recorded in the P0 measurement below) and `audit C-21dd6a7642` reported 34 `[probe_surface]` problems whose repair hint read `(re-run webv2 probes <campaign> run --emit)` | bare `probes C-21dd6a7642 run --emit` prints `emit: created 16, updated 54, kept 0, reopened 0, orphaned 8` — the surface's own recorded `--per-axis 30 --total 70` — and `audit C-21dd6a7642` reports 8 `[probe_surface]` problems, all eight naming the campaign and quoting the quotas: ``… re-run `webv2 probes C-21dd6a7642 run --emit` (rebuilds with the surface's recorded --per-axis 30 --total 70)``; no problem string contains `<campaign>` (reproduced on fresh copies of the campaign; `d818150` makes the parity fixture discriminate the recorded-quota case) |

**D1 residual (open).** The D1 row above records the bare-command default as
it stood at the P0 batch; that half of the residual is now closed (see the
audit's-repair-hint row and the placeholder sweep below). Bare
`probes C-21dd6a7642 run --emit` adopts the surface's recorded quotas and
leaves `orphaned 8`; what remains is **plan↔surface identity drift**, not a
quota choice: any sanctioned repair rebuilds 70 rows where the original had
62, so `audit C-21dd6a7642` reports 8 `[probe_surface]` problems — plan
priorities Q-253…Q-260 cite probe rows the rebuilt surface no longer carries
— with the `trust-assumption` axis under-filling 29 → 21 rows (the copy also
carries 4 unrelated `[artifacts]` missing-file problems and 6
`[sequence_coverage]` ones). So the plan's "audit then reports zero
`[probe_surface]` problems" acceptance is **still not** reproduced here; the
abort is gone (the defect D1 names) and the hint no longer makes the surface
worse, but plan↔surface identity on this copy is a separate open item.

**The `<campaign>` placeholder sweep (Task 4 of the emit-quota plan, added
mid-plan by `12da714`, widened by `3cb90d1`).** The audit hint was the visible end of a defect class: an
operator-facing repair hint that had the campaign id in hand but printed the
literal `<campaign>` metavariable. `70047f5` "Name the campaign in the
planner's probe-row repair hints", `7def13b` "Name the campaign in the rest
of the framework's repair hints", `9ca4f46` "Name the campaign in the gate,
bounty, roles and budget repair hints" and `9a4f809` "Name the campaign in
the intake warning and the stale-index rebuild hint" swept it through
`internal/planner`, `internal/cli`, `internal/completion`, `internal/doctor`,
`internal/findings`, `internal/bounty`, `internal/roles` and
`internal/structidx` (plus `internal/immunize`/`internal/taxonomy` in tests;
two `testdata` trees were re-recorded). The gate/bounty catalogs and the
planner's `campaignIDForPlan` became templates rendered with the campaign in
hand — the sibling of `findings.NameCampaign` — and the re-recorded captures
were checked substitution-only: `internal/orchestrator/testdata/oracles.json`
is byte-identical to its predecessor once every campaign id is normalized
back to `<campaign>` (392,394 → 392,409 bytes, 5 substitutions).

**Acceptance item 1 — `scripts/verify-full.sh` green, all 13 steps — did not
hold.** On re-run the script stops at step 12: steps 1–11 pass, and step 12
fails the assertion at `scripts/verify-full.sh:685-699`
(`fail 12 "smoke probes: no blind axis/key published"`), which selects a
campaign axis whose `status` is exactly `blind` and whose `blind` list is
non-empty. `internal/probes/surface.go:143-152` sets `blind` only when the axis
has `sites > 0` and `rows == 0`, and the smoked corpus never produces one. The
reason is `snap`: it pins the whole repository, not the directory it is handed,
so the smoke's `index --src <snapshot>` covers the entire tree — the
enforcement-timing probe, blind against its single-fixture index, instead finds
125 sites and ranks 12 rows, and the six axes come out five `emitted` and one
`no-sites`. That assertion is therefore unsatisfiable on the corpus the script
builds; it fails identically at `da7200a`, the commit whose record carries the
13/13 claim corrected above, so that claim does not reproduce there and should
not be repeated as fact. It also fails at `9e9a671` (which added the check, its
P3 gate report claiming every step passes) and at the P0 batch's record commit
`2737486` (its twin `690ee07`, on `wave-g-tranche-1`, fails identically).
Repairing the acceptance needs a decision this batch did not take: either
**make the smoked corpus contain a genuinely blind axis** — untried, and it
means changing what `snap` pins for the smoke — or **exercise the blank
attestation against a fixture-only index**, which this record did reproduce
(`index --src internal/probes/testdata/probes/assertion_strength/clean` then
`probes run` yields `enforcement-timing`: 4 sites, 0 rows, `blind`, 5
blind entries), and which would have the smoke index a fixture tree instead of
the snapshot.

**Repaired (2026-09-10, Task 5).** The second option was taken, narrowly:
step 12 now builds a second scratch campaign whose index is built straight
from `internal/probes/testdata/probes/assertion_strength/clean`, so its
`enforcement-timing` axis is genuinely `blind` (sites 4, rows 0, 5 blind
entries), and moves its own corpus build (`init`, `index --src <fixture>`,
`probes run`) plus the `probes list --axis` / `probes blank` / after-blank
listing onto it. The repo-wide campaign keeps its `probes run --emit`, `plan`,
`relations`, `resemble`, `corpus-surface`, memory/publish, baseline, cost and
closing audit/verify assertions. The selector was tightened: the blind
requirement was already strict and is now pinned to the exact tuple the fixture
produces (axis `enforcement-timing`, sites 4, rows 0, 5 blind entries), failing
with a `selected ... want ...` message. Its old failure mode is unchanged: a
corpus with no blind axis still fails the step by name.
`bash scripts/verify-full.sh` is green again, 13/13.

### Still open (deferred, with the reason)

| item | evidence at HEAD | why deferred |
|---|---|---|
| **D2** capability graph has no writer | `chainengine/materialize.go:437` is the `capability gap: F-… -> F-… (grants …, needs …)` error; the graph reads `capabilities.granted`/`capabilities.required` (materialize.go:429). Grep finds no writer: there is no `link` verb and no command that sets those keys, so `chain`/`chains` is a gate feature the operator cannot populate (`capability links: 0`) | recording edges is a new mutation surface over the finding payload plus `show` rendering — a subsystem, not a P0 fix; the plan allows exactly one new flag (`--queue-finding`) |
| **D3** severity floor has no mutation surface | `bounty/bounty.go:298` (`blast_radius`) and `:312` (`require_invariant_violation`) read those keys in the policy rules; outside tests the same `economic_impact.blast_radius` is also read by `risk/risk.go:237` (validated-risk scoring), `chainengine/materialize.go:316` (`chainBlastRadius`) and `privileged/privileged.go:217` (`pathBlastRadius`), and nothing writes that field — no `severity` verb, no idempotent payload patch | it needs a decision about whether the policy inputs are operator-set or ingest-only, plus a mutation surface (or a documented idempotent patch) |
| **D7** tooling failure ≡ coverage failure | `cmd_sequence.go:394-401` renders every `VerifySequenceCoverage` reason as a FAIL row; a tooling failure (`sequencepoc/run.go:209-212`, the exec-output-dir-outside-the-campaign-tree guard; also `:214-216`, a missing `sequence_result.json`) produces a reason of the same shape as a genuine actor/step gap, so `EXEC-9ff37b9a43` (`FAIL`, `exec output dir is outside the campaign tree — refusing to honor it`) reads as a permanent coverage FAIL | distinguishing tooling failure from coverage needs a classification on the reason and a retryability rule — a contract change to `sequence verify`, and it pairs with D9 |
| **D9** budget has no attempt classes | `reproduction.RecordAttempt` enforces one `max_repro_attempts_per_finding` counter (`state/campaign.go:86`, default 6) over every outcome; on `F-f53dc0dbbf10` (the finding that hit the 6-attempt cap) three of six attempts (3/4/6, `failure_class: logic`) failed on tooling, not on the exploit — `seq: empty address for anvil:0` twice (`EXEC-c1af63b57d`, `EXEC-9ff37b9a43`) and `Error: Function signature does not contain parentheses` once (`EXEC-05183445ce`); the only `http://host.docker.internal:8545` execs are `F-6791c9aee0b5`'s two, and the sanctioned fix was hand-editing `campaign_state.json` to raise the cap 6 → 12 (backup `campaign_state.json.bak-prebudget`) | attempt classes are a new axis on the attempt ledger plus a migration/decision for the existing counter; out of the P0 plan's scope |

**Correction to the eval retro's premise.** The retro says the campaign
reached `bounty-gate` with "every authoritative stage green"
(`eval-retro-gold-findings.md` §3a). `prove` on the campaign copy does not
agree — `discovery` is open and authoritative:

```
$ webv2 --root . prove C-21dd6a7642
discovery                  open  [authoritative] — Q-001: Can the drain-capable roles (user, staker, challenger, rollu; Q-143: Within its stated constraints (timelocked=no, threshold=n/a); Q-144: Within its stated constraints (timelocked=no, threshold=n/a)
```

(`hostile-review`, `maximal-exploitation` and `protocol-model` are the
authoritative stages that were DONE.) The real gap is therefore not "every
gate was green" but what the green gates measure, in three parts: **(a)** the
bounty gate never consumes coverage — grep finds no `probe`/`coverage` read
anywhere in `internal/bounty/`, so `bounty-gate DONE` is independent of 0/62
probes worked; **(b)** the `discovery` bar is the whole plan —
`proofDiscovery` (`completion/proofs.go:197`) drains `planner.WorkQueue`, so
it demands all 261 priorities, not the tier-0 / risk≥0.85 slice that would
have surfaced G-01's Q-199 (risk 0.9); and **(c)** `brief` renders the probe
surface as a bare count — `probe surface: 62 rows (0 dispositioned, 62 open)`
next to `questions worked 0/261`, with no ranked-coverage line.

**Row-id collision is unreachable in practice.** *Status: open.* The
`idSlots` fallback hashes `observed` into the fourth identity slot — the one
holding the `custody` label derived from `expected` — when `custody` is
absent (`internal/probes/collapse.go:63-68`), so two `custody-primitive`
divergences sharing (contract, consumer, observed) and differing only in
`expected` now hash to the same row id, and the
`extras[RowIDFor(withProbe)]` write (`internal/probes/symmetry.go:584-594`)
silently overwrites one row's expected/direction/asset/why. The final review
found the collision unreachable on `C-21dd6a7642` (all 12 fresh custody rows
have distinct consumers) and in the fixtures — the guarding test builds two
rows with different consumers (`internal/probes/symmetry_test.go:268-302`,
the `noncreditSurface` rows at `:217-218`), so it cannot bite — and it noted
a mirror collision existed before the fix. **Recommendation:** when the
fallback is taken and `expected` differs from `observed`, fold `expected`
into that slot; add a fixture with two same-consumer divergences to pin it.

**The `<campaign>` placeholder still reaches the operator on id-less paths.**
*Status: open.* The sweep above closed the placeholder wherever the caller
has the id; these paths do not, and each is parked rather than fixed:

- `internal/structidx/index.go:44-49` — `RequireParseVersion` renders
  `IndexRebuildCommand` with the index's `campaign_id` when it is present and
  keeps the literal when it is absent, so a legacy/pre-v3 index with no
  `campaign_id` prints `webv2 index <campaign> --src <target>`. The probes
  path reaches it through `loadProbeIndex`
  (`internal/cli/cmd_probes.go:459`) → `probes.RunProbes` →
  `internal/probes/surface.go:205` `structidx.RequireParseVersion(index,
  "structural index")`, which receives only the index — the caller's
  `c.CampaignID` is never threaded. **Recommendation:** thread the id or
  correct the comment.
- `internal/structidx/structidx_test.go:214` — `TestRequireParseVersion`
  exercises only the id-less branch, so the new named branch (`campaign_id`
  present) has no test and a revert stays green.
- `internal/immunize/immunize_test.go:439` — `sawPlaceholder` is declared
  once outside the `mainnet-fork-poc`/`immunization` loop (`:416`) and set
  inside it, so the per-row assertion passes when *either* row carries the
  token even if a catalog row silently drops it.
- The remaining hits are not operator-facing repair hints. At this head the
  literal occurs **253 times in 96 Go files** (66 of them inside `_test.go`):
  92 in template strings that are rendered with the id before printing, 84 in
  comments, 66 in test-file uses (assertions, fixtures, the `campaignToken`
  constant), 6 in usage/help strings, and 5 lines that are the literal
  itself — the id-less fallbacks `planner/gates.go:42`,
  `findings/ingest.go:562` and `findings/levels.go:368`, plus the constants
  `findings/gate.go:29` and `structidx/parser.go:29`. A few dozen more sit
  outside `.go` files (plans, this record, prompt assets, `testdata`) as the
  metavariable used deliberately in documentation.

**`--anchor custody` hard-errors on a non-credit divergence row.** *Status:
open.* `custody` is a declared anchor for `custody-primitive`
(`internal/probes/registry.go:60`, field map `:129-130`), but after D1 a row
whose expected primitive is neither mint nor burn omits the key, so
`RowAnchorValue` reaches `!vHas(row, field)` and returns `row of
'custody-primitive' has no field 'custody'`
(`internal/probes/shape.go:177-179`). The row is still closable — `base` and
`consumer` remain declared anchors and emitted fields
(`internal/probes/registry.go:60-62`). **Recommendation:** name the usable
anchors in the error, or treat a declared-but-absent anchor as a
parenthesised miss like the other assertion gaps.

**The plan still states the unmet acceptance criterion unqualified.**
*Status: open.*
`docs/superpowers/plans/2026-09-10-p0-review-consumption.md:59-61` asserts
that after D1 `audit C-21dd6a7642` then reports zero `[probe_surface]`
problems; the D1 residual above shows it reports 8 on this campaign (plan
priorities Q-253…Q-260), and the emit-quota plan did not change that.
**Recommendation:** point that acceptance line at this section, so the plan
and the record agree.

### The P1 consumption batch (the eval retro's asks)

One line each on why it matters and what it costs; this is the P0 plan's
"out of scope" list.

| ask | why it matters | what it costs |
|---|---|---|
| provenance (`probe_row_id` on findings) | none of the four confirmed findings cites a probe row (`provenance keys: []`), so probe burn-down, family concentration and "predicted, never tested: 2 tier-0 rank-1 rows" are not computable | a new finding-payload field validated by ingest and rendered in `show`/report, plus schema + golden vectors and a story for findings already written |
| a scoped ranked-coverage gate consumed by the bounty gate | every gate measured the quality of what the campaign had; none measured which ranked hypotheses were tested, so the gate passed with 0/62 probes worked and 0/261 priorities answered | a new gate clause and waiver vocabulary, and a decision on the scope (tier-0 / risk≥0.85) — unscoped it is a blanket block |
| a per-row probe disposition verb | the surface has 0/62 dispositioned rows and no per-row lifecycle; the only consumer is the stage that ran once | a new CLI surface plus disposition storage; it must be one-row-one-reason or it recreates the G-01 closure at scale (see C4 above) |
| consequence-shaped row rendering | G-01 was the #1-ranked row and was skimmed because its `why` reads as `class 4 … class-0 guard … equality-to-persisted-state`, not as an attack, while G-02's reads as one | a renderer change over every probe's `why`; must stay deterministic and must not move row ids or ranks |

### Task 4 residual — the two terminal-status vocabularies disagree

Carried out of Task 4's review (real, deferred, outside D4's fix):
`completion.TerminalStatuses` (`internal/completion/completion.go:34`) is
`CONFIRMED, DISPROVED, DUPLICATE, OUT_OF_SCOPE, INFORMATIONAL, CHAIN`, while
`learning.MEMORY_STATUSES` (`internal/learning/learning.go:21`) is
`CONFIRMED, DISPROVED, DUPLICATE, OUT_OF_SCOPE, INTENDED_BEHAVIOR,
UNREACHABLE, NON-ECONOMIC, TEST-HARNESS-ONLY`. The learning proof therefore
demands a memory row for a terminal finding whose status is `INFORMATIONAL`
or `CHAIN`, and `memory --queue-finding` is required to refuse exactly those
(status ∉ `MEMORY_STATUSES`). Two options: **widen** `MEMORY_STATUSES` with
`INFORMATIONAL`/`CHAIN` — which edits `assets/schema/memory.schema.json`, and
assets are hash-pinned by `assets/testdata/asset_manifest.json`; or **narrow**
`TerminalStatuses` so the learning proof stops tracking those two — a change
to a gate's own scope. Either is a gate/vocabulary decision, not a bug fix.

### Where the reproductions live

The plan's reproductions rest on controller-side scratch, not repo fixtures:

- the campaign copy is `.scratch/morph-eval/campaigns/C-21dd6a7642`
  (untracked; the binary's `--root .` is `.scratch/morph-eval`);
- the emit-quota record's before/after pair is `.scratch/bin/webv2-pre`
  (built from `535366a`, the commit immediately before `1164289`) and
  `.scratch/bin/webv2` (built from its head), each run against a fresh copy —
  `.scratch/morph-eval-pre/campaigns/C-21dd6a7642` for the former (both
  copies are untracked and gitignored);
- to re-run: copy the campaign to a throwaway dir, build
  (`GOCACHE=.scratch/gocache go build -o .scratch/bin/webv2 ./cmd/webv2` —
  `$HOME/.cache/go-build` is read-only in this environment), and pass
  `--root <copy>`. Prefer a copy: `probes run --emit`, `report` and
  `memory --queue-finding` all write.

---

*End of the 2026-09-10 P0 batch record.*
