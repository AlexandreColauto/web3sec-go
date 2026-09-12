# MiniCertora × web3sec-go — the Proof Loop

Architecture for one system that uses the best of both frameworks: web3sec-go
as the deterministic **control plane** (what to prove, who pays, what counts,
what we remember) and MiniCertora as a **prover backend** (bounded SMT
verdicts with a closed refusal vocabulary). Status: proposal, 2026-09-14.
Liftable to `docs/IMPROVEMENTS.md` as Wave L when un-parked.

## 0. Premise — this is Wave K, realized

Wave K's locked decision stands: *"No new verifier is built in this wave —
integrate provers, don't become one."* MiniCertora (local, keyless, bounded,
`solc --ir` → Yul CFG → SMT → z3/cvc5) lands as the prover K predicted, but
it changes the wave's shape in one important way:

- **K1/K3 collapse.** K1 (solc SMTChecker) and K3 (Kontrol unbounded) were
  separate backends because we had no local VC-gen pipeline. MiniCertora
  subsumes their slot: one binary, JSON-lines verdicts, honest bounds. K1
  stays independently shippable (zero new deps) but is no longer the critical
  path.
- **K4 inverts.** K4 proposed *building* a CVL-subset spec surface and
  lowering it to halmos/SMTChecker/Kontrol. MiniCertora ships its own `.mspec`
  language (`rule`/`invariant`/`ghost`/`summary`/`require`/`assert`/
  multi-call/`reenter`/`expect_revert` — all implemented, parser in
  `spec/grammar.lark`). Do not build a CVL subset; adopt `.mspec` as a native
  spec kind. **K4-full dies here — recorded so it stays dead.**
- What MiniCertora does NOT provide is K2's slot (Medusa: coverage-guided
  fuzzing finds, never proves) and K3's `PROVEN-UNBOUNDED` rung — its verdicts
  are bounded by `--loop-bound`/`--path-cap` by design. The unbounded rung
  stays reserved for a real induction prover (Kontrol or its successor);
  `invariant` blocks are **one-step induction**, and their rung must render
  that honestly, not as full proof.

## 1. Best of both — the asset map

| the framework has | MiniCertora has |
|---|---|
| `INV-*` ledger (`internal/invariants`, `invariant_links.json`), `documented_invariants` / `intent_claims` extraction | a machine-checkable spec form for exactly those statements: `rule` (safety) and `invariant` (one-step induction over every entrypoint + constructor init) |
| G8 seam: `verify --scaffold` → BODY-law scaffold → `exec` (EXEC record) → `verify --harness-result` → rung on `verification.harness` → `brief`/audit render | exit-code = worst verdict (0 PROVEN / 1 VIOLATED / 2 UNKNOWN), one JSON line per rule — structured output that beats halmos stdout scraping |
| rung vocabulary `counterexample / proved-bounded(k) / inconclusive`, fail-open-to-inconclusive law (`internal/harness/outcome.go`) | closed 23-code `reason` vocabulary + `details` — every refusal names what was refused; the mapping is a bijection, not a heuristic |
| evidence ladder E0–E7; `HostProfile` rails (host profiles never back E4+); fork-PoC reproduction (`fork-runner`); `mint`/`gate`/`verdict` | `confidence: confirmed/unconfirmed/modeled`, full witness (`params`/`initial_storage`/`calls[]`/`final_storage`/`failed_assertion`) — bounded model-level counterexamples, exactly the E1–E3 artifact a host profile is allowed to carry |
| budget/timeout mechanisms, `WEBV2_*` pinning, exec tool-version capture | declared bounds per verdict (`bounds.loop_bound`, `path_cap`, `solver_timeout_ms`, `loop_bound_exhaustive`) — bounds-as-data, our native language |
| negative memory (disproved hypotheses), G3 backtest law, `planner`/`brief`/`deferred` | reason codes as *planner-consumable signal*: `loop-bound-may-be-exceeded` ≠ `unsupported-storage-layout` ≠ `vacuous-rule` — three different next actions |
| `assets/evalsuite` (19 gold-eval rows), `archetypes`, 69 probes | `corpus/targets/` (33 bug-class targets with `expected.json` ground truth) + `corpus/MATRIX.md` + anvil conformance probes |

The "best of both" is not the plumbing table — it is that both tools share
the same **fail-safe law** (never claim what you did not check), which makes
the mapping honest instead of lossy. Most external tools force you to lie a
little when you squash their output into a three-rung ladder. Here the
squash is nearly lossless, and the loss is recorded, not hidden.

## 2. Architecture — six planes

```
                 ┌────────────────────────────────────────────────┐
  L6 CALIBRATE   │ reason histograms → planner · G3 backtest ·     │
                 │ shared corpus fixtures (both directions)        │
  L5 SWEEP       │ archetype rule templates → batch mspec legs     │
  L4 EVIDENCE    │ rungs render · VIOLATED → fork repro → ladder   │
  L3 ESCALATE    │ reason-code disposition → next exec (bounded)   │
  L2 VERDICT     │ mapMiniCertora: JSONL+exit → rung+proof object  │
  L1 SPEC        │ INV-n → .mspec scaffold (BODY law) → artifact   │
  L0 TOOLCHAIN   │ profile minicertora · shim · version pinning    │
                 └────────────────────────────────────────────────┘
   web3sec-go owns the arrows; MiniCertora only ever answers queries.
```

### L0 — Toolchain plane (presence-gated, pinned, host-side)

- **Profile `minicertora`** beside `halmos`/`forge-fuzz` in
  `internal/sandbox/profiles.go`: network `none`, filesystem `readonly`,
  `HostProfile` → true (so it can never back E4+ evidence — the same rail
  that already forces fork repro for real PoCs). Add it to the
  `sandbox_execution.schema.json` profile enum (additive; golden bytes move
  only for campaigns that use it).
- **A `minicertora` shim on PATH**, not a raw `cd … && python -m cli` argv.
  The tool must run from its package root (`python -m cli` puts CWD first on
  `sys.path`), with its venv interpreter and an **absolute** `--solc-path`.
  The shim encodes those three facts once (like the slither/aderyn host
  probes) so EXEC `command` strings stay clean and reviewable:
  `minicertora <C.sol> <INV-n.mspec> --solc-path /abs/solc --loop-bound 4
  --timeout-ms 30000`.
- **Versions recorded, always.** `toolVersions` probe += `minicertora --version`
  first line (absent → honest omit, presence-gate for everything below);
  every EXEC already captures `environment.tool_versions`. The prover's own
  report lines carry `tool_version`, `spec_version`, `solc_version`,
  `evm_version` (= paris), `optimizer_enabled` (= False) — mapMiniCertora
  **cross-checks** them against the EXEC record and refuses to bind a run
  whose solc differs from the pinned compiler (rung inconclusive,
  `toolchain-mismatch` in the summary). That check is what makes a proof
  byte-reproducible in the `WEBV2_*`-pinning sense.

### L1 — Spec plane: `.mspec` scaffolds under the BODY law

- `harness.Kind` += `MiniCertora` (string `"minicertora"`). Same contract as
  the other kinds: `Scaffold(kind, inv)` is a pure function rendering a
  complete `.mspec` file; the model writes **only** the BODY region between
  the existing `// >>> BODY` / `// <<< BODY` markers (the marker spellings
  are `//`-comment-shaped, so they survive into mspec as line comments —
  `Validate` re-renders the scaffold and rejects any byte outside the window
  that moved; the whole G8 law applies verbatim to a text artifact, which is
  the quiet win: no Solidity lexer needed).

- Scaffold rendering from the INV entry (`statement`, `kind`, source spans):
  - frame: `rule INV_<n>__<slug>(env e) {` + the snapshot lines the
    statement's referenced storage reads need + `BODY: require/assert pair
    slots` + `}` — the rule NAME is scaffold-owned and embeds the invariant
    id, which is how L2 attributes lines without guesswork (one rule per
    scaffold; multi-rule files stay out of scope for the seam, mirroring the
    "no auto-detect" rail);
  - `statement` verbs that match the induction shape ("always",
    "never … after construction") render an `invariant INV_<n>__<slug>() {
    assert …; }` skeleton instead — the ledger's `kind` axis (security /
    liveness) plus a deterministic shape heuristic picks which; a
    misclassification comes back as `vacuous-*`/`invariant-unchecked-functions`
    and routes through L3, not through a manual re-spec.
- Artifact id: `HARNESS-INV-<n>-minicertora`, registered exactly like the
  halmos scaffolds (same `harness_scaffold` event, same sha binding at
  `verify --harness-result` — the Decision-2b bind-a-run-to-scaffold-by-hash
  law carries over unchanged and is what keeps a proof honest about *which*
  spec it proved).
- Scaffold-owned fields the model may NOT touch (reviewed data, not
  model freeform): the env binding (`e.tx.origin` stays a free symbol —
  `--assume-direct-calls` never appears in generated commands), `msg.value`
  posture (every rule body that moves value must use `with { msg.value = v
  }`; the tool's `msg.value-default-zero` assumption renders in the proof
  object, so a zero-value "proof" about a payable path is visible as such).

### Errata (post-landing, 2026-09-12)

The core wave that landed MiniCertora shipped a **subset** of what L1, §2 L2,
§3 and §8 draft, and the shipped spellings are the authoritative ones:

- **Rule name.** The shipped scaffold pins `rule inv_<n>` — `snake()` of the
  invariant id (`MspecRuleName`, `internal/harness/mspec.go:26`, rendered by
  `scaffoldMspec` at `internal/harness/mspec.go:59`) — *not* the
  `rule INV_<n>__<slug>` frame this section and §2 L2 ("the scaffold's
  embedded `INV_<n>__…` name") and §3's data-contract row draft. Verdict-line
  attribution keys on that exact snake name, and on nothing else.
- **Artifact path and name.** The shipped artifact is
  `artifacts/harness/INV-<n>/INV.mspec`, registered as
  `HARNESS-INV-<n>-minicertora` (`internal/cli/cmd_verify.go:320` for the id,
  `internal/cli/cmd_verify.go:328-330` for the filename and path) — *not* the
  flat `artifacts/HARNESS-INV-7-minicertora.mspec` that §8's command line
  shows.
- **Unfilled body.** A fresh scaffold's BODY window is comment-only
  (`DummyMspec`, `internal/harness/mspec.go:36`): a bare comment is the honest
  "no rule body written yet" signal, not a runnable stub.
- **Rule blocks only.** The core wave renders `rule` blocks; the
  `invariant INV_<n>__<slug>() { assert …; }` skeleton L1 sketches above did
  **not** land — it is deferred to the follow-on wave. Consequently §2 L2's
  `proof.invariant_check` and §3's `invariant` object row have no shipped
  producer yet.

The design prose above is left standing: it records the intent this errata
corrects, and the correction layer — not the prose — is the contract.

### L2 — Verdict plane: `mapMiniCertora` (the only real mapping code in the wave)

`MapRun` gains one branch. Unlike halmos (stdout scraping, `kMarker` regex,
noisy-log hazards), the input is **JSONL + exit code + returncode** — so the
branch parses lines, it never pattern-matches prose. Rules:

1. **Line classification.** A line with a `rule` key is a verdict; a line
   **without** one is an abort (whole-doc parse/loader failure — key on the
   missing `rule`, never on exit code alone, which is how the tool actually
   behaves). Any abort line → rung `inconclusive`, summary `aborted:
   <reason>: <details>`, output not used for anything else.
2. **Attribution.** Exactly one verdict line whose `rule` matches the
   scaffold's embedded `INV_<n>__…` name is required; zero or two matching
   lines → `inconclusive` (the no-guesswork rail again).
3. **The rung bijection** (rung vocabulary extended, never renumbered):

   | minicertora | rung | recorded |
   |---|---|---|
   | exit 0, `verdict: PROVEN` | `proved-bounded` | `bounded_k = bounds.loop_bound` — the bounded claim, never bare "proven" |
   | exit 1, `verdict: VIOLATED`, `confidence: confirmed` | `counterexample` | witness summary: `failed_assertion.expression` (≤120-char excerpt, existing cap) |
   | exit 1, `verdict: VIOLATED`, `confidence: unconfirmed` (crossed a havoc'd call under `--external-calls havoc-storage`) | `counterexample` + `confidence: unconfirmed` flag | **never promotable without fork repro** (L4 rule) |
   | exit 1, `verdict: VIOLATED`, `confidence: modeled` | `counterexample` + flag | rare (a SAT-model class the conformance suite pins); renders, informs critic |
   | exit 2, any `verdict: UNKNOWN` | `inconclusive` | summary = `reason: <details>` (details capped) |
   | timeout (kill) | `inconclusive` | `timeout after Ns` wins over bytes — the existing law, unchanged |
   | exit code contradicts lines (e.g. 0 with a VIOLATED line) | `inconclusive` + `report-contradiction` | a prover that disagrees with itself gets zero trust, per fail-open law |

4. **The `proof` sidecar** (additive, presence-gated object under
   `verification.harness` — golden campaigns never had it, their bytes don't
   move): `{tool_version, solc_version, spec_version, evm_version,
   confidence, reason, assumptions[], bounds{loop_bound, path_cap,
   solver_timeout_ms}, ghosts[], warnings[]}`. This is the honesty layer:
   the tool's own doctrine is that the `assumptions` list is the complete
   caveat set for the verdict, and the report keeps whatever it says —
   webv2 neither invents caveats nor drops them. The brief line stays
   `INV-3: PROVEN-BOUNDED (minicertora, k=4, EXEC-9)`; the caveats surface
   in the audit section and the critic prompt, not the one-liner.
5. **Portfolio disagreement.** `--solver portfolio` with
   `solver-disagreement` writes a diagnostic bundle
   (`--emit-diagnostic-bundle DIR`, default `minicertora-diagnostics/`); the
   EXEC records the bundle path under `artifacts/` so the disagreement is
   campaign evidence, not /tmp litter. Exit 0 is never a proof of the
   *campaign* property — it is a proof of the scaffolded rule, under the
   recorded sidecar.

### L3 — Escalation plane: reason codes are router inputs, not verdicts

This is the plane most single-tool designs lack: an UNKNOWN is not a dead
end, it is a **named next action**, and the framework already has the budget
mechanism to pay for it. Disposition table (all 23 codes — the closed set in
`corpus/runner.py::REASON_CODES` — defined once as data in
`internal/harness/disposition.go`):

| disposition | reason codes | automatic next action (each = one more EXEC, budgeted) |
|---|---|---|
| **escalate-bound** | `loop-bound-may-be-exceeded` | re-run same scaffold at `--loop-bound 8` → `16`, hard ceiling (default 32), then honest inconclusive. This is the escalation ladder K3 wanted for Kontrol, made cheap. |
| **escalate-flag** | `path-limit-reached` | one re-run at `--path-cap 256`; still capped → `--lowering splitting` (implemented; joins→per-exit VCs); still → inconclusive |
| **escalate-solver** | `solver-timeout` | one re-run at `--timeout-ms` × 4 within the exec wall-clock; `--solver portfolio` only on operator request (heavy, never automatic) |
| **spec-rewrite** | `vacuous-rule`, `vacuous-block` | **not a verdict about the contract — a finding about the spec.** The precondition is infeasible: the drafted rule asserts an impossible world. Route back to the spec queue (model rewrites BODY within the same scaffold), and record the vacuity as negative memory: the campaign believed a state was reachable that the model says cannot exist. That is signal the planner keeps. |
| **honest-refusal** | `unsupported-feature`, `unsupported-opcode`, `unsupported-storage-layout`, `rejected-feature`, `unrecognized-dispatcher`, `external-call-abstraction`, `summary-unverified`, `multi-call-ambiguous-call-site`, `multi-call-inner-arg-unsupported`, `multi-call-stmt-between-calls`, `invariant-uninitialized`, `invariant-unchecked-functions` | rung inconclusive + shape tag into the campaign's `model_gaps` tally (from `details`: `packed-storage:<C>.<f>`, `inline-assembly:<C>`, `immutable-variable:…`, `delegatecall-layout-compat-unverified`, `multi-contract-environment`, …). The planner downgrades prover legs on contracts whose gap profile says "unprovable here" — no repeated budget burn, no silent sweep. |
| **tool-error** | `tool-error` | escalate to operator; empty-details `tool-error` is an upstream bug — bundle path recorded if present. Never retried automatically. |
| **model-bug** | `unresolved-phi-source`, `unresolved-branch-cond`, `modelling-inconsistency`, `solver-disagreement` | rung inconclusive + filed as upstream issue material (by the tool's own law these are pipeline bugs — the integration harvests them, never hides them). |

Every escalation re-uses the scaffold bytes (hash-bound), so the EXEC chain
for one invariant is a readable proof ladder: k=4 refused → k=8 PROVEN. The
rung records the *winning* exec; the ladder stays in events.

### L4 — Evidence plane: where verdicts may and may not go

- **PROVEN-BOUNDED** renders (brief/audit/report, presence-gated) and
  informs the critic; per the G3 law it carries **zero gate weight** until
  the backtest says `improves` on held-out adjudicated rows. Same as halmos's
  first landing — no special pleading for the new kid.
- **counterexample (confirmed)** = E1–E3 host evidence: a concrete witness
  (call sequence, initial/final storage, `failed_assertion.expression`) that
  triage can promote. Full E4+ promotion keeps requiring the normal ladder:
  the witness compiles to a `sequence_poc` and reruns under `fork-runner`
  against the deployment — the prover's model is not the chain. "The report
  keeps whatever the tool says" stops at the rung, not at the finding. Where
  fork repro is impossible by policy (unbounded-value classes), the finding
  lands at its host-profile ceiling with the proof object cited — honest,
  capped.
- **counterexample (unconfirmed / modeled)** — crosses a havoc'd call or a
  pinned-known-bad encoding class: triage shows it, gate never credits it;
  disposition is "re-spec under `no-reentry`, or fork-repro the witness".
- **falsified intent claim** → negative memory via the existing
  disproved-hypothesis path (G8 pattern). Minicertora counterexamples are
  the first refutations that arrive with machine-checkable witnesses.
- **invariant rungs render as one-step induction**, never as "the invariant
  holds": the report's `invariant` object (`per_function[]` rows with
  `init`, `witness_function`) says exactly which step checked; the proof
  sidecar keeps it verbatim.

### L5 — Sweep plane: the inverse direction (templates, not ad-hoc rules)

Both provers only check what you spec. The framework's
`internal/archetypes` knows bug *classes*; the sweep plane closes that gap
deterministically (principle 4 — no model in the loop):

- A committed **rule template library** (`internal/harness/templates/`,
  data): one `.mspec` body per archetyped class the model can actually
  express — `wrap-unchecked` (`total >= before`), rounding-drain,
  donation-accounting, cap-respected, access-control-mint (auth case via
  `expect_revert`), privilege-escalation, tx-origin-auth. The prover's 33-
  target corpus is literally the template test suite (each `expected.json`
  pins the template's verdict on the fixture — L6).
- Rendering a template over the structural index (`internal/structidx`,
  `internal/corpus/shapes`) + snapshot is a pure function; the sweep emits N
  scaffold artifacts + a batch exec list under the normal `exec`/budget
  rails. VIOLATED lines enter findings as **ingest candidates** through the
  G1 adapter pattern — detector verdicts import as data
  (`provenance.tool = {name: minicertora, version, …}`), never as live gate
  dependencies.
- This is the framework's version of what Certora does on a codebase: spec
  once per class, run per contract, every result attributable, every refusal
  counted.

### L6 — Calibration plane: the two corpora grade each other

- **Its corpus → our fixtures.** `corpus/targets/*/expected.json` is
  committed ground truth (sol + spec + exact expected verdicts/reasons/
  witnesses/assumptions). Selected rows vendor into
  `internal/probes/testdata/` as probe/archetype fixtures — pinned with
  `tool`/`solc` versions and replayed by our suite as **toolchain-drift
  tripwires**: a z3 or solc upgrade that flips `wrap-unchecked` from
  VIOLATED must fail our golden loudly.
- **Our evalsuite → its scorecard.** Run the sweep templates over
  `assets/evalsuite` (19 gold rows): a prover scorecard on *our* bug
  distribution — precision/refusal profile per class, feeding the G3
  per-backend backtest and the G2 per-class weights. Until this scorecard
  exists, no minicertora rung moves any gate; treat the scorecard as the
  acceptance test for the whole wave.
- **Reason histograms as memory.** Per-campaign and (via
  `shared`/`globalize`) per-program disposition tallies — "minicertora
  refused 22/30 rules on this program, all `packed-storage`" — are planner
  facts, and exactly the cross-campaign learning the ladder exists to
  store.

## 3. Data contract (the exact seam)

One verdict line in → one `verification.harness` object out. Key mapping:

| minicertora report key | webv2 destination |
|---|---|
| `rule` (`INV_<n>__slug`) | attribution at `verify --harness-result INV-<n>` (exact match, no fuzz) |
| `verdict` + exit code | `rung` (L2 table; contradiction → inconclusive) |
| `confidence` | `proof.confidence` (+ gate rule in L4) |
| `reason` / `details` | `proof.reason` / summary tail / L3 disposition lookup / `model_gaps` tag |
| `bounds.loop_bound` | `bounded_k` (same field halmos's `k=` populates) |
| `bounds.path_cap`, `bounds.solver_timeout_ms`, `bounds.loop_bound_exhaustive` | `proof.bounds` (rendered in audit, not brief) |
| `assumptions[]` | `proof.assumptions[]` verbatim (includes `msg.value-default-zero`, `entry-binding:wrapper`, `external-call-abstraction`, `env-override:s<i>:<field>`, `solver:<name>`) |
| `params` / `initial_storage` / `calls[]` / `final_storage` / `failed_assertion.expression` | counterexample excerpt (brief, capped) + full witness stored as EXEC stdout artifact; the `sequence_poc` compiler (existing) consumes `calls[]` for repro: `calls[i] = {step, function, target?, args[], env{msg.sender, msg.value}, reverted, reentrant, overrides}` maps 1:1 onto a fork call sequence with per-step actor/value overrides |
| `ghosts[]` / `warnings[]` | `proof.ghosts` / `proof.warnings` (audit render only) |
| `tool_version` / `solc_version` / `spec_version` / `evm_version` / `optimizer_enabled` / `schema_version` | `proof.*` + cross-check against the EXEC record's `environment.tool_versions` (L0 mismatch rule) |
| abort line (no `rule` key) | rung inconclusive, `aborted: …` summary |
| `invariant` object (`per_function[]`, `init`, `witness_function`) | `proof.invariant_check` verbatim; rung honesty per L4 |

Schemas touched (all additive, presence-gated): `verification.harness`
gains optional `proof`; sandbox profile enum gains `minicertora`;
`harness_kind` choices gain `minicertora`. Nothing existing moves bytes.

## 4. Determinism posture

- The prover is Python + z3; we are "same inputs → same bytes". The bridge:
  **the verdict line is data, stored as captured** — replayability is
  guaranteed by the EXEC record (argv, workdir, pinned `--solc-path`, tool
  versions, sha-bound scaffold), not by promising z3 is deterministic.
  `portfolio`/`cvc5` runs may legitimately disagree; that is a recorded
  disposition (`solver-disagreement` + bundle), never a silently re-rolled
  verdict.
- `mapMiniCertora` is a pure function over `(stdout bytes, exit code,
  timedOut, scaffold hash)` — unit-testable against fabricated transcripts
  exactly like `mapHalmos` is today (harness fixtures: proved, violated,
  unconfirmed, aborted, contradictory, noisy-with-two-rule-lines).
- Golden impact: zero expected (new kind/profile/fields are unreachable in
  existing fixtures) — verified per task with the standard byte check.

## 5. Explicit non-goals (principle 6, recorded so they stay dead)

- Building a verifier or a CVL-subset lowering (Wave K non-goal restated;
  K4-full is superseded by L1, see §0).
- `PROVEN-UNBOUNDED`: minicertora never gets the unbounded rung; one-step
  induction is rendered as what it is. The rung stays reserved for K3.
- Multi-contract specs: `multi-contract-environment` is a named refusal —
  inter-contract bugs stay in the fork-repro lane (`forkdiff`,
  `sequencepoc`), where they are the framework's strength already.
- Auto-attribution of stray prover runs to invariants (no-guesswork rail,
  identical to halmos's).
- Gate weight for any minicertora rung before its G3 backtest row says
  `improves` on held-out adjudicated data.
- `--trust-unchecked-summaries` and `--assume-direct-calls` in generated
  commands: operator-only flags, and when used their assumptions ride into
  the proof sidecar anyway.
- Editing campaign state from the prover side, ever: minicertora answers
  queries; webv2 writes events (one-writer law).

## 6. Landing plan (Wave L-shaped, each task gated by its own tests)

| # | task | ships | tests |
|---|---|---|---|
| L-a | toolchain | profile `minicertora` + shim recipe + `toolVersions` probe + schema enum | argv allow/deny (pattern: `TestHalmosProfileRunsOnHost`), absent-binary omit |
| L-b | scaffold | `Kind MiniCertora`, `.mspec` renderer + BODY-window `Validate`, artifact naming | byte-pins incl. the "marker-spelling" naive-window behavior; scaffold-of-INV fixture |
| L-c | mapping | `mapMiniCertora` + rung bijection + proof sidecar + exit/line contradiction rail | fabricated JSONL transcripts each way; timeout-wins; abort-line rule |
| L-d | CLI | `--scaffold minicertora` / `--kind minicertora` choices; no new verbs | argparse parity; the existing harness-result flow untouched for halmos bytes |
| L-e | escalation | `disposition.go` table + re-run ladder driven through ordinary `exec` + `model_gaps` tally | per-disposition fixtures incl. vacuity → spec-queue + negative memory |
| L-f | sweep v1 | 6–8 rule templates + renderer over structidx + `provenance.tool` ingest | template corpus pins from vendored `expected.json` rows; byte check |
| L-g | calibration | evalsuite scorecard run (scripted, not a verb) + probes fixtures + shared-memory reason tallies | tripwire fixture; scorecard JSON golden |
| L-h | repro bridge | `calls[]` → `sequence_poc` compiler (confirmed counterexamples only) | anvil e2e with a wrap-unchecked witness (existing fork-runner tier) |

Order: a→b→c→d is the honest minimal integration (one invariant, one
scaffold, one exec, one rung — end to end, gate weight zero). e–h are the
"system" half; f is the one that makes it *faster than either tool alone*.

## 7. Errata to feed back before MiniCertora's last fixes land

From the source-vs-README inventory (worth fixing in its tree, both because
we will cite the README): (1) `summary` example uses a `balanceOf_initial(to)`
pseudo-builtin that is not in the grammar — summaries are `require`/`ensure`
over plain expressions; (2) §4 implies missing-assumptions ⇒ `vacuous-*`
refusal — vacuity is only infeasible-precondition/empty-path; the
assumptions floor is a corpus-check, not a CLI refusal; (3) `--prune-phis` is
documented but inert (`pruned_arms=0` always) — the table should say so;
(4) "EXP-heavy shapes are refused" has no code counterpart; (5) test counts
drift between README/§2c and collection — the fast tier collects 165 here,
not 164; (6) the abort-line convention ("no `rule` key") deserves a bolded
line in §2a because integrators key on it (we do — L2 rule 1).

## 8. Operational loop (the "second pass", made a system)

Per campaign, after `plan`:

```bash
# 1. queue = INV ledger + halmos/forge inconclusives + deferred hypotheses
webv2 brief $CID                       # what is unproven and matters
# 2. spec it (model writes BODY only; boundary validates)
webv2 verify $CID --scaffold minicertora --invariant INV-7
# 3. prove it (host profile, pinned toolchain; escalation = more execs)
webv2 exec $CID --profile minicertora --command \
  'minicertora target/src/V.sol artifacts/HARNESS-INV-7-minicertora.mspec \
   --solc-path /abs/solc-0.8.36 --loop-bound 4 --timeout-ms 30000'
webv2 verify $CID --harness-result INV-7 --exec EXEC-12 --kind minicertora
#    → INV-7: counterexample (minicertora, EXEC-12)      [or PROVEN-BOUNDED k=4]
# 4. promote honestly: witness → sequence_poc → fork-runner → E4+ ladder
# 5. learn: disposition tallies to shared memory; vacuity → negative memory
```

The single-tool world gives you a verdict per rule. The system gives you:
which rules *should* be proved next (planner), what a refusal *costs and
implies* (dispositions), whether a witness is *money-real* (fork repro),
what the campaign should *remember* (ladders), and — the part neither side
has today — a *scorecard* of the prover itself on the bug distribution you
actually get paid for.

