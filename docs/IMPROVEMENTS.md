# web3sec-go Improvement Plan — post morph-campaign review

Date: 2026-09-10 · Status: PROPOSAL → implementation in waves A→E.

Source: the Morph L2 rollup campaign (`C-42bd211e3e`, 537 events, 52 findings,
snapshot `22ca805e`) against the gold-standard eval with two planted bugs
(G-01 `commitBatch` prevStateRoot unvalidated → chain freeze; G-02
`onDropMessage` safeTransfer-not-mint → unrecoverable reverse deposits).
Both golds were found (critic-confirmed) — the failure mode is **precision and
calibration, not recall**. This plan fixes that, plus the plumbing defects the
campaign exposed. All anchors below were verified against the code on
2026-09-10.

## Scorecard recap

| Dimension | Observed | Target |
|---|---|---|
| Recall (golds found) | 2/2 | 2/2 (keep) |
| Critic-confirmed findings | 23 of 52 | precision budget + ranking (A3) |
| G-02 severity | 4.0 medium | ≥ 6.5 high (E5 reversibility) |
| G-01 severity | 9.0 critical | keep (liveness clause B2) |
| Scope / known-issues policy | no accepted-risk channel | first-class policy input (A1) |
| Submission readiness | `confirmed: 0` in report | dual counting (D1) |
| Chains (G-01 freeze half) | none materialized (dead code) | HYPOTHESIS chains (B3) |
| Pipeline `run` | report stage "module not wired" | wired (D2) |
| `webv2 audit` | FAIL: stale ghost artifact hashes | green after reconcile (D3) |
| Tier-2/3 dedup | unreachable: hand-written 16-hex | CLI + adapter dispatch (D4) |

## Design principles

1. **Go is the source of truth.** The Python twin is deprecated; no
   byte-compat obligation, but `scripts/golden.sh` must stay green (179 steps ×
   2 twins, 68 files byte-match). New features are **additive**: new CLI verbs,
   new flags with defaults that preserve current output, new report sections
   gated behind the new fields being present. Where a new section changes an
   existing report's bytes for an existing campaign, a
   `KNOWN_DIVERGENCES.md` row is added.
2. **Fail-open where judgment, fail-closed where money.** Accepted-risk hits
   flag + block submission (not hard-reject like exclusions); evidence floors
   stay fail-closed.
3. **Every gate check gets a named waiver path** (existing `waive` verb,
   stage-scoped) — a check that cannot be waived is a trap, not a guard.
4. **Deterministic where possible.** The new capabilities (C1, C2) and the
   in-code-ack matcher (A2) are pure functions over the structural index /
   finding anchors — no model in the loop.
5. **Tests:** every item ships a unit test; the morph campaign is the
   integration fixture (a copy under `testdata/` for the regression suite).
6. **Surface budget (2026-09-10, user directive after C2/D6/D3/D4/D5).** The CLI
   is the product's largest hand-maintained surface (76 registered verbs across
   84 CLI files, counted 2026-09-10) and every verb is a permanent contract:
   usage text, help text, argparse parity, docs, a test. So a new capability lands as a **flag on
   an existing verb** unless it clears one bar: *an existing capability is
   demonstrably unreachable from any command*. A verb that duplicates what
   another verb already does (`memory promote` vs `memory --approve`, which
   already prints the promotion commands), or reaches a path nothing calls, is
   not worth the contract. A change that only makes an existing capability
   honest — a truthful count, a proof that can go green, a state that stops
   being permanently stale — always is, even when it changes bytes. When the bar
   is not met, the item stays in this document as a deferred ask, which is what
   Wave E is.

---

## Wave A — Precision & Scope  *(the single biggest problem)*

### A1. `accepted_risks[]` in the bounty policy

**Failed behavior:** the policy has only `exclusions[]` (schema
`assets/schema/bounty_policy.schema.json`, `kind` enum incl. `known-issue`),
and `bounty.go` check4 **fails closed** on any exclusion hit — no way to say
"known, accepted, do not pay, do not block the report". The operator had no
first-class channel for "this is a documented known issue the program accepts".

**Design:**
- Schema: add `accepted_risks: array` to `bounty_policy.schema.json`, items
  `{pattern (required), kind?, reference?, note?, min_severity?}` — same
  pattern-matching semantics as exclusions (substring over class/title/
  description, `internal/bounty/bounty.go` exclusion matcher).
- New gate check **check13 `accepted-risk`** in `internal/bounty/bounty.go`
  (after check12, before `submission_ready` assembly at L1040): on hit, set
  `finding.bounty.accepted_risk = {pattern, kind, reference, note}` and add a
  **blocker** `accepted-risk-hit` (submission_ready=false) — *but* the
  exclusion check4 no longer treats an `accepted_risks` hit as an exclusion
  (accepted risks are removed from the exclusion tripwire set when both match
  the same pattern — accepted-risk is the *narrower*, more specific rule).
- Named waiver: `webv2 waive <CID> accepted-risk --subject
  <finding|*> --reason "..."` (the stage name matches the check, as with
  `mainnet-fork-poc` and `immunization`); accepted-risk blockers are waivable
  per-finding. A waiver on an accepted-risk blocker is logged with `reason`
  and rendered in the report (new line in the finding section).
- Report: findings with an accepted-risk hit render under a new
  "Accepted-risk findings" subsection (D1 adds the table anyway) — visible,
  counted, but not in the submission table.

**Anchors:** `assets/schema/bounty_policy.schema.json` (after `exclusions`);
`internal/bounty/bounty.go` check4 (~L577-983 region) + check13 +
`submission_ready` (L1040); `internal/report/report.go` new subsection.
**Tests:** unit — hit/miss/narrower-rule/waiver; policy schema round-trip.

### A2. In-code acknowledgement matcher (`in_code_ack`)

**Failed behavior:** G-02's `onDropMessage` path sits in code that is
acknowledged-in-spirit by surrounding comments/conventions, and the framework
had no way to demote "this is a stub / not implemented / owner-intended"
acceptance likelihood. Dismissal vocabulary was never scanned anywhere
(see B4 for the probe-side twin).

**Design:**
- New pure function `internal/findings/ackscan.go`:
  `InCodeAck(f finding, idx structidx) (ack *Ack, err)` — for each anchor
  (file/function/line from `affected[]` + `exploit_sequence[]` sites), read
  the source lines in a ±N window (N=12) and scan for acknowledgement
  phrases (configurable list in the function, case-insensitive):
  `not implemented`, `stub`, `placeholder`, `todo`, `fixme`, `hack`,
  `simplified`, `temporary`, `for testing`, `not yet`, `pending impl`,
  `unimplemented`.
- On hit: set `finding.dedup_meta.in_code_ack = {file, line, phrase,
  window}` (additive finding field, schema `finding.schema.json`
  `dedup_meta` is a free object) and stamp an event
  `finding.ack_scanned` (data: finding_id, hit bool, ack).
- **Effect:** (a) new advisory in the gate report — `in_code_ack present:
  acceptance likelihood demoted`; (b) feeds the A3 acceptance score as a
  negative factor; (c) report finding section shows the hit quote.
- CLI: `webv2 ack <CID> [finding]` (scan one or all live findings, idempotent
  re-scan) — deterministic, no model.
- Runs automatically as part of `webv2 ingest` (post-save hook) so the flag is
  present from the moment a finding is filed.

**Anchors:** new `internal/findings/ackscan.go`; hook in
`internal/findings/ingest*.go` post-save; new CLI verb
`internal/cli/cmd_ack.go`; `assets/schema/finding.schema.json`
(`dedup_meta.in_code_ack` documented).
**Tests:** phrase windowing, multi-anchor, idempotence, no-hit case.

### A3. Precision budget + acceptance ranking

**Failed behavior:** 23 critic-confirmed findings, 2 golds. The report counts
statuses (`report.go` L488-547) but never ranks findings by *acceptance
likelihood*, never shows a false-positive ratio, and the submission table has
no cap — an operator cannot tell which 5 of 23 are worth paying attention to.

**Design:**
- Policy: `submission_budget: {max_findings: int (default 0 = uncapped),
  rank_by: "acceptance" | "severity" (default "acceptance")}` in
  `bounty_policy.schema.json`.
- Acceptance score (deterministic, `internal/risk/acceptance.go` new file):
  `acceptance = wSeverity(band) + wEvidence(evidence_level) + wCritic(verdict)
  - wDemotion(in_code_ack ? 1.0 : 0) - wAcceptedRisk(hit ? 2.0 : 0) +
  wReversibility(irreversible +1.0 / trusted-party +0.5 / reversible 0)`.
  Weights: severity critical 3.0 / high 2.0 / medium 1.0 / low 0.5; evidence
  E0 0.0 … E7 3.0 (reuse `wLevel` from `risk.go:53-57`); critic keyed on
  the REAL `critic_verdict` enum — `confirmed` +1.5, `disproved` −2.0
  (the only verdict that DISQUALIFIES the finding: it drops out of the
  top-K table, named below it), every other recorded verdict 0 (the
  non-committal `pending`/`possible`/`informational` and the scope
  verdicts `duplicate`/`out_of_scope` — the live-set filter already
  removes the scope ones). Score clamped at 0 (a number this low means
  "do not spend reviewer time here"; negative likelihood is not a thing).
- Finding field `risk.acceptance_score` (float, additive) computed by
  `webv2 gate` (and `webv2 run` at bounty-gate stage) and stored on the
  finding; the report recomputes it live (the stored value is the gate's
  audit trail, never the source of truth).
- Report "Results" section: add **Precision** block — `critic-confirmed: N`,
  `evidence-confirmed: M` (dual counting, D1), `top-K by acceptance` table
  (K = `submission_budget.max_findings`, or top 10 when uncapped), and
  `false-positive ratio = (critic-confirmed − evidence-confirmed) /
  critic-confirmed` when both > 0. Submission table capped at
  `max_findings` when set, with a note line when capped. Presence-gated
  (the additive convention, §1): the block renders only when an A3 field
  is present — `risk.acceptance_score` stored on at least one finding, or
  `submission_budget` in the policy — so a pre-A3 campaign's report bytes
  are unchanged.
- CLI: `webv2 gate <CID>` (existing) re-runs scoring; `webv2 rank <CID>`
  new verb — prints the acceptance-ranked table (the operator-facing answer
  to "which findings matter").

**Anchors:** `assets/schema/bounty_policy.schema.json`; new
`internal/risk/acceptance.go`; `internal/bounty/bounty.go` (score at gate
time); `internal/report/report.go` Results section (L488-547) + submission
line (L544); new `internal/cli/cmd_rank.go`.
**Tests:** `internal/risk/acceptance_test.go` (exact weights, demotions,
clamp-at-0, the real critic vocabulary, monotonicity, ranking order,
top-K cap); `internal/bounty/bounty_test.go` (gate stores the score —
rounded to 2dp, schema-valid finding, not leaked into the gate result);
`internal/report/precision_test.go` (dual counts + ratio, table order,
disqualified line, budget cap + note, uncapped, and the presence gate —
no A3 field, no bytes); `internal/cli/cmd_rank_test.go` (byte-exact
table, no-findings, budget header, argparse taxonomy). Golden: the
`gates` scenario `calibrate_all` oracle gained the `acceptance_score`
key (see KNOWN_DIVERGENCES, IMPROVEMENTS waves row).

### A4. Paid-exploitability argument (mandatory before submission)

**Failed behavior:** nothing in the pipeline forces the question "who pays,
and why does the bug make them pay?" — the difference between a bug and a
bounty finding.

**Design:**
- Finding field `exploitability: {paid: bool, argument: string (≥ 200 chars
  when paid=true)}` — additive in `finding.schema.json` (not in `required`;
  presence + validity checked by the gate).
- New gate check **check14 `paid-exploitability`**: blocks submission_ready
  when `paid: true` and argument missing/too short, OR when `paid` is absent
  on a CONFIRMED/CHAIN finding with `economic_impact.extractable_usd > 0`
  (an extractable claim must have answered the question). `paid: false` with
  an argument is allowed (the argument then records *why it is not payable*).
- Waivable per-finding via the existing `waive` verb (reason required).
- Adapter prompt: add to `structuredOutputs` (adapter.go:516-523) a
  `findings.set_exploitability(campaign, finding_id, paid, argument)` entry —
  and per D4's dispatch fix, make it actually callable.
- Report: finding section renders the argument (collapsed to first line in
  the table, full in the finding detail).

**Anchors:** `assets/schema/finding.schema.json`;
`internal/bounty/bounty.go` check14; `internal/adapter/adapter.go:516-523`;
`internal/cli/cmd_ingest*.go` (setter verb `webv2 exploit <CID> <F> --paid
--arg "..."`).
**Tests:** length validation, extractable-implies-answer, waiver.

---

## Wave B — Liveness & Chains  *(the missing half of G-01)*

G-01 was found as a correctness finding, but its real impact — **the chain
freezes** — was unpriceable: the impact model has no liveness terminal, and
the chain engine (the mechanism that would turn "commitBatch can be bricked"
into "sequencer liveness loss → all users" as a materialized chain) has a
hard gate that only accepts CONFIRMED/CHAIN members, while the finding sat at
HYPOTHESIS with E0 evidence.

### B1. Liveness terminal in taxonomy + chain engine

**Design:**
- `internal/taxonomy/` (terminal capability table): add capability
  `LIVENESS_LOSS` — a non-economic terminal. Severity mapping for pricing:
  `LIVENESS_LOSS` prices at the `protocol-solvency` blast-radius weight (7.0)
  floor, since a frozen chain freezes every user's funds (bridge-canonical 8.0
  when the frozen asset is bridged capital).
- `internal/chainengine/terminal.go`: `terminalNodes` (L118) currently loads
  only CONFIRMED/CHAIN findings — extend with an `includeHypothesis bool`
  mode used by the B3 verb; `terminalPathDoc` (L210) accepts
  `terminal_capability = LIVENESS_LOSS` (no capital field required — the
  `CAPITAL_FIELDS` check is bypassed for the liveness terminal, mirroring how
  `ATTACKER_BASELINE` is handled).
- `internal/impact/` pricing: a chain ending in `LIVENESS_LOSS` yields
  `economic_impact.kind = "liveness"` with a non-USD note; the risk
  calibration stage picks up blast_radius `all-users`/`protocol-solvency`
  automatically from the terminal (no new factor needed — E5 covers the rest).
- Schema: `chain.schema.json` `terminal_capability` enum += `LIVENESS_LOSS`
  (additive).

**Anchors:** `internal/taxonomy/*.go` capability registry;
`internal/chainengine/terminal.go:118,210`; `internal/impact/*.go`;
`assets/schema/chain.schema.json`.
**Tests:** liveness chain materializes; pricing floor; golden-safe (new
terminal id only appears when a finding declares the capability).

**As-built (Go-only, the Python twin is retired):**
- The capability registry is `internal/capabilities/` (not a taxonomy dir):
  `KINDS` gains `"liveness"`, `COMMON["liveness"] = {liveness_loss}`, and
  `TERMINAL_KINDS` becomes `{asset, liveness}` — so `IsTerminal` (and every
  consumer: the chain search, `relations` drift diagnostics, `sharedmem`
  signatures) now treats `liveness_loss` as a terminal. `IsLivenessTerminal`
  / `IsEconomicTerminal` split the two flavors. Vector rows pinned in
  `testdata/vectors/capabilities.json` (LIVENESS_LOSS, liveness loss,
  drain_treasury, control_protocol_pause).
- `internal/chainengine/terminal.go`: `terminalNodesMode(c,
  includeHypothesis)` is the new seam — default mode (CONFIRMED/CHAIN) is
  byte-identical to before; the mode also admits every non-TERMINAL status
  (HYPOTHESIS..POSSIBLE) for B3. Exported as `FindTerminalChainsMode`
  (B3's `chain --unproven` will call it); `FindTerminalChains` delegates.
  `terminalPathDoc` needed no change: `IsTerminal` covers the liveness
  label and the capital fields default to 0/empty — the "no capital field
  required" clause of the spec.
- Pricing lives at materialization, not in an impact verb:
  `MaterializeChain` runs `livenessImpact` when the (verified) terminal
  annotation names a liveness capability — `economic_impact.kind =
  "liveness"`, blast_radius FLOORED at `protocol-solvency` (a member claiming
  `bridge-canonical` keeps its 8.0; the floor never downgrades), and the
  named non-USD decision `priceable: false` + `ceiling` (the freeze itself
  is the impact). `risk.validated_risk` then picks the blast weight up
  automatically (wBlast 7.0/8.0) — no new factor, per the spec.
- The `TerminalReport` note gains a liveness sentence **only when a
  liveness terminal actually surfaced** (presence-gated — the golden note
  bytes are unchanged for every existing campaign).
- Schemas: `finding.schema.json` `economic_impact.kind` is a new additive
  property (enum `["liveness"]`; absent = ordinary economic impact, so the
  closed-object schema and every pre-existing finding keep their behaviour —
  the ingest legend picks up the one new line `economic_impact/kind:
  liveness`, pinned in `t14FindingLegend`). `chain.schema.json`
  `terminal.capability` is a free string (not an enum — the spec's enum
  assumption did not match the actual schema), so the terminal description
  was updated instead; the liveness terminal is named there.
- `webv2 terminals`, the privileged track, and the brief all render liveness
  rows through the existing generic paths — no CLI changes.
- Tests (`internal/chainengine/liveness_test.go`): materialization with the
  terminal annotation (kind/blast floor/priceable/ceiling, no USD figures),
  bridge-canonical preservation, un-annotated pair stays unpriced
  (golden-safety), liveness terminal found by the default search,
  `FindTerminalChainsMode` surfacing a HYPOTHESIS terminal (default mode
  must not), the presence-gated note both ways, and the registry vectors.

### B2. Mandatory adversarial-game clause for liveness findings

**Failed behavior:** a "freeze" finding can be dismissed as "liveness-only,
the owner can revert" with no requirement to answer *who profits from the
freeze and how the challenge/governance interplay fails*. That is exactly how
G-01-class findings get buried (3/32 dispositions in the morph campaign used
dismissive vocabulary — B4 lints the probe side; B2 lints the finding side).

**Design:**
- Finding field `adversarial_game: {who_profits: string,
  profit_mechanism: string, challenge_interplay: string}` — required (all
  three, ≥ 20 chars each) when the finding's `root_cause.class` is a
  liveness class (`chain-freeze`, `sequencer-halt`, `liveness`, or any class
  whose terminal is `LIVENESS_LOSS`) **or** when `economic_impact.kind ==
  "liveness"`.
- Gate check **check15 `adversarial-game`** (`bounty.go`): blocks
  submission_ready on missing/incomplete clause for liveness findings.
  Waivable per-finding (waiver + reason).
- Adapter: `findings.set_adversarial_game(campaign, finding_id, game)` in
  `structuredOutputs` (callable per D4).
- Report: finding section renders the clause; the liveness findings
  subsection lists `who_profits` per row so an operator sees the incentive
  argument at a glance.
- Planner seed: the L-01 liveness lens (`internal/planner/lenses.go` seed
  `L-01`) gets a hint appended: "for every liveness hypothesis, file the
  adversarial_game clause at ingest — the gate requires it".

**Anchors:** `assets/schema/finding.schema.json`;
`internal/bounty/bounty.go`; `internal/adapter/adapter.go:516-523`;
`internal/report/report.go`; `internal/planner/lenses*.go`.
**Tests:** class-trigger matrix, waiver, short-field rejection.

**As-built (Go-only, the Python twin is retired):**
- The clause lives in `internal/findings/adversarial.go`:
  `AdversarialGameFields` (who_profits, profit_mechanism,
  challenge_interplay — that order, preserved in the stored object),
  `AdversarialGameFieldMin = 20` counted in **runes** (not bytes, matching
  `BlankReasonMin`), `IsLivenessFinding` (class in `LivenessClasses`
  {chain-freeze, sequencer-halt, liveness} **or** `economic_impact.kind ==
  "liveness"` **or** a granted capability whose kind is a liveness terminal),
  `AdversarialGameDeficits` (`["missing"]`, the short/absent field names, or
  empty), and `SetAdversarialGame` — which validates every field before
  touching disk (an `InputError`, so nothing is persisted and no event is
  logged on a short field) and then logs `finding.adversarial_game_set`
  carrying the three per-field character counts.
- Schema: `finding.schema.json` gains `adversarial_game` (object,
  `additionalProperties: false`, the three strings `minLength: 20`, all
  required) as an **optional finding-level property** — the schema cannot
  express "required only for liveness findings", so presence is enforced by
  check15, not by ingest. A non-liveness finding may carry the clause
  harmlessly (the report renders it; the gate does not read it).
- Gate: **check15 `adversarial-game`** (`internal/bounty/bounty.go`) runs
  last, after check14. Non-liveness → an explicit "not a liveness finding"
  pass row. Liveness → waiver lookup on stage `adversarial-game`
  (`subject` = the finding id or `*`), then `AdversarialGameDeficits`:
  complete → pass; otherwise a fail row whose detail names the single short
  field or lists the incomplete set, plus (absent a waiver) the blocker
  "liveness finding has no adversarial_game clause". A waiver keeps the fail
  row and adds the waived pass row, exactly like the other waivable checks.
  `BountyRemediation["adversarial-game"]` names the CLI verb, and because
  `GateExplain` is map-driven, `webv2 gate explain <CID> adversarial-game`
  resolves without a code change.
- CLI: `webv2 adversarial-game <campaign> <finding> --who-profit X
  --mechanism Y --interplay Z` (`internal/cli/cmd_adversarial.go`, ord 71).
  All three flags are required — a missing one is an argparse-shaped
  `t14ArgparseErr` ("the following arguments are required: …" listing every
  absent flag) → exit 2; `--flag=VALUE` works; a missing campaign/finding is
  `t14ExitErr` → exit 1. Success prints
  `<CID>: adversarial-game clause recorded (who_profits N chars) — the
  adversarial-game gate clause is now complete`.
- Adapter/planner: `structuredOutputs()` gains the `adversarial_game` key
  (the model sees the callable verb in ingest context), and
  `lensQuestions["liveness"]` carries the "file the clause for every
  liveness hypothesis" hint so the lens seed asks for it at ingest.
- Report (both blocks presence-gated — a campaign with neither the clause
  nor a liveness finding is byte-identical to pre-B2): `findingSection`
  renders the three clause lines after the exploitability block when
  `adversarial_game` is present; `Generate` emits a "### LIVENESS FINDINGS
  — who profits from the freeze" subsection **before** the confirmed
  sections, one row per liveness finding at **any** status (sorted by id)
  — `who_profits` when answered, `UNANSWERED (gate check15)` otherwise — so
  a freeze finding at HYPOTHESIS is visible instead of silently missing.
- Golden: no existing campaign declares a liveness finding or the clause,
  so every rendering path is unreachable in the fixtures. The intentional
  oracle updates are the planner lens text (changes the plan content, hence
  the pinned plan sha256s and scenario/probe lens strings in
  `internal/planner/testdata/*.json`), the orchestrator `gates` scenario's
  `bounty_gate_all` oracle (the check15 row, 15 → 16 rows), and the bounty
  unit goldens (`internal/bounty/bounty_test.go`: 21 gate vectors — the four
  new cases are `adversarial_{missing,short,waived,complete}` — the
  16-row `TestFullSubmissionReady` / `EvaluateSavesFindingAndLogs` counts,
  the `explain` / remediation catalogs, and the sorted unknown-check list).
  Regenerated by replaying the Go scenarios, not by re-running the retired
  twin.
- Tests: `internal/findings/adversarial_test.go` (6 — trigger matrix,
  deficits, set/overwrite, three short-field rejections, unknown finding),
  `internal/cli/cmd_adversarial_test.go` (5 — record + print, `=` form,
  short field exit 2, argparse failures, unknown finding exit 1),
  `internal/report/report_adversarial_test.go` (3 — clause renders only with
  the data, liveness subsection goes UNANSWERED → answered on the next
  generate, economic-only campaign renders neither), and the four bounty
  gate vectors.

### B3. Chain materialization at HYPOTHESIS (`--unproven`)

**Verified state:** `chainengine.MaterializeChain`
(`internal/chainengine/materialize.go:33`) has **zero non-test callers**; its
hard gate (L157-169) rejects any member not in {CONFIRMED, CHAIN};
`checkPins` (L197-218) requires one shared non-null pin; the orchestrator's
`chainFindings` (`internal/orchestrator/chain.go:176`) only filters by
`nonDuplicate` (L42) — so proposals exist at HYPOTHESIS, but nothing can
materialize them. The campaign's `chaining` stage note says exactly this:
"proposals become chains on …" (never, in practice).

**Design:**
- New CLI verb `webv2 chain <CID> <chain-id|F-ids...> [--unproven]
  [--note ...]`:
  - default: existing behavior (members must be CONFIRMED/CHAIN — the hard
    gate stays for proven chains);
  - `--unproven`: members may be HYPOTHESIS (any evidence level); the
    materialized chain is stamped `chain.provenance = "unproven"` and every
    member link carries `link_evidence = <member's evidence level>`;
  - `checkPins` relaxed for `--unproven` to "members may share one pin OR be
    pinned to the active snapshot" (G-01's members were all pinned to
    `src-22ca805e` anyway, but cross-snapshot hypothesis chains are legal as
    *proposals*).
- Materialized unproven chains: (a) appear in `report.md` under a clearly
  marked "Unproven chains (hypothesis-level)" section — never in the
  submission table, never counted as evidence-confirmed; (b) feed the chain
  engine's terminal search in B1's `includeHypothesis` mode so a HYPOTHESIS
  G-01 can still price its `LIVENESS_LOSS` terminal (with an "unproven"
  caveat in the pricing note); (c) `webv2 chains <CID> list` renders the
  provenance.
- Event: `chain.materialized_unproven` (distinct from `chain.materialized`).
- This is the mechanism that turns "52 findings, 0 chains" into "G-01 freeze
  chain: F-0f0af9039f30 → sequencer liveness loss, UNPROVEN (E0)".

**Anchors:** `internal/chainengine/materialize.go:33,157-169,197-218`;
`internal/orchestrator/chain.go`; new `internal/cli/cmd_chain.go` (or extend
the existing `chains` verb file); `assets/schema/chain.schema.json`.
**Tests:** unproven gate pass/reject, pin relaxation, provenance stamping,
golden-safe (no new output for existing campaigns without the flag).

**As landed (B3):**
- `internal/chainengine/materialize.go` carries the whole change.
  `MaterializeOpts{Unproven bool}` + `MaterializeChainOpts(...)` are the new
  entry point; `MaterializeChain` (the Python-era signature, six args) now
  delegates with `Unproven: false`, so every existing caller and byte shape is
  untouched. `loadChainMembersMode` drops the status gate only for unproven;
  `checkPinsMode` is the gate table described below; `chainLinksMode` adds
  `link_evidence` (`bestEvidenceLevel`: the strongest E-level on the link's
  `from_finding`, `E0` when it has none) to each link for unproven;
  `writeChainDoc` appends `provenance` only when non-empty (a proven doc has
  no such key — the pre-B3 byte shape); the event is
  `chain.materialized_unproven` with data `{members, evidence_floor,
  provenance}` and no `super_finding`.
- **No super-finding — a deliberate tightening of the design.** The design
  asked for an unproven chain that (a) is never counted as evidence-confirmed
  and (b) prices its liveness terminal. In Go the price lives on the CHAIN
  super-finding's `economic_impact`, and a CHAIN-status finding is read as
  confirmed by *at least* the report's confirmed count, the bounty-gate re-run
  inside `Generate`, `TerminalReport`, the briefing and relations — so (a)
  cannot hold while a super-finding exists without filtering every one of
  those consumers, and each miss silently upgrades a lead. Materializing the
  doc alone gives (a) structurally: the members keep their statuses, no
  finding is written, and no code path can see the chain as evidence. The
  cost is (b): with no finding there is no `economic_impact`, so the price is
  **not** asserted — the report's unproven section states the price that would
  apply ("a liveness freeze would price at the blast-radius floor … no price
  is asserted") and names the terminal (`derivedTerminal`, which is exactly
  B1's `FindTerminalChainsMode(..., includeHypothesis=true)` seam, matching
  the derived path set to the member set and carrying `via_finding` +
  `total_capital_required_usd`). `livenessImpact` therefore keeps its original
  single-argument signature: no dead `unproven` branch. Documented as a
  divergence rather than silently.
- **Pin relaxation, as implemented.** The design's literal words ("share one
  pin OR be pinned to the active snapshot") collapse to the proven rule for a
  non-empty set — a set that is all-active *is* a shared pin — so the
  meaningful relaxation is admitting a mixed set. `checkPinsMode(pins,
  unproven)` therefore accepts any set of non-null pins for unproven
  (including ingest's `unpinned` placeholder, which is what a finding carries
  when no snapshot was active yet) and still refuses a member with no pin at
  all: a chain with no stated basis is not a lead. The proven path is
  byte-for-byte the old rule and error text.
- CLI `internal/cli/cmd_chain.go`, **ord 72**: `webv2 chain <campaign>
  <finding> <finding> [...] [--unproven] [--note NOTE] [--title TITLE]`.
  Positionals are greedy (argparse `nargs='+'`), `--flag=VALUE` works,
  `--unproven=true` is rejected as argparse rejects an explicit argument to
  `store_true`, `-h/--help` prints the verb's help block (Go-only verb — the
  prose is ours), and a refusal from the proven gate maps to exit 2 with
  `chain failed: … — pass --unproven to materialize a hypothesis-level
  chain`. Default title is the member path `<F-a> -> <F-b>` (deterministic, and
  comfortably past the chain schema's 10-rune title floor); `--note` becomes
  the narrative. Success prints one line: `CHAIN-…: unproven chain materialized
  from 2 members (evidence floor E0), terminal liveness_loss via F-…, no
  super-finding (hypothesis-level)`. (`adversarial-game` from B2 gained the
  same `-h/--help` treatment in this wave.)
- `chains` renders the provenance as a suffix on the materialized row and
  splits its headline when one exists (`materialized chains: 2 (1 unproven —
  hypothesis-level leads, not evidence)`) — both appended only when an
  unproven chain is present, so a campaign without one prints the pre-B3
  bytes; same marker on the `terminals` rows (an unproven chain's terminal is
  a destination, not a result). Adapter `structuredOutputs()` gains the
  `chain` key.
- Report (`internal/report/report.go`): `splitChainsByProvenance` is the one
  split (field presence; a pre-B3 doc with no `provenance` key is proven), the
  `- chains materialized: **N**` line counts `len(provenChains)`, and when
  `len(unprovenChains) > 0` a `- unproven chains (hypothesis-level): N — leads
  only, never counted as confirmed` line follows. The unproven chains render
  in their own `## Unproven chains (hypothesis-level)` section after the
  proven `### CHAIN:` blocks: `### UNPROVEN CHAIN: <title>`, id + provenance +
  evidence floor, members, narrative, per-link `from-member evidence E…`, and
  the terminal with the no-price-asserted note. Both blocks are
  presence-gated, so a campaign without an unproven chain is byte-identical to
  pre-B3 (asserted in the tests, not assumed).
- Schema `assets/schema/chain.schema.json`: `provenance` (enum `["proven",
  "unproven"]`, default `proven`) as an optional top-level property, and
  `link_evidence` (enum `E0`–`E7`) as an optional property of each
  `capability_links` entry — both additive, neither required, so every
  existing chain doc still validates.
- Tests: `internal/chainengine/unproven_test.go` (6 — doc/provenance/
  link-evidence/derived-terminal/no-super-finding/event, cross-snapshot pins
  vs the proven refusal, the proven refusal + proven byte shape with a
  super-finding, the `checkPinsMode` table, duplicate rejection),
  `internal/cli/cmd_chain_test.go` (5 — help, six argparse vectors, the
  unproven path end to end through `chains`, the proven refusal hint, the
  missing-campaign mapping), `internal/report/report_unproven_test.go` (2 —
  the section + count lines + "chain id appears exactly once", and the
  presence gate).
- Golden: **no oracle updates and no normalization**. No fixture calls
  `chain --unproven` (`MaterializeChain` stays the default path), the schema
  additions are optional, and the new verb's help/usage text is not captured
  by any scenario step. `scripts/golden.sh` and `go test ./...` are green.

### B4. Disposition linter (D1 — would have caught the G-01 miss)

From `docs/feedback-triage.md:277-299` (open since 2026-09-09): G-01 sat at
rank 1 of the probe surface and was discharged `answered` (safe) with free
prose; disposition reason text is never checked (`internal/planner/answered.go`,
`internal/probes/closure.go`). In the morph campaign, 3/32 dispositions
contained dismissal vocabulary and those 3 are *exactly* the dispositions
that buried G-01.

**Design — ship v1 + v2 (v3 as a follow-up):**
- **v1 (warning, ~20 lines):** at disposition time (probe `answered`/
  `deprioritized` rows), scan `reason` for dismissal vocabulary:
  `liveness-only`, `liveness only`, `owner-revert`, `owner can revert`,
  `not exploitable`, `never permanently`, `until the owner`, `no economic
  impact`, `no profit`. Flag rows that are **tier-0 or gap ≥ 3** (the
  high-priority surface). Surfaced in `webv2 brief` and `report.md` under
  "Disposition review" (new section: flagged rows with row_id, probe, rank,
  reason quote).
- **v2 (refusal, ~80 lines):** the rule — *a tier-0 or gap≥3 row may not be
  discharged `answered` on a compensating-control argument without an
  exec-backed or invariant-backed refutation* — enforced in
  `probes/closure.go` as a hard gate with a named override
  `webv2 answered <CID> <row-id> --override-dismissal --reason "..."`
  (logged as `probe.dismissal_overridden` with actor+reason; the override is
  listed in the report).
- **v3 (structural, later):** reason text must reference a symbol/contract
  from the row's own surface entry (checkable against the structural index,
  same seam as B5's anchor validation); a dismissal citing another finding
  must cite a real finding id.
- **Finding-side twin:** the same vocabulary scan runs over finding
  `verdict` reasons at `webv2 verdict` time (advisory warning only — the
  finding-side rule is softer because verdicts are human judgment).

**Anchors:** `internal/probes/closure.go`; `internal/planner/answered.go`;
`internal/cli/cmd_answered.go` (new override flag);
`internal/report/report.go` (Disposition review section);
`internal/briefing` (brief output).
**Tests:** vocabulary table, tier-0/gap≥3 gating, override logging,
morph-campaign fixture (the 3 flagged rows reproduce).

**As-built (Go-only, the Python twin is retired):**
- The gate lives in `internal/planner/answered.go` (`checkDismissalGate`,
  wired into `MarkAnswered` after the anchorless check) — that is the actual
  disposition seam; `probes/closure.go` only carries the axis-surface
  blocker and was left alone. `internal/planner/disposition.go` holds the
  vocabulary (`DismissalPhrases`/`DismissalHits`), the high-risk rule
  (`HighRiskRow`: tier 0 or gap ≥ 3, missing tier reads as 0), the v1 scan
  (`DispositionReview`), and the backing check (`refutationBacked`: an
  `EXEC-` ref needs `execs/EXEC-*/exec_record.json` on disk; an `INV-` ref
  needs an entry in `invariant_links.json`).
- The v2 gate polices **all dispositioned outcomes**
  (`ProbeRowDispositioned`: answered / not-applicable / deprioritized), not
  just `answered` — a tier-0 row "deprioritized: liveness-only" is just as
  dangerous. `blocked` is not a disposition and never trips it.
- The override is `--override-dismissal --override-reason R` (the reason is
  deliberately separate from the closure `--reason`: the dismissal text and
  its justification are different data). Without a reason the flag is
  refused; with one it closes the row and logs
  `probe.dismissal_overridden` (row_id, tier, gap, actor, phrases,
  override_reason, closed_reason).
- A4 interaction: `resolveAnchor` now accepts a refutation-backed ref on a
  probe row — `closed_ref` becomes the EXEC/INV id while
  `probe.anchor.ref` keeps the rendered anchor citation. Any other
  non-anchor ref is still rejected.
- v1 surfaces: the report's **Disposition review** section (flagged rows +
  OVERRIDDEN lines from the audit events; presence-gated — no bytes for a
  clean campaign) and the brief's `disposition_review` array (the key
  exists only when something is flagged — presence-gated so a clean
  campaign's `brief --json` bytes are unchanged).
- Finding-side twin: `webv2 verdict` prints an advisory warning when the
  critic reason uses dismissal vocabulary — it never blocks or fails.
- The morph-campaign fixture was not ported; the testdata probe surface
  (tier-0/gap-4 row) plus the planner/CLI/report/brief suites pin the full
  matrix instead.

---

## Wave C — Deterministic Capabilities  *(archetypes → tools)*

The six probe archetypes (`internal/probes/registry.go:37` `probesTable`:
assertion-strength, custody-primitive, sequential-cursor, short-circuitable-
guard, trust-assumption, invariant-precision) are good *seeds*, but two of
them produced their value by the model doing ad-hoc work the index could do
deterministically.

### C0. Storage-list fidelity: `writes_storage` under-reports (added 2026-09-10, out of the C1 pass)

**Failed behavior:** the parser detects a state-variable write with
`stateWriteRe(name)` (`internal/structidx/parser.go:109-112`), a regex that
requires the assignment operator to follow the variable name *directly*:

    (?<!\w)NAME(?!\w)\s*(?:\+=|-=|\*=|/=|\+\+|--|=[^=])

So `total = v` and `total += v` are recorded in the per-function
`writes_storage`, while an **indexed or member lvalue** — `balances[who] = v`,
`withdrawsRequests[user] = 0`, `prevStateRoot[i+1] = root`,
`rewardState.index = x` — is not: the `[` (or `.`) after the name breaks the
match. The same statements ARE recorded in the statement-level `uses` (which
carry `kind: "write"`, the exact line, and the concept keys), so the index
contradicts itself: `uses` proves writes the list denies.

**Measured (2026-09-10, the 18 fixture indexes: `internal/structidx/testdata/
structural_index.json`, `internal/probes/testdata/golden/index_*.json`, and a
golden campaign's `structural_index.json`):** 144 (state-variable, kind) pairs
are statement-proven; **52 of them are missing from the lists, and every single
one is a write.** Reads are complete. Concrete misses: `commitBatch` writes
`prevStateRoot`, `finalizeBatch` writes `newStateRoot`, `updateTokenMapping`
writes `tokenMapping` in all eight gateway contracts, `poke` writes
`rewardState`, `_deposit` writes `deposits`, `claimWithdrawRequest` writes
`lastWithdrawRequest`/`withdrawsRequests`, `commitBatch` writes `pendingRoots`.

**Consumers that inherit the under-report** (all read the list directly):
`structidx.StorageWriters` (the `storage_writers` query),
`internal/corpus/probes.go` (`pReentrancy`, `pSharePriceInflation`,
`pAccessControl`, `pLogicError` — four prescreen predicates),
`internal/archetypes/evaluate.go` (`unguarded_entry_writes`), and
`internal/histmining/recency.go` (the asset-writer-file heuristic). A
reentrancy-shaped or access-control-shaped function whose only write is an
indexed lvalue looks read-only to every one of them.

**As landed (C0) — the read-side reconciliation, not an index change:** the
index bytes stay exactly as the parser wrote them (its own golden tests pin
them, and rewriting the index would churn every downstream fixture), and the
consumers are handed the union instead.
- `internal/structidx/writers.go`: `WritersOf(index, node)` is the parser's
  `writes_storage` in its own order followed by the statement-proven writes the
  list omits, resolved to variable NAMES through the index's `state-variable`
  nodes with the same maximal-concept-key rule the enforcement table uses
  (statements whose key belongs to no known state variable — locals,
  parameters, library expressions — are not storage writes and are dropped).
  `ReadsWritesOf` is that unioned with the (complete) `reads_storage`.
  `EffectiveWriters(index, varName)` is the complete `storage_writers`;
  `StorageWriters` keeps the reference semantics verbatim beside it, since the
  parity goldens pin its behaviour and it has no live callers.
- Routed: the four corpus prescreen predicates, the archetype's
  `unguarded_entry_writes`, and recency's asset-writer-file scan. The
  `histmining.IndexAPI` seam gained `WritersOf`; an incompletely wired seam
  (index but no reconciliation) falls back to `rawWriters` — the pre-C0 list —
  rather than silently reporting that nothing writes storage.
- Tests: `internal/structidx/writers_test.go` (3 — the reconciliation against
  the morph fixture: `prevStateRoot` appears via the statement, the list order
  is preserved, no non-storage name leaks, a list-complete function is
  unchanged, and the union keeps every id `StorageWriters` finds);
  `internal/corpus/probes_test.go::TestIndexedStatementWriteIsSeenByTheProbes`
  (an indexed-only writer fires `access-control`; it also PINS the divergence —
  the test fails if the parser starts recording indexed writes, which is the
  signal to delete this reconciliation); and
  `internal/archetypes/archetypes_test.go::
  TestUnguardedEntryWritesSeesIndexedStatementWrites`.
- **Follow-up (not done here):** the root cause is one regex in the parser. A
  future item can teach `stateWriteRe` an optional postfix chain
  (`(?:\s*(?:\[[^\]]*\]|\.[A-Za-z_]\w*))*` before the operator), regenerate
  the index fixtures, and delete `writers.go` — at the cost of an intentional
  fixture regeneration plus a divergence row, which is why it is not bundled
  into a fidelity fix.

### C1. Enforcement-timing capability: (write-site, read-site) stage table

**Failed behavior:** the `assertion-strength` archetype (axis
`enforcement-timing`, lens L-03) finds *single* assertion/consumer pairs. The
full question — "for state variable X: who writes it, in what order, where is
it guarded, where is it consumed, and at which stage is the invariant
actually enforced?" — is answerable from the structural index, which already
records per-function `reads_storage` / `writes_storage`
(`internal/structidx/parser.go:215-226`) and statement-level read/write uses
(`extractUses`, `parser.go:793`), but no query assembles them.

**Design:**
- New query `internal/structidx/enforcement.go`:
  `EnforcementTable(idx, varName) (*EnforcementTable)` — for a named storage
  variable (or concept key), emit an ordered table of
  `{site: contract::function@line, kind: write|read, guarded_by: [guard
  classes from the containing function's assertion rows], invariant:
  [invariants asserting the variable]}` — ordered by call-graph reachability
  from entry points when available, else by (contract, function) declaration
  order, with a deterministic note when ordering is partial.
- New CLI verb `webv2 enforce <CID> <variable|concept>` — prints the table;
  `--json` for machine use.
- Probe integration: the `assertion-strength` probe emits one row per
  (write-site, read-site) *stage pair* that lacks a guard — i.e., the probe
  surface now contains the full stage table, not just single pairs. New
  `probe_spec` field `stages: []stageRef` (additive; existing rows unchanged
  shape, new rows carry the pair).
- This is the deterministic backbone for G-01-class bugs: "prevStateRoot is
  written in commitBatch with no prior-state check, read in nextCommitBatch
  under a class-1 guard" is a row, not a hypothesis the model has to stumble
  onto.

**Anchors:** new `internal/structidx/enforcement.go`;
`internal/structidx/queries.go` (export helpers);
`internal/probes/probe_assertion.go` (stage-pair emission);
new `internal/cli/cmd_enforce.go`.
**Tests:** table ordering determinism, guard attribution, morph fixture
(prevStateRoot table reproduces the gold's shape).

**As landed (C1):**
- `internal/structidx/enforcement.go` is the query.
  `EnforcementTable(index, name)` /
  `EnforcementTableOpts(index, name, EnforcementOpts{Contract})` emit
  `{name, match, concept_key, concept_keys, contract?, ordering, note?, sites[],
  stages[], signals[], stats{}}`; `LoadIndex(c)` reads the stored index with no
  source tree and no freshness check, so the verb works on a campaign whose
  index is already built. `match` is `storage` (the index knows the name as a
  state variable or a reads/writes_storage entry), `concept` (only keyed
  statements matched) or `none`.
- **Which sites win.** The design assumed the per-function
  `reads_storage`/`writes_storage` lists are authority and the statement-level
  `uses` merely sharpen lines; the fixture shows the opposite can hold —
  `commitBatch`'s `writes_storage` records only `storedHash` while its
  statement-level uses carry the write of `prevStateRoot` at line 15. So the
  query collects statement-level sites first (kind write|read, exact line,
  `granularity: "statement"`) and falls back to the function-level lists only
  for a (function, kind) with no statement site (`granularity: "function"`, at
  the declaration line). An index without statement uses still answers,
  coarsely, and every row says which granularity it is.
- **Matching is by the maximal concept key**, not "any shared token".
  `conceptKeyOf` normalizes the typed name (separators folded onto `_`, then
  `splitIdent`'s camelCase/`_` split plus the synonym fold, joined by `:`), so
  `prev-state root` finds exactly `prevStateRoot`'s sites. It matters:
  `storedHash` folds to `stored:root`, and a shared-token rule would sweep in
  every `stateRoots`/`prevStateRoot` expression in the index. Both
  `concept_keys` (the full list) and `concept_key` (the one used) are
  published so a surprising hit is explainable.
- **Guard attribution.** Each site carries its containing function's guards,
  each marked `about_variable` when the guard's concept keys contain that
  maximal key, and `guarded` when any does. `class` is the index's own
  `guardStrength` (0..4).
- **Ordering.** BFS depth over `calls` edges from entry points (depth 0), then
  (contract, function, line, kind). `ordering` is `call-graph`, `partial`
  (unreachable sites sort last, counted, with a note) or `declaration` (the
  index has no entry point, with a note).
- **Stage pairs are scoped to related sites** — same contract, same
  inheritance family (union-find over `inherits` edges), or one function
  reaching the other over `calls` edges within 4 hops. Unscoped is noise, not
  thoroughness: the sibling gateway contracts each declare their own
  `tokenMapping`, and pairing them yields 144 pairs where 8 survive; every
  skipped pair is counted in `stage_pairs_skipped`.
- **Pair coverage is per side.** Each pair carries `write_guarded` /
  `read_guarded`, and `gap` means the *write* side has no assertion about the
  variable (the value was committed unverified) while `stats.stage_open_gaps`
  counts pairs where neither side does. A guarded write reaching an unguarded
  read is neither: the write was checked, that consumer just trusts it.
  `signals[]` are `no-writer`, `no-reader`, `unguarded-read` (per site) and
  `unguarded-stage` (per gap, naming both ends and whether the read side is
  guarded).
- CLI `webv2 enforce <campaign> <name> [--contract C] [--json]`
  (`internal/cli/cmd_enforce.go`, ord 73 — a new Go-only verb with argparse
  semantics from `cmd_p3_args`): the text table (headline, one line per site
  with kind/contract.function@line/depth/entry/guard text, signals, stage
  counts), `--json` for the whole table, and `--contract` — not in the design,
  added because a variable name is rarely unique across contracts. A
  `--contract` that matches no site exits 2.
- **Probe surface integration is opt-in.** `ProbeOpts{StageTables}` +
  `BuildSurfaceOpts` (`internal/probes/surface.go`), with
  `ProdProbeOpts()` used by `RunProbes` and by `audit.go`'s re-derivation;
  `BuildSurface` keeps its reference signature and passes the zero value. The
  zero value IS the reference surface byte-for-byte (the parity goldens keep
  pinning the port), while the shipped surface attaches
  `stages_unguarded[]` + `stages_unguarded_total` to assertion-strength rows
  that have a gap, capped at 8 carried pairs (`internal/probes/stages.go`).
  Pairs are scoped to the row's own contract and carry both sites plus
  `write_guarded`/`read_guarded`. `assets/schema/probe_surface.schema.json`
  gains the two optional row properties and a shared `definitions.stage_site`.
- Tests: `internal/structidx/enforcement_test.go` (8 — never-written variable,
  the writes_storage/uses precedence, guard attribution, stage pairs and
  scoping, concept matching, contract scope, unknown name, determinism, and
  the two partial orderings), `internal/cli/cmd_enforce_test.go` (7 — help,
  six argparse vectors with exact stderr, missing index, text table, JSON,
  contract scope, unknown name), `internal/probes/stages_test.go` (3 —
  enrichment + schema validation, the opt-in/parity guarantee, enrichment
  surviving the quota slice).
- Golden stays green with no normalization: the enrichment is opt-in, its keys
  are absent from non-opted-in surfaces, and the golden campaign's surface has
  **0** assertion-strength rows (the other four probes supply its 4 rows), so
  nothing it prints changed. `RowShapeSha` hashes only anchors/classes/
  siblings/stranded, so the new row fields are shape-neutral by construction
  and the audit's re-derivation check is unaffected.

**Review corrections (facts the design block above got wrong):**
- The design says "for a named storage variable (or concept key)" as if a
  concept→variable map existed. There is none: concept keys are token n-grams
  of the *expressions the parser saw*, and the only bridge is that a
  statement's lvalue produces the variable's own key. The query matches on
  that key (see above) instead of consulting a mapping.
- The design's row shape includes `invariant: [invariants asserting the
  variable]`. `internal/structidx` has **no** invariants — the trust probe
  reads them from the protocol model (`protocol_model.json`), not the index. C1
  therefore attributes *guards* (which the index does record, with classes),
  and any item that wants invariants must read the model, not the index.
- "Additive; existing rows unchanged shape" is true of the shape hash (see
  above) but not of the parity goldens, which byte-compare whole surfaces: any
  new row field changes them. Hence the `ProbeOpts` seam rather than a bare
  field.
- The design's `{site, kind, guarded_by, invariant}` row is missing the
  ordering's own honesty (`depth`, `granularity`, `is_entry_point`) and the
  stage pair's per-side guard state; both are in the landed rows because the
  "who checks what, at which stage" question is unanswerable without them.

### C2. Primitive-symmetry matrix (family × custody-primitive)

**Failed behavior:** the `custody-primitive` archetype (axis
`primitive-symmetry`, lens L-04) flags single divergent siblings
(`probe_custody.go` — custody verb detection: burns/mints/transfers/
onDropMessage). The morph campaign's G-02 is exactly a divergent sibling
(`onDropMessage` transfers where the forward path mints), but the *systematic*
question — "for each contract family, what custody primitive does each
member use for each asset direction, and where do siblings diverge?" — was
never computed.

**Design:**
- New capability `internal/probes/symmetry.go`:
  `PrimitiveMatrix(idx, model)` — rows = contract families (inheritance
  groups from the structural index), columns = (direction: deposit |
  withdrawal | drop | recover, asset class: native | ERC20 | share), cells =
  custody primitive detected in the implementing function (mint | burn |
  transfer | safeTransfer | external-call | none). Deterministic from
  `probe_custody.go`'s verb table (extract the verb detection into a shared
  helper).
- Divergence flag: any family where the same (direction, asset) cell differs
  across members → one row in the probe surface under the
  `custody-primitive` axis, `whyTemplate` extended: "family {family}: {a}
  uses {pa} and {b} uses {pb} for {direction} {asset} — who funds the
  difference?" (G-02: Rollup family — forward `mint` vs `onDropMessage
  safeTransfer` → divergence row at rank ≤ 3).
- CLI: `webv2 symmetry <CID> [--family F]` prints the matrix; the probe
  surface picks up the divergence rows automatically (additive rows, new
  row_id hash includes the family key so existing rows' row_ids are stable).

**Anchors:** new `internal/probes/symmetry.go`; shared verb table extracted
from `internal/probes/probe_custody.go`; `internal/probes/registry.go`
(spec extension); new `internal/cli/cmd_symmetry.go`.
**Tests:** matrix determinism, G-02 divergence reproduces on the morph
fixture, row_id stability.

**As landed (C2):**
- `internal/probes/symmetry.go` (~590 lines): `PrimitiveMatrix(index)` is the
  capability — families (union-find over the index's `inherits` edges) × cells
  (direction ∈ deposit|withdrawal|drop|recover|other × asset ∈ native|erc20|
  share × primitive ∈ mint|burn|transfer-in|transfer-out|send-native) with the
  defining contract on every cell, so an inherited function counts once, not
  once per inheritor.
- Two divergence kinds, both carrying BOTH ends and a rendered question:
  `member-disagreement` (siblings use different primitives for one
  (direction, asset)) and `funding-mismatch`.
- **The funding-mismatch rule is the reference probe's own discriminator,
  lifted to the family**: a forward path that MINTS or BURNS while a recovery
  path pays the asset out with transfer-out / send-native. The first draft used
  "forward credits (transfer-in) vs recovery pays out", which fired on the
  *clean* custody fixture — a forward path that HOLDS custody and pays it back
  is self-consistent. The clean fixture is now the guard test for that
  false positive (`TestPrimitiveMatrixIsDeterministicAndCleanStaysSilent`).
  This is the G-02 shape: `L1ReverseCustomGateway::_deposit` burns while the
  inherited `L1ERC20Gateway::onDropMessage` transfers out — one row naming both
  ends and asking who funds the difference.
- Surface integration rides the **existing** custody-primitive axis and probe
  id (dispositions, anchors, schema and the sibling anchor all keep working),
  behind `ProbeOpts.Symmetry` — the C1 pattern: divergence raws are appended
  before `collapse`, so they get a real `RowIDFor` id, `rank`, `shape_sha` and
  the sibling list, and the family extras are stamped **after** `finalize`
  (finalize copies only the probe's declared fields, so an extras map keyed by
  row_id is what survives; a folded row keeps its extras). `ProdProbeOpts()`
  turns it on; the zero value still reproduces the reference surface
  byte-for-byte, which the parity test pins.
- New row fields (schema `probe_surface.schema.json`, all optional): `family`,
  `direction`, `asset`, `divergence`, `expected`, `expected_asset`, `observed`,
  `base_function`, `members`. Note `custody` is the reference enum
  ("burns"/"mints"), so a divergence row pluralizes its credit primitive to fit.
- CLI `webv2 symmetry <campaign> [--family F] [--json]` (ord 74): the headline
  counts, the matrix per family grouped by direction, and each divergence as
  `! kind: question`. `--family X` narrows to one family (exit 2 when the index
  has no such family); the JSON keeps the full matrix shape.
- Tests: 6 new (`internal/probes/symmetry_test.go`) covering the family
  members, the cells, both ends + question of the divergence, determinism,
  clean silence, the row shape on the axis (row_id/rank/gap/why/siblings), and
  the opt-in parity claim with schema validation; 5 new CLI tests
  (`internal/cli/cmd_symmetry_test.go`) covering help, argparse vectors, no
  index, the text matrix and the JSON + `--family` scope. New fixture
  `internal/structidx/testdata/symmetry/` (the G-02 bridge shape; the probe
  fixtures are not reachable from `internal/cli` tests).
- Golden green, no oracle update: the golden fixture carries no family with a
  mint/burn-vs-transfer-out divergence, and the new rows appear only under
  `ProdProbeOpts` on a family that has one.

---

## Wave D — Report Honesty & Plumbing

### D1. Dual counting + full findings table in the report

**Failed behavior:** `report.md` said `confirmed: 0` while 23 findings were
critic-confirmed. The Results section (`internal/report/report.go` L488-547)
counts only `status` (CONFIRMED/CHAIN vs the rest) and `submission_ready`; it
never reads `verification.critic_verdict`. `findingSection` (L956) renders
only CONFIRMED/CHAIN — the other 30+ findings are invisible.

**Design (all additive; sections appear when data present):**
- **Results:** dual counters side by side:
  `critic-confirmed: N` (count of findings with
  `verification.critic_verdict.verdict == "confirmed"` regardless of status),
  `evidence-confirmed: M` (count with `evidence.level` meeting
  `floors.EffectiveFloor` for the finding's class/status), and the existing
  status counts. Plus the A3 Precision block.
- **Findings table:** new section "All findings" — one row per finding
  (id, title, class, status, evidence level, critic verdict, risk score+band,
  acceptance score (A3), submission_ready, chain membership, exploitability
  (A4: first line of the argument, or `payable`/`not payable`/`—`)), sorted
  by acceptance score desc. This is the operator's single view of all 52.
- **C6 section (prior-round ask):** "Dismissed with strong reaching" —
  findings that were DISPROVED/OUT_OF_SCOPE but whose probe rows or evidence
  had tier-0/gap≥3 surface (i.e., we reached them hard and then dismissed
  them) — these deserve a human second look. Deterministic from the probe
  surface + finding verdicts.
- **Effective floor display:** each finding row shows the floor that applied
  (class-specific via `floors.FloorOverride` when set, else the default
  table) — the "why is this not confirmed" answer.
- **FP ratio:** the A3 false-positive ratio line.

**Anchors:** `internal/report/report.go` (Results L488-547; new sections
after "Answer quality" L559; `findingSection` L956 unchanged for
CONFIRMED/CHAIN detail).
**Tests:** counter fixtures (dual-count disagreement case = the morph case),
table sorting, floor display, golden: new sections are gated on
`critic_verdict` presence — existing golden campaigns without critic verdicts
render byte-identically (verify with `scripts/golden.sh`; if any golden
campaign does have critic verdicts, add a KNOWN_DIVERGENCES row).

### D2. Report stage wiring in the pipeline ("module not wired")

**Verified root cause:** `internal/cli/cmd_run.go:76` calls
`pipeline.New(c, adapter, nil)` — the handlers map is **literal nil**, so
every stage falls through `step()` (`internal/pipeline/pipeline.go:675`):
handler==nil + kind=="deterministic" → builtin → the report builtin is the
`noReport` stub returning "report module not wired: cannot run stage
report". `cmd/webv2/main.go` never constructs a Pipeline with handlers;
`cmd_report.go` calls `report.Generate` directly, bypassing the seam.

**Design:**
- In `cmd_run.go`, build the handler map: at minimum
  `report → report.Generate` (the real module), plus the other deterministic
  stages that have direct implementations today (`dedup → dedup.RunDedup`,
  `bounty-gate → bounty gate all`, `risk-calibration → risk recompute`) —
  each wired behind the existing pipeline seam so `webv2 run` completes
  through the report stage instead of failing with the waiver.
- Model stages (`learning`, etc.) keep `needs-model` behavior when the
  adapter is absent — no change.
- The existing waiver on the morph campaign (`report stage "module not
  wired"`) becomes obsolete for new runs; add a regression test: pipeline
  with wired report handler runs the report stage and logs
  `report.generated`.

**Anchors:** `internal/cli/cmd_run.go:76`; `internal/pipeline/pipeline.go:511,675`;
`internal/report/report.go:308`.
**Tests:** handler-map wiring test; end-to-end `webv2 run` smoke on a
minimal campaign reaching the report stage.

**As landed (D2):**
- The root cause was confirmed exactly as written, and the fix is smaller than
  the design: **no handler map is needed.** `cmd_run` already passes a real
  orchestrator (`orchestrator.PipelineAdapter{O: orchestrator.New(c)}`), which
  owns every other deterministic builtin (`dedup`, `chaining`,
  `risk-calibration`, `bounty-gate`, `reproduction`, `scope`,
  `structural-index`, `campaign-planning`) — the handler map is the
  per-campaign *override* seam, and leaving it nil is correct. The one stage
  that did NOT flow through the orchestrator is `report`: its builtin calls the
  package-level `reportImpl` seam, which was left at `noReport{}` because
  nothing ever called `pipeline.SetReport`. So the fix is one seam install in
  `ensureSeams()` (`internal/cli/cmd_dedup.go`, the file that installs every
  other cross-module seam) plus a four-line adapter:
  `reportAdapter{}.Generate` → `report.Generate`.
- Verified by negative control: with the seam stashed, the new test fails with
  `run exit 2, halt "stage 'report' failed: report module not wired: cannot
  run stage 'report'"`; with it, `run` executes the report stage (writes
  `report.md`, logs `report.generated`) and halts at the following model stage
  (`learning`), which is the honest behaviour `run` is supposed to have.
- New test `internal/cli/cmd_run_test.go::TestRunReachesTheReportStage`:
  snapshots the fixture, seeds every stage report depends on to `done`, runs
  `webv2 run`, and asserts (a) no "not wired" text anywhere, (b) `report` is in
  the `ran` list, (c) the halt is `blocked on model stages: ['learning']`,
  (d) `report.md` exists in the campaign directory.
- Golden stays green with **no** oracle update: the recipe's single `run` step
  still exits 3, because its ready frontier halts at a model stage that comes
  *before* report (`mainnet-fork-poc` blocks `bounty-gate`, which blocks
  `report`). The recipe therefore never reaches the report stage, which is why
  the pre-D2 golden was green despite the bug — the gap the unit test now
  closes. Verified: identical tree (165 events, 75 files) and exit codes before
  and after (2026-09-10). A future recipe that seeds the upstream stages would
  exercise the report stage end-to-end; noted, not done, because it would grow
  the golden surface beyond this item's scope.

### D3. Artifact supersession fix (report-DONE vs audit-PASS)

**Verified root cause (reproduced on the morph campaign):** `report.md` has
**four** registry rows — two kind `other` (from `webv2 artifacts register`,
default kind, `internal/cli/cmd_artifact_register.go:18`) and two kind
`report` (from `report.Generate` → `RegisterOrRefresh`,
`internal/state/artifacts.go:325`). `RegisterOrRefresh` refreshes only the
*latest* row at the same resolved path; when the latest row's kind differs
from the requested kind it **mints a new row instead of reconciling**. Every
regeneration rewrites `report.md`, so all non-latest rows keep stale
hashes, and the audit's artifacts section
(`internal/audit/sections/artifacts.go:16-50`) re-hashes **every** row →
permanent `content hash mismatch` → `webv2 audit` FAIL. Fixing it
(prune/refresh) logs events → the report-freshness proof
(`internal/completion/proofs2.go:203` — fresh iff last event is
`report.generated`) goes red → the pipeline's report stage re-fails.
Mutually exclusive, forever.

**Design:**
1. **`RegisterOrRefresh` reconciles instead of minting:** when a row exists
   at the same resolved path, always refresh the latest row **and migrate its
   kind** to the requested kind (kind migration logged in the refresh data:
   `kind_migrated: other → report`). At most one row per resolved path,
   always re-hashed on refresh → the audit section can be green again.
   (Ghost rows of a *different* kind at the same path are pruned to
   `artifacts/superseded/` with an `artifact.pruned` event, reason
   "superseded: same path re-registered as kind X".)
2. **New verb `webv2 artifacts reconcile <CID> [--dry]`:** re-hashes every
   registered row whose file changed since registration; refreshes the
   living ones (reason "reconcile after external rewrite"), reports the
   rest. This is the operator's escape hatch for any batch of rewrites.
3. **Report freshness ordering rule (documented, not code):** run
   `webv2 report` as the LAST state-changing command before `webv2 audit`;
   `webv2 run` ends with the report stage for the same reason (pipeline
   order already puts report second-to-last, before model `learning`).
4. **Migration for the live morph campaign:** run the reconcile verb + a
   one-shot kind-migration pass over the four rows (the code fix makes this
   idempotent).

**Anchors:** `internal/state/artifacts.go:325` (RegisterOrRefresh);
`internal/state/artifacts.go` (new Reconcile method);
new `internal/cli/cmd_artifacts_reconcile.go`; `internal/audit/sections/
artifacts.go` (unchanged — it was right; the registry was dirty).
**Tests:** ghost-row repro fixture (4 rows, 3 stale → reconcile → audit
green → report regenerated → audit still green), kind-migration log,
idempotence.

**As landed (D3, 2026-09-10):**
- `RegisterOrRefresh` reconciles instead of minting: the row at the resolved
  path is refreshed with its kind MIGRATED (the refresh event gains
  `kind_migrated: <old>→<new>`), and every other row at that path — the ghost —
  is pruned with `artifact.pruned`, reason `superseded: same path
  re-registered as kind <K>`. One row per resolved path, always re-hashed on
  refresh, which is the state the audit's re-hash-every-row check can clear.
- **Declared deviation from the reference:** the ported Python test
  `test_different_kind_same_path_registers_new` becomes
  `TestLivingDifferentKindSamePathMigratesRow`; the D3 design's
  `4 rows → keep the newest, mint nothing` is a contract change, taken
  deliberately because a second row at a live path is a stale hash no sequence
  of commands could ever clear.
- **Deviation from the design's step 1 (recorded):** ghosts are pruned, not
  copied to `artifacts/superseded/`. Every ghost resolves to the SAME file as
  the row that replaces it, so the copy would be an unverifiable duplicate with
  no provenance value; the `artifact.pruned` event carries the retired id, kind
  and path, which is the audit trail that matters.
- `Campaign.ReconcileArtifacts(dry)` + CLI `artifact-reconcile <campaign>
  [--dry]` (ord 75): re-hash every registered row, refresh the ones whose file
  changed (reason `reconcile after external rewrite`), report missing files and
  leave hash-less rows alone (`--dry` reports without writing or logging).
  Named `artifact-reconcile` rather than the sketch's `artifacts reconcile`: the
  CLI's verbs are flat, and the singular prefix matches `artifact-register` /
  `artifact-list`.
- Report-freshness ordering (design step 3) needed no code: with one row per
  path re-hashed at generation, `report.generate()` leaves
  `artifact.refreshed` (or nothing) before its final `report.generated`, so the
  `proofReport` rule ("fresh iff the last event IS report.generated") holds and
  the mutually-exclusive loop is gone.
- Tests: state (`internal/state/reconcile_test.go` — ghost pruning with the
  prune event, N generations stay one row, reconcile live/dry/missing/
  idempotent), audit end-to-end (`internal/audit/d3_supersession_test.go` — the
  two-row stale shape is RED before and GREEN after; the reconcile sweep clears
  an external rewrite), CLI (`internal/cli/cmd_artifact_reconcile_test.go` —
  help/argparse, dry vs live counts, missing file, idempotence, unknown
  campaign).
- Golden green with no oracle update: the recipe's steps keep their exit codes,
  the event chain stays intact, and the checker pins exit codes, tree shape and
  the audit surface rather than artifact bytes.

### D4. Dedup signatures: CLI verbs + adapter dispatch (16-hex + resolve)

**Verified root cause (two compounding gaps):**
1. `dedup.SetRootCauseSignature` / `SetEconomicSignature`
   (`internal/dedup/dedup.go:151,174`) take a **plain sentence** and compute
   the 16-hex `TextSignature` themselves — the API is fine — but there is
   **no CLI verb** exposing them (the `dedup` verb is the deterministic sweep
   only, `internal/cli/cmd_dedup.go`), and the adapter's
   `structuredOutputs` (`internal/adapter/adapter.go:516-523`) lists the
   function names as **prose only, with no dispatch** — a model reading the
   prompt cannot call them. Net effect: tier-2/3 signatures can only be
   hand-written into finding JSON (the "hand-written 16-hex hashes"
   complaint). In the morph campaign, `dedup-normalization` sat at
   `needs-model` and no tier-2/3 signatures were ever set.
2. `resolve-candidate` (`internal/dedup/dedup.go:501`; CLI
   `internal/cli/cmd_resolve_candidate.go`) requires the pair to be in
   `dedup.possible_duplicate_of` — set only by the tier-1 cross-snapshot
   flag or the tier-3 economic-signature sweep. Two findings with the same
   root cause at **different code sites** (the "code-protected" pairs —
   protected from auto-merge by `sameSpot`, `dedup.go:369-371`) form a tier-2
   lineage but are **never flagged** → `resolve-candidate` is unreachable for
   them, and each burns a full PoC cycle.

**Design:**
- **New CLI verbs:**
  `webv2 dedup-signature <CID> <finding> --root-cause "sentence" [--cwe CWE-xxx]`
  and `webv2 dedup-signature <CID> <finding> --economic "sentence"` — thin
  wrappers over the existing functions (which compute the hash; the operator
  never writes hex).
- **Tier-2 candidate flagging:** in `tier2Sweep`
  (`internal/dedup/dedup.go:337`), after folding members into the lineage,
  also `flagPossibleDuplicate` for every pair in the cluster that is
  *not* auto-merged (i.e., not same-spot) — so code-protected same-root-cause
  pairs become `resolve-candidate`-able. Deterministic, no model needed for
  the flag; the model/human still adjudicates.
- **Adapter dispatch:** the model-facing structured outputs need a real
  dispatch path for the listed functions (this is the deeper fix — the
  adapter prompt currently advertises `dedup.set_root_cause_signature /
  set_economic_signature`, `findings.add_evidence`, etc. as functions a model
  "must use", but nothing executes them). Scope for this wave: route the
  dedup-signature + exploitability + adversarial-game setters through the
  CLI verbs listed in the prompt as the callable surface (prompt text
  updated to the CLI form `webv2 dedup-signature ...`); a full
  model→function dispatch layer is a separate design item (noted, deferred).
- The dedup completion proof (`internal/completion/proofs2.go`) already
  tracks candidate verdicts — no change.

**Anchors:** new `internal/cli/cmd_dedup_signature.go`;
`internal/dedup/dedup.go:337-371` (tier-2 flagging);
`internal/adapter/adapter.go:516-523` (prompt text).
**Tests:** verb → signature computed (golden vector: same sentence ⇒ same
16-hex), tier-2 flag fixture (two same-root-cause different-site findings
become resolvable), resolve-candidate on the flagged pair.

**As landed (D4, 2026-09-10):**
- CLI `dedup-signature <campaign> <finding> {--root-cause SENTENCE [--cwe CWE]
  | --economic SENTENCE}` (ord 76): thin wrappers over
  `dedup.SetRootCauseSignature` / `SetEconomicSignature`, which compute the
  16-hex `TextSignature` from the sentence — the operator (or the model) never
  writes a hash. The two kinds are mutually exclusive (`--root-cause` with
  `--economic` is an argparse error, as is `--cwe` without `--root-cause`),
  because recording one while believing the other is the mistake the tiers
  exist to separate; both may still be set on one finding via two calls.
- Tier-2 flagging in the sweep: after folding a signature group into its
  lineage, every pair of members that auto-merge did not handle (different code
  sites, hence code-protected) is flagged on BOTH sides
  (`dedup.possible_duplicate_of` + `finding.possible_duplicate`), so
  `resolve-candidate` can adjudicate it. Flag-only — nothing merges; the
  same-spot auto-merge path is untouched and pinned by a guard test.
- Model-facing map (`adapter.structuredOutputs.dedup_signatures`) now names the
  callable verb instead of `dedup.set_root_cause_signature /
  set_economic_signature`: the setters have no dispatch entry, so a model told
  to call them had nothing to call — the deeper "advertised but not
  executable" gap. A general model→function dispatch layer remains a separate
  design item, deliberately not attempted here.
- Tests: `internal/cli/cmd_dedup_signature_test.go` — help/argparse vectors
  (missing both kinds, both kinds, `--cwe` alone, missing value, unknown flag),
  the root-cause hash and stored sentence/CWE, determinism of
  `TextSignature`, the economic path and its event, an unknown finding, the
  tier-2 flag reachability end-to-end (flag on both sides → both findings still
  live → `resolve-candidate --verdict distinct` lands), and the same-spot merge
  guard.
- Golden green with no oracle update: the sweep only ADDS flag records and
  events, and the checker pins exit codes, tree shape and the audit surface.

### D6. An unscoped campaign must not look complete (post-mortem 2026-09-10)

**Failed behavior:** the post-mortem's first and largest complaint was "no
scope/known-issues policy was ever loaded (verified: `webv2 scope` → "no policy
provided"), and nothing separated 'the program will pay' from 'real but
accepted'" — 23 critic-confirmed findings, 2 gold, and no signal anywhere on the
finished report that no program policy had ever been applied. Every policy-
dependent capability landed in Wave A (`accepted_risks`, `submission_ready`,
`acceptance_score`, the `submission_budget` cap, the paid-exploitability gate);
what was missing was the *refusal to proceed quietly*.

**Design (as landed):**
- **The gate was already loud** — `Orchestrator.BountyGateAll` raises
  `bounty gate requires a policy; run scope(policy_path=...) first` for a
  campaign with no (or a vanished) `policy_path`
  (`internal/orchestrator/triage.go:210-222`, pinned by
  `TestPortBountyGateRequiresPolicy`). The hole was downstream of it: `webv2
  report` calls `report.Generate` directly, and `Generate` simply SKIPPED the
  gate re-run, the precision block and the submission line when `policy_path`
  was empty — emitting a complete-looking report with no trace of the missing
  policy.
- **Report**: `precisionBlock` now returns an explicit **unscored notice** —
  "NO POLICY LOADED — this report is unscored: no acceptance ranking, no
  submission budget, no accepted-risks check and no paid-exploitability gate
  ran. Every finding below is a technical claim, not a submission
  recommendation." — plus the exact command that fixes it. Presence-gated: a
  scoped campaign never prints it (the A3 block's bytes for scoped campaigns are
  unchanged, so the golden recipe — which runs `scope --policy` before the gate
  — does not move). The submission line is now keyed on the policy *value*, not
  on the raw path, so a stale path cannot print a gate result that did not run.
- **Ranking**: `webv2 rank` prints the same warning above its table when the
  campaign has no `policy_path`: a severity order is not a submission order.
  (This is an intentional change to an unscoped campaign's rank output;
  `TestRankTable` pins the new bytes.)
- **Tests**: `internal/report/unscoped_test.go` — the notice is present without
  a policy and absent with one (the scoped case writes a schema-valid policy and
  patches `policy_path`); the gate refusal stays pinned in
  `internal/orchestrator/port_test.go`.
- Deliberately NOT done: a new audit section. The audit's section list is
  pinned in two tests plus a parity dump (14 → 15 sections) and a failing
  section would flip the golden's `ok=True`; the report + rank + gate trio
  already answers "was this campaign scoped?" at the three places an operator
  reads.

### D5. Learning CLI verbs (queue + reflect)

**Verified state:** `internal/learning/learning.go` has `QueueMemory` (L96),
`ApproveMemory` (L226), `PromotionCommands` (L343), `ReflectionEntry` (L376),
`PlannerHint` (L408), `PendingMemory` (L477), `AllMemory` (L492) — but the CLI
(`internal/cli/cmd_memory.go`) exposes only `list`, `--approve`, and `hint`.
The learning stage's completion proof (`internal/completion/proofs2.go:263-317`)
requires a MEM row per terminal finding + non-empty `learnings.jsonl`, so the
stage can never complete without the missing verbs.

**Design:**
- `webv2 memory queue <CID> --kind <lesson|tactic|fact|policy|habit>
  --text "..." [--finding F-*]` → `QueueMemory`.
- `webv2 memory reflect <CID> --finding F-* --reflection "..."` →
  `ReflectionEntry` (appends to `learnings.jsonl`).
- `webv2 memory reject <CID> <memory-id> --reason "..."` → reject a pending
  candidate (new small function in learning.go mirroring ApproveMemory).
- `webv2 memory promote <CID> <memory-id> [--execute]` → `PromotionCommands`
  (prints the promotion command; `--execute` runs it).
- The pipeline's `learning` stage handler (wired per D2 pattern) calls
  QueueMemory for terminal findings missing a MEM row — makes the stage
  completable deterministically.

**Anchors:** `internal/cli/cmd_memory.go`; `internal/learning/learning.go`;
`internal/completion/proofs2.go:263-317` (unchanged).
**Tests:** each verb round-trips through the memory schema; proof goes
green after queue+reflect on a terminal finding.

**As landed (D1, 2026-09-10):** the counting half had already landed with A3
(the precision block prints critic-confirmed / evidence-confirmed / FP ratio),
and the "23 findings, all invisible" half is now closed by an **All findings**
table in Results: one row per finding (`id + title | status | evidence | critic
| risk score+band | accept score | submit | chain`), ordered **status first**
(confirmed/chain → hypothesis → dismissed), and only then by the LIVE acceptance
score descending with the finding id as tie-break, critic-disproved last within
its group — the same key and posture `risk.AcceptanceRanking` uses *inside* a
group. Status has to lead because the score is not comparable across statuses
and the golden campaign proved it: a HYPOTHESIS with a stamped band outranked
three CONFIRMED findings that had no validated band yet (an absent band
contributes zero), so a score-only order opened the inventory with an unproven
claim above the confirmed ones. A closing line states the order and counts the
critic-disproved rows, so it is never a mystery.
The gate is only "there are findings": the precision block is capped by the
submission budget, skips DUPLICATE/OUT_OF_SCOPE, and needs a policy, so a
policy-less campaign previously hid everything — which is exactly the
post-mortem's case. Every cell degrades to `—`, never to an error: this is the
view an operator reads when something already looks wrong. Deferred from the
original design: the "dismissed with strong reaching" section (C6) and the
per-row effective floor (the FP ratio plus the floor column the ranker prints
already answer "why is this not confirmed") — both stay here as asks.
`internal/report/report.go` (`allFindingsTable`), tests in
`internal/report/allfindings_test.go` (every status visible, live-score order,
unscoped render, empty campaign prints nothing).

**As landed (D5, 2026-09-10, reduced):** the design above is stale in two of its
four verbs and over-built in the other two. Verified: `queue_memory` is already
reachable (the ladder's disprove path calls it through the seam wired in
`cmd_t28_wire.go`), and `promote` is already covered (`memory --approve` prints
`PromotionCommands`). The real holes were reachability: `ReflectionEntry` had no
caller outside its own test, so `learnings.jsonl` — the file the learning proof
requires (`proofs2.go:302`) — could not be written by any command, and a queued
candidate could only ever be *approved*. Both landed as **flags on the existing
`memory` verb** (surface budget, principle 6): `--reflect TEXT [--round N]` and
`--reject MEM --reason TEXT [--rejection-class C]`, mutually exclusive with
`--approve` and with each other. `learning.RejectMemory` mirrors `ApproveMemory`
but refuses a row that is already `human-approved`/`promoted` (rejecting is not
revocation — silently overwriting an approval would erase who approved what),
and it keeps the **reason in the event log** (`memory.rejected`), not in the row:
the memory schema is `additionalProperties:false` with no reason field, and the
audit trail is the log. Tests: `internal/completion/d5_learning_test.go` (the
proof demands a reflection entry until one is recorded — the reachability claim,
pinned at the proof itself) and `internal/cli/cmd_memory_learn_test.go` (both
verbs, argparse vectors, the approval guard, the invalid class refused by the
schema, listing shows the new state).

---

## Wave E — Remaining asks  *(DEFERRED by the surface budget — principle 6)*

**Status (2026-09-10):** E1–E6 are recorded, not scheduled. Each one adds a new
capability surface for a workflow the evaluated campaigns never hit, and E5
(reversibility in scoring) would move scores, rankings and goldens for a
modelling gain that needs a campaign to justify it. They land when a real run
trips them — that is what this document is for.

### E1. Finding amend/supersede (prior-round C1, P1-1)

No path exists to amend a filed finding or supersede it with a corrected
version (only plan/floor have supersede). Design:
`webv2 amend <CID> <F> --title/--class/--claim/--note` (bumps
`claim_version`, appends `history[]` entry, logs `finding.amended`) and
`webv2 supersede <CID> <F-new> --of <F-old>` (old → `SUPERSEDED` status,
new carries `supersedes: F-old`; old's evidence/chains re-parent to the new
one). Add `SUPERSEDED` to the status set (`internal/findings/levels.go`
`STATUS_FLOOR` + transitions). Report shows superseded findings collapsed
into the successor's section.

**Anchors:** `internal/findings/*.go` (new amend/supersede fns);
`internal/cli/cmd_amend.go`; `assets/schema/finding.schema.json`;
`internal/report/report.go`.

### E2. Probe batch disposition (prior-round C4)

The probes CLI is run/list/blank only. Design:
`webv2 probes dispose <CID> <row-id...> --status answered|deprioritized
--reason "..."` (batch; per-row reason required unless `--reason-all`) and
`webv2 probes unblank <CID> <row-id...>`. Runs the B4 linter on the way in.

**Anchors:** `internal/probes/closure.go`; new CLI file.

### E3. Ladder "other" axis (prior-round C5)

`maximization/maximization.go` has 5 fixed axes. Design: `--axis other --
label <text>` records a free-form axis label on the rung (schema additive:
`variant_ladder.schema.json` rung `axis` becomes `string` with a
`axis_known` bool; existing 5-axis values unchanged).

**Anchors:** `internal/maximization/maximization.go`;
`assets/schema/variant_ladder.schema.json`.

### E4. Campaign severity floor (prior-round C7)

`bounty.go` has per-finding severity floors but no campaign-level one.
Design: policy field `min_severity: "critical"|"high"|"medium"|"low"`;
new gate check **check16 campaign-severity**: when set and no finding reaches
the band, the gate emits a *named, waivable* campaign-level result
`no-finding-at-or-above <floor>` (report line + event) — the "campaign has
no CRITICAL finding" statement the operator had to make by hand.

**Anchors:** `assets/schema/bounty_policy.schema.json`;
`internal/bounty/bounty.go`; `internal/report/report.go`.

### E5. Reversibility factor in risk calibration

**Verified gap:** `internal/risk/risk.go` — `wBlast` (L46-49), `wLevel`
(L53-57), `validatedScore` (L143-190: base + evidence + unprivileged +1.0 +
extractable bump), `riskBand` (L197-206: ≥8.5 critical, ≥6.5 high, ≥4.0
medium). No reversibility/recoverability dimension — which is exactly what
separates G-02 (4.0 medium, gold says **high**) from a cosmetic bug: the
depositor cannot recover their funds without trusted-party intervention.

**Design:**
- Finding field `risk.reversibility: "irreversible" | "trusted-party" |
  "reversible"` (operator/model-set, additive; default when absent:
  `reversible` with 0.0 — no behavior change for existing findings).
- New weight table in `risk.go`: `wReversibility = {irreversible: +3.0,
  trusted-party: +2.0, reversible: 0.0}`; added in `validatedScore` after
  the unprivileged bump.
- **G-02 check:** subset-of-users 3.0 + E0 0.0 + unprivileged 1.0 +
  trusted-party 2.0 = **6.0**… below 6.5. → also classify G-02's blast as
  `bridge-canonical`? No — the correct fix is that *unrecoverable by the
  victim* is the irreversibility: the victim has no path at all (not even a
  trusted-party one the victim can invoke — sequencer/operator recovery is
  discretionary, not a right). G-02 is `irreversible` from the victim's
  perspective → 3.0 + 0.0 + 1.0 + 3.0 = **7.0 → high** ✓. G-01: already
  9.0 critical; `trusted-party` (governance can unstick) +2.0 → 11.0,
  still critical ✓ (bands are floors, capping is fine).
- `webv2 impact <CID> <F> --reversibility <mode>` setter verb (additive flag);
  report risk line shows the component (e.g. `3.0 blast + 0.0 E0 + 1.0
  unpriv + 3.0 irreversible = 7.0 high`).
- Golden: findings without the new field score exactly as before (default
  reversible/0.0) — byte-safe.

**Anchors:** `internal/risk/risk.go:46-57,143-190,197-206`;
`assets/schema/finding.schema.json` (`risk` object);
`internal/cli/cmd_impact.go`; `internal/report/report.go` risk line.
**Tests:** G-02/G-01 fixtures land at high/critical; absence-of-field
byte-equality against current scoring.

### E6. (folded into E5) — G-02 severity correction

No separate item; E5 is the fix. Verification: re-run `webv2 impact` on a
copy of the morph campaign's G-02 finding with `reversibility: irreversible`
and assert the band is `high`.

---

## Plan review (2026-09-10, after landing A1–A4, B1–B4, C1)

Written from the far side of four waves: every point below is grounded in
something that actually bit during implementation, not in reading the plan.

**1. The parity goldens are a translation contract, not a product spec — label
each item accordingly.** The plan says "additive, so no oracle updates" for
several items. That is true of the *shape hash* (`RowShapeSha` covers anchors,
classes, siblings and the stranded set, so new row fields are invisible to it —
C1's `stages_unguarded` proved the point) and false of the *parity goldens*,
which byte-compare whole surfaces and raw probe output. Any plan item that
touches probe output needs a seam like C1's `ProbeOpts` (zero value =
reference bytes, production opts in) and should say so in its design block.
Recommended edit: mark each item `parity-pinned` (byte-identical required) or
`Go-only` (new tests, presence-gated) — the distinction is currently implicit
and C1's design block got it wrong before implementation.

**2. New capability has no oracle. Say what its regression net is.** For
Go-only work the only net is hand-written tests plus the golden suite's
well-formedness checks. Each item should name its net explicitly (unit tests,
a schema, a fixture). C1's net is: 8 structidx tests, 7 CLI tests, 3 probes
tests, the schema, and the parity tests that pin the untouched path.

**3. `writes_storage`/`reads_storage` under-report, and several existing
probes inherit it — this should be an item, not a footnote.** C1 found that
`commitBatch` writes `prevStateRoot` at line 15 statement-level while
`writes_storage` records only `storedHash`. `StorageWriters`, the
custody-primitive probe and the accumulator-skew probe all read those
per-function lists, so the same gap is a candidate false-negative source
*outside* C1. Recommended new item, ahead of C2 (which reads the same lists):
**C0 — storage-list fidelity**: derive the per-function storage lists from the
statement-level uses at index time (or reconcile them and publish the delta),
then measure the change on the fixtures and the golden campaign. This is
probably the highest-value discovery of the C1 pass and it is currently
unplanned.
*(Landed 2026-09-10 as the `### C0` block above, read-side: `structidx.WritersOf`
reconciles the lists with the statement proofs and the consumers use it. The
parser-regex fix remains open and is described there as the follow-up.)*

**4. Scope every pair/matrix search by relatedness up front, and count what
you skipped.** C1's unscoped stage pairing produced 144 pairs for
`tokenMapping` where 8 were real. C2's family × custody matrix and D4's dedup
signatures have the same shape of search space. Make it a stated principle
(the way "additive" already is) and reuse the C1 helpers
(`enforcementFamilies`, the `calls` adjacency) rather than re-deriving
families per item; C2's design already asks for the shared helper — name it as
`structidx`'s family index and move it out of `enforcement.go` when C2 lands.

**5. Land large items as two commits: core+CLI first, surface second.** C1 was
split into a deterministic query + CLI verb (zero golden risk, fully testable)
and the probe-surface enrichment (needs the opt-in seam). That split is worth
making explicit in "Implementation order" for every L item, because it gives a
large item a safe landing point instead of one big unverified diff.

**6. Consider hoisting the cheap report-honesty items (D1/D2) before C2.**
Wave D affects every campaign the tool produces; C2's matrix only pays off once
an agent (or a report section) reads it, and C1's table likewise only pays off
through the probe surface. D2 in particular is sized S and fixes a
"module not wired" class of bug that invalidates otherwise-good work. Ordering
suggestion: C0 (fidelity) → D2 → D1 → C1′/C2, with C1 already landed.

**7. Make the CLI conventions explicit.** The plan does not say which verbs get
`--json` or a scope flag. C1 added `--contract` (a named variable is rarely
unique across contracts) and `--json` without either being in the design. Add
to the design principles: every new read-only verb takes `--json`, and every
verb over a *set* takes a scope flag that narrows it — with a scoped miss
exiting non-zero rather than printing an empty table.

**8. The golden suite never exercises the probe surface's new fields.** The
golden campaign's surface has 4 rows, 0 of them assertion-strength, so C1's
enrichment is invisible to the one end-to-end check the project trusts. Any
future probe field has the same blind spot. Recommended D-wave item: extend the
golden recipe (or add a second recipe/scenario fixture) so at least one row per
probe axis is emitted and the surface is validated against its schema in-process
— the schema already runs on write, so a richer recipe would then cover the
field.

**9. Two smaller papercuts worth folding into the next wave.** (a) The plan's
C1 design assumed invariants were available from the index; they live in the
protocol model. Any plan text that says "the invariant for X" should name its
source (`protocol_model.json`) — the C1 corrections block records this once, but
it will recur. (b) `docs/IMPROVEMENTS.md`'s "Divergence ledger (to add as items
land)" tail and the `KNOWN_DIVERGENCES.md` ledger are two lists of the same
thing; keep the plan's tail as the checklist and require the actual row in
`KNOWN_DIVERGENCES.md` at landing time (B3 and C1 both did this — it should be
stated).

## Implementation order

Each step lands green (`go build ./... && go test ./... && scripts/golden.sh`)
before the next starts. Order is by dependency, not wave letter:

| # | Item | Depends on | Est. |
|---|---|---|---|
| 1 | E5 reversibility factor | — | S |
| 2 | A1 accepted_risks | — | M |
| 3 | A2 in-code ack | — | M |
| 4 | A4 exploitability check | — | S |
| 5 | A3 acceptance scoring + rank verb | E5, A1, A2 | M |
| 6 | B4 disposition linter v1+v2 | — | M |
| 7 | B1 liveness terminal | — | M |
| 8 | B2 adversarial-game clause | B1 | S |
| 9 | B3 chain --unproven | B1 | M |
| 10 | C1 enforcement table | — | L |
| 11 | C2 primitive symmetry matrix | C1 (shared helpers) | M |
| 12 | D1 dual counting + tables | A3, E5 | M |
| 13 | D2 pipeline report wiring | D1 (report is the payload) | S |
| 14 | D3 artifact reconcile + migration | — | M |
| 15 | D4 dedup signature verbs + tier-2 flag | — | M |
| 16 | D5 learning verbs | — | S |
| 17 | E1 amend/supersede | — | M |
| 18 | E2 probe batch disposition | B4 (linter runs on dispose) | S |
| 19 | E3 ladder other axis | — | S |
| 20 | E4 campaign severity floor | — | S |

S ≈ <2h, M ≈ 2–5h, L ≈ 5–8h of focused work.

## Verification plan

1. **Unit:** every item above ships its listed tests; `go test ./...` green
   (baseline: 1,963 test functions, 62 packages).
2. **Golden:** `scripts/golden.sh` after each step (baseline: 179 steps × 2
   twins, 68 files byte-match). Any new report section that would change
   bytes for an existing golden campaign gets a `KNOWN_DIVERGENCES.md` row —
   all new sections are gated on new-field presence, so the expectation is
   **zero** new divergences.
3. **Campaign replay (the real test):** on a copy of
   `morph/campaigns/C-42bd211e3e`:
   - `webv2 scope --policy policy-v2.json` (policy with `accepted_risks`,
     `submission_budget: {max_findings: 10}`, `min_severity: high`)
   - `webv2 ack <CID>` → expect `in_code_ack` hits on stub-adjacent findings
   - `webv2 gate <CID>` → expect: G-02 band = high (after `impact
     --reversibility irreversible`), accepted-risk hits flagged,
     paid-exploitability blockers on extractable findings, campaign-severity
     check green (G-01 critical present)
   - `webv2 rank <CID>` → top-10 table with both golds in top-3
   - `webv2 chain <CID> --unproven F-0f0af9039f30 <freeze-member...>` →
     unproven liveness chain materializes
   - `webv2 report <CID>` → dual counting (critic-confirmed 23 /
     evidence-confirmed M), full 52-row findings table, Disposition review
     section flags the 3 G-01-burying dispositions, G-02 risk line shows the
     reversibility component
   - `webv2 artifacts reconcile <CID>` then `webv2 report` then
     `webv2 audit` → **PASS** (the mutual-exclusion is dead)
   - `webv2 dedup-signature` on two same-root-cause findings →
     `resolve-candidate` reachable
   - `webv2 memory queue/reflect` on terminal findings → learning proof green
   - `webv2 run` from a fresh minimal campaign → completes the report stage
     (no "module not wired")
4. **Smoke:** `go run ./cmd/webv2 selftest [--full]`.

## Golden-suite & divergence ledger impact

- New CLI verbs (ack, rank, chain, enforce, symmetry,
  dedup-signature, artifacts reconcile, memory queue/reflect/reject/promote,
  amend, supersede, probes dispose, exploit): **no golden impact** unless the
  global usage block is byte-diffed — the global usage string
  (`internal/cli/cmd_scope.go:244`) lists commands; adding verbs changes it
  → **one KNOWN_DIVERGENCES row** for the usage block (or keep the new verbs
  out of the D11 global usage list, which is the existing pattern for P1b
  additions — check how `resolve-candidate`/`hint`/`sft` were added).
- New report sections: gated on new fields → no byte change for golden
  campaigns (verified per-item during implementation).
- Risk formula: default-reversible = 0.0 → byte-identical scores for existing
  findings (verified by a scoring-equality test over all 52 morph findings
  with and without the field).
- Dedup tier-2 flagging: **changes sweep output** for campaigns with
  same-root-cause different-site findings → check whether any golden
  campaign exercises tier-2; if yes, KNOWN_DIVERGENCES row (expected: no,
  the golden fixtures predate lineage work — verify).
- **Resolved in practice (B3 `chain`, C1 `enforce`):** both new verbs are
  listed in the global usage block (`internal/cli/cmd_scope.go`, `ord 72` /
  `ord 73`) and `scripts/golden.sh` stays green with no normalization, so the
  block is not byte-diffed by the golden suite. D31 below is therefore only
  needed if a future checker starts diffing `--help`/usage output.

## Divergence ledger (to add as items land)

| # | Change | Reason | Golden impact |
|---|---|---|---|
| D31 | global usage lists new verbs | P1b pattern | none — verified green for `chain` (B3) and `enforce` (C1) |
| D32 | (if needed) tier-2 sweep flags code-protected pairs | D4 | dedup output |
| D33 | (if needed) report Precision/All-findings sections | D1/A3 | report bytes |

---

*Anchors verified 2026-09-10 against the working tree. Line numbers are
pointers, not contracts — re-locate by symbol when editing.*
