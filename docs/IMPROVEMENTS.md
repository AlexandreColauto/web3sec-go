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

---

## Wave E — Remaining asks

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

## Divergence ledger (to add as items land)

| # | Change | Reason | Golden impact |
|---|---|---|---|
| D31 | global usage lists new verbs | P1b pattern | usage block |
| D32 | (if needed) tier-2 sweep flags code-protected pairs | D4 | dedup output |
| D33 | (if needed) report Precision/All-findings sections | D1/A3 | report bytes |

---

*Anchors verified 2026-09-10 against the working tree. Line numbers are
pointers, not contracts — re-locate by symbol when editing.*
