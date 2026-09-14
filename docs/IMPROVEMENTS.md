# web3sec-go Improvement Plan — post morph-campaign review

## 2026-09-14 — critic round 13: two processes, one truth
Nothing in `state` guarded between PROCESSES: two concurrent `hint`s minted duplicate seqs and dropped an event while both reported success; two concurrent `snap`s last-writer-wined the state and orphaned a pin (dir + event alive, row gone — invisible to the state->event projection). Campaign writes now take a per-campaign advisory flock (`campaign.lock`, re-entrant by depth, 5s budget then a loud retry message): Log spans read-tail->append->mirror-save, save is locked end-to-end, and the waiver row+event pair is one unit. Pinned by 6-subprocess race (contiguous seqs, every event once) and reproduced green live. Same round: the index no longer stamps an arbitrary --src with the ACTIVE pin's id — the claim is proven by content hash (foreign tree -> `unpinned`, decoy executed live; the test fixture that pinned a fake `deadbeef` hash discovered itself); execs grew the projection law's missing direction (ledger events whose record dir was deleted burn red); supersede now warns on stderr when the retired row granted capabilities the successor lacks (r12's terminal law made that silent proposal loss); the genesis rewind discloses `ledger_rewound` in the new chain's first event; torn waiver lines are numbered; the [snapshots] ghost message tells the truth about activeness. All four golden fixtures + every waiver-bearing port case verified unaffected.

## 2026-09-14 — critic round 12: one law, or the sweeps disagree
with themselves
`chainengine.nonDuplicate` still hand-listed three statuses while its
sibling sweep used the framework's TERMINAL law — superseded rows kept
granting capabilities and seeding chain proposals, the r5 drift class
reborn in one switch; the filter now calls IsTerminal (pinned dropping
SUPERSEDED and DISPROVED). r11's heal was half a heal: Log into a MISSING
events.jsonl appended onto the dead ledger's state tail, stranding verify
red with no verb to repair the mirror — the first append to a missing log
now rewinds the tail (genesis), and the RUNBOOK says the heal is per-row.
The [snapshots] section checked only the ACTIVE pin while its own message
threatened "the ledger pins are ghosts" — every referenced row must exist
now. A discovery waiver was INERT: the no-plan leg returned before
waiverMap was ever read, so `waive discovery --subject '*'` printed
"waived" and changed nothing; the consult precedes the refusal and the
note names the actor. waivers.jsonl lived outside every integrity check
(delete it: audit PASS) — VerifyLog cross-checks it against
completion.waived events both directions. REFUSED: hash-equal refresh as
a no-op — two ported twin pins require the provenance event for identical
bytes (a re-verification IS an act), so report's honest freshness flip
stays, with the law noted at the seam. Line-attributed parse errors
replace the bare json message; LoadLiveFindings' asymmetry against
IsTerminal got its explanation in the doc.

## 2026-09-14 — critic round 11: the heal must exist before the red is honest
The r10 un-gating made a stripped pinned-event catchable — and caught it
FOREVER: re-pin keyed its event on the STATE row (no row ⇒ log), so a row
whose event was erased could never legally regain it, and the only exit
was the hand-edit the check exists to police. PinSnapshot now keys on the
LEDGER (no snapshot.pinned event for this id ⇒ emit it, marked
reconciled: true), which makes a plain `snap` of the same content the
sanctioned heal — documented in RUNBOOK §3. Same round: the CLI `index`
verb registered NOTHING while the orchestrator registered raw — forged
index rows fed prescreen/sinks under a green audit; every writer of the
regenerated structural_index.json (CLI verb, pipeline stage, the
EnsureFreshIndex wrapper) now goes through RegisterOrRefresh (one row per
path, always re-hashed — the D3 lesson this file already knew); the
exit-code paragraph stopped claiming a convention the unknown-id family
does not have; r9's ledger-first read learned to unwind too when Events()
itself cannot parse.

## 2026-09-14 — critic round 10: a gate is only as good as its blind spot
Section 5's snapshot-row check ran only WHEN THE LEDGER HAD PINNED EVENTS —
so deleting an event from both ledger copies (jsonl + state mirror) blinded
the exact check that polices lying projections, and the r9-then-green audit
came back. The state-row direction is now UNCONDITIONAL (message and
checked=4 stay the twin's; the ledger->state leniency for legacy stands).
Same round: root: gate tails must pass the class grammar to be live —
otherwise one "root: a b" entry evaded the duplicate-anchor refusal by
looking different while matching nothing; unfireable roots now fold into
the same dead symbol as [] and below-bar phrases.

## 2026-09-14 — critic round 9: the projection lied while the directory healed
r8's half-pin rollback removed the right directory but PinSnapshot had ALREADY
saved campaign_state.json — a ledger that then refused its event left the
state naming a snapshot that never existed, and the row's existence suppressed
the event forever: permanent audit red from a healed pin. The pin now UNWINDS
the state projection when its event is refused (log failure ⇒ pre-pin state
bytes restored; verified with a corrupted tail end to end). Mechanism-leg
third pass: anchorKey keys on the gate's behavior — phrase fingerprints are
words()-folded content-word sets, and every inert gate form ([] , blank,
below-bar) is ONE match-nothing symbol distinct from no-gate; a hand-scaled
chain failure in StaleBugClass now says "successor unreadable" instead of
going silent; the brief's STALE line tells which geometry actually holds
("computed before any pin existed" — nothing moved); the exit-code
convention (0/1/2 families) got its one RUNBOOK paragraph. r9: 8/10.

## 2026-09-13 — critic round 8: equality means WHAT THE CODE SEES
anchorKey v1 still keyed on raw JSON; the scorer sees MEMBERSHIP sets,
trimmed phrases and basename collapse — so duplicates with reordered/
repeated/whitespace-padded legs loaded (missed refusals) while a dead
{"file":"a/"} location collapsed onto class-only rows (false refusal).
The key now mirrors anchor()'s predicates exactly, including the
present-but-dead location leg as its own symbol. Also: copyTree creates
its root before the walk (empty-source r2 law, restored) and mkdirs a
symlink's parent (root-level symlink killed whole pins); any failure AFTER
the staging->final rename now removes what it installed and names the
rollback — the half-pin the audits chase can no longer be manufactured by
the pinner itself; StaleBugClass follows the supersede chain through the
event ledger (a frozen old row's class is not the taxonomy in force);
floors set keeps the open-vocabulary law but TELLS you a class binds
nothing yet; publish collapses (program, kind, pattern) duplicates on the
shared tier with a counted field, and the twin's byte-frozen ledger record
stayed byte-frozen doing it.

## 2026-09-13 — critic round 7: my own fix ate the project's answer key
The duplicate-anchor refusal read fields the scorer never uses (.path for
.file, object mechanisms for strings) — collapsing every location leg and
REFUSING THE SHIPPED PACK; nothing but the real pack exercised the loader,
so now a pin loads assets/evalsuite/cases.json through LoadGoldPack every
test run, and anchorKey mirrors anchor()'s join exactly (class+accept set,
file basenames, outcome, string mechanisms). Same round: the re-pin discard
unseals before RemoveAll (sealed children made the removal fail silently
and strand a staging ghost the r4 audit would chase forever); --adjacent=
is a SET flag — its empty value contradicts --adjacent-clear like the space
form; staged FILES get chmod-after-WriteFile so the umask stops rewriting
group/other bits the copy2 claim was made of; memory approve/reject errors
name their cause instead of echoing a bare id, and approval warns when the
source finding's class moved under the row; baseline remove was proposed
to gain a stderr note — and the pinned twin argparse golden answered: the
reference output has EMPTY stderr there, so the twin's rm-rf idempotence
stands (a ghost remove exits 0, quiet) and the ruling is recorded in a
pin, not smuggled in as a behavior change.

## 2026-09-13 — critic round 6: the fixes' own regressions died first
r5's copystat-last sealed the staged ROOT — and the pin writes snapshot.json
INTO it, so an 0500 source root became permanently un-pinnable (half-pin
burning the r4 ghost check forever, invisible to the unit test that only
exercised copyTree). The twin's law is sharper than round 5 read it:
copytree seals CHILD dirs after their content, and the staged root — the
pin's own creation — stays writable; that is pinned end to end now
(pinned, re-pinned, audited). Same round: audit section 14 learned the
mirror direction (a decision ERASED from the file while the chain's last
word is unpriceable — the gate already refused to credit it, the audit was
blind); gold packs refuse duplicate ANCHORS under distinct case_ids (one
finding satisfying two rows inflates GoldTotal and tightens a Wilson CI on
a phantom sample); intake refuses affected.path that escapes the pinned
tree; move --adjacent X --adjacent-clear is a refused contradiction, not a
silent clear; the report's dismissal roster gained INFORMATIONAL; README's
section arithmetic matches the two presence-gated tails.

## 2026-09-13 — critic round 5: readers must agree with the law they cite
copyTree now seals directory modes AFTER the content walk (shutil's
copystat order): a read-only source tree pinned like the twin instead of
failing where Python succeeds — and a FAILED pin discards its staging dir,
so no `staging-*` ghost burns the r4 audit red forever. rank answers
"which findings MATTER": DISPROVED/INFORMATIONAL rows are outcomes the
scorecard and calibration still count, not candidates — said explicitly,
never silently dropped. The gate no longer trusts a hand-edited
economic_impact projection: a NAMED DECISION counts while the CHAIN agrees
with it (audit section 14's rule, enforced at the clause, drift renders
UNTRUSTED). exec's binding guard runs before preflight; sequence run refuses
to invent a typed --workdir; prove refuses a stage that is not a stage;
prices.json set_by reconciles against the logged raw-vs-stripped actor; one
IsTerminal predicate replaces the five hand-copied dead-row lists; the
README's section arithmetic is current.

## 2026-09-13 — critic round 4: the money path gets a watchdog
PRICING joined the audit surface as a presence-gated section (eval-law:
unpriced campaigns render nothing, the golden surface is unchanged):
prices.json reconciles against the last logged price.set per id — hand-edited
figures, ghost rows and lost rows each name themselves. Same round: exec
--finding refuses ghost and terminal bindings (the row is forever), the
snapshots section fails when the projection names a directory the store
doesn't hold (disclose loudly, don't block ingest — the r3 conversion law),
gate all-pass now names the missing state-machine hop, the waive guard globs
proofs*.go, and copytree stages the source root's own mode bits.

## 2026-09-13 — critic round 3: the conversion law, stated once
A probe asked whether re-classing a CONFIRMED finding below its new class
floor should be REFUSED. Ruling: no — the system's own law (pinned by the
ported work-order test) is CONVERSION, not invalidation: a raised bar keeps
the status and turns the row into mandatory verification work the gate reads
on the spot. What is refused is SILENCE: amend --class now prints the floor
movement on stderr, floors changes are attributed decisions. Refused by the
same rounds: supersede 2-cycles, verdicts and dedup-signatures on terminal
rows (the sweep/adjudicate laws extended, not invented), zero-file pins
(refused BEFORE mutating), timeout execs whose records do not explain the
-1, floor overrides on classes no finding can carry. Mechanism-gate control
rows with dead match_mechanisms are refused at pack load.

## 2026-09-13 — wave N: operator friction (FRAMEWORK_EVAL) — LANDED (14e78426..2465c4ca, 6/6)
All six triaged items landed: real-shape remediation hints + registry-read guard
(T1), ingest exec_ref with single-source mint validation and
schema->ledger->gate ordering (T2), reconcile model-vs-ledger drift report,
ledger governs (T3), ingest --lint zero-write validation (T4), supersede
discoverability without a basis-vocabulary hole (T5, ruling: double exclusion
paths would hide bookkeeping from precision), known-class floor advisory +
CONFIRMED floor on both acceptance surfaces + re-file parity (T6). Golden
oracles regenerated for the advisory cascade (authorized controller edit;
Python twin absent from this environment). NOT taken: adjudication basis
`duplicate`, --extra-bind (single-bind is a reproducibility law). Still open
from the same review: chains grammar/manual editor, known-issues register
for stubs, same-run `exec && mint` composition (exec_ref covers the existing-
EXEC case), doctor --check-selfcontained naming the first escaping import.
All gated behind the next fork/RPC wave or a documented small pass.

## 2026-09-12 — gold mechanism gate (near-miss inflation closed) — LANDED (283cd3fd, 4ccade32)
External model feedback (previous-version run, rollup target): a
same-outcome-different-mechanism liveness finding (timeout-latch freeze vs
the gold fake-prevStateRoot freeze) would have scored as a HIT under the
class+location join. Landed: optional `gold.match_mechanisms` on the
evaluation_case pack — full-vocabulary containment (identifier-folded,
stop-words exempt), `root:<class>` equality pin, absent = historical join
bit-identical, malformed entries fail CLOSED per entry. Deny-lists
deliberately NOT expressible (they age badly and fail open). Near-miss now
scores miss + unanchored-true-positive, adjudicable honestly.
*Revised by critic rounds 1–2 (commits 283528c3, 7f236505): per-entry
malformed behavior is SKIP-not-poison (order-free); a phrase needs >=2
non-stopword content words or anchors nothing; `no/not/cannot/can/without/
set` left the stop-word list — negation and domain nouns are load-bearing;
control cases carrying match_mechanisms are refused at pack load (the leg
never runs for absence checks).*

**Deliberately NOT landed:** the feedback's "mandatory multi-vector
enumeration before the first liveness PoC" — current main already carries
three overlapping untested mechanisms for it (Agent H lifecycle-game
question, ANCHOR lifecycle re-scan, disproof-sibling rule); adding a fourth
gate before measuring those three is tuning on vibes, and unbounded
enumeration buys filler rows. Condition: if the re-run of this same target
on current main still anchors-then-stops (F-5ba35-confirmed, G-01-shaped
vector never dispositioned), the EARNED change is narrow — ANCHOR closure
requires per-stage unchecked-assertion rows (L-03 `consumer/asserter`), not
a new machine. Re-run under way at review time; check its event log before
building anything here.


Date: 2026-09-10 · Status: waves A–D + C0 + E5 LANDED; E1/E2 LANDED via G14,
E3/E4 deferred by principle 6; D8 LANDED 2026-09-10; the port-scaffolding cleanup is wave F
(`docs/LEANNESS_REVIEW.md`). **Wave G tranche 1 LANDED 2026-09-10 (G1, G6, G7;
source: the "Beyond Smart Contracts" hybrid-defense report + our deep-research
deliverable "Deconstructing Claims, Validating AI, and Weighting Risks");
tranche 2 LANDED 2026-09-11 (G2, G3, G4, G5, G8, G12–G18 — plan
`docs/superpowers/plans/2026-09-11-wave-g-tranche-2.md`);
tranche 3 LANDED 2026-09-11 (G9, G10, G11 — plan
`docs/superpowers/plans/2026-09-11-wave-g-tranche-3.md`).
Wave G is COMPLETE (G1–G18 all LANDED).**
Wave H backlog filed 2026-09-11 — **closed by Wave J 2026-09-11** (H1–H15
landed; H16 filed) — Wave I LANDED 2026-09-11 (I1–I6). **Wave J, the definitive
close-out, LANDED 2026-09-11** (plan
`docs/superpowers/plans/2026-09-11-wave-j.md`); see "Wave J — definitive
close-out" below. Wave K (free prover backends) is **PARKED** — post-production,
not required for readiness. **Wave M LANDED 2026-09-11** — the
`morph/FRAMEWORK_EVAL_NOTES.md` slice (M1–M6, the C3 retirement, and the
polarity/deployment rules); see "Wave M — the eval-notes slice" at the end of
this document. (A later, distinct **Wave M** — the SDD minicertora
fork-consumption + run-2 plan — landed 2026-09-12; see "Wave M — LANDED
2026-09-12" in the minicertora queue section.)

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

1. **Go is the source of truth.** The Python twin is retired (2026-09-09); no
   byte-compat obligation, and `scripts/golden.sh` — Go-only since the P4
   cutover — must stay green. New features are **additive**: new CLI verbs,
   new flags with defaults that preserve current output, new report sections
   gated behind the new fields being present. Where a new section changes an
   existing report's bytes for an existing campaign, it is called out in the
   commit message (the divergence ledger at `docs/archive/KNOWN_DIVERGENCES.md`
   is frozen history; Go-only changes need no row).
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
  `false-positive ratio = critic-confirmed without the evidence floor /
  critic-confirmed`, or `n/a (no critic-confirmed findings)` when the
  denominator is 0. Submission table capped at
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
- **v3 (structural — SHIPPED 2026-09-11, see the as-built below):** reason
  text must reference a symbol/contract from the row's own surface entry; a
  dismissal citing another finding must cite a real finding id.
- **Finding-side twin:** the same vocabulary scan runs over finding
  `verdict` reasons at `webv2 verdict` time (advisory warning only — the
  finding-side rule is softer because verdicts are human judgment).

**Anchors:** `internal/probes/closure.go`; `internal/planner/answered.go`;
`internal/cli/cmd_answered.go` (new override flag);
`internal/report/report.go` (Disposition review section);
`internal/briefing` (brief output).
**Tests:** vocabulary table, tier-0/gap≥3 gating, override logging,
morph-campaign fixture (the 3 flagged rows reproduce).

**Proof added 2026-09-10 (the gate is now exercised end to end, not just
unit-tested):**
- The golden recipe drives the whole G-01 shape: `answered-dismissal-refused`
  (exit 2, the refusal's *reason text* asserted), 
  `answered-dismissal-override-unreasoned` (exit 2 — an override still needs
  its justification), `answered-dismissal-overridden` (exit 0, and the step
  announces the override). `check-golden.py` gained declared output markers
  (`expect_err`/`expect_out`): an exit code never said WHY a step refused, and
  for these steps the why is the contract. The markers caught a real mistake
  on the first run (a probe row needs its `--anchor` before the gate is even
  reached), which is exactly the rot they exist to catch.
- `check_disposition_review` validates the report ARTIFACT: the row must
  appear as a flagged dismissal *and* as an override with its actor and
  written reason — the G-01 miss was a high-risk row that left no visible
  trace of the argument that buried it, and the report is what a human reads
  afterwards.
- The override's "logged" signal reaches the operator: `AnsweredOpts`
  carries an out-param (`OverrideLogged`) that the CLI prints as
  `dismissal overridden: <prio> logged as probe.dismissal_overridden (actor
  <a>)`. It used to be silent — the operator had to take the log on faith.
  Pinned both ways: the override path must report it, and a
  refutation-backed dismissal (which logs no override) must not.
- The rule is documented where it is read: `assets/runbook/RUNBOOK.md`
  ("A dismissal close to the money has to run") and
  `assets/runbook/AGENT_BOOTSTRAP.md` — the latter is the doc dropped into
  every campaign, and the dismissing party in the G-01 miss was an agent.

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

**v3, the structural layer (shipped 2026-09-11 — D1 is now closed):**
- v2 polices the WORDS; v3 polices the ARGUMENT. The row's own surface entry
  is the citation source, and it is read from the ROW, not the structural
  index: `RowSymbols` collects `contract`, `consumer`, `base`, `asserter`,
  `concept_keys`, `forward` and `siblings[].contract` — the same identity the
  row publishes in `why`. The index would have added a dependency and a
  failure mode (a row the index never saw) for no extra truth.
- A high-risk closure that quotes none of them is refused with the list it
  would have accepted: *"the closure reason names nothing from the row's own
  surface entry … quote the code the row is about (L1ReverseCustomGateway,
  onDropMessage, L1ERC20Gateway, _deposit), or pass a refutation that runs …
  or override explicitly"*. Generic tokens are filtered (`burns`/`mints`/
  `forwards` name no code), so the list is a citation list, not a vocabulary
  list.
- **The false-refusal guard is part of the rule:** a row whose symbols are
  all absent is exempt by construction (`RowSymbols` empty ⇒ skip). The rule
  exists to make a dismissal checkable, never to make a row unclosable, and
  `TestARowWithNoSymbolsStaysClosable` pins that.
- **The converse duty runs at every tier** (`checkCitedRecords`): a finding/
  exec/invariant id in the closure reason or `--ref` must exist, or the
  closure is refused as fabricated. `ghostCitation` reads the findings store,
  `execs/<id>/exec_record.json` and the invariant registry, and shares
  `invariantRegistered` with `refutationBacked` so the two can never disagree
  about what "registered" means. Id-shaped prose (`F-1`, `INV-x`) is not a
  citation; only well-formed ids are read.
- **Precedence is now explicit and tested:** anchorless (shape) → fabricated
  citation (a ref/naming that resolves to nothing) → anchor mismatch (a real
  but wrong citation) → v2 vocabulary → v3 citation. Each layer answers with
  the message its author can act on; `MarkAnswered` therefore resolves the
  anchor BEFORE the policy gates, which it did not before.
- **Blast radius, honestly:** six closures in the corpus were written in the
  style v3 refuses and were rewritten to cite the row's own code — four CLI
  fixtures, two probe fixtures, and the committed oracle vector's `anchor_ok`
  case, whose reason was literally *"checked it thoroughly by hand"*. The
  vector change is the most instructive one: the frozen Python-era oracle had
  encoded the G-01 closure style as correct.
- **Why the axis-level path needed nothing:** `probes blank` (attesting a whole
  axis blind) already demands the falsifiable citation v3 asks of a row —
  `--anchor-blind K` must name a key that axis actually PUBLISHED, checked
  against the surface, plus an actor and a written reason. That is v3's
  contract in a stronger form (a real key, not prose that contains one), so
  adding the vocabulary scan there would have been ceremony. Asked and
  answered once, here, so it is not re-litigated.
- **Proof:** the golden recipe drives both halves —
  `answered-structural-refused` (exit 2, markers assert the refusal names the
  symbols it wants) and `answered-structural-accepted` (exit 0 on the second
  tier-0 row with a reason quoting that row's own contract, its stdout
  asserted). A rule that only ever refuses is indistinguishable from a wall,
  so the accept step is the load-bearing one. `internal/planner` adds
  `TestRowSymbolsReadTheRowsOwnEntry`, `TestARowWithNoSymbolsStaysClosable`,
  `TestGhostCitationsAreRefused` and two v3 rows in `TestDismissalGateMatrix`.

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

### D7. The runbook is a test: registry ↔ document drift (added 2026-09-10, out of the runbook audit)

**Verified state (before):** `assets/runbook/RUNBOOK.md` documented 67 of the
76 registered verbs. The nine missing ones were exactly ordinals 68–76 — every
capability this programme added (`exploit`, `ack`, `rank`, `adversarial-game`,
`chain`, `enforce`, `symmetry`, `artifact-reconcile`, `dedup-signature`), three
of which (`adversarial-game`, `artifact-reconcile`, `dedup-signature`) appeared
nowhere in the file at all. The `memory` cheat-sheet line predated `--reflect` /
`--reject`; the report section predated the All-findings table (D1) and the
unscoped notice (D6); the artifact text predated one-row-per-path (D3). No gate
could notice: `scripts/runbook-walkthrough.sh` was written against the **Python**
reference runbook for the T37/P4 deliverable and is re-run by nothing,
`release.sh` has its own mini walkthrough, and `selftest`'s Go walkthrough is a
small embedded subset. Documentation drift was not a failing condition anywhere.

**What landed:**
- The nine verbs are documented where they belong (cheat sheet + the owning
  section), with the real signatures read off the binary: §4b is new (the
  `enforce` / `symmetry` tables and *when* to read them — before attesting L-03 /
  L-04), §6 gains `rank` / `ack` / `dedup-signature`, §7 gains `exploit`, §8
  gains `chain` / `adversarial-game`, §9 gains `artifact-reconcile` and the
  memory flags, and the hard rules state the one-row-per-path artifact rule.
- Behaviour that had no prose at all is now stated: the All-findings table and
  its ordering, `NO POLICY LOADED` and what an unscoped report cannot compute,
  `--unproven` chains being leads that never inflate the confirmed count, and
  `--reject` being the other half of `--approve` (reason required, approved rows
  refused).
- `docs/runbook-go-notes.md` no longer claims the Python repo is authoritative
  "until cutover" (the cutover happened) and its status line is dated and tied
  to a test rather than a hand-run script.
- **The guard:** `internal/cli/runbook_test.go` reads the **embedded** runbook
  and asserts both directions against the registry — every registered verb is
  documented (`TestRunbookDocumentsEveryRegisteredVerb`) and every documented
  `webv2 <verb>` is registered (`TestRunbookCommandsAreRegistered`, line-leading
  match so prose like "the webv2 operator runbook" is not read as a command).
  Both were verified to fail on injected drift (a renamed command line and a
  removed verb mention) before landing.

**The `-h` gap, fixed the same day (D7 follow-up).** The audit that produced the
runbook pass found 23 of 76 verbs did not answer `-h`/`--help` with exit 0 the
way the reference's argparse did: 18 flat parsers rejected the flag outright, 5
printed usage but exited 2 because required-argument checking ran first, and
`selftest` *ran the whole self-check* on `-h` because it deliberately ignored
unknown tokens. All 76 now answer help first, before argument validation and
before any state access. The fix is one shared entry guard (`helpRequested` in
`internal/cli/cli.go`) called by the 24 affected entries; the usage text is the
captured argparse block when the verb has one, its existing usage constant
otherwise, and for the four with neither (`init`, `status`, `log`, `snap`) it is
derived from the command registry — so the help line cannot drift from the
registered signature.

**Pinned by:** `internal/cli/runbook_test.go` (2 tests) and
`internal/cli/help_test.go` (`TestEveryCommandAnswersHelp`,
`TestHelpPrecedesArgumentValidation` — every registered verb, both flags,
against an empty workspace). **Surface budget:** no new verbs, no new flags —
documentation, a shared guard and tests.

### D8. The patch clause should follow the target program, not the framework *(LANDED 2026-09-10)*

**Landed as.** `poc_requirements.patch_clause` (`verification` | `prose` |
`none`, absent = `verification`) with the schema description as the operator
contract; `check12` switches on it, the prose branch reads
`verification.recommendation` (>= 40 runes — the finding schema carries the
field now), and the boundary-mutation record moves to a new non-blocking
advisory channel (`g.advisories` → `bounty.advisories`, the same list A2's
`in_code_ack` uses) instead of vanishing. The verification branch is
byte-identical to the pre-D8 check and the absent key is the default, so every
existing campaign, the golden fixture and the pinned gate vectors are
untouched. Unknown values are refused twice: the policy schema's enum at scope
load, and a loud `UnknownPatchClauseError` from the gate itself. Tests:
`internal/bounty/patch_clause_test.go` (7 cases over three policies x four
finding states, plus the default guard, the unknown-value refusal and the
waiver path); the runbook's patch-clause section documents the switch. No new
verb, no new flag, no new artifact kind — the surface budget holds.

**Divergence.** Go-only extension of a ported check: `cli.py` has no mode
switch, so `check12` under a policy carrying the new key diverges from the
reference. The ledger that would carry this row is archived and frozen
(`docs/archive/KNOWN_DIVERGENCES.md`) because the twin retired; this paragraph
is the row.

**Verified state:** `check12` (`internal/bounty/bounty.go:1038`) requires
`IsImmunized` — `verification.patch_verified` with `patch_blocks_poc=true`,
`boundary_mutations_tested=3`, `boundary_bypass_found=false` and a non-empty
`artifact_id` — for **every** finding the gate evaluates, and the only escape is
a per-finding waiver (`waive <C> immunization --subject F-xxx --reason ...`,
added in B1 because the unconditional check made `submission_ready`
unreachable). That bar is the framework's own, not the program's:
`assets/schema/bounty_policy.schema.json` carries `poc_requirements`
(`min_evidence_level`, `require_fork_repro`, `require_economic_quantification`,
`require_exploit_contract`, `min_extractable_usd`) and
`reporting.required_fields`, but nothing that says whether the target program
wants a recommendation, a tested patch, or neither.

**Why this is worth doing.** Practice differs per program and the gate cannot
currently tell them apart:

- The platform's report format makes **Recommendation** a mandatory section —
  "state the minimal fix (specific function + specific change), provide
  before/after code snippets, mention related areas to review as follow-up; if
  multiple fix options exist, list them in order of preference". That is a
  *prose* obligation, not a verified patch
  ([Immunefi report guide §3](https://github.com/wakaka23333333/defi-audit-targets/blob/main/IMMUNEFI-REPORT-GUIDE.md)).
- Payout tier is set by impact against the program's severity table; a verified
  fix never raises it. Requiring one uniformly spends operator time for no
  expected payout change.
- Some programs explicitly do not want a patch, some make it optional, and a few
  make a tested fix a condition of the top tier. One hard-coded strictness is
  wrong for most of the programs the framework will meet, and a per-finding
  waiver makes the operator pay that mismatch one finding at a time.

**Design (policy is data — the same posture as `floors` and `budget`).** Add one
key under `poc_requirements`:

| value | the gate reads | the record |
|---|---|---|
| `verification` (**default when the key is absent**) | today's `check12`: `IsImmunized` required, waiver as today | unchanged |
| `prose` | passes on a written recommendation on the finding (`verification.recommendation`, a length-floored string); the boundary mutations become an **advisory** line (like A2's `in_code_ack`), not a blocker | the same `patch_verified` object, if recorded |
| `none` | passes with the policy's own sentence ("this program does not ask for a fix"), nothing required of the finding | optionally recorded |

The boundary-mutation test stays in the record in **every** mode: it is the
root-cause insurance (a mutation that still extracts under the patch means a
misdiagnosed root cause → duplicate risk, or an under-claimed impact), and that
value does not depend on what the program asks for. Only its *gate authority*
changes. `check12`'s detail text names the mode and the target program, so the
report never implies the framework's bar where the policy said otherwise.

**Non-goals.** No new verb and no new flag (surface budget: this is a policy
field, and `scope <C> --policy F` already loads it). No new artifact kind. No
change to `immunize`'s record shape. The framework still never applies a patch —
the fix remains a suggestion inside the report.

**Compatibility.** The absent key means `verification`, which is exactly today's
behaviour, so every existing campaign, the golden fixture and the pinned gate
outputs are untouched byte-for-byte; only a campaign that opts in moves, and only
in its gate `blocking_reasons`/advisories. A policy naming an unknown value is a
**load error**, never a silent default — the same rule the rest of the policy
follows.

**Tests.** Three policy fixtures × four finding states (no record, prose-only,
immunized, bypass) asserting the check state and `submission_ready`; the `none`
mode asserting a pass that quotes the policy; an unknown value asserting a load
error; and a guard that the default (absent) path still requires immunization.

**Divergence ledger.** Go-only extension of a ported check — the reference has no
mode switch, so `check12` under a policy carrying the new key diverges from
`cli.py` and needs a `KNOWN_DIVERGENCES.md` row.

**Open question for the operator (this is why it is PROPOSED, not scheduled).**
Does any target program actually reward a *verified* patch — as opposed to a
recommendation? If none of ours does, the correct default is `prose` and
`verification` becomes the opt-in for programs that ask for a tested fix. That is
a decision to take with a real program page in hand, not in the abstract.

## Wave E — Remaining asks  *(DEFERRED by the surface budget — principle 6)*

**Status (2026-09-10, updated):** **E5 has LANDED** (checkpoint `92104cf`:
`risk.reversibility` ∈ {irreversible +3.0, trusted-party +2.0, reversible
+0.0}, absent = byte-identical scoring; G-02 regression pins 7.0 high — E6
is closed by it). E1/E2 CLOSED by G14 (amend/supersede + batch dispose, tranche 2); E3/E4 remain recorded, not scheduled: each adds a new
capability surface for a workflow the evaluated campaigns never hit. They
land when a real run trips them — that is what this document is for.

### E1. Finding amend/supersede (prior-round C1, P1-1)

**LANDED via G14** (`4edfd60`): `webv2 amend <CID> <F>` and `webv2 supersede <CID> <F-new> --of <F-old>` exist (`internal/cli/cmd_amend.go`), with `SUPERSEDED` in the status set. The original ask is kept below as history. Design:
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

**LANDED via G14** (`b8ed2c6`): the batch-dispose path lives in `internal/planner/batch.go`. The original ask is kept below as history. Design:
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
| 17 | E1 amend/supersede — LANDED via G14 | — | M |
| 18 | E2 probe batch disposition — LANDED via G14 | B4 (linter runs on dispose) | S |
| 19 | E3 ladder other axis | — | S |
| 20 | E4 campaign severity floor | — | S |

S ≈ <2h, M ≈ 2–5h, L ≈ 5–8h of focused work.

## Verification plan

1. **Unit:** every item above ships its listed tests; `go test ./...` green
   (baseline counts live in the CI output, not in this document).
2. **Golden:** `scripts/golden.sh` after each step (Go-only since the P4
   cutover). Any new report section that would change
   bytes for an existing golden campaign gets a commit-message callout —
   the divergence ledger (`docs/archive/KNOWN_DIVERGENCES.md`) is frozen
   history and takes no new rows;
   all new sections are gated on new-field presence, so the expectation is
   **zero** byte changes on existing campaigns.
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

> **Ledger frozen (2026-09-10):** the sections below were written while
> `KNOWN_DIVERGENCES.md` still accepted rows. It now lives in
> `docs/archive/` and takes none; where they say "row", read
> "commit-message callout". Everything they concluded was verified true.

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

> Retained as the landing checklist it became; the rows were never written —
> no item shipped a byte change on an existing campaign (ledger frozen).

| # | Change | Reason | Golden impact |
|---|---|---|---|
| D31 | global usage lists new verbs | P1b pattern | none — verified green for `chain` (B3) and `enforce` (C1) |
| D32 | (if needed) tier-2 sweep flags code-protected pairs | D4 | dedup output |
| D33 | (if needed) report Precision/All-findings sections | D1/A3 | report bytes |

---

*Anchors verified 2026-09-10 against the working tree. Line numbers are
pointers, not contracts — re-locate by symbol when editing.*

---

# Wave G — Hybrid tools, calibration & the beyond-contract stack

Date: 2026-09-10 · Status: **tranche 1 LANDED (G1, G6, G7) 2026-09-10;
tranche 2 LANDED (G2, G3, G4, G5, G8, G12–G18) 2026-09-11;
tranche 3 LANDED (G9, G10, G11) 2026-09-11 — Wave G COMPLETE (G1–G18)**.
**G13–G18 (2026-09-11, review follow-up — non-G jumps: ROI,
operator correctness, PoC quality, coverage, tactic calibration, export)
landed with tranche 2.** Anchors are pointers to be re-located at landing time (same
convention as above).

**Sources.** (1) *Beyond Smart Contracts: A Hybrid Defense Strategy* — the
multi-layer report (hybrid static+symbolic+fuzzing, LLM auditing trends,
beyond-contract attack surface, crowdsourced-model consolidation). (2) Our own
deep-research deliverable *Deconstructing Claims, Validating AI, and Weighting
Risks* (claim-invalidation checklist, empirical LLM harvest, incident-weighted
taxonomy). (3) This repo's audited state: A1–A4/B/C/D waves landed, the dataset
registry, `internal/risk/acceptance.go`.

**Three corrections carried from the research review — they bind every G item:**

1. **Incident-loss data is THREE weights, never one priority number.** Search
   prior (what gets drained in the wild → what we hunt), acceptance prior
   (P(real|flagged) × P(paid|class) → how we rank), and severity-if-real
   (target-specific impact → the gate) are different quantities feeding three
   different existing slots. A class-average loss must never set a finding's
   severity, and a cheap-to-flag class (reentrancy) is not the same as a
   costly-to-lose class.
2. **Soundness defenses KILL findings; policy defenses DEMOTE them.** A
   recognized mitigation on the flagged path (`nonReentrant` wrapping exactly
   the flagged function, EIP-712 domain separator in the verified payload) is a
   critic-stage correctness question. A documented finality/trust assumption is
   a gate-stage accepted-risk question (check13/A1). The two layers must never
   share a code path.
3. **The current 2-gold gold-eval supports NO recall claim** (2/2 found ⇒
   recall 95% CI ≈ 20–100%). The source research notes are internal working
   material, not normative — the claim is asserted here and G4 makes the suite
   able to carry it.

**Consistency with the principles:** no new verbs anywhere (flags, adapters,
data, prompts, schemas); deterministic where judgment-free (principle 4);
additive fields gated on presence so existing campaigns' bytes don't move
(principle 1, re-verified per item); fail-open on advisory, fail-closed on
money (principle 2).

| item | one-liner | effort | gate-for |
|---|---|---|---|
| G1 | detector output as first-class evidence + corroboration factor — LANDED (tranche 1, 2026-09-10) | M | — |
| G2 | per-class three-weight table (search / acceptance / severity-if-real) — LANDED (tranche 2, 2026-09-11; weights ship neutral BY DESIGN — graduation needs a G3-backtest `improves` on real data) | M | G3 ✓ |
| G3 | acceptance priors from the adjudicated outcome store + A3 backtest — LANDED (tranche 2, 2026-09-11; policy-gated `acceptance_priors`, `corpus-surface --backtest` verdict = Wilson-lower must strictly rise) | L | G2 ✓ |
| G4 | gold-eval expansion (≥15 scenarios, clean control, CIs on recall) — LANDED (tranche 2, 2026-09-11; 17-case suite, presence-gated `## eval` audit section; grew to **19** in Wave J Task 3 — two pre-0.8.24 fixtures, so the suite is no longer a single-compiler monoculture) | M | claims ✓ |
| G5 | two-layer defense matcher: `mitigation_present` vs check13 — LANDED (tranche 2, 2026-09-11; non-interference law enforced by tests) | M | G1 ✓ |
| G6 | critic triager-outlook rubric (prompt data, policy-injected) — LANDED (tranche 1, 2026-09-10) | S | — |
| G7 | claim-intake checklist + `provenance[]` on baked-in external claims — LANDED (tranche 1, 2026-09-10) | S | — |
| G8 | invariants → Halmos/forge PBT harnesses as an evidence rung — LANDED (tranche 2, 2026-09-11; BODY-region scaffolds, rungs counterexample/PROVEN-BOUNDED(k)/inconclusive) | L | — |
| G9 | beyond-contract `components[]` + two data-only playbooks — LANDED (tranche 3, 2026-09-11; tracked-but-opaque surfaces, `frontend-injection` + `infra-boundary` classes/playbooks, no scanners) | M | G3 ✓ |
| G10 | cross-chain assumption table + separator/finality archetypes — LANDED (tranche 3, 2026-09-11; sidecar `chain_assumptions[]`, two mechanical gap rules, selector-evidence predicates, hint-only) | S–M | — |
| G11 | `verify --post-patch` regression loop — LANDED (tranche 3, 2026-09-11; still_reproducible/fixed/indeterminate verdicts + capped scope diff + plant check, fail-open) | S–M | — |
| G12 | OWASP/SCVS aliases on taxonomy classes — LANDED (tranche 2, 2026-09-11; 7 honest OWASP-2025 mappings fetched from the primary page, SCVS pending primary source — no secondhand ids) | S | G7 ✓ |
| G13 | cost-per-confirmed-finding + per-lens yield (ROI stop-loss) — LANDED (tranche 2, 2026-09-11; cost-per-confirmed + `lens_yield` render as ADVISORY ONLY — no gate consumes them, by principle 2 the stop-loss stays the operator's hand) | S | — |
| G14 | operator correctness: amend/supersede + batch dispose + dismissed-with-reach — LANDED (tranche 2, 2026-09-11; the sanctioned principle-6 verb exception: `amend` never moves status, `supersede` is the only exit INTO SUPERSEDED, batches are all-or-nothing, dismissed-with-reach joins by file overlap with a footnote saying so) | M | — |
| G15 | PoC quality gate at mint (rerun variance + fork freshness) — LANDED (tranche 2, 2026-09-11; `--verify-reruns` opt-in variance, fork-stale advisory always-on with NAMED reason, fail-open: no advisory can block a mint) | S | — |
| G16 | second golden recipe for probe-surface coverage — LANDED (tranche 2, 2026-09-11; P5 `surface2` campaign lights all six axes — every axis needs ≥1 row or the suite fails) | S | C1/C2 ✓ |
| G17 | tactic batting-average (per-lens/playbook precision, auto-deprioritize) — LANDED (tranche 2, 2026-09-11; `auto_tune`-gated demotion, trip law is Wilson-upper <10% with n≥10 — zero-hit parks only from n=35; the doc's "0/20" rhetoric is ERRATA: 0/20's upper is 16.1% and does NOT park) | M | G3 ✓ |
| G18 | Immunefi-shaped export flag on report — LANDED (tranche 2, 2026-09-11; `report --format immunefi`, one file per submission-ready finding, checklist-first fail-open) | S | G12 ✓ |

## G1. Detector evidence as first-class input

**Motivation.** The report's only quantitative hybrid claim (static-analysis
guidance + fuzzing ≈ +10% detection; CSAFuzzer) and the ByteEye diagnosis both
reduce to: every detector has a measurable per-class FP/FN profile, and
corroboration between independent methods is signal. Today the sandbox ALLOWS
`slither`/`aderyn`/`forge` (`internal/sandbox/exec.go:566`) but their output
dies as exec-log prose: never a tracked hypothesis, never dedup-linked to a
finding, never credited by the acceptance score.

**Design.**
- `internal/datasets/slither/adapter.go`: Slither JSON-L lines → common-shape
  records (`dataset:"slither"`, `provenance.tool = {name, version, detector_id}`),
  class mapping table owned by the adapter; unmapped detector-ids land
  `unmapped:true` (same convention as `defihacklabs`), severity NEVER copied as
  a verdict — detector severity is a hint for the gate, not the ladder.
- Registry: add `"slither"`, `"aderyn"` to the dataset vocabulary
  (`internal/ingest/ingest.go:47`) and the `evaluation_case.schema.json` enum;
  records flow through the existing `Ingest` path (eval case + memory rows +
  campaign seed) — no lifecycle change.
- Corroboration factor in `internal/risk/acceptance.go`: `+0.5` when the same
  root cause is flagged by BOTH a tool and a model path, keyed strictly on the
  D4 tier-2 signature (same root cause, same-or-overlapping site). Never
  invent a link (the critic-column law): no signature match, no credit.
- Tool-FP ledger (data, evalstore): counts of tool-flag × critic-verdict per
  class, appended at `verify` time; surfaced in `brief`. This is the empirical
  detector profile the report says nobody publishes — we compute our own.
- CLI: `ingest <CID> --from slither --json-file out.json` (flag on the existing
  verb).
- **Deferred (tranche 1):** the dataset vocabulary additions (`slither`/
  `aderyn` in `internal/ingest/ingest.go:47` and the
  `evaluation_case.schema.json` enum), `--backtest`, and any automatic
  corroboration detection REMAIN deferred. Corroboration is recorded only on
  operator-resolved pairs (per this tranche).

**Anchors:** `internal/datasets/defihacklabs/defihacklabs.go` (adapter
template), `internal/ingest/ingest.go:47` (vocabulary),
`internal/risk/acceptance.go` (factor table), `internal/evalstore`,
`internal/briefing`, `internal/sandbox/exec.go` (tool allowlist already covers).
**Tests:** adapter round-trip incl. unmapped ids; corroboration fires only on
tier-2 match and NOT same-site-different-cause; ledger counts on a fixture
campaign; default-off byte check (no `provenance.tool` fields → no byte move).

## G2. Per-class three-weight table (search / acceptance / severity-if-real)

**Motivation.** The deep-research taxonomy section supplies real loss figures
(access-control dominance in 2024 losses; reentrancy/unchecked-call far
smaller) but treats them as one priority dial — correction 1. The framework
already HAS the three slots; none is data-weighted by adjudicated reality:
`internal/corpus` blends "historical frequency and loss" (search), A3
acceptance (rank), floors/`validated_risk` (severity-if-real).

**Design.**
- New embedded asset `assets/taxonomy/class_weights.json`: per taxonomy class
  (incl. the `unmapped` bucket and G9's component classes) a triple
  `{search, acceptance, severity_default, provenance[]}`; schema-validated,
  pinned by the asset-pack manifest like every embedded asset.
- Consumers: `internal/corpus` reads `search` (replaces its hard-coded blend —
  golden byte check required, normalization if it moves); `acceptance` is
  CONSUMED BY G3 (this item ships the table + validators, not the estimator);
  `severity_default` is a report tie-breaker only and MUST be refused by
  `internal/floors`/risk at the API boundary — decoupling severity from target
  facts is exactly the trap floors was built to avoid.
- Data-hygiene gate (G7's first client): every row carries
  `{source_url, checked_date, primary: bool}`; secondary-source figures (blog
  mirrors of the OWASP list) seed NOTHING until re-verified against the primary
  page — the $953.2M headline stays `uncorroborated` until then.
- Authoring rule (docs): claims baked into playbooks/prompts/assets cite this
  table, not prose.

**Anchors:** `assets/` embed + manifest test, `internal/taxonomy/taxonomy.go`
(the table keys ON the class vocabulary), `internal/corpus/corpus.go`,
`internal/floors/floors.go` (refusal check). **Tests:** schema validation;
every canonical class present exactly once (drift test); `severity_default`
rejected as an input to floors even when hand-written onto a finding; corpus
golden byte-stable after the weights are pinned.

## G3. Acceptance priors from the adjudicated outcome store + A3 backtest

**Correction up front:** this is NOT "go ingest Immunefi data" — the store is
already half-built. The ingest registry declares
`scabench, defihacklabs, defihacklabs-explorer, forge, forge-curated, c4audit,
sherlock, smartbugs-curated, manual` (`internal/ingest/ingest.go:47`), the
eval-case schema carries `platform` (immunefi/cantina/sherlock), and `Outcomes`
(L36-44) IS a triage vocabulary — confirmed-exploitable / disproved /
out-of-scope / duplicate / economic-no-go / confirmed-not-exploitable. What is
missing is the *consumer*: only `defihacklabs` has a loader (the rest ride in on
externally-shaped records), and nothing computes per-class acceptance rates or
backtests the acceptance score against adjudicated ground truth.

**Design.**
- Loaders for the datasets that carry adjudication outcomes: `c4audit` and
  `sherlock` (judge verdicts High/Medium/QA/INVALID/duplicate → an
  `Outcomes` mapping table inside each adapter), and `immunefi-resolved`
  (public resolved reports: accepted/rejected/downgrade → outcomes + a `paid`
  flag). Template: `internal/datasets/defihacklabs`.
- `internal/risk/calibration.go` (pure, no model):
  `AcceptancePrior(class, evalStore) -> {rate, n, ci_low, ci_high}` — Wilson CI
  over adjudicated cases; `accepted := confirmed-exploitable` (+ `paid` when
  the case carries it). Classes with n < threshold (default 10) fall back to
  the global prior and SAY SO in the rendered record. `duplicate` /
  `out-of-scope` count against acceptance (they are triage outcomes, not
  absolution of the bug — rendered separately in the report).
- **Backtest** — the only venue where "the score improved" may be claimed:
  recompute A3 over stored adjudicated cases, emit top-K precision against
  outcomes with CIs. Deterministic report; `--backtest` flag on an existing
  verb (`verify` or `report`, chosen at landing — surface budget decides).
- Wiring: new acceptance term `wPrior(class)` in `acceptance.go`, bounded ±0.5,
  **policy-gated OFF by default** (`bounty_policy.acceptance_priors: false`)
  until the backtest shows improvement on held-out cases; only then does the
  score change earn its divergence check (principle 1).
- Surfacing: per-class prior + n in `brief` finding rows and the report's
  submission table; the G1 tool-FP ledger renders beside it (same store).

**Anchors:** `internal/ingest/ingest.go:36-49`, `internal/datasets/`,
`internal/evalstore/evalstore.go`, `internal/risk/acceptance.go`,
`assets/schema/bounty_policy.schema.json`, `internal/briefing`,
`internal/report`. **Tests:** outcome→accepted mapping incl. negative rows;
Wilson CI against a pinned table; threshold fallback; gated-off byte check
(golden); backtest determinism; one loader fixture per new dataset.

## G4. Gold-eval expansion — make recall claims possible

**Motivation.** Correction 3: two planted bugs measure nothing, and the whole
precision-first narrative rests on a suite that cannot certify even its own
recall. The report's checklist must burn OUR eval first: synthetic-injection
labels (SmartBugs/SolidiFI style) are excluded by design — only real-executed
(DeFiHackLabs lineage, G3-provenanced) or genuinely planted-then-exploited
scenarios count as ground truth.

**Design.**
- ≥15 planted-bug campaign fixtures spanning ≥8 taxonomy classes (access
  control, reentrancy, oracle, share-price/accounting, precision-rounding,
  upgrade-initializer, cross-chain replay, one liveness/DoS), each with gold
  anchors in the finding shape it must produce; at least one bug planted in a
  **clean control protocol** that must yield zero live findings — a recall-only
  suite teaches nothing about precision; the control makes the FP rate
  measurable.
- Variant axes drawn from the research: non-default solc pins; obfuscated /
  poorly-commented sources; one in-code-ack'd decoy (exercises A2 demotion);
  one tool-corroborable bug (exercises G1's factor); one documented-assumption
  bug (exercises G5's layer split).
- Metrics discipline: recall/precision rendered with Wilson CIs in a new audit
  section (gated on presence — principle 1). A 2/2-gold campaign must render
  `recall: 2/2 (95% CI 20–100%)` — the CI is the point.
  *(erratum 2026-09-11: Wilson 95% for 2/2 is **34.2–100.0** — "20–100" is the
  2/3 interval mislabeled; the framework renders the exact computed value from
  `internal/wilson` with a pinned table, and the shipped eval-suite docs quote
  the corrected numbers. Never tune math to a doc sentence — G7 discipline.)*
- Prefer DeFiHackLabs-sourced golds (already confirmed-exploitable and
  provenanced via G3) over hand-planting where a license-clean PoC exists.

**Anchors:** `scripts/golden/`, `internal/reproduction/testdata`,
`internal/evalstore`, `internal/audit/sections`. **Tests:** every fixture
round-trips deterministically under `selftest`; CI rendering pinned; control
protocol yields zero findings or the suite fails.

## G5. Two-layer defense matcher — `mitigation_present` (critic) vs check13 (policy)

**Motivation.** Correction 2. The research collapses two different things named
"defense": `nonReentrant` on the flagged function makes a reentrancy hypothesis
FALSE (it deserves a dismissal the critic can attach), while a documented
finality assumption makes a TRUE finding UNPAYABLE (accepted risk). One signal,
two stages — if merged, the gate starts making correctness claims or the critic
starts making payment claims. Both wrong, and the report shows how easily they
blend.

**Design.**
- *Soundness layer* — `internal/findings/mitigscan.go`, sibling of
  `ackscan.go`, same shape and same post-ingest hook: recognized-mitigation
  patterns matched strictly against the finding's anchors (file/function/line,
  `affected[]` + exploit-sequence sites): reentrancy guard wrapping exactly the
  flagged function (reuses the C1 enforcement-timing stage table), CEI shape on
  the flagged path, EIP-712 domain separator present in a signature-checked
  payload, pull-pattern on a listed transfer site. Stores
  `dedup_meta.mitigation_present {pattern, file, line, note}` — evidence for
  the critic, NEVER an auto-dismissal (the critic records the verdict; the
  matcher informs it — same law as `in_code_ack`).
- Acceptance: a `mitigation_present` demotion in `acceptance.go`, beside the
  ack demotion (same magnitude class, ~-1.0).
- *Policy layer* — zero new logic: documented assumptions remain an
  `accepted_risks` pattern match (check13). Additive only: `bounty.accepted_risk`
  gains an optional `reference_url` (the doc that carries the assumption).
- Structural separation, enforced: a test proves `mitigscan` output can never
  write `bounty.accepted_risk`, and check13 can never write a critic verdict —
  and the report renders the two under DIFFERENT subsections ("why the critic
  dismissed" vs "why the program won't pay").

**Anchors:** `internal/findings/ackscan.go` (template + hook),
`internal/findings/ingest.go` (post-save hook), C1 enforce table,
`internal/risk/acceptance.go`, `internal/bounty/bounty.go` (check13 ~L1185),
`internal/report`. **Tests:** per-pattern hit/miss on G4's decoy fixtures;
demotion magnitudes; the two-layer non-interference test; byte check with the
field absent.

## G6. Critic triager-outlook rubric (prompt data, policy-injected)

**Motivation.** The report's persistent finding: expert triage judgment is the
last filter and LLM precision is the weak axis (high recall / low precision is
the consistent measured pattern). Our critic answers "is it real?" — the
payoff question is "would a triager accept AND pay?". The empirical harvest
gives the lever: hallucination rates collapse when outputs are grounded in
explicit evidence sources (the 4.23%→spike ablation) — exactly our anchor
discipline, extended to the payment question.

**Design.**
- Extend the critic system prompt (`assets/prompts/48_critic_system.md` — data,
  no code): a second, separately-answered question with a rubric INJECTED from
  the live bounty policy object at dispatch (exclusions, accepted_risks,
  minimum-severity/payout tables, scope) — injected, never copy-pasted, so the
  rubric can't drift from the gate that enforces it.
  *(As landed, tranche 1: the rubric is a static prompt section instructing the
  critic to read the live policy itself (`scope --show`, the brief) before
  answering; automatic policy injection at dispatch REMAINS a G3-era idea —
  the drift-prevention goal holds, via "cite the policy line, never a vibe",
  not yet via machinery.)*
- New finding field `verification.triager_outlook {likely | uncertain |
  unlikely, reason}` (schema-additive; the boundary layer rejects malformed
  responses as usual). Acceptance score: small POSITIVE/NEGATIVE nudge
  (±0.5), bounded, and the backtest (G3) is the only way it graduates from the
  default-off gate. Critic verdict semantics untouched — outlook never alters
  a status.
**Anchors:** `assets/prompts/`, `assets/schema/finding.schema.json`
(verification), `internal/briefing/helpers.go` (policy injection at dispatch),
`internal/risk/acceptance.go`. **Tests:** outlook field round-trip + boundary
rejection of a malformed one; default-off byte check; golden prompts manifest
update.

## G7. Claim-intake checklist + `provenance[]` on every baked-in external claim

**Motivation.** Both source reports contain numbers that fail their own audit:
soft-tier citations (content farms, a lovable.app page) carrying headline
figures, one arXiv id cited for two different papers' claims, a GMX attack
mis-tagged "flash-loan" against every writeup, one incident (Polter) classified
in two categories at once, and the inverted 2-gold sentence. The framework's
defense is process: an external claim may become DATA only if it survives the
checklist, and every data row remembers the trial.

**Design.**
- `docs/eval-methodology.md`: the nine checks — the five from the research
  (temporal split INCLUDING pretraining-cutoff for LLM claims; residual-leakage
  removal; per-class metrics; baseline-vs-per-class-best-detector, not
  "always Slither"; significance testing) plus the four it missed: unit of
  evaluation must be sub-contract (contract-level F1 is gamed by flagging whole
  files), label provenance (injected pattern ≠ exploitable — never mix
  injected-corpora scores with real-incident scores), run variance/pass@k for
  any LLM detector claim, and cost accounting (a 4.2× token-overhead result is
  a different result).
- `provenance[]` (array of `{claim, source_url, checked_date, verdict,
  tier}`) added to: `class_weights.json` rows (G2), playbook/prompt asset
  headers where they cite external numbers, and corpus weighting config.
  Validator in the asset-pack manifest check: any numeric external claim in an
  asset WITHOUT provenance fails validation; `verdict: uncorroborated` is
  legal but renders in reports (honesty, not blocking — principle 2's
  fail-open-for-judgment).
- The source research notes are internal working material; their numbers enter
  the framework ONLY through this validator. Already caught during drafting:
  OWASP loss figures conflated editions (the $953.2M/2024-incident numbers are
  from the 2025-edition analysis; the 2026 edition is built on 122
  deduplicated 2025 incidents, ~$905M — [scs.owasp.org/sctop10](https://scs.owasp.org/sctop10/)),
  one incident (Polter) classified twice, GMX mis-tagged flash-loan-mediated
  (writeups: refund-based cross-contract reentrancy — [Sherlock](https://sherlock.xyz/post/gmx-exchange-hack-explained),
  [BlockSec](https://blocksec.com/blog/gmx-incident-cross-contract-reentrancy-bypasses-a-four-year-old-guard)).
  G2's weight rows must cite the primary OWASP pages, not the notes.
**Anchors:** `docs/`, `assets/` manifest validation
(`internal/validation/schema.go`, asset-pack test). **Tests:** validator
refuses a number without provenance; `uncorroborated` renders; checklist doc is
linked from the runbook's hard rules (D7 keeps it honest).

## G8. Invariants → symbolic/PBT harnesses as an evidence rung

**Motivation.** The report's layered-strategy pillar (symbolic execution for
path exploration, fuzzing for dynamic anomaly) is the one leg our sandbox only
supports by hand. We already EXTRACT the raw material —
`documented_invariants` / `intent_claims` (`internal/invariants`) — and
nothing compiles it into a runnable test. A proven invariant is the strongest
confirmation the ladder has ever been able to record; a counterexample is
concrete EXEC evidence.

**Design.**
- Deterministic scaffold generator: invariant object → Halmos symbolic-test /
  forge-invariant skeleton (file, imports, entry-point stub, assertion hook);
  the model writes the predicate BODY only, inside the scaffold (boundary layer
  validates; the scaffold keeps the model out of structure).
- Exec as usual: sandbox recipes added for `halmos` and `forge fuzz` beside the
  existing foundry/anvil paths; every run is an EXEC record with the pinned
  toolchain; wall-clock/SMT timeouts record `inconclusive` (the report's
  symbolic-execution-scalability warning is OUR budget mechanism's native
  language).
- Outcome mapping: counterexample → EXEC + evidence promotion through the
  normal ladder; proof (bounded) → new rung label `PROVEN-BOUNDED` rendered in
  the ladder (presence-gated field — principle 1, existing bytes move only for
  campaigns that prove things); falsified intent claim → negative memory via
  the existing disproved-hypothesis path.
- No new verbs: generation is a flag on `exec`/`verify`; results are ordinary
  records.
**Anchors:** `internal/invariants/`, `internal/sandbox/`,
`internal/reproduction`, `internal/findings/levels.go` (rung vocabulary —
extend, don't renumber), `internal/learning` (negative memory).
**Tests:** scaffold compiles against pinned solc (fixture); outcome mapping
each way; timeout→inconclusive; byte check without proofs.

## G9. Beyond-contract scoping — `components[]` + two data-only playbooks

**Motivation.** The report's title thesis and the market fact that programs pay
for it (Leather-class scopes list frontend/provider bugs): our model/scope
vocabulary is Solidity-only, so an in-scope frontend is invisible to the
ProtocolModel, the plan, and the acceptance machinery.

**Design.**
- `protocol_model.schema.json`: additive `components[]` —
  `{kind: frontend | relayer | keeper-service | domain | offchain-service,
  path?, url?, trust, in_scope, paid_for}`; actors already carry
  `KEEPER`/`EXTERNAL-PROTOCOL`, so this extends, not redesigns. `brief`/`plan`
  render them as tracked-but-oporous surfaces (opaque to structidx, honest in
  the model).
- Snapshot: hashes arbitrary trees today (verify at landing); the promise is
  only: frontend subtrees are pinned, cited in findings by path+hash, and never
  pretended-over by structural probes.
- Two new playbook YAMLs (data, zero surface cost): `frontend-injection`
  (DOM-XSS sinks, approval/permit phishing flows, pairing-URI phishing,
  extension/plugin supply chain) and `infra-boundary` (DNSSEC/CAA gaps,
  subdomain takeover of parked entries, deploy-path/CI compromise, upgrade
  multisig ops). Each carries class links into the taxonomy so findings on
  components flow through dedup/gate like contract findings.
- NO scanners: frontend findings arrive as model findings (with anchors into
  the pinned tree) or G1-style adapter imports. Per-component acceptance priors
  join G3's table only where the program demonstrably pays (`paid_for`).
**Anchors:** `assets/schema/protocol_model.schema.json`, `assets/playbooks/`,
`internal/protocolgraph`, `internal/snapshot`, `internal/planner`.
**Tests:** schema round-trip + legacy-model byte stability; playbook lint
against `playbook.schema.json`; a fixture campaign filing one frontend finding
end-to-end through gate/report.

## G10. Cross-chain assumption table + separator/finality archetypes

**Motivation.** Bridge losses dominate the incident record (~36% of all
hacked value; the research's Nomad/Binance-Bridge/Harmony-Horizon mechanics are
all *documented-assumption* failures: default-on verifier state, incomplete
Merkle-path checks, threshold keys). We have `bridge-message` playbooks and a
relay archetype but no place where per-hop assumptions become queryable facts.

**Design.**
- Model additive: `chains[]` entries gain `assumptions` (finality model,
  confirmation depth, messenger kind, validator set/threshold, domain
  separator convention) — prose-recon-in, structured-out, same law as the rest
  of the model.
- Deterministic projection (protocolgraph query, no model): per-hop assumption
  table rendered in `brief` + report; every message-handling path is checked
  against the assumptions its endpoints declare — a mismatch (payload signed
  without chainId/domain separator while both chains are named; verifier
  accepting roots the source chain's finality model doesn't guarantee) is
  listed as an ASSUMPTION GAP row.
- Two new archetype YAMLs (hypothesis pre-screen, hint-only):
  `signed-payload-no-separator` and `pre-finality-proof-accepted`
  (structidx predicates); gold fixtures ride G4's cross-chain replay scenario.
**Anchors:** `assets/schema/protocol_model.schema.json`,
`internal/protocolgraph`, `assets/archetypes/`, `internal/findings/levels.go`
(`cross-chain-replay` exists in the class vocabulary). **Tests:** table
determinism; the two predicates on buggy/clean fixture pairs; legacy models
without `assumptions` render the table as "declared: none" (byte-gated).

## G11. `verify --post-patch` regression loop

**Motivation.** The report's audit-practice evolution — one-shot review toward
collaborative/continuous engagement — is exactly what our `immunize`
patch-clause record still lacks: a way to PROVE the fix, not just record the
clause.

**Design.** Flag on existing `verify`: given a post-patch snapshot, replay
(a) the finding's reproduction PoC (must now fail to reach the terminal
capability), (b) the gold archetype set + candidate probes over the diff
(forkdiff between pinned snapshots gives the changed-surface scope), (c) the
clean-control checks (the patch must not have *planted* anything). Output:
`patch_regression` record {finding, still_reproducible | fixed |
indeterminate, exec ids} rendered in the report beside the immunize clause. No
new verb; the existing exec machinery runs everything.
**Anchors:** `internal/cli/cmd_verify*`, `internal/reproduction`,
`internal/forkdiff`, `internal/immunize`, `internal/report`.
**Tests:** fixture pair (buggy→patched trees) yields fixed; unpatched yields
still_reproducible; missing post-snapshot is a clean usage error.

## G12. OWASP/SCVS aliases on taxonomy classes

**Motivation.** Programs and triagers speak standards; our reports speak only
our class names. Aliasing is also the forcing function for G7: an alias table
is external data and carries `provenance[]`.

**Design.** `assets/taxonomy/aliases.json`: class → `{owasp_sctop10: id,
scvs: [ids], swc: [ids]}` rendered as one line in each finding's report header
and the taxonomy CLI output; unmapped classes alias to nothing (never invent a
mapping). Figures/editions re-verified against the primary OWASP pages first —
this item lands after G7's validator exists so it is the first compliant data
asset.
**Anchors:** `assets/taxonomy/`, `internal/taxonomy/taxonomy.go`,
`internal/report`. **Tests:** every alias target exists in the cited standard's
committed id list; byte-gated report rendering.

## G13. Cost-per-confirmed-finding + per-lens yield (ROI stop-loss)

**Motivation.** Both source reports demand cost accounting (the 4.2×
token-overhead multi-agent result is a different result), and G7 enforces it
for *external* claims — but the framework never attributes its *own* spend.
`budget/cost/yields/price` track campaign totals; nothing answers "$ per
critic-confirmed" or "lens L-04 burned N tokens for 0 confirmations".

**Design.**
- Stamp `execs/` records + adapter calls with `cost{usd, tokens, ms}`
  (reuses `internal/costs`, `internal/pricing` — data only).
- Roll up in `brief` + report Results: `$/critic-confirmed`,
  `$/evidence-confirmed`, and a per-lens/per-playbook yield table
  `{n_planned, n_confirmed, cost}`. Presence-gated (no cost fields → no
  bytes — principle 1).
- No auto-kill: the table is advisory (fail-open, principle 2); the operator
  kills the lens. G17 graduates this to auto-deprioritization.
**Anchors:** `internal/costs`, `internal/pricing`, `internal/briefing`,
`internal/report`. **Tests:** rollup arithmetic on a fixture campaign;
byte check without cost fields; lens table ordering determinism.

## G14. Operator correctness: amend/supersede + batch dispose + dismissed-with-reach

**Motivation.** Three deferred/leftover asks (E1, E2, D1-C6) that keep biting
under time pressure. Filed findings cannot be corrected except by hand-editing
JSON (history loss, hash-chain lies); probes close one-row-at-a-time so the B4
linter gets bypassed; DISPROVED/OUT_OF_SCOPE findings with tier-0/gap≥3 reach
(the false-*negative* direction — everything else guards false positives) have
no second-look queue.

**Design.**
- `amend <CID> <F> --title/--class/--claim/--note` bumps `claim_version`,
  appends `history[]`, logs `finding.amended`; `supersede <CID> <F-new> --of
  <F-old>` moves old → `SUPERSEDED`, re-parents evidence/chains. New verbs are
  the principle-6 exception: the capability is demonstrably unreachable today
  (E1's bar). Status-set + `levels.go` transitions extended.
- Batch dispose: `answered <CID> <row-id...> --status … --reason …`
  (`--reason-all` for shared reason), B4 v2/v3 gates run on the way in.
- "Dismissed with strong reaching" report subsection (D1-C6 as designed):
  DISPROVED/OUT_OF_SCOPE findings whose probe rows or evidence had
  tier-0/gap≥3 surface — deterministic from surface + verdicts, presence-gated.
**Anchors:** `internal/findings/*.go`, `internal/cli/cmd_amend.go` (new),
`internal/planner/answered.go`, `internal/report`. **Tests:** amend round-trip
+ history; supersede re-parenting; batch gate refusal on one bad row;
second-look fixture (morph's 3 G-01-burying rows reproduce).

## G15. PoC quality gate at mint (rerun variance + fork freshness)

**Motivation.** G11 proves the *fix* later; nothing proves the *proof* now.
`mint` accepts an EXEC that passed once on a fork that may be weeks old.
LLM-generated PoCs hallucinate non-determinism; fork-state drift makes green
runs meaningless.

**Design.** Two fail-open advisories at `mint` time (never blockers —
principle 2):
- **Rerun variance:** re-run the PoC N=3 through the existing sandbox seam;
  `flaky` when not 3/3, recorded on the evidence item, surfaced in
  `brief`/report. Deterministic replays stay silent (no bytes).
- **Fork freshness:** `fork_block_number` vs pinned-snapshot age; stale
  (>N blocks or >7d, policy-tunable) warns "re-pin with `snap`, re-`mint`".
**Anchors:** `internal/reproduction`, `internal/cli/cmd_mint*.go`,
`internal/findings/levels.go` (E4–E6 rung vocabulary — extend, don't
renumber). **Tests:** flaky fixture (2/3) flagged; deterministic 3/3 silent;
stale-fork warning + fresh silence; byte check when the fields are absent.

## G16. Second golden recipe for probe-surface coverage

**Motivation.** Plan-review §8, still open: the golden campaign's surface has
4 rows, 0 of them assertion-strength, so C1/C2 enrichment is invisible to the
one end-to-end check the project trusts. G4 is planted-*bug* eval
(recall/precision); this is surface-*coverage* eval — a different blind spot.

**Design.** One extra deterministic fixture emitting ≥1 row per probe axis
(assertion-strength with a gap, custody divergence, trust, cursor,
short-circuit) + in-process schema validation of the surface. No new bugs,
just coverage — the next "0 rows of this axis, enrichment silently dead" rot
fails the suite instead of shipping. Golden-safe by construction (new recipe,
existing recipe untouched).
**Anchors:** `scripts/golden/`, `internal/probes/*_test.go`,
`assets/schema/probe_surface.schema.json`. **Tests:** the recipe itself;
per-axis row presence; schema-valid surface; existing golden bytes unchanged.

## G17. Tactic batting-average (per-lens/playbook precision, auto-deprioritize)

**Motivation.** D5 gave `memory --reflect/--reject` but nothing *consumes*
the ledger: a lens/playbook that goes 0/20 keeps getting planned. G3
calibrates *classes*; this calibrates *our own tactics*.

**Design.** Pure function over `evalstore` + campaign verdicts →
per-lens/per-playbook `{n, precision, Wilson CI}` rendered in `brief`;
planner down-weights below threshold only when
`policy.auto_tune: true` (default off — same posture as G3's `wPrior`).
No auto-promotion, only auto-deprioritization with a reason line (fail-open).
**Anchors:** `internal/learning`, `internal/planner/lenses*.go`,
`internal/evalstore`, `assets/schema/bounty_policy.schema.json`.
**Tests:** precision + CI against a pinned table; threshold fallback;
gated-off byte check; planner ordering with the flag on/off.

## G18. Immunefi-shaped export flag on report

**Motivation.** D8 established programs want prose Recommendation, not verified
patches, and the platform report guide mandates sections (Summary / Impact /
PoC / Recommendation / Related areas + severity against *their* table).
Submissions today are hand-reformatted from `report.md` — the dumbest loss
reason is "rejected for format".

**Design.** Flag on the existing verb (no new surface): `report --format
immunefi` renders existing fields into that shape + `submission_ready` mapped
to the program's severity table, with a missing-section checklist (fail-open
list, not blocker). G12 aliases ride it as the severity-mapping line.
**Anchors:** `internal/report`, `internal/bounty` (program tables),
`assets/taxonomy/aliases.json` (G12). **Tests:** section presence on a
fixture campaign; missing-section list; default (no flag) bytes unchanged.

---

## Wave G — explicit non-goals (principle 6, recorded so they stay dead)

- Consensus/p2p fuzzing (LOKI/Fluffy class) and formal consensus specs —
  different product, different buyer, unbounded surface.
- Training our own detector/fine-tuned model — `sft/` remains a data-capture
  pipeline; the model shop is someone else.
- Homegrown frontend/DOM or DNS scanners — G9 scopes them, G1-style adapters may
  import their results; we never build them.
- Benchmark *standardization proposals* — G4/G7 build our internal discipline;
  writing the field's standard is not our campaign.

## Wave G — landing order & dependencies

1. **G7 first** (docs + validator, one day; unblocks honest provenance for
   everything after) → **G1 + G6** (independent, precision-focused, small).
2. **G4** — the measurement harness; nothing after it may claim improvement
   without a CI.
3. **G3 (+ G2 as its data layer)** — the calibration engine; backtest is then
   the gate for G1's corroboration weight, G6's outlook nudge, and G2's
   acceptance column graduating from default-off.
4. **G5** — rides the ackscan/C1 machinery; its decoys already exist as G4
   variant fixtures.
5. **G8 / G9 / G10 / G11 / G12** as decisions allow; G12 is gated on G7,
   G9's priors on G3, G10's fixtures on G4.
6. **G13–G18 (review follow-up)** — G16 first (coverage safety before more
   probe work), then G14 (E1/E2/C6 correctness), then G13+G15 (ROI + PoC
   quality), then G18 (rides G12), then G17 (rides G3's backtest posture).

**Divergence posture:** every wiring change ships behind a presence-gate or a
policy default-off; the expected golden byte movers are the corpus `search`
weight swap (G2) and any accepted-off switch of A3 terms after a backtest win
(G3/G6) — each gets its divergence-ledger row when it actually lands.

---

## Wave H — review backlog (filed 2026-09-11, from the tranche-2/3 gate reviews)

Non-blocking follow-ups the per-task reviewers surfaced and the final
whole-branch reviews triaged as FOLLOW-UP (nothing here is a correctness
emergency; the DROPs — cosmetic/test-prose items — were discarded, not filed).
Ordered roughly by real-world bite.

| # | item | why it matters |
|---|---|---|
| H1 | ~~`internal/costs/costs.go` unattributed edge: all cost rows lensed + bare priorities ⇒ no unattributed row emitted, planned count silently vanishes. Fix: add `\|\| planned["unattributed"]>0` to the emit gate + test that shape.~~ **LANDED Wave J** (`edf9aaf`) | Only one that can surprise in a real campaign's advisory table. |
| H2 | ~~`internal/reproduction/postpatch_scope.go` uncapped walk: `scopeSolFiles` reads every common file fully; only output is capped (50 rows). Add a file-count or total-bytes guard.~~ **LANDED Wave J** (`502a0da`) | Latency on huge vendored trees. |
| H3 | ~~Same file, uncapped detail join: cap plant rows with the same overflow convention as scope rows.~~ **LANDED Wave J** (`00d280a`) | Record bloat on chatty archetypes × huge changed sets. |
| H4 | ~~Same file mirrors `structidx`'s excluded-dirs by value: extract a shared constant.~~ **LANDED Wave J** (`2d6a051`) | Silent drift if the parser's set changes. |
| H5 | ~~`dedup_meta.mitigation_present` + component citation hashes ride JSON strings / evidence description text: consider dedicated `affected[].hash`-style fields (schema migration).~~ **LANDED Wave J** (`3dcea47`) | Machine-checkable citations; today's shape is honest but stringly. |
| H6 | ~~evalsuite test lacks ES16-ack / ES17-clean presence asserts (`assets/evalsuite_test.go`).~~ **LANDED Wave J** (`2d6a051` + follow-up `1215f86`) | The decoy/control semantics are covered in mitigscan tests but not in the suite's own test. |
| H7 | ~~mitigscan state-write regex under-detects nested-index writes (`deposits[rs[i]]`).~~ **LANDED Wave J** (`4ca4c2c`) | Pattern coverage, not a correctness bug (falls through to the next check). |
| H8 | ~~`SURFACE2_AXES` hand-copied literal vs `check-golden.py` `EXPECTED_PROBE_AXES` (`scripts/golden-run.py:131-134`): read the shared list.~~ **LANDED Wave J** (`2d6a051`) | A 7th axis would slip past the rot gate. |
| H9 | ~~`forgePassSummary` matches `Suite result` across the whole text instead of per-line (`internal/harness/outcome.go:208`).~~ **LANDED Wave J** (`c054884`) | Nil blast radius today (zero-FAIL-lines required regardless); tighten on touch. |
| H10 | ~~`sweep_t35_registry_test.go` still mirrors eight playbooks: extend to ten for tool-id coverage.~~ **LANDED Wave J** (`c054884`) | Registry-completeness intent. |
| H11 | ~~immunefi loader cleanup: dead `paid` param + twin `sha12` derivation paths (`internal/datasets/immunefi/`).~~ **LANDED Wave J** (`c054884`; scope widened to all four twins) | Hygiene. |
| H12 | ~~`string(rune)` test idiom → `strconv.Itoa` (`internal/evalscore/evalscore_test.go:376` + eval section test).~~ **LANDED Wave J** (`0c4cc57`; the two sites the item named — the two more found under it are filed as H16) | Robust past 9 cases. |
| H13 | ~~`class_weights.schema.json` strictness: `number` accepts int `1` and float `1.0` alike; confirm no `"null"`-string `source_url` in fixtures.~~ **RESOLVED Wave J** (`0c4cc57`; decision + comment, no migration) | Schema hygiene; verify fixture data, then decide. |
| H14 | ~~Scaffold `_witness` storage var is contract-visible in halmos symbolic context (`internal/harness/harness.go`).~~ **RECORDED Wave J** (`0c4cc57`; hold stated at `WitnessVar`, no code change) | Harmless for dummy scaffolds; revisit when real invariants run. |
| H15 | ~~`reentrancy` carries no `swc` alias although the fetched registry list has SWC-107 ("Reentrancy") — the mapping I6 deliberately deferred. Adding it is one data line in `assets/taxonomy/aliases.json` (`"reentrancy": {"owasp": "SC05", "swc": "SWC-107"}`) plus **four pinned display literals** that must grow in step: `internal/report/aliases_test.go:36,64`, `internal/briefing/aliases_test.go:58`, `internal/classweights/aliases_test.go:92` — plus the `assets/testdata/asset_manifest.json` regen. No code change: `ClassAliasSuffix` already renders `[OWASP SC05; SWC-107]`.~~ **LANDED Wave J** (`fa9bb27`) | Deferred by I6's byte law, which required every existing OWASP-only rendering to stay byte-identical in that wave, not by any doubt about the mapping (the id is in the fetched list and the class is the registry's own word for it). |
| H16 | `string(rune('0'+i))` idiom survives in two more test files with no `%10` guard — `internal/report/sweep_t35_unprice_test.go:80`, `internal/cli/sweep_t35_unprice_test.go:36` (found by H12's sweep; same >9 latent drift). Fix: `strconv.Itoa`, same as H12. | Robustness past 9 rows in two table-driven tests; the item H12 named is fixed, these are the remainder. |

**Status (closed by Wave J, 2026-09-11).** H1–H12 and H15 are landed; H13 and
H14 were decisions the items asked for (a strictness finding and a hold
statement) and landed as recorded decisions, not code changes. Nothing in this
backlog is open except **H16**, which H12's sweep filed after closing its own
scope — it is genuine and small (two identical one-line fixes), deliberately
left rather than widening H12 past the files it named.

E3 (ladder "other" axis) and E4 (campaign severity floor) stay deferred under
principle 6 — they are NOT part of this backlog; they land when a real run
trips them.

---

## Wave I (external-feedback responses, 2026-09-11)

Responses to the external feedback round (items I1–I6). Each item lands as its
own commit(s); this section is expanded by the wave's close-out task. Defect
corrections found while planning the wave are filed here honestly — the earlier
plan and runbook history blocks are NOT retro-edited to pretend the defect was
always known.

### I1. Eval cases get a date, and a date can strike a case out (I1a + I1b)

**What the feedback asked.** The G7 self-apply discipline (do not train on the
thing you test) was only half-applied: the gold suite had no notion of *when* a
case's bug lived, so a held-out case could be older than everything in the dev
partition, and a near-copy of a dev case could sit in the held-out leg and
inflate recall.

**Landed.** I1a `b596bf8` (`deployed_at` on eval cases + schema), I1b `625cae2`
(temporal gate + cross-partition near-dup scan, exclusions only).

**What changed.** `assets/schema/evaluation_case.schema.json` gains an additive
optional `deployed_at` (`created_at` stays the ingestion stamp written by
`AddCase`; `deployed_at` is when the underlying bug lived on-chain / the
advisory published, operator-supplied, absent-ok) and `AddCase` passes a
supplied value through without defaulting or overwriting it.
`internal/evalstore/temporal.go` adds `PartitionHealth`, applied at scoring
time: a held-out row is temporal-excluded iff its date is strictly older than
the max dev date (compare `deployed_at` when both rows carry a parseable
`YYYY-MM-DD`, else `created_at`; an unparseable `deployed_at` fails the row
closed and the run open), and near-dup-excluded iff its token Jaccard against
ANY dev/training row is ≥ 0.8 (`nearDupThreshold`). `internal/backtest` prints
`held-out excluded: <N> temporal, <M> near-dup` and the audit's `## eval`
section renders the same block presence-gated (problems non-empty only). No
stored row is mutated or deleted — rows are excluded from ranking, never
rewritten, so a later fixed dataset shows what changed instead of hiding it.

**Disclosures.** All 17 `assets/evalsuite/cases.json` rows carry
`deployed_at: 2026-09-11` **copied from their own `created_at`** — the suite does
not record real exploit/advisory dates, and none were invented; every row is
copied, and no row claims a provenance it does not have.

**Deviation (D1).** `archetypes.Jaccard` could not be imported from
`internal/evalstore` — the cycle was verified real, not assumed. The function
moved to a new leaf package `internal/textsim` (pure token-set Jaccard, its own
tests), and `archetypes.Jaccard` survives as a one-line delegating wrapper so
corpus callers move zero bytes.

### I2. SAST loaders read the tools' real output, and every recall gets a floor (I2a + I2b)

**What the feedback asked.** (a) The Slither lane had never been validated
against real tool output, and Aderyn was not wired at all; (b) an eval recall
number with no baseline beside it is unreadable — "found 26 flags" means
nothing without "and a program that flags everything would score X".

**Landed.** I2a `3ed9815` (Slither real-shape repair + Aderyn loader +
`--from aderyn`), I2b `61f8a8b` (baseline runner). **I2a is a defect
correction — the full write-up is the `I2a.` entry below; it is filed there in
full rather than duplicated here.**

**What changed (I2b).** `internal/backtest/baseline.go` adds the fixed roster
`always, never, slither, aderyn` and
`BaselineBlock(names, held, run ToolRunner) string`; `corpus-surface
--backtest --baseline NAME` (repeatable) prints the block AFTER the `verdict:`
line, advisory only — it never moves the verdict, the exit code, or any earlier
byte, and it prints in roster order whatever order argv gave. `always` flags
everything (the floor any detector must beat, so recall never prints without
its price), `never` prints the literal `precision: 0/0 (95% CI n/a)` that
`wilson.Format` already returns — never a fabricated 0%. The tool baselines run
the real binary once per resolved source root, parse with the I2a loaders, and
flag a case iff an admitted payload's file basename matches one of the case's
`gold.locations[].file` basenames. A case with no local checkout (a GitHub URL,
an empty `gold.locations`) is **skipped, never a miss**
(`skipped: <k>/<n> cases (no local checkout)`); a missing binary or one that
fails on every root prints a single SKIPPED line and exits 0. Spawning uses
`os/exec` directly, deliberately not `internal/sandbox` (a sandbox run mints
`sandbox_execution` records on a campaign; a baseline is an eval-side
measurement on a read-only scorecard).

**Deviation (adjudicated correct).** The locked plan text defined the baseline
`recall` as `anchored / n` with "anchored" borrowed from the framework's own
scoring semantics (`gold.outcome == "confirmed-exploitable"`). The shipped
comparator scores `recall = flagged / scored` — for an *external detector
baseline* the honest question is whether the tool flagged the case, and reusing
the framework's anchor definition would have made `always` and `slither` differ
in kind while hiding the tool's own behaviour. The Task 6 review adjudicated
the shipped semantics correct; the plan sentence is superseded by the contract
documented at `internal/backtest/baseline.go:117`.

### I2a. G1 Slither adapter read a fabricated fixture shape (defect correction)

**Defect.** The shipped G1 adapter (`internal/datasets/slither/slither.go`)
read `results` as a JSON ARRAY and took locations from
`vertices[].filename`/`line_no`. Real Slither JSON (slither 0.11.6,
`slither src --json out.json`) has `results` as an OBJECT whose `detectors[]`
rows carry locations in `elements[].source_mapping`. Neither `vertices` nor an
array `results` exists in real output, so `slither.ToPayloads` returned an
empty slice for every real document and `webv2 ingest --from slither` silently
created ZERO hypotheses and exited 0 — a framework adapter reporting "found
nothing" beside a tool that found 26 flags.

**Why the suite could not see it.** The checked-in fixture
`internal/datasets/slither/testdata/slither_sample.json` was fabricated in the
same wrong shape, and `internal/cli/cmd_ingest_test.go` pinned that shape
inline, so adapter and tests agreed with each other and disagreed with the
tool.

**Fix.** The adapter now reads `results.detectors[]`, anchors each detector
from `elements[].source_mapping` (`filename_relative` → `filename_short` →
`filename_absolute`; line = `lines[0]`, dropping unanchorable elements and
dependency elements), and is pinned by REAL captured fixtures (slither 0.11.6
+ aderyn 0.6.8 over a scratch copy of `assets/evalsuite/src`, trimmed by
deleting whole rows only). The same task adds an Aderyn loader
(`internal/datasets/aderyn`) and generalizes the ingest lane (`--from
{slither,aderyn}`). Fixed in
`fix(I2): slither loader reads real Slither JSON; add aderyn loader + --from aderyn`
(Wave I, 2026-09-11).

### I3. Acceptance score-band precision, and ECE refused as inapplicable

**What the feedback asked.** "Calibration" for acceptance scores — an expected
calibration error (ECE) over the scores, so a reader could trust a high score.

**Premise corrections (both recorded, both load-bearing).**
1. **Acceptance scores are not probabilities**, so ECE over them is meaningless.
   The score is an additive evidence sum — severity band 0–3, evidence level
   0–3, critic verdict ±(−2/+1.5), demotions, reversibility, clamped at 0 — and
   the schema description at `assets/schema/finding.schema.json:1248` is
   authoritative. The honest question the scores CAN answer is "does a higher
   score band actually contain a higher fraction of gold-anchored findings?",
   and that is what shipped instead. ECE was refused, not deferred.
2. **There is no "B4v3" anywhere in this tree** — no such gate, no such event
   version. There is also no *stored refusal event*: stale/superseded refusals
   surface as a `BoundaryError` at `internal/findings/boundary.go:258-262` and
   are not logged. Neither shape was needed by this task; the mapping the
   feedback implied does not exist.

**Landed.** `4b57129`.

**What changed.** `internal/evalscore/bands.go` adds
`Bands(programs, liveByProgram, cases, score ScoreFn) (rows, unscorable,
fabricated, fabByBand)` over the SAME suite scope `ScoreSuite` already defines
(extracted into unexported helpers; `ScoreSuite` output stays byte-identical,
proven by its existing tests). Buckets are the locked ladder
`[0,1) [1,2) [2,4) [4,+Inf)` over `bandEdges = {0,1,2,4}`; each non-empty
bucket renders `wilson.Format(anchored, total, "precision")` so the edges are
always visible in the line. A finding whose score is unavailable, NaN or ±Inf
is counted `unscorable` and lands in NO bucket (never a silent bucket 0). The
fabrication ledger counts only findings the *record itself* retracted
(`verification.critic_verdict == "disproved"` or status `DISPROVED`);
`SUPERSEDED`/`DUPLICATE`/`OUT_OF_SCOPE`/`INFORMATIONAL` are explicitly NOT
fabrications (a superseded row is a replacement, a duplicate is a dedup
outcome, out-of-scope is a scope call) — the choice is a code comment so it
cannot drift silently. `internal/audit/sections/eval.go` appends the block
after the false-positive line and adds the `bands` / `unscorable` /
`fabricated` / `fabrication_bands` value keys; everything is presence-gated, so
a scope with zero live findings renders byte-identically to before.

### I4. Operator-supplied DNS/dependency facts on `components[]` — readability, not hashing

**What the feedback asked.** Make `remappings.txt` and lockfiles visible to the
snapshot, and give `components[]` a place for DNS/dependency facts so an
operator can answer "which package version, observed when, by whom?".

**Premise correction (recorded).** `remappings.txt` and the lockfiles were
**already inside the source Merkle root**. `internal/snapshot/hashing.go`
`pinnedFiles` excludes only `SourceExcludes` (`.git`, `.hg`, `.slps`,
`node_modules`, `cache`, `out`, `.venv`, `__pycache__`, `.mantis_snapshots`),
has NO extension filter, and skips only a root-level `snapshot.json`; changing
a remapping already moves the source hash, and `LockfileLeaves` additionally
hashes the lockfiles as `dependency_lock_hash`. What was genuinely missing was
**readability**: the snapshot gives one opaque dependency hash and the protocol
model carried no dependency or DNS facts at all. This task adds the readable,
dated, attributed slots — it does NOT add hashing (already correct) and does
NOT add any network path.

**Landed.** `668bcd0`.

**What changed.** `assets/schema/operator_facts.schema.json` +
`internal/protocolgraph/facts.go` (`ApplyFacts`, additive and idempotent,
joined on `(kind,url)` or `(kind,path)`) + `internal/protocolgraph/manifests.go`
(`FactsFromDir` over `remappings.txt` and six lockfile formats, format-specific
and total — an unreadable entry is an error naming file+line, never skipped);
`components[]` items gain two additive optional objects; `webv2 model <C>
[file] --facts PATH [--facts-observed-at YYYY-MM-DD]`. A fact matching no
component, matching two components, or repeating a fact type on one component
is an ERROR (an operator asserted it; a typo must not be dropped silently). A
directory of manifests has no date inside it, so `--facts-observed-at` is
required there and is **never** taken from the wall clock; a JSON document
carries its own `observed_at` per fact. There is no socket, no resolver, no
DNS cache read — `rg -n "net\.|LookupHost|LookupIP|net\.Resolver"
internal/protocolgraph/` returns nothing (the structural proof, run in the task
gate). Without `--facts` the verb moves zero bytes.

### I5. Four bridge predicates — threshold, relayer-key, Merkle-path, default-on verifier

**What the feedback asked.** Cover the bridge shapes the paper names: a
multisig threshold with no enforcement on the execution path, a single
relayer key that can move messages, a Merkle proof accepted without a
completeness/length check, and a trust flag that is written `true` by default.

**Landed.** I5a `d87ff34` (`threshold_without_enforcement`,
`relayer_single_key`), I5b `e3d3217` (`merkle_proof_no_length_check`,
`verifier_default_on`). Plan coordination note corrected in `758e3b6`.

**What changed.** Four check types + registry entries in
`internal/archetypes/evaluate.go`, four schema `oneOf` variants, four YAML
archetypes (all `criticality: high`, `playbook_hint: bridge-message`), paired
buggy/clean fixtures, and the archetype count pin moved exactly once per task:
Nine → **Eleven** (I5a) → **Thirteen** (I5b). (The plan's original coordination
note predicted Ten → Twelve; the tree already shipped nine YAMLs, and the
locked rule is "bump by exactly the predicates YOU add, never touch the other
task's number" — hence Eleven and Thirteen. Verified, not re-derived.)

**Honesty (the reason these are hint-only).** State-variable nodes in
`structidx` carry NO values (`internal/parser/parser.go:1059-1061`;
initializers are discarded at `:87`), so all four predicates match on *shape*:
a threshold-named variable with no guard reference to it; an `onlyX`-guarded
entry point whose guard maps to a single relayer-named address variable; a
proof-shaped parameter with no `length` evidence on the path; a trust-named
state flag written in a constructor/initializer-shaped function by an
unguarded writer. Each YAML description and its code comment state what is
invisible: they tell an operator where to look, never that a bug is there.

### I6. SWC aliases fetched verbatim, and an embargoed disclosure bundle on publish

**What the feedback asked.** (a) Cross-reference taxonomy classes to SWC ids
(like the existing OWASP aliases); (b) let a publish carry a disclosure bundle
with an embargo.

**Landed.** `0e7a4f4` (aliases), `5f5796b` (disclosure bundle).

**Fetch-primary discipline (I6a).** All 37 `SWC-<n>` ids and titles in
`assets/taxonomy/aliases.json` were fetched **verbatim** from the SWC registry
overview table
(`raw.githubusercontent.com/SmartContractSecurity/SWC-registry/master/entries/index.md`)
on **2026-09-11**; nothing was hand-typed from memory. `provenance[].figure`
records the page's sha256. The registry's own staleness caveat is recorded in
`provenance[].note`: its content has not been thoroughly updated since 2020, is
known to be incomplete, and may contain errors; maintained guidance is the EEA
EthTrust Security Levels specification. The alias is a cross-reference for a
human reader, never an authority claim.

**Coverage is partial and honest (I6a).** Exactly ONE class is mapped:
`unchecked-external-call → SWC-104` ("Unchecked Call Return Value"). Every
other class deliberately carries no `swc` key rather than inventing a mapping
to reach a round number; an unmapped row renders byte-identically to before
(`[OWASP SC06]`), and `ClassAliasSuffix` renders nothing for a class with no
alias. The obvious second mapping, `reentrancy → SWC-107` ("Reentrancy"), is
**DEFERRED**, not doubted: adding it moves four pinned display literals
(`internal/report/aliases_test.go:36,64`, `internal/briefing/aliases_test.go:58`,
`internal/classweights/aliases_test.go:92`) plus the asset manifest, and I6's
byte law required every existing OWASP-only rendering to stay unchanged. It is
filed as **H15** in the Wave H backlog below.

**Disclosure bundle (I6b).** `assets/schema/disclosure.schema.json` +
`internal/sharedmem/disclosure.go` + `PublishCampaignWith` (the old
`PublishCampaign` delegates with the zero value, so every existing caller and
record is byte-identical) + `publish --disclosure FILE`. Validation is
fail-closed (exit 1): every cited finding must EXIST in the campaign, be
`CONFIRMED`/`CHAIN` (never a hypothesis or a possible), be part of this
publish, and be cited once. If the publish then fails, the campaign-local
artifact stays on the campaign and is NOT in the shared store.

**The safety property (package doc comment, restated here).** The bundle's
CONTENTS never enter shared memory: the campaign-local artifact holds the
prose, and the publish RECORD carries only `disclosure_sha256` (hex) and
`disclosure_embargo_until`. Checked by a real grep of the written store tree
for a sentinel string in the test's summary, not by an assertion about a
struct.

**Embargo is a policy field, NOT enforcement (locked).** The framework does
not refuse, delay, or suppress a publish while an embargo is open; it makes the
state legible so a recorded embargo is never mistaken for an enforced one. The
output line says so: `disclosure: bundle <sha256[0:12]> (<n> findings),
embargo_until <date> — recorded, not enforced` (or `, no embargo` for null).
Record fields are appended ONLY when a bundle was attached; the disclosure hash
is a third, separate field and is never folded into `sig`/`mem`.

### Wave I — CI-correctness pass (pre-merge, 2026-09-11)

**Method.** Added lines of `git diff <base c17d5dc>..<wave head>` grepped for
`(95% CI`; every literal `<k>/<n> (95% CI lo–hi%)` recomputed against
`wilson.Interval`/`wilson.Format` semantics (`z = 1.959963984540054`, bounds
rendered as tenths of a percent, clipped to [0,1]).

**Result: 49 added lines matched, 48 carried a parsable metric literal (the
49th is the plan-prose sentence in this section's own bullet), spanning 12
distinct `(k,n)` pairs:**

| k/n | literal | k/n | literal |
|---|---|---|---|
| 0/0 | `n/a` | 1/2 | `9.5–90.5%` |
| 0/1 | `0.0–79.3%` | 1/3 | `6.1–79.2%` |
| 0/2 | `0.0–65.8%` | 2/2 | `34.2–100.0%` |
| 0/3 | `0.0–56.1%` | 2/3 | `20.8–93.9%` |
| 0/4 | `0.0–49.0%` | 2/4 | `15.0–85.0%` |
| 1/1 | `20.7–100.0%` | 4/4 | `51.0–100.0%` |

**Zero mismatches.** The G4 erratum is not repeated anywhere in the wave: both
`2/2` literals added by Wave I read `34.2–100.0%` (the old wrong value was
`20–100%`, which is the 2/3 interval). The one place a raw `2/2 (95% CI
20–100%)` still appears in this document is the Wave G4 example at line 2074,
where the erratum beside it is intentional and unchanged.

*Scope note: this pass covers the code/asset/plan diff through `5f5796b`. This
close-out section itself contains `95% CI` strings by construction (it cites
the pass) and is excluded from the count.*

---

# Wave K — Free prover backends behind the G8 seam (wrap, don't build)

Date: 2026-09-11 · Status: **PARKED — post-production proposal (user decision
2026-09-11).** Wave J, the definitive close-out, shipped without it: this
section was written concurrently by another writer, was never one of Wave J's
nine tasks, and is not required for production readiness. Nothing here blocks
the shipped tree; nothing in the shipped tree blocks this except a green tree.

*Update 2026-09-12: MiniCertora landed as the G8 third kind (docs/superpowers/plans/2026-09-12-minicertora-harness-backend.md; architecture docs/MINICERTORA_ARCHITECTURE.md). K1/K3/K4 re-scoped per that doc §0.*

**Wave L-core — LANDED 2026-09-12 (SDD, plan above; commits `60663100..d87f3c5f`).**
Shipped: the `minicertora` scaffold kind (`.mspec` under the BODY law, rule
name `inv_<n>`), `MapMinicertora` (JSONL → rung + verbatim `proof` sidecar,
negative-exit floor), the host profile `minicertora` (E3-capped,
version-probed), CLI wiring (three-kind `--scaffold`/`--kind` choices,
`INV.mspec`, exit-status plumbing, three-mode proved-bounded display,
Decision-2b `.mspec` binding), the envgo `e4_capable` pin, and the schema
`proof` contract (key set is the contract; values admitted verbatim by
design). Golden GREEN throughout; existing bytes moved only in choice-list
help/error texts.

Follow-ups triaged from the final review — **all of 1–5 CLOSED by Wave
L-advice** (`d07385ac..f33294b9`, 2026-09-12; see the landing record below):
1. **CLOSED** (`f33294b9`): the model_response/trajectory `execution_profile`
   enums + prompts 36/47/49 now carry all eight `sandbox.Profiles` names in
   declaration order (`host-readonly, halmos, forge-fuzz, minicertora,
   docker-networkless, docker-gvisor, vm-snapshot, fork-runner`), pinned
   three ways (`TestReproducerRequestProfileRegistryParity`, the schema
   enum-order test, the sft corpus resync).
2. **CLOSED** (`414ac16f`): audit's `harnessBoundK` falls back to
   `proof.bounds.loop_bound` when `bounded_k` is null/absent — exact decimal
   text, so a beyond-int64 bound renders verbatim, matching the CLI.
3. **CLOSED** (`f33294b9`): timeout or signal death on a minicertora run
   stores `inconclusive (no clean completion; loop bound was N)` (or the
   clause-free form when no bound was found) instead of the wrong-unit
   `timeout after Ns`; halmos/forge keep their byte-pinned wording.
4. **CLOSED** (`f33294b9`): `proof` carries a ten-key schema `required` array
   (values still admitted verbatim), pinned by the
   `proof missing warnings key` reject row.
5. **CLOSED** (`f33294b9`): the stale `mcArr` comment is reworded to the
   post-landing contract — the schema pins the key set, tool values ride
   verbatim.
6. Deferred planes stand, with the L3 row now landed in advisory form:
   **L3 escalation dispositions — advisory form LANDED**
   (`d07385ac` + `414ac16f` + `ff3775d1`: the 25-code → 8-class disposition
   table renders as ` | next: <advice> (<class>)` on minicertora inconclusive
   audit lines; see the landing note in `docs/MINICERTORA_ARCHITECTURE.md`
   §L3). Auto-spawning the escalation execs stays operator/model-driven by
   design (surface budget); the `model_gaps` tally is **NOT built** — the
   audit line IS the gap surface, deliberately. Still deferred: L5 sweep
   templates, L6 calibration fixtures, the `calls[]`→sequence_poc bridge, and
   invariant-block scaffolds (architecture errata §L1).

**Wave L-advice — LANDED 2026-09-12 (SDD, plan
`docs/superpowers/plans/2026-09-12-wave-l-advice-dispositions.md`; commits
`d07385ac..f33294b9`).** Docs/rendering wave, no new verbs and no gate moved:
- **`internal/harness/disposition.go`** (new, `d07385ac`): the 25
  `REASON_CODES` → eight classes (`escalate-bound`, `escalate-flag`,
  `escalate-solver`, `spec-rewrite`, `honest-refusal`, `tool-error`,
  `model-bug`, `witness-triage`) as pure data, plus `Disposition(summary)` →
  `(class, advice, ok)`; unknown codes → `unmapped`, plumbing floors →
  `ok=false` (never advice). A ninth exported class, `escalate-runtime`,
  names the runtime floor (see the timeout-wording row below). Advisory
  only — nothing in it gates anything.
- **Audit rendering** (`414ac16f` + `ff3775d1`): a minicertora inconclusive
  line gains ` | next: <advice> (<class>)`; every other (kind, rung) pair is
  byte-identical to before. The decoration `harnessMapBound` appends
  (` (unbound: …)`) is stripped before classification, so a decorated floor
  still gets no advice and a decorated mapped reason keeps its real class.
- **Registry parity** (`f33294b9`): eight-profile `execution_profile` enums in
  both schemas, prompts 36/47/49, pinned by the boundary registry-parity test,
  the enum-order test and the roles pins — the model-facing bundle no longer
  advertises a profile its schema rejects.
- **Honest timeout wording + the named runtime floor** (`f33294b9` + the
  final-review fix): minicertora timeout/signal-death summaries say
  `no clean completion (loop bound was N)`; that floor is a **NAMED
  disposition** — `Disposition` matches it on the inner text before the
  `: ` separator and returns `escalate-runtime` (advice: "the run never
  completed — re-run with a larger --timeout-ms or a longer exec
  wall-clock; a killed or timed-out run maps no verdict"), so a killed or
  timed-out run renders a next action instead of a bare inconclusive. The
  same floors-first ordering keeps a rule name containing `: ` from
  sneaking past into `unmapped` advice. MapRun's `timeout after %ds` stays
  for halmos/forge-fuzz — its summary is never the inconclusive wrapper,
  so the kind guard rejects it.
- **`proof` required-array** (`f33294b9`): the ten mapper keys are mandatory
  in `protocol_model.schema.json`; value types stay verbatim.
- **Corpus-resync precedent (binding).** Editing a proposer system prompt is
  not a one-file change: every embedded copy must be resynced in the same
  commit. In the golden fixtures that is **8 occurrences across 5 files** —
  `scripts/golden/p4/sft/` (`examples.json` ×4, `lint-pass.json` ×1,
  `lint-dedup.json` ×1, `lint-reject.json` ×1) and
  `scripts/golden/sft-example.json` ×1 (the runbook-walkthrough sample SFT
  store) — plus the committed `sft/examples.json` seed corpus ×2 and its
  byte-identical taxonomy mirror
  (`internal/taxonomy/testdata/seed/examples.json`) ×2. The `internal/sft`
  lint byte-identity law (`internal/sft/lint.go`) is the tripwire: `golden.sh`
  catches the `p4/sft/*` copies (step 175 `sft-lint-pass`) and
  `scripts/runbook-walkthrough.sh` catches `sft-example.json` (`§cheat
  sft-lint` / `sft-add` / `sft-list`), so **both** gates must be run after a
  prompt edit — Task 3 ran only golden and the walkthrough went RED at
  close-out; the missed 8th copy was resynced here with the same method.
  Resync mechanically (escaped-text substitution, occurrence-count + round
  trip + structural proofs; note `scripts/golden/sft-example.json` is
  `ensure_ascii=True`, the `p4/sft/*` set is not); `scripts/golden/p4/build.py`
  cannot regenerate the fixtures (retired Python twin) and must not be used to.
- **Explicitly not built**: the `model_gaps` reason tally (the audit line is
  the gap surface), automatic escalation exec spawning (operator/model `exec`
  by design), and L3's two open sub-parts — reason histograms as planner
  memory, and the `sequence_poc` witness bridge (deferred to the system
  wave).

**Wave L-system — LANDED 2026-09-12 (SDD, plan
`2026-09-12-wave-l-system-sweep-calibration.md`; commits `31e4bea1..HEAD`).**
The system half of `docs/MINICERTORA_ARCHITECTURE.md` (§L1–§L6). Docs, data and
one instrument: **zero new event types, zero new verbs, no new `verify` flags**
(template and invariant modes are statement syntax), and no golden campaign byte
moved. Landing notes in §9 of that doc.
- **L6a vendored corpus tripwires** (`31e4bea1`): eight upstream targets
  (`wrap-unchecked`, `rounding-drain`, `reentrancy-double-payout`,
  `access-control-mint`, `privilege-escalation`, `tx-origin-auth`,
  `invariant-cap`, `packed-storage-rejected`) committed verbatim at upstream
  `5a35567d` with per-file sha256 provenance in `VENDOR.json`; `corpus_test.go`
  checks self-consistency only (recorded sha == bytes, schema/enum conformance)
  and never runs the tool; the closed reason set is now exported as data
  (`dispositionOf` + `harness.IsReasonCode`) as the one source the tripwires and
  the disposition table share.
- **L5 four archetype templates** (`c574605b`): statements
  `template:<name> of <Contract>.<Function>` seed the BODY window from
  `internal/harness/templates/*.tmpl` behind an explicit allowlist; the seeds
  are STARTING CONTENT, never evidence (scorecard and gates must not credit
  them); three of the four bodies are distinct (`tx-origin-auth` ≡
  `access-control-mint` upstream — disclosed), and `rounding-drain` ships the
  corpus's own refusal shape.
- **L4 witness bridge + poc rendering** (`a89909df`, `5e27bf66`):
  `harness.BridgeSequence` maps a counterexample's `calls[]` to a
  `sequence_poc`-shaped candidate (actors aliased from `env["msg.sender"]` by
  first appearance, `reverted` → `expect_revert`, `mine_blocks` never emitted;
  refusals `no calls to bridge` / `unbridgable step: <why>` / `symbolic senders
  cannot be fork-repro'd`), and the audit line carries
  ` | poc: <n> calls bridged`, live end to end from stored state.
- **L1 + L2 invariant form and the 12-key sidecar** (`af516726`,
  RULING-12KEY): `invariant:<slug> of <Contract>.<State> <op> <expr>` renders
  the induction scaffold (declaration `invariant inv_<n>()`, reviewed assert
  scaffold-owned OUTSIDE the BODY window — the grammar has no `foralls`/`init`
  clauses, disclosed), and `proof` is 12 keys with `required[]` = the same 12;
  `invariant` rides verbatim as an object, `calls` verbatim as an array (`[]` is
  a value). The tool's real `per_function` is an ARRAY of dicts
  (`cli.py::_invariant_report`); the vendored `expected.json` condensed objects
  are curated summaries, not tool output.
- **L6b scorecard instrument** (`35215e86`, fix `92de6d70`):
  `scripts/minicertora-scorecard.py` grades the prover over
  `assets/evalsuite/cases.json` from raw tool lines (three-tier join rule →
  contract → results-file stem, one key per line, never a blend; duplicate
  `tie_key` or unknown `case_id` are hard errors) with a byte-pinned fixture
  self-test. **Acceptance law: no minicertora rung moves any gate until an
  operator has run this scorecard on the REAL evalsuite with the REAL tool** —
  that run is operator-side (it needs the binary) and is not a gate of this
  wave; the self-test proves the instrument only.

**Wave L-system — DEFERRALS queue (named, not forgotten).** *Wave L-defer
(`8b89f96d..35b5dbb9`, 2026-09-12) closed 1–4; 5–7 stand, each with its reason.*
1. **CLOSED** (`8b89f96d`, fix round `66395b50`): `harness.Validate` now runs on
   the `verify --harness-result` rail — inside the hash-bound branch first, then
   (fix round) on the unbound arm too — so a filled artifact whose
   outside-the-BODY-window bytes no longer match the CURRENT claim is refused as
   `scaffold-degraded: <reason>` (rung inconclusive, no `proof` key, exit 0).
   Failure order is the documented one: hash-bind first (WHICH bytes ran), then
   Validate (those bytes vs the current claim); in-window edits still map
   normally. Still open from the T1/T1-fix reports, none of them the deferral
   itself: the exec-terminalize / pre-commit artifact hook (Validate rides only
   the `--harness-result` rail), `scaffoldDegradedReason` stores only the short
   reason class, and the unbound arm cannot tell whether the run used the file
   at all (the exec side records no harness-file hashes).
2. **CLOSED** (`20c5a8d7`): the library is at **seven** template names
   (`wrap-unchecked`, `rounding-drain`, `access-control-mint`, `tx-origin-auth`,
   `privilege-escalation`, `unchecked-callback`, `value-transfer-accounting`),
   the three new bodies adapted from the vendored corpus specs;
   `tx-origin-auth` ≡ `access-control-mint`, so seven names carry six distinct
   bodies. `donation-accounting` and `cap-respected` stay out with their reasons
   written down (no corpus ground-truth spec; an `invariant:` scaffold, not a
   rule body) — the RUNBOOK sentence names all seven plus those two
   dispositions. T2 also disclosed a premise repair (two more corpus targets
   vendored to back the new bodies; corpus census eight→ten).
3. **CLOSED, both halves** (`01e91ed9` value; `c8e2a299` `final_assertions` via
   layout map): sequence_poc steps carry an OPTIONAL `value` (wei literal —
   schema pattern, bridge refusal for anything unparseable, driver threads it
   into the call), and `BridgeSequenceWithLayout` translates concrete final
   storage into `final_assertions` through an explicit `<Contract>.<var>` → slot
   map, with absent-name/symbolic values SKIPPED rather than guessed (the `n of
   m` honesty line lives in the docstring). `BridgeSequence` keeps today's
   behavior byte-for-byte (empty array; nil layout).
4. **CLOSED** (`35c7e56a`, plus the wave's closing nit `f60a5601`): the audit
   renders ONE derived line — `prover refusals (minicertora): <n> —
   <class>:<count>…; top reasons: <code>×<n>` — walking the campaign's stored
   harness records via `proof.reason`, falling back to
   `harness.Disposition(summary)`, presence-gated so a halmos-only or
   no-refusal campaign emits nothing. (`f60a5601` is the tail nit on the T3
   value pattern — an uppercase `0X` prefix is refused, never silently parsed.)
5. **OPEN — template runtime-state-identifier surfacing** (T2 M-1/M-2): the
   bodies bake state identifiers (`role`, `nominated`, `balanceOf`, `total`)
   that surface only at run time as a loader/unknown-symbol refusal, and an
   uppercase/near-miss template name still falls through to the plain skeleton
   (RUNBOOK clause + byte-pin; no CLI warning). **Now evidence-backed:** the
   first real evalsuite run checked the other half — none of those four names is
   a state variable in ANY of the 19 evalsuite contracts (`total` occurs once, in
   a comment), so a seeded body meets its match in the wild as a name the
   contract does not own — see the L-eval record below.
6. **OPEN — scorecard tier-2 defensive path**: joining on a `contract` with no
   `rule` is exercised by construction only (the real run joined through
   `--class-map`, so tier 2 is still unexercised), and the T5 N3 nit (an
   unreachable check in `audit_lines`' ABORT branch) is still carried.
7. **CLOSED** (`96d7e282`, wave M T3): `verify` now writes the runnable bridged
   PoC `artifacts/harness/<INV>/poc-<INV>.json` — a `sequence_poc` a real
   `webv2 sequence run <C> <path> --finding <INV>` consumes — plus the optional
   operator `layout.json` sidecar that grounds its `final_storage` (the solc
   layout map the harness does not own stays the operator's). The bridge is no
   longer consumed by its tests only; what remains is the fork RUN itself (RPC)
   and the layout map's correctness — see the wave M record below.

**Wave L-eval (operator) — first real evalsuite scorecard run, LANDED
2026-09-12** (`35b5dbb9`; raw data `docs/minicertora-eval/2026-09-12/`).
The operator half of the §L6b acceptance law was finally exercised: 19
evalsuite cases across 15 classes, scored by `scripts/minicertora-scorecard.py`
with an operator-written `--class-map` and hand-authored claims. **detected 2**
(`authorization` ES02GovernanceOwnable/`setowner_keeps_owner` and `flash-loan`
ES13FlashLoanSpot/`flashloan_free`, both `assertion-violated`), **refused 7**
(5 `rejected-feature`: the string-literal aborts plus the `unsupported-type` and
`packed-storage` loader rejections; 2 `unsupported-feature`: the `donation` and
`share-price-inflation` rules that have no call at all), **proven_silence 0** —
including the clean control (ES17CleanControl/`deposit_never_wraps` PROVEN),
where the operator's own reading is that the authored claim (`total`
monotonically non-decreasing) is simply TRUE for that donation sink, so the
PROVEN is an honest negative about the CLAIM and not prover power. The other 10
cases scored nothing: 7 tied no tool line at all (reentrancy ×3,
cross-chain-replay, signature-replay, liquidation-logic, unchecked-external-call
ES19), one tied a `solver-timeout` (escalate-solver — deliberately not a refusal
class), one tied a `malformed-spec` (spec-rewrite), and the clean control's
PROVEN is by construction not a count. Three tool-capability findings are now
facts of record: **(a)** mapping reads (`st[key]`) parse ONLY in call-argument
position — in a `require`/`assert` lvalue they are `malformed-spec` (7
first-round rejections); **(b)** a Solidity string literal anywhere in the
contract (`require(x, "msg")`) makes the tool abort rule-lessly as
`rejected-feature: string literal in an expression is out of scope` (a rule-less
envelope, so it joins by file stem and lands in the unmapped-by-rule bucket);
**(c)** `with { msg.value = x; }` overrides work (corpus-pinned) while a bare
payable call binds zero value. **The operator-gate law STILL stands, unchanged:**
one 12-case local run with hand-written claims is data, not acceptance — no
minicertora rung moves any gate until a backtest verdict exists per G3. What
this run buys is a measured reach profile (2 detections, 7 refusals, 10 silent
cases) and a verified tool vocabulary, not a gate verdict; the instrument
itself (`--self-test`) is unchanged and still the only thing the wave gates on.

**Wave M — LANDED 2026-09-12** (SDD, plan
`docs/superpowers/plans/2026-09-12-wave-m-fork-consumption-run2.md`; commits
`65036078..814a2021`, one fresh subagent per task, every rung verified on the
committed tree). **Fork consumption is LIVE end-to-end minus the RPC**, and the
minicertora eval has a second real sweep.

- **T1 `65036078` — bridged actor keys are run-path legal.** The bridge spells
  aliases `actor_N` (was `actor-N`). A role key becomes the shell variable
  `A_<role>` and the env var `FORK_KEY_<ROLE>`, and the run path admits only
  `[A-Za-z][A-Za-z0-9_]*` (`sequencepoc.roleKeyRe`; `driver.go::actorFragments`),
  so every hyphenated bridged document was refused by `LoadSequenceSpec` **and**
  `BuildCommand` for a reason unrelated to what it said. §L4's refusal pin
  (`c8e2a299`) is inverted into the POSITIVE round-trip pin
  `TestBridgedActorAliasesAreRunPathLegal` (two senders; the document written to
  disk exactly as bridged; loaded actor keys byte-compared to the bridged ones;
  `FORK_KEY_ACTOR_1/2` asserted in the driver text), while the hyphen-refusal
  *rule* stays covered by a hand-written illegal spec. A bridged PoC is now legal
  **as emitted** — no rename sits between bridge and loader.
- **T2 `0a9dbfee` — scorecard specificity + tie-collision law.** New seventh
  column `clean_agreed`: a clean control (gold in `CLEAN_OUTCOMES`) whose every
  tied line is PROVEN — the exact mirror of `proven_silence`, and the two can
  never both be 1 for one case. The tie-collision law drops a rule-bearing line
  whose rule and results-file stem tie DISJOINT cases, naming both on stderr
  before any count sees it. Live on run 1 it moved `access-control` to
  `2/0/0/1/1` (the ES17 control) and closed the run's "1 honest unjoin".
  **The T2 reviewer's condition — rescore the run-1 record with the 7-column
  instrument and retract the inverted gold note — is discharged by `814a2021`**:
  run-1 `scorecard.{tsv,json}` regenerated 7-column (`12 tied, 0 unjoined`) and
  `claim-sources.md`'s "gold-label drift" paragraph retracted (no drift existed —
  ES17 IS `confirmed-not-exploitable`; the drift was in the reading).
  **Correction at close-out (verified, not assumed): the collision law did NOT
  fire live in run 2 either.** The run-2 class-map comment claimed LegacyVaultT's
  `withdraw_decreases_balance` line was excluded (rule → ES03, stem → ES18), but
  the committed map carries no `LegacyVaultT` key, so the stem ties nothing, the
  law takes its documented silent branch, and both lines joined ES03
  (`external-call-abstraction=2` for one case) while ES18 scored nothing. The
  committed `scorecard.{tsv,json}` reproduce exactly, with no exclusion line on
  stderr; the wrong prose is corrected in place. Its **first live firing is still
  pending** — deferral (d).
- **T3 `96d7e282` — `verify` emits the runnable PoC artifact + layout sidecar.**
  A mapped minicertora `counterexample` writes
  `artifacts/harness/<INV>/poc-<INV>.json` through the SAME path/write/commit
  seam `verify --scaffold` uses (no parallel bespoke writer), presence-gated (no
  `calls` → nothing written, stderr names why), overwrite-deterministic (changed
  witness refreshes the file; identical bytes are a no-op). The emitted bytes
  validate against the real `sequence_poc` schema and pass `LoadSequenceSpec` +
  `BuildCommand`, i.e. a real `sequence run` consumes them — the T3 review built
  the actual argv from the emitted file. The operator sidecar
  `artifacts/harness/<INV>/layout.json` grounds `final_storage` (malformed shape
  → stderr note + layoutless bytes; well-shaped but grounding nothing → silently
  a layoutless PoC). Queue item 7 and §L4's "consumed by its tests only" are
  closed by this commit.
- **T4 `814a2021` — second real evalsuite sweep** (raw data
  `docs/minicertora-eval/2026-09-12-run2/`). 19 cases / 15 classes, 9 tool lines,
  9 tied / 0 unjoined: **detected 1** (`share-price-inflation` — ES06's REAL
  contract violates the pro-rata inequality, witness present; the class run 1
  could only refuse), **proven_silence 1** (ES14's semantics-preserving twin
  PROVEN on a gold-bad row — honest: the real bug is spot-vs-TWAP and out of the
  model's reach), **refused 3 cases / 5 lines** (`external-call-abstraction` ×3 —
  BankT, LegacyVaultT, LenderT: symbolic returndata copy bounds are not modelled;
  `unsupported-opcode` ×2 — ES09 keccak256 outside storage-slot paths),
  **clean_agreed 0** (no clean-control line authored this pass). Both codes were
  sighted in the wild for the first time and both were already rows of the closed
  25-code set (`internal/harness/disposition.go`): the vocabulary survived its
  first contact with production unchanged.

**Wave M deferrals** (recorded, none blocking): **(a) `finding_id` binding** —
T3's PoC carries the invariant id as `finding_id` (the harness-result path has no
finding in scope), so `sequence run --finding F-x` is refused loudly rather than
mis-attributed; the real binding lands when a fork campaign needs it (**T3-M2,
ACCEPTED as-is**). **(b) audit-suffix-vs-file gap** — `| poc: N calls bridged`
renders from `proof.calls` even when the bridge refuses, so a counterexample with
calls but no artifact signals that gap only on stderr. **(c) stale-PoC history is
single-view** — one file per invariant; a second witness overwrites it
(`artifact.refreshed`) and the history lives only in the exec stdout the bridge
read. **(d) third run, then any gate move** — a run that surfaces the template
state identifiers plus a **G3 backtest** verdict are prerequisites before ANY
minicertora rung moves a gate (the operator-gate law is unchanged), and the run-3
class-map must bind the twin stems (e.g. `LegacyVaultT → ES18`) for the collision
law to fire live.

*Rename note: parked as **Wave K** (items J1–J4 → K1–K4) because Wave J's own
letters were spent by the close-out wave that shipped first. The rename is the
only edit to this section's content: nothing below was rewritten, re-scoped or
re-argued, and the only characters that moved are the item ids and the wave
letter in cross-references.* Anchors are pointers to be re-located at landing
time (same convention as above).

**Sources.** (1) The Certora-architecture review (compiler → bytecode →
TAC → static analysis → VC gen → SMT → counterexample) and the build-vs-wrap
decision recorded before this wave: integrate provers, don't become one.
(2) G8 as-landed (`internal/harness`: `halmos` + `forge-fuzz` BODY-region
scaffolds, `counterexample / PROVEN-BOUNDED(k) / inconclusive` rungs).
(3) Paid APIs out — every backend below is local, pinnable, no cloud, no key.

**Decision (locked).** No new verifier is built in this wave. Each item adds
one free backend behind the existing G8 seam: same invariant in, same
BODY-law scaffold out, same EXEC record + outcome mapping, same
presence-gated rendering. A backend earns acceptance weight only via the G3
backtest law (`improves` on held-out adjudicated rows) — until then its rung
renders and informs the critic, never moves a gate.

**Consistency with the principles:** no new verbs anywhere (flags on `exec` /
`verify` / `invariant-verify`, adapters, data, schemas); deterministic where
judgment-free (principle 4 — pinned toolchains, fixed seeds, recorded
timeouts); additive presence-gated fields so existing campaigns' bytes don't
move (principle 1); fail-open advisories, fail-closed gates (principle 2);
surface budget holds (principle 6).

| item | one-liner | effort | gate-for |
|---|---|---|---|
| K1 | `solc` SMTChecker backend (zero new deps — the compiler you pin becomes a prover) | S | — |
| K2 | Medusa backend (Go-native coverage-guided PBT, Foundry-compatible) | M | — |
| K3 | Kontrol backend (open, self-hosted KEVM — the unbounded prover without the cloud bill) | M–L | K4 |
| K4 | Scribble / CVL-subset spec surface, lowered to all backends | M | K1–K3 |

## K1. `solc` SMTChecker backend

**Motivation.** The cheapest soundness you don't have. `WEBV2_SOLC_DIR`
already pins the compiler; `solc --model-checker-engine chc/bmc` turns the
`assert`s you extract as `documented_invariants` into proofs or
bytecode-level counterexamples with no new binary to pin.

**Design.**
- Scaffold kinds += `smt-bmc` / `smt-chc`: same invariant in, same BODY-law
  (model writes predicate BODY only; `Validate` re-renders and rejects
  outside-window moves — `internal/harness` pattern verbatim).
- Sandbox: host profiles `smt-bmc` / `smt-chc` beside `halmos` /
  `forge-fuzz` (`internal/sandbox/profiles.go`, exec allowlist, `--version`
  first-line probe, fail-open omit when absent); every run is an EXEC record
  with pinned `solc` version + engine + timeout.
- Outcome mapping (existing vocabulary — extend, don't renumber):
  counterexample → EXEC + evidence promotion through the normal ladder;
  engine `SAFE` → `PROVEN-BOUNDED(k)` with `k` = unroll bound in the record
  (never a bare "proven"); timeout/OOM → `inconclusive`.
- No new verbs: `--backend smt-bmc|smt-chc` flag on the existing
  generation / `exec` / `verify` path.
**Anchors:** `internal/harness/`, `internal/sandbox/` (profiles, exec,
probes), `internal/invariants/`, `internal/findings/levels.go` (rung
vocabulary). **Tests:** scaffold byte-pins; BMC counterexample fixture;
CHC `SAFE` → bounded rung with bound recorded; timeout → inconclusive;
absent-binary omit; byte check without proofs.

## K2. Medusa backend

**Motivation.** Echidna's successor, Go-native, GPLv3, coverage-guided,
property-based, Foundry-compatible — the fuzzer that embeds cleanly in a Go
binary instead of dragging Haskell behind it. Complements `forge fuzz`
(different scheduler, parallel workers, perverse-state exploration) rather
than replacing it; differing FP profiles are corroboration signal for G1.

**Design.**
- Scaffold kind += `medusa`: Foundry-property skeleton with BODY region
  (same law); pinned binary hash + fixed `--seed` recorded on every EXEC
  (deterministic corpus; same seed → same run, timeouts → `inconclusive`).
- Sandbox host profile `medusa` (allowlist + version probe + network `none`
  + readonly fs, G8 pattern); corpus + coverage stored under `execs/`.
- Outcome mapping: crash / property-break → EXEC + ladder promotion;
  clean run → coverage evidence only (never a proof claim — fuzzing finds,
  it doesn't prove); corpus minimized with seed pin before storing.
- Flags only: `--backend medusa` on generation / exec; no new verb.
**Anchors:** `internal/harness/`, `internal/sandbox/`,
`internal/reproduction/`, `internal/datasets/slither`-style provenance
(`provenance.tool = {name: medusa, version, seed}`). **Tests:** scaffold
pins; seeded determinism (same seed, same verdict); counterexample fixture
end-to-end to evidence; absent-binary omit; byte check without runs.

## K3. Kontrol backend (self-hosted KEVM, no cloud)

**Motivation.** The unbounded prover without the Certora bill: Kontrol +
KEVM are Apache-2.0, open, self-hosted — Foundry tests as specs, proved for
all inputs instead of fuzzed for some. Reserved for high-value math kernels
and auth matrices where SMTChecker/Halmos return `inconclusive`.

**Design.**
- Scaffold kind += `kontrol`: symbolic Foundry test (`vm.symbolic` inputs)
  with BODY region (same law); the human bounds loops/storage, the model
  drafts the BODY — bounds are scaffold-owned data, reviewed, never
  model-freeform.
- Sandbox: pinned Nix-closure hash recorded on the EXEC (the whole K+LLVM+
  KEVM closure — "same inputs → same bytes" dies without it); generous
  timeout → `inconclusive` is the EXPECTED common case, rendered honestly
  (the symbolic-scalability warning is the budget mechanism's native
  language, G8 pattern).
- Outcome mapping: `QED` → `PROVEN-UNBOUNDED` (new rung label, extending not
  renumbering — it outranks `PROVEN-BOUNDED(k)` and must never merge with
  it); counterexample → EXEC + promotion; timeout/OOM → `inconclusive`.
  `PROVEN-UNBOUNDED` renders with prover version + timeout + bound
  assumptions, never bare.
- Flags only: `--backend kontrol`; no new verb. Heavy profiles never run by
  default — invoked per-finding, never as a sweep.
**Anchors:** `internal/harness/`, `internal/sandbox/` (Nix-closure pin +
version probe), `internal/findings/levels.go` (new rung),
`internal/report` (presence-gated render). **Tests:** scaffold pins;
`QED` → unbounded rung with versions recorded; counterexample path;
timeout → inconclusive; absent-toolchain omit; byte check without proofs.

## K4. Scribble / CVL-subset spec surface, lowered to all backends

**Motivation.** Three backends must not mean three spec languages. Scribble
(ConsenSys, Apache-2.0 — annotations as comments, instrumented into code,
consumed by Echidna/Medusa/forge/Harvey) is the low-friction surface; a
pinned CVL-subset (`rule` + `invariant` + `assert`, no `ghost`/`hook` in
v1) is the Certora-UX surface. One spec in, lowered to every backend —
the 80%-of-Certora-UX at 5%-of-cost thesis, made concrete.

**Design.**
- Spec kinds: `scribble` annotations (`#if_succeeds`, `#invariant`) and
  `cvl-subset` (`rule`/`invariant`/`assert` only — `ghost`/`hook`/
  summaries explicitly refused in v1 with a named error pointing at K3
  manual bounds instead). Model writes annotation BODY only; boundary
  layer validates; scaffold keeps model out of structure (G8 law verbatim).
- Lowering (deterministic, pure): scribble → instrumented source for
  forge-fuzz/medusa; assertion-set → Halmos/SMTChecker harnesses;
  rule bodies → Kontrol symbolic tests. Lowering failures are errors naming
  file+line, never silent skips.
- v1 refusals (locked): no `ghost`, no `hook`, no callee summaries — those
  are the soundness cliff; K3 covers bounds by hand until a later wave
  earns them with backtest data.
- Flags only: `--spec scribble|cvl-subset --backend <name>` on the existing
  generation path; results are ordinary EXEC/evidence records.
**Anchors:** `internal/harness/` (new spec kinds + lowering),
`internal/invariants/` (source of annotated statements),
`internal/sandbox/` (instrumented-build recipe). **Tests:** annotation
round-trip; CVL-subset accept/refuse matrix (`ghost` refused with named
error); lowering each way on fixtures; instrumented build compiles against
pinned solc; byte check without specs.

## Wave K — explicit non-goals (principle 6, recorded so they stay dead)

- Building a new verifier (TAC, alias analysis, VC gen, solver heuristics)
  — integrate provers, don't become one.
- Paid/cloud provers (Certora cloud or any keyed API) — local + pinnable
  only; verdicts import as data (G1-adapter pattern), never as live gate
  dependencies.
- `ghost`/`hook`/summaries in v1, consensus/p2p fuzzing, training our own
  detector — same dead list as Wave G, restated so K4 is not re-litigated.

## Wave K — landing order & dependencies

1. **K1 first** (zero new deps; proves the backend seam on the toolchain
   you already pin) → **K4-spec-minimal** (scribble annotations feeding
   the backends you already have: halmos/forge-fuzz/K1 — earns its keep
   before new binaries arrive).
2. **K2** (Medusa binary + seeded determinism) → **K3** (Kontrol closure
   pin + unbounded rung).
3. **K4-full** (CVL-subset accept/refuse + lowering to K1–K3) last — the
   surface graduates only after every backend it lowers to exists.
4. Backtest graduation (G3 law) happens per-backend after landing, never
   inside the landing commit: rungs render and inform the critic first,
   move gates only on `improves`.

**Divergence posture:** every backend ships behind a presence-gate (no
scaffold of that kind → no bytes) and every rung behind a policy
default-off for gate weight; expected golden byte movers: none (new
scaffold kinds, new rung labels, and new sandbox profiles are all
unreachable in existing fixtures — verified per-item with the byte check).

---

# Wave J — definitive close-out (2026-09-11)

**Premise.** Wave J was scoped as the *last* implementation round: close every
open review item, delete every test that was skipping instead of checking,
repair every doc that had drifted from the code, add the two operator-visible
measurements the eval surface still lacked, then gate once — including `-race`
and the determinism double-run, neither of which any wave had run since
2026-09-10 — and merge. Nothing in it was exploratory. Plan of record:
`docs/superpowers/plans/2026-09-11-wave-j.md`; base `f4b6c66` (Wave I merge);
wave head `c4fc214`; 21 commits, 135 files, +3506/−813 — plus this close-out
commit on top of it.

| task | what shipped | commit(s) |
|---|---|---|
| J1 docs | stale-prose correction: header + Wave E status now say what actually landed | `c5fadfd` |
| J2 perclass | per-class recall/precision block in `## eval` (`internal/evalscore/classes.go`) | `059d8e0` |
| J3 diversity | ES18/ES19 pre-0.8.24 fixtures — suite 17 → **19** rows, no single-compiler monoculture | `422d04a` |
| J4 backlog | all fifteen H items — H1–H15 | `edf9aaf` `502a0da` `00d280a` `4ca4c2c` `fa9bb27` `3dcea47` `2d6a051` `c054884` `0c4cc57` `1215f86` |
| J5 lies | two skip-lies deleted and their gates wired; walkthrough rows; README drift | `8bbf6ee` `3f78475` |
| J6 ci | `.github/workflows/ci.yml` — the gate runs without this box | `c4fc214` |
| J7 truthy | `pyTruthy` consolidated: one canonical form, divergent variants named | `fcaee03` |
| J8 recovery | torn-log hand-recovery procedure + `probes --flag=value` parity | `50f2644` |
| J9 closeout | this section: Wave H closed, Wave K parked, CI-correctness pass, full gate | (close-out commit) |

## J1. Stale prose corrected — the doc told two lies

The Wave J header claimed E1/E2 were "deferred" and that D8 "awaits a
decision". Both were false when written: **G14** had already landed E1/E2
(`4edfd60`, `b8ed2c6`, `7230c42`) and **D8** had landed as `85b2e3d`. The fix
is prose-only (8 lines, no code). It is the reason this close-out section
exists at all: a landed item still described as pending is the same failure
mode as a skipped test that reports success.

## J2. Per-class recall/precision in `## eval`

The aggregate eval line was the only scoring the audit rendered, so a suite
that scored 19/19 could hide a class with zero recall. `## eval` now carries a
per-class block between the aggregate and the acceptance-band table:

```
  - access-control: recall 1/1 (95% CI 20.7–100.0%), precision 1/2 (95% CI 9.5–90.5%)
  - oracle-manipulation: recall 0/0 (95% CI n/a), precision 0/1 (95% CI 0.0–79.3%)
```

Two readings are locked in, both deliberate:

- **A class with no applicable case renders `0/0 (95% CI n/a)`** rather than
  being suppressed. A suppressed row and a perfect row are indistinguishable in
  a table; `n/a` is not.
- **The block header says the cells are small**: `per-class cells are small —
  read the intervals, not the ratios`. A `1/1` is a 20.7–100.0% interval, not a
  certainty, and the render says so where the operator reads it.

## J3. Suite compiler diversity — 17 → 19 rows

The source report asked for "contracts compiled with different, non-default
compiler versions". Every one of the 17 fixtures carried `pragma solidity
^0.8.24` (ES07's 0.8.19 note is a comment; it still compiles 0.8.24), so the
suite's `17/17` was a single-compiler measurement wearing a general claim.
Two fixtures with older pragmas (ES18/ES19) were added, both tool-flaggable.
The suite self-score literal was re-derived rather than assumed: **19/19
(95% CI 83.2–100.0%)**. The `17` count was stale in exactly two
operator-facing places — `assets/runbook/RUNBOOK.md` (§Wave G tranche 2) and
the G4 row above — and this close-out fixed both; the runbook line now also
names the older pragmas, so the reason for the growth travels with the number.
Historical plan files (`2026-09-11-wave-i.md`, `2026-09-11-wave-g-tranche-2.md`,
and this wave's own plan, where `17` is a *pre-task* statement) keep their
`17`s: they record what was true when they were written, and rewriting them
would destroy the audit trail this methodology is built on.

## J4. The Wave H backlog, closed

All fifteen H items landed. Where an item's real scope differed from the plan's
one-liner, the difference is recorded rather than quietly absorbed:

- **H11 scope widened.** The plan named the immunefi `sha12Hex` twin; the
  sweep found the same private function in `sherlock` and `c4audit` too —
  **four** copies, all four now `validation.Sha12Hex` with a pin test.
- **H12 scope narrowed → H16.** The item named `internal/evalscore/…` and the
  eval-section test; those are fixed. The idiom also survives in
  `internal/report/sweep_t35_unprice_test.go:80` and
  `internal/cli/sweep_t35_unprice_test.go:36`, which the item did not name.
  Rather than widen H12 past its own scope mid-commit, the remainder is filed
  as **H16** (see the Wave H table above).
- **H13 is a decision, not a migration.** `class_weights.schema.json` accepts
  int `1` and float `1.0` alike. The fixture audit that settled it: 46 float
  weights, 23 `source_url`s, **zero** `"null"` strings. Recorded in the
  schema description; no data touched.
- **H14 is recorded, not changed.** The `_witness` storage var is
  contract-visible in halmos symbolic context. Harmless for dummy scaffolds;
  the hold and its revisit condition are stated at `WitnessVar`.
- **H5 is the largest single item** and got its own commit: an additive,
  optional `affected[].citations` object (`mitigation_present`, `component`,
  `^[0-9a-f]{12,64}$`, `additionalProperties: false`) so a citation is
  machine-checkable instead of buried in a JSON string. Every pre-existing
  stringly channel stayed byte-identical — `dedup_meta.mitigation_present` is
  still `type: string` — which is what made the migration safe to land in the
  same wave as everything else.
- **Falsifiability was proved, not asserted.** Each new gate was verified by
  breaking it: remove ES16's ack → H6 test fails; add an ack to ES17 → fails;
  revert `ln`→`text` → H9 test fails; add a seventh axis to the shared table →
  H8 rot gate fails. All mutations reverted; `assets/evalsuite/` byte-clean
  afterwards.

## J5. Two skip-lies deleted, five walkthrough rows added

A skipped test that reports `ok` is worse than no test: it converts an
unchecked surface into an apparent check. The skip audit found two, and both
were **deleted, not converted** — with the reasoning recorded in the commit
rather than left implicit:

- **`WEBV2_PARITY_PROBE`** (`internal/orchestrator/parity_probe_test.go`) was
  inert without an env var whose only un-skip was an untracked, gitignored
  `.scratch/` driver whose other half is the **retired** Python twin. Nothing
  to replace: the golden suite plus the committed legacy cross-audit cover the
  same ground against committed fixtures.
- **`requireClones` / `WEBV2_POC_ROOT`** (`internal/datasets/defihacklabs`)
  was 4× SKIP on this box because `data/datasets/` is neither present nor
  tracked (`git ls-files data` is empty). Converting would have meant
  vendoring 930 third-party records and >700 PoCs; everything those tests
  exercised is already exercised against the synthetic `sampleTree` in the
  same file.

Five new runbook-walkthrough rows then covered the four new flags that had
never been executed by any gate (backtest baselines, tool baselines,
`ingest --from aderyn`, `model --facts`), plus `publish --disclosure`. They
are section-anchored, not line-anchored, so the rows survive edits above them.
The binary-gated row prints `[SKIP]` when slither/aderyn are absent — an
honest skip, named in the output, not a silent pass.

## J6. CI — the gate now runs without this box

`.github/workflows/ci.yml` (first workflow in the repo): ubuntu-latest, Go
1.26.x, then `go build ./...`, `go vet ./...`, `go test ./... -count=1`,
`bash scripts/golden.sh`.

Deliberately excluded, and the exclusions are the interesting part: `-race`,
the docker e2e tiers, and tool installation. The 13-step gate of record stays
`scripts/verify-full.sh` on a workstation. What made this safe is a property
worth stating: `golden.sh` pins its caches to repo-relative `.scratch/` paths
and neither script contains a box-specific absolute path, so the recipe was
reproduced on a fresh clone under `env -i` with a **read-only HOME** —
build/vet/test/golden all exit 0. The gated suites (`forge`, `slither`,
`aderyn`, the defihacklabs clones) SKIP rather than FAIL with an empty
`PATH`, which is exactly what makes a minimal CI honest instead of red.

## J7. `pyTruthy` — one canonical form, the rest named

The predecessor's truthiness predicate existed as **twenty** copy-pasted local
`pyTruthy` definitions (identical signature, an assortment of equivalent
spellings — IntText, merged case, fall-through, operator-precedence). The
commit deleted all twenty and left **one** canonical `validation.PyTruthy`
("canonical format v1", its contract in the doc comment rather than "matches
CPython" prose), now called from **72 sites across 22 files**. The three
genuinely different truth functions were *not* folded in; they keep their own
names and their file-local definitions:

| variant | local defs | what makes it different |
|---|---|---|
| `pyTruthyBigNonEmpty` | 6 | any non-empty `Big` is truthy — even `Big == "0"` |
| `pyTruthyInt64Only` | 2 | `Int` reads only `I`; a big integer reads **false** |
| `pyTruthyLenientContainers` | 1 | empty arrays/objects read **truthy** |

`pyTruthyCLI` (one local def) was surveyed and pinned but left out of scope.
Seventeen new pin-test functions in seventeen new files freeze every
definition's pre-consolidation truthiness, so the refactor is provably
behaviour-preserving rather than merely plausible. 72 files, +987/−423.

## J8. Torn-log recovery, by hand — and no repair verb

A torn session log was a dead end: the framing guard refuses, `verify` reports
a line-numbered malformed-line problem, and read paths emit a terse `error:
EOF` with no next step. The runbook's §10 gained **"Torn log recovery (by
hand, no tool)"**: copy the torn log aside as evidence, truncate at the last
complete record, re-verify, record the loss.

The procedure was derived from real reproductions in `.scratch`, not from
reading the code, and that is what caught the case the plan had wrong: an
in-flight tear truncates to a clean `"ok": true`, but a tear that ate whole
records leaves the **state projection ahead of the log**, and verify then
keeps reporting "state event tail does not match the log suffix". Recovery
therefore needs a projection re-derive (rebuild the mirror, let `doctor`
re-serialize it through the CLI's own writer) *before* re-verify. The plan's
step 4 said "re-run verify" and would have looped forever on that input.

**No `verify` repair verb was added, deliberately.** Rewriting a hash-chained
log means the tool must state what the rewritten chain claims — and it cannot
know. A hand procedure that records the loss is honest; an automated silent
repair would not be.

Also in this task: `probes` value flags now route through the shared
`splitFlag` splitter the converted verbs use, so `--per-axis=2`, `--total=40`,
`--axis=L-01`, `--anchor-blind=K`, `--reason=R` and `--actor=A` parse exactly
like their space-separated forms — pinned byte-for-byte (stdout, stderr, exit
code) by `TestProbesFlagEqualsFormIsTheSpaceForm`.

## J9. The wave's premise corrections

Recorded because each one contradicts something the plan asserted:

1. **A concurrent writer existed.** Someone else added a +179-line "Free
   prover backends" proposal to this file while the wave was running. It was
   never one of Wave J's nine tasks. **User decision: adopt it as a parked
   follow-up — Wave K** (see the section above). Nothing below was rewritten,
   re-scoped or re-argued there; the only characters that moved are the item
   ids and the wave letter in cross-references. It is not a Wave J deliverable
   and nothing in it blocks the shipped tree.
2. **H11 was four copies, not one.** See J4.
3. **H12's real remainder was outside its named files.** Filed as H16.
4. **H13/H14 were decisions, not code changes.** Both items asked for a
   finding; both got one.
5. **The torn-log procedure had a missing step.** See J8.
6. **The suite count was stale in two places**, not the one the plan named.
   See J3.

## Wave J — CI-correctness pass (pre-merge, 2026-09-11)

Same method as Wave I, applied to the wave diff. Added lines of
`git diff f4b6c66..c4fc214` grepped for `(95% CI`; every literal
`<k>/<n> (95% CI lo–hi%)` recomputed against `wilson.Interval`/`wilson.Format`
semantics (`z = 1.959963984540054`, tenths of a percent, clipped to [0,1],
`math.Round`).

**29 added lines matched, carrying 39 literals across 6 distinct `(k,n)`
pairs** (27 of the lines are code/test literals — `internal/audit/sections/
eval_test.go`, `internal/evalscore/classes_test.go`, `internal/cli/
cmd_selftest_test.go`, `internal/audit/eval_gate_test.go` — and 2 are the
plan's own prose):

| k/n | literal | k/n | literal |
|---|---|---|---|
| 0/0 | `n/a` | 1/2 | `9.5–90.5%` |
| 0/1 | `0.0–79.3%` | 2/2 | `34.2–100.0%` |
| 1/1 | `20.7–100.0%` | 19/19 | `83.2–100.0%` |

**Zero mismatches.** The only literal new to this wave is `19/19
(95% CI 83.2–100.0%)`, introduced by J3's suite growth; it was re-derived from
the interval formula rather than copied from the prior 17/17 rendering. The
`0/0 (95% CI n/a)` form appears 10 times and is the honest degenerate
rendering, not a suppressed metric. The Wave G4 erratum is not repeated: no
`2/2` literal anywhere in this wave reads `20–100%` (that interval belongs to
`2/3`).

## Wave J — declined with reasons (no open ask is a forgotten todo)

Every still-open ask that this wave did **not** implement, with the reason it
will not be. Nothing here is waiting on capacity; each is a decision.

| ask | decision |
|---|---|
| corpus score cap | **Declined** — the cap is the operator's number. A framework-chosen cap would silently change what a score means; the operator sets it or nobody does. |
| `structidx` ↔ `probes` shared authz vocabulary | **Declined** — it is a coverage-contract change, not a rename. Making two surfaces agree on vocabulary changes what each one promises to cover, which is a wave of its own. |
| E6 queue tie-break | **Deliberate, pinned** — the current ordering is deterministic and pinned by test; a "better" tie-break is a preference, not a defect. |
| C1 as `amend` | **Declined** — the store is append-only. `supersede` via G14 is the sanctioned spelling; re-opening C1 would add a second, weaker way to say the same thing. |
| C2 | **Declined** — low value. |
| C4 | **Recommended against** — it is a G-01-at-scale machine; the cost is in the running, not the building. |
| C5 / E3 | **Deferred** — needs an "explored" rule first; without one the axis cannot be scored, only asserted. |
| C7 / E4 | **Do-not-build** — a reporting knob with no consumer. |
| `verify` log-repair verb | **Declined** — the hand procedure ships instead (J8). See the reasoning there: a chained log cannot be rewritten by a tool that cannot state what the rewritten chain claims. |

With this table, Wave H is empty except H16, Wave K is explicitly parked, and
every remaining ask carries a reason instead of a promise.

# Wave M — the eval-notes slice (2026-09-11)

**Premise.** Source: `../morph/FRAMEWORK_EVAL_NOTES.md` — the operator's
write-up of the Morph L2 campaign (10 dislikes, 6 wishes) — plus the two gaps
that write-up surfaced in the *discovery* loop rather than in the plumbing.
Base: `b0f8a23` (Wave J close-out). Nothing here is exploratory: every item
either removes a documented dead end or makes an existing obligation
mechanical.

Evidence for the whole wave: `scripts/verify-full.sh` 13/13 (including
`-race` and the determinism double-run) and the 196-step golden. Row counts
quoted for probe work are from the Morph tree the campaign ran against (500
files, 8082 index entries, 14404 probe sites).

| task | what shipped |
|---|---|
| M1 scope | `webv2 scope --example` — the policy template is reachable from the binary (it had to be dug out of `scripts/golden/policy.json`) |
| M2 snap | `snap --dry-run`; the unbounded exclusion print is summarized; untracked working-tree files are named at pin time |
| M3 version | `--version` names the build commit; `snapshot.pinned` records `framework_build` so a later `brief` on a different binary can warn instead of silently trusting changed probe semantics |
| M4 ingest | `--trajectory` accepts the dispatch letters (A–H) prompt 39 teaches; the schema enum still takes full names |
| M5 prompts | `webv2 prompts {list,show}` — the embedded stage prompts are readable without a framework checkout |
| M6 brief | an untouched lens names its mechanical table (L-01/L-03/L-04) in `next_actions` |
| C3 probes | never-asserted-consumption rows: **measured on Morph and retired** behind `ProbeOpts.AbsenceRows`; the near-key collapse is kept, unconditionally |
| L4 polarity | Stage 38 requires both polarities of every lifecycle transition; Stage 39's H trajectory works both |
| L5 deployment | runbook §4c — the facts the code cannot answer (caps, slot maps, thresholds, post-deploy roles) |
| L6 proof | `verify-full` 13/13; golden green with `enforcement-timing` BLIND as declared |

## M1–M6. The DX batch

Six small holes, each one an operator paying for the same discovery twice.

- **M1 `scope --example`** (dislike 4). The policy schema demands six required
  keys and `scope --help` taught none of them; the only valid template in
  existence lived in the framework's own test fixtures, invisible from the
  installed binary. The emitter mirrors `ingest --example`: schema-valid JSON
  on stdout, legend on stderr, pipeable. The template's platform is `direct`
  so a copy-paste cannot be mistaken for program ground truth.
- **M2 `snap --dry-run`** (dislike 8 + the untracked-file trap). One
  `node_modules` line per entry drowned the four lines that mattered, and a
  pin silently swept untracked operator files into the snapshot. The dry run
  prints the ladder, the prune set (summarized: counts plus the top names) and
  every untracked file that a real pin would capture — and records nothing,
  which the snapshot tests pin.
- **M3 `--version` + `framework_build`** (DEFECT-2 follow-up). A campaign
  carries probe rows produced by the binary that ran them; when the operator
  later runs a different build, the rows' semantics may have changed with no
  trace in the record. `snapshot.pinned` now carries the build commit. Event
  data is free-form (audit checks the hash chain, never the data keys), so old
  campaigns without the key simply never warn — the grandfather rule.
- **M4 trajectory letters** (friction, unreported but reproduced). Prompt 39
  and the runbook teach trajectories as `A`–`H`; the schema enum wants
  `code`…`lifecycle`; `ingest --trajectory A` failed schema validation. Single
  letters normalize at parse time now. Junk still fails loudly, and `chain` /
  `model` (which have no letters) pass through untouched.
- **M5 `prompts {list,show}`**. The stage prompts shipped embedded in the
  binary but only reachable by running a model stage or reading the repo. The
  new verb prints the index, and accepts a full name, a stem or a stage number.
- **M6 brief lens routing** (wish: "brief next-actions still listed the waived
  diversity item"). The item was the symptom; the disease was that a lens
  could be "worked" against nothing. An untouched lens now names its
  mechanical table in `next_actions` (`enforce` for L-03, `symmetry` for L-04,
  the liveness rows for L-01), the routing line carries the verb the operator
  should run, and generic actions no longer stand in for it.

## C3. Never-asserted-consumption rows — measured, then retired

The reference `assertion-strength` probe asks "validated here (class 4),
consumed there (class ≤ 1)?" and is *silent* when nothing asserts the concept
at any class — the skip drops the key before a row or even a rejected-site
blind entry exists. That silence is exactly the G-01 shape (`prevStateRoot`
consumed at `commitBatch`, unchecked at every stage), so C3 filled it with an
absence rule: consume a concept while writing state, and nothing in the
closure asserts it.

Two forms were built and measured on the Morph tree:

| form | rows | what the emitted quota actually contained |
|---|---|---|
| ungated | 421 | constructors, `computeL2TokenAddress`-style pure address/hash math, `L2ERC1155GatewayTest._deployERC1155`, `msg:sender` — tier 0, `assertion_gap` 4, i.e. ranked above the rows carrying real defects |
| hand-off gate | 276 | the same families: a concept must be written to storage, read by a stage declared below the writer, and the consumer must not be `constructor` — and the top of the list is unchanged |

The row the campaign actually needed (`Rollup.commitBatch#204 … asserter
finalizeBatch`) is emitted by the **reference** probe once the custody enum
defect is fixed and the surface can be built at all. The enrichment bought
noise, not coverage.

**Retired**: `ProdProbeOpts` is `{StageTables, Symmetry}`; the code stays
behind `ProbeOpts.AbsenceRows`, tested, with the measurements in its header,
for an iteration that finds an obligation shape with a real differential. The
zero `ProbeOpts` value remains byte-identical to the reference surface, which
the parity goldens pin.

One piece was **kept, unconditionally**: `collapseNearKeys`, the OBS-1 fix
(near-duplicate near-key blind entries that attested the tokenizer rather than
the lens). It was built alongside C3 but is not part of it — the eval's OBS-1
finding stands on its own, so the collapse no longer depends on the flag.

## L4–L5. The two discovery-loop gaps

Neither is a CLI defect; both are cases where the framework knew a rule and
did not require it.

- **L4 polarity.** The campaign planned and answered the *permissive* arm of
  the batch lifecycle (a fake claimed root finalizing through the challenge
  game) and never asked the restrictive mirror — a root that is never accepted
  stopping the batch cursor and stranding every later withdrawal. Same three
  lines of code, different bug, different impact class. Stage 38 now carries a
  mandatory polarity matrix (one priority per arm, the restrictive question
  must name what gets *stuck*), Stage 39's H trajectory works both arms
  explicitly, and the runbook says checking the second arm is part of reading
  the plan. L-01 liveness is named as the restrictive arm's lens.
- **L5 deployment facts.** The snapshot proves *which code* is deployed; the
  bytecode hash says nothing about the *values* the instance holds. Caps
  (`Staking.MAX_STAKERS`), slot maps seeded at `initialize`, relayer quorum
  thresholds, oracle addresses and post-deploy role grants are all invisible
  to the index, to `enforce`, to `symmetry` and to every probe. Runbook §4c is
  the table of where each one lives and how to read it, with the rule: if
  exploitability turns on a number you did not read from the deployment, the
  hypothesis is an assumption — quote the read or record a coverage gap.

## L6. The proof

- `scripts/verify-full.sh` — **13/13 green** (vet, build, tests, `-race`,
  determinism double-run, asset manifest, golden, crash smoke, legacy
  cross-audit, P1/P2/P3 CLI smokes).
- `scripts/golden.sh` — **196 steps, 177 events, chain intact**, audit surface
  complete; step 105 reports six live axes with `enforcement-timing` BLIND on
  the golden target, which is the declared expectation after C3's retirement.
- `python3 scripts/sync-asset-manifest.py --check` — current (130 files,
  9 packs); the prompt and runbook edits in this wave ride that manifest.

**Declined with reasons** (so the next reader does not rebuild them):

| ask | decision |
|---|---|
| ship the absence rows behind a `--flag` | **Declined** — an operator flag that mints 276 noise rows is a footgun with a nicer name. Opt-in for tests, off in production. |
| a `polarity` field on `priorities[]` | **Not built** — the eval's gap was hypothesis generation, not record-keeping; a schema field no gate reads and no command sets is the "field no CLI can set" anti-pattern (dislike 2) pointed the other way. The prompt + runbook requirement is the honest home for it. |
| a gate requiring both polarities per lifecycle family | **Not built** — the divergence gate has no model access, so "which families does this priority touch" would be inferred from free text; and the framework's own bootstrap and `--emit` priorities would trip it. Text rules belong in prompts; gates belong where the data is structured. |

# Wave R — the recall wave, closed out (2026-09-12)

The operator post-mortem (implementation plan in commit `d7d270a`) became
eight tasks; all landed. What changed, in the shape a reviewer can check:

- **Sentinel-form rows** (`e76031c`): a zero-check guard (`stateRoot !=
  bytes32(0)` and its kin) cannot assert the truth of the value it guards —
  every non-zero value passes it. Such rows now carry `own_form="sentinel"`,
  the guard's own text, and an adversarial `why` prompt.
- **The `--passes` gate** (`1a433d3`): closing a sentinel-guarded row
  (`answered` / `not-applicable`) demands `--passes VALUE` — the concrete
  value that passes the check, recorded on the priority as its `passes`
  field. The escape hatch stays the dismissal override
  (`--override-dismissal --override-reason`), logged as
  `probe.dismissal_overridden` with actor and both reasons.
- **The discovery-slot reform** (`b95ec56`): bare HYPOTHESIS ingest is
  free; a finding's slot is charged exactly once, at its FIRST rise above
  the E0 baseline — an evidence item above E0 or the first promotion whose
  floor is above E0. The counter and its ceiling are the pre-reform ones;
  only the charge point moved, and `budget` now reports "findings risen so
  far".
- **The payout-funding question** (`84ee0ce`): funding-mismatch symmetry
  rows force the question the framework cannot answer from source — who
  funds the payout path, read from the deployment — instead of letting the
  row close on structure alone.
- **The diversity union** (`ddc9b61`): the plan diversity gate unions the
  campaign's own bug classes with the findings', and the builder stamps the
  canonical class onto each priority so the clause counts what the campaign
  actually names, not a free-text echo.
- **`plan --json`** (`ef795be`): the machine-readable plan carries the real
  work queue and priorities count instead of a stub.
- **CLI hygiene** (`43ff52b`, `9b2bfb6`, `b1cc5ff`): console row/path
  dumps cap at 40 entries with one `--json` pointer line; `register` prints
  its immutability notice; the default root resolves as
  `--root` > `$WEBV2_ROOT` > ancestor walk-up (≤ 5 levels, cwd included) >
  `.`. Targeted DUPLICATE + reopen (`653ff3d`, `c45359b`) and the sentinel
  override arm (`a6faf36`) round the wave out.

## Round 2–3 close-out: the never-inert falsifiability batch (2026-09-12)

Three adversarial review rounds graded the closure surface and named the gaps
to 9. The batch that closes them is one contract — **a flag the verb cannot
use is refused at exit 2 with the reason named, never silently dropped; a
closure that can be checked is checked** — applied everywhere the gates had
quiet edges. The items below are the review's must/major list, all landed;
each ships negative controls at the API and CLI layers.

### The closure gates (round 2: FIX-A/B/C, round 3: FIX-E)

- **Sentinel override arm needs its reason** (`a6faf36`). The
  `--override-dismissal` escape hatch on a sentinel-row closure refused the
  bare flag: it demands `--override-reason`, and the override lands as a
  logged `probe.dismissal_overridden` event, printed to the operator at the
  moment it happens. An override without a justification is no longer a
  syntax quirk of the flag parser — it is refused like any other unpriced
  closure.
- **The deferred-consequence vocabulary is a trigger, not a hint**
  (`2b421aeb`, FIX-A/round-2 chief item 1). The v1 trigger was the asserter
  anchor alone; a tier-0 closure whose REASON uses the failure-consequence
  vocabulary (`unfinalizable`, `stranded`, `frozen`, `revert-forever`, …)
  now demands the same pricing (`--finding F-<id>` or `--interim` citing the
  row's own surface entry) or the logged override — and the refusal names
  which trigger it is answering. The vocabulary lives in the rejection
  layer, where `webv2 deferred` (§5) sweeps it later, so the gate and the
  sweep cannot disagree about what counts.
- **The discovery exit fires on `IsLivenessFinding`** (`41c5c93a`, FIX-B).
  `proofDiscovery` gated the adversarial_game clause demand on
  `economic_impact.kind == "liveness"` alone, while the bounty gate's
  check15 fires on the shared predicate (`root_cause.class` in
  {`chain-freeze`, `sequencer-halt`, `liveness`}, or the recorded kind, or a
  granted liveness-terminal capability). A class-typed freeze with no
  `economic_impact` object used to exit discovery clause-less while the
  bounty gate still demanded the clause — one question, two disagreeing
  gates. Both now call `findings.IsLivenessFinding`; dead terminal
  dispositions stay exempt (`livenessOwedStatuses`).
- **The `--passes` plausibility floor** (`d7d980c9` 3a, `e542f709` FIX-E).
  The sentinel gate accepts a value only when it is checkable: it names a
  symbol from the row's own surface entry, or it is a concrete literal
  (decimal integer, hex number / Ethereum address `0x…`, `bytes32(0x…)`,
  boolean, quoted string) — junk (`TBD`, `zzz`, `n/a`, …) is refused naming
  both legal shapes, the ≥ 3-character floor stays, and the quoted-string
  arm no longer admits quoted junk (the shared junk lexicon excludes it
  whole-value, case-insensitive; an honest quoted literal that merely
  contains a junk word stays legal).
- **The floor is always on** (`e542f709` FIX-E, round-3 chief item 5).
  `checkPassesValue` backstops every route the sentinel gate stands down on:
  whenever `--passes` is supplied — any priority, any status — the value
  goes through the SAME `passesPlausible` floor, so the two paths cannot
  disagree. A sub-floor value is a refusal naming the floor, never
  `closePriority`'s silent drop.
- **Live-finding exits** (`2b421aeb` + `d7d980c9` 3b). `--finding` refuses a
  ghost id and a TERMINAL finding (DISPROVED, OUT_OF_SCOPE,
  INFORMATIONAL, DUPLICATE, SUPERSEDED — a dead record prices nothing about
  a window still open); the `--reconcile` finding exit refuses a terminal
  finding the same way, with its recorded status named. Verified as landed
  by the FIX-C round; the runbook states it.
- **Recon evidence is bound to the campaign** (`d7d980c9` 3c, `e542f709`
  FIX-E 3). `state.StampRecon` stamps `campaign_id` beside `src`/`at`; the
  L-04 gate refuses a prescreen whose `snapshot_id` is not the campaign's
  active pin, a sinks stamp naming another campaign (or none), and — when
  both verbs stamped their src — a sinks run over a different tree than the
  prescreen's. Pre-binding artifacts without the field stay accepted (their
  snapshot binding is their whole evidence); state files stay
  operator-writable — the gates stop laziness, not forgery.
- **An empty `--reconcile` is refused, not a wipe** (`d7d980c9` 3d). A blank
  spec parses to zero records, which would overwrite the stored
  reconciliation with "nothing to reconcile"; the parse layer refuses it and
  the record survives.

### The never-inert contract (round 3: FIX-D, `85659ad0`)

- **`answered` L-* routes**: `--finding`/`--interim`/`--passes`/`--anchor`
  were dropped silently on a lens closure while the help claimed validation
  on every closure. All four are refused before the recon gate, with the
  route and the drop named — a ghost `--finding` can no longer ride a lens
  closure.
- **`answered --reconcile` off-route**: a Q-* closure ignored the spec at
  exit 0, and a non-closing lens status ignored it AND dropped the stored
  reconciliation. Both refused, naming the only consuming route (the L-04
  primitive-symmetry closure); the stored record survives.
- **`deferred --json`** is ONE parseable document: the skipped list rides
  inside the object (`"skipped": [...]`) instead of human lines appended
  after the JSON — prose-after-JSON broke every parser exactly when skips
  existed.
- **`move --of` off-route** was silently dropped on any non-DUPLICATE move;
  it is refused at exit 2 before the campaign opens, naming DUPLICATE as the
  route that consumes the flag.

### The remaining two named items

- **`snap --dry-run --json`** (`bda634fd`): the machine view emits the FULL
  pruned-paths table the prose view shows, so a script can predict what a
  real pin would capture without parsing human lines.
- **The `--of` refusals themselves** (`653ff3d`, `c45359b`, reviewed
  2026-09-12): targetless, ghost, self and retarget merges are refused with
  the pointer written in the same single save as the status — a durable
  targetless DUPLICATE is unrepresentable.

### Also in this batch (round-3 polish sweep)

- A waiver stage the system never reads used to record silently; the CLI now
  validates the stage against the vocabulary the proofs and gate checks read
  (2026-09-12, round-3 polish — `webv2 waive` refuses a typo'd stage naming
  the valid list). The library keeps Python-replay parity; the refusal is
  the verb's.
- The schema-count prose (27/28 vs the current 32) is now count-free in the
  live comments and release script; generated and frozen historical
  documents keep their counts as dated records.

