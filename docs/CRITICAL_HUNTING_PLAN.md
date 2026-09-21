# Critical-hunting plan for web3sec-go (`webv2`) — what to build, in what order, and why

**Status:** proposal / design document. **No code was changed to produce it.**
**Date:** 2026-09-21 · **Author:** research pass over `web3sec-go` @ `528b6ae9` + the
real-target evidence in the sibling workspace (`morph/`, `targets/`).

---

## 0. TL;DR — the argument in one page

`webv2` is an unusually rigorous **bookkeeping** machine: hash-chained state,
schema-first writes, deterministic gates, evidence floors, a hostile critic, a
mechanical probe surface, and a refusal to let a model promote its own finding.
That is real and rare. But **not one critical has ever been confirmed with it**.
The only live campaign against a real protocol (Morph L2, a pinned vulnerable
commit with two known high/critical bugs) holds **31 findings, all HYPOTHESIS,
0 execs, 0 CONFIRMED**, and it missed the ranked-hardest bug of the eight-bug
difficulty ladder twice.

Diagnosis, in one sentence each:

1. **Nothing in the framework attacks anything.** `exec` runs an operator-written
   command; nothing schedules, synthesizes, funds, or parameterizes an exploit.
   The budget even reserves 6 repro attempts per finding; 0 were used.
2. **The code model is a name graph, not a value/flow graph.** The v3 structural
   index carries no expressions, no arithmetic order, no parameter names, no
   storage layout, no loops, no balance deltas — so the highest-yield critical
   families (rounding/first-depositor, oracle substance, accrual, weird tokens,
   liquidation edges, MEV) are **declared `Unprobed` in the framework's own
   source**, not merely unimplemented.
3. **The model boundary is a halt, not a loop.** `run` stops at `needs_model`
   and waits for a human to hand-feed JSON; the campaign stalls mid-discovery.
4. **Hypothesis generation is bounded by a half-empty prior library**: 25
   canonical classes, **10** with a playbook; the class the framework's own
   flagship bug belongs to (`l2-fee-oracle`-ish) has no name at all.
5. **The feedback loop cannot close**: 19 eval cases, all hand-planted, only 6
   held-out → the Wilson-interval verdict that governs whether a tuning change
   "improves" anything is statistically unreachable, so weights ship neutral
   forever and tuning is taste.
6. **The paid-bounty half has never executed.** The real Morph policy's
   `severity_rules` name bug classes that are not in the taxonomy (`"drain"`,
   `" griefing-persistent"` — note the leading space), so `SeverityFor` matches
   nothing and every gate run dead-ends at a `human-review` blocker.

Therefore the plan is **not** "add more detectors". It is, in order:

- **Wave 0 — make the loop run at all** (unblock exec, unblock the model
  handoff, unblock the severity gate, make yield measurable). Days, not weeks.
- **Wave 1 — build the exploit factory.** The framework's entire value is the
  gate; a gate with nothing to gate confirms nothing. This is the single
  biggest expected-value item in the document.
- **Wave 2 — give the index value-level vision** (arithmetic spine, storage
  layout, param names, loops, balance deltas). This converts the classes the
  framework itself declares unreachable into ranked rows.
- **Wave 3 — upgrade hypothesis generation** (classes, playbooks, mandatory
  strongest-attacker arm, critic attack on the impact *number*).
- **Wave 4 — build measurement that can actually certify improvement** (a
  `Gold-100` from public exploit corpora, a clean-corpus false-positive suite,
  cost/time joined to gold anchors, a ship-gate rule). Everything in waves 1–3
  is then tunable on evidence instead of argument.
- **Wave 5 — convert confirmed bugs into paid bounties** (payout/EV model,
  enforced one-root-cause export, self-contained PoC in the Immunefi export,
  submission provenance).

Waves 0 and 4 come first **even though they find no bugs themselves**, because
without them every later change is unfalsifiable: you cannot tell whether a new
probe helped. That ordering is the main non-obvious claim of this document.

---

## 1. What "critical" actually means — the payoff function we are optimizing

Design has to start from the payout function, because it is not "find bugs".

**Severity is impact-shaped, not CVSS-shaped.** Immunefi classifies on a
4-level scale (Critical/High/Medium/Low) and the top band is essentially
*direct theft of funds, permanent freezing of funds, or breaking a core
protocol invariant* ([Immunefi VSCS v2.3](https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/);
[severity classification systems](https://immunefi.com/severity-classification-systems/)).
High covers temporary freezing, griefing, and significant disruption.
Protocol-design complaints with no on-chain impact are typically out of scope
([web3.new](https://www.web3.new/protocols/immunefi)).

**A runnable PoC is mandatory, not a nice-to-have.** Reports without an
executable exploit are routinely closed as informational *even when the bug is
real* ([web3.new](https://www.web3.new/protocols/immunefi),
[Immunefi report guide](https://github.com/wakaka23333333/defi-audit-targets/blob/main/IMMUNEFI-REPORT-GUIDE.md)).
This single fact is why Wave 1 (the exploit factory) outranks every detector in
this plan: **evidence production is the bottleneck, not hypothesis production.**

**The money is concentrated at the top.** Immunefi paid close to
[$11M in bounties in 2025](https://darkmode.securityalliance.org/darkmode-2026/talk/P8GGKC/);
Q1 2026 paid $7.87M across 1,104 reports with the average payout nearly
tripling to ~$7,131 as the mix shifted toward critical/high
([Immunefi Q1 2026 update](https://www.kucoin.com/blog/id-immunefi-ecosystem-2026-q1-update));
by June 2026 nearly **6 in 10 bounty dollars went to critical severity**
([Immunefi June 2026 update](https://docs.immunefi.foundation/june-2026-immunefi-ecosystem-update/)).
Expected value per hour therefore sits almost entirely in *critical with a
reproducible exploit*, and is approximately zero for low/medium.

**It is a race.** Payouts are first-to-report on a root cause; duplicates pay
nothing. That makes *time-to-first-finding on a live program* and
*one-root-cause-per-submission discipline* primary metrics, not cleanliness
metrics.

**The frontier is moving.** LLM agents now reproduce real historical exploits:
SCONE-bench (405+ contracts actually exploited 2020–2025, anvil forks, a
`FlawVerifier` that must extract ≥0.1 native token) reports frontier models
draining ~$4.6M in simulation at >55% success
([Anthropic](https://www.anthropic.com/research/smart-contracts),
[scone-bench](https://github.com/anthropics/scone-bench)), and
[CyberChainBench](https://arxiv.org/html/2606.26216v1) builds detection,
exploit-generation and patch-synthesis tasks from 541 DeFiHackLabs incidents.
The read-across for us is uncomfortable and useful: **the winning move is not
"reason about code"; it is "fork mainnet, run the attack, measure the delta"** —
exactly the capability `webv2` currently lacks and the capability its evidence
ladder (E5/E6/E7) already assumes exists.

**Design consequence.** Optimize for: *confirmed criticals per unit of agent
time, each carrying a runnable fork PoC and a measured USD delta.* Everything
below is scored against that.

---

## 2. Measured state of the union (every number here was read from disk)

| fact | value | where |
|---|---|---|
| canonical bug classes | 25 + `unmapped` | `assets/taxonomy/class_weights.json` |
| classes with a playbook | **10** | `assets/playbooks/` |
| deterministic probes (axes) | 6 | `internal/probes/registry.go` |
| structural archetypes | 13 | `assets/archetypes/` |
| eval cases | **19, all `source.dataset = manual`** (13 dev / 6 held-out; 17 exploitable + 2 clean controls) | `assets/evalsuite/cases.json` |
| real held-out targets | 1 program, 2 gold cases | `../targets/morph-gold-cases.json` |
| live campaign (Morph L2, commit `22ca805e`) | 31 findings, **all `HYPOTHESIS`**; `execs/` **empty**; phase `DISCOVERY`, pass 1/8; `memory/`, `chains/` empty | `../morph/campaigns/C-5e04a99520/` |
| findings on **non-canonical** classes | 8 of 31 (`lifecycle-race`, `signature-bypass`, `fee-undercharging`, `config-drift`, …) | same `findings/*.json` |
| gold result on the real target | **G-02 found** (E1 only); **G-01 missed** in every scored round | `../targets/gold-findings.json`, `docs/feedback-triage*` |
| CONFIRMED evidence floors | 12 classes E4 · 3 E5 · 6 E6 · **4 classes unmapped → default E5** (`precision-rounding`, `donation`, `centralization-risk`, `unchecked-external-call`) | `internal/findings/levels.go:52` |
| Morph policy severity vocabulary | `"drain"`, `"theft-of-funds"`, `" griefing-persistent"` … — **none** in the taxonomy | `../morph/campaigns/C-5e04a99520/bounty_policy.json` |

Two of these deserve emphasis because they are not opinions:

- **Zero execs on a campaign with `max_repro_attempts_per_finding: 6`.** The
  budget for reproduction exists and was never spent. That is a plumbing
  failure, not a research failure — and it is the cheapest thing to fix.
- **The hardest bug in the ladder is a *lifecycle/liveness* bug, and it is the
  one the framework misses.** `G-01` (rank 1 of 8 by reasoning difficulty):
  `prevStateRoot` is validated only in `finalizeBatch`, never in `commitBatch`;
  a malicious sequencer commits a batch from a *fake* previous root, wins the
  challenge with a proof that is valid *relative to the fake root*, steals the
  honest challenger's deposit, and — because finalization is sequential —
  **the chain can never finalize again**. The gold note says why it is hard:
  auditors anchor on asset theft, and this bug is a liveness invariant whose
  defective check *exists*, just in the wrong lifecycle stage. Our L-01
  (liveness) and L-03 (enforcement-timing) lenses are aimed at exactly this,
  yet the bug was still dismissed at surface rank 1 in round 1 and never
  re-derived. **The lens exists; the mechanism that would force the model to
  walk the lifecycle and price the interim window does not.**

---

## 3. Diagnosis — six structural causes, and the mechanism behind each

### C1. The framework verifies attacks; it does not make them

`exec` runs an operator-written command string. `verify --scaffold` writes an
invariant harness with a `BODY` region the model fills. `sequencepoc` executes
an operator-authored spec. `minicertora`/`miniprover` produce bounded
counterexamples that can bridge into a sequence spec. Nothing generates a
Foundry test, an attacker contract, a fork setup, or funding
(`internal/harness/templates.go`, `internal/sequencepoc/sequencepoc.go`,
`docs/MINIPROVER_INTEGRATION.md` — and note the prover is **E3-capped and
host-run**, so it can never back E4+ by itself).

**Why it costs criticals.** The CONFIRMED gate requires an `EXEC` record at the
class floor (E4 local / E5 fork / E6 independent). If the agent cannot write
the exploit, the finding dies *before* the gate — and the sanctioned escape is
`floors set`, which lowers the floor and thereby launders weak evidence into
CONFIRMED. So the missing capability does not merely slow us: it quietly
degrades the gate. That is the mechanism behind "31 hypotheses, 0 execs".

### C2. The index sees names, not values or flows

The v3 structural index carries, per function: visibility, entry-point flag,
modifiers, selector, `reads_storage`/`writes_storage` **name sets**, internal
and external call edges (including cast/chained forms), `delegatecalls`,
`guards[]` (line, concept keys, class 0–4, text) and `uses[]` (line, concept
keys, kind); per contract, the inheritance closure. It carries **no**
expressions, no arithmetic order, no parameter names or values, no state-var
types/order/slots, no loops, no events, no balance deltas
(`internal/structidx/parser_model.go`; the archetype YAMLs carry explicit
"VALUE-BLINDNESS" honesty notes).

**Why it costs criticals.** The framework's own `internal/corpus/probes.go`
declares `precision-rounding` and `signature-replay` **`Unprobed`** —
"requires body-level arithmetic-ordering analysis not present in the structural
index". Those two entries are the *highest-yield* DeFi families. Everything
downstream inherits the blindness:

- rounding / first-depositor inflation → invisible (no mulDiv order, no
  `totalAssets == 0` seeding check, no virtual-offset formula);
- oracle substance and **read-only reentrancy** → invisible (no view-function
  return-flow anywhere in the schema; `pOracleManipulation` is a call-name
  regex);
- accrual/fee math → name vocabulary only; no time/period semantics;
- **MEV/ordering** → nothing models ordering, slippage, or deadlines (and with
  no parameter values, `minAmountOut = 0` is unseeable);
- unbounded loops / gas griefing → the parser emits **no loop nodes at all**;
- proxy storage collision / initializer replay → state vars are
  `{id, kind, name, path, line}` with no type or order;
- weird tokens (fee-on-transfer, rebasing, ERC-777, ERC-4626) → the economics
  transforms fire only if the *operator* hand-declared the flag on the protocol
  model (`economics.go hasFlag()`), so the code cannot discover them;
- cross-chain replay / bridge finality → five bridge archetypes are
  selector-text hints with honesty notes admitting a `uint256 relayer` matches
  identically to a real one.

**Implication.** These are not "we haven't written the detector yet"; they are
"the substrate cannot express the question". That is why Wave 2 is a parser
change, not a probe change.

### C3. The model boundary is a halt, so the loop needs a human

`run` walks the 17 stages and exits at the first model stage with a
`needs_model` report naming the prompt and the expected structured output. The
operator must read the prompt, produce JSON, and ingest it. There is no
file-drop convention, no `run --feed`, no batching. The Morph campaign sat at
`DISCOVERY` / `needs_model` with `pass 1/8` and empty `memory/` and `chains/`,
and the operator's own notes list the handoff as the top friction item
(`../morph/FRAMEWORK_NOTES.md`, "Wish list"). Doc/code drift compounds it: the
bootstrap says `run` exits 3 on a model halt; the build the operator used
returned 0.

**Why it costs criticals.** Discovery (stage 6) is where hypotheses are born,
and it is exactly where the pipeline stops. A framework that cannot iterate
discovery without a human in the loop cannot do the thing that actually finds
criticals: **many cheap hypotheses, killed fast, in parallel trajectories.**
Meanwhile 31 findings sat unadjudicated because nothing drove triage → exec →
mint.

### C4. Hypothesis generation is capped by the prior library

25 canonical classes but only 10 playbooks; `liquidation-logic`,
`flash-loan`, `signature-replay`, `token-integration`, `sequencer-halt`,
`chain-freeze`, `liveness`, `donation`, `dos-griefing` and friends have **no
prior file**, so the proposer works from one-line trajectory cards that defer
to legacy stages. Whole families have no class at all and land in `unmapped`
(default E5 floor, no prior, cannot anchor a gold case): AMM/curve math,
delegatecall + storage collision, L2 fee oracle / withdrawal-proof depth
(**the exact family of the framework's own Morph `GasPriceOracle` run**),
ERC-4337 paymasters, MEV/ordering, governance-flash-loan, timelock bypass,
keeper incentives.

Two prompt-level holes matter as much:

- `47_proposer_system.md` makes the attacker block **optional** ("absent means
  arbitrary EOA") and `required_capital_usd` nullable, and stage 38 ranks the
  queue by *prior risk × validation cost*, never by expected extractable value.
  So the queue systematically prefers cheap low-impact work.
- `48_critic_system.md` is told the `economic_impact` numbers are "assertions
  under test" and is forbidden to reconstruct a mechanism — but is **never
  asked to check the numbers for internal consistency** (extractable ≤
  demonstrated liquidity, `extraction_ratio` vs `blast_radius`). The number
  that decides critical-vs-high is the one number nobody attacks.

**Why it costs criticals.** A hypothesis that never gets an attacker model
understates impact; a hypothesis whose impact number is never cross-examined
overstates it. Both push the campaign away from *paid* criticals.

### C5. The feedback loop cannot certify anything

`docs/eval-methodology.md` sets a good rubric (no leakage, temporal split, no
strawman baseline, contract-level F1, significance test). What exists: 19
hand-planted fixtures (13 dev / **6 held-out**), 2 real gold cases (Morph,
scored **0/2**, verdict FAIL), one clean control (ES17) plus one decoy (ES16),
a `--backtest` over **pseudo-findings** (class+severity band only — no
evidence, no critic, no pipeline), baselines `always/never/slither/aderyn`, and
a Wilson lower-bound "improve" verdict.

**Why it costs criticals.** With 6 held-out rows, `B.lo > A.lo` is
statistically unreachable, so class weights stay neutral forever and every
tuning decision is taste. Worse, the backtest certifies a **ranking signal in
the store**, not the end-to-end pipeline — the pipeline can regress silently
while the verdict says "improved". And the only real measurement (Morph, 0/2)
is the one number that says we are losing.

### C6. The paid-bounty half has never run against a real program

`internal/bounty/policy.go` `SeverityFor` exact-matches a rule's
`bug_classes` against the canonical taxonomy. The real Morph policy names
`"drain"`, `"theft-of-funds"`, `"canonical-data-corruption"`,
`" griefing-persistent"` (leading space) — so most rules can never fire and
every gate run dead-ends on the `severity` check → `human-review` blocker →
`submission_ready` structurally unreachable. Related: the Immunefi export
renders the PoC section as evidence *lines* (`E5 [fork-test] … artifact ART-x`)
with no runnable commands, no PoC source, no pinned block or toolchain, even
though prompt 43 promises them; the "one root cause per submission" hard rule
is enforced nowhere before export; and there is no payout/duplicate/EV model
(`max_severity` and `platform` in the policy schema have zero non-test
consumers).

**Why it costs criticals.** A correct critical that cannot pass the gate or
cannot be reproduced from its own export pays **zero** — which, in a
first-to-report race, is the same as not finding it.

---

## 4. The plan

Sequencing rule used throughout: **unblock → produce evidence → sharpen →
tune → convert.** Each item carries *what / why / expected effect / effort /
risk*. Effort is S (≤1 day), M (~1 week), L (~1 month), XL (multi-month).
"Verify by" is the falsifiable check that decides whether the item worked.

### Wave 0 — Unblock the loop (no new bug-finding power; pure throughput)

These are cheap and they are prerequisites: until they land, every experiment
below is unmeasurable and every finding is unreproducible.

**0.1 Auto-schedule reproduction execs.** *(M)* When triage passes a
hypothesis, create the `EXEC` attempt the budget already allows
(`max_repro_attempts_per_finding = 6`, currently 0 used) instead of waiting for
a manual model loop: profile selection from the class floor
(`docker-networkless` for E4, `fork-runner` for E5/E6), workdir convention, and
`classify` on failure routing ENVIRONMENT → no retry, SETUP → fresh context,
LOGIC → argue the hypothesis.
*Why:* this is the whole gap between 31 hypotheses and the first CONFIRMED.
*Verify by:* on a resumed Morph campaign, `execs/` stops being empty and at
least one finding reaches `POSSIBLE` with an EXEC citation.

**0.2 Non-interactive model-stage handoff (`run --feed`).** *(S)* A documented
drop-file convention: the harness writes `campaigns/<C>/inbox/<stage>.json`,
`webv2 run --feed <file>` validates against the stage's output schema and
ingests; exit codes match the documented 0/1/2/3 contract (fix the drift where
`run` returned 0 on a model halt).
*Why:* discovery is where the pipeline stops today; an unattended loop is what
lets us run many cheap hypotheses across trajectories.
*Risk:* unvetted model output entering the record — mitigate by schema
validation plus provenance on the event (which model, which prompt hash).

**0.3 Policy lint + provisional severity.** *(S)* At `scope`, validate
`severity_rules[].bug_classes` against the taxonomy: warn on unknown names,
auto-map known aliases (`replay` → `signature-replay`, `griefing` →
`dos-griefing`, `drain` → `economic-invariant`), and normalize whitespace. When
no rule matches in `SeverityFor`, emit a *provisional* band derived from
`validated_risk` + `blast_radius` + extractable thresholds, printed as a
reviewable proposal rather than a bare `human-review` blocker.
*Why:* one data defect currently bricks the entire submission path; a reasoned
default keeps the human decision fast.
*Verify by:* the Morph policy loads with zero unknown-class warnings and at
least one finding gets a non-blocked severity band.

**0.4 Anchor-cluster dedup pass.** *(S)* Deterministic dedup reported
tier1/tier2/tier3 = 0 while four near-identical `whitelistChecker` hypotheses
and three `challenge-extension` ones sit in `findings/`. Cluster by overlapping
affected anchors + title terms when the deterministic pass returns nothing, and
surface the cluster instead of seven separate rows.
*Why:* duplicates are the direct tax on precision and on operator attention;
the eval's own adjusted-precision rule (<0.5 = partial) would fail on this.

**0.5 Built-in adjudication pass.** *(S)* A verb that records a verdict
(`additional-true-positive` / `false-positive` / `assumption-gated`) for every
live finding before handoff. `eval_adjudications = 0` today, and the scoring
rule counts unadjudicated findings as false positives — so the campaign's yield
is literally unpresentable.

**0.6 `phase-report` telemetry.** *(S)* One command printing time per stage,
gate refusals, dedup counts, evidence-rung distribution, adjudication rate, and
cost per campaign.
*Why:* this audit had to be assembled by hand from `events.jsonl`. Yield
telemetry is what turns framework arguments into framework evidence — and it is
also on the operator's own wish list.

### Wave 1 — The exploit factory (highest expected value in this document)

**1.1 Foundry PoC synthesizer.** *(L)* Generate, from the finding's
`root_cause`, `affected[0]`, `exploit_sequence` and preconditions: (a) a
`test/` scaffold pinned to the snapshot's solc and the fork block, (b) an
attacker contract template, (c) a `BODY`-marked region the model fills (same
body-window law as the invariant harness), (d) a `forge test` invocation whose
output the existing meaningfulness check already parses.
*Why:* C1 — the framework verifies operator-written PoCs only, and PoCs are
mandatory for payout. This is the difference between "found a bug" and "paid
for a bug". *Risk:* arbitrary toolchains; scope first to `fork-runner` and
solc-pinned container profiles. *Verify by:* on a known-vulnerable fixture from
`assets/evalsuite/`, a synthesized test reproduces the planted bug without a
human writing it.

**1.2 Funding primitive in the fork runner.** *(L)* A reusable
`funding:` block for sequence PoCs — flash-loan (provider, asset, amount)
compiled into the cast driver before the exploit steps, with a whale-prank /
`anvil_setBalance` fallback behind a per-profile allowlist.
*Why:* capital-minimization is the definition of the modern critical; if the
operator cannot fund the attack, the bug stays at E4 or gets a floor override.
This is precisely the capability that makes SCONE-bench-style agents work.

**1.3 Measured impact (balance deltas → USD).** *(M)* Fork profiles snapshot
per-actor balances before/after (native + ERC20 via `cast`), compute attacker
profit, price it through the existing price table, and write
`economic_impact.measured_usd`. The gate prefers measured over operator-typed
`extractable_usd` and flags drift.
*Why:* today `extractable_usd` is unverifiable narrative, and the *unpriceable*
bypass can satisfy the E7 clause with zero measurement. Measurement is also
what makes severity calibration (Wave 4) possible at all.

**1.4 Evidence-kind floor.** *(S)* In the gate's default branch, require a
*PoC-class* evidence type (`local-poc ∪ fork-poc`) for execution floors
instead of any type at the right level.
*Why:* the gate currently conflates level with kind — a static/reasoning item
at E4 satisfies an E4 floor. This is the cheapest false-positive path in the
system.

**1.5 E4+ mints must cite a measured artifact.** *(M)* An E4+ evidence item
must carry a machine-checked output marker (balance-delta block or
`sequence_result.json`), not merely `exit 0`.
*Why:* a green `assertTrue` test minted as "drains the pool" currently
satisfies the floor. *Risk:* legacy findings fail until re-minted — migrate
with an advisory period.

**1.6 Lifecycle/liveness archetype.** *(M)* Emit a hypothesis when a state
machine's *restrictive* arm is unchecked: a check that exists in stage N+1
(`finalize`) but not stage N (`commit`) on a value consumed sequentially, plus
the mandatory "what gets stuck" clause. Wire it to force the interim-window
pricing (`--interim` / `--finding`) the enforcement-timing lens already
demands.
*Why:* this is the direct, mechanical answer to `G-01` — the check exists, in
the wrong stage; the model has to be *made* to walk commit → challenge →
finalize and price the freeze. It also serves the second half of the
"two polarities" rule that the runbook already states but cannot enforce.

**1.7 Liveness adversarial-game clause at CONFIRMED.** *(S)* Mirror the
bounty-gate `adversarial-game` check into `ConfirmationGateClauses` for
`chain-freeze` / `sequencer-halt` / `liveness`.
*Why:* freeze bugs currently confirm at E4 with no who-profits analysis; the
clause exists only in the waivable bounty gate.

**1.8 Reachability-grounded floor overrides.** *(S)* `floors set` lowering an
E5/E6 class must cite why the fork is unreachable (an `env doctor` artifact or
a fork exec classified ENVIRONMENT).
*Why:* otherwise the sanctioned override is the standard escape hatch that
launders unmet floors into CONFIRMED — the degradation loop described in C1.

### Wave 2 — Give the index value-level vision (parser v4 + new probes)

One parser change unlocks most of the `Unprobed` class space. `parse_version`
already forces a rebuild on mismatch, so an additive index field is safe.

**2.1 Arithmetic spine (mini-AST for accounting functions).** *(L)* For
functions matching the accounting vocabulary, record per-statement binary ops:
operator order (`*` before `/`), operand *kinds* (storage read / param /
`balanceOf` call / `msg.value` / literal), and literal values. New probes:
*rounding-direction* (division before multiplication; `/ totalAssets` where
`totalAssets` can be 0 on a first-mint path, seeded from the writers-of query)
and *denominator-movable* (a ratio operand is a live balance writable by a
plain transfer → donation).
*Why:* closes the framework's own declared `precision-rounding` hole and, with
it, first-depositor inflation independent of variable naming. *Risk:* assembly
`mulDiv` and Yul read as unknown — emit an `assembly-present` blind key rather
than a claim.

**2.2 Balance-delta token-flow pass (weird tokens).** *(M)* Over existing cast
-form call edges, classify each entry point's external calls into token-in,
token-out, and balance reads; compare the *recorded* amount against the
*implied* amount. Emit rows for fee-on-transfer shape, for a rate derived from
a balance the entry point does not control (donation), and for hook-shaped
calls (ERC-777/1155 receivers) inside a storage-write window (reentrancy-on-view
candidate).
*Why:* the four economics transforms today fire only on operator-declared
flags; this makes weird-token detection code-derived and feeds the donation
predicate. *Risk:* assembly transfers and multicall wrappers — gate to
ERC20-call-edge functions.

**2.3 Storage-layout extractor.** *(M)* Capture ordered state-var declarations
**with type text and constant/immutable flags** (today: `{id, kind, name,
path, line}`). Implement proxy-vs-implementation collision candidates over the
delegatecall family + inheritance closure, EIP-1967 slot recognition, and
initializer-replay rows (an `initialize*` entry whose guards reference no
initializer-flag-shaped concept).
*Why:* upgrades the two most-covered-by-regex criticals
(`upgrade-initializer`, `delegatecall-to-user-input`) to layout-derived
evidence at near-zero FP cost.

**2.4 Parameter names + emitted events in the index.** *(S)* Names only — no
values. New probes: *signature-consumption* (an `ecrecover`/verify-marked entry
whose guards/writes never mention a nonce/chainid/deadline concept) and
*guard-pair* (is the recovered signer compared against anything?).
*Why:* the archetype honesty note says value-blindness is the core limiter;
names alone distinguish a dead `chainId` argument from a consumed one and turn
`signature-replay` from marker-absent to registry-absent.

**2.5 Loop census.** *(M)* Emit one node per `for`/`while`: bound source
classified as literal / param-array-length / storage-read / unknown, plus flags
for external calls, delegatecalls, or storage writes in the body. Row only for
param-length or unbounded-storage bounds with a call-out or write inside.
*Why:* the parser emits no loop nodes today, so unbounded iteration and
per-item external calls — a whole DoS family — are invisible. *Risk:* high
baseline noise; require axis quota + tier ranking and budget the blind keys.

**2.6 Oracle-consumer staleness census.** *(M)* For every function matching the
existing oracle amplifier regexes, emit a row when no guard/use concept folds
to a staleness vocabulary (`updatedAt`, heartbeat, timeout, `roundId`,
`sequencer`, L2 uptime feed).
*Why:* staleness is currently only a question *string* gated on an
operator-declared `OracleChain`; a code-side census fires on every real feed
consumer and covers the L2 sequencer-uptime case that bit our own Morph run.

**2.7 Executable economic canaries (turn the transform catalog into checks).**
*(M)* The 13-entry transform catalog in `internal/economics` is prose the model
is asked to consider. Ship a fixed deterministic transaction suite per
transform — donate-to-vault, first-mint-at-zero-supply, direct-transfer-then-
deposit, deposit-a-fee-token — run it against the pinned fork, and diff the
model's declared accounting vars against the synthesized invariant equations.
Violations mint invariant-registry entries **with E5 evidence automatically.**
*Why:* this is the strongest FP profile of any proposal here because it runs on
real state: donation / first-depositor / ERC-4626-inflation stop being
hypotheses and become measured outcomes. *Risk:* needs RPC + a pinned block for
determinism; anything outside the declared equations must be reported as
unexplained, never passed.

### Wave 3 — Hypothesis generation: classes, priors, and adversarial impact

**3.1 Add the missing canonical classes** (each with a playbook, a floor row,
ingest canonicalization, and a gold-eval anchor): *(S–M each)*

| new class | why it needs to exist |
|---|---|
| `amm-invariant` | curve/getAmountOut rounding, fee off-by-one, LP mint/burn deflation — a top DeFi loss family that today lands in `logic-error` or `unmapped` (wrong floor, no prior, no anchor) |
| `delegatecall-storage` | archetype-only today → `unmapped` + E5 default; but these are provable locally at E4 like reentrancy, so the wrong floor wastes fork budget |
| `l2-fee-oracle` (+ withdrawal-proof depth) | **our own flagship bug family** (Morph `GasPriceOracle`) has no canonical name — the bug type we demonstrably find is invisible to our taxonomy |
| `governance-flashloan` | vote-snapshot / quorum capture / timelock bypass currently forced into `flash-loan` (price mechanics) or `economic-invariant`; different PoC shape, different floor |
| `account-abstraction` (ERC-4337) | distinct trust boundary (paymaster sponsorship, userOp validation); no class or playbook routes it |
| `fee-accrual-accounting` (split from `share-price-accounting`) | reward-index update order, vesting, fee mint/burn ordering, unclaimed-fee double count — different structure and PoC shape from share pricing |

**3.2 Write the missing 15 playbooks** *(M)* — prioritize `liquidation-logic`
(dutch-auction edges, bad-debt socialization), `flash-loan`,
`signature-replay`, `token-integration`, `sequencer-halt`, `chain-freeze`,
`liveness`, `donation`, and extend trajectory B's transform list with AMM math,
liquidation incentives, governance snapshots, ERC-4337, L2 fee oracles, and
read-only reentrancy via ERC-777/4626 hooks.
*Why:* hypothesis generation is bounded by the class prior; a one-line card
cannot carry 25 classes' surfaces.

**3.3 Write the class boundary document** *(S)* — define `access-control` vs
`authorization` vs `centralization-risk` (the third is a documented trust
assumption, not a bug).
*Why:* three overlapping classes with no written boundary let tier-2/3 dedup
merge or split inconsistently and let the 4-class diversity gate be satisfied
by relabeling one mechanism four ways.

**3.4 Mandatory strongest-attacker arm at proposal time** *(S)* — for
`oracle-manipulation`, `flash-loan`, `share-price-inflation`,
`liquidation-logic`, `economic-invariant`, make `attacker` required with
enumerated capabilities ("may hold any position, use flash loans, occupy the
first-depositor/keeper seat") and `required_capital_usd` non-null.
*Why:* today "absent means arbitrary EOA" and the strongest-attacker arm only
activates in stage 50 (simulation) or 44 (post-CONFIRMED) — i.e. exactly too
late to raise the impact ceiling a hypothesis claims.

**3.5 Require a profit model sentence per hypothesis** *(S)* — who pays, why
paying is rational under public information, and the extraction path (stage 50
already has this discipline; extend it to all classes).
*Why:* mechanism-design criticals are defined by a rational benign payer; this
separates genuine extraction from informational accounting oddities *before*
reproduction budget is spent.

**3.6 Numeric cross-examination in the critic** *(S)* — on economic classes,
require the critic to check `extractable_usd` against the liquidity the cited
evidence actually demonstrates and `extraction_ratio` against `blast_radius`;
mark `possible` with `missing_proof` when the magnitude is unsupported.
*Why:* the critic's disbelief stance covers assumptions but not the number that
decides critical-vs-high, so a fabricated 100% extraction passes today.

**3.7 Rank the queue by expected value** *(S)* — replace "prior risk ×
validation cost" with expected extractable value × P(confirm) ÷ cost.
*Why:* the current rule starves expensive high-impact surfaces, which is
precisely where criticals live.

### Wave 4 — Measurement that can actually certify improvement

Without this wave, waves 1–3 are a set of opinions. With it, they become
experiments. This is why it is sequenced *before* tuning anything.

**4.1 `Gold-100`: a dataset-sourced eval store.** *(L)* Ingest ≥100 cases from
DeFiHackLabs ([687 documented incidents](https://deepwiki.com/SunWeb3Sec/DeFiHackLabs),
[explorer](https://defihacklabs.io/explorer/index.html)), C4/Cantina/Sherlock
judge verdicts (the ScaBench-curated set behind `targets/gold-findings.json`
covers 31 projects / 555 findings from 2024-08 to 2025-08), and
[SCONE-bench](https://github.com/anthropics/scone-bench)-style historical
exploits. `evaluation_case.schema.json` already declares these sources and
loaders exist; only the cases are missing. Partition by **incident date** with
pretraining-cutoff discipline (the suite already excludes held-out rows older
than the newest dev row and near-duplicates at Jaccard ≥ 0.8).
*Why:* 6 held-out rows cannot produce a Wilson verdict at any effect size, so
nothing can ever be proven to "improve". n≈40+ held-out is the smallest set
where `B.lo > A.lo` becomes reachable.

**4.2 Clean-corpus false-positive suite.** *(M)* ~30 production-audited
contracts with no known high/critical; run the full pipeline; report FP/LOC and
FP/case **per detector lane** with Wilson CIs beside the backtest block.
*Why:* precision claims today rest on one synthetic control (ES17). A detector
that adds 50 noisy rows on real repos is a net loss, and nothing measures it.

**4.3 Join cost and time to gold anchors.** *(S)* `cost.recorded` exists but is
never joined to gold anchors. Emit `USD-per-confirmed-finding` and
`time-to-first-anchored-finding` per campaign.
*Why:* those two numbers decide whether a tuning change is worth shipping, and
they are the closest proxies for the real objective (bounty EV per hour).

**4.4 Score the real pipeline, not pseudo-findings.** *(S)* Add an end-to-end
backtest mode: replay *actual adjudicated campaign findings* through
`evalscore` over `Gold-100` with the same Wilson rule; keep the
pseudo-finding signal test only as a cheap pre-gate.
*Why:* today's verdict certifies a store ranking signal while the pipeline can
regress silently.

**4.5 Severity calibration vs the platform taxonomy.** *(M)* On adjudicated
rows, build the confusion matrix of framework band vs judge/Immunefi outcome;
report weighted kappa and per-band precision; gate any change to
`severity_default` behind it.
*Why:* mispricing severity costs payout credibility directly, and
`severity_default` is currently display-only and uncalibrated.

**4.6 Rolling real-target holdout.** *(M)* The `targets/gold-findings.json`
difficulty ranking already hands us eight ranked real targets with pinned
vulnerable commits — Morph L2 (chain-freeze, rank 1), Idle Finance
(`epochEndDate == 0` guard short-circuit + donation), LoopFi
(`accrued.divDown(totalShares)` rounds to 0 while `lastBalance` advances),
Uniswap minimal-delegation (no executor field + EIP-150 63/64 gas griefing),
Kinetiq, Lambo.win, plus two easy controls (cross-chain replay, missing access
control). Pin them as operator gold packs, run the documented rerun protocol on
every release candidate.
*Why:* real bounty work is recall on unaudited multi-file repos; synthetic
fixtures cannot predict it, and today n=1 (Morph, 0/2). These eight are also a
*curriculum*: they are ranked by the exact reasoning skills we are trying to
build (lifecycle, adversarial game, rounding, mempool/gas semantics).

**4.7 Ship-gate rule.** *(S)* Any weight/prompt/playbook change must pass three
printed blocks before merge: (a) backtest verdict `improve` on the expanded
held-out, (b) no clean-corpus FP regression beyond CI, (c) no real-target
rerun regression.
*Why:* G3/G7 define the verdict law; nothing enforces running it.

**4.8 Duplicate-pressure proxy.** *(S)* For contest-derived gold cases, record
how many co-finders the bug had (the gold pack already notes "28 co-finders:
easy" vs "only 2 co-finders") and report framework findings' overlap with the
duplicate pool.
*Why:* in a first-to-report market, a bug 28 people find is worthless; this
makes "hard and lonely" a first-class search criterion — arguably the single
best predictor of payout.

### Wave 5 — Convert confirmed bugs into paid bounties

**5.1 Payout model in the policy schema** *(M)* — payout table/caps,
first-to-report flag, duplicate policy, KYC/embargo flags; render expected
payout per finding; let `rank` order by EV; make the dead `max_severity` and
`platform` fields live.
*Why:* "submission-ready" is not "worth submitting first". Caps and duplicate
risk dominate EV and are currently unmodeled.

**5.2 Enforce one-root-cause at export** *(S)* — cross-check submission-ready
findings' tier-2/3 signatures before `report --format immunefi`; block
same-signature exports with a pointer to `chain` or `supersede`.
*Why:* programs penalize spray, and a chain super-finding is usually the better
submission anyway.

**5.3 Self-contained platform export** *(M)* — embed exact repro commands from
the EXEC ledger, the PoC source, pinned block/chain/forge version, and an
impact narrative templated from `economic_impact` + `adversarial_game` +
the paid-exploitability argument.
*Why:* triagers reproduce from the report; an unrunnable PoC is the top
rejection cause for *correct* bugs (see §1). Prompt 43 already promises these
fields — the export must render what the pipeline recorded.

**5.4 Submission provenance** *(M)* — record submission timestamp, content
sha256, and program contact per finding; render a submission ledger; warn when
a new finding shares a signature with an already-submitted one.
*Why:* first-to-report disputes are decided by timestamps, and nothing on disk
proves when or what was sent.

**5.5 Platform-shaped exports** *(L)* — switch export shape on
`policy.platform` (Immunefi vs C4/Sherlock/Cantina), and consume
`scope.max_severity` to downgrade findings above a scope entry's cap.

**5.6 Field-drive one finding end to end** *(M)* — take one Morph finding
HYPOTHESIS → CONFIRMED (fork PoC, exploit, measured impact, immunize) and run
the export against the pinned real policy. Also create the missing
`docs/SECURITY.md` disclosure checklist.
*Why:* there are **zero** `bounty.gate` events in the record. Every
gate/export claim in this framework is lab-tested; the first real run should
not be under a bounty deadline.

---

## 5. Why this order (the reasoning, made explicit)

**Unblock before sharpening.** Items 0.1–0.6 add no hunting power, yet they
come first because every downstream experiment needs a pipeline that can run
unattended and produce an EXEC. A new probe that cannot be scored is a hobby.

**Evidence production before hypothesis production.** We produced 31 hypotheses
on one real target and zero evidence. Marginal hypotheses are worth ~0 (they
are not paid, and they cost triage); marginal evidence is worth a lot (it is
the gate and the payout condition). Hence Wave 1 before Wave 3.

**Value-level vision before more probes.** Adding a seventh or eighth probe on
top of a name graph multiplies rows over the same blind spot. One parser
upgrade (Wave 2) moves the *frontier* — it converts two families the framework
declares unreachable into ranked rows and strengthens five more.

**Measurement before tuning.** Class weights are neutral by design and will stay
neutral until a backtest graduates them. That graduation is arithmetically
impossible at n=6 held-out. So the honest order is: build the dataset (4.1–4.2,
4.6), *then* let weights, priors, and probe quotas move — under the ship-gate
(4.7). Tuning first is taste dressed as engineering.

**Conversion last, but not optional.** Everything upstream is worthless if the
report cannot be reproduced by a triager or the severity vocabulary blocks the
gate (C6). Wave 5 is last only because it needs confirmed findings to exercise
it.

**Rough cost/benefit, by wave** (effort is a guess; the *ordering* is the claim):

| wave | effort | what it buys | if skipped |
|---|---|---|---|
| 0 | ~2 weeks | a pipeline that runs and reports | nothing is measurable; findings stay HYPOTHESIS |
| 1 | ~2 months | the ability to prove and price a bug | the gate has nothing to gate; floors get lowered instead |
| 2 | ~2 months | the top DeFi families become visible | probes keep finding the same narrow slice |
| 3 | ~1 month | better hypotheses, honest impact numbers | good mechanics, wrong targets |
| 4 | ~1.5 months | falsifiable tuning | every change is an argument |
| 5 | ~1 month | payout | correct bugs that pay zero |

---

## 6. Anti-goals — what not to build (and why)

- **Do not build a general symbolic execution engine or our own SMT solver.**
  The cost is XL and the ecosystem already has Halmos/Certora/KEVM plus
  Echidna/Medusa; our job is orchestration and evidence, and the prover lane is
  already E3-capped by design. Buy bounded results, never own the solver.
- **Do not chase non-EVM or multi-language coverage yet.** Morph's Go client and
  prover were hand-excluded and a Go finding "would have nowhere to live" — a
  real gap, but an *out-of-language scope ledger* (so excluded trees are
  tracked, not silently dropped) is the right size for now; a Go/TS structural
  index is a separate product.
- **Do not let `floors set` become the release valve.** Every unsupported floor
  override weakens the gate that is the framework's whole identity. Item 1.8
  exists solely to make that escape expensive and visible.
- **Do not autopilot submissions.** Keep the human gate on submission and on
  memory approval. A false submission costs program trust, which is the one
  asset a bounty hunter cannot re-earn.
- **Do not reward finding counts.** Never adopt a metric that grows with
  hypotheses filed; every metric in Wave 4 is conditioned on gold anchors or on
  evidence produced.
- **Do not delete the friction that is working.** The probe disposition gates
  (no dismissal on "liveness-only"/"owner can revert" prose without a ref that
  runs), the sentinel `--passes` rule, the interim-window pricing — these are
  the framework's best ideas and the Morph round-1 dismissal of `G-01` is
  exactly the failure they were built to prevent. Keep them; give them better
  inputs.

---

## 7. Acceptance criteria for this plan

The plan is working if, on a real pinned target, these move:

| metric | today | target after wave 1 | target after wave 4 |
|---|---|---|---|
| CONFIRMED findings on a real target | 0 | ≥1 with a fork PoC | ≥1 per campaign |
| `G-01` (rank-1 hardest: lifecycle/liveness chain-freeze) | missed 2× | found and dispositioned | found by the deterministic+lifecycle path, not by luck |
| execs per campaign | 0 | ≥ hypotheses triaged | reproduction is automatic |
| held-out eval cases | 6 (all manual) | — | ≥40, dataset-sourced, dated |
| real held-out targets scored | 1 (0/2) | 1 | ≥5 on a rerun protocol |
| clean-corpus FP/LOC | unmeasured (1 control) | — | measured per lane with CIs |
| USD per confirmed finding / hours to first hit | unmeasured | — | reported per campaign |
| `bounty.gate` events in any campaign | 0 | ≥1 blocked-by-severity diagnosis fixed | ≥1 finding exported reproducibly |

And the single honest scoreboard sentence: **"a critical found on a live
program, reproduced from our own export, paid."** Everything above is
instrumentation for that.

---

## Appendix A — Evidence index (every load-bearing claim and where it lives)

| claim | file / command |
|---|---|
| 31 findings, all HYPOTHESIS; `execs/` empty; pass 1/8; DISCOVERY | `../morph/campaigns/C-5e04a99520/{campaign_state.json,findings/,execs/}` |
| 8 of 31 findings use non-canonical classes | same, vs `assets/taxonomy/class_weights.json` |
| `G-01` missed, `G-02` found (E1) | `../targets/gold-findings.json`, `docs/feedback-triage-morph-r2.md`, `docs/feedback-triage-morph-r3.md` |
| 25 classes + `unmapped`; 10 playbooks; 6 probes; 13 archetypes | `assets/taxonomy/class_weights.json`, `assets/playbooks/`, `internal/probes/registry.go`, `assets/archetypes/` |
| `precision-rounding` and `signature-replay` declared `Unprobed` | `internal/corpus/probes.go` (`Unprobed` table) |
| index carries no expressions / param names / slots / loops | `internal/structidx/parser_model.go`; VALUE-BLINDNESS notes in `assets/archetypes/*.yaml` |
| weird-token transforms gated on operator-declared flags | `internal/economics/economics.go` (`hasFlag`) |
| CONFIRMED floors per class (E4/E5/E6, default E5) | `internal/findings/levels.go:52` |
| gate clauses and the 17 bounty checks | `internal/findings/gate.go`, `internal/bounty/bounty.go` |
| `SeverityFor` exact-matches canonical classes | `internal/bounty/policy.go`; real policy: `../morph/campaigns/C-5e04a99520/bounty_policy.json` |
| eval suite: 19 manual, 13 dev / 6 held-out, 17+2 | `assets/evalsuite/cases.json` |
| backtest / baselines / Wilson verdict / temporal exclusion | `internal/backtest/`, `internal/evalscore/`, `internal/evalstore/temporal.go`, `docs/eval-methodology.md` |
| prover is E3-capped and host-run | `docs/MINICERTORA_INTEGRATION.md`, `docs/MINIPROVER_INTEGRATION.md` |
| proposer leaves attacker optional; critic never checks numbers | `assets/prompts/47_proposer_system.md`, `assets/prompts/48_critic_system.md` |
| operator friction: handoff, policy cold-start, Solidity-only lens, `run` exit-0 drift | `../morph/FRAMEWORK_NOTES.md` |

## Appendix B — A ready-made held-out curriculum (from `targets/gold-findings.json`)

Ranked by reasoning difficulty, selected from 31 projects / 555 audit findings
(ScaBench-curated, 2024-08 → 2025-08), each with a pinned vulnerable commit.
These are both eval targets **and** a syllabus of the skills we must build.

| rank | project | the bug (condensed) | skill it tests |
|---|---|---|---|
| 1 | Morph L2 (Sherlock) | `prevStateRoot` checked only in `finalizeBatch`, not `commitBatch` → fake root wins the challenge, steals the deposit, and sequential finalization freezes the chain | lifecycle + adversarial game + **liveness** invariant |
| 2 | Idle Finance Credit Vaults | `epochEndDate == 0` short-circuits `claimWithdrawRequest`'s guard → claim before the first epoch; plus donation/inflation | pre-first-state machine + donation |
| 3 | LoopFi (C4) | `accrued.divDown(totalShares)` rounds to 0 while `lastBalance` advances → rewards lost forever | reward-index rounding + call frequency |
| 4 | Uniswap minimal-delegation (Cantina) | no executor field in the signed digest; `msg.value = 0`, `shouldRevert = false` breaks the batch; EIP-150 63/64 gas griefing | signature scheme + mempool + gas semantics |
| 5 | Kinetiq (C4) | `receive()` re-stakes withdrawn HYPE arriving as native gas → unconfirmable withdrawal + ratio inflation | native-token path handling |
| 6 | Lambo.win (C4) | `rebalance()` takes unvalidated `directionMask`/amounts → wrong-amount flashloan breaks the peg | unvalidated-parameter + flashloan |
| 7 | Next Generation (C4) | cross-chain replay via user-supplied `domainSeparator`, no deadline | easy control (28 co-finders) |
| 8 | Blackhole (C4) | `createGauge` missing access control → anyone drains reward token | easy control (9 co-finders) |

Note the pattern: **the top three are all "the check exists, but in the wrong
place / at the wrong precision / at the wrong time"** — not missing checks.
That is precisely the shape our L-01/L-03/L-04 lenses were built for and the
shape we still miss.

## Appendix C — External references used for the payoff function

- Immunefi Vulnerability Severity Classification System v2.3 — <https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/>; severity systems index — <https://immunefi.com/severity-classification-systems/>
- Immunefi platform expectations (impact-shaped severity, PoC mandatory) — <https://www.web3.new/protocols/immunefi>; report guide — <https://github.com/wakaka23333333/defi-audit-targets/blob/main/IMMUNEFI-REPORT-GUIDE.md>; "How to submit bug reports that get paid" — <https://medium.com/immunefi/how-to-submit-bug-reports-that-get-paid-b57096ea1638>
- Payout scale: ~$11M in 2025 — <https://darkmode.securityalliance.org/darkmode-2026/talk/P8GGKC/>; Q1 2026 $7.87M / 1,104 reports / ~$7,131 average — <https://www.kucoin.com/blog/id-immunefi-ecosystem-2026-q1-update>; ~60% of June 2026 dollars to criticals — <https://docs.immunefi.foundation/june-2026-immunefi-ecosystem-update/>
- LLM agents exploiting contracts: SCONE-bench (405–417 real exploited contracts, ~$4.6M simulated, >55% success for frontier models) — <https://www.anthropic.com/research/smart-contracts>, <https://github.com/anthropics/scone-bench>; CyberChainBench (541 DeFiHackLabs incidents; detection / exploit generation / patch synthesis) — <https://arxiv.org/html/2606.26216v1>
- Corpora for `Gold-100`: DeFiHackLabs (687 incidents) — <https://deepwiki.com/SunWeb3Sec/DeFiHackLabs>, <https://defihacklabs.io/explorer/index.html>; incident root-cause analysis (734 incidents) — <https://web3sec.notion.site/c582b99cd7a84be48d972ca2126a2a1f>

## Appendix D — Decisions needed from the operator

1. **Fork RPC access.** Waves 1, 2.7 and 4.6 all need a reliable archive-node
   RPC at pinned historical blocks. Without it, E5/E6 remains theoretical and
   `floors set` stays the release valve. This is the single biggest external
   dependency.
2. **Corpus ingestion licence/scope.** Are we allowed to ingest DeFiHackLabs
   PoCs and C4/Sherlock judge verdicts into a committed eval store? (Contamination
   discipline from `targets/README.md` must be preserved: the answer key stays
   eval-side, outside the binary, never in a campaign context bundle.)
3. **Which three targets are the first holdout?** Recommendation: Morph (rank 1,
   already pinned), Idle (rank 2), LoopFi (rank 3) — they test the three skills
   we are weakest at, and two are small enough to run cheaply.
4. **Autonomy level.** How much of Wave 0–1 may run unattended (model handoff,
   auto-exec, auto-adjudication) before a human reviews? The plan assumes
   "hypotheses and execs automatic; status changes, submissions and memory
   human-gated" — which matches the framework's existing law.






