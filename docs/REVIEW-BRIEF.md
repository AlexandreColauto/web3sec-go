# web3sec-go — reviewer brief

**What this document is.** A complete, self-contained description of the `web3sec-go`
project — what the software is, what it does today, what it refuses to do, where it is
going, and what is still unproven — written so that an expert reviewer who has never seen
the repository can review it usefully in one pass and propose improvements.

**State it describes.** Repository `web3sec-go`, module `websec`, binary `webv2`,
branch `main`. Written at commit `2771d466` (2026-09-23), immediately after the v16
work item §5.1 landed (`911be0a9`). The working tree is dirty on purpose: a second agent
is executing the v16 work queue (`docs/gates/v16-prompt.md`) in parallel with this
document being written — see §6.6.

**Honesty contract.** Everything below is either *measured* (a command was run, a file was
read, a number came off disk), *asserted by a document in the repo*, or *refused* (we tried
and could not establish it, and the refusal is recorded). Those three are labelled
throughout, because the project's central doctrine is that conflating them is the failure
mode that costs money. If you find a claim here that is not true of the tree, that finding
is itself valuable: report it as such.

---

## 0. How to use this document

**0.1 Read order for a reviewer.** §1–§3 describe the artifact. §4 is the history that
explains why the code looks the way it does. §5 is the specification the project is
building toward. §6 is the current phase. §7 is the strategic gap analysis. §8 is the
prover lane. §9 is the honest state of the union — *verified vs asserted vs unproven*.
§10 is the ranked list of things we already know are weak. §11 is the next-steps plan.
§12 is what we want from you. Appendices A–D are the map, the command surface, the
document map, and a glossary.

**0.2 What would be most useful from you.** In rough value order:

1. Attack §10 (known weaknesses) and §9 (the honesty ledger). We have tried to make
   attacking easy: every claim carries its evidence.
2. Tell us where the *design* is wrong, not where the code is untidy. The code is
   unusually disciplined; the risk is that it is disciplined about the wrong things.
3. Judge the central bet (§1.3) on its merits: a deterministic, model-free control plane
   wrapped around model-driven discovery and external provers. Is that the right
   architecture for finding critical bugs in Web3 protocols, or is it a very good
   bookkeeping machine around a discovery engine that does not exist yet?
4. Where you propose a change, say what measurement would falsify it. The project has a
   standing rule (D9, §5.1) that the specification changes only in response to a
   measurement, and a habit of recording refusals — so "this seems better" is weaker here
   than "this is better, and here is the number".

**0.3 What not to spend time on.**

- **Byte-level parity with the retired Python twin.** The Python implementation
  (`web3sec-final`) was retired on 2026-09-09. The Go tree still reproduces its output
  byte-for-byte in places (Python float repr, `json.dumps` key order, Python `str.lower`
  semantics) because a committed legacy fixture is audited by the release gate. That is
  deliberate and load-bearing; it is not an accident of the port, and "just use the Go
  idiom" would break a promise we intend to keep.
- **Code style.** `gofmt`, `go vet` and `golangci-lint` are enforced; the pre-commit
  entropy gate blocks large AI-shaped diffs.
- **Documentation volume.** It is large on purpose (§4.4) and is being compacted
  separately.

---

## 1. What the product is

### 1.1 The problem

Web3 bug bounties (Immunefi, Sherlock, Cantina, Code4rena) pay for critical
vulnerabilities in smart contracts and protocols. The work is done by human researchers
and, increasingly, by LLM-driven agents. Two things go wrong when agents do it:

1. **Generation is easy; closure is hard.** An agent can produce dozens of plausible
   findings. Turning one into a *paid* report requires a runnable proof of concept on a
   pinned fork, a measured economic impact, a severity that matches the platform's rubric,
   and a duplicate check — and it requires all of that to be *credible to a program's
   triage team*, which is a hostile reader.
2. **Nothing an LLM says is evidence.** A model that claims "this is a reentrancy that
   drains $7M" has produced a sentence, not a fact. Frameworks that let the model's own
   confidence promote a finding end up with reports that are wrong in ways that are
   expensive: a false submission costs program trust, and a retracted severity costs
   reputation on platforms that track validity ratios.

The motivating failure is concrete and in-repo: a real campaign against Morph L2 (a pinned
vulnerable commit with two known high/critical bugs) produced **31 findings and 0
confirmations**; the framework's generation half found both planted bugs, and its closure
half converted neither. That postmortem is what the current architecture is a response to.

### 1.2 The thesis

Split the problem into a **deterministic control plane** and **untrusted workers**.

- The **control plane** is a single static Go binary, `webv2`. It never calls a model. It
  owns the campaign record: what was scoped, what was indexed, which hypotheses exist,
  what evidence each one has, what severity the evidence supports, what it cost, what was
  refused and why. Every mutation is an append to a hash-chained event log; every read is
  a projection of that log.
- The **workers** are everything else: LLM agents (via files, never via an API call from
  the binary), fuzzers, symbolic-execution provers, the operator's shell. They produce
  artifacts and verdicts. The control plane decides whether a verdict *counts* — and its
  default answer is no.

The invariant that makes this worth building: **same inputs → same bytes.** Given pinned
clock and id streams, a campaign's artifacts are reproducible, and a machine can prove the
log was not edited. That is what makes the record admissible as evidence to a third party
(a program's triage team, a platform's arbitration, or a future version of ourselves).

### 1.3 The bet, stated plainly

> A deterministic, model-free bookkeeping core, wrapped around model-driven discovery and
> external provers, produces more *paid* critical findings per unit of agent time than
> either an unconstrained agent or a conventional static-analysis pipeline.

The honest status of that bet is in §9: the bookkeeping half is real and tested; the
discovery half is the weakest part of the system, and the project's own strategic plan
(§7) says so in its first sentence.

### 1.4 Explicit non-goals

Recorded so that a reviewer does not propose them as if they were oversights:

- **No model in the binary.** No API key, no HTTP call to an LLM, no prompt execution. The
  binary emits `needs_model` halts and consumes model output as validated files.
- **No SMT solver of our own, no symbolic-execution engine of our own.** Bounded provers
  (MiniCertora, Halmos) are integrated as external workers behind an exec profile, capped
  at evidence rung E3 unless a machine-checked artifact says otherwise.
- **No autopilot submissions.** Submissions are operator-gated; the tool can prepare an
  export and refuse to send it.
- **No finding-count rewards.** The framework deliberately refuses to optimize for the
  number of findings; it optimizes for closure.
- **No live Code4rena support** (historical corpus retained for dedup only), and no
  non-EVM coverage yet.

---

## 2. What the software is, concretely

### 2.1 Shape

| property | value (measured at `2771d466`) |
|---|---|
| language / module | Go 1.26.2 (toolchain go1.26.6), module `websec` |
| binary | `webv2`, one static binary, `CGO_ENABLED=0 -trimpath`, assets embedded via `go:embed` |
| Go files | 1,336 tracked (669 of them `_test.go`) |
| packages | 75 (`go list ./...`) |
| internal packages | 67 directories under `internal/` |
| CLI verbs | 90 registered subcommands (`register(command{...})` in `internal/cli/cmd_*.go`) |
| JSON schemas | 35 (`assets/schema/*.json`), all `additionalProperties: false` |
| audit sections | 19 registered; 16 render on a typical campaign (2 presence-gated) |
| embedded assets | prompts (21), playbooks (10), archetypes (13), taxonomy, protocol, evalsuite, runbook, schemas |
| third-party deps | 4: `santhosh-tekuri/jsonschema/v6`, `pelletier/go-toml/v2`, `gopkg.in/yaml.v3`, `golang.org/x/text` |
| commits | 637 on `main` |

**A discrepancy to note immediately:** the v16 working law says "stdlib only" (§6.2) while
`go.mod` requires four third-party modules. They are real dependencies, used in 13
non-test files: `jsonschema/v6` for schema validation and error rendering, `go-toml/v2`
for toolchain detection, `yaml.v3` for taxonomy/policy loading, and `x/text` for
Python-equivalent case folding (`strings.ToLower` diverges from Python `str.lower()` on
U+0130 and final sigma, which would break a byte-exact signature contract). The law should
read "no new dependency without a measured reason" — a reviewer should say which reading
they think is correct, because the tree and the prompt currently disagree.

### 2.2 The record: a hash-chained ledger

A campaign is a directory, `campaigns/<C-id>/`, containing:

```
events.jsonl          append-only hash-chained event log — the source of truth
campaign_state.json   the projection (a pure function of the log)
findings/F-*.json     one file per finding (schema-validated)
artifacts/            snapshots, models, indexes, harness scaffolds, reports
execs/                one directory per sandbox execution (EXEC-*)
report.md             the rendered report
```

Laws that hold across the codebase:

- **One writer per campaign.** A `flock`-based process lock; every writer takes it, and
  the review history records a lost-update bug class that was found and fixed precisely
  because one new writer forgot it (§10, item 12).
- **One event per mutation, and the projection unwinds if the log write fails.** A
  mutation that cannot be logged is rolled back; a state file is never ahead of the log.
- **The projection is derived, never authoritative.** `webv2 verify` re-walks the chain;
  `webv2 audit` reconciles the projection against the log.
- **Determinism pins.** `WEBV2_NOW`, `WEBV2_UUID`, `WEBV2_FINDING_IDS` pin the clock and
  the id stream so that a campaign can be replayed byte-for-byte in a test.
- **Artifacts are content-addressed and registered.** `state.register_artifact` logs the
  path exactly as passed, which is why fixtures must use campaign-relative paths.

The chain is a tamper *detector*, not a tamper *proof*: it proves the log was not edited
after the fact by anyone who does not also rewrite the chain. An external head-hash pin
was considered and refused (§6.5, refusal 13) — a reviewer should judge whether that
refusal was right.

### 2.3 The evidence ladder and the gates

Every finding has a status (`HYPOTHESIS → POSSIBLE → CONFIRMED`, plus `DISPROVED`,
`DUPLICATE`, `INFORMATIONAL`) and an evidence level E0–E7. Promotion is not a judgement
call made in prose; it is a set of machine-checked clauses:

- **`CLASS_CONFIRM_FLOOR`** maps a bug class to the evidence level CONFIRMED requires
  (e.g. `input-validation → E4`, most classes `E5`/`E6`). A class with no entry falls to
  `STATUS_FLOOR["CONFIRMED"] = E5` — the conservative default for an unknown string, not a
  judgment about the bug.
- **Confirmation clauses** (`check1`…`check15` in `internal/findings/`) are the actual
  gate: exploit-contract presence, economic-impact argument, adversarial-game clause,
  remediation shape, and so on. Each clause has a failure branch and a blocker message.
- **Waivers are singular.** There is exactly one `waive` path; every gate check can name a
  waiver, and an unattributed omission is not expressible.
- **Floors can be overridden per campaign, with a reason** (`floors set`), and the override
  is itself a ledger event that the audit reconciles. This exists because a class-floor
  gap was blocking a correct finding — and the override was the *honest* fix, where editing
  the global floor table would have been the dishonest one.
- **A reported loss is never laundered into `extractable_usd`.** This is a hard rule
  (§5.1, §9.3). If the framework cannot measure what an attacker could extract, it must
  say so; the schema was changed in v16 §5.1 precisely because the old one *forced* a
  fabricated number.

### 2.4 The audit

`webv2 audit <C>` renders 19 sections, in a contractual order, reconciling the record
against itself: `event_log`, `artifacts`, `execs`, `findings`, `projection`, `snapshots`,
`relations`, `floor_policy`, `stage_completions`, `baselines`, `invariant_verification`,
`sequence_coverage`, `probe_surface`, `unpriceable`, `eval` (presence-gated),
`price_table` (presence-gated), `v16_coverage`, `regression_suite` (presence-gated),
`exec_record_anchor` (presence-gated). A section that cannot render says so (`ErrSkip`) —
it never silently reports clean. An audit problem is a first-class output: the
`regression_suite` problem is *correctly red* today because no measured `extractable_usd`
exists (§9.3).

### 2.5 The CLI and the surface budget

91 verbs in seven families: campaign lifecycle (`init`, `scope`, `snap`, `model`, `plan`,
`ingest`, `move`, `mint`, `verdict`, `verify`, `impact`, `gate`, `complete`), deterministic
hunting surfaces (`index`, `sinks`, `prescreen`, `forkdiff`, `recency`, `probes`,
`relations`, `resemble`, `corpus-surface`, `dedup`, `prioritize`, `rank`, `brief`,
`report`), knowledge stores (`memory`, `publish`, `globalize`, `shared`, `ladder`,
`immunize`, `sft`), operational tooling (`doctor`, `env doctor`, `audit`, `execs`,
`budget`, `floors`, `price`, `cost`, `yields`, `run`, `selftest`), and the v1.6 additions
(`enforce`, `adjudicate`, `regress`, `trajectory`, `prompts`).

Two rules constrain growth:

- **Surface budget.** A new capability lands as a flag on an existing verb unless it is
  demonstrably unreachable from any command. The count is tracked (76 verbs on
  2026-09-10, 91 today) — a reviewer may reasonably ask whether the budget is being
  enforced or merely observed.
- **Byte-pinned CLI surfaces.** Help/usage/error text is asserted verbatim in tests, and a
  `--flag` name must appear quoted in the source. This makes the CLI contract testable; it
  also makes any CLI change expensive, which is the point.

### 2.6 The verification apparatus

This is the part of the project that is most unusual, and the part a reviewer should
stress-test: the claim "it works" is backed by machines, not by prose.

| gate | command | what it proves |
|---|---|---|
| self-check | `webv2 selftest [--full]` | embedded assets, a deterministic walkthrough, an in-process CLI audit; `--full` adds the suite (~2 s / ~30 s) |
| unit + integration | `go test ./... -count=1` | the whole in-process suite (669 test files) |
| golden suite | `scripts/golden.sh` | a deterministic recipe: exit codes, tree shape, event chain, rendered audit surface |
| RUNBOOK walkthrough | `scripts/runbook-walkthrough.sh` | every documented command, asserted against its exit code and output markers |
| full gate | `scripts/verify-full.sh` | 13 ordered fail-fast steps: vet, build, tests, race, determinism ×2, asset manifest, golden, crash smoke, legacy cross-audit, P1/P2/P3 CLI smokes, runbook walkthrough |
| real containers | `scripts/p2-docker-e2e.sh` | real `docker exec` (pass and fail) plus a real anvil sequence, and four `WEBV2_DOCKER_TESTS=1` tiers |
| dependency scan | `scripts/security-check.sh` | govulncheck; a missing scanner or a finding is `INCOMPLETE`/failed, never `PASS`, and every run prints the advisory-DB provenance and timestamp |
| release | `scripts/release.sh` | static binary, embedded assets, standalone, and the dependency scan as its final strict step |
| entropy gate | `pre-commit-gate/` + `.entropy-gate.toml` | pre-commit: blocks unconfigured languages, diffs over 1,200 staged lines, and low AI-slop scores; drives eslint/knip/dependency-cruiser/import-linter templates |
| legacy compatibility | `verify-full.sh` step 9 | the Go binary reads a Python-era campaign and renders all sections clean |

Two ambient fixtures (forge libs for the compile proof; a sibling `sharevault` checkout
for a corpus e2e) are *not* part of a default clone: those tests skip with a reason rather
than fail. A reviewer should note the asymmetry — the project prefers a visible skip over
a silent pass, and it treats "no scanner installed" as a failed check rather than a green
one.

### 2.7 Determinism and Python semantics

Because the legacy fixture must stay readable and byte-identical, the Go tree carries a
small emulation layer: `internal/jval` (order-preserving JSON value with canonical dump,
Python float repr, `json.dumps` escaping), `internal/validation` (`PyTruthy`, `PyRepr`,
round-half-even, schema error text matching the Python `jsonschema` library byte-for-byte),
and `x/text` case folding where Python's full case mapping differs. This is technical debt
with a purpose; it is also a place where a subtle divergence could hide. The cross-twin
oracle method that was used to prove parity is recorded in the project's learnings ledger.

---

## 3. What it does, end to end

### 3.1 The campaign lifecycle

A campaign is one program (an Immunefi/Cantina/etc. bounty) or one contest. The operator
drives it through the CLI; the binary writes the record.

```bash
./dist/webv2 --root . init  --program "Acme Immunefi"      # C-xxxxxxxx
./dist/webv2 --root . scope $CID --policy policy.json      # what is in scope, what pays
./dist/webv2 --root . snap  $CID ./target --deployment deployment.json
./dist/webv2 --root . model $CID model.json                # protocol model (actors, assets, invariants)
./dist/webv2 --root . index $CID --src target              # structural index of the source
./dist/webv2 --root . plan  $CID                           # the staged campaign plan
./dist/webv2 --root . ingest $CID --json-file finding.json # a hypothesis enters the record
./dist/webv2 --root . brief $CID                           # "what matters now"
./dist/webv2 --root . audit $CID                           # integrity audit
```

Every step is a ledger event plus a projection update. Nothing is inferred from the
filesystem: if it is not in the log, it did not happen.

### 3.2 The pipeline stages (the v1.6 target)

The specification defines a 14-stage pipeline (§5.2). What exists today, stage by stage
(this is the honest mapping; §9 quantifies it):

| stage | what it is | state in the tree |
|---|---|---|
| 1 | target scoring (programs, not code) | **absent** |
| 2 | scope + snapshot: policy load, commit/solc pin, bytecode-vs-source verify, `scope --check` | scope/snap exist; `--check` absent |
| 3 | index + config reads (`cast` reads of caps, oracles, quorums, roles) | index exists; config reads partial |
| 4 | field-validation matrix (obligations for attacker-writable fields read by a terminal path) | **absent** (raw material exists in `structidx/enforcement.go`) |
| 5 | sweep: Slither/Aderyn/Semgrep, upgradeability, storage-layout diff → hypotheses only | loaders exist (real-shape), advisory only |
| 6 | differential + clone sweep | `forkdiff` exists; cross-instance clone sweep absent |
| 7 | invariant authoring (protocol model) | exists (`model`, `invariants`) |
| 7a | broad fuzz smoke (Chimera-style) | **absent** |
| 8 | discovery: probes + lenses → hypotheses | **exists** (6 probe axes, 4 lenses, divergence gate) |
| 9 | severity, provisional pass | **absent** (severity is recomputed live, not event-sourced) |
| 10 | verification: deep fuzz, Halmos, fork PoC to `MAXIMIZED` | exec/harness exist; the maximization loop is **absent** |
| 11 | severity, final pass (authoritative) | **absent** |
| 12 | adjudication: dedup, dual-arm critic, bypass analysis | dedup exists; dual-arm critic and bypass are **absent** |
| 13 | report: emission gate (`status ∈ {CONFIRMED, CHAIN}` + final pass) | report exists; gate is status-half only |
| 14 | (spec Part 3a) the regression suite / eval store | partially exists (19 cases, a control target, a scorecard) |

**Read this table carefully**: it is the single most important fact in this document. The
control plane is built and tested; the *hunting* half of the specification is mostly
unbuilt. §7 is the project's own plan for closing that gap, and §12.3 asks whether the
plan's ordering is right.

### 3.3 The three real campaigns so far

The framework has been run against real targets three times, and each run produced a
triage document (`docs/feedback-triage*.md`, kept as history):

| campaign | target | outcome | what it taught |
|---|---|---|---|
| `C-66191ec8cd` | Morph L2 (pinned vulnerable commit) | 537 events, 52 findings, 23 critic-confirmed, **0 confirmed** | generation worked, closure failed — the origin of the current architecture |
| `C-f4e27261f7` (morph r2) | Morph L2, second pass | triage fully closed | fork-ladder and record-trust defects |
| `C-e0fc3ecd17` (morph r3) | Morph L2, third pass | triage fully closed (16 of 18 rows mapped to commits; 2 refuted/by design) | feedback loop discipline |
| `C-5e04a99520` | Morph L2, latest | at HEAD: 31 findings, 9 exec dirs, 2 CONFIRMED (E4+E6), phase COMPLETE, 22 `bounty.gate` events | the strategic plan's "0 confirmed" headline is stale |

The two gold cases (`G-01`, `G-02`, from the answer key) scored **0/2**: G-02 was found at
E1 only, G-01 was missed in every scored round. That number is the honest measure of
discovery power today.

---

## 4. Where it came from (and why that matters to a reviewer)

### 4.1 The Python twin, and its retirement

The project began as a Python implementation (`web3sec-final`, the "twin"). A decision was
taken to port it to Go — for test speed (the Python suite was heavy), for a single static
binary with embedded assets, and for a type system that makes the record's shape
checkable. The port ran as numbered waves (P0…P4) with a **byte-exactness contract**: the
Go binary had to reproduce the Python output byte-for-byte on the same inputs, verified by
cross-implementation oracle vectors.

The twin was retired at the **P4 cutover on 2026-09-09**. The promise that survives is
reader compatibility: campaign directories written by the Python reference stay readable
forever, kept honest by a committed legacy fixture that `verify-full.sh` step 9 audits with
the Go binary.

### 4.2 What the port left behind

A leanness review (`docs/LEANNESS_REVIEW.md`, 2026-09-10) found three kinds of leftover
cost: a parity tax on a retired twin, ported-but-never-wired modules (~4.4k LOC of dead
Go kept alive by 1:1 accounting), and docs describing a different repository. The
port-scaffolding removal plan is recorded; the residue is visible in the tree as
`DEPRECATED` headers on `wilson`, `backtest`, `classweights` — modules the v1.6 spec
*cuts*, guarded (not deleted) by an allowlist test. A reviewer may ask whether a cut list
that leaves the code importable is a decision or a postponement (§10, item 3).

### 4.3 The improvement waves

After the cutover, work proceeded as named waves, each with a plan under
`docs/superpowers/plans/`, a landing record in `docs/IMPROVEMENTS.md`, and adversarial
review. As of this writing: **A–D, G (18 items), I, J, L, M, N, R and a production-readiness
wave have landed**; **E is deferred** (surface budget) except E5 and E1/E2; **K is parked**
(free prover backends — superseded by the MiniCertora integration, §8); **H16 is the only
open H item** (a `%10` guard in two test helpers).

The waves that matter most for a reviewer:

- **A (precision & scope)** — the operator found that of 52 critic-confirmed findings, 23
  were wrong. Fixes: an `accepted_risks[]` policy field with its own check and waivable
  blocker, an in-code acknowledgement scanner (±12 lines), a precision budget, and a
  mandatory paid-exploitability argument.
- **B (liveness & chains)** — the framework had no way to price a *liveness* failure (a
  chain freeze), only theft. `LIVENESS_LOSS` entered the taxonomy with a
  protocol-solvency blast-radius weight, plus a mandatory adversarial-game clause.
- **C (deterministic capabilities)** — probe archetypes became pure functions; a
  write-site/read-site enforcement-timing table (`webv2 enforce`); a primitive-symmetry
  matrix.
- **D (report honesty)** — dual counting (`critic-confirmed` vs `evidence-confirmed`), a
  supersession reconcile, dedup signatures, and a registry↔runbook drift test.
- **I (external feedback)** — `deployed_at` plus a temporal/near-duplicate partition gate,
  real-shape SAST loaders with recall floors, acceptance score-band precision, SWC aliases,
  an embargoed disclosure bundle.
- **M/N/R** — operator friction and recall: `scope --example`, `snap --dry-run`,
  `prompts {list,show}`, remediation hints, `ingest --lint`, sentinel-form rows, a
  `--passes` gate, discovery-slot reform, diversity union.

### 4.4 Why the documentation is large

Every wave, review round and refusal is written down, because the project's most valuable
asset is not the code — it is the record of *which claims survived checking*. Two reviewer
retractions are retained as doctrine: a "verified" claim about dataset cadence and a
proposed capability whose platform premise turned out to be false. The rule that follows
(D7) is that verification is repeatable and adoption is retractable.

The cost is real: `docs/IMPROVEMENTS.md` alone is 5,236 lines. It is being compacted into
a wave ledger plus a metrics file, with the full text preserved in git history. A reviewer
should not read it end to end; §Appendix C says what to read instead.

---

## 5. Where we are going: the v1.6 specification

`framework-plan-v1.6.md` (478 lines, at the repo root) is the product specification. It
consolidates v1.0–v1.5 and four external review rounds into one re-baselined document.
**Note for the reviewer: this file is currently untracked in git.** It is cited by 15 Go
files and by the gate reports; it should be committed. (Tracked-or-not is itself a finding
we are reporting rather than hiding.)

### 5.1 The nine decisions that shape everything (D1–D9)

| # | decision |
|---|---|
| D1 | Keep the record spine and the full discovery/probe layer (six probes, four lenses, divergence gate, four-state closure). The field evidence showed generation worked and closure failed. |
| D2 | Severity is a **computed, event-sourced property**, not a field: per-platform policy data, two immutable passes (provisional and final), the projection carries `severity_authoritative_pass`, the final pass gates submission, and a policy reload never rewrites an event. |
| D3 | Gate *hardness* scales with gate cost; gate *funding* scales with decidability and class-relative metric headroom — **never** with the provisional estimate. An estimate must not gate the funding of the evidence that would correct it. |
| D4 | Ship the first campaign before the framework is finished: a shadow campaign with manually-computed severity (provenance-quarantined) and the first engine-scored submission around Phase 5. Shadow platform: Immunefi only. |
| D5 | Postmortems are ledger input, not prose. The regression suite is a standing operation. |
| D6 | A hardening induced from one failure is a hypothesis about that failure's *class* until checked against cases it was not built from. Blast radius scales with the layer. |
| D7 | External proposals are judged on merits against what is built and tested — not adopted for being well-argued, not rejected for arriving as criticism. |
| D8 | The regression suite measures **closure discipline and rediscovery** on disclosed, already-judged contests. It structurally cannot measure novelty or duplicate rate, which is what actually costs money. Every number it produces is labelled as such and never reported as a detection rate. |
| D9 | **Freeze.** No further review rounds until a Phase 3 regression run exists; the specification changes only in response to measured defects, each change recorded with the measurement that motivated it. |

D9 is why the spec has not been revised in response to this brief. It is also why a
reviewer's most useful contribution may be a *measurement proposal*, not a spec edit.

### 5.2 The severity engine (C4) — the largest unbuilt surface

Severity is specified as a pure function of seven inputs — `directness`, `permanence`,
`role_obtainable`, `capital_available`, `magnitude`, `replayable`, `preconditions` — with
rubric-declared composition (`band-by-impact-then-cap | threshold-lookup | full-table`),
modifier semantics (cap vs downgrade), impact transforms (e.g. Sherlock's replay rule
computing rounds-to-exhaustion from demonstrated per-round extraction), and admissibility
filters (a privileged-role finding yields no payable finding). Policy splits into
`platform_rubric` (per platform) and `program_scope` (per program).

Two further rules matter:

- **Two passes.** The provisional pass emits a band plus a *typed magnitude bound* that is
  funding-signal only and never report-visible. The final pass runs on `MAXIMIZED` evidence
  and is authoritative; the report generator refuses a provisional-only finding.
- **Demonstrated ≠ computed ≠ reported.** §2.4 makes these three distinct quantities that
  may never be conflated, and a *reported* loss is never laundered into `extractable_usd`.

In the shipped tree today, severity is **recomputed live on every read**
(`bounty.SeverityFor`) and there is no `severity.*` event, no `rescore`, no stale-severity
flag, and no `submit` verb. This is the biggest gap between spec and code (§9.4).

### 5.3 The discovery surface (C5) and negative closure

The discovery surface is the part that exists: six probe axes, four lenses (L-01…L-04), a
divergence gate, and four-state closure. What the spec adds is the **negative space**:

- **§C5.1 obligation generator** — a write-site × terminal-read join producing the field
  obligations of stage 4. Raw material exists in `structidx/enforcement.go`; the generator
  does not.
- **§C5.2 consensus-critical closure** — a consensus-critical row cannot be closed by
  prose. It closes as `no-violating-state-constructible` (`closed-by-failed-construction`),
  with mechanically-derived ranked and truncated search spaces (hand-authored search
  spaces are refused), per-obligation effort floors, tranche-size distribution auditing,
  and a third held-out control.
- The anti-laundering controls exist because "we looked and found nothing" is the easiest
  claim in this domain to fake, including to oneself.

### 5.4 Targeting (C6), adjudication (C7), policy and report (C9)

- **C6**: target scoring (programs, not code), scope checking, cross-instance clone sweeps
  (a $292M drain is cited where a 1-of-1 DVN was shared by ~47% of applications), an
  out-of-language scope ledger, abandonment records with nulls rather than silence.
- **C7**: a **dual-arm hostile critic** — a theft-first arm and a liveness-first arm, each
  with a mandatory adversarial template; `DISPROVED` requires both arms; disagreement
  promotes the finding to `POSSIBLE` and opens a mandatory obligation. Plus external-corpus
  dedup with an excluded-disclosure duplicate-risk mode, and a bypass statement on every
  confirmed finding. Today there is a single-arm critic and no bypass statement.
- **C9**: policy authoring (`policy init`), per-platform report renderers, and a
  `policy.amended` cause taxonomy that routes a downgrade to rubric/scope/evidence/review.

### 5.5 The regression suite (Part 3a) and the eval store

The spec's measurement plan: take ScaBench `curated-2025-08-18` (114 high findings, 31
projects), bucket labels onto the taxonomy, pick targets by greedy set-cover weighted by
gold-finding count, constrain to four target shapes, add the diagnosed Morph campaign as
training data and one already-exploited control target; hold out by project, pin commits
before revealing answers, grep for contamination and fail the snapshot if found, and
double-transcribe keys with a recorded disagreement rate.

The honest state: the ScaBench harness was deleted in the leanness pass; the eval store
holds 19 hand-planted cases (17 exploitable, 2 clean controls, 13 dev / 6 held-out); one
control target exists end to end; a scorecard instrument exists and is self-tested. A
reviewer should note the tension the spec itself acknowledges: **at six held-out rows, a
statistical claim like "the new weights improve" is unreachable**, which is why the
calibration weights ship neutral.

### 5.6 The build order (Phases 0–9)

Phase 0 regression suite (2 weeks) → Phase 1 record+schema (1–2 weeks) → Phase 2
maximization spike (3–4 weeks) → Phase 2b shadow campaign (weeks 4–9) → Phase 3 regression
run (weeks 5–9) → Phase 4 (10–12) → Phase 5 first engine-scored submission (13–15) → Phase
6–8 → Phase 9. The plan itself warns that Phase 2b and Phase 3 contend for the same
operator weeks: *"Either Phase 2b stays inside its one-program/one-contract scope — days —
or Phase 3 slips."*

---

## 6. The current phase: v16

### 6.1 What v16 is

v16 is the phase that closes the gap between the shipped binary and the v1.6 spec, **in
spec build order**. Its whole state is one file, `docs/gates/v16-prompt.md` — the only
prompt file, maintained as work proceeds: finished items move from the queue (§5) into the
ledger (§3) with their commit sha.

### 6.2 The standing laws

In force for every code change:

- Go floor `go 1.26.2`, module `websec`; **stdlib only** (see §2.1 for the discrepancy).
- **TDD.** Plain Go tests, same package, `t.TempDir()`, no Docker, no network, no model.
- **Gates:** `go test ./... -count=1 -p 2`, then `scripts/verify-full.sh`, plus gofmt /
  `go vet` / `golangci-lint`.
- **Byte-pinned CLI surfaces.** Help/usage/error text asserted verbatim; a `--flag` name
  must appear quoted in `internal/cli/*.go`.
- **Ledger law.** One hash-chained event per mutation; projection unwind on log-write
  failure.
- **Determinism pins.** `WEBV2_NOW` / `WEBV2_UUID` / `WEBV2_FINDING_IDS`; never
  `time.Now()` or a raw UUID in a new record.
- **Schema discipline.** `additionalProperties: false`; a new key means a schema edit plus
  `validation.Validate(v, name, 1)` on the write path.
- **Asset manifest.** Any edit under `assets/` requires
  `python3 scripts/sync-asset-manifest.py`.
- **D9 freeze.** Spec changes only on measurement.
- **§2.4 replayability.** Demonstrated vs computed vs reported are three distinct
  quantities; a reported loss is never laundered into `extractable_usd`.
- **Refusal is a valid outcome.** *Measured, or refused with a recorded reason.* An
  unmeasured spike is refused rather than estimated; the refusal is itself evidence.
- **Model routing.** Implementation on one model, review on a different one; adversarial
  review on anything that changes code or a record's claims. This rule has earned its keep
  every time — it refuted a central claim and found tests passing for the wrong reason.

### 6.3 The v16 work queue, and its status

| item | what it is | status |
|---|---|---|
| **§5.1** | **The handoff schema fabrication trap.** `assets/schema/regression_target.schema.json` required `extractable_usd` as a strictly positive number, so closing the audit problem *required inventing a figure*. The codebase already had the right shape elsewhere (`UnpriceableDecision`: `priceable:false` plus a non-blank ceiling basis). | **LANDED** `911be0a9`: `priceable` / `ceiling` / `reason` / `recorded_by`, with an `allOf`/`if`/`then` forbidding `extractable_usd` under `priceable:false`. Note the residual a reviewer should check: the schema's `reason` floor is `minLength: 1` while the write path (`checkUnpriceableHandoff`) demands ≥10 characters — the schema alone does not enforce what the code does. |
| **§5.2** | Resolve the `codebase_id` vs `project_id` gap (blocks Step 7 and Task 4) by *counting usages* in the codebase — a fact, not a judgement. | in progress by the parallel agent; the measurement made during this brief: `codebase_id`/`CodebaseID` appears 4× in Go source, `project_id`/`ProjectID` 0×; the row schema's key is `project`, a third spelling. |
| **§5.3** | P0 Task 3: the spec's own `containsWord` closes both word boundaries, making every stem phrase in its own table unmatchable — **its own test fails under it**. Fix the matcher, then **re-measure Steps 1–6** and report whether any result changes. Two HIGH review defects (both tests passing for the wrong reason) must be dispositioned. | open |
| **§5.4** | P0 Task 3 Step 7, then Task 4 (weighted set-cover). P0 stays on the critical path: the control target supplies the true side only; the false side needs P0's fresh targets. | open |
| **§5.5** | Build P5 — the runner-level fork pin. Justification is **silent pruning** (a pruned node returns `0x` for a contract that exists, indistinguishable from "not deployed yet"), *not* "no archive endpoint works" — that overstatement was corrected and must not reappear. | scoped only (`9ba6bb12`); the build is refused for now |

### 6.4 What v16 has already established (the §3 ledger, abridged)

- **The E5-floor discovery.** `RequiredLevelFor("CONFIRMED", "input-validation")` misses
  `CLASS_CONFIRM_FLOOR` and falls through to `STATUS_FLOOR["CONFIRMED"] = E5`. Because
  `bug_class` is free-form, E5 was the conservative default for an unknown *string*, not a
  judgment about absent-guard bugs. Fixed with a **campaign floor override** (a ledger
  event), not a spec change. Consequence: at E4 this target needs no fork to reach
  CONFIRMED, so the fork spike is *off the confirmation path*.
- **No ladder-adjacency rule exists.** "Monotonic, no skipping" is a comment only;
  `AddEvidence` performs no skip check. E0 → E4 on a single item is legal. (A reviewer
  should judge whether that is a bug or a feature.)
- **Route 2** — the absent-guard mint path: `expected_outcome: pass|fail` (absent means
  `pass`, so every pre-existing record keeps exact bytes), `expected_failure` required
  under `fail` and forbidden under `pass`, with a signature rule (8-character floor, the
  literal `FAIL` banned, forge-like commands must carry `[FAIL`). Both keys live on the
  *exec record*, never on the evidence item — declaring the expectation at mint time would
  be writing it after seeing the result.
- **The exec-record anchor.** An `exec_record_sha256` digest binds a mutable
  `exec_record.json` to its event, with a mandatory algorithm label, fail-open when absent
  and fail-closed when present. Its **provenance limit** is recorded: the anchor proves the
  record is contemporaneous with its own run, *not* that the operator was blind to the
  result. A reviewer should push on this: it is the honest boundary of the strongest
  integrity claim in the system.
- **The control target reached CONFIRMED at E4** with a full history of reasons — the
  first CONFIRMED finding on a real protocol, obtained on a *known* bug (post-hoc), which
  is why it is a control and not a discovery result.
- **The docker section count was proved by enumeration** (19 registered − 3 presence-gated
  = 16 rendered), because a reviewer asked whether the pinned number had ever been
  observed. It had not; now it is derived.

### 6.5 The refusal ledger

Refusals are first-class outcomes here. The v16 phase alone records 22 of them; the ones a
reviewer should examine:

1. **ScaBench's baseline runner and the Nethermind judge arm** — refused: no API key.
2. **The Exactly Protocol P1 handoff** — refused: no CONFIRMED finding and no measured
   `extractable_usd`.
3. **Reported loss → `extractable_usd`** — forbidden by §2.4; `$7.6M` is "a ceiling at
   best", and the incident's own numbers spread 65% ($7.3M / $7.6M / ~$12.04M).
4. **`extractable_usd` in the fork spike** — refused: no attack was run; *"nothing was
   lost, so there is no loss to measure."*
5. **Fail-closed anchoring** — rejected on four measured grounds (it would redden the
   legacy step, invalidate a frozen fixture, break two seeding harnesses, and retroactively
   invalidate history) — fail-open adopted permanently, with an **accepted residual**: 
   deleting the carrier event *and* editing the projection produces no audit row at all.
6. **"Every cited exec must be anchored"** — rejected for the same reason.
7. **Field carry instead of a digest** — rejected; the canonical encoding label is
   mandatory (an unlabelled hash is not evidence).
8. **A ladder-adjacency rule** — does not exist, deliberately.
9. **The P5 fork-pin build** — refused for now: the endpoint is not ours, and a
   precondition that fails on rate limits is worse than none.
10. **A CLI verb for caller-typed E0–E3 evidence** — a real gap, deliberately off the
    current path.

The doctrine behind the ledger: *an unmeasured spike is refused rather than estimated, and
the refusal is itself evidence.* A reviewer who disagrees with a refusal should say which
one and what measurement would change it — that is exactly the currency this project
trades in.

### 6.6 What is happening right now

A second agent is executing the same queue in this working tree, in parallel with this
document. At the time of writing it has landed §5.1 (`911be0a9`) and the prompt update
(`2771d466`), and has uncommitted work in flight on the derived-label rule table
(`internal/regression/labels.go`, `assets/schema/regression_labels.schema.json`) — i.e.
§5.2/§5.3. **A reviewer should treat the tree as a moving target** and re-read
`docs/gates/v16-prompt.md` §3/§5 rather than trusting this table's status column.

---

## 7. The strategic gap: what the project's own research says

`docs/CRITICAL_HUNTING_PLAN.md` (856 lines, 2026-09-21) is the most important document in
the repository for a reviewer of the *product* (as opposed to the record machinery). It is
a design proposal written as a research pass over this repository plus the real-target
evidence in a sibling workspace. Its opening argument, in its own words:

> `webv2` is an unusually rigorous **bookkeeping** machine: hash-chained state,
> schema-first writes, deterministic gates, evidence floors, a hostile critic, a
> mechanical probe surface, and a refusal to let a model promote its own finding. That is
> real and rare. But **not one critical has ever been confirmed with it**.

That was written before the v16 control target reached CONFIRMED — and the control target
is a *known* bug reproduced post-hoc, so the strategic claim still stands: **discovery
power is unproven.**

### 7.1 The six structural causes (C1–C6)

| # | cause | mechanism |
|---|---|---|
| **C1** | **The framework verifies attacks; it does not make them.** | `exec` runs an operator-written command; `verify --scaffold` fills a model-written body; the provers are E3-capped and host-run. Nothing schedules, synthesizes, funds, or parameterizes an exploit. Because the CONFIRMED gate needs an EXEC at the class floor, a missing exploit kills the finding before the gate — and `floors set` becomes the release valve that launders weak evidence into CONFIRMED. |
| **C2** | **The index sees names, not values or flows.** | Per function it carries visibility, modifiers, selector, `reads_storage`/`writes_storage` name sets, call edges, delegatecalls — but no expressions, arithmetic order, parameter names/values, state-variable types/order/slots, loops, events, or balance deltas. Exactly two classes are declared unprobeable (`precision-rounding`, `signature-replay`). |
| **C3** | **The model boundary is a halt.** | `run` exits at the first model stage with a `needs_model` report; there is no drop-file convention and no batching. Discovery is where hypotheses are born and where the pipeline stopped. (A `run --feed` drop-file path has since shipped.) |
| **C4** | **Hypothesis generation is capped by the prior library.** | 25 canonical classes, 10 playbooks; 9 classes have no prior at all, so the proposer works from one-line cards. Prompt holes were measured: the proposer system prompt makes the attacker optional; the critic prompt names `economic_impact` fields but never asks the critic to check them. |
| **C5** | **The feedback loop cannot certify anything.** | 19 hand-planted fixtures, 2 gold cases scored 0/2, one control, a backtest over pseudo-findings, a Wilson lower-bound verdict. At 6 held-out rows the comparison the calibration needs is unreachable, so weights stay neutral: the backtest certifies a store-ranking signal, not the pipeline. |
| **C6** | **The paid-bounty half has never run against a real program.** | Severity matching exact-matches taxonomy strings; real policy files name non-canonical classes (`drain`, `theft-of-funds`); the Immunefi export renders the PoC as evidence lines rather than runnable commands; there is no payout/EV model. |

### 7.2 The plan it proposes (Waves 0–5)

Ordering rule: **unblock → produce evidence → sharpen → tune → convert.**

- **Wave 0 — unblock the loop (days).** Auto-schedule reproduction execs per class floor;
  a drop-file transport for model stages; policy lint + provisional severity with an alias
  map for non-canonical class names; anchor-cluster dedup; an adjudication verb; a
  phase-report telemetry verb. Acceptance: `execs/` non-empty, ≥1 `POSSIBLE` carrying an
  EXEC citation, zero unknown-class warnings.
- **Wave 1 — the exploit factory (highest expected value in the document).** A Foundry PoC
  synthesizer (pinned solc/fork scaffold, attacker template, a body region, `forge test`),
  a funding primitive (flash-loan block, whale-prank fallback), measured impact via balance
  snapshots, an evidence-kind floor (`local-poc ∪ fork-poc`), E4+ mints that must cite a
  machine-checked artifact, a lifecycle/liveness archetype, `adversarial-game` in the
  confirmation clauses, and reachability-grounded floor overrides. Rationale: a runnable
  PoC is mandatory for payout.
- **Wave 2 — give the index value-level vision.** An arithmetic spine mini-AST (operator
  order, operand kinds, literals) enabling rounding-direction and denominator-movable
  probes; balance-delta token flow; a storage-layout extractor (typed ordered state
  variables, proxy collision, EIP-1967, initializer replay); parameter names and events;
  a loop census; an oracle-staleness census; economic canaries.
- **Wave 3 — hypothesis generation.** Six new classes with playbook/floor/canonicalization/
  gold-anchor each (`amm-invariant`, `delegatecall-storage`, `l2-fee-oracle`,
  `governance-flashloan`, `account-abstraction`, `fee-accrual-accounting`), the 15 missing
  playbooks, a class-boundary document, a mandatory strongest-attacker arm, a profit-model
  sentence, critic numeric cross-examination, EV ranking.
- **Wave 4 — measurement that can certify improvement.** A ≥100-case dataset-sourced gold
  set with an incident-date partition (n≈40+ held-out so that a statistical comparison is
  reachable), a clean-corpus false-positive suite with per-lane confidence intervals, cost
  and time joined to gold anchors, an end-to-end backtest, severity calibration, a rolling
  real-target holdout (eight ranked targets), a ship gate, and a duplicate-pressure proxy.
- **Wave 5 — convert to paid bounties.** A payout model in the policy schema, one-root-cause
  enforcement at export, a self-contained export, submission provenance, platform-shaped
  exports, and one Morph finding driven end to end in the field.

Acceptance criteria: CONFIRMED 0→≥1 with a fork PoC; execs 0→≥ hypotheses triaged;
held-out 6→≥40; real targets 1 (0/2)→≥5; `bounty.gate` 0→≥1.

### 7.3 The anti-goals it records

No symbolic-execution engine or own SMT solver ("buy bounded results, never own the
solver"); no non-EVM or multi-language coverage yet; do not let `floors set` become the
release valve; no autopilot submissions; do not reward finding counts; keep the friction
that works (probe disposition gates, the `--passes` sentinel).

### 7.4 The four decisions the plan needs from the operator

1. **Fork RPC access** — Waves 1, 2.7 and 4.6 all need a reliable archive node at pinned
   historical blocks. Without it, E5/E6 stays theoretical and `floors set` remains the
   release valve. *This is the single biggest external dependency in the project.*
2. **Corpus ingestion licence/scope** — may we ingest public exploit PoCs and contest
   judge verdicts into a committed eval store? (Answer keys stay eval-side, never in a
   campaign context bundle.)
3. **Which three targets are the first holdout** — recommendation: Morph (rank 1, already
   pinned), Idle, LoopFi.
4. **Autonomy level** — the plan assumes hypotheses and execs are automatic, while status
   changes, submissions and memory stay human-gated.

### 7.5 A caveat we are reporting on our own plan

The plan's §2 "measured state of the union" is **stale at HEAD**, and its headline rests on
it. It says the live campaign holds "31 findings, all HYPOTHESIS, 0 execs, 0 CONFIRMED,
phase DISCOVERY"; at HEAD that campaign holds 31 findings across five statuses, **9 exec
directories, 2 CONFIRMED**, phase COMPLETE, 570 events including 22 `bounty.gate` rows.
Wave 0.2 also proposes building a feed transport that has since shipped. And C6's
"leading space" claim (`" griefing-persistent"`) is wrong — the policy file has no space.
The *diagnosis* survives all three corrections; the *numbers* do not. Treat the plan as a
hypothesis document that needs re-measurement before it is executed, which is what D9
requires anyway.

---

## 8. The prover lane: MiniCertora and MiniProver

Two external Python tools are integrated as workers. Neither is in this repository.

### 8.1 The three-service split

```
 webv2 (Go)                    miniprover (Python)            minicertora (Python)
 ─────────────────────         ─────────────────────          ────────────────────
 control plane                 auto-prover                    bounded verifier
 owns the INV-* ledger,        LLM agents author .mspec       solc --ir → Yul CFG
 invariant_links.json,         properties and drive           → SMT → z3/cvc5;
 the E0–E7 ladder, budgets,    minicertora in a               one JSON line per rule
 every event                   verify/revise loop
```

Ownership is strict: verdict JSON lines belong to minicertora, `reports/report.json`
belongs to miniprover, `INV.mspec` belongs to webv2. No repo merging, no shared state
beyond files each service owns. The one-writer law is stated as: *"minicertora answers
queries; webv2 writes events."*

### 8.2 The proof loop

```bash
webv2 brief  $CID                                        # what is unproven
webv2 verify $CID --scaffold minicertora --invariant INV-7
webv2 exec   $CID --profile minicertora --command \
  'minicertora <C.sol> artifacts/harness/INV-7/INV.mspec --solc-path /abs/solc --loop-bound 4 --timeout-ms 30000'
webv2 verify $CID --harness-result INV-7 --exec EXEC-12 --kind minicertora
```

The scaffold pins the rule header; the model writes **only** between start/end markers, and
`Validate` re-renders the scaffold and refuses any byte moved outside that window (a
weakened `<=` → `>=` is refused as `scaffold-degraded`). Attribution is an exact string
match on the scaffold-owned rule name. A run emits `harness_scaffold` and `harness_run`
events — "zero new event types, zero new verbs and no new `verify` flags".

### 8.3 The verdict vocabulary (the honest part)

- **Rungs (3, never renumbered):** `counterexample`, `proved-bounded`, `inconclusive`.
- **Exit-code law:** 0 = all PROVEN, 1 = VIOLATED, 2 = UNKNOWN/refusal/tool error; worst
  wins. Exit codes are tripwires, never verdicts.
- **Refusal reasons: a closed set of exactly 25**, as data, classed as `escalate-bound`,
  `escalate-flag`, `escalate-solver`, `spec-rewrite`, `honest-refusal` (12 codes),
  `tool-error`, `model-bug`, `witness-triage`.
- **Fail-open to inconclusive:** a malformed line, an abort, zero or two attributed lines,
  or an exit/verdict disagreement yields `inconclusive` and a null sidecar — never a
  silent promotion.
- **Hard caps:** the host profile is E3; it can never back E4+. `PROVEN-UNBOUNDED` is
  refused (invariants are one-step induction only), multi-contract specs are refused,
  auto-attribution is refused, and the trust-relaxing flags are never passed in generated
  commands.
- **Zero gate weight** until a backtest says the lane improves. The scorecard's self-test
  proves the *instrument*, not the prover; operator runs are data, not gate moves.
- **Honest labels:** the record says `host (unconfined — nothing enforces network-off)`
  rather than claiming a sandbox boundary it does not have.

### 8.4 MiniProver: the host contract

webv2 **never launches the prover**; it consumes one file, `reports/report.json`, through
`verify --autoprove INV-x --property TITLE --report PATH [--exec EXEC-x]`, and refuses on
a long list of conditions, all exit 2, in gate order:

| refusal | reason |
|---|---|
| `schema_version` not `1.x` | the contract changed; no best-effort |
| non-empty `publish_problems` | binding it would launder the prover's own veto, even when `published` is true |
| `published: false` | a skip is not a result |
| no `property_outcomes` map, or the named property absent | titles are agent-authored, so a guess credits another row |
| non-empty `review_error` | an unmade review is not a cleared one |
| SUSPECT finding on this property | PROVEN next to SUSPECT; fail-closed on shape |
| `flags.loop_bound` < 1 or non-integer | k=0 checks only the initial state |
| rollup not literally `PROVEN`/`VIOLATED` | `PROVEN_VACUOUS`, `PROVEN_CONDITIONAL`, `OUT_OF_FRAGMENT`, `INCONCLUSIVE`, `REFUSED`, `UNATTRIBUTED` all map to inconclusive |
| PROVEN with empty/disagreeing per-rule lines; VIOLATED with no violated line | per-rule lines are the authority |

A **ledger mode** closes the webv2→prover gap: `--invariants PATH` feeds the prover the
campaign's own invariant ledger (`id` → title verbatim, `statement` → description, blank
statement raises — the tool never invents the claim), and the report records
`attribution.mode == "ledger"`.

### 8.5 The measured weakness of this lane

Run 1 of the prover scorecard: **19 cases, 2 detected, 0 proven-silence, 7 refused, 9 in
neither state**. Run 2: 1 detected, 1 proven-silence, 3 refused cases. That is thin reach,
and the project records it as such. A reviewer should treat "the prover lane works" as
*unproven* and say what would prove it.

### 8.6 Known doc-versus-code drift in this area

The architecture document is a proposal with a landing-notes appendix, and where the two
disagree the landing notes win. Recorded drift a reviewer can verify: the doc says the
`solc` mismatch refusal "is still design" (it is closed); it says `Validate` is "still not
wired into the run path" (it is); it keys attribution on `INV_<n>__slug` (the code uses
`inv_<n>`); it names a 10-key sidecar (the shipped one has 12); it calls the filesystem
`readonly` where the record deliberately discloses "unconfined". None of these are
behavioural bugs; all of them are traps for a reader who trusts the prose over the code.

---

## 9. The honest state of the union

This section exists because the project's own doctrine requires it, and because a reviewer
who cannot tell verified from asserted cannot review anything.

### 9.1 Verified by machine (a gate runs it, and the gate can fail)

- **Determinism.** The golden suite runs the same recipe twice and compares bytes; a
  mutated output string turns the gate red (this was tested by mutating, not assumed).
- **Ledger integrity.** The chain verifies; the projection is reconciled against the log;
  a torn log is detected (and, per J8, hand-recoverable — there is deliberately *no* repair
  verb).
- **Legacy compatibility.** The Go binary reads a Python-era campaign and renders every
  section clean (step 9 of the full gate).
- **Asset integrity.** Every embedded asset is pinned by a SHA-256 manifest; the manifest
  test fails on drift.
- **CLI contract.** Help/usage/error text is asserted verbatim; the RUNBOOK walkthrough
  executes every documented command and asserts its exit code and output markers.
- **Dependencies.** govulncheck runs on every release; a missing scanner or a finding is
  `INCOMPLETE`, never `PASS`, and each run prints its advisory-DB provenance.
- **Release.** A static, stripped, standalone binary is built and smoke-run from another
  directory.

### 9.2 Verified by one measurement (true once, not yet re-measured)

- The **docker section count** (16 rendered of 19 registered) — derived by enumeration,
  never observed live (no Docker in the authoring environment).
- The **control target's** facts — proxy/impl addresses, bytecode sizes, block heights —
  measured on one endpoint, at one time. The repoint height and the "three transactions"
  fact each corrected an earlier wrong claim.
- The **exec-record anchor's** digest — recomputed independently in Python and matched.
- **Route 2's** signature rule — refuted once by review, then re-specified and re-measured
  against pre-commit messages byte-for-byte.
- The **eval suite's** 19/19 self-score and the 2/2 gold recall — measured on hand-planted
  fixtures, which the project explicitly refuses to call a detection rate.

### 9.3 Refused, or unproven, and reported as such

- **No measured `extractable_usd` exists anywhere in the project.** The fork spike refused
  it because no attack was run; the incident's reported loss is a *ceiling*, not a
  measurement, and laundering it is forbidden. Consequence: the `regression_suite` audit
  problem is correctly red, and Phase 2's extraction half is unproven.
- **Discovery power.** 0/2 gold cases; 0 criticals confirmed by discovery on a real
  protocol (the one CONFIRMED finding is a control — a known bug reproduced post-hoc).
- **The maximization loop** does not exist, so `poc_tier: maximized` has writers and
  readers but no producer.
- **The severity engine** does not exist as specified (§9.4).
- **The prover lane's reach** is thin (§8.5) and carries zero gate weight by design.
- **The statistical layer** (Wilson intervals, backtest, acceptance bands) is cut by the
  spec, guarded in code, and cannot produce a claim at the current sample size.

### 9.4 The specification-versus-code gap (from the repo's own recon)

Six reconnaissance reports (`docs/sdd/v16-recon/01…06`) audit the shipped tree against the
v1.6 spec line by line, with a three-valued verdict (EXISTS / PARTIAL / ABSENT) and a
`path:line` for every row. Their consolidated gap list, ranked:

1. **Negative/absent-guard evidence had no mintable path** — `ValidateExecRecord` required
   `exit_status == 0` and refused a failing suite, so a defect whose signature *is* an
   absent guard could not be minted at any profile. (Patched by Route 2 in v16; the
   provenance limit in §6.4 stands.)
2. **No measured `extractable_usd`** — as above.
3. **The C4 severity engine in full** — append-only severity events, `rescore`, stale
   flags, typed bounds, two-pass authority, `severity_authoritative_pass`, `submit`.
4. **The maximization loop and its status enum** — `ladder optimize`, the
   `converged | no-improvement | budget-expired | engine-failed` enum, per-class deltas.
5. **The C9 policy split** — `platform_rubric` vs `program_scope`, `policy init`,
   per-platform renderers.
6. **The C5 negative space** — the §C5.1 obligation generator, §C5.2 closure gate,
   EXEC-negative tags, the closure-quality log, truncation records.
7. **The C7 dual-arm critic and external corpus** — arms, disagreement promotion,
   `--external`, pre-fork halt, excluded-disclosure rate, `bypass_statement`.
8. **C6 targeting** — `target-score`, `scope --check`, clone sweep, abandonment nulls,
   acceptance telemetry.
9. **Part 3a / P0** — the ScaBench harness rebuild, checkout and pin tooling, the
   contamination grep, double transcription, commit-before-reveal.
10. **The runner-level fork pin** (scoped, not built) and the Part 4 cut deletion (guarded,
    open).

Caveat, stated by the reports themselves: **they were refreshed 27 commits ago**. Landed
since: the derived-label rule table, the control target reaching CONFIRMED, the exec-record
anchor, the absent-guard mint admission, 10a/10b, and the P5 scope. Re-measure before
trusting any status.

---

## 10. What we already know is weak (ranked, for a reviewer to attack)

Items 1–6 are the ones we would attack first if we were the reviewer.

1. **The product's core claim is unproven, and the architecture may be the reason.**
   Everything in §2 is a machine for *refusing to be fooled*; nothing in it finds bugs. The
   project's own research says so (C1–C6, §7). The strongest version of the criticism is:
   *this is an excellent evidence system wrapped around a discovery engine that does not
   exist, and the evidence system's rigour is being used to justify not building one.*
   Judge whether the sequencing (evidence first, exploitation second) is correct, or
   whether the exploit factory (Wave 1) should have come before the record machinery.
2. **Severity is recomputed live, and the spec says it must be an event.** Today
   `bounty.SeverityFor` recomputes on every read, asserted as deliberate in the finding
   schema. The spec requires append-only severity events with two passes and a policy
   reload that never rewrites history. A reviewer should ask whether the event-sourced
   design is worth its cost, or whether the current recompute is right and the spec is
   over-engineered (D2 is one of the oldest decisions in the document).
3. **A cut list that leaves the code importable is a postponement, not a decision.** The
   spec's Part 4 cuts the statistical eval layer; `internal/wilson`, `internal/backtest`
   and `internal/classweights` still exist, carry `DEPRECATED` headers, and are held behind
   an allowlist test that pins the importer set in both directions. Either delete them or
   un-cut them.
4. **Spec-versus-reality contradictions that are cheap to fix and expensive to ignore.**
   The spec says "ARGUS's 23-class taxonomy" and the live RUNBOOK repeats "23"; the code
   holds **25 canonical classes + `unmapped`**. The spec claims "14 stages, monotonic" but
   enumerates 13 plus an out-of-sequence 7a. The spec's Phase 1 exit criterion asserts an
   exit-code contract that the CLI does not implement as written (`run` halts with exit 3,
   documented in one file and omitted in another). Each of these is a small edit with a
   measurement behind it (D9-compliant), and each is currently a trap for a new reader.
5. **Policy is being set from single measurements.** 92.6% vs 40.7% recall, a duplicate
   paying 27–45% of a unique find, an invariant bypassable in 17 of 18 cases, 1,505 s and
   2.25M tokens for eight properties with zero verified, 20/27 vs 3/27 exploits blocked.
   Each of these is one study, generalized into a funding rule, a critic template, or a
   budget rule. D6 says a hardening from one failure is a hypothesis about its class —
   the same standard should apply to these numbers.
6. **The strongest integrity claim has a recorded hole.** The exec-record anchor binds a
   mutable record to its event, but (a) it cannot prove the operator was blind to the
   result when the expectation was declared, and (b) the accepted residual is that
   deleting the carrier event *and* editing the projection produces **no audit row at
   all**. The project chose this deliberately (fail-closed was rejected on four measured
   grounds) and recorded it — but a reviewer should judge whether "no row at all" is
   acceptable for the system's central evidence object, or whether a cheap detector exists
   (e.g. a cross-check that every `EXEC-*` directory has a carrier event).
7. **The §5.1 escape is narrower in code than in schema.** The schema's `reason` floor is
   `minLength: 1`; the write path demands ≥10 characters. The schema alone therefore does
   not enforce the rule the design intends, which matters because the schema is the
   artifact a third party would audit.
8. **`poc_tier: maximized` can be written but never produced.** The tier has writers, a
   reader, and no producer. That is a live invitation to declare a maximization that never
   happened — precisely the class of dishonesty the framework exists to prevent.
9. **The prover lane is integrated but not measured**, and its architecture document
   disagrees with its own shipped code in at least six places (§8.6). Its reach on the
   scorecard is 2/19 and 1/… .
10. **Test-depth residuals** (recorded, not hidden): `check6ExploitContract`'s fail branch
    and blocker text are executed by no test; `cmd_impact`'s prefix matching accepts
    near-miss flags; `mint --poc-tier` is discarded on the idempotent no-op path;
    `AddEvidence` has no `ValidatePocTierOrder`; `v16_coverage` still misses a finding file
    with neither an ingest ref nor a chain-materialized id.
11. **Three real campaigns, one target family.** Every field run has been Morph L2 (plus
    one ScaBench target and one control). The framework's class priors and severity
    weights have never been exercised against a different protocol shape, and the eval
    store is 19 hand-planted cases — the project's own plan calls fresh-target authoring
    "the largest uncosted item in the plan".
12. **The record is only as good as the writer discipline, and the review history proves
    it.** A new writer forgot the campaign lock (lost-update class); a ledger-law test was
    green under three mutations including replacing the log call with a no-op; an id
    pattern matched none of the ids the framework actually mints, hiding a refusal that
    could never fire; a walk collected a sentinel and wrote a false rejection row. Every
    one was found by adversarial review, not by the suite. A reviewer should ask what class
    of bug the suite structurally cannot catch — the answer recorded so far is *"the test
    and the code agreeing on the same wrong assumption"*.
13. **Loss risk in the working tree.** `framework-plan-v1.6.md` (the specification) and
    `docs/gates/v16-prompt.md` (the only prompt file) are **untracked**. Both are cited by
    live code and gates. Committing them is a one-line fix that has not been made.
14. **The "stdlib only" law and `go.mod` disagree** (§2.1). Whichever way it is resolved,
    the law should be restated as a rule that the tree actually satisfies.

---

## 11. Next steps, in order

### 11.1 Immediately (the v16 queue, owned by the parallel agent)

1. **§5.2** — resolve `codebase_id` vs `project_id` by counting usages, then give the row
   schema the canonical key. Blocks Step 7 and Task 4.
2. **§5.3** — fix the spec's `containsWord`, re-run P0 Task 3 Steps 1–6, and report whether
   any result changes (the shipped outputs are suspect until re-measured, because the spec
   they were built against was self-contradictory). Disposition all nine review defects,
   including the two HIGH ones.
3. **§5.4** — P0 Task 3 Step 7, then Task 4 (weighted set-cover). P0 stays on the critical
   path: the control target supplies the true side only; the false side needs fresh targets.
4. **§5.5** — build the runner-level fork pin *for silent pruning*, with the four acceptance
   criteria already scoped.

### 11.2 Then (the strategic plan, once the four operator decisions are made)

- **Wave 0 (days):** auto-scheduled reproduction execs, the drop-file transport (shipped),
  policy lint with a class-alias map, anchor-cluster dedup, an adjudication verb, and
  phase-report telemetry. Acceptance is deliberately modest: `execs/` non-empty and ≥1
  `POSSIBLE` carrying an EXEC citation.
- **Wave 1 (the exploit factory):** the PoC synthesizer, the funding primitive, measured
  impact, and an evidence-kind floor. This is the highest-expected-value work in the plan
  and the thing that makes every downstream claim measurable.
- **Wave 4 in parallel, because it gates everything else:** the ≥100-case gold set with an
  incident-date partition, so that a calibration claim becomes reachable at all.
- **Waves 2, 3, 5** after: index value-vision, hypothesis generation, and the paid-bounty
  conversion.

### 11.3 Housekeeping that is cheap and overdue

- `git add framework-plan-v1.6.md docs/gates/v16-prompt.md`.
- Re-measure the six recon reports (27 commits stale) or re-date them explicitly.
- Re-measure the strategic plan's §2 numbers, or mark the section as of its baseline
  commit.
- Fix the four dangling references and the two contradictory counts (23 vs 25; exit codes).
- Execute or drop the Part 4 cut.
- Compact the documentation (in progress, §Appendix C) so a new reader is not buried.

### 11.4 The four decisions only the operator can make

Fork RPC access; corpus ingestion licence; the first three holdout targets; the autonomy
level. Until the first is answered, E5/E6 evidence stays theoretical and `floors set`
remains the release valve — which is the one failure mode this project has already
diagnosed in itself.

---

## 12. What we want from you

### 12.1 The review protocol we would use

1. **Pick a claim from §9.3 or §10 and try to falsify it.** The repo is built for this: the
   gates run in about two minutes, the golden suite is deterministic, and every claim above
   names its evidence.
2. **Check one thing end to end yourself.** The fastest honest path: build the binary
   (`scripts/release.sh`), run `webv2 selftest --full`, then walk one campaign from
   `init` to `audit` with the commands in §3.1. If the tool is not what this document says
   it is, that is the finding.
3. **Read one gate report and its code.** `docs/gates/v16-P1-10a.md` is the best single
   example: it contains a real finding, a real refusal, a real anchor, and a recorded
   provenance limit.
4. **Then answer the design questions in §12.2.**

### 12.2 The questions we most want answered

1. **Is the central bet right?** (§1.3) Is a deterministic control plane the right
   architecture for this problem, or is the rigour a substitute for discovery? If you think
   the ordering is wrong, say what should have been built first and what it would cost to
   change now.
2. **Where should the next unit of effort go?** The candidates: the exploit factory
   (Wave 1), the severity engine (C4), the gold-set measurement (Wave 4), or the
   remaining v16 queue. We have an ordering argument (§11); attack it.
3. **Is the refusal doctrine load-bearing or is it a way to avoid finishing?** The project
   refuses to estimate, refuses to launder, refuses to build without a measurement. That
   has produced real integrity — and a fork spike, a P5 build, and an audit problem that
   are all still open. Where is the line between "measured or refused" and "not done"?
4. **What would you delete?** Both in code (the guarded Part 4 cut, the ported-but-unwired
   modules, the 90-verb surface) and in process (the wave/review apparatus itself).
5. **What measurement would you add first?** Given that a calibration claim is unreachable
   at 6 held-out rows and a discovery claim is unreachable at 2 gold cases, what is the
   cheapest experiment that would move the project's knowledge the most?
6. **Where is the framework's honesty incomplete?** §10 items 6 and 8 are two places we
   know of where the record can be technically true and materially misleading. Find the
   others.

### 12.3 What we will do with your review

The project's rule (D7) is that proposals are evaluated on merits against what is built
and tested — adopted or rejected with a recorded reason, never adopted for being
well-argued. D9 freezes the *specification* until a Phase 3 regression run exists, so
spec-level changes will be recorded as proposals with the measurement that would unblock
them. Everything else (code, tests, docs, this brief) can change immediately.

---

## Appendix A — Repository map

```
cmd/webv2/main.go        the binary: seam wiring + main
internal/                67 packages (75 including cmd and nested test packages)
assets/                  embedded via go:embed, pinned by a SHA-256 manifest
  schema/                35 JSON schemas (additionalProperties: false everywhere)
  prompts/               21 model prompts (the binary never executes them)
  playbooks/             10 class priors · archetypes/ 13 bug archetypes
  taxonomy/              class weights, aliases · protocol/ · evalsuite/ (19 cases)
  runbook/               RUNBOOK.md (the operator contract, 2,022 lines) + AGENT_BOOTSTRAP.md
  testdata/              the asset manifest
scripts/                 release, golden, verify-full (13 steps), runbook-walkthrough,
                         p2-docker-e2e, security-check, sync-asset-manifest, scorecard
pre-commit-gate/         the entropy gate (language config, diff size, AI-slop score)
docs/                    see Appendix C
sft/                     the SFT example store (committed on purpose; VCS is its integrity layer)
```

The packages that carry the most weight for a reviewer:

| package | role |
|---|---|
| `internal/state` | the ledger, the projection, the process lock, artifacts, ids |
| `internal/validation` | schema validation, Python-equivalent rendering, atomic IO |
| `internal/findings` | the finding IR, the evidence ladder, the confirmation clauses (81 files) |
| `internal/bounty` | the bounty policy engine, severity matching, the gate bindings |
| `internal/orchestrator`, `planner`, `pipeline` | the staged campaign lifecycle |
| `internal/probes`, `structidx` | the deterministic hunting surfaces and the structural index |
| `internal/sandbox`, `harness` | exec profiles, output integrity, harness scaffolds (Solidity and `.mspec`) |
| `internal/audit` + `sections` | the 19-section integrity audit |
| `internal/regression` | the v1.6 Part 3a record layer (targets, runs, labels, the fork pin) |
| `internal/harness` | the prover bind: MiniCertora mapping, the 25-code refusal vocabulary, MiniProver report mapping |
| `internal/cli` | the 90-verb surface (298 files) |

## Appendix B — The command surface (90 registered verbs)

`init, status, doctor, complete, dedup, prioritize, repro-queue, chains, terminals,
privileged, cost, yields, relations, resemble, index, sinks, prescreen, forkdiff, recency,
baseline, brief, invariant-verify, artifact-register, artifact-list, invariant-contradict,
publish, globalize, corpus-surface, shared, report, memory, ingest, model, plan, answered,
probes, floors, execs, budget, exec, scope, move, mint, sequence, verdict, recall, impact,
snap, run, log, verify, audit, ladder, waive, prove, gate, price, price-basis, env,
classify, shield, precondition, immunize, resolve-candidate, hint, sft, selftest, exploit,
ack, rank, adversarial-game, chain, enforce, symmetry, artifact-reconcile, dedup-signature,
amend, supersede, prompts, adjudicate, scorecard, deferred, artifact-prune, schema,
anchors, assume, review-session, fact-read, fork-dependence, regress`

`webv2 help` prints them in registration order; `webv2 <verb> --help` prints an
argparse-shaped usage block. Both are byte-pinned by tests.

## Appendix C — The document map

**Read these (live):**

| document | what it is |
|---|---|
| `README.md` | the entry point: quick start, the verification table, the layout |
| `docs/gates/v16-prompt.md` | the current phase: laws, the §3 ledger, the §5 queue (**untracked — should be committed**) |
| `framework-plan-v1.6.md` | the specification (**untracked — should be committed**) |
| `docs/CRITICAL_HUNTING_PLAN.md` | the strategic gap analysis and the six-wave plan (§7) |
| `assets/runbook/RUNBOOK.md` | the operator contract; a test keeps it in sync with the registry |
| `docs/sdd/v16-recon/01…06` | the spec-versus-code audit, line by line (§9.4) |
| `docs/gates/v16-*.md` | the current phase's gate reports, including the refusal ledger |
| `docs/MINICERTORA_*.md`, `docs/MINIPROVER_INTEGRATION.md` | the prover lane (§8) |
| `LEARNINGS.md` | the project's durable lessons ledger (tactics, traps, verified facts) |
| `SECURITY.md` | the threat model |

**Frozen history (read only when tracing a decision):** `docs/archive/` (the divergence
ledger, the Python-twin issue log, the test accounting map), `docs/gates/P0…P4` (the port
cutover), `docs/feedback-triage*.md` (the three real campaigns), `docs/IMPROVEMENTS.md`
(the wave ledger), `docs/LEANNESS_REVIEW.md`, `docs/runbook-go-notes.md`.

**Process archaeology (compacted):** the port-era task reports under `docs/sdd/` and the
closed plan trails under `docs/superpowers/plans/` were collapsed into
`docs/archive/PORT-ERA-DIGEST.md`, with the originals removed from the working tree and
preserved in git history. `docs/INDEX.md` is the canonical map of what lives where.

## Appendix D — Glossary

| term | meaning |
|---|---|
| **campaign** | one bounty program or contest, identified `C-<hex>`, owning a directory and one event log |
| **ledger / event log** | `events.jsonl`: append-only, hash-chained, the source of truth |
| **projection** | `campaign_state.json`: a derived view, reconciled against the log by `audit` |
| **finding** | `F-<hex>`: a hypothesis with a status, an evidence level, and a history |
| **evidence ladder** | E0–E7; promotion is gated by class floors and confirmation clauses |
| **class floor** | the evidence level a bug class needs for CONFIRMED (`CLASS_CONFIRM_FLOOR`) |
| **floor override** | a per-campaign, reasoned, ledger-recorded change to that floor |
| **clause / check** | a machine-checked condition in the confirmation gate (check1…check15) |
| **exec record** | `EXEC-<hex>`: one sandboxed run, its profile, exit status, output digest, and (v16) an anchor digest |
| **profile** | an execution posture: `docker-networkless`, `fork-runner`, `host-readonly`, `minicertora`, … each with an evidence cap |
| **rung** | a prover verdict: `counterexample`, `proved-bounded`, `inconclusive` |
| **refusal** | a recorded decision *not* to claim something, with the reason and the measurement that was missing |
| **extractable_usd** | what an attacker could actually extract — must be *measured*, never inferred from a reported loss |
| **unpriceable** | the named decision that a finding cannot be priced, with a non-blank ceiling basis |
| **§2.4 quantities** | demonstrated vs computed vs reported impact — three distinct things, never conflated |
| **dual-arm critic** | a theft-first and a liveness-first critic; `DISPROVED` requires both (spec C7) |
| **regression suite** | the ScaBench-derived eval record layer (v1.6 Part 3a) |
| **gold case** | an eval case with a known answer, used as a held-out measurement |
| **surface budget** | the rule that new capability lands as a flag on an existing verb unless unreachable otherwise |
| **D9 freeze** | the specification changes only in response to a measurement |
