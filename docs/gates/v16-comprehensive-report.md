# webv2 / v16 — comprehensive delivery and architecture report

**Scope.** One working session against the v16 queue, plus the standing state of the system it
touched. Written because the architecture is about to change: it therefore leads with **what was
learned**, not what was built, and separates *measurements* from *judgements* throughout.

**State at close.** `main` at `cf364ed5`, tree clean, everything pushed. One interrupted item
preserved in `git stash`. All gates green.

**Reading order for a decision-maker:** §1 (what the session concluded) → §4 (the four findings
that should drive the change) → §5 (recommendations) → §6 (open items). §§2–3 are the supporting
record; §7 is the appendix.

---

## 1. Executive summary

Seven queue items were worked. Three were routine. **Four produced a finding that argues against
the plan as written**, and those are the reason this document exists:

1. **The derived-label rule table does not work.** Run against the real 114-row snapshot for the
   first time, it leaves **54.4% unmapped** and — worse — **29 of the 52 rows it does classify carry
   a class the mechanism contradicts**. Every one of its 20 `upgrade-initializer` rows is an
   artifact of scanning whole multi-KB descriptions.
2. **The plan's weighting is inert.** The set-cover weighting was the plan's stated mechanism for
   buying class coverage. Measured: weighted and unweighted greedies select the **identical six
   projects**. A gain that *sums class weights* cannot raise the *count* of covered classes.
3. **The plan's Task 4 test and Task 4 code are mutually unsatisfiable.** Its own fixture fails
   under its own algorithm.
4. **The handoff schema forced a fabricated number.** A required, strictly-positive field with no
   attributed way to say "unmeasurable" — while the only way to clear an audit problem was to
   invent a figure.

The through-line is one failure mode repeated at four layers: **a system that cannot represent
"I don't know" will manufacture an answer that looks like knowledge.** The label table converts a
miss into a plausible wrong class; the weighting converts a design gap into a number; the handoff
schema converts an unpriceable loss into a fabricated figure. Each was individually reasonable and
each laundered uncertainty one layer down.

---

## 2. The system this work sits in

Orientation for a reader who has not been in this tree.

**What it is.** `webv2` is a Go control plane for a security-research pipeline over smart-contract
bug bounties. Module `websec`, Go 1.26.2, **standard library only**. Roughly **138k lines of Go
(196k with tests)** across ~70 internal packages and a very large CLI surface (~200 `cmd_*.go`
files).

**The spine.** A campaign is a hash-chained event log. Findings move through an evidence ladder
(`E0`–`E7`, `internal/findings/levels.go`) toward a status, gated by `GateRequirements`. A
`CONFIRMED` status has a floor plus clauses beyond it — a hostile-critic verdict and a verified
memory recall. A **projection** is derived from the log and must reconcile with it; a mutation
writes exactly one chained event.

**Invariants the codebase enforces on itself.**

| invariant | how it is enforced |
|---|---|
| One chained event per mutation | ledger law; projection unwinds on log-write failure |
| Schemas are closed | `additionalProperties:false` + `validation.Validate(v, name, 1)` |
| CLI surfaces are byte-pinned | help/usage/error text asserted verbatim in tests |
| Runs are deterministic | `WEBV2_NOW`, `WEBV2_UUID`, `WEBV2_FINDING_IDS` seams; no raw `time.Now()` |
| Assets are manifested | `python3 scripts/sync-asset-manifest.py` |
| No lint suppressions | **zero `nolint` directives in the repo**, by policy |
| Tests are hermetic | same package, `t.TempDir()`, no Docker, no network, no model |
| A spec changes only on measurement | the **D9** rule |

**Gates.** `go test ./... -count=1 -p 2` (72 packages), then `scripts/verify-full.sh` — 14 steps
including a golden run, a docker e2e script, the runbook walkthrough and `webv2 verify` over a
committed fixture. Plus `gofmt`, `go vet`, `golangci-lint` (funlen ≤30 lines/≤20 statements,
gocyclo ≤10, dupl, unparam, errcheck). Two lint traps are worth knowing: funlen and gocyclo are
attributed to the **declaration line**, so `--new-from-rev HEAD` can hide a breach on an unchanged
line — a full run over touched packages is required.

**The regression suite** (`internal/regression/`), which most of this session touched, is the P0
deliverable: pinned fork targets, an audit section that reconciles them, and the selection of which
targets the suite is built from. Its two halves are the **control target** (supplies the true side)
and **fresh targets** (supply the false side).

---

## 3. What the session delivered

Commit order. "Finding" marks an item that changed what we know rather than only what we have.

| # | item | commit | result |
|---|---|---|---|
| 1 | Provenance limitation | `e4b683e6` | **Finding.** The exec-record anchor proves an expectation was contemporaneous with *its own* run. It does **not** prove operator blindness — the signature was chosen after four earlier failing runs. The record now states the weaker, true claim. |
| 2 | Docker section count | `7e0eac87` | `p2-docker-e2e.sh`'s `!= 16` proved by enumeration: 19 registered − 3 skipping (`eval`, `price_table`, `regression_suite`) = 16. Cross-checked against the *old* passing assertion of 15. The old comment's "17 registered" was already wrong. |
| 3 | `failure_class` archival | `95cedeb5` | The classifier's verdict is persisted on the `sandbox.exec` event (6 keys) and `sandbox.exec.registered` (7). On the **event**, never the record — the closed `sandbox_execution` schema would refuse it. Digest invariance proved in both directions. Header states plainly the archive is written but **not consumed**: admission still recomputes. |
| 4 | P0 Task 3, Steps 1–6 | `414b4a0c` | Rule table (17 rules), classifier, label-file schema, repo-level CLI action. Two spec defects found (§4.5). Nine review defects fixed inside the same commit. |
| 5 | 10b fork spike | `c5ba1048` | **Finding.** `fork_block_used = 108375557`, measured from observed `(block: …)` output on **two** independent forks. EIP-1967 slot read at that block returns impl A. Ran on a **copy** of the checkout so the evidence tree's hashes are unchanged. **`extractable_usd` refused** — no attack run was made, and no figure was invented. |
| 6 | P5 scope + handoff refusal | `9ba6bb12` | P5 scoped, deliberately **not** built. The sharper result is the refusal: see §4.4. |
| 7 | Handoff unpriceable escape | `911be0a9` | **Finding.** The schema *forced* fabrication. Fixed by mirroring the codebase's own existing `unpriceable` named-decision pattern. |
| 8 | `codebase_id` gap | `b7b063fd` | Tie measured **3–3** across `internal/`, `cmd/`, `assets/schema/`. The project's own tie rule picked `codebase_id`. `project` stays the picker's key; `codebase_id` is the optional checkout key. |
| 9 | Task 3 re-measure | `9ea30f55` | **Finding — the headline answer: no result changes.** The spec's broken matcher was never committed; it exists only in the plan document, so no artifact was ever produced from it. The matcher's *left* edge was pinned nowhere and now is. |
| 10 | Task 3 Step 7 (real run) | `8bead12c` | **Finding — the rule table is unfit.** See §4.1. |
| 11 | Task 4 selection | `a76005d7` | **Finding — the weighting is inert.** See §4.2–4.3. Six picks, 40/114 findings, 8/14 classes. |
| 12 | Prompt + summary maintenance | `2771d466`, `152d7d78`, `6787b740`, `cf364ed5` | `docs/gates/v16-prompt.md` kept current: finished items move from §5 to §3 with their shas. |

**Deliberately not done, and why.**

- **The rule table was not "fixed" during Step 7.** Step 7 is the operator step: the code is fixed
  and the data is the input. Repairing the matcher is a Steps 1–6 code change with its own tests
  and its own review. The run reports the defect; it does not quietly paper over it.
- **`extractable_usd` was never produced.** A reported loss was never laundered into an
  `extractable_usd`. Refusal with a recorded reason beats an estimate.
- **The docker count was never *executed*** — it has a proof by enumeration, which is a different
  and weaker thing, and it is recorded as such.
- **P5 was not finished.** It was started, interrupted, and stashed rather than left broken.

---

## 4. The findings

Each is **measured**. Where a number is a judgement it says so.

### 4.1 The derived-label rule table does not work (HIGH — blocks everything downstream)

`docs/gates/v16-P0.md`, Task 3 section, has the row-by-row review.

Step 7 ran for the first time against the real snapshot at
`/home/xand/webv2-p0/scabench/datasets/curated-2025-08-18/`. Results:

- **62 of 114 rows (54.4%) classify as `unmapped`.**
- **29 of the 52 that *did* classify carry a class the mechanism contradicts.**
- **All 20 `upgrade-initializer` rows are artifacts.**
- Three rules (`signature-replay`, `token-integration`, `economic-invariant`) produced **no row at
  all**.
- Defensible coverage after a hand read: **~11 classes**, not the 17 the table nominally supports.

**Mechanism.** The matcher takes longest-phrase-wins over the **entire multi-KB description**. An
incidental word therefore dominates the mechanism:

- a finding about withdrawals fires on `IERC20Upgradeable` → `upgrade-initializer`;
- a reentrancy finding fires on `upgrade-initializer`.

**Why a wrong class is worse than no class.** `unmapped` is *visibly* a miss — a reviewer sees the
bucket and knows something is uncovered. A plausible-but-wrong class is indistinguishable from
coverage, and it is **weighted** by everything downstream. The failure is silent by construction.

**The reassuring half, also measured.** With `upgrade-initializer` neutralized to `unmapped`, the
**same six picks** come back. The pick is not artifact-driven; only the coverage number is
inflated. That is worth knowing before discarding the selector.

**The plan's own fixture cannot classify correctly either.** The reviewer ported `Classify` and
confirmed the fixture's 114 rows classify as the plan assumes — the fixture is fine, the *real*
data is what breaks.

### 4.2 The weighting is inert — the plan's central selection claim is a category error (HIGH)

Task 4's premise: weight the greedy set-cover by gold-finding count and it will buy **class coverage
per checkout**. Measured on the real snapshot:

- weighted greedy → `bakerfi, loopfi, next-generation, morph, initia, idle` — 9 classes, 45 findings;
- unweighted greedy, same constraint → **the identical six**, same 9 classes, same 45.

The reason is structural: a gain that **sums class weights** cannot raise the **count** of covered
classes. The reviewer sharpened this correctly — it is a *per-step* property (the weighted argmax
at a given state never covers more new classes than the unweighted argmax at the same state), and
here it is **measured**, not proven for arbitrary inputs. The plan's demanded property — "the
weighted pick covers a class an unweighted pick misses" — is **unsatisfiable by any weight-sum
gain**, so the plan's fixture cannot demonstrate it either.

**The trade the plan never weighs.** Against the plan's own "six biggest" reading (54 of 114 gold
findings), the argued pick trades **36 gold findings for one extra class**. Whether that is right
is a legitimate design question. What is not legitimate is reaching it while believing weighting
did the work.

### 4.3 The plan's Task 4 test and Task 4 code are mutually unsatisfiable (MEDIUM)

On the plan's **own** fixture, the plan's **own** algorithm returns
`{big-a, filler-21, filler-02, filler-03, filler-01, filler-04}`. That set:

- never covers `oracle-manipulation`, and
- picks only **one** of the two held-out projects.

So the plan's Step 2 test fails against the plan's Step 4 code. The reviewer verified this by
independent simulation and established that **no tie-break or weight tweak rescues it** —
`oracle-manipulation` (weight 3) loses pass 1's slot to weight-4 classes and loses pass 2 to
weight-4 ties under both weightings.

The implementation resolved it by following Step 4's code (the concrete artifact downstream tasks
consume) and **reporting the contradiction** rather than editing the test to pass. Pass 1 also had
to change from gain-gated to a constraint: gain-gated, the real run refuses outright
(`no project covers shape 'bridge-messaging'`).

### 4.4 The handoff schema forced a fabricated number (HIGH)

`handoff.extractable_usd` was **required, strictly positive, with no escape** — while the audit
reports a problem when a control target has no handoff. So the only way to clear that audit problem
was to **invent a figure**. The codebase had already solved exactly this problem for economic
impact (`economic_impact.priceable` + `risk.RecordUnpriceable`) and had not applied it here.

**The fix, and why its shape matters.** `priceable:false` now requires:

- a non-blank `ceiling`,
- a `reason` of ≥10 runes,
- a named `recorded_by`,

and **forbids** `extractable_usd` via a draft-07 `"extractable_usd": false` subschema. `priceable`
absent means priceable, so every pre-existing handoff keeps its exact bytes.

**How it prevents an *unattributed* omission** — the trap one layer down: the write path refuses a
blank ceiling, a short reason, and a missing actor; the schema carries the same 10-rune floor (it
was 1) and requires `recorded_by`; and the audit — which previously accepted **three schema-invalid
records**, one carrying a figure beside the decision — now validates every target against the schema
**and** reconciles the projection leaf-by-leaf against the `regression.control.handoff` event, in
both directions.

**Generalizable rule.** Any "required, positive" field on a record a human must write is a
fabrication trap unless there is an attributed way to say "this cannot be measured". The escape
must require a *reason and a basis*, never permission to omit silently.

### 4.5 The spec's own matcher fails the spec's own test (MEDIUM)

The plan's `containsWord` closes **both** word boundaries, which makes every **stem** phrase in its
own rule table unmatchable — "reentrancy" has a "c" after "reentran". Measured:

| haystack | spec's matcher | shipped matcher |
|---|---|---|
| phrase as a stem | **0 / 77** | 77 / 77 |
| realistic occurrence | **67 / 77** | 77 / 77 |

The spec's own test input classifies as `unmapped` under the spec's own matcher.

**It was never committed** — it exists only in the plan document (`git log -p --all` shows zero
occurrences), which is why the re-measurement's headline answer is **no result changes**: no
artifact was ever produced from it. The shipped matcher keeps the left boundary strict and the
right edge open, and both edges are now pinned by tests (the left edge was pinned *nowhere* before —
deleting the check left both packages green).

### 4.6 Supporting findings

- **The dataset was present all along** at `/home/xand/webv2-p0/scabench/datasets/curated-2025-08-18/`
  after several sessions recorded it as absent. Its shape confirmed every claim the plan made:
  31 projects, 555 vulnerabilities (114 high / 237 medium / 184 low / 20 informational), exactly
  **one** multi-codebase project (Starknet Perpetual), and all five of the plan's distribution
  numbers (mean 3.68, median 2, max 12, 11 projects with ≥4, top six carrying 54 of 114).
- **The shape map was wrong twice, and it drove the pick.** Morph was labelled a non-rollup L2
  while its own audit is `Rollup.sol` with batches, state roots and challenge games; Telcoin Network
  was labelled an L2 while its contracts *are* a standalone PoS consensus layer. Neither reaches the
  "oracle-driven protocol" branch on its own findings. Both were **removed** rather than re-argued —
  keeping a label to preserve a selection is precisely the failure the work forbids.
- **A required caveat was optional.** The `input_class_fitness` field recording that the input's
  classes are known-unfit was not in the schema's `required`, so a future selection could omit it
  and its coverage would read as coverage of *real* classes. Now required and test-pinned.
- **One map iteration survived on a refusal path**, so with two bad shapes the error named a
  *random* project (Go randomizes map order). It always refused, so no decision changed — but it
  contradicted the documented determinism claim.

---

## 5. Recommendations for the architecture change

Ordered by leverage. Each is grounded in a measurement above.

1. **Make "unknown" representable at every layer, or expect it to be fabricated.** This is the
   single lesson of §4.1, §4.2 and §4.4. Concretely: a required field with no escape hatch becomes
   a lie generator; a classification with no "unclassifiable" outcome becomes a false-positive
   generator. Every closed vocabulary in the system should be audited for a missing *attributed*
   "none of the above".
2. **Fix or replace the derived-label matcher before anything consumes it.** If derived labels
   stay: weight the title, truncate the description, or make phrases specific. Whatever is chosen,
   the label file needs a **review gate that can see conflation, not just misses** — the current
   `unmapped_reviewed` flag cannot detect a wrong-but-plausible class, which is the actual failure
   mode.
3. **Decide what the selection objective is, in writing.** Weighting does nothing. The real
   choice is "class coverage per checkout" versus "gold findings per checkout" — a trade the plan
   never states. Pick one and make the record say which.
4. **Keep the pieces that measured well.** The selector is deterministic, reproducible from
   committed inputs plus a pinned clock, and **not artifact-driven** (§4.1). The six-pick set is
   recomputable rather than re-arguable once the labels improve.
5. **Institutionalize the adversarial review.** Every review this session refuted something real —
   including a claim I had personally doubted and was wrong about (§7.3). The pattern that works:
   an independent re-implementation of the algorithm in a different language, run against the
   committed artifacts, reproducing the committed numbers exactly before attacking them.
6. **Treat "the spec's own test fails the spec's own code" as a first-class defect class.** It
   happened twice (§4.3, §4.5). A plan that has never been executed is a hypothesis.

---

## 6. Open items

| # | item | state | owner |
|---|---|---|---|
| 1 | **The rule table is unfit** (§4.1) | open, blocks downstream | next session |
| 2 | Re-run the selection after the labels are fixed | blocked on #1; fully reproducible | next session |
| 3 | The weighting/objective decision (§4.2) | design decision, not a bug | you |
| 4 | **P5 runner-level fork pin** | started, interrupted, **in `git stash`** | next session |
| 5 | Cross-agent conflict over Morph | needs its owner | the other agent |
| 6 | `extractable_usd` | **refused by decision**, not omission | closed |
| 7 | The `regression_suite` audit problem | correctly still reported | closed |

**On #4.** The interrupted work is preserved, not lost:
`git stash list` → *"WIP P5 runner-level fork pin (INTERRUPTED - 4 tests failing)"*. `git stash pop`
restores it. The scope at `docs/gates/v16-P5-runner-fork-pin-scope.md` remains the specification,
and its justification is **silent pruning** — a pruned node answers `eth_getCode` with `0x`, which
is byte-identical to "never deployed", so a run cannot tell from inside whether the state it read
was real. It is **not** "no archive endpoint works"; that overstatement was corrected and must not
reappear.

**On #5.** `docs/superpowers/plans/2026-09-23-replay-set-and-discovery-baseline.md` (the other
agent's, untouched) holds out Morph. After `a76005d7` Morph is not in the suite at all. That
document needs updating by its owner.

---

## 7. Appendix

### 7.1 The selection, as committed

Computed from `eval/scabench/labels-2025-08-18.json` (114 rows) plus the shapes map plus a pinned
clock. Reproducible end to end.

| pick | gold | partition |
|---|---|---|
| BakerFi | 7 | held-out |
| Initia | 4 | dev |
| Idle Finance | 2 | dev |
| LoopFi | 2 | dev |
| Starknet Perpetual | 2 | held-out |
| Next Generation | 1 | dev |

**Coverage:** 40 of 114 findings, **8 of 14 classes**. Uncovered: `bridge-message`,
`cross-chain-replay`, `dos-griefing`, `logic-error`, `reentrancy`, `unchecked-external-call`.

**Known-unfit caveat (now a required field in the record):** no `upgrade-initializer` row and no
`flash-loan` row is defensible, and **those two artifact classes carry 21 of the covered findings**.

**Tie-break:** lowest project string, ascending, in both passes. No decision iterates a Go map.

### 7.2 Cross-cutting hazards worth carrying forward

- **A second agent was working this same tree**, on the same queue. It committed `c2ff160c`
  (`docs/REVIEW-BRIEF.md`, 1204 lines) and describes *this* session as "a second agent" in its §6.6.
  Mutations afterwards used `go test -overlay` so a shared file could not be clobbered. Re-check
  `git status` before and after any edit; never `git add -A` — stage explicit paths.
- **`rg` output mangled identifiers** in this environment (`fork_block` → `n`, `derived labels` →
  `ns`). Anything load-bearing was verified with Python or by reading the file.
- **The entropy gate blocks unknown extensions.** `.sha256` sidecars are load-bearing —
  `internal/regression/repofile.go` *refuses* a record whose sidecar is missing — and had no
  language block, so **any commit adding one was blocked**, with a message about the language
  rather than the file. Added a real format check (bare 64-hex digest), mirroring the existing
  `.jsonl` block's reasoning. `.entropy-gate.toml`.
- **Mutation discipline.** A `str.replace` with a wrong anchor silently no-ops, and `git diff`
  shows nothing for an untracked file — so a failed mutation is indistinguishable from a passing
  test. Assert the old text is present, write, grep for the marker, run, restore **in the same
  shell call**, assert byte-identical after.
- **funlen/gocyclo attribution.** Both attach to the *declaration line*, so `--new-from-rev HEAD`
  hides a breach introduced on an unchanged line. Run a full lint over touched packages.
- **`webv2 audit <path>` rejects a path.** The correct form is
  `webv2 audit --root <root> <C-ID> --json`; a path errors `malformed campaign id`.
- **Host `curl`** needs `--cacert /etc/ssl/certs/ca-certificates.crt` (a corrupt `CURL_CA_BUNDLE`).
  `git commit` hits an entropy gate; allow a long timeout.

### 7.3 Corrections made to my own work

Recorded because the reviews were right and the record should show it.

- I **doubted** a reviewer's report that a second agent was churning this repo. It was **correct** —
  confirmed by `git show c2ff160c`. The reviewer was right and I was wrong.
- A claim of "**22 mutations killed**" was **unverifiable** (gitignored scratch, no committed
  record). A reviewer reproduced 6 instead (5 killed, 1 survived). The number was not repeated as
  fact, and mutation logs are now written into the gate record.
- The implementation's own stated mechanism for the profile fix was **wrong** even though the fix
  was right — a required, strictly-positive field could not in fact produce `0`, because the
  candidate was created inside the mapped-row branch. Both the code comment and the gate record
  were rewritten to the true mechanism. In this repo a wrong explanation is a defect.

### 7.4 Laws this work was held to

TDD (tests written first, observed failing, reported). Byte-pinned CLI surfaces. Ledger law.
Determinism pins. Closed schemas. Asset manifest. **No `nolint` directives — the repo has zero.**
D9: a spec changes only on measurement. §2.4: `demonstrated` / `computed` / `reported` are never
conflated, and **a reported loss is never laundered into `extractable_usd`**. Refusal with a
recorded reason beats an estimate.

### 7.5 Where to look

| what | where |
|---|---|
| The v16 queue and its done-state | `docs/gates/v16-prompt.md` |
| Task 3 and Task 4 detail, row-by-row label review | `docs/gates/v16-P0.md` |
| The fork spike and the `extractable_usd` refusal | `docs/gates/v16-P1-10b-fork-spike.md` |
| P5 scope (still the spec) | `docs/gates/v16-P5-runner-fork-pin-scope.md` |
| The plan being executed | `docs/superpowers/plans/2026-09-21-v16-p0-regression-suite.md` |
| Short-form summary of this session | `docs/gates/v16-delivery-summary.md` |
