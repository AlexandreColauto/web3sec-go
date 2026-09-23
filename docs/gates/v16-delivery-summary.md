# v16 delivery summary

One session's work on the v16 queue, in commit order. Written to be read **before an
architecture change**, so it leads with what was *learned* rather than what was built: four of the
seven items produced a finding that argues against the plan as written.

State at the end: tree clean, everything pushed to `main`, one interrupted item preserved in
`git stash`.

---

## 1. What was delivered

| item | commit | result |
|---|---|---|
| Provenance limitation | `e4b683e6` | The anchor proves an expectation was contemporaneous with **its own** run; it does **not** prove operator blindness. The signature was chosen after four earlier failing runs, and the record now says so. |
| Docker section count | `7e0eac87` | `p2-docker-e2e.sh`'s `!= 16` proved by enumeration: 19 registered − 3 skipping = 16, cross-checked against the *old* passing assertion of 15. |
| `failure_class` archival | `95cedeb5` | The classifier's verdict is now persisted on the `sandbox.exec` event (6 keys) and `sandbox.exec.registered` (7). On the **event**, never the record; digest invariance proved both ways. |
| P0 Task 3, Steps 1–6 | `414b4a0c` | Rule table, classifier, label-file schema, repo-level CLI action. Two spec defects found. |
| 10b fork spike | `c5ba1048` | `fork_block_used = 108375557`, measured from observed output. Proxy slot at that block is impl A. **`extractable_usd` refused** — no attack run. |
| P5 scope + handoff refusal | `9ba6bb12` | Scope written, not built. The handoff refusal is the sharper result: see §2.4. |
| Handoff unpriceable escape | `911be0a9` | The schema **forced fabrication**; fixed by mirroring the existing `unpriceable` named decision. |
| `codebase_id` gap | `b7b063fd` | Tie measured 3–3; `project` stays the picker's key, `codebase_id` added as the optional checkout key. |
| Task 3 re-measure | `9ea30f55` | **No result changes** — the spec's broken matcher was never committed. Left edge now pinned. |
| Task 3 Step 7 (real run) | `8bead12c` | The dataset was present. 114 rows labelled — and the rule table found **unfit**. |
| Task 4 selection | `a76005d7` | Six picks, 40/114 findings, 8/14 classes. The weighting measured **inert**. |

---

## 2. The findings that matter for an architecture change

These are the reason this summary exists. Each is measured, not argued.

### 2.1 The derived-label rule table does not work as specified

Step 7 finally ran against the real snapshot (`8bead12c`). Two numbers:

- **54.4% of rows (62/114) are unmapped.**
- **29 of the 52 that *did* classify carry a class their mechanism contradicts.**

Every one of the 20 `upgrade-initializer` rows is an artifact: the matcher takes
longest-phrase-wins over the **whole multi-KB description**, so an incidental word dominates. A
finding about withdrawals fires on `IERC20Upgradeable`; a reentrancy finding fires on
`upgrade-initializer`.

The structural problem is that **a wrong class is worse than no class**. Unmapped is visibly a
miss; a plausible-but-wrong class looks like coverage, and Task 4's set-cover would have weighted
it. The defensible coverage after a hand read is ~11 classes, not the 17 the table nominally
supports, and three rules produced no row at all.

Reassuring half, also measured: with `upgrade-initializer` neutralized to unmapped, the **same six
picks** come back — the pick is not artifact-driven, only the coverage number is inflated.

**If the architecture keeps derived labels, the matcher needs title-weighting, description
truncation, or phrase specificity — and the label file needs a review gate that can see
conflation, not just misses.**

### 2.2 The weighting is inert — the plan's central claim is a category error

Task 4's premise is that weighting the set-cover by gold-finding count buys class coverage per
checkout. Measured on the real snapshot: **the weighted and unweighted greedies pick the identical
six projects** — same classes, same findings. A gain that *sums class weights* cannot raise the
*count* of covered classes; that is a per-step property, and it holds here.

Against the plan's own "six biggest" reading (54 of 114 gold), the argued pick **trades 36 gold
findings for one extra class**. Whether that trade is right is a design question the plan never
actually asks, because it believed weighting was doing the work.

### 2.3 The plan's Task 4 Step 2 test and Step 4 code are mutually unsatisfiable

On the plan's own fixture, its own algorithm returns
`{big-a, filler-21, filler-02, filler-03, filler-01, filler-04}` — which never covers
`oracle-manipulation` and picks only **one** of the two held-out projects, so the plan's own test
fails against the plan's own code. No tie-break or weight tweak rescues it.

### 2.4 The handoff schema forced a fabricated number

`handoff.extractable_usd` was required, strictly positive, no escape — while the audit reports a
problem when a control target has no handoff. With `extractable_usd` legitimately refused, closing
that audit problem **required inventing a figure**. The codebase had already solved this for
economic impact (`economic_impact.priceable` + `risk.RecordUnpriceable`) and had not applied it
here. Now mirrored: `priceable:false` + a non-blank ceiling + a ≥10-rune reason + a named actor,
with the audit validating against the schema **and** reconciling against the ledger.

**Generalizable lesson: any "required, positive" field on a record a human must write is a
fabrication trap unless there is an attributed way to say "this cannot be measured".**

### 2.5 The spec's own matcher fails its own test

The plan's `containsWord` closes **both** word boundaries, which makes every stem phrase in its own
rule table unmatchable — "reentrancy" has a "c" after "reentran". Measured: the spec's matcher
matches **67 of 77** phrases against realistic inputs and **0 of 77** when a phrase occurs as a
stem. Its own test input classifies as `unmapped`.

It was never committed — it exists only in the plan document — so no artifact was ever produced
from it. That is why the re-measurement found **no result changes**.

---

## 3. Cross-cutting things worth keeping

- **A second agent was working this same tree.** It wrote `docs/REVIEW-BRIEF.md` (which describes
  this session as "a second agent" in §6.6) and committed `c2ff160c`. A reviewer reported
  concurrent churn, I initially doubted it, and it was **correct**. Mutations afterwards used
  `go test -overlay` so a shared file could not be clobbered.
- **`rg` output mangled identifiers** in this environment (`fork_block` → `n`). Anything
  load-bearing was verified with Python or by reading the file.
- **The entropy gate blocks unknown extensions.** `.sha256` sidecars are load-bearing
  (`repofile.go` refuses a record whose sidecar is missing) and had no language block, so any
  commit adding one was blocked. Added a real format check, mirroring the existing `.jsonl` block.
- **The dataset was present all along** at
  `/home/xand/webv2-p0/scabench/datasets/curated-2025-08-18/`, after several sessions recorded it
  as absent. Worth checking before declaring an operator step blocked.

---

## 4. Open, and what to do first

1. **The rule table is unfit** (§2.1). Everything downstream of it inherits the problem. Fix the
   matcher, or replace derived labels with something reviewed.
2. **Re-run the selection after that.** It is fully reproducible from the label file, the shapes
   map and a pinned clock, so it can be recomputed rather than re-argued.
3. **The weighting question** (§2.2) is a design decision, not a bug: if weighting does nothing,
   say what the objective actually is.
4. **§5.5 P5** — started, interrupted with four tests failing, preserved in `git stash`
   ("WIP P5 runner-level fork pin (INTERRUPTED)"). The scope at
   `docs/gates/v16-P5-runner-fork-pin-scope.md` remains the specification. Justification is
   **silent pruning**, never "no archive endpoint works".
5. **A cross-agent conflict**: `docs/superpowers/plans/2026-09-23-replay-set-and-discovery-baseline.md`
   (the other agent's) holds out Morph. After `a76005d7` Morph is not in the suite at all — its
   shape label was indefensible. That document needs updating by its owner.
6. **`extractable_usd` remains refused**, and the P1 handoff is therefore unpriceable by decision,
   not by omission. The `regression_suite` audit problem is correctly still reported.
