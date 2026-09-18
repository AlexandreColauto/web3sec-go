# Morph gold re-run protocol (operator-driven measurement loop)

The 0/2 score only moves when a fresh campaign runs against the pinned target on
a freshly built binary. This document is that protocol. **Executing it is an
operator session — it is not automated, and it does not run in CI.**

Baseline it is measured against: the archived campaign `C-7f1005ecd5` scored
`{"found": [], "missed": ["G-01", "G-02"], "false_positives": 0, "verdict": "FAIL"}`
against `web3sec-final/targets/gold-findings.json` (Morph L2 @ `22ca805e`).

Paths the commands below use — set them once:

```bash
WEB3SEC2=~/Projects/dsh-plugins/websec2   # holds the sibling checkouts web3sec-go/, web3sec-final/, morph/
WS=$HOME/campaigns/morph-rerun            # campaign workspace root (holds campaigns/)
SCRATCH=$WS/targets                       # scratch checkouts — never the fixture tree
mkdir -p "$WS" "$SCRATCH"
```

Everything this protocol says to **record** goes into the campaign record: the
campaign dir itself plus a write-up beside the 0/2 eval
(`$WEB3SEC2/morph/FRAMEWORK_EVALUATION.md`), which is the template for its shape.

## 1. Pinned target

Morph L2 @ vulnerable commit `22ca805e` ("add gas-oracle&prover ci (#500)").

Verify the checkout hash before starting, and record the actual hash:

```bash
git -C "$WEB3SEC2/morph" rev-parse HEAD          # must start 22ca805e
```

The fixture checkout sits on a different commit today (`8e8b6c5`). Do **not**
move it — historical fixtures stay where they are. Take a scratch worktree:

```bash
git -C "$WEB3SEC2/morph" worktree add "$SCRATCH/morph-22ca805e" 22ca805e
```

**A fresh release on THIS checkout is required before discovery starts:**

```bash
bash scripts/release.sh      # from the web3sec-go checkout that will run the campaign
```

It must exit 0 and end with:

```
RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean
```

Record the checkout hash, the `sha256:` and `size:` lines, and the tail of the
release log in the campaign record. Install the binary the campaign will use:

```bash
install -m755 dist/webv2 ~/.local/bin/webv2
```

`docs/sdd/release-final.log` (committed at `10182b5c`) proves **the script works**
— it was a green run on a different commit. It is never a substitute for the
fresh run. Repeatability is the point of the measurement loop.

## 2. Contamination re-check (FIRST)

Run this **before any campaign work**, on a clean environment. The store it reads
is machine-global (`~/.webv2/shared-memory`), not repo-local: a clean checkout
says nothing about it, and every `publish`/`globalize` during a campaign adds
rows.

Store integrity, then the benchmark's keyword list — copied verbatim from
`contamination_check` in `web3sec-final/targets/gold-findings.json`:

> Sherlock morphl2 audit, ScaBench, prevStateRoot/commitBatch/finalizeBatch, or onDropMessage

```bash
webv2 shared --verify
rg -i -c 'sherlock|morphl2|scabench|prevstateroot|commitbatch|finalizebatch|ondropmessage' \
   ~/.webv2/shared-memory/memory.json
```

Expected: `integrity: PASS`, then no output and exit 1 (no matching row) =
**CLEAN**. Grep the rows file (`memory.json`), not the whole store directory —
the manifest carries store provenance notes, not corpus rows.

A hit means the store already knows something about this target. Read the row; if
it names this finding, either clean the store or run the campaign on the strict
A/B arm the benchmark documents (`strict_ab_option`): point
`WEBV2_GLOBAL_MEMORY_DIR` at an empty directory so the run carries zero corpus
memory.

Record the **date**, the result, and the row count in the campaign record
(766 approved global rows on 2026-09-18).

**CI note:** a runner with a persistent home dir will fail this check by design.
That is the check working, not a bug — and it is one reason the protocol does not
run in CI (§6).

## 3. Campaign protocol

Start from the workspace root; `webv2` resolves `campaigns/` under the cwd.

```bash
cd "$WS"
webv2 init --program "Morph L2"                     # -> campaigns/<C-id>
webv2 snap <C-id> "$SCRATCH/morph-22ca805e"         # source pin; record the snapshot id
webv2 index <C-id> --src "$SCRATCH/morph-22ca805e"  # structural index (probes need it)
```

The campaign's own `RUNBOOK.md` (dropped by `init`) is the general lifecycle.
Three obligations are specific to this measurement.

**3.1 Model `rollup_finalization` as a state machine.** Not optional: the
per-machine liveness gate refuses a model whose liveness coverage is partial.
Minimal shape (`model.json`; schema `assets/schema/protocol_model.schema.json`):

```json
{"state_machines": [{"name": "rollup_finalization",
  "states": [{"id": "committed"}, {"id": "challenged"},
             {"id": "finalized", "terminal": true}],
  "transitions": [
    {"from": "committed",  "to": "challenged", "trigger": "challengeState"},
    {"from": "challenged", "to": "finalized",  "trigger": "finalizeBatch"}]}]}
```

```bash
webv2 model <C-id> model.json
```

The machine **name** is the stable handle (the `LC-###` ids are display-only and
shift when a machine sorts earlier).

**3.2 Expected gate firings.** These are the hardening work working. Do not route
around them — record each firing you see.

1. **Per-machine liveness refusal** —
   `protocol model: state machine(s) <names> have no liveness invariant (one per machine — stage 37)`.
   Refused at load, before any write. If the uncovered machine is
   `rollup_finalization`, the gate has just named the G-01 gap. Fix the *model*
   (or register a real liveness invariant covering that machine), never the gate.
2. **Cold-probe nag** — while the phase is DISCOVERY with no probe emit on
   record, the cockpit carries `webv2 probes <C-id> run --emit`:
   "cold probe surface — DISCOVERY is running with no probe emit on record, so
   the mechanical surface is unprobed". Clear it while discovery is still open:

   ```bash
   webv2 probes <C-id> run --emit
   ```

   That mechanical pass is what the later gates read. The line is advisory — it
   gates nothing; it stands until the emit is on record.
3. **Exec-relevance refusal** —
   `invariant verify failed: cited exec EXEC-… does not target any applies_to contract of INV-… (<reason>)`,
   with `reason` ∈ `no-exec-record`, `no-command-record`, `no-target-match`. A
   Foundry full-suite log names every contract it printed, so it no longer closes
   an invariant. Close with an exec whose **recorded command** targets the
   invariant's `applies_to` contract (`--match-contract` / `--match-path`), then:

   ```bash
   webv2 invariant-verify <C-id> <INV-id> --exec <EXEC-id>
   ```

Record the phase transitions, the firings, and the closing exec per invariant.

## 4. Scoring

The invocation, pinned by the plan and verified 2026-09-18 against the archived
campaign (exit 0, the 0/2 baseline above):

```bash
python3 scripts/eval-gold.py \
  --gold "$WEB3SEC2/web3sec-final/targets/gold-findings.json" \
  --campaign "$WS/campaigns/<C-id>"
```

The plan spells `--gold` as `web3sec-final/targets/gold-findings.json`; `$WEB3SEC2`
is the directory that spelling is relative to (the parent of the sibling
checkouts). Same read-only file either way. The scorer never writes.

Read the match evidence before confirming anything, then record the operator's
semantic confirmation (advisory — it never moves `pass`/`bonus`/`verdict`):

```bash
python3 scripts/eval-gold.py \
  --gold "$WEB3SEC2/web3sec-final/targets/gold-findings.json" \
  --campaign "$WS/campaigns/<C-id>" --confirm G-01
```

Record the full JSON verdict **and** the FP count in the campaign record.

The bar, verbatim from the benchmark's `scoring` block:

- `pass`: "G-01 found at CONFIRMED with E4+ evidence (or HYPOTHESIS/INVESTIGATING
  with the correct root cause named and a working PoC draft)"
- `bonus`: "G-02 also found"
- `false_positive_budget`: "count all other CONFIRMED findings; a
  submission-ready report that includes G-01 but buries it under 10+ FPs is a
  partial result"

The scorer's own gate, from the repo root with no path hacks (both green
2026-09-18, 25 tests):

```bash
python3 -m unittest scripts.eval_gold_test
python3 scripts/eval_gold_test.py
```

## 5. Honesty rules

- **No score pressure on the record.** The record is evidence, not a pitch. The
  re-run score is not a deliverable of the closure plan — framework quality and
  measurement repeatability are.
- **A miss is recorded as a miss**, with its failure analysis. The 0/2 eval
  (`$WEB3SEC2/morph/FRAMEWORK_EVALUATION.md`) is the template: headline result,
  what the framework did well with receipts, what it failed at with receipts, and
  why the gold findings were missed.
- **Numbers learned during the re-run enter framework DATA** (assets, playbooks,
  prompts, weights) only through the provenance rubric in
  `docs/eval-methodology.md`: a `provenance` row
  `{claim, source_url, checked_date, verdict, tier}` per numeric claim. Numbers
  without a row enter only as `uncorroborated` and render that way. The scorer's
  output is an eval artifact, not framework DATA.
- **Record what actually happened**, including gate firings, refusals, and
  reversals. A verdict that cannot be reproduced from the campaign record is not
  a measurement.

## 6. Out of scope

- **No exploit-development automation.** No task, script, or CI step synthesizes
  exploits or runs attacks; the re-run is an operator session using the framework
  normally.
- **No CI execution of this protocol.** The score is not a CI gate; runners with
  persistent home dirs fail the contamination check by design (§2).
- **No benchmark edits.** `web3sec-final/targets/gold-findings.json` is read-only
  evidence — changing it invalidates the comparison to 0/2. The pinned target is
  frozen the same way: take a scratch worktree for `22ca805e` (§1) instead of
  moving the fixture checkout.
- **No release substitution.** The archived `docs/sdd/release-final.log` is
  evidence the script works; only the operator's fresh `bash scripts/release.sh`
  on the campaign's checkout opens discovery (§1).
