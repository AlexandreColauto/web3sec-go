### Task 5: re-run protocol document (the measurement loop)

The score only moves when a fresh operator campaign runs against the pinned target on the hardened binary. This task ships the protocol; executing it is the operator's session (explicitly out of CI and out of this plan's automation).

**Files:**
- Create: `docs/eval/morph-rerun-protocol.md`

**Interfaces:**
- Consumes: `scripts/eval-gold.py` (Task 4); `web3sec-final/targets/gold-findings.json` (benchmark, read-only); the contamination check recorded in the benchmark (`contamination_check.checked: 2026-09-07` — the protocol re-runs it); `docs/eval-methodology.md` (claim-intake rubric for anything the re-run learns).
- Produces: the canonical re-run checklist.

- [ ] **Step 1: Write the protocol document**

Content (all sections mandatory, no placeholders):

1. **Pinned target**: Morph L2 @ vulnerable commit `22ca805e` (verify the checkout hash before starting; record the actual hash). **A fresh `bash scripts/release.sh` on THIS checkout is required before discovery starts and must print `RELEASE OK`** — an archived log from a different commit (`docs/sdd/release-final.log` @ `10182b5c`) proves a different checkout was clean and is cited only as evidence the script itself works, never as a substitute for the fresh run. Repeatability is the point of the measurement loop.
2. **Contamination re-check**: the global store it reads (`~/.webv2/shared-memory`) is machine-global, not repo-local — run the check FIRST, before any campaign work populates the store, on a clean environment; record the date + result in the campaign record. Note for CI: runners with persistent home dirs will fail this check by design — that is the check working, not a bug. Re-run against the benchmark's `contamination_check` keyword list (copy it verbatim from the JSON).
3. **Campaign protocol**: fresh campaign; model the protocol including `rollup_finalization` as a state machine (the hardening branch's per-machine liveness gate now refuses the model without it — that gate firing is expected and is itself a test of the hardening work); run the lifecycle machines' probes (`probes run --emit`) while discovery is open (the Task 11 cold-probe warning will nag until this happens — expected); close invariants only with execs that target `applies_to` (Task 1 gate now refuses suite-run citations — expected).
4. **Scoring**: `python3 scripts/eval-gold.py --gold web3sec-final/targets/gold-findings.json --campaign <dir>` (invocation pinned exactly as Task 4 Step 4 verified); operator semantic confirmation via `--confirm G-01` after reading the match evidence; record the JSON verdict and the FP count in the campaign record. FP-budget language comes from the benchmark's `scoring.false_positive_budget` verbatim. The scorer's own gate, from the repo root with no path hacks: `python3 -m unittest scripts.eval_gold_test` (also runnable as `python3 scripts/eval_gold_test.py`; both verified green 2026-09-18, 25 tests).
5. **Honesty rules**: no score pressure on the record; a miss is recorded as a miss with the failure analysis (the 0/2 eval's diagnosis is the template); numbers learned during the re-run enter framework DATA only through the `docs/eval-methodology.md` provenance rubric.
6. **Out of scope**: no exploit development automation, no CI execution of the protocol, no benchmark edits (the benchmark file is read-only evidence; changing it invalidates the comparison to 0/2).

- [ ] **Step 2: Verify the protocol's commands actually exist**

Run every command the protocol names with `--help` or against a scratch campaign (never against the pinned target): `webv2 probes run --emit`, `python3 scripts/eval-gold.py --help`, and confirm `scripts/release.sh` exists and is runnable on a scratch checkout (the canonical green full-run evidence remains `docs/sdd/release-final.log`; Task 5 does not re-run a full release — the protocol itself requires the operator's fresh run at execution time).
Expected: all commands resolve; any drift is fixed in the doc before commit.

- [ ] **Step 3: Commit**

```bash
git add docs/eval/morph-rerun-protocol.md
git commit -m "docs(eval): Morph gold re-run protocol (operator-driven measurement loop)"
```

---

