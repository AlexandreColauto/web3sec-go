# v1.6 Phase 2 spike record — the maximization loop on one confirmed finding

**Verdict: the operator run is NOT RUN. The spike's driver and its offline proof are
DONE and verified; no number was produced.**

The Phase 2 exit criterion has two halves, and this record keeps them apart (plan Task
10 header; `docs/gates/v16-P1.md` §7). Conflating them is exactly the failure the plan
names:

- **ARITHMETIC half** — two-round termination, rounds-to-exhaustion,
  `cumulative_attack_cost_usd`: **TEST-PROVEN**, in CI, with no Docker, no fork and no
  operator. Named tests: `internal/risk/replay_test.go` →
  `TestComputeReplaySeparatesDemonstratedFromComputed`,
  `TestComputeReplayRoundsUpAPartialFinalRound`, `TestReplayProfitabilityIsRequired`.
- **EXTRACTION half** — *"a defensible `extractable_usd` on one already-confirmed
  finding"*: **NOT SPIKE-PROVEN.** The spike has not been run, so this document names
  **no** finding id and offers **no** `extractable_usd`.

Plan: `docs/superpowers/plans/2026-09-21-v16-p1-p2-record-and-evidence.md` (Task 10).
Written 2026-09-21 at HEAD `2d8e3a90`.

---

## 1. What is DONE (Task 10 steps 1–2, entirely offline)

| Deliverable | State | Proof |
|---|---|---|
| `scripts/v16-spike.sh` | DONE | `bash -n` clean; `DRY_RUN=1` walks all six steps, exit 0 (§3.2) |
| `internal/cli/spike_driver_test.go` | DONE | `go test ./internal/cli -run TestSpikeDriverEmitsOnlyKnownFlags -count=1` → PASS (§3.3), with teeth proven by mutation (§3.4) |
| Operator run (steps 3–4) | **NOT RUN** | needs a mainnet RPC URL + a pinned block + one already-CONFIRMED finding on a real target (§4) |

`bash -n` proves the script parses and nothing else. The driver is the only place
`exec --profile fork-runner`, `mint --poc-tier` and `impact --replayable` are driven
together, so a typo in a flag name would otherwise surface mid-spike, with Docker up
and a fork pinned. That is what the offline test exists to prevent.

## 2. What the driver does

Interface, exactly as the plan's Step 1 specifies:

```
scripts/v16-spike.sh [--dry-run] <campaign> <finding> <fork-rpc> <block>
```

`set -euo pipefail`; **every** `webv2` call goes through one `run()` helper that
echoes the command and returns 0 when `DRY_RUN=1`. The six plan steps:

1. `exec --profile fork-runner --command "forge test --fork-url $RPC
   --fork-block-number $BLOCK --match-test $TEST_NAME" --finding "$FID"` → captures the
   `EXEC-*` id from the transcript's first field.
2. `mint "$C" "$FID" --exec "$EXEC" --type fork-test --poc-tier existence
   --description "state break on the pinned fork"`.
3. The amplification, at the same pin: `ladder start`, `ladder add` (the rung the
   operator selects via `AMP_NAME`/`AMP_AXES`/`AMP_RATIO`), a second `exec` with
   `--match-test "$AMP_TEST"`, `ladder repro` of that rung onto the second exec, then
   `mint --poc-tier maximized` and `ladder complete`.
4. If replayable (`REPLAYABLE=1`, the default): `impact --replayable
   --extractable-per-round X --max-loss POOL --gas-cost G --frequency F --rounds-run 2
   --replay-assumption ... --replay-blocker ...`.
5. `audit "$C"`, with the exit code carried into the summary and out of the script.
6. The machine-readable summary block (`--- v16-spike summary ---`, `key: value` lines):
   campaign, finding, pinned block, RPC host (host only, never the full URL), tiers
   reached, both exec ids, the maximal rung, the per-round extraction, and — where
   replayable — `rounds_to_exhaustion`, `ceiling_usd`, `cumulative_attack_cost_usd`,
   plus `audit_exit`.

Operator knobs beyond the four arguments are documented in the script's header
(`TEST_NAME`, `AMP_*`, `REPLAYABLE`, `X_PER_ROUND`, `POOL_USD`, `GAS_USD`,
`FREQ_PER_DAY`, `REPLAY_ASSUMPTION`, `REPLAY_BLOCKER`).

Step 4 passes `--max-loss` but no `--extractable`, so `impactBody` records the replay
without touching a previously measured `extractable_usd`: `setFloatField` treats a null
value as a no-op (`internal/risk/pyvalue.go:81`). The maximized measurement therefore
survives step 4.

## 3. Offline evidence (reproducible now, no Docker, no RPC)

### 3.1 Syntax

```
$ bash -n scripts/v16-spike.sh
$ echo $?
0
```

### 3.2 Dry run — every command echoed, nothing executed

```
$ DRY_RUN=1 bash scripts/v16-spike.sh C-xxxxxxxxxx F-xxxxxxxxxx http://localhost:8545 21000000
== step 1: existence exec on the pinned fork ==
webv2 exec --profile fork-runner --command forge test --fork-url http://localhost:8545 --fork-block-number 21000000 --match-test test_exploit --finding F-xxxxxxxxxx
== step 2: mint the existence tier ==
webv2 mint C-xxxxxxxxxx F-xxxxxxxxxx --exec EXEC-DRYRUN-1 --type fork-test --poc-tier existence --description state break on the pinned fork
== step 3: amplify at the same pin, then mint the maximized tier ==
webv2 ladder C-xxxxxxxxxx start F-xxxxxxxxxx
webv2 ladder C-xxxxxxxxxx add F-xxxxxxxxxx --name amplified --description amplification of the base variant at the same pin --axes capital-minimization --ratio 1
webv2 exec --profile fork-runner --command forge test --fork-url http://localhost:8545 --fork-block-number 21000000 --match-test test_exploit_amplified --finding F-xxxxxxxxxx
webv2 ladder C-xxxxxxxxxx repro F-xxxxxxxxxx RUNG-DRYRUN-1 --exec EXEC-DRYRUN-2
webv2 mint C-xxxxxxxxxx F-xxxxxxxxxx --exec EXEC-DRYRUN-2 --type fork-test --poc-tier maximized --description amplified state break at the same pin
webv2 ladder C-xxxxxxxxxx complete F-xxxxxxxxxx
== step 4: the replay arithmetic ==
webv2 impact C-xxxxxxxxxx F-xxxxxxxxxx --replayable --extractable-per-round 0 --max-loss 0 --gas-cost 0 --frequency 1 --rounds-run 2 --replay-assumption replayed against the pinned fork state --replay-blocker none identified at the pinned block
== step 5: audit ==
webv2 audit C-xxxxxxxxxx
== step 6: machine-readable summary ==
--- v16-spike summary ---
campaign: C-xxxxxxxxxx
finding: F-xxxxxxxxxx
pinned_block: 21000000
fork_rpc_host: localhost:8545
tiers_reached: existence,maximized
exec_existence: EXEC-DRYRUN-1
exec_maximized: EXEC-DRYRUN-2
maximal_rung: RUNG-DRYRUN-1
extractable_per_round_usd: 0
rounds_to_exhaustion: (dry-run)
ceiling_usd: (dry-run)
cumulative_attack_cost_usd: (dry-run)
audit_exit: 0
--- end v16-spike summary ---
$ echo $?
0
```

Exit 0, and the driver walks end to end without Docker, an RPC or a campaign.

### 3.3 The flag test

```
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/cli -run TestSpikeDriverEmitsOnlyKnownFlags -count=1 -v
=== RUN   TestSpikeDriverEmitsOnlyKnownFlags
--- PASS: TestSpikeDriverEmitsOnlyKnownFlags (0.00s)
PASS
ok  	websec/internal/cli	0.011s
```

The test reads `scripts/v16-spike.sh`'s **source**, extracts every `run <verb> ...`
invocation (joining backslash continuations) and checks each verb against
`CommandNames()` — the dispatch registry itself — and each `--flag` against the
package's own non-test sources. Nothing is hand-copied: a renamed CLI flag or verb
breaks this test rather than the spike. Three further assertions keep it from passing
vacuously: at least one invocation must exist; the loop's five verbs (`exec`, `mint`,
`ladder`, `impact`, `audit`) must all appear; and every direct `webv2` call must sit
inside `run()` (so a bare call cannot escape the flag scan).

Full package run after the change: `go test ./internal/cli -count=1` → `ok
websec/internal/cli 34.041s`.

### 3.4 The test has teeth (mutation evidence)

Each mutation was applied to `scripts/v16-spike.sh`, the test run, then the file
restored:

| Mutation | Result |
|---|---|
| `--poc-tier existence` → `--poc-tierz existence` | FAIL: `driver emits flag "--poc-tierz" that no command declares` |
| `run impact` → `run impacts` | FAIL: `driver invokes unregistered verb "impacts"` **and** `driver never invokes "impact" — the Phase 2 loop is incomplete` |
| a bare `webv2 audit "$C"` added outside `run()` | FAIL: `bare webv2 call outside run() at line 145` |

After restore: `bash -n` clean and the test PASSes again.

**One documented deviation from the plan's skeleton.** The skeleton scans the whole
source for `--flags`; this test scans the invocation lines it already extracted. The
reason is mechanical: the forge command handed to `exec --command` carries foundry's
own `--fork-url` / `--fork-block-number` / `--match-test`, which no webv2 command
declares, so a whole-source scan fails on correct code. Scoping the scan to the
invocations is also truer to what the test claims to assert — what `run()` actually
emits. The `registeredNames()` helper the skeleton mentions was not needed:
`CommandNames()` (`internal/cli/cli.go`) is the registry's existing read side and is
already used by other cli tests.

## 4. The operator run — NOT RUN

**Owner: `<OPERATOR>` (the human with the RPC and the finding).** Steps 3–4 of Task 10
are theirs; nothing in this tree can stand in for them.

**Blocker, precisely:** the spike needs (a) a mainnet **fork RPC URL** and (b) a
**pinned block number**, plus (c) **one already-CONFIRMED finding on a real target**
whose exploit reproduces on that pin. This machine has Docker up, but `FORK_RPC_URL` is
unset, no block is pinned, and the campaign in this checkout has no CONFIRMED finding
(`docs/gates/v16-P1.md` §5). So the run cannot be faked or approximated here: it is not
a code gap, it is missing inputs.

The command, verbatim (never paste the full RPC URL into a document — the summary
block prints the host only):

```bash
scripts/v16-spike.sh C-xxxxxxxxxx F-xxxxxxxxxx "$FORK_RPC" 21000000 | tee /tmp/v16-spike.out
```

Then fill in §5 from `/tmp/v16-spike.out`, and confirm `audit` came back clean and the
summary block carries both tiers plus — where the finding is replayable — `rounds_run:
2` with a non-zero `rounds_to_exhaustion` and `cumulative_attack_cost_usd`.

## 5. The record's unfilled fields

Every field below is **PENDING — operator**. None of them is inferable from the
offline work, and none is guessed here.

| Field | Value |
|---|---|
| Campaign id | `<PENDING — operator>` |
| Finding id (already CONFIRMED on a real target) | `<PENDING — operator>` |
| Pinned block | `<PENDING — operator>` |
| RPC host (never the full URL) | `<PENDING — operator>` |
| `EXEC-*` — existence run | `<PENDING — operator>` |
| `EXEC-*` — maximized run | `<PENDING — operator>` |
| Tiers reached | `<PENDING — operator>` |
| `extractable_usd` and how it was derived | `<PENDING — operator>` |
| Replay figures (`rounds_to_exhaustion`, `ceiling_usd`, `cumulative_attack_cost_usd`), or "not replayable" | `<PENDING — operator>` |
| `audit` verdict | `<PENDING — operator>` |

## 6. What the spike does NOT prove

Running it would still not prove any of the following, and the record must not be read
as if it did: no rubric integration (no rubric dimension is scored or funded by the
number), no class-metric funding (the extraction figure does not move a
class-level metric or a bounty band by itself), and no status field (nothing in the
finding's status lifecycle is written). Those are **Phase 5** work. The spike's whole
claim is narrower and is the one the Phase 2 criterion asks for: that the loop, driven
end to end on one already-confirmed finding against a pinned fork, produces a
defensible `extractable_usd` and — where the finding is replayable — the two-round
termination arithmetic on that finding's own bytes. The arithmetic itself is already
test-proven (§ top); the spike would add the extraction instance, nothing more.

## 7. What remains for the operator

1. Run §4 and fill §5.
2. Commit the three Task 10 files:
   `git add scripts/v16-spike.sh internal/cli/spike_driver_test.go docs/gates/v16-P2-spike.md`
   (this document is written now, before the run, and is honest about that state).
3. **Stale cross-reference, owned by the controller:** `docs/gates/v16-P1.md` §7b
   (lines ~421–422) asserts that `docs/gates/v16-P2-spike.md` and `scripts/v16-spike.sh`
   "**do not exist** in this tree". Both now exist. Those bullets were true at HEAD
   `f854a599` and are superseded by this record; the P1 document was left untouched
   because it is Task 11's dated artifact, not Task 10's.
