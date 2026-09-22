# Task 2 review — the already-exploited control target, and the P1 spike handoff

**Verdict: APPROVE, superseded in part by the §7 re-check below.** The implementation is sound
and keeps its must-fix-free standing — the pin's parentage and the 5/5-vs-0/5 contrast both
verified independently. But the second pass found **one false factual claim in the gate record**
(the fork height's provenance) and the record has been corrected in place. That is a must-fix on
the *record*, and it is done; see §7.

**Provenance deviation, stated plainly.** This review was performed by the controller, not by a
separate reviewer subagent. The reviewer dispatch was interrupted twice by the machine running out
of memory (the user's report: the subagent was drawing all system resources and the process was
crashing). The controller did not implement this task — two implementer subagents did — so the
review is independent of the implementation, but it is not the independent-agent check the process
calls for, and the gap is recorded rather than hidden.

## What was independently verified

Every check below was run against the working tree, not read from the implementer's report.

### 1. The central claim — the pin is the vulnerable revision

The report claims the pre-patch pin `46e840222e11caf30a3a710b66d9333be76531b6` is the fix commit's
direct parent, and that the guard is absent at the former and present at the latter.

```
$ git rev-parse e73bfb21284074adc3d82b322fe8eccdbde6922d^
46e840222e11caf30a3a710b66d9333be76531b6          # == the declared pin

$ git show 46e84022…:contracts/periphery/DebtManager.sol | rg -c checkMarket
0                                                  # absent at pre-patch
$ git grep -c checkMarket e73bfb21…
e73bfb21…:contracts/periphery/DebtManager.sol:14   # present at the patch
```

**The claim holds.** The fix commit is `🚑 debt-manager: validate markets` (2023-08-18), it touches
`contracts/periphery/DebtManager.sol`, and its parent is exactly the pin. This is the claim the whole
task rests on, and it survives independent checking.

*(A false alarm worth recording: my first probe looked at `src/DebtManager.sol` and found the symbol
absent at both commits. The path is `contracts/periphery/`. The report's claim was right; my probe
was wrong. Recorded because a reviewer's near-miss is data about how the claim can be misread.)*

### 2. The tests bite — reproduced by mutation

The report lists ten mutations. I reproduced the load-bearing one independently: forcing
`if spec.PrePatchSHA == spec.PatchSHA` to never fire makes
`TestRecordControlRefusesAnUncitedOrUnpinnedIncident` fail with

```
control_test.go:59: pre-patch equals patch: err = <nil>, want a refusal naming "same commit"
```

Restored, package green, and the file's sha256 is `60c32564cebaf6fd9256fb3a9a83a743194b89fa40363ef641d690ad92b7bf3e`
— byte-identical to the hash the report records, so nothing was left mutated.

The report's own finding here is honest and worth keeping: two of the six refusals (the uncited loss
figure, the non-positive `extractable_usd`) are enforced **twice** — by an explicit Go check and by
the draft-07 schema that `writeThenLog` validates on every write. Removing only the Go check leaves
the test green *because the record is still refused, by the schema, with a message that still names
the field*. The tests bite the invariant; the Go checks are defence in depth. A reviewer who saw only
the first layer would have called it a broken test.

### 3. Schema discipline

```
incident: additionalProperties=False required=['url','date','loss_usd','loss_source']
control:  additionalProperties=False required=['pre_patch_sha','patch_sha','harness']
handoff:  additionalProperties=False required=['finding_id','extractable_usd','source','recorded_at']
```

The loss citation is mandatory in the schema, not merely checked in Go — which is the right place for
it, because a record that cannot be written without its citation cannot lie about its provenance.
`assets` package green, so the manifest is in sync.

### 4. The record does not overstate — the thing that mattered most

This task exists to unblock P1's Task 10. It did **not** claim to. The report's §6 is explicit:

> **NOT RUN: the P1 handoff.** No finding was ingested, no exec minted, no verdict recorded, and no
> `extractable_usd` measured. […] P1's Task 10 therefore remains blocked on **both** halves.

and it refuses the temptation the record offers — the incident's reported loss is **$7.6M**, and the
gate record declines to launder it into an *extractable* figure, on the correct grounds that measuring
one means simulating the extraction and reading the delta, which is P1's own Phase 2 spike. Given
this repo has twice fixed a defect whose shape was *a record asserting something untrue*, a control
target that pins a real vulnerability, runs a real harness at both commits (5/5 PASS at the patch,
0/5 at pre-patch, all five failing because `MarketNotListed` is never raised) and still refuses to
call its dollar figure an extraction is the behaviour to want.

## Observations, not findings

1. **`FORK_RPC_URL` is effectively solvable now, and the report does not press the point.** It records
   that free public archive endpoints served the fork — `https://mainnet.optimism.io` ran the whole
   harness; `https://optimism.drpc.org` had the state but 429'd; `publicnode` wants a token and
   `rpc.flashbots.net` prunes that height. So P1 Task 10's "blocked on `FORK_RPC_URL`" is a
   configuration step, not a missing capability. The report correctly declined to change P1's status
   on its own initiative; the controller should act on it when P1's Task 10 resumes.
2. **The harness demonstrates the absent guard, not a fund-draining extraction.** Stated that way
   everywhere, including in the gate record. That is the honest framing and it is what the control
   target is for — but it means the control target does not by itself supply the confirmed finding
   with a measured `extractable_usd` that P1 needs. P1's Task 10 needs a *finding* on this target,
   which is a separate piece of work.
3. **Scratch left in place** under `/home/xand/webv2-p0/target/` (the checkout, a clean pre-patch
   worktree, DeFiHackLabs) and `.scratch/p0/root` (campaign `C-725aa2c6a8`). All outside the module
   tree or gitignored. `$WEBV2_P0_DIR` was not exported, so the checkouts were placed by hand —
   worth fixing before the next operator run so the plan's paths are the real ones.

## Not verified

- `go test ./...` and `scripts/verify-full.sh` — deliberately not run: the full suite OOM-kills this
  machine (31 GiB total, ~9 GiB available, swap already deep into zram). The focused packages
  (`./internal/regression`, `./assets`) are green.
- The deployed bytecode ↔ pre-patch commit correspondence — argued from the fix commit's parent and
  the incident date, not verified byte-for-byte. The report says so itself.
- The other nine mutations — read, not reproduced. The one reproduced is the one whose invariant the
  task's central claim depends on.

## 7. Second pass — the two claims that carry the record, checked on purpose

Task 2's record is the input the spike rests on, and two claims carry all of it: the parentage of
the pin, and the 5/5-vs-0/5 result. This pass went after exactly those two, with the fork height
the third thing checked — because "a commit is not a fork pin" turned out to be where the record
was wrong.

**Claim 1, the pin's parentage — HOLDS.** Re-derived from the object store, not from the report:

```
$ git rev-list --parents -n 1 e73bfb21284074adc3d82b322fe8eccdbde6922d
e73bfb21… 46e840222e11caf30a3a710b66d9333be76531b6     # one parent, and it is the pin
$ git log -1 --format='%H %ci %s' 46e840222e…
46e840222e… 2023-08-17 18:42:51 -0300 🔧 finance: extend rewards program
$ git grep -c checkMarket <fix>          → contracts/periphery/DebtManager.sol:14
$ git show 46e84022…:contracts/periphery/DebtManager.sol | rg -c checkMarket   → 0
```

The guard is absent at the pin, present at the fix, and the pin is the fix's only parent. The
five matching tests exist (`testFakeMarket{CrossDeleverage,CrossLeverage,Leverage,Deleverage}`,
`testFakeMarketRollFixed`), so "5/5" counts a real five.

**Claim 2, the 0/5 at pre-patch — HOLDS, reproduced live.** Re-ran the arm in the scratch
checkout:

```
$ OPTIMISM_NODE=https://mainnet.optimism.io forge test --match-path test/DebtManager.t.sol \
    --match-test testFakeMarket -vv --fork-url optimism --fork-block-number 99811375
Suite result: FAILED. 0 passed; 5 failed; 0 skipped
# 3x "call reverted as expected, but without data"; 1x "AS != MarketNotListed()";
# 1x "Contract 0x0000…0000 does not exist … != MarketNotListed()"
```

Every failure is the expected refusal not happening. Two reviewer notes: my *first* attempt
reported 1 failed / 0 run, because I omitted `export OPTIMISM_NODE=…` — a missing env var reads
as a suite failure if you do not look at which line failed. And the gate record does document
the export, so the record is reproducible as written.

**Claim 3, "the fork height is the state the exploit ran against" — FALSE, and this is the
finding.** The harness forks 99,811,375 because *the project hardcoded it*:

```
$ rg -n 'createSelectFork' test/*.sol
test/DebtManager.t.sol:51:    vm.createSelectFork(vm.envString("OPTIMISM_NODE"), 99_811_375);
```

Against the chain: 99,811,375 → 1684525449 → **2023-05-19**. The attack tx `0x3d6367de…` ran at
**108,375,558** → 1692349893 → **2023-08-18** — three months later. And the exploited
implementation `0x675d410d…` has **no code at all** at 99,811,375 (`eth_getCode` returns `0x`);
it deployed at 107,135,785 on 2023-07-20. `--fork-block-number` cannot fix this: re-running with
108375557 still reports `(block: 99811375)` on every line, because the test's own
`createSelectFork` wins.

**Consequence, and what changed.** The source-level contrast survives, and §5 of the record
already framed the failures as "the expected refusal is absent" rather than "funds drained". What
does not survive is any downstream number computed at that height: an `extractable_usd` measured
on a fork predating the vulnerable deployment measures a counterfactual. The gate record's §3 and
§5 are corrected in place, §3.1 records the full SHA↔block↔address mapping, roadmap §4 gains the
law (*a fork run carries a resolved block*), and P1's Task 10 is re-scoped into **10a** (get a
finding to CONFIRMED — a pipeline run, not a spike) and **10b** (the spike, forking
108,375,557). The incident's `$7.6M` is now labelled in §2.4's own vocabulary as neither
demonstrated nor computed — a third quantity, someone else's reported figure.
