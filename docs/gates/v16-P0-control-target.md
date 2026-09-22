# v1.6 Phase 0 — the already-exploited control target

**Verdict: OPERATOR-RUN for the sourcing, the pre-patch pin and the harness run;
NOT RUN for the P1 handoff.**

A real, publicly exploited project — Exactly Protocol, 2023-08-18, ~$7.6M — is
sourced, cloned, pinned at its **pre-patch** commit and run under its **own**
harness at that pin. The handoff P1's Phase 2 spike consumes is **not**
recorded: no finding on this target is CONFIRMED and no `extractable_usd` has
been measured. The campaign's audit is therefore **red**, and it is red on the
missing handoff alone (§4).

**How to read this record — the distinction the plan insists on.** Two
different things were proven in Task 2, and they are not the same thing:

| | what it is | where it is proven |
|---|---|---|
| the *code* refuses a bad record | unit tests + mutation evidence | `internal/regression/control_test.go`, `internal/audit/sections/regressionsuite_test.go`, the Task 2 report |
| a *real* control target exists | a sourced incident, a real pre-patch pin, a real harness run at that pin | this document, §1–§3 |
| the *handoff* P1 consumes exists | a CONFIRMED finding + a measured `extractable_usd` | **nowhere — NOT RUN**, §4 |

A red audit is the correct state for this target and is not a defect in the
record: §3a's control target is finished only when it carries both the control
block and the handoff, and this one carries only the first.

## 1. The target

| field | value |
|---|---|
| program | Exactly Protocol |
| repo | `exactly-protocol/protocol` |
| record_id | `exactly-protocol` |
| kind / shape | `control` / `already-exploited` |
| **pre-patch SHA** | `46e840222e11caf30a3a710b66d9333be76531b6` (2023-08-17) |
| **patch SHA** | `e73bfb21284074adc3d82b322fe8eccdbde6922d` (2023-08-18) |
| target id | `T-7e2781f96e25` |
| campaign | `C-725aa2c6a8` (scratch root `.scratch/p0/root`, gitignored) |
| snapshot | `src-46e840222e11` (git-clean, 334 files, foundry / solc 0.8.17) |
| harness | foundry |

The patch SHA is the fix commit's parent's child: `46e840222e…` is the direct
parent of `e73bfb2128…`, which is `🚑 debt-manager: validate markets` — the
emergency fix pushed the day of the incident. `checkMarket` is **absent** from
`contracts/periphery/DebtManager.sol` at the pre-patch commit and present at the
patch commit:

```
$ cd /home/xand/webv2-p0/target/exactly
$ git worktree add -q --detach /home/xand/webv2-p0/target/exactly-prepatch 46e840222e11caf30a3a710b66d9333be76531b6
$ rg -c "checkMarket" contracts/periphery/DebtManager.sol || echo "checkMarket ABSENT at pre-patch (expected)"
checkMarket ABSENT at pre-patch (expected)
```

The four `regress` commands, as run (binary `.scratch/webv2`, built from the
working tree at `b36fb5905d8d`):

```
$ ./.scratch/webv2 --root .scratch/p0/root init --program 'Exactly Protocol'
initialized C-725aa2c6a8 at .scratch/p0/root/campaigns/C-725aa2c6a8

$ ./.scratch/webv2 --root .scratch/p0/root snap C-725aa2c6a8 /home/xand/webv2-p0/target/exactly-prepatch
pinned src-46e840222e11 (git-clean, 334 files)
  toolchain: foundry — solc 0.8.17 (detected from the pinned tree)

$ ./.scratch/webv2 --root .scratch/p0/root regress C-725aa2c6a8 target add-control \
    --program 'Exactly Protocol' --record-id 'exactly-protocol' \
    --repo 'exactly-protocol/protocol' \
    --incident-url 'https://medium.com/@exactly_protocol/exactly-protocol-incident-post-mortem-b4293d97e3ed' \
    --incident-date '2023-08-18' --loss-usd '7600000' \
    --loss-source 'Exactly Protocol Incident Post-Mortem (2023-08-30): "financial losses approximating $7.6 million"' \
    --postmortem-url 'https://medium.com/@exactly_protocol/exactly-protocol-incident-post-mortem-b4293d97e3ed' \
    --pre-patch-sha '46e840222e11caf30a3a710b66d9333be76531b6' \
    --patch-sha 'e73bfb21284074adc3d82b322fe8eccdbde6922d' \
    --harness-runner 'foundry' \
    --harness-command 'forge test --match-path test/DebtManager.t.sol --match-test testFakeMarket -vv'
control target T-7e2781f96e25 recorded (pre-patch 46e840222e11caf30a3a710b66d9333be76531b6)

$ ./.scratch/webv2 --root .scratch/p0/root regress C-725aa2c6a8 target pin T-7e2781f96e25 \
    --resolved-sha 46e840222e11caf30a3a710b66d9333be76531b6 \
    --snapshot src-46e840222e11 --actor "$(whoami)"
pinned T-7e2781f96e25 to 46e840222e11caf30a3a710b66d9333be76531b6 at snapshot src-46e840222e11
```

`webv2 regress <cid> status`:

```
1 target(s), 0 run(s)
T-7e2781f96e25  control   Exactly Protocol         sha=46e840222e11caf30a3a710b66d9333be76531b6 snapshot=src-46e840222e11
T-7e2781f96e25  control pre-patch=46e840222e11caf30a3a710b66d9333be76531b6 handoff=- extractable_usd=-
```

`webv2 --root .scratch/p0/root audit C-725aa2c6a8 --json` (exit 1), the
`regression_suite` section verbatim:

```json
{
  "checked": 1,
  "targets": [
    {
      "target_id": "T-7e2781f96e25",
      "kind": "control",
      "program": "Exactly Protocol",
      "shape": "already-exploited",
      "commit_hint": "46e840222e11caf30a3a710b66d9333be76531b6",
      "resolved_sha": "46e840222e11caf30a3a710b66d9333be76531b6",
      "snapshot_id": "src-46e840222e11",
      "runs": 0,
      "control_pre_patch_sha": "46e840222e11caf30a3a710b66d9333be76531b6",
      "handoff_finding_id": "",
      "handoff_extractable_usd": ""
    }
  ],
  "runs": [],
  "measurement": "rediscovery",
  "problems": [
    "control target T-7e2781f96e25 carries no P1 handoff — the Phase 2 spike's extraction half stays blocked until a CONFIRMED finding and its extractable_usd are recorded here"
  ],
  "ok": false
}
```

Two things to read out of that section, both of them live rather than asserted:
the control target is **not** reported as carrying "no control block" (the
incident, the pre-patch pin and the harness are all on the record), and the
absent handoff figure renders as `""`, **not** as `0` — a section may not print
a zero that reads as a measurement.

## 2. The incident and its citation

| field | value |
|---|---|
| incident url | `https://medium.com/@exactly_protocol/exactly-protocol-incident-post-mortem-b4293d97e3ed` |
| date | 2023-08-18 |
| loss | `$7,600,000` (`--loss-usd 7600000`) |
| loss_source | Exactly Protocol Incident Post-Mortem (2023-08-30): "financial losses approximating $7.6 million" |
| postmortem url | same as the incident url (the project's own post-mortem is both) |
| attack tx | `https://optimistic.etherscan.io/tx/0x3d6367de5c191204b44b8a5cf975f257472087a9aadc59b5d744ffdef33a520e` |

The figure is the project's own, quoted verbatim from the post-mortem's
abstract: *"Exactly Protocol suffered a security breach on August 18, 2023, that
resulted in financial losses approximating $7.6 million."* The same document
names the root cause — *"a lack of input validation in several functions
exposed by the DebtManager contract"*, bypassed by passing a malicious `market`
argument — which is exactly the call the fix commit guards with `checkMarket`
and exactly what the harness below exercises. No loss figure in this record is
uncited, and none was derived by us.

## 3. The harness

Runner `foundry`; the project's own repository is the harness — `foundry.toml`,
`test/Fork.t.sol`, and the tests the fix commit itself added. The fix commit
`e73bfb2128…` adds `+90/-0` lines to `test/DebtManager.t.sol`, five tests that
each assert the fake market is refused with `MarketNotListed`:
`testFakeMarketLeverage`, `testFakeMarketDeleverage`,
`testFakeMarketCrossLeverage`, `testFakeMarketCrossDeleverage`,
`testFakeMarketRollFixed`. The harness is fork-based: it selects Optimism
mainnet at block `99,811,375`, the state the exploit ran against.

**At the patch commit — the project's own tests pass (5/5):**

```
$ cd /home/xand/webv2-p0/target/exactly
$ git checkout -q e73bfb21284074adc3d82b322fe8eccdbde6922d
$ printf '\n[rpc_endpoints]\noptimism = "https://mainnet.optimism.io"\n' >> foundry.toml
$ export OPTIMISM_NODE=https://mainnet.optimism.io
$ forge test --match-path 'test/DebtManager.t.sol' --match-test testFakeMarket -vv

Ran 5 tests for test/DebtManager.t.sol:DebtManagerTest
[PASS] testFakeMarketCrossDeleverage() (gas: 2287906)
[PASS] testFakeMarketCrossLeverage() (gas: 1513669)
[PASS] testFakeMarketDeleverage() (gas: 1283518)
[PASS] testFakeMarketLeverage() (gas: 1321905)
[PASS] testFakeMarketRollFixed() (gas: 2011828)
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 45.75s (47.77s CPU time)
```

**At the pre-patch commit — the same five tests fail (0/5), because the
`MarketNotListed` refusal never happens:** the call is not validated, so it
reaches the attacker-supplied market instead of being stopped at the boundary.

```
$ git checkout -q 46e840222e11caf30a3a710b66d9333be76531b6
$ git show e73bfb21284074adc3d82b322fe8eccdbde6922d:test/DebtManager.t.sol > /tmp/dm_fix_commit.sol
$ cp /tmp/dm_fix_commit.sol test/DebtManager.t.sol      # the fix commit's file, byte-identical
$ rg -c "checkMarket" contracts/periphery/DebtManager.sol || echo "checkMarket ABSENT (vulnerable revision)"
checkMarket ABSENT (vulnerable revision)
$ forge test --match-path 'test/DebtManager.t.sol' --match-test testFakeMarket -vv

Ran 5 tests for test/DebtManager.t.sol:DebtManagerTest
[FAIL: Error != expected error: AS != MarketNotListed()] testFakeMarketCrossDeleverage() (block: 99811375) (gas: 2255374)
[FAIL: call reverted as expected, but without data] testFakeMarketCrossLeverage() (block: 99811375) (gas: 1447170)
[FAIL: call reverted as expected, but without data] testFakeMarketDeleverage() (block: 99811375) (gas: 1291101)
[FAIL: call reverted as expected, but without data] testFakeMarketLeverage() (block: 99811375) (gas: 1388949)
[FAIL: call reverted as expected, but without data] testFakeMarketRollFixed() (block: 99811375) (gas: 2018510)
Suite result: FAILED. 0 passed; 5 failed; 0 skipped; finished in 2.11s (1.90s CPU time)
```

Read precisely: the pre-patch failures are *not* "the attack succeeded and
drained funds". They are "the expected refusal is absent" — `call reverted as
expected, but without data` means the call reverted inside the unvalidated fake
market, not at the `checkMarket` boundary. That is the vulnerability as the
post-mortem describes it (a missing input validation on `market`), demonstrated
at the pinned revision with the project's own test, and nothing more.

**Two deviations from the plan's Step 8 recipe, both recorded:**

1. `[rpc_endpoints] optimism` was appended to the **scratch checkout's**
   `foundry.toml` (outside the module tree; nothing under `assets/` or the repo
   was touched). Neither the pre-patch nor the patch commit commits an
   `[rpc_endpoints]` section, so forge-std's `getChain(10)` →
   `vm.rpcUrl("optimism")` throws `CheatCodeError("invalid rpc url optimism")`
   and forge-std re-reverts instead of falling back to its default URL:
   `[FAIL: invalid rpc url: optimism] setUp() (block: 99811375)`.
2. The plan's Step 8 says "the harness command that demonstrates the exploit".
   The command run is `forge test --match-path test/DebtManager.t.sol
   --match-test testFakeMarket -vv`, i.e. the five tests the project's own fix
   commit added. The harness is the project's; the tests are the project's; the
   pin is real. What the run demonstrates is the absent guard (§3 above).

**Observation for P1, not a change to its status.** `FORK_RPC_URL` is still
unset on this machine, but a fork does not require it: the free public archive
endpoints `https://mainnet.optimism.io` and `https://optimism.drpc.org` both
returned code at Optimism block `99,811,375` (`eth_getCode` on the WETH
predeploy). `mainnet.optimism.io` served the whole harness run; `drpc.org`
rate-limited it (`HTTP 429 ... You reached Public endpoint rate limit`).
`https://ethereum-rpc.publicnode.com` refuses archive requests without a token
and `https://rpc.flashbots.net` prunes state at that height. This is recorded
because it is a measurement; P1 Task 10 Step 3's status is P1's to change.

## 4. The P1 handoff (the point of this task) — **NOT RUN**

No handoff is recorded. `handoff_finding_id` and `handoff_extractable_usd` are
empty on the record, the audit's `problems` array carries the missing-handoff
line (§1), and `ok` is `false`.

**What is missing, precisely:**

- **No CONFIRMED finding.** The campaign has no finding on this target at all:
  `audit --json`'s `findings` section reads `{"checked": 0, ...}`. The plan's
  Step 8 recipe ingests a finding, registers an exec record, mints it and
  verdicts it `confirmed`; none of that ran.
- **No measured `extractable_usd`.** The only dollar figure this record has is
  the incident's **reported loss** (`$7.6M`, §2). That is not the same number as
  the **extractable** figure P1 Task 10 Step 4 consumes, and this record will
  not launder one into the other. Measuring an extractable figure means
  simulating the extraction on a fork and reading the balance delta — which is
  the arithmetic half of P1's own Phase 2 spike, not a by-product of a
  validation-gap test run.
- **What the harness run does and does not license.** It licenses "the guard is
  absent at `46e840222e…` and present at `e73bfb2128…`, and the project's own
  tests say so". It does not license "we reproduced a $7.6M extraction". The
  pre-patch failures are missing-refusal failures, as pasted above.

**What this unblocks, stated exactly:** P1's Phase 2 extraction half remains
blocked on **both** halves. `docs/gates/v16-P1.md` §7b named two things —
a mainnet fork RPC URL with its pinned block number, and one already-confirmed
finding on a real target. This record supplies neither: it supplies a **sourced,
pinned, harness-verified control target**, which is the substrate both halves
need, not the halves themselves. `FORK_RPC_URL` is still unset (§3 records that
public archive endpoints would serve a fork). P1 Task 10 Steps 3–4 still cannot
run — say exactly that, and nothing more.

## 5. What this does NOT prove

- One incident is not a detection rate, and nothing here is a measurement of
  the framework's detection ability.
- The control target exercises the **PATCHED-KNOWN** path (§C7.2): the finding
  is known before the run, the revision is pinned before the run, and the tests
  are the fix's own. It says nothing about novelty.
- The harness run demonstrates the **absence of a validation guard** at the
  pinned revision. It is not a fund-draining reproduction and no value was
  extracted, simulated or measured.
- `$7.6M` is the incident's reported loss, cited to the project's post-mortem.
  It is not an `extractable_usd`, and no `extractable_usd` exists for this
  target.
- The pin is a commit the deployed vulnerable code corresponds to; the harness
  forks the state the exploit ran against (`99,811,375`). The deployed bytecode
  was not decompiled and compared to the pre-patch commit's build — the
  correspondence is argued from the fix commit's parent and the incident date,
  not verified byte-for-byte.

