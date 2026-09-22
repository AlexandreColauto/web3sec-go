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
| attack txs (3) | `0x3d6367de5c191204b44b8a5cf975f257472087a9aadc59b5d744ffdef33a520e`, `0x1526acfb7062090bd5fed1b3821d1691c87f6c4fb294f56b5b921f0edf0cfad6`, `0xe8999fb57684856d637504f1f0082b69a3f7b34dd4e7597bea376c9466813585` (etherscan: `https://optimistic.etherscan.io/tx/<hash>`) |

The figure is the project's own, quoted verbatim from the post-mortem's
abstract: *"Exactly Protocol suffered a security breach on August 18, 2023, that
resulted in financial losses approximating $7.6 million."* The same document
names the root cause — *"a lack of input validation in several functions
exposed by the DebtManager contract"*, bypassed by passing a malicious `market`
argument — which is exactly the call the fix commit guards with `checkMarket`
and exactly what the harness below exercises. No loss figure in this record is
uncited, and none was derived by us. "Reported" is nonetheless **not a
well-defined quantity**: at least three figures are in circulation for this
incident — `$7.3M` (Olympex), `$7.6M` (the project's own, quoted above), and
about `$12.04M` (Safful) — a 65 percent spread. A cited figure must name both its
source and the spread. The attack is likewise **three** transactions, not one
(the table above names all three); any `extractable_usd` derived from a single
transaction is one of three — the caveat travels with the number or the number
misleads.

## 3. The harness

Runner `foundry`; the project's own repository is the harness — `foundry.toml`,
`test/Fork.t.sol`, and the tests the fix commit itself added. The fix commit
`e73bfb2128…` adds `+90/-0` lines to `test/DebtManager.t.sol`, five tests that
each assert the fake market is refused with `MarketNotListed`:
`testFakeMarketLeverage`, `testFakeMarketDeleverage`,
`testFakeMarketCrossLeverage`, `testFakeMarketCrossDeleverage`,
`testFakeMarketRollFixed`. The harness is fork-based. **Its fork height is the
project's, not ours, and it is not the exploit's state — §3.1 corrects what this
record first claimed here.**

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
unset on this machine, but a fork does not require it. Four public endpoints were
tried; **three failed and one serves full archive state unauthenticated** —
`https://mainnet.optimism.io`, verified again this session, where
`eth_getStorageAt` and `eth_getCode` at historical heights returned real values.
It 503s under load (three calls needed retries), and it served the whole harness
run. `https://optimism.drpc.org` returned code at Optimism block `99,811,375`
(`eth_getCode` on the WETH predeploy) but rate-limited the run
(`HTTP 429 ... You reached Public endpoint rate limit`);
`https://ethereum-rpc.publicnode.com` refuses archive requests without a token
and `https://rpc.flashbots.net` prunes state at that height. **All public
endpoints are rate-limited, and pruning fails silently** — which is the real
hazard, and why P5's runner-level fork pin survives this observation unchanged.
P1 Task 10 Step 3's status is P1's to change.

**A working RPC is a configuration fact here, not a capability.** Every free
public endpoint will eventually throttle (drpc already did, mid-run) or prune —
and §3.1 just showed a height that is *wrong* can still serve perfectly, so the
silent-failure mode is an endpoint answering at all. What makes a fork run
repeatable is not the endpoint's goodwill but a **height recorded with the run**.
The durable fix is P5's runner-level fork pin — the harness, not the operator's
shell, supplies and records the block — and this whole observation is the
evidence that justifies that work. Until then the pin lives in the target
record (§3.1) and the caveat lives here.

## 3.1 The SHA ↔ block mapping, and a correction to §3

A commit is not a fork pin. `46e84022…` is a git SHA; a fork run needs a **block**,
and the run is only meaningful if that block is the state the exploit actually
ran against. §3 first said the harness "selects Optimism mainnet at block
`99,811,375`, the state the exploit ran against". **That sentence was false**,
and this subsection is the mapping that shows it. Every number below was
re-derived on 2026-09-22 from the object store and the chain, not from §3.

| quantity | value | how it was verified |
|---|---|---|
| pre-patch commit (git) | `46e840222e11caf30a3a710b66d9333be76531b6` | `git rev-list --parents -n 1 e73bfb21…` → its **only** parent is the pin |
| fix commit | `e73bfb21284074adc3d82b322fe8eccdbde6922d` | `git cat-file -p` → `parent 46e84022…`; subject `🚑 debt-manager: validate markets` |
| attack transactions | `0x3d6367de5c191204b44b8a5cf975f257472087a9aadc59b5d744ffdef33a520e` (one of three — §2) | cited in §2 from the post-mortem; this is the tx whose block number is read below |
| **attack block** | **`108,375,558`** | `cast tx … --field blockNumber` |
| attack block time | `1692349893` → **2023-08-18** | `cast block … --field timestamp` |
| contract the attack called | `0x6dD61c69415c8ECAb3FEFD80d079435ead1a5B4d` | the attack tx's `to` — the **attacker's own contract**, **not** the DebtManager proxy `0x675d410d…`; `eth_getCode` returns code at that block |
| DebtManager proxy (EIP-1967) | `0x675d410dcf6f343219AAe8d1DDE0BFAB46f52106` | `deployments/optimism/DebtManager.json` at the fix commit |
| its deployment block | `107,135,785` → **2023-07-20** | that record's `receipt.blockNumber` |
| **the harness's fork height** | **`99,811,375`** → **2023-05-19** | hardcoded at `test/DebtManager.t.sol:51` |

Three things follow, and each one contradicts what §3 said:

1. **The fork height is the project's constant, not the exploit's block.**
   `test/DebtManager.t.sol:51` reads
   `vm.createSelectFork(vm.envString("OPTIMISM_NODE"), 99_811_375)`. That block is
   **2023-05-19 — three months before the 2023-08-18 exploit.** It is the state
   the project's test suite was written against, which is why the same constant
   appears in `test/DebtPreviewer.t.sol:47`.
2. **The `--fork-block-number` flag is inert.** Re-running the pre-patch arm with
   `--fork-block-number 108375557` still reports `(block: 99811375)` on every
   line: the test's own `createSelectFork` wins. The §3 commands therefore
   reproduce, but not at the height they appear to name.
3. **The exploited contract did not exist at the harness's height.**
   `eth_getCode 0x675d410d…` at block `99,811,375` returns `0x` — the
   DebtManager proxy was deployed at `107,135,785` (2023-07-20), after the fork
   height and a month before the attack.

**What this does and does not invalidate.** The 5/5-vs-0/5 contrast survives: it
is a *source-level* difference — `checkMarket` is absent from the pre-patch
revision and present at the fix — and the failures are the expected-refusal-is-
absent kind, which does not depend on the deployed bytecode. What does **not**
survive is any claim that the run reproduces the exploit's own state, and
therefore any downstream figure computed at that height. An `extractable_usd`
measured on a fork where the vulnerable implementation is not even deployed
would be a number about a counterfactual, not about the incident. **The spike
(10b) must fork at the attack's own height — `108,375,557` for pre-attack
state — and say which it used.**

The general rule this is an instance of is recorded with P0's SHA bookkeeping:
*a snapshot carries a resolved SHA, and a fork run carries a resolved block.* A
pin that names only one of the two is half a pin.

## 3.2 What the chain actually holds: a real before/after pair, and why the harness still misses it

B2 was going to say this: *the deployed DebtManager was never patched in place —
identical bytecode sha256 at pre-attack, attack block and today — so there is no
on-chain before/after pair, and this control target can only certify source-level
detection.*

**The evidence is misleading and the conclusion is wrong.** Hashing
`0x675d410d…` does return one identical digest at every height — because it is an
**EIP-1967 proxy**, and a proxy's own bytecode never changes, not even when its
implementation is swapped. That hash is the same in a world where nothing was
patched and in a world where everything was. It cannot tell the two apart, so it
cannot support either conclusion. It also makes the draft's *nothing more* too
weak: because the pair exists at **implementation** level, the target certifies
bytecode/diff detection as well — for detectors that resolve the proxy (below).

Read the implementation slot instead (`0x360894a1…382bbc`) and the pair is right
there, documented at both ends by the repository itself:

| | pre-patch pin `46e84022` (impl A) | fix `e73bfb21` (impl B) |
|---|---|---|
| `deployments/optimism/DebtManager_Implementation.json` names | `0x16748Cb753A68329cA2117a7647aA590317EbF41` | `0x910E91D24a948c3E36b71B505Fb45fE80E95adB3` |
| its recorded `receipt.blockNumber` | `107,135,784` | `108,401,937` |
| code size | 24087 bytes | 24356 bytes |
| sha256, `0x`-prefixed hex-string encoding | `a6b122975ddd09ab…` | `b3926e4df7f2e7d9…` |
| sha256, bytecode-bytes encoding | `c71f16467ad6f37f…` | `8d10f651af0a43d4…` |

Implementation B is **269 bytes larger** than implementation A (24356 vs 24087),
consistent with an added market-validation guard.

**Every sha256 in this record carries its encoding, because an unlabelled
canonical encoding is not evidence.** The `a6b12297…` / `b3926e4d…` pair quoted
here is computed over the `0x`-prefixed hex string, **not** over the bytecode
bytes; both encodings are valid fingerprints and they differ, so anyone
reproducing by hashing bytes gets different values and will think the record is
wrong. This is the third encoding ambiguity in the project, and it is a defect
class worth remembering. The proxy's own invariant code is the same story:
`0x675d410dcf6f343219aae8d1dde0bfab46f52106`, 1648 bytes, sha256
`f6a8bbe02df8db8b…` over the `0x`-prefixed hex string and `7d8a887950049e1c…`
over the bytecode bytes.

The proxy's slot, read at height:

- **through block `108,445,161`** → `0x16748cb7…` (impl A, sha256 `a6b12297…`
  over the `0x`-prefixed hex string and `c71f1646…` over the bytecode bytes). The
  attack at `108,375,558` sits inside this window, so the pin's own deployment
  record names the implementation the exploit actually ran against.
- **from block `108,445,162`** (2023-08-19 23:51:41 UTC) → `0x910e91d2…`
  (impl B, sha256 `b3926e4d…` over the `0x`-prefixed hex string and `8d10f651…`
  over the bytecode bytes), the implementation the fix commit records.

Timeline, all UTC: attack `09:11:33` on 2023-08-18 → fix commit `15:10:43` the
same day (+5h59m) → implementation B created `23:50:51` the same day (+8h40m
after the commit, block `108,401,937`) → proxy repointed `23:51:41` on
2023-08-19 (+24h 0m 50s after implementation B, block `108,445,162`). The
vulnerable implementation was never edited and is **still** `a6b12297…` (hex-string
encoding) today: it was orphaned by a proxy upgrade, not patched in place. So the
draft's instinct — *remediation happened as an upgrade, not an edit* — is right;
what follows from it is the opposite of what the draft concluded. The ~24h gap
between implementation B's creation and the repoint is **consistent with a
one-day timelock**, not with a same-night hotfix; the timeline is not proof that a
timelock was used, but nothing in it reads as an emergency response after the fix
commit landed.

**The transactions, for the record.** Implementation B was created by tx
`0x21ba352d001bed7e67267ea86f3791f2e7e31bf25af1eae374c418369b345fd6` from
`0xe61bdef3fff4c3cf7a07996dcb8802b5c85b665a` at block `108,401,937`. The proxy
was repointed by tx
`0x2474d2a50b4439434cefa63c42278f3530c2d494510b6e56d51f8fcc23321ad2` at block
`108,445,162`. That repoint transaction's `to` is
`0xc0d6bc5d052d1e74523ad79dd5a954276c9286d3`, **not** the proxy; its selector is
`0x6a761202` (Gnosis Safe `execTransaction`), submitted by
`0x35e6fd7c7e3d1c72a29fcdb5fcabc654f81c4f6c`; the proxy emitted `Upgraded(address)`
(event topic `0xbc7cd75a…`) naming `0x910e91d2`.

**The general rule: `tx.to` is not "the contract that changed."** No transaction
at block `108,445,162` has `to` equal to the proxy. Anything that derives "the
contract that changed" from `tx.to` is wrong for the **fix** exactly as it was
wrong for the **attack**, where `tx.to` was the attacker's own contract
`0x6dd61c69415c8ecab3fefd80d079435ead1a5b4d`, not the DebtManager. Two
independent instances of the same trap.

**Two consequences, one strengthening and one limiting.**

*Strengthening.* §5 used to say the pin's correspondence to the deployed
vulnerable code was "argued from the fix commit's parent and the incident date,
not verified byte-for-byte". That is now too modest. The pre-patch pin's own
deployment record names `0x16748cb7…`, the proxy's implementation slot named
`0x16748cb7…` at the attack block, and that address's bytecode is byte-identical
today. The correspondence is no longer an argument from dates.

*Limiting.* The harness forks `99,811,375`, where the proxy has **no code at all**
(§3.1), so it exercises **neither** side of the pair above. It cannot, in
principle, demonstrate anything about the deployed fix, because it never runs
against either deployment.

**What the control target certifies, exactly.** The pair exists at
**implementation** level — the proxy's own code never changes, only the slot it
resolves does — so the target certifies source-level detection, **and**
bytecode/diff detection **only for detectors that resolve EIP-1967 proxies**. A
detector keyed on the attacked address's own code is provably **blind** on this
target: it sees the invariant 1648-byte proxy at every height and reports
"unchanged" — a false negative by construction, at every height. The pair lives
at blocks `108,445,161` / `108,445,162`. That makes this control target a
**proxy-resolution** test case, which is a capability detectors commonly fail.

The source-level result is real and useful — `checkMarket` is absent at the pin,
present at the fix, and the five tests fail at the pin because the refusal is
missing, which is what "PATCHED-KNOWN" is supposed to test — but it is not an
on-chain before/after demonstration, and 10b must not be written as though the
fork at `108,375,557` supplies one. It does not; reaching the pair above is a
different run.

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
  "Reported" is not merely distinct from "demonstrated" — it is **not a
  well-defined quantity at all**: at least three figures are in circulation for
  this incident (`$7.3M` Olympex, `$7.6M` this record's figure, about `$12.04M`
  Safful — a 65 percent spread), so a cited figure must name both its source and
  the spread. In the spec's §2.4 vocabulary a reported figure is **neither
  demonstrated nor computed**: it
  is a third quantity, a figure *reported by someone else* about what an attack
  took, and it is a ceiling at best. Demonstrated is what a verification run
  actually extracted (two-plus rounds, precisely characterized); computed is the
  arithmetic extrapolation to rounds-to-exhaustion. This record carries a
  reported figure and nothing else, and it is labelled as such. Presenting a
  reported loss as either of the other two is precisely the misrepresentation
  §2.4 forbids, so the separation is stated here rather than left to be inferred
  from the absence of a number.
- The pin is a commit the deployed vulnerable code corresponds to, and that
  correspondence is now **verified on-chain rather than argued from dates**
  (§3.2): the pre-patch pin's deployment record names `0x16748cb7…`, the proxy's
  implementation slot held `0x16748cb7…` at the attack block, and its bytecode is
  byte-identical today. **The harness nonetheless does not fork the exploit's
  state**: it forks `99,811,375` (2023-05-19) because the project hardcoded that
  constant, three months before the attack, where the proxy has no code at all
  (§3.1). What remains unverified is the last link — the deployed implementation
  was not decompiled and compared to the pre-patch commit's own build, so "this
  bytecode came from this source" is inference, not a match. A downstream
  `extractable_usd` computed at the harness's height would describe a
  counterfactual; §3.2 names the two heights where it would not.

