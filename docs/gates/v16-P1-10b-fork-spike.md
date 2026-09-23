# 10b — the fork spike, reframed

10b is off the CONFIRMED path: the fork requirement was an artifact of the E5 floor, which the
campaign override moved to E4. It is worth running for exactly two reasons — it is the only route
to a **measured** `extractable_usd`, and it exercises the **proxy-resolution** case, where
detectors keyed on the attacked address's own code are provably false-negative.

**Outcome: one measurement, one refusal.** `fork_block_used` is measured. `extractable_usd` is
**refused**, with the reason recorded below — nothing is reported as a loss, and no figure is
promoted into `extractable_usd`.

## Where it ran, and why not in the evidence checkout

`EXEC-f2223595c6` — the anchored exec behind `F-cfff3ebc0250` — records `input_hashes` for
`test/DebtManager.t.sol` (`254c9fa4…`) and `contracts/DebtManager.sol` (`d3e9e4fc…`). The spike
must edit `test/DebtManager.t.sol`, so it ran on a **copy** at `/home/xand/webv2-p0/spike-10b`,
with `node_modules` symlinked read-only and `.git`/`out` excluded. The reference checkout was
verified byte-identical afterwards (`254c9fa4f5534452b84e62587417d258ebcebef1ecae739edd91007f590e4a10`).
Editing it in place would have made the CONFIRMED finding's declared inputs unreproducible.

## The diff

`99_811_375` → `108_375_557`, at `test/DebtManager.t.sol:51` and `test/DebtPreviewer.t.sol:47`,
both `vm.createSelectFork(vm.envString("OPTIMISM_NODE"), …)`:

```
   function setUp() external {
-    vm.createSelectFork(vm.envString("OPTIMISM_NODE"), 99_811_375);
+    vm.createSelectFork(vm.envString("OPTIMISM_NODE"), 108_375_557);
```

## `fork_block_used` — measured, not the passed flag

```
$ OPTIMISM_NODE=https://mainnet.optimism.io forge test --match-path test/DebtManager.t.sol -vv
(block: 108375557)
Suite result: FAILED. 4 passed; 74 failed
```

`fork_block_used = 108375557`, read from the **observed** `(block: …)` line. It happens to equal
the flag, and that agreement is the point of reading it rather than assuming it: the derived
value is the one the fork actually used.

The second edited file reproduces it independently:

```
$ OPTIMISM_NODE=https://mainnet.optimism.io forge test --match-path test/DebtPreviewer.t.sol -vv
(block: 108375557)
Suite result: FAILED. 14 passed; 49 failed
```

Both files fork the same block, so `fork_block_used` is confirmed on two independent forks rather
than read off one.

## The proxy-resolution case — measured independently

A direct `eth_getStorageAt` of the EIP-1967 implementation slot
(`0x360894a1…382bbc`) on the proxy `0x675d410dcf6f343219AAe8d1DDE0BFAB46f52106`, at the spike's
own fork block and either side of the repoint:

| block | implementation slot |
|---|---|
| **108,375,557** (the fork block) | **`0x16748cb753a68329ca2117a7647aa590317ebf41`** |
| 108,445,161 | `0x16748cb753a68329ca2117a7647aa590317ebf41` |
| 108,445,162 | `0x910e91d24a948c3e36b71b505fb45fe80e95adb3` |

At the fork block the proxy resolves to **impl A**, not to impl B and not to its own code — which
is the false-negative the case exists to demonstrate. The repoint boundary is reproduced exactly
where it was recorded, now measured at the block the spike actually forked.

## `extractable_usd` — REFUSED

**No attack was run.** The spike ran the target's *own* test suite, which is pinned to block
99,811,375; at 108,375,557 it fails 73 of 78 tests. Those failures are not a result about the
target. They are the suite being stale against a fork 8.5M blocks newer:

- **68** fail with a genuine `EvmError: Revert` — the pinned fixtures no longer hold;
- **5** are contaminated by the public endpoint: `HTTP error 429 … Your IP has exceeded its
  requests per second capacity`.

So the run is **partly an artifact of the free RPC tier**, and the honest reading is that it
measures the fork, not the target. Nothing was lost, so there is no loss to measure.

Two further reasons the number is not obtainable here, recorded so the next attempt does not
re-derive them:

1. **The attack is three transactions.** Any single-transaction figure would be one of three, not
   the total, and would need stating as such.
2. **`tx.to` is the attacker's contract, not the DebtManager.** A loss figure derived from the
   DebtManager's own balance delta would miss value that never returns to it.

A reported loss is never laundered into `extractable_usd`; the refusal is the deliverable.

## The `regression_suite` audit problem — also refused, for the same reason

`webv2 audit --root .scratch/p0/root C-725aa2c6a8` reports one problem, in `regression_suite`:

```
control target T-7e2781f96e25 carries no P1 handoff — the Phase 2 spike's extraction half
stays blocked until a CONFIRMED finding and its extractable_usd are recorded here
```

The check is `!validation.HasKey(target, "handoff")`, so closing it means writing a `handoff`
object on the control target. **It cannot be closed honestly.** The `handoff` object's schema
(`assets/schema/regression_target.schema.json`) requires `finding_id`, `extractable_usd`,
`source` and `recorded_at`, and `extractable_usd` is a number with `exclusiveMinimum: 0` — a
strictly positive figure. There is no way to record the handoff without one.

Half the condition is met: `F-cfff3ebc0250` **is** CONFIRMED. The other half is the figure this
spike **refused**, because no attack was run and no loss was measured. Writing a number to clear
the audit would be exactly the fabrication the standing law forbids — and the schema is right to
require it: `exclusiveMinimum: 0` is what stops a handoff from carrying a placeholder zero.

So the problem stays, and it is **correctly reported**. The audit is not stuck; it is telling the
truth about a control target whose extraction half has not succeeded. The honest next step is the
extraction half (P1 plan Task 10), not a handoff record.
