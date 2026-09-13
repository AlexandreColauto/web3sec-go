# Run-2 mechanics (operator, 2026-09-12)

Same tool/env as run 1 (`.scratch/mcvenv`: z3 5.1.0, click/lark/networkx; solc
0.8.36 on PATH; `--loop-bound 4 --timeout-ms 60000`).

## What run 2 adds over run 1

- **share-price-inflation DETECTED** (`small_deposit_gets_at_least_pro_rata`,
  assertion-violated, witness present): the pro-rata inequality on the REAL
  ES06 contract catches the donation-inflation arithmetic directly. Run 1's
  ES06 only refused.
- **The reentrancy trio is honestly blind**: `external-call-abstraction`
  (symbolic returndata copy bounds) refuses BankT + LegacyVaultT, and LenderT
  (unchecked-call family) refuses the same way — the tool does not model
  external call RETURN data. Accounting claims that avoid reading the call
  result still run (ES14 twin PROVEN below).
- **ES14 (liquidation) twin: PROVEN** — sequential `liquidate` cannot increase
  debt. That is a true bounded fact about a contract whose REAL bug
  (health computed off spot, not TWAP) is out of the model's reach: honest
  proven_silence candidate once the gold row ties; recorded as data.
- **ES09 cross-chain-replay: unsupported-opcode** (keccak256 outside
  storage-slot paths) — first sighting of that code in the wild; it is IN the
  closed 25-set (`rejected-feature` family row exists; unsupported-opcode is
  its own row — verified against disposition map at run time).
- **Collision law live evidence**: BankT and LegacyVaultT share the rule name
  `withdraw_decreases_balance`; the map ties the rule to BankT's case only, so
  LegacyVaultT's line is EXCLUDED with a named stderr collision note. Run 2 is
  the first real data where the M2 law fires on non-fixture input.

## Twins (named, disclosed)

BankT/LegacyVaultT/LenderT/LiquidationT = evalsource contracts with every
`require(<cond>, "<msg>")` STRING-LITERAL guard line stripped (the tool aborts
rule-lessly on string literals anywhere — run-1 finding). Only ES14's twin
preserves semantics (the removed guards were revert messages on paths the
claim didn't take); the other three are PROBE-SHAPE, not proof-grade claims.
MintFreeC = free-mint donation analogue with an `add(uint256)` storage writer.

## Scoring

`results/` are raw tool JSONL verbatim; `class-map.tsv` documents the ties.
Reproduce from repo root:

    python3 scripts/minicertora-scorecard.py \
      --results docs/minicertora-eval/2026-09-12-run2/results \
      --cases assets/evalsuite/cases.json \
      --class-map docs/minicertora-eval/2026-09-12-run2/class-map.tsv

Totals: 9 lines, 9 tied, 0 unjoined; detected 1, proven_silence 1, refused 3,
clean_agreed 0 (no clean-control line authored this pass).
