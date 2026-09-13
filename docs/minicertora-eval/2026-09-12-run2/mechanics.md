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
  closed 25-set as its own row (`internal/harness/disposition.go`,
  `HonestRefusal` — not a `rejected-feature` family member). The other
  first-in-the-wild code is `external-call-abstraction`, likewise already a row.
- **Collision law did NOT fire (corrected at close-out, verified)**: BankT and
  LegacyVaultT share the rule name `withdraw_decreases_balance`. The class-map
  comment claimed LegacyVaultT's line would be EXCLUDED (rule → ES03, stem →
  ES18), but the committed map carries NO `LegacyVaultT` key, so the stem ties
  nothing, the law takes its documented silent branch, and BOTH lines joined ES03
  (`external-call-abstraction=2` for one case) while ES18 scored nothing.
  Re-running the scorecard on these committed results + map reproduces the
  committed `scorecard.{tsv,json}` with no exclusion line on stderr
  (`9 result lines, 9 tied to a case, 0 unjoined`). First live firing is still
  pending: the run-3 map must bind the twin stem (e.g.
  `LegacyVaultT → CASE-000000000012`).

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

Totals: 9 lines, 9 tied, 0 unjoined; detected 1, proven_silence 1, refused 3
CASES / 5 refusal lines (external-call-abstraction ×3, unsupported-opcode ×2),
clean_agreed 0 (no clean-control line authored this pass).
