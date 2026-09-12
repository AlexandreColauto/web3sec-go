# access-control-mint

- bug_class: access-control
- source: distilled from the classic access-control flaw family (DAOhack-style
  un-gated mint), DV DeFi challenge `RiggedVoting`/`SimpleGovernance` shape; single
  scalar `totalMinted` keeps the contract inside v0.1's modelled subset.
- lineage: plain `totalMinted += amount` with no gate; the rule reads `owner` (bare
  scalar) and requires a non-owner caller.
- distillation decision: kept the mapping-free scalar core; the "mint" is
  unconditional so the single-call rule is decidable today.
- measured: VIOLATED (exit 1), failed_assertion "totalMinted == before", final_storage.totalMinted += amount; matches expected.json. Replay: required (anvil #1 non-owner mint raises totalMinted).
- assumptions posture: n/a (VIOLATED)

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
| 2026-09-12 | task-4 | expected_reason_code | `null` (report reason `"tool-error"`) | `"assertion-violated"` | 4b: the CLI VIOLATED branch never set a reason, so a *confirmed* violation was indistinguishable from a crash in the matrix — every VIOLATED row read `tool-error`, and the runner reason vocabulary could not be used to triage Stage 1. The verdict, witness and exit code are unchanged. | `python -m cli Minting.sol mint_owner_only.mspec` → `{"verdict": "VIOLATED", "confidence": "confirmed", "reason": "assertion-violated"}`, exit 1, witness unchanged |
