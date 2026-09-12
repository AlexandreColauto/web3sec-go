# tx-origin-auth

- bug_class: auth
- source: distilled from the classic tx.origin phishing/auth bug (DV `PartnerRegistry`
  family / Solidity docs "never use tx.origin for authorization").
- lineage: `require(tx.origin == owner)` — a real middle-contract vulnerability in
  EVM (owner calls an attacker contract; the attacker's call passes the check).
- distillation decision: single scalar + scalar owner; the rule is the honest
  non-owner-cannot-mint statement.
- measured: VIOLATED (exit 1) — see ruling
- assumptions posture: n/a (VIOLATED). v0.1 DECLARED `tx.origin-equals-msg.sender` without enforcing it; 4k removed the false declaration and keeps the middle-contract channel OPEN on purpose (that channel is this target's true positive). `--assume-direct-calls` binds AND declares the equality, and under it this target is PROVEN — see the ruling below.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
| 2026-09-12 | task-2 | expected_verdict | PROVEN (brief, "documented limitation") | VIOLATED (observed) | The brief's premise is wrong about v0.1: the tool DECLARES `tx.origin-equals-msg.sender` in every report but never constrains `__origin__` to `__caller__` (ORIGIN maps to a fresh symbolic). With unconstrained origin the honest rule `e.msg.sender != owner; mint; assert totalMinted == before` is violated whenever origin == owner while sender != owner — exactly the real middle-contract attack. A clean EVM witness exists (owner=O, sender=C≠O, origin=O), so this is a TRUE violation, not an artifact. The corpus keeps the observed VIOLATED — the tool already finds the bug class this target exists to measure. CASUALTY: the PROVEN-under-assumption row the brief wanted cannot exist in v0.1. | `python -m cli Auth.sol mint_owner_only.mspec` → verdict VIOLATED, reason tool-error |
| 2026-09-12 | task-4 | expected_reason_code | `null` (report reason `"tool-error"`) | `"assertion-violated"` | 4b, as for `access-control-mint`: the true violation this target exists to find was labelled `tool-error` in the matrix. Verdict, witness and exit code unchanged. | `python -m cli Auth.sol mint_owner_only.mspec` → `{"verdict": "VIOLATED", "reason": "assertion-violated"}`, exit 1 |
| 2026-09-12 | task-4k | assumptions posture (`expected_assumptions_include` was already `[]`) | `tx.origin-equals-msg.sender` declared on every report while NOT enforced | declaration removed; the middle-contract channel stays OPEN by default | 4k Step 1. The VIOLATED is unchanged and is now *honest*: the report no longer advertises a constraint the model does not impose. The opt-in `--assume-direct-calls` binds `__origin__` to `__caller__` **and** declares the equality; under it this target is PROVEN (the contract's `require(tx.origin == owner)` becomes `require(msg.sender == owner)`, so the rule's `e.msg.sender != owner` path is infeasible and nothing that could mint survives) — measured, not assumed. Default VIOLATED → VIOLATED; with the flag PROVEN. | before: `python -m cli Auth.sol mint_owner_only.mspec --loop-bound 4 --timeout-ms 30000` → `{"verdict": "VIOLATED", "reason": "assertion-violated"}`, exit 1, `assumptions` containing `... "msg.value-default-zero", "tx.origin-equals-msg.sender", "solc-0.8.36" ...`; after: same verdict, reason, exit and witness with the entry gone; adding `--assume-direct-calls` → `{"verdict": "PROVEN", "reason": null}`, exit 0, the entry present together with `path-infeasible-proof` (`tests/test_env_origin_posture.py`) |
