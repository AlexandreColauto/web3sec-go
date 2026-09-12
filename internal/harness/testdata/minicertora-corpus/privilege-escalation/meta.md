# privilege-escalation

- bug_class: privilege
- source: distilled from the victim-action-then-escalate sequence family (DV
  `PrivilegeEscalation`-adjacent shapes).
- lineage: victim's `nominate` grants the attacker the permission `escalate` needs —
  the attack is `nominate(attacker); escalate()` in ONE transaction.
- distillation decision: the honest rule keeps both calls; `escalate` alone
  (single-call) would vacuously revert.  Task 6 Step 6 added one line —
  `require nominated(e.msg.sender) == false;` before the calls — because without
  it the target is VIOLATED for the *wrong reason*: `nominated` is a mapping and
  v0.2 models mappings as `arbitrary-initial-storage`, so `escalate` could pass
  on a nomination the sequence never made.  With the require, the pre-state
  cannot supply it and call 1 succeeds only because call 0 ran.
- measured (Task 6, `--multi-call sequential`): **VIOLATED** (exit 1),
  confidence confirmed, reason `assertion-violated`, failed_assertion
  `role(e.msg.sender) == 0`; witness `nominated[?] = 0 -> 1`, `role[?] = 0 -> 2`,
  and both `calls[].env` show the same actor (`msg.sender` 0) for `nominate` and
  `escalate` — which is exactly the permissive-model point: each step has its
  own actor symbol, and the solver instantiated them equal because that is the
  only way to reach the violation (mini-spec §9).  `replay: none`: no harness
  executes a two-call EVM sequence yet.
- counter-measurement (the reason the require is in the spec): the same rule
  *without* `require nominated(...) == false` is also VIOLATED, with
  `initial_storage.nominated[?] = 1` already set.  Recorded because a verdict
  alone would not distinguish "the sequence escalated" from "the state was
  already escalated".
- assumptions posture: VIOLATED, so the report stands on its own; it carries
  `multi-call-sequential`, `mapping-slot-injective`, `arbitrary-initial-storage`
  and the standard 0.8.36/IR/`external-calls=no-reentry` set.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
| 2026-09-12 | task-4 | expected_error_code + shape | `unrecognized-dispatcher` (per-rule UNKNOWN, rule report present) | `unsupported-feature` / details `multi-call-sequence:` (rule-less abort) | 4a, as for `flashloan-price-oracle`. | `python -m cli Privileged.sol no_privilege_escalation.mspec` → `{"verdict": "UNKNOWN", "reason": "unsupported-feature", "details": "multi-call-sequence: rule no_privilege_escalation has 2 calls; ..."}`, exit 2 |
| 2026-09-12 | task-6 | status / blocked_on / expected_error_code → rules | `unwritable` / `multi-call-sequence` / `unsupported-feature` | `expected` / — / verdict `VIOLATED` + `assertion-violated`, flags gain `--multi-call sequential` | Step 6: the sequence is decidable, so the refusal is discharged and the honest expectation replaces it. Spec strengthened in the same commit so the flip is evidence about the *sequence* rather than about arbitrary initial storage. | `python -m cli corpus/targets/privilege-escalation/Privileged.sol corpus/targets/privilege-escalation/no_privilege_escalation.mspec --multi-call sequential --loop-bound 4 --timeout-ms 30000` → `{"verdict": "VIOLATED", "confidence": "confirmed", "reason": "assertion-violated", "initial_storage": {"role[?]": "0", "nominated[?]": "0"}, "final_storage": {"role[?]": "2", "nominated[?]": "1"}}`, both `calls[].env.msg.sender` = 0, exit 1 |
