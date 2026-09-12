# wrap-unchecked

- bug_class: arithmetic-overflow
- source: seed target (Task 1); derived from the v0.1 `tests/end_to_end/overflow.mspec`
  family — a deliberately unchecked `add` that wraps at 2**256.
- lineage: `Counter.add` uses an `unchecked` block; `total + x` wraps. The rule
  `add_never_wraps` reads `total` before the call and asserts it never
  decreases.
- measured: 2026-09-11, solc 0.8.36, `python -m cli Counter.sol wrap.mspec
  --loop-bound 4 --timeout-ms 30000` → verdict `VIOLATED` (exit 1),
  `failed_assertion.expression = "total >= before"`,
  `final_storage.total = "0"` with `params.x = 2**256 - 1`. Matches
  `expected.json`.
- note: `expected_reason_code` stays `null` on purpose — v0.1 VIOLATED reports
  carry the placeholder `reason: "tool-error"` until Task 4's D5 fix sets
  `assertion-violated`.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
[]
| 2026-09-12 | task-4 | expected_reason_code | `null` (report reason `"tool-error"`) | `"assertion-violated"` | 4b: reason added to the VIOLATED branch; this target's `replay: required` scriptlet is unaffected. | `python -m cli Counter.sol wrap.mspec` → `{"verdict": "VIOLATED", "reason": "assertion-violated"}`, exit 1 |
