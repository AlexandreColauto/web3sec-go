# unchecked-callback

- bug_class: unchecked-callback
- source: DV "side entrance"-shaped single-contract distillation (the shape behind
  the DV vault bugs where a re-entering deposit during a callback/withdrawal gaps
  the accounting), built to live inside v0.1's modelled subset: no structs, no
  multi-call, no expect_revert.
- lineage: `payable(msg.sender).transfer(amount)` runs BEFORE
  `balanceOf[msg.sender] -= amount`.
- distillation decision: the external call is abstracted to
  `--external-calls havoc-storage`, so the witness is the *unconfirmed* divergence
  (`crosses_havoc`). replay: none — the witness is unconfirmed-by-replay (the brief
  mandates `replay: none` + this note).
- measured: VIOLATED (exit 1), confidence unconfirmed (crosses_havoc), failed_assertion "balanceOf(e.msg.sender) == before - amount", under --external-calls havoc-storage; the callback may re-deposit into the caller's balance mid-withdrawal. Matches expected.json.
- assumptions posture: n/a (VIOLATED); the report carries external-calls=havoc-storage.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
| 2026-09-12 | task-4 | expected_reason_code | `null` (report reason `"tool-error"`) | `"assertion-violated"` | 4b: reason added to the VIOLATED branch; `confidence` stays `unconfirmed` (the witness crosses a havoc'd call), which is the field that carries the caveat. | `python -m cli Vault.sol withdraw_keeps_accounting.mspec --external-calls havoc-storage` → `{"verdict": "VIOLATED", "confidence": "unconfirmed", "reason": "assertion-violated"}`, exit 1 |
