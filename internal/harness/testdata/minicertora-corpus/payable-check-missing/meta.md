# payable-check-missing

Task 10's target: the same intent — *a call that must not be able to send ether
must not move the state* — written twice, once without the check and once with the
check the compiler emits on the caller's behalf. The pair is what makes the
dispatcher-entry binding measurable; the second rule is the one that was
unwritable before it.

- measured: 2026-09-12, solc 0.8.36,
  `python -m cli Ledger.sol ledger.mspec --loop-bound 4 --timeout-ms 30000`
  → exit 1, two JSON lines (one per rule).

## The bug: the check is missing from the contract

`Ledger.record` is meant to refuse ether, but it is declared `payable` — so
`solc` emits **no** `callvalue()` guard for it — and the author never wrote the
`require(msg.value == 0)` that would have taken the guard's place. Value is
accepted and `total` moves:

```
{"rule": "value_accepted_where_it_must_not_be", "verdict": "VIOLATED",
 "confidence": "confirmed", "reason": "assertion-violated", "details": "",
 "failed_assertion": {"expression": "total == before"},
 "params": {"v": <v>}, "calls": [{"step": 0, "function": "record", "args": [],
 "overrides": {"msg.value": "v"}, "reverted": true, …}],
 "final_storage": {"total": <before + 1>}}
```

The witness is not pinned to literals: `total` starts arbitrary and ends one
higher, so *every* initial value witnesses the bug and pinning one would pin
z3's arbitrary model, not the finding. `params.v: "*"` pins the part that
matters — the witness exercised the value channel.

## The control: the check is present, in the wrapper

`Ledger.settle` is the same body with `nonpayable` instead of `payable`. Nothing
in its source mentions value: the guard that refuses it is emitted by `solc` into
`external_fun_settle_*`, the wrapper the deployed selector switch calls. The
corpus default (`--entry-binding=wrapper`) binds that wrapper, so the guard is in
the model and the claim holds:

```
{"rule": "nonpayable_entry_refuses_value", "verdict": "PROVEN",
 "confidence": "modeled", "reason": null, "details": "",
 "assumptions": [ …, "entry-bound-via-selector-map", "path-infeasible-proof"],
 "calls": [{"step": 0, "function": "settle", "reverted": true, …}]}
```

`path-infeasible-proof` is the honest caveat (4j): the rule's own precondition is
satisfiable, and the guard-passed path contradicts the assertion, so the PROVEN
rests on the contract's reverting guard rather than on an unreachable rule.

## Both bindings, measured

`--entry-binding=internal` binds `fun_settle_*`, whose body is just
`total = total + 1`: the override then reaches the body and the *same* rule is
reported VIOLATED, with a witness for an execution the EVM reverts (the
dispatcher rejects the value before either function runs). Same contract, same
rule, opposite verdict — this target exists to make that difference a corpus row
instead of a claim.

## Rulings

| date | task | field | old | new | reason | evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-09-12 | task-10 | status | the Stage-1 shape of this row: `unwritable`, `blocked_on: entry-binding` — with only the internal implementation bound, no honest expectation for the control rule could be written (the only reachable one was the false VIOLATED below), so the row could not be measured at all | `expected` with two rules | the flip the task is for: binding the wrapper puts the payable `callvalue()` check into the model, and the row became writable without weakening a single existing expectation | this directory; rule 2 PROVEN above |
| 2026-09-12 | task-10 | verdict (control, `--entry-binding=internal`) | — | `VIOLATED` | recorded, not fixed: the internal binding is v0.1's behaviour and it keeps the v0.1 verdict. It is a false positive — the dispatcher reverts that call — which is exactly why the wrapper binding is the default and the flag is an escape hatch, not the other way round | `python -m cli Ledger.sol ledger.mspec --loop-bound 4 --timeout-ms 30000 --entry-binding=internal` → rule 2 `VIOLATED`/`assertion-violated`, assumptions `entry-bound-at-internal-implementation` |
| 2026-09-12 | task-10 | assumptions | the base list (no entry-binding marker) | `… "entry-bound-via-selector-map"`, plus `path-infeasible-proof` on the PROVEN | the §2.5 contract: which entry a rule was verified against is a promise the model makes, so it is declared on every report. The old internal marker is *not* removed — it stays for the fallback bindings (argument-carrying calls, hand-written `ir`, a wrapper whose guard contradicts the ABI) | both rules' `assumptions` above; `tests/test_entry_binding.py` |
| 2026-09-12 | task-10 | spec vocabulary | the brief's Step-1 sketch: `require e.msg.value > 0; record(e);` | `require v > 0; record(e) with { msg.value = v; }` | repo reality: `e.msg.value` is the documented constant zero (`msg.value-default-zero`), so a rule written on it is vacuous whatever entry is bound — it cannot witness this target's bug or its control. Value is sent explicitly, which also makes the two "not balance checked" caveats appear honestly | `tests/test_entry_binding.py::test_nonpayable_call_with_value_is_rejected_by_the_wrapper` (the sketch, kept and explained) vs this target's two rules |
| 2026-09-12 | task-10 | witness | — | `params.v: "*"`, `initial_storage`/`final_storage` unchecked | `total` is arbitrary initial storage: the finding is "the state moved by one on a value-carrying call", which every initial value witnesses. A literal would pin the solver's arbitrary choice and break on any z3/version change without any change in the bug | the VIOLATED line above |
