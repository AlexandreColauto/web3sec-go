# invariant-cap

- bug_class: invariant-induction
- source: Task 12 (v0.2) — the first corpus target whose PROVEN is about an
  `invariant` block rather than a rule. `Capped.sol` is the brief's contract with
  `setCap` guarded (`require(c >= total)`), so both external functions preserve
  `total <= cap`.
- lineage: `invariant <name>([env e]) { assert …; }` declarations (design §3b),
  checked by one-step induction over the entrypoints; the report carries
  `invariant-one-step-induction`, `invariant-init-checked` and
  `invariant-init-from-zeroed-storage`.
- measured: 2026-09-11, solc 0.8.36,
  `python -m cli corpus/targets/invariant-cap/Capped.sol \
   corpus/targets/invariant-cap/cap.mspec --loop-bound 4 --timeout-ms 30000`
  → one line, `cap_respected` `PROVEN`, exit 0, `loop_bound_exhaustive = true`,
  `invariant.per_function = {deposit: proved, setCap: proved}`,
  `invariant.init = {function: constructor, kind: proved}`.

## What the verdict actually claims

The checked formula is the induction step, per external function `f`:

```
assume inv(s);  assume f's requires and path conditions under a symbolic env e
f(e, a₀, …);    assert inv(s')
```

`env e` is one symbolic frame per step, shared between the call and the
assertion: the claim is "for every caller, whatever state the call left satisfies
`inv`", not "one fixed state satisfies `inv` under every env" (which is false for
any interesting `inv`). Together with the initialization check
(`constructor(e); assert inv`) the composition is:

- every entrypoint proved **and** init proved → PROVEN;
- any entrypoint refuted → VIOLATED (see `invariant-cap-broken`);
- anything else → UNKNOWN, with the entrypoints still named per function.

The step set is the ABI's `function` entries minus the state-variable getters
(`total()`, `cap()`): a getter cannot write, so it cannot break the invariant —
and the report says so explicitly rather than leaving the reader to infer it
(`invariant-state-getters-not-checked`).

## The initialization check runs from deploy storage

The init check lowers the constructor and then constrains the *entry* state to
what a deployment actually starts with: every storage word zero. That is EVM
semantics, not a convenience — identical code is PROVEN under it and
`invariant-uninitialized` without it
(`tests/test_invariants.py::test_the_initialization_check_uses_deploy_storage`,
which re-runs the check with the constraint removed and observes the refutation).
The constraint is applied to the translated query (`z3_formula`, `feasibility`,
`rule_requires`), leaving `vcgen/translate.py` untouched and the rule path
byte-identical.

## Why this target exists next to its twin

`expected.json` pins the *composition evidence*, not only the verdict: a PROVEN
that had silently skipped `setCap` would still be `cap_respected`/`PROVEN`, so
the expectation names both steps and the initialization kind. `_invariant_problems`
compares the per-function map in both directions for exactly that reason.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
| 2026-09-11 | task-12 | the brief's Step-1 contract | unguarded `setCap(uint256 c) { cap = c; }` with `verdict == "PROVEN"` expected | guarded `setCap` (`require(c >= total)`), and the unguarded body kept as the `invariant-cap-broken` twin | with no guard `setCap` is precisely the function that breaks `total <= cap`, so the brief's expectation is false — the honest reading is that the brief meant the guarded body for the HOLDS half and the unguarded one for the BREAKS half | this target PROVEN vs `invariant-cap-broken` VIOLATED with `invariant.witness_function = "setCap"` |
| 2026-09-11 | task-12 | the violated-step reason code | the brief's `invariant-violated` | `assertion-violated`, with the failing function in `invariant.witness_function` | `invariant-violated` is not in the plan's reason-code vocabulary (`corpus/runner.py REASON_CODES`), and the violated step genuinely is a negated-assertion counterexample; inventing a code would have split one phenomenon across two names | `expected.json` of `invariant-cap-broken`; `tests/test_invariants.py::test_a_violating_function_makes_the_invariant_violated` |
| 2026-09-11 | task-12 | the declaration's condition field | the brief's `cond: Expr` (single expression) | `conds: list[Expr]` (the body's asserts in order) | the expression evaluator has no `"and"` node, so a multi-assert body could not be conjoined as one expression; the translator already conjoins a rule's asserts, so a list is both simpler and truthful | `tests/test_invariants.py::test_multiple_asserts_are_all_claimed` (both clauses are claimed; reordering them does not change the verdict) |
