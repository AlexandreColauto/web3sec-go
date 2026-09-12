/// Task 12: one-step induction over every entrypoint.
///
/// `deposit` and `setCap` both preserve `total <= cap`, and the constructor
/// leaves a state that satisfies it, so the invariant holds after any sequence
/// of calls.  The verdict is PROVEN only because *every* entrypoint was checked
/// (`invariant.per_function`) and the initialization check was proved from the
/// zeroed storage a deployment starts with
/// (`invariant-init-from-zeroed-storage`); the report names both.
invariant cap_respected() {
    assert total <= cap;
}
