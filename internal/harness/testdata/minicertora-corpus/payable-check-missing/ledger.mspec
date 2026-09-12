// Task 10: value is sent explicitly (`with { msg.value = v }`), never through
// `e.msg.value` — in this repo that channel is the documented constant zero
// (`msg.value-default-zero`), so a rule written on it cannot see either shape.
//
// Both rules assert the same invariant ("a call that is not allowed to take
// ether does not move the state"), and they differ only in *where* the refusal
// lives: in the contract (missing) or in the dispatcher wrapper (present).

rule value_accepted_where_it_must_not_be(env e, uint256 v) {
    require v > 0;
    uint256 before = total;
    record(e) with { msg.value = v; };
    assert total == before;
}

rule nonpayable_entry_refuses_value(env e, uint256 v) {
    require v > 0;
    uint256 before = total;
    settle(e) with { msg.value = v; };
    assert total == before;
}
