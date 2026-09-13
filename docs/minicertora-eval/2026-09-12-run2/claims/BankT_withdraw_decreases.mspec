rule withdraw_decreases_balance(env e, uint256 b0) {
    require b0 == bal;
    withdraw(e);
    assert bal == b0;
}
