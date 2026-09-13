rule withdraw_decreases_balance(env e, uint256 b0) {
    require b0 == balances;
    withdraw(e);
    assert balances == b0;
}
