rule withdraw_keeps_accounting(env e, address caller, uint256 amount, uint256 before) {
    require e.msg.sender == caller;
    require amount > 0;
    require balanceOf(e.msg.sender) == before;
    require before >= amount;
    withdraw(e, amount);
    assert balanceOf(e.msg.sender) == before - amount;
}
