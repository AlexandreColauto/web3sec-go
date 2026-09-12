rule no_double_payout(env e, uint256 x) {
    require x > 0;
    require balanceOf(e.msg.sender) >= x;
    withdraw(e, x);
    reenter { withdraw(e, x); }
    assert payouts <= 1;
}
