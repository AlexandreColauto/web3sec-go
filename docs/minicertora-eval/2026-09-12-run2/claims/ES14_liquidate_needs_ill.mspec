rule liquidate_reduces_debt(env e, uint256 d0, uint256 c0) {
    require d0 == debt;
    require c0 == collateral;
    require d0 > 0;
    liquidate(e, e.msg.sender);
    assert debt <= d0;
}
