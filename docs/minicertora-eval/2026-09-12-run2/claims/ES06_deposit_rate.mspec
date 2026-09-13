rule small_deposit_gets_at_least_pro_rata(env e, uint256 a0, uint256 s0, uint256 v) {
    require v > 0;
    require s0 > 0;
    require a0 == totalAssets;
    require s0 == totalShares;
    deposit(e) with { msg.value = v; };
    assert shares * a0 >= v * s0;
}
