rule donation_keeps_rate(env e, uint256 d, uint256 p0, uint256 s0, uint256 k0) {
    require s0 > 0;
    require d > 0;
    require p0 == pool;
    require s0 == supply;
    require k0 == p0 * 1000000000000000000 / s0;
    add(e, d);
    assert pool * 1000000000000000000 / supply == k0;
}
