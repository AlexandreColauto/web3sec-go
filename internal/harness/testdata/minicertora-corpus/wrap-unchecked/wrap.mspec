rule add_never_wraps(env e, uint256 x) {
    uint256 before = total;
    add(e, x);
    assert total >= before;
}