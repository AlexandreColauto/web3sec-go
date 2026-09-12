rule bump_keeps_positive(env e) {
    bump(e);
    assert total >= 1;
}