rule borrow_decreases_credit(env e, uint256 c0, uint256 amt) {
    require c0 == credit;
    require c0 >= amt;
    borrow(e, amt);
    assert credit == c0 - amt;
}
