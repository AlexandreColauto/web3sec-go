rule harvest_pays_at_most_accrued(env e, address caller) {
    require e.msg.sender == caller;
    uint256 already = users(caller).claimed;
    harvest(e, caller);
    assert users(caller).claimed <= already + users(caller).accrued;
}
