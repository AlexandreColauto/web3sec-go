rule mint_owner_only(env e, address caller, uint256 amount) {
    require e.msg.sender == caller;
    require e.msg.sender != owner;
    uint256 before = totalMinted;
    mint(e, amount);
    assert totalMinted == before;
}
