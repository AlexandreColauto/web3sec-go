// ES01VaultMissingAuth.sol — planted access-control flaw: withdraw moves
// contract funds to the caller with no ownership or allowance check.
pragma solidity ^0.8.24;
contract VaultMissingAuth {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amt) external {
        require(address(this).balance >= amt, "funds");
        payable(msg.sender).transfer(amt);   // flaw: no auth check
    }
    receive() external payable {}
}
