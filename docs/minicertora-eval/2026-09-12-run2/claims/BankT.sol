// ES03BankReentrancy.sol — planted reentrancy (CEI violation)
pragma solidity ^0.8.24;
contract Bank {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = bal[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");   // effects AFTER interaction
        bal[msg.sender] = 0;                            // violation: CEI broken
    }
    receive() external payable {}
}