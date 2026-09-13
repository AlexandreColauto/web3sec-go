// ES18LegacyVaultReentrancy.sol — planted reentrancy (CEI violation).
// solc-pin: ^0.8.0 — the suite's pre-0.8.24 compiler-diversity fixture
// (Wave J Task 3): same flaw family as ES03, carried on a legacy pragma
// range so the suite is not a single-compiler monoculture. The caller is
// bound to a named local so the structural index sees the balance write
// (an indexed `msg.sender` lvalue is a documented parser under-report).
pragma solidity ^0.8.0;
contract LegacyVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        address who = msg.sender;
        uint256 amount = balances[who];
        (bool ok, ) = who.call{value: amount}("");   // interaction first
        balances[who] = 0;                           // flaw: effects after interaction
    }
    receive() external payable {}
}