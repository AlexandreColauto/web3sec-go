// ES16AckDecoyVault.sol — IN-CODE-ACK DECOY: the withdraw below is
// CEI-correct (effects before interaction), so there is no live reentrancy;
// the TODO line makes ackscan record in_code_ack — feeds G5/A2 tests.
pragma solidity ^0.8.24;
contract AckDecoyVault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    // TODO: known issue, accepted by design — reentrancy reviewed, CEI holds
    function withdraw() external {
        uint256 a = bal[msg.sender];
        require(a > 0, "zero");
        bal[msg.sender] = 0;                            // effects first
        (bool ok, ) = msg.sender.call{value: a}("");    // interaction last
        require(ok, "send");
    }
    receive() external payable {}
}
