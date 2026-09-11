// ES15BridgeMsgReplay.sol — planted bridge-message flaw: release() trusts
// the claimed source message with no nullifier, so one message mints twice.
pragma solidity ^0.8.24;
contract BridgeMsgReplay {
    address public relayer;
    mapping(address => uint256) public bal;
    constructor(address r) { relayer = r; }
    function release(address to, uint256 amt, bytes32 msgHash) external {
        require(msg.sender == relayer, "auth");
        bal[to] += amt;                     // flaw: msgHash never nullified
        _burn(msgHash);
    }
    function _burn(bytes32) internal {}
}
