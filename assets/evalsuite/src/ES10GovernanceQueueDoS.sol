// ES10GovernanceQueueDoS.sol — planted dos-griefing (liveness): one
// reverting proposal bricks execution of every proposal queued behind it.
pragma solidity ^0.8.24;
contract GovernanceQueueDoS {
    address[] public targets;
    function queue(address t) external { targets.push(t); }
    function executeAll() external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call("");   // flaw: revert bricks the queue
            require(ok, "bricked");
        }
        delete targets;
    }
}
