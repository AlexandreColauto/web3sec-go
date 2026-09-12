// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Privileged {
    mapping(address => uint256) public role;      // 0 = none, 2 = admin
    mapping(address => bool) public nominated;

    function nominate(address who) public {
        nominated[who] = true;
    }

    // BUG (privilege escalation): the attacker sequence is
    //   1. victim.action  → the victim nominates the attacker, then
    //   2. attacker.escalate → the attacker mints admin for themself.
    // The honest rule needs BOTH calls in one transaction —
    // multi-call-sequence, a v0.2 feature.
    function escalate() public {
        require(nominated[msg.sender]);
        role[msg.sender] = 2;
    }
}
