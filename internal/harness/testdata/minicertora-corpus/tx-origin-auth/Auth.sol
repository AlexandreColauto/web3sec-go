// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Auth {
    address public owner;
    uint256 public totalMinted;

    constructor() { owner = msg.sender; }

    // BUG (auth): authorization keyed on tx.origin instead of msg.sender —
    // a contract called by the owner (victim) passes the check, so an
    // attacker contract in the middle of the call chain mints freely.
    function mint(uint256 amount) public {
        require(tx.origin == owner);
        totalMinted += amount;
    }
}
