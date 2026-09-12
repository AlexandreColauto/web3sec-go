// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Minting {
    address public owner;
    uint256 public totalMinted;

    constructor() { owner = msg.sender; }

    // BUG (access control): no gate — anyone can mint, inflating the supply.
    function mint(uint256 amount) public {
        totalMinted += amount;
    }
}
