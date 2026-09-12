// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Counter {
    uint256 public total;

    function add(uint256 x) public {
        unchecked { total = total + x; }
    }
}