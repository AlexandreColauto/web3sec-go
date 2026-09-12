// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Packed {
    uint256 public total;
    uint128 public a;
    uint128 public b;

    function bump() public {
        total = total + 1;
    }
}