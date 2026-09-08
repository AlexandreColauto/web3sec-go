// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Tiny} from "../src/Tiny.sol";

contract TinyTest {
    function test_two() public {
        Tiny t = new Tiny();
        require(t.two() == 2, "two() must be 2");
    }
}
