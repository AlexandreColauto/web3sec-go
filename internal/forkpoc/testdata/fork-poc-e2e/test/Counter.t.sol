// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Counter} from "../src/Counter.sol";

contract CounterTest {
    Counter public counter;

    function setUp() public {
        counter = new Counter();
    }

    function test_exploit() public {
        counter.setNumber(42);
        require(counter.number() == 42, "exploit failed");
    }
}
