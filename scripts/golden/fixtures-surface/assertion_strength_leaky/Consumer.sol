// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Own} from "./Own.sol";

/// assertion-strength LEAKY fixture, consumer half: commitBatch consumes the
/// same `prev:state:root` concept (inherited from Own) and writes state
/// under a class-0 guard without asserting it — drives an enforcement-timing
/// row with assertion_gap >= 1.
contract Consumer is Own {
    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(stateRoot != bytes32(0), "zero root");
        prevStateRoot[batchIndex + 1] = stateRoot;
        emit BatchCommitted(batchIndex, stateRoot);
    }
}
