// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// assertion-strength WEAK fixture: the concept is consumed and a sanity
/// guard exists (so the probe has sites), but nothing asserts it at class 4.
/// rows must be 0 AND the blind list must still name what was rejected — an
/// axis with sites and no citable blind key cannot be attested.
contract Rollup {
    mapping(uint256 => bytes32) private prevStateRoot;

    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(stateRoot != bytes32(0), "zero root");
        prevStateRoot[batchIndex + 1] = stateRoot;
    }
}
