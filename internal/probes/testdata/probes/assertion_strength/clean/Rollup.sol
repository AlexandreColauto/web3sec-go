// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// assertion-strength CLEAN fixture: commitBatch asserts the concept itself
/// (class 4), so there is no asymmetry to report — but the concept is still
/// seen, so the axis is blind, not empty.
contract Rollup {
    mapping(uint256 => bytes32) private prevStateRoot;

    event BatchCommitted(uint256 indexed batchIndex, bytes32 stateRoot);

    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(prevStateRoot[batchIndex] == stateRoot, "state root mismatch");
        prevStateRoot[batchIndex + 1] = stateRoot;
        emit BatchCommitted(batchIndex, stateRoot);
    }
}
