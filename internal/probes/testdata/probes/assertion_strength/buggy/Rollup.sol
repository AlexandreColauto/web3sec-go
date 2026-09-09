// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// assertion-strength BUGGY fixture: `prev:state:root` is asserted with
/// equality-to-persisted-state (class 4) only in finalizeBatch, while
/// commitBatch consumes the same concept and writes state under a class-0
/// guard — the G-01 shape (validated there, consumed here).
contract Rollup {
    mapping(uint256 => bytes32) private prevStateRoot;
    mapping(uint256 => bytes32) private newStateRoot;

    event BatchCommitted(uint256 indexed batchIndex, bytes32 stateRoot);

    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(stateRoot != bytes32(0), "zero root");
        prevStateRoot[batchIndex + 1] = stateRoot;
        emit BatchCommitted(batchIndex, stateRoot);
    }

    function finalizeBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(prevStateRoot[batchIndex] == stateRoot, "state root mismatch");
        newStateRoot[batchIndex] = stateRoot;
    }
}
