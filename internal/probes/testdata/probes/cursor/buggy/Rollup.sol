// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// sequential-cursor BUGGY fixture: `finalizeBatch` may only consume the next
/// batch index in strict order (`cursor + 1 == arg`), so one blocked item
/// freezes every later one. `commitBatch` can strand it by advancing the
/// pending queue while the cursor stays put.
contract Rollup {
    uint256 private lastFinalizedBatchIndex;
    mapping(uint256 => bytes32) private batchRoots;
    mapping(uint256 => bytes32) private pendingRoots;

    event BatchCommitted(uint256 indexed batchIndex, bytes32 stateRoot);
    event BatchFinalized(uint256 indexed batchIndex, bytes32 stateRoot);

    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external {
        pendingRoots[batchIndex] = stateRoot;
        emit BatchCommitted(batchIndex, stateRoot);
    }

    function finalizeBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(lastFinalizedBatchIndex + 1 == batchIndex, "out of order");
        batchRoots[batchIndex] = stateRoot;
        lastFinalizedBatchIndex = batchIndex;
        emit BatchFinalized(batchIndex, stateRoot);
    }
}
