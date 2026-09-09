// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// sequential-cursor CLEAN fixture: the cursor is bounded but not sequential
/// (no `cursor + 1 == arg`), so a blocked item cannot freeze the queue and
/// the axis has no sites at all.
contract Rollup {
    uint256 private lastFinalizedBatchIndex;
    mapping(uint256 => bytes32) private batchRoots;

    function finalizeBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(batchIndex > lastFinalizedBatchIndex, "stale batch");
        batchRoots[batchIndex] = stateRoot;
        lastFinalizedBatchIndex = batchIndex;
    }
}
