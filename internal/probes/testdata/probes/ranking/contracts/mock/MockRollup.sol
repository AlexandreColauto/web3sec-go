// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Rollup} from "../../Rollup.sol";

/// C3 fixture: the Morph `contracts/mock/MockRollup.sol` shape. `MockRollup is
/// Rollup` inherits every Rollup function, so sibling-collapse folds it into
/// every Rollup group as a second site. Before C3 that doubled `len(siblings)`
/// (demoting G-01 `commitBatch` below seven single-site rows) and won the
/// alphabetical representative tiebreak, anchoring the real row at a test
/// double. A mock is scaffolding, not a second site of the pattern.
contract MockRollup is Rollup {
    uint256 private lastFinalizedBatchIndex;

    function setLastFinalizedBatchIndex(uint256 batchIndex) external {
        lastFinalizedBatchIndex = batchIndex;
    }
}
