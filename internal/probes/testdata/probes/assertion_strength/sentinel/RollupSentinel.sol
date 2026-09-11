// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// assertion-strength SENTINEL fixture: commitBatch consumes `state:root`
/// under a zero-check (`stateRoot != bytes32(0)`) while finalizeBatch asserts
/// the same concept at equality-to-persisted-state (class 4) — the gold shape.
/// A sentinel check cannot express the truth of the value it guards: any
/// non-zero lie passes it, so the row has to demand the value that passes.
contract RollupSentinel {
    bytes32 public stateRoot;

    function commitBatch(bytes32 root) external {
        require(stateRoot != bytes32(0), "zero root");
        stateRoot = root;
    }

    function finalizeBatch(bytes32 claimed) external view {
        require(keccak256(abi.encode(stateRoot)) ==
            keccak256(abi.encode(claimed)), "state root mismatch");
    }
}
