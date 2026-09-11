// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// assertion-strength LEAKY fixture, asserter half: `prev:state:root` is
/// asserted with equality-to-persisted-state (class 4) in finalizeBatch.
/// Consumer.sol inherits this contract and consumes the same concept under
/// a class-0 guard without asserting it — the G-01 shape (validated here,
/// consumed there). Mirrors internal/probes/testdata/probes/
/// assertion_strength/buggy/Rollup.sol, split across the inheritance edge so
/// the row's asserter and consumer live in different files.
contract Own {
    mapping(uint256 => bytes32) internal prevStateRoot;
    mapping(uint256 => bytes32) private newStateRoot;

    event BatchCommitted(uint256 indexed batchIndex, bytes32 stateRoot);

    function finalizeBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(prevStateRoot[batchIndex] == stateRoot, "state root mismatch");
        newStateRoot[batchIndex] = stateRoot;
    }
}
