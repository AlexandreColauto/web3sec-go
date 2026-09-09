// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Concept-folding fixture: prevStateRoot and getPrevStateHash must yield the
/// same fuzzy keys (prev:state:root). Also exercises the full guard scale 0..4.
contract StateRoots {
    mapping(uint256 => bytes32) private prevStateRoot;
    mapping(uint256 => bytes32) private newStateRoot;
    mapping(address => uint256) private whitelist;
    mapping(address => uint256) private stateRoots;
    bytes32 private storedHash;

    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external {
        require(prevStateRoot[batchIndex] == stateRoot, "state root mismatch");
        prevStateRoot[batchIndex + 1] = stateRoot;
        storedHash = getPrevStateHash(batchIndex);
        if (batchIndex == 0) { storedHash = stateRoot; }
    }

    function getPrevStateHash(uint256 index) internal view returns (bytes32) {
        return prevStateRoot[index];
    }

    function foldCheck(bytes32 candidate, uint256 index) external view {
        require(getPrevStateHash(index) == candidate, "digest mismatch");
        if (candidate != bytes32(0)) revert ZeroRoot();
    }

    function guardScale(uint256 amount, address who, bool enabled) external {
        require(enabled, "disabled");
        require(amount != 0, "zero");
        require(amount <= 1e18, "too big");
        require(whitelist[who], "not allowed");
        require(stateRoots[who] == amount, "bad root");
    }

    /// Nested-comma guard: the condition contains commas at bracket depth 2
    /// (`abi.encode(leaf, proof, root)`), so a naive split(",")[0] truncates
    /// it and loses the class-4 keccak equality.
    function relayMessage(bytes32 root, bytes32[] calldata proof, bytes32 leaf)
        external view
    {
        require(keccak256(abi.encode(leaf, proof, root)) == storedHash, "bad proof");
    }

    /// Stopword-only guard: every token (`length`) is dropped as noise, yet
    /// the condition is still a non-zero sanity assertion.
    function touch(uint256 length) external view {
        require(length != 0, "empty");
    }
}
