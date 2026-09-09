// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Morph-shaped ranking fixture (deliberately NOT the 31k-line tree): the
/// measured G-01 row is `commitBatch` — gated by a semi-trusted staker role,
/// consuming `prev:state:root` under a class-0 guard while `finalizeBatch`
/// asserts the same concept at class 4. Six tier-0 rows, one unresolvable
/// tier-1 row and three onlyOwner tier-2 rows surround it so the rank key
/// (tier, -assertion_gap, siblings, name) has to do real work: `commitBatch`
/// must stay rank 1 of its axis.
contract Rollup {
    address private owner;
    address private guardian;
    mapping(address => bool) private stakers;

    mapping(uint256 => bytes32) private prevStateRoot;
    mapping(uint256 => bytes32) private droppedMessageRoot;
    mapping(uint256 => bytes32) private provenProofRoot;
    mapping(uint256 => bytes32) private replayedReceiptRoot;
    mapping(uint256 => bytes32) private activeStakerRoot;
    mapping(uint256 => bytes32) private genesisRoot;
    mapping(uint256 => bytes32) private revertedBatchRoot;
    mapping(uint256 => bytes32) private withdrawLockRoot;
    mapping(uint256 => bytes32) private challengedClaimRoot;
    uint256 private finalizedCount;

    modifier onlyActiveStaker() {
        require(stakers[msg.sender], "not staker");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "not guardian");
        _;
    }

    // ---- tier 0: attacker-reachable --------------------------------------

    /// G-01 shape: consumes prev:state:root with no guard on it at all.
    function commitBatch(uint256 batchIndex, bytes32 stateRoot) external onlyActiveStaker {
        prevStateRoot[batchIndex + 1] = stateRoot;
    }

    function dropMessage(uint256 batchIndex, bytes32 messageRoot) external {
        droppedMessageRoot[batchIndex] = messageRoot;
    }

    function proveState(uint256 batchIndex, bytes32 proofRoot) external {
        provenProofRoot[batchIndex] = proofRoot;
    }

    function replayMessage(uint256 batchIndex, bytes32 receiptRoot) external {
        replayedReceiptRoot[batchIndex] = receiptRoot;
    }

    function getActiveStakers(uint256 batchIndex, bytes32 stakerRoot) external {
        activeStakerRoot[batchIndex] = stakerRoot;
    }

    /// the asserter for the commitBatch concept (class 4, same concept key).
    function finalizeBatch(uint256 batchIndex, bytes32 stateRoot) external onlyActiveStaker {
        require(prevStateRoot[batchIndex] == stateRoot, "state root mismatch");
        finalizedCount = batchIndex;
    }

    // ---- tier 1: unresolvable modifier -----------------------------------

    function challengeState(uint256 batchIndex, bytes32 claimRoot) external onlyGuardian {
        challengedClaimRoot[batchIndex] = claimRoot;
    }

    // ---- tier 2: trusted role --------------------------------------------

    function importGenesisBatch(uint256 batchIndex, bytes32 root) external onlyOwner {
        genesisRoot[batchIndex] = root;
    }

    function revertBatch(uint256 batchIndex, bytes32 root) external onlyOwner {
        revertedBatchRoot[batchIndex] = root;
    }

    function updateWithdrawLock(uint256 batchIndex, bytes32 root) external onlyOwner {
        withdrawLockRoot[batchIndex] = root;
    }

    // ---- asserters (view: they never write, so they are never consumers) --

    function auditProof(uint256 batchIndex, bytes32 proofRoot) external view {
        require(provenProofRoot[batchIndex] == proofRoot, "proof mismatch");
    }

    function auditDrop(uint256 batchIndex, bytes32 messageRoot) external view {
        require(droppedMessageRoot[batchIndex] == messageRoot, "drop mismatch");
    }

    function auditReplay(uint256 batchIndex, bytes32 receiptRoot) external view {
        require(replayedReceiptRoot[batchIndex] == receiptRoot, "replay mismatch");
    }

    function auditStakers(uint256 batchIndex, bytes32 stakerRoot) external view {
        require(activeStakerRoot[batchIndex] == stakerRoot, "staker mismatch");
    }

    function auditGenesis(uint256 batchIndex, bytes32 root) external view {
        require(genesisRoot[batchIndex] == root, "genesis mismatch");
    }

    function auditRevert(uint256 batchIndex, bytes32 root) external view {
        require(revertedBatchRoot[batchIndex] == root, "revert mismatch");
    }

    function auditLock(uint256 batchIndex, bytes32 root) external view {
        require(withdrawLockRoot[batchIndex] == root, "lock mismatch");
    }

    function auditChallenge(uint256 batchIndex, bytes32 claimRoot) external view {
        require(challengedClaimRoot[batchIndex] == claimRoot, "claim mismatch");
    }
}
