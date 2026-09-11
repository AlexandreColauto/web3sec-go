// testdata/merklepath/buggy.sol — Binance-Bridge shape (I5b): a withdrawal
// proof is consumed with NO completeness check on the path — no guard anywhere
// on the execution path references the proof's `length`. The finality gate on
// `lastCheckpoint` is deliberately present, so this fixture stays a
// merkle-PATH bug and not a depth-gate bug:
// `merkle_verify_without_depth_gate` (G10) reads a depth marker here and stays
// ABSENT, which is how the two archetypes stay separable.
pragma solidity ^0.8.0;

contract BridgeWithdrawal {
    mapping(bytes32 => bool) public processed;
    uint256 public lastCheckpoint;

    function verifyProof(bytes32[] calldata proof, bytes32 root) external {
        bytes32 h = proof[0];
        require(h == root, "bad proof");
        require(lastCheckpoint != 0, "no checkpoint");
        processed[root] = true;
    }
}
