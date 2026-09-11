// testdata/merklepath/clean.sol — the same withdrawal shape WITH the
// completeness check: the guard text mentions `proof.length`, so the I5b
// predicate is absent. Everything else about the contract is unchanged.
pragma solidity ^0.8.0;

contract BridgeWithdrawal {
    mapping(bytes32 => bool) public processed;
    uint256 public lastCheckpoint;

    function verifyProof(bytes32[] calldata proof, bytes32 root) external {
        require(proof.length > 0, "empty proof");
        bytes32 h = proof[0];
        require(h == root, "bad proof");
        require(lastCheckpoint != 0, "no checkpoint");
        processed[root] = true;
    }
}
