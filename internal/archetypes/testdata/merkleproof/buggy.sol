contract MerkleDistributor {
    mapping(bytes32 => bool) public accepted;

    function verifyProof(bytes32[] memory proof, bytes32 root) external {
        bytes32 h = proof[0];
        require(h != bytes32(0), "empty proof");
        accepted[root] = true;
    }
}
