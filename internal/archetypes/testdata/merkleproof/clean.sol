contract MerkleDistributorGated {
    mapping(bytes32 => uint256) public confirmations;
    uint256 public minConf;
    mapping(bytes32 => bool) public accepted;

    function verifyProof(bytes32[] memory proof, bytes32 root) external {
        require(confirmations[root] >= minConf, "not finalized");
        bytes32 h = proof[0];
        require(h != bytes32(0), "empty proof");
        accepted[root] = true;
    }
}
