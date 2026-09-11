contract SigVerifierChainChecked {
    function verify(bytes memory signature, address signer, uint256 chainId) external view returns (address recovered) {
        require(chainId == block.chainid, "wrong chain");
        bytes32 h = keccak256(abi.encodePacked(signer, chainId));
        recovered = ecrecover(h, uint8(signature[0]), bytes32(0), bytes32(0));
    }
}
