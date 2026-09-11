contract SigVerifierChainUnused {
    function verify(bytes memory signature, address signer, uint256 chainId) external pure returns (address recovered) {
        bytes32 h = keccak256(abi.encodePacked(signer));
        recovered = ecrecover(h, uint8(signature[0]), bytes32(0), bytes32(0));
    }
}
