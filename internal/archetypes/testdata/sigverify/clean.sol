type ChainId is uint256;

contract SigVerifierGated {
    function verify(bytes memory signature, address signer, ChainId chainId) external view returns (address recovered) {
        require(ChainId.unwrap(chainId) == block.chainid, "wrong chain");
        bytes32 h = keccak256(abi.encodePacked(signer, ChainId.unwrap(chainId)));
        recovered = ecrecover(h, uint8(signature[0]), bytes32(0), bytes32(0));
    }
}
