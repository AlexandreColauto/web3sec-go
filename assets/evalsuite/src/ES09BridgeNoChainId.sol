// ES09BridgeNoChainId.sol — planted cross-chain-replay: the signed digest
// omits block.chainid, so a signature replays on every forked chain.
pragma solidity ^0.8.24;
contract BridgeNoChainId {
    address public signer;
    mapping(bytes32 => bool) public spent;
    constructor(address s) { signer = s; }
    function claim(address to, uint256 amt, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amt));   // flaw: no chainId
        require(!spent[digest], "spent");
        require(ecrecover(digest, v, r, s) == signer, "sig");
        spent[digest] = true;
        payable(to).transfer(amt);
    }
    receive() external payable {}
}
