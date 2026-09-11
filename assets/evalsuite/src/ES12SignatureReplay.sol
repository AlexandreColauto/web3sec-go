// ES12SignatureReplay.sol — planted signature-replay: the authorization
// digest binds no nonce, so one signature authorizes unlimited withdrawals.
pragma solidity ^0.8.24;
contract SignatureReplay {
    address public signer;
    mapping(address => uint256) public bal;
    constructor(address s) { signer = s; }
    function fund() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amt, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amt));   // flaw: no nonce
        require(ecrecover(digest, v, r, s) == signer, "sig");
        require(bal[msg.sender] >= amt, "bal");
        bal[msg.sender] -= amt;
        payable(msg.sender).transfer(amt);
    }
    receive() external payable {}
}
