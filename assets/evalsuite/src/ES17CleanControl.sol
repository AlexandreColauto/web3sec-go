// ES17CleanControl.sol — the protocol that must yield ZERO findings
pragma solidity ^0.8.24;
contract Escrow {
    mapping(address => uint256) public deposits;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = deposits[msg.sender];
        require(a > 0, "zero");
        deposits[msg.sender] = 0;                       // effects first
        (bool ok, ) = msg.sender.call{value: a}("");    // interaction last
        require(ok, "send");
    }
    function sweep(address payable to) external onlyOwner { to.transfer(address(this).balance); }
}
