pragma solidity ^0.8.24;
contract MintFreeC {
    uint256 public supply;
    uint256 public pool;
    mapping(address => uint256) public shares;
    function add(uint256 d) external { supply += d; }
    receive() external payable { pool += msg.value; }
}
