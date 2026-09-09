
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken { function transfer(address, uint256) external returns (bool); }

contract Vault {
    IToken public token;
    mapping(address => uint256) private _shares;
    uint256 public totalShares;

    constructor(address t) { token = IToken(t); }

    function deposit(uint256 amt) external {
        _shares[msg.sender] += amt;
        totalShares += amt;
        token.transferFrom(msg.sender, address(this), amt);
    }

    function withdraw(uint256 amt) public {
        _shares[msg.sender] -= amt;
        totalShares -= amt;
        token.transfer(msg.sender, amt);
    }

    function rescueTokens(address to) external onlyOwner {
        token.transfer(to, token.balanceOf(address(this)));
    }

    modifier onlyOwner() { require(msg.sender == owner()); _; }
}
