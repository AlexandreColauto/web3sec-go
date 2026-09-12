// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Distilled reentrancy: the guard is evaluated against state the callee can
/// still change, and both payouts are counted — no underflow, no revert, so the
/// bug is visible in state (`payouts`) rather than in a balance the tool cannot see.
contract Vault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;
    uint256 public payouts;

    // `payable`: the brief's source spelled this non-payable while its own
    // Attacker does `vault.deposit{value: a}(a)` — the EVM reverts on value sent
    // to a non-payable function, so the replay could not run at all (meta.md ruling).
    function deposit(uint256 amount) public payable {
        balanceOf[msg.sender] += amount;
        totalDeposits += amount;
    }

    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balanceOf[msg.sender] = 0;      // idempotent: the second frame cannot underflow
        payouts = payouts + 1;
    }
}
