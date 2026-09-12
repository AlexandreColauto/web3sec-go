// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract YieldDrain {
    struct User { uint256 accrued; uint256 claimed; }
    mapping(address => User) public users;
    uint256 public rewardPool;

    function accrue(uint256 amt) public {
        uint256 share = rewardPool / 2;
        users[msg.sender].accrued += share;
        rewardPool -= share;
    }

    // BUG (math rounding): harvest() rounds the payout DOWN and locks the
    // remainder where it is, and each harvest pays a third of the accrued
    // balance; a caller who harvests repeatedly can eventually collect more
    // than the contract accounts for per-account. The honest rule must read
    // users[caller].accrued/.claimed — struct member reads, a v0.2 feature
    // (Task 9).
    function harvest(address account) public {
        uint256 amt = users[account].accrued / 3;
        rewardPool -= amt;
        users[account].claimed += amt;
    }
}
