// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// short-circuitable-guard CLEAN fixture: the same ordering check in the same
/// function, still a conjunction, but NO conjunct is a non-zero/`> 0`
/// sentinel — the check cannot be short-circuited by an unset
/// epoch/deadline/rate. The condition is still a site, so the axis is blind
/// (`no-sentinel-conjunct`), not empty.
contract EpochQueue {
    error NotAllowed();

    uint256 public epochEndDate;
    uint256 public epochNumber;
    mapping(address => uint256) public lastWithdrawRequest;
    mapping(address => uint256) public withdrawsRequests;

    function claimWithdrawRequest(address user) external returns (uint256 amount) {
        if (epochEndDate > block.timestamp && epochNumber <= lastWithdrawRequest[user]) {
            revert NotAllowed();
        }
        amount = withdrawsRequests[user];
        withdrawsRequests[user] = 0;
        lastWithdrawRequest[user] = 0;
    }
}
