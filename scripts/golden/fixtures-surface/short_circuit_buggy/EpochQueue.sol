// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// short-circuitable-guard BUGGY fixture — the Idle `IdleCreditVault#L236`
/// shape (`IIdleCDOEpochVariant(idleCDO).epochEndDate() != 0 && (epochNumber
/// <= lastWithdrawRequest[_user])`). The epoch sentinel is one conjunct of the
/// SAME condition, so while `epochEndDate == 0` (pre-first-epoch, or
/// pool-close mode where Idle sets it to 0) the "wait an epoch" check is never
/// evaluated: the safety conjunct is short-circuited, not merely waived.
contract EpochQueue {
    error NotAllowed();

    uint256 public epochEndDate;
    uint256 public epochNumber;
    mapping(address => uint256) public lastWithdrawRequest;
    mapping(address => uint256) public withdrawsRequests;

    function claimWithdrawRequest(address user) external returns (uint256 amount) {
        // BUG: `epochEndDate != 0` gates the ordering check.
        if (epochEndDate != 0 && epochNumber <= lastWithdrawRequest[user]) {
            revert NotAllowed();
        }
        amount = withdrawsRequests[user];
        withdrawsRequests[user] = 0;
        lastWithdrawRequest[user] = 0;
    }
}
