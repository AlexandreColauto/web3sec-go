// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }

    function toUint128(uint256 a) internal pure returns (uint256) {
        return a;
    }
}

/// accumulator-basis-skew BUGGY fixture — the LoopFi
/// `RewardManager::_updateRewardIndex` shape (line 74
/// `if (totalShares != 0) index += accrued.divDown(totalShares);` next to the
/// unconditional `rewardState[token] = RewardState({index, lastBalance})`
/// store). The rounded accumulator can stay at zero while the companion basis
/// advances by the full `accrued` delta: INV-006 "no accounting variable moves
/// without its companion", read in the loss direction.
contract RewardManager {
    struct RewardState {
        uint256 index;
        uint256 lastBalance;
    }

    using PMath for uint256;

    mapping(address => RewardState) public rewardState;

    function _updateRewardIndex(address token, uint256 accrued, uint256 totalShares) internal {
        RewardState memory state = rewardState[token];
        uint256 index = state.index;
        // BUG: divDown rounds the accumulator; `lastBalance` below does not.
        if (totalShares != 0) {
            index += accrued.divDown(totalShares);
        }
        rewardState[token] = RewardState({
            index: index.toUint128(),
            lastBalance: state.lastBalance + accrued
        });
    }
}
