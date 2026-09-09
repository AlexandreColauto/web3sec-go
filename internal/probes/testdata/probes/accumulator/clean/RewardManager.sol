// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function toUint128(uint256 a) internal pure returns (uint256) {
        return a;
    }
}

/// accumulator-basis-skew CLEAN fixture: the same accumulator and the same
/// companion basis are written in the same function, but the accumulator is
/// NOT rounding-limited — it and the basis move by the same delta, so there is
/// no skew to look at. No rounding primitive on any accumulator write means
/// the axis has no sites at all.
contract RewardManager {
    struct RewardState {
        uint256 index;
        uint256 lastBalance;
    }

    using PMath for uint256;

    mapping(address => RewardState) public rewardState;

    function _updateRewardIndex(address token, uint256 accrued, uint256 totalShares) internal {
        RewardState memory state = rewardState[token];
        uint256 index = state.index + accrued;
        rewardState[token] = RewardState({
            index: index.toUint128(),
            lastBalance: state.lastBalance + accrued
        });
    }
}
