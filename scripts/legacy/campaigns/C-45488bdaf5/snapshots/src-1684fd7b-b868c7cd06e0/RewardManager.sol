// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

/// accumulator-basis-skew BLIND fixture: a rounding-limited accumulator update
/// that reaches storage, and NOTHING else in the function moves — the probe
/// publishes `no-companion-write` so the axis is blind (sites > 0, rows == 0)
/// and the operator must attest a cited key to close it.
contract RewardManager {
    struct RewardState {
        uint256 index;
        uint256 lastBalance;
    }

    using PMath for uint256;

    mapping(address => RewardState) public rewardState;

    function poke(address token, uint256 accrued, uint256 totalShares) external {
        if (totalShares != 0) {
            rewardState[token].index += accrued.divDown(totalShares);
        }
    }
}
