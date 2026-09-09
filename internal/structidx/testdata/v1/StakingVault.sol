
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {IERC20} from "./IERC20.sol";

contract StakingVault is Ownable {
    uint256 public totalStaked;
    uint256 public rewardPerToken;
    mapping(address => uint256) private _stakes;
    IERC20 public stakingToken;

    event Staked(address indexed who, uint256 amount);

    error ZeroAmount();

    constructor(address token) { stakingToken = IERC20(token); }

    modifier updateReward(address account) {
        rewardPerToken = _accrue();
        _;
    }

    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        if (amount == 0) revert ZeroAmount();
        totalStaked += amount;
        _stakes[msg.sender] += amount;
        stakingToken.transferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }

    function claim() public updateReward(msg.sender) returns (uint256 rew) {
        rew = _earned(msg.sender);
        _stakes[msg.sender] = 0;
        stakingToken.transfer(msg.sender, rew);
    }

    function _earned(address who) internal view returns (uint256) {
        return _stakes[who] * rewardPerToken / 1e18;
    }

    function _accrue() internal returns (uint256) { return rewardPerToken; }

    function rescue(address to) external onlyOwner {
        stakingToken.transfer(to, stakingToken.balanceOf(address(this)));
    }

    receive() external payable {}

    fallback() external payable {}

    function batchStake(uint256[] calldata amounts) external {}

    function fixedStake(uint256[3] calldata amounts) external {}
}
