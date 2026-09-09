
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlash { function flashLoan(address, uint256, bytes calldata data) external; }
interface IFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
interface IHub { function sendMessage(bytes calldata data) external; }

contract Manipulator is BridgeLike {
    IFlash public fl;
    IFeed public feed;
    IHub public hub;
    address public target;

    constructor(address f, address p) { fl = IFlash(f); feed = IFeed(p); }

    function attack() external {
        fl.flashLoan(address(this), 1000, "");
        int256 p = feed.latestRoundData();
        hub.sendMessage("");
        (bool ok, ) = target.delegatecall(abi.encodeCall(IHook.hook, (p)));
    }

    function relay(bytes calldata msg) external {
        (bool ok, ) = target.call(msg);
    }
}

contract BridgeLike {}
interface IHook { function hook(int256) external; }
