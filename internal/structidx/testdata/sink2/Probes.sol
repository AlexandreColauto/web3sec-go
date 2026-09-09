
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILender { function flashLoan(address, uint256) external; }

contract SinkProbes {
    address public impl;
    ILender public lender;

    function forward(address target, bytes memory data) external {
        (bool ok, ) = target.call(data);
        require(ok);
    }

    function proxyTo(address _impl, bytes memory data) external {
        (bool ok, ) = _impl.delegatecall(data);
        require(ok);
    }

    function borrow(address asset, uint256 amt) external {
        lender.flashLoan(asset, amt);
    }
}
