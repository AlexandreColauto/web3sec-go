// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// Symmetry fixture (C2), base half (the Morph G-02 shape): the recovery path
/// `onDropMessage` pays the counterpart out of THIS contract's balance and is
/// defined in the base, so a derived gateway can change the custody model
/// without touching the recovery path.
abstract contract L1ERC20Gateway {
    IERC20 public token;

    event Dropped(address to, uint256 amount);

    function onDropMessage(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
        emit Dropped(to, amount);
    }
}
