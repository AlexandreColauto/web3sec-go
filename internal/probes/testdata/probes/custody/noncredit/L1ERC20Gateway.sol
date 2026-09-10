// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// custody-primitive NONCREDIT fixture, base half: the forward path `_deposit`
/// HOLDS custody with transferFrom — the transfer-in primitive. No mint/burn
/// anywhere in the family, so the schema's custody enum (mints|burns) has no
/// value for the divergences the derived half disagrees with.
abstract contract L1ERC20Gateway {
    IERC20 public token;

    event Deposited(address to, uint256 amount);

    function _deposit(address to, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposited(to, amount);
    }
}
