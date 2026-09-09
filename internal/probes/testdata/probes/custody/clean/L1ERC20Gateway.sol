// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// custody-primitive CLEAN fixture, base half: the same recovery path and the
/// same pay-from-self — the discriminator must be the forward path, not this.
abstract contract L1ERC20Gateway {
    IERC20 public token;

    event Dropped(address to, uint256 amount);

    function onDropMessage(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
        emit Dropped(to, amount);
    }
}
