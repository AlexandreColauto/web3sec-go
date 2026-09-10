// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {L1ERC20Gateway} from "./L1ERC20Gateway.sol";

/// Symmetry fixture (C2), derived half: the forward path `_deposit` BURNS the
/// bridged amount (the gateway holds nothing) while the inherited recovery
/// path still pays out of its own balance — a family-level funding mismatch.
contract L1ReverseCustomGateway is L1ERC20Gateway {
    uint256 private totalBurned;

    function _deposit(address to, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        _burn(address(this), amount);
    }

    function _burn(address from, uint256 amount) internal {
        totalBurned += amount;
    }
}
