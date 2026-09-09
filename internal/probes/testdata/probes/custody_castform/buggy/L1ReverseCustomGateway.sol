// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {L1ERC20Gateway, IERC20Upgradeable, IMorphERC20Upgradeable} from "./L1ERC20Gateway.sol";

/// C2 fixture, derived half: the forward path burns through a CAST receiver
/// (`IMorphERC20Upgradeable(_token).burn(...)`, the Morph G-02 gold shape at
/// `L1ReverseCustomGateway.sol:134`) while the inherited recovery path pays out
/// of this contract's own balance. Neither half is an `identifier.method(`
/// call, so the pre-fix index saw no custody pair at all.
contract L1ReverseCustomGateway is L1ERC20Gateway {
    function _deposit(address to, uint256 amount) external {
        IERC20Upgradeable(_token).safeTransferFrom(msg.sender, address(this), amount);
        IMorphERC20Upgradeable(_token).burn(address(this), amount);
    }
}
