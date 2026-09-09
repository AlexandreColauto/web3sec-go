// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {L1ERC20Gateway} from "./L1ERC20Gateway.sol";

/// custody-primitive CLEAN fixture, derived half: the forward path HOLDS
/// custody (transfer-in only, no burn/mint), so paying out of the balance is
/// self-consistent and no row may be emitted. The primitives are still seen,
/// so the axis is blind, not empty.
contract L1ReverseCustomGateway is L1ERC20Gateway {
    mapping(address => uint256) private deposits;

    function _deposit(address to, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        deposits[to] += amount;
    }
}
