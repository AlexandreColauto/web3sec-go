// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {L1ERC20Gateway} from "./L1ERC20Gateway.sol";

/// custody-primitive NONCREDIT fixture, derived half: TWO deposit-direction
/// forward paths pay the asset out of this contract's own balance with
/// transfer (transfer-out) instead of holding it, disagreeing with the base's
/// transfer-in about the same (deposit, erc20) column. Two observed cells give
/// two divergence rows, and neither expected/observed primitive has a
/// schema-legal custody label.
contract L1ReverseCustomGateway is L1ERC20Gateway {
    function _depositByTransfer(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }

    function depositViaVault(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }
}
