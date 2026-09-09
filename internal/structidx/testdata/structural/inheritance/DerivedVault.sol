// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseVault} from "./BaseVault.sol";

contract DerivedVault is BaseVault {
    function updateTokenMapping(address token, uint256 amount) public override {
        require(amount > 0 && amount <= 1e18, "bounds");
        tokenMapping[token] = amount;
        emit TokenMappingUpdated(token, amount);
    }
}
