// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DerivedVault} from "./DerivedVault.sol";

/// Third level: proves the closure is TRANSITIVE and that an override wins
/// even when it sits two levels below the queried contract.
contract AuditedVault is DerivedVault {
    function onlyAudited() external {}
}
