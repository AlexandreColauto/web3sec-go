// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Inheritance fixture base: DerivedVault overrides updateTokenMapping, so the
/// closure of every descendant must keep DerivedVault as the DEFINING contract.
contract BaseVault {
    uint256 internal totalAssets;
    mapping(address => uint256) internal tokenMapping;

    event TokenMappingUpdated(address indexed token, uint256 amount);

    function updateTokenMapping(address token, uint256 amount) public virtual {
        require(token != address(0), "zero token");
        tokenMapping[token] += amount;
        totalAssets += amount;
    }

    function onlyBase(address token) internal view returns (uint256) {
        return tokenMapping[token];
    }
}
