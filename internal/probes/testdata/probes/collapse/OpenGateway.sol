// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// sibling-collapse fixture: identical (function + concept signature + tier)
/// shape as GatedGateway, but reachable without any authorization modifier.
/// The collapsed row must keep THIS gate (the weakest) and list this site
/// first, even though "GatedGateway" sorts before "OpenGateway".
contract OpenGateway {
    mapping(address => uint256) public tokenMapping;

    function updateTokenMapping(address token, uint256 amount) external {
        require(token != address(0), "zero token");
        tokenMapping[token] = amount;
    }

    function checkTokenMapping(address token, uint256 expected) external view {
        require(tokenMapping[token] == expected, "bad mapping");
    }
}
