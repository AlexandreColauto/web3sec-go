// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Sibling-collapse fixture (one of seven): every sibling defines the same
/// updateTokenMapping shape, so identical (fn + concept signature + tier)
/// must fold into ONE candidate while every defining contract stays named.
contract L2CustomGateway {
    mapping(address => uint256) public tokenMapping;
    address public counterpart;

    event TokenMappingUpdated(address indexed token, uint256 amount);

    modifier onlyCounterpart() {
        require(msg.sender == counterpart, "not counterpart");
        _;
    }

    function updateTokenMapping(address token, uint256 amount) external onlyCounterpart {
        require(token != address(0), "zero token");
        require(amount > 0, "zero amount");
        tokenMapping[token] = amount;
        emit TokenMappingUpdated(token, amount);
    }

    /// class-4 asserter added by A2: makes the tokenMapping concept joinable
    /// so the sibling-collapse regression has seven real rows to fold.
    function checkTokenMapping(address token, uint256 expected) external view {
        require(tokenMapping[token] == expected, "bad mapping");
    }
}
