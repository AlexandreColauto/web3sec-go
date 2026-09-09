// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// sibling-collapse fixture: same shape as OpenGateway, gated by an
/// inside-boundary mechanism (still tier 0) — so the two rows collapse and
/// the weakest gate (unprivileged) has to win.
contract GatedGateway {
    mapping(address => uint256) public tokenMapping;
    address public counterpart;

    modifier onlyCounterpart() {
        require(msg.sender == counterpart, "not counterpart");
        _;
    }

    function updateTokenMapping(address token, uint256 amount) external onlyCounterpart {
        require(token != address(0), "zero token");
        tokenMapping[token] = amount;
    }

    function checkTokenMapping(address token, uint256 expected) external view {
        require(tokenMapping[token] == expected, "bad mapping");
    }
}
