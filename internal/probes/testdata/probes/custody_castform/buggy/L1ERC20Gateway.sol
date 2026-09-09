// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Upgradeable {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

interface IMorphERC20Upgradeable {
    function burn(address from, uint256 amount) external;
}

/// C2 fixture: the recovery pay is CAST-FORM —
/// `IERC20Upgradeable(_token).safeTransfer(to, amount)` — the exact shape the
/// identifier-only call regex used to miss on the pinned Morph tree
/// (`L1ERC20Gateway.sol:87`), which is why the custody axis emitted 0 rows on
/// every held-out tree.
abstract contract L1ERC20Gateway {
    address internal _token;

    event Dropped(address to, uint256 amount);

    function onDropMessage(address to, uint256 amount) external {
        IERC20Upgradeable(_token).safeTransfer(to, amount);
        emit Dropped(to, amount);
    }
}
