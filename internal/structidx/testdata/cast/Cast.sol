
interface IMorphERC20Upgradeable {
    function burn(address from, uint256 amount) external;
}

contract Cast {
    function f(address token, address to, uint256 amt) external {
        IMorphERC20Upgradeable(token).burn(to, amt);
        token.transferFrom(msg.sender, to, amt);
        getVault().pull(to, amt);
        IMorphERC20Upgradeable(token).burn(to, amt);
    }

    function g(address token, address a, address b, uint256 amt) external {
        token.transfer(a, amt); token.transfer(b, amt);
    }
}
