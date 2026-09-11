// ES14LiquidationTWAP.sol — planted liquidation-logic flaw
// (documented-assumption decoy: the comment below asserts a TWAP that the
// code never reads — the documented assumption is false, like ES17's true
// one; only the code decides).
pragma solidity ^0.8.24;
contract LiquidationTWAP {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    // ASSUMPTION: health factor uses the 1h TWAP oracle (see ES17 pattern).
    function health(address u) public view returns (uint256) {
        return collateral[u] * 1e18 / (debt[u] + 1);   // flaw: spot, not TWAP
    }
    function liquidate(address u) external {
        require(health(u) < 1e18, "healthy");
        debt[u] = 0;
        collateral[u] = 0;
    }
}
