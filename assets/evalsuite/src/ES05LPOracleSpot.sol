// ES05LPOracleSpot.sol — planted oracle-manipulation: borrow limit priced
// off instantaneous spot reserves with no TWAP, manipulable in one swap.
pragma solidity ^0.8.24;
contract LPOracleSpot {
    uint256 public reserve0;
    uint256 public reserve1;
    mapping(address => uint256) public debt;
    function sync(uint256 r0, uint256 r1) external { reserve0 = r0; reserve1 = r1; }
    function spot() public view returns (uint256) {
        return reserve1 * 1e18 / reserve0;   // flaw: spot price, no TWAP
    }
    function borrow(uint256 amt) external {
        require(amt <= spot() * 100, "limit");
        debt[msg.sender] += amt;
    }
}
