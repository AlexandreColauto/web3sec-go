// ES13FlashLoanSpot.sol — planted flash-loan flaw (economic-invariant
// companion): repayment is checked at manipulable spot price, so the loan
// can be repaid with devalued collateral in the same transaction.
pragma solidity ^0.8.24;
contract FlashLoanSpot {
    uint256 public price = 1e18;
    mapping(address => uint256) public debt;
    function setPrice(uint256 p) external { price = p; }
    function flashLoan(uint256 amt) external {
        uint256 due = amt * price / 1e18;   // flaw: spot-priced repayment
        debt[msg.sender] += due;
        payable(msg.sender).transfer(amt);
    }
    receive() external payable {}
}
