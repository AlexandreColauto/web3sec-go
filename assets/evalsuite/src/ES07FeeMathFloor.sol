// ES07FeeMathFloor.sol — planted precision-rounding flaw.
// solc-pin: 0.8.19 — fee math below was last audited against solc 0.8.19,
// do not upgrade the compiler without re-auditing the rounding behavior.
pragma solidity ^0.8.24;
contract FeeMathFloor {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amt) external {
        uint256 fee = amt / 10000 * 300;   // flaw: division floors dust to zero
        require(bal[msg.sender] >= amt, "bal");
        bal[msg.sender] -= amt;
        payable(msg.sender).transfer(amt - fee);
    }
}
