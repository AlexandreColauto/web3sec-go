// ES04LenderUnderflow.sol — planted unchecked-external-call: the low-level
// call return value is ignored, so failed sends silently lose accounting.
pragma solidity ^0.8.24;
contract Lender {
    mapping(address => uint256) public credit;
    function fund() external payable { credit[msg.sender] += msg.value; }
    function borrow(uint256 amt) external {
        credit[msg.sender] -= amt;
        payable(msg.sender).call{value: amt}("");   // flaw: success ignored
    }
    receive() external payable {}
}