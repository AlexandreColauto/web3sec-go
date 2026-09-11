// ES19LegacySplitterUnchecked.sol — planted unchecked-external-call.
// solc-pin: >=0.7.0 <0.9.0 — the suite's range-pragma compiler-diversity
// fixture (Wave J Task 3): the low-level send's return value is ignored,
// so a failed payout silently desyncs accounting (same class as ES04).
// The caller is bound to a named local so the structural index sees the
// balance write (an indexed `msg.sender` lvalue is a parser under-report).
pragma solidity >=0.7.0 <0.9.0;
contract LegacySplitter {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function sweep() external {
        address payable who = payable(msg.sender);
        uint256 amount = balances[who];
        balances[who] = 0;
        who.call{value: amount}("");   // flaw: a failed send silently desyncs accounting
    }
    receive() external payable {}
}
