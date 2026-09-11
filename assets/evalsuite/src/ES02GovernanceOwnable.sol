// ES02GovernanceOwnable.sol — planted authorization flaw: setOwner lacks
// the onlyOwner gate, so anyone can seize governance.
pragma solidity ^0.8.24;
contract GovernanceOwnable {
    address public owner;
    mapping(uint256 => uint256) public votes;
    constructor() { owner = msg.sender; }
    function setOwner(address n) external {
        owner = n;                            // flaw: missing onlyOwner
    }
    function vote(uint256 id) external { votes[id] += 1; }
}
