// testdata/verifier/clean.sol — the same flag with no default-on writer: the
// trust flag is written only by an authorization-gated admin setter, and the
// constructor (an initializer-shaped writer) never touches it.
pragma solidity ^0.8.0;

contract NomadReplica {
    bool public verified;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address o) {
        owner = o;
    }

    function setVerified(bool v) external onlyOwner {
        verified = v;
    }

    function process(bytes32 root) external {
        require(verified, "not verified");
        emit Processed(root);
    }
}
