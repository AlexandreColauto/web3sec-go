// testdata/verifier/buggy.sol — Nomad-shape trust root (I5b): the
// trust-granting flag is written in the CONSTRUCTOR, an initializer-shaped
// writer with no authorization modifier, so the flag is on from deployment.
//
// VALUE-BLINDNESS: this fixture writes true, but the structural index records
// only THAT `verified` is written — a constructor writing `verified = false`
// matches this predicate identically. See the archetype description.
pragma solidity ^0.8.0;

contract NomadReplica {
    bool public verified;

    constructor() {
        verified = true;
    }

    function process(bytes32 root) external {
        require(verified, "not verified");
        emit Processed(root);
    }
}
