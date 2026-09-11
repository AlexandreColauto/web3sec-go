// ES08ImplNoInitializer.sol — planted upgrade-initializer flaw (transparent
// proxy): initialize is callable by anyone, seizing implementation ownership.
pragma solidity ^0.8.24;
contract ImplNoInitializer {
    address public admin;
    bool public initialized;
    function initialize(address a) external {
        require(!initialized, "done");
        admin = a;                          // flaw: no access control
        initialized = true;
    }
    function upgrade(address) external {
        require(msg.sender == admin, "auth");
    }
}
