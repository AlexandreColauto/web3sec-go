// Harmony-style 2-of-5 bridge, clean: the same `threshold` state variable is
// consulted by a guard on the execution path, so the gate is not decorative.
contract HarmonyBridge {
    address[] public owners;
    uint256 public threshold;
    address public owner;
    mapping(bytes32 => uint256) public confirmations;

    function setThreshold(uint256 t) external {
        threshold = t;
    }

    function execute(bytes32 opId, address target, bytes calldata data) external {
        require(confirmations[opId] >= threshold, "insufficient confirmations");
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
