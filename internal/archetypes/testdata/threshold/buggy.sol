// Harmony-style 2-of-5 bridge: `threshold` is settable, and no require/assert
// anywhere in the contract consults it, so the "2-of-5" claim is decorative.
contract HarmonyBridge {
    address[] public owners;
    uint256 public threshold;
    address public owner;

    function setThreshold(uint256 t) external {
        threshold = t;
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
