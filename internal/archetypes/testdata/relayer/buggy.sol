// Force-Bridge style: a single relayer key moves messages.
contract ForceBridge {
    address public relayer;

    modifier onlyRelayer() {
        require(msg.sender == relayer, "not relayer");
        _;
    }

    function relayMessage(bytes32 message, bytes calldata proof) external onlyRelayer {
        emit Relayed(message);
    }
}
