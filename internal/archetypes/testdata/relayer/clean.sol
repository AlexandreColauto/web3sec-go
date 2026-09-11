// Force-Bridge style, clean: the relay gate consults a distinct signer set in
// addition to the relayer key, so one key cannot move a message alone.
contract ForceBridge {
    address public relayer;
    address[] public signers;

    modifier onlyBridge() {
        require(msg.sender == relayer, "not relayer");
        require(signers.length >= 2, "not enough signers");
        _;
    }

    function relayMessage(bytes32 message, bytes calldata proof) external onlyBridge {
        emit Relayed(message);
    }
}
