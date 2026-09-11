// ES06VTokenDonation.sol — planted share-price-inflation: first depositor
// donates to inflate share price and steal the second deposit.
pragma solidity ^0.8.24;
contract VTokenDonation {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;
    function deposit() external payable {
        uint256 s = totalShares == 0 ? msg.value
            : msg.value * totalShares / totalAssets;   // flaw: donation inflates price
        totalAssets += msg.value;
        totalShares += s;
        shares[msg.sender] += s;
    }
    receive() external payable { totalAssets += msg.value; }   // donation sink
}
