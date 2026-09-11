// ES11MintInflation.sol — planted donation flaw (obfuscated comments
// axis): the cheerful comments describe a fair mint, but direct donations
// inflate the share price against later minters.
pragma solidity ^0.8.24;
contract MintInflation {
    uint256 public supply;   // total minted shares, always fair
    uint256 public pool;     // matched 1:1 by mints, nothing else enters
    mapping(address => uint256) public shares;
    function mint() external payable {
        // fair pro-rata mint at the current transparent rate
        uint256 s = supply == 0 ? msg.value : msg.value * supply / pool;
        pool += msg.value;
        supply += s;
        shares[msg.sender] += s;
    }
    receive() external payable { pool += msg.value; }   // donations enter here
}
