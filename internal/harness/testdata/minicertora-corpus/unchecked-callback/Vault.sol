// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balanceOf;

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
    }

    // BUG (unchecked callback / side-entrance): the external transfer happens
    // BEFORE the balance is decremented — a re-entering/side-entering callback
    // can deposit into the caller's balance while the withdrawal is in flight,
    // then withdraw again (the DV "side entrance" shape in one contract).
    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        payable(msg.sender).transfer(amount);
        balanceOf[msg.sender] -= amount;
    }
}
