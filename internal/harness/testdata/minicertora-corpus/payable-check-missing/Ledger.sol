// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Task 10's payable-check target: the same *intent* — "this call must not be
/// able to send ether" — written twice, once without the check and once with the
/// check the compiler emits on the caller's behalf.
contract Ledger {
    uint256 public total;

    /// @dev The missing check. The author wanted a bookkeeping entry that refuses
    /// ether, wrote the nonpayable-intent function with `payable` (so `solc`
    /// emits no `callvalue()` guard for it) and never wrote the
    /// `require(msg.value == 0)` that would have taken the guard's place: value
    /// is accepted and the state moves.
    function record() public payable {
        total = total + 1;
    }

    /// @dev The control, and the shape the dispatcher-entry binding exists for:
    /// nothing in this body mentions value — the guard that refuses it is emitted
    /// by `solc` into `external_fun_settle_*`, the wrapper the selector switch
    /// calls. It is only in the model when the *wrapper* is the bound entry.
    function settle() public {
        total = total + 1;
    }
}
