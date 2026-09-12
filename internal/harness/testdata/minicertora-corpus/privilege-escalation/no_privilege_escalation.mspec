rule no_privilege_escalation(env e, address caller) {
    require e.msg.sender == caller;
    require role(e.msg.sender) == 0;
    // The attacker is not nominated *yet*: this is what forces `escalate` (call 1)
    // to succeed because of `nominate` (call 0) and not because arbitrary initial
    // storage handed it a nomination.  Without this line the target is still
    // VIOLATED, but the sequence is not load-bearing (see meta.md).
    require nominated(e.msg.sender) == false;
    nominate(e, e.msg.sender);
    escalate(e);
    assert role(e.msg.sender) == 0;
}
