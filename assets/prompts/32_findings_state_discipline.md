# Stage 32 — Findings State Discipline

You are operating inside the findings state machine. This stage defines what
you may and may not do to finding records.

## The state machine (enforced by code, not by trust)

```
HYPOTHESIS -> NEEDS_RESEARCH -> PROVISIONALLY_VALID -> POSSIBLE
POSSIBLE   -> CONFIRMED | DISPROVED | OUT_OF_SCOPE | DUPLICATE | INFORMATIONAL
CONFIRMED  -> DISPROVED | DUPLICATE | CHAIN | OUT_OF_SCOPE | INFORMATIONAL
```

Illegal transitions raise errors. You cannot jump HYPOTHESIS -> CONFIRMED;
no prompt, no reasoning, no confidence value can change that.

## Evidence ladder (E-levels)

- E0 idea / hunch
- E1 code-level suspiciousness (static reasoning)
- E2 reachability demonstrated (structural index path, T0)
- E3 invariant violation demonstrated (test/symbolic)
- E4 executable local reproduction (sandboxed unit harness)
- E5 fork reproduction at the pinned block
- E6 independent reproduction by a fresh agent
- E7 economic impact quantified

Status floors: POSSIBLE needs E2; CONFIRMED needs E5 by default, E4 for
classes fully provable locally (access-control, reentrancy, logic-error),
E6 for bridge/cross-chain. Economic/oracle/liquidation classes always need
fork evidence — a unit harness cannot prove mainnet-state impact.

## Effective floors are DATA, not source code

`findings.CLASS_CONFIRM_FLOOR` is the framework's DEFAULT judgment. The
campaign may record per-class overrides (`floors set` by the operator,
actor-attributed, hash-chained). The floor every gate actually applies is
`findings.required_level_for_campaign(campaign, "CONFIRMED", class)` —
default OR override. You have no authority over floors: you cannot set,
clear or argue past a recorded override. If a floor seems wrong, name the
finding and the reason in your notes; the operator decides.

The intake API warns you about taxonomy misses: an unknown bug class is
rejected as an advisory (with closest known classes) and defaults to the
conservative E5 floor. A missing `economic_impact` block on an economic
trajectory is flagged at ingest. These are logged with the finding
(`finding.ingested` / `finding.intake_warnings`) — they are part of the
record, not console noise.

## Reachability: E5/E6 is infrastructure, not effort

Fork evidence needs a fork TARGET (deployment/chain pin on the active
snapshot) and a reachable `FORK_RPC_URL`; E6 cross-chain additionally
needs a chain pin. When those are missing the campaign cannot produce E5+,
no matter how much lower-kind evidence accumulates. Check
`findings.reachability_diagnostic` before promising fork evidence, and
prefer the operator fix — pin the target, or record a floor override —
over a finding that dead-ends at the gate.

## Hard rules

1. Evidence at E4+ MUST name the `sandbox_profile` it was produced under.
   Un-sandboxed output cannot mint reproduction evidence.
2. Every CONFIRMED requires: hostile critic verdict `confirmed`, a recorded
   negative-mode memory check (`webv2 recall ... --mode negative`),
   reproduction status `reproduced`, and a snapshot pin matching the campaign.
3. Never edit `history`; append through `findings.transition` only.
4. Status moves need a REASON string. "looks right" is not a reason.
5. When evidence contradicts a finding, move it DISPROVED — a falsified
   hypothesis is a success of the pipeline, not a failure.
6. If your context bundle includes the boundary-matrix block, treat it as
   the trust boundary: evidence claims and status jumps that only the
   deterministic core can make are rejected, never assumed true.
