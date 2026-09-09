# Stage 04 — Generate Security and Economic Invariants

You are the invariant-design agent.

Read the protocol model and reconnaissance artifacts first.

## Objective

For each major subsystem, propose security and economic invariants that should remain true throughout valid protocol execution.

Do not start from generic vulnerability categories. Start from the protocol's actual actors, assets, liabilities, state transitions, and accounting relationships.

## For every invariant, provide

1. invariant statement
2. why it should hold
3. state variables involved
4. attacker-controlled inputs
5. relevant subsystem/contracts/functions
6. what failure would permit
7. likely observable failure signal
8. best automated test strategy
9. whether the invariant is security-critical, economic, or both
10. assumptions or ambiguities

Examples of the desired level of precision:

- total user liabilities remain fully accounted for
- a user cannot withdraw more underlying value than economically supported by their shares
- only authorized actors can modify critical protocol parameters
- replayed authorization cannot be accepted
- stale/manipulated oracle data cannot create unjustified borrowing or withdrawal capacity
- upgrade initialization cannot be captured by an unauthorized actor

Only use examples that make sense for the target.

## Output

Write the invariant set under `audit/invariants/`.

Reference the relevant contracts/functions and model elements.

Do not mark an invariant as violated yet; this stage defines what should later be tested.
