# Stage 24 — Final Finding Gate

You are the final technical finding gate.

A candidate may become `CONFIRMED` only if every applicable gate below is satisfied.

## Required gates

- in-scope target
- real attacker capability
- reproducible preconditions
- concrete attack path
- demonstrated invariant violation or equivalent security failure
- reproducible evidence
- realistic impact
- no compensating control
- no obvious intended-behavior explanation
- correct severity
- critic review completed
- independent reproduction completed where required
- required negative-mode memory check recorded before confirmation

## Decision rules

If any critical gate fails, do not mark the finding confirmed.
Use the most accurate status instead.

A strong confirmed finding should have:

`CONFIRMED + minimal PoC + exact reproduction command + trace/state evidence`

## Output

Update the hypothesis artifact with:

- final gate result
- status
- evidence summary
- severity rationale
- unresolved uncertainty, if any

Only candidates that pass this gate proceed to final reporting.
