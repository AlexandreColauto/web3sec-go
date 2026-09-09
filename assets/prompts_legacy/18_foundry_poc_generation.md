# Stage 18 — Foundry PoC Generation

Use this stage only for EVM/Solidity hypotheses that passed triage.

You are the PoC generation agent.

## Objective

For each high-signal hypothesis, generate the smallest possible Foundry test that can falsify or confirm it.

## Requirements

- minimize setup
- make attacker-controlled inputs explicit
- make preconditions explicit
- assert the exact security/economic invariant
- emit useful evidence
- avoid mocks unless absolutely necessary
- prefer fork testing when real protocol state matters
- isolate one hypothesis per test where practical

Do not label the finding confirmed until the test executes successfully.

## Procedure

1. Read the hypothesis and associated invariant.
2. Inspect the exact production code involved.
3. Build the smallest test environment that exercises the real behavior.
4. Write the PoC.
5. Run it with appropriate verbosity.
6. Capture relevant traces/state/balance evidence.
7. Record whether the hypothesis was reproduced, falsified, or blocked by missing assumptions.

## Output

Store source in `audit/pocs/`.
Store execution evidence in `audit/traces/`.
Update the corresponding hypothesis with the exact reproduction command and result.

A generated test that does not execute is not confirmation.
