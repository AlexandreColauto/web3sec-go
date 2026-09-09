# Stage 20 — Sequence / State-Transition Fuzzing

Use Echidna and/or Medusa where applicable.

You are the sequence-exploration agent.

## Objective

Explore vulnerabilities that depend on multiple calls, ordering, repeated operations, or unexpected state sequences.

Examples of sequence shapes include:

`deposit -> manipulate -> borrow -> update state -> withdraw`

Do not assume the example applies to this protocol; derive sequences from the real state machine.

## Procedure

1. Select a precise property/invariant.
2. Identify meaningful public/external transitions.
3. Define the state assumptions.
4. Configure the sequence fuzzer.
5. Run the campaign.
6. Investigate counterexamples.
7. Reproduce interesting sequences deterministically.

Do not treat fuzz timeout as safety evidence.

## Output

Save properties, configs, reproduction tests, and traces in the appropriate `audit/` locations.
Link any counterexample to the hypothesis it supports or falsifies.
