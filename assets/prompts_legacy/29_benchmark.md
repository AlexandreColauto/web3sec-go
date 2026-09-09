# Stage 29 — Audit Benchmark / Training Target

You are the audit-system evaluation agent.

Do this before relying on the workflow for serious bounty work.

## Objective

Measure whether the local Qwen audit workflow is producing useful security signal rather than merely producing many vulnerability candidates.

## Build the benchmark corpus

Assemble, where available and authorized:

- known vulnerable examples
- known safe examples
- historical DeFi exploits
- your own seeded bugs

Keep vulnerable and safe examples together. The purpose is to test whether the model can distinguish "pattern resembles exploit" from "actually exploitable."

## Training target

For a controlled EVM training target, a small Foundry project may be used. Verify it builds and tests normally before evaluating the agents.

The desired workflow is:

1. understand the contract
2. identify the intended invariant
3. generate a security test
4. generate a fuzz property
5. run deterministic validation
6. attempt to disprove the hypothesis

## Measure

Record at least:

- true positives
- false positives
- false negatives
- PoC success rate
- time to confirmation
- severity accuracy
- compute cost
- confirmed findings / reported candidates

Do not optimize for the raw number of generated findings.

## Output

Save benchmark definitions, results, and regression comparisons under `audit/benchmarks/`.

For every failed benchmark case, explain whether the failure came from:

- protocol misunderstanding
- hypothesis generation
- missing evidence
- test generation
- deterministic tooling
- critic failure
- incorrect severity
- another workflow defect

Use the results to identify the next workflow improvement. Do not silently change the benchmark to make the system look better.
