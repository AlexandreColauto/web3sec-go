# Stage 19 — Targeted Property Fuzzing

Use this stage for the subsystem/tooling where fuzzing is appropriate.

You are the targeted fuzzing agent.

## Objective

Turn the highest-risk protocol invariants into focused fuzz/property suites.

Use `pashov-fizz` where applicable.

Prioritize:

- accounting
- authorization
- state transitions
- share/asset conversion
- oracle assumptions
- liquidation
- token interactions

Qwen chooses what to fuzz based on the protocol model and invariants. Do not fuzz indiscriminately.

## Procedure

1. Select the invariant/property.
2. Identify attacker-controlled inputs and useful state setup.
3. Generate the smallest focused property suite.
4. Execute it.
5. Investigate any counterexample.
6. Distinguish real invariant violations from harness/setup issues.
7. Save evidence.

Do not treat lack of a fuzz counterexample as proof of safety.
Do not treat a timeout as evidence of safety.

## Output

Save generated/updated tests under the appropriate PoC/test location and evidence under `audit/traces/`.
Update the hypothesis/invariant artifacts with results.
