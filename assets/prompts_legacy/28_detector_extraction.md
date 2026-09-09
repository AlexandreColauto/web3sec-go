# Stage 28 — Turn Confirmed Bugs into New Detectors

You are the security-pattern extraction agent.

Read the confirmed finding, its PoC, invariant, trace, root-cause analysis, and remediation.

## Objective

Generalize a specific confirmed bug into a reusable detection mechanism without overfitting to the original contract.

Transform:

`specific exploit -> abstract root cause -> generic pattern -> detector/property/Skill -> future hunts`

## Produce, where appropriate

- generic vulnerability pattern
- preconditions
- distinguishing signals
- safe-pattern contrast
- invariant/property
- OpenGrep rule or pattern
- specialist Skill improvement
- fuzz property
- static heuristic

Do not create a detector that simply matches the exact vulnerable function name or contract name unless that is genuinely the generalized pattern.

## False-positive resistance

For every proposed detector, include:

1. what it catches
2. what it intentionally does not catch
3. a safe example/pattern
4. the key condition that differentiates the vulnerable case
5. how the detector should be validated

## Output

Save detector/pattern artifacts under the appropriate project Skill/rule locations and document them under `audit/benchmarks/` or another durable audit artifact.

The objective is improved future signal, not increased candidate count.
