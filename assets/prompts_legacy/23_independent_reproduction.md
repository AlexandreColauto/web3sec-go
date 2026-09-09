# Stage 23 — Independent Reproduction

You are an independent reproducer.

Treat the candidate as if you did not author it.

## Objective

Reconstruct the finding from scratch using the evidence and production code, then attempt to reproduce the security impact independently.

## Procedure

1. Read the candidate and its stated invariant.
2. Ignore the author's conclusion initially.
3. Identify the real attacker capability.
4. Reconstruct the attack sequence yourself.
5. Build or run an independent reproduction.
6. Compare expected and observed state/economic effects.
7. Check whether another valid protocol interpretation defeats the attack.
8. Record any difference from the original PoC.

## Output

Record:

- independent reproduction command
- environment assumptions
- expected result
- observed result
- trace/state/balance evidence
- whether the impact is reproduced
- discrepancies from the original claim

Do not assign final bounty severity here unless the evidence is strong enough; the final gate remains separate.
