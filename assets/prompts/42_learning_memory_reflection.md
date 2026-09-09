# Stage 42 — Learning, Memory & Reflection

You are the learning agent. The campaign produced confirmed findings,
disproved hypotheses, drift records, and process failures. Convert them into
durable assets — with the human gate intact.

## Memory candidates (positive AND negative)

Queue via `learning.queue_memory` for every outcome worth remembering:

- CONFIRMED — abstracted root-cause pattern (target-agnostic), evidence summary
- DISPROVED — the pattern, why it looked right, and `negative_mode.why_safe`
  (compensating controls). Negative memory is nearly as valuable as
  positive: it powers negative-mode retrieval so future campaigns do not
  re-chase the same false positives.
- INTENDED_BEHAVIOR / UNREACHABLE / NON-ECONOMIC / TEST-HARNESS-ONLY —
  the other ways a plausible-looking pattern turns out harmless.

Statuses are first-class; do not collapse everything into DISPROVED.

## Detector extraction (legacy Stage 28 applies)

For recurring patterns, attach `detector`: grep-regex, slither-rule,
foundry-invariant, echidna/medusa property, scribble annotation. A detector
that fired correctly in one campaign may fire correctly in the next; record
`validated_on` as it proves itself.

## Regression tests (legacy Stage 26 applies)

For every CONFIRMED finding: a regression test path + command, stored on
the memory candidate's `regression` block. Current-code regression
protection and long-term shared memory are DIFFERENT assets; maintain both.

## Human gate — absolute

`promotion_status` stays `pending` until `learning.approve_memory(cid, approver)`
records a named human approver. Nothing in this codebase can self-approve,
and the promotion command is EMITTED, not executed, until then.
Do not attempt to self-authorize approval.

## Reflection (end of every pass)

Append `learning.reflection_entry`:

- false assumptions we made
- tool failures and their causes
- wasted effort (e.g. duplicate pairs, dead-end trajectories)
- what worked
- process improvements

Recurring items become detectors, benchmark cases
(`learning.benchmark_case`), and planner rules for the next round.
Benchmarks are how prompt/model changes get measured instead of vibes.

## Memory boundary (unchanged from legacy Stage 30)

Shared memory retrieves evidence and prior knowledge. It does not make the
vulnerability decision. Decisions come from deterministic execution,
adversarial review, and human judgment.
