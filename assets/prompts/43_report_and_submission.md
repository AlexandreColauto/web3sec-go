# Stage 43 — Campaign Report & Submission Package

You are the reporting agent. The report is a VIEW generated from the finding
IR — regenerate it, never hand-edit it.

## Generate

    from webv2 import report as REP
    REP.generate(campaign)          # -> campaigns/<id>/report.md

The generated report contains: coverage with explicit UNKNOWN accounting,
confirmed findings (claim / mechanism / sequence / evidence ladder / risk /
bounty gate), materialized chains, dismissed candidates WITH reasons
(negative-mode transparency), and the memory queue with pending approvals.

## Report rules

1. Every number in the report comes from state — recompute, do not estimate.
   The funnel (hypotheses -> deduped -> reviewed -> reproduced -> confirmed
   -> submission-ready) comes from `coverage.update_funnel`.
2. "unknown" is a legitimate status. Unswept contracts are listed as
   unexamined, never as secure. `unknown ≠ secure` appears in the report.
3. Dismissed candidates keep their reasons. A reviewer who cannot see what
   was rejected and why cannot audit the audit.
4. Evidence ladder levels are shown per item — a CONFIRMED finding without
   visible E4+ sandboxed evidence is a bug in the pipeline, and the report
   should make that impossible to miss.
5. Chains show their evidence floor: the chain is only as strong as its
   weakest member's evidence.

## Submission package (per submission-ready finding)

- title + severity per policy rules
- the markdown view of the finding IR (claim, mechanism, sequence)
- minimal PoC + exact reproduction command + forge version + pinned block
- balance-delta evidence and trace references (EXEC ids)
- economic impact: max_loss AND extractable, with the block used for
  liquidity measurement
- invariant violated (INV-###) and how the PoC demonstrates it

## Before submitting (human checklist)

- re-read the actual program page: known issues, exclusions, severity floors
- confirm the finding is against the DEPLOYED code (deployment pin verified)
- confirm the PoC runs from a clean checkout at the pinned commit + block
- confirm no compensating control was missed (hostile critic reasoning)
- one report per root cause; do not spray variants of the same bug
