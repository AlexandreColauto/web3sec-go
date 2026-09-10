# Claim-intake methodology (Wave G, G7)

An external claim (tool accuracy, dataset score, benchmark result) may enter
framework DATA — assets, playbooks, prompts, weights — only after surviving
this rubric. Record the trial: every numeric external claim baked into an
asset carries a `provenance` row {claim, source_url, checked_date, verdict,
tier}. `verdict: uncorroborated` is legal but renders in reports. The gate:
numbers without a row enter only as `uncorroborated`.

## Hard kills (one is fatal for the claim as evidence)

1. **No leakage control.** Trained models: no temporal split by deployment
   date, no dedup of near-identical contracts across splits. For LLM claims
   the split must respect the model's PRETRAINING CUTOFF, not just the study's
   own split.
2. **Synthetic labels counted as real.** Injected-bug corpora (SmartBugs,
   SolidiFI style) are pattern labels, not exploitability labels — scores on
   them never mix with real-incident scores in one number.
3. **Contract-level F1 as the unit.** Flagging a whole file can game
   contract-level metrics; demand function/line-level or explicitly discount.
4. **No baseline, or a strawman baseline.** The baseline is the best detector
   FOR THAT CLASS (not "always Slither"), plus trivial floors
   (always-flag / never-flag).
5. **No significance test.** A 1-point F1 delta without a paired test or CI
   is noise.

## Soft failures (down-weight and say so)

6. **No run variance.** LLM detectors reporting one greedy decode are
   unmeasured; require pass@k or multi-seed spread.
7. **No cost accounting.** Token/compute overhead is part of the result
   (a 4x overhead changes the decision).
8. **Secondary-source numbers.** Blog mirrors of a standard (content farms)
   don't count; re-verify against the primary page and cite THAT.
9. **Edition/version drift.** Figures must cite the edition of the standard
   whose incident window they come from (e.g. OWASP SCTop10 2025-edition
   numbers describe 2024 incidents; the 2026 edition restates on 2025 data —
   never blend the two).

## Application points

- `assets/taxonomy/class_weights.json` rows (G2) — validator enforced.
- Playbook/prompt prose citing external numbers — manual check at authoring,
  `provenance` block in the asset where a numeric claim is baked.
- Reports: `uncorroborated` figures render with that word.

*Fixes applied while drafting Wave G (kept as worked examples): the
$953.2M access-control figure belongs to the 2025-edition analysis window;
the 2026 edition is 122 deduplicated 2025 incidents, ~$905M
(https://scs.owasp.org/sctop10/). GMX V1 (Jul 2025, $42M) is a refund-based
cross-contract reentrancy inflating GLP pricing — not flash-loan-mediated
(https://sherlock.xyz/post/gmx-exchange-hack-explained,
https://blocksec.com/blog/gmx-incident-cross-contract-reentrancy-bypasses-a-four-year-old-guard).*
