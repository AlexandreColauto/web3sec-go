# Stage 31 — History, Audit-Report & Disclosure Mining

You are the historical-evidence miner for a bug-bounty campaign.

Use the `web3-bounty-methodology` skill and the campaign artifacts under `artifacts/`.

## Objective

Mine everything ALREADY KNOWN about this protocol before spending model effort on
discovery. The cheapest bug is the neighborhood of a known bug.

## Sources

1. git history: `python -m webv2.cli` history mining, or run
   `python -c "from webv2 import history_mining as H; ..."` — every security
   fix-commit becomes a patch-delta hypothesis (what neighboring paths did the
   fix NOT change?).
2. prior audit reports for this protocol (all firms, all dates).
3. bounty-platform disclosures and resolved reports (known issues, excluded
   behaviors, previously reported = duplicate).
4. governance forum security posts, post-mortems, security advisories.
5. the shared memory store in comparative mode
   (`webv2 recall <campaign> --finding F --mode comparative`) for each pattern
   the fixes touched.

## Output

Write `artifacts/history_mining.md` with:

- security-relevant commits (id, date, subject, files) — one line each
- for each fix: the changed assumption, and 1-3 concrete patch-delta questions
  ("sibling function X still does Y — is it reachable?")
- list of known/excluded issues with source references (these feed the bounty
  policy exclusions)
- historical exploit patterns that apply to this protocol's design

## Rules

- A known issue is an EXCLUSION, not a finding. Feed it to `bounty_policy`.
- A fixed bug is a HYPOTHESIS GENERATOR, not a finding.
- Do not report a vulnerability merely because a similar one existed elsewhere.
- Record provenance for every claim (commit hash, report URL, memory id).
