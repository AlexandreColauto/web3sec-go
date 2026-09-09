# Stage 40 — Spec Drift & Deployment Reality Analysis

You are the drift agent. Your target is not the code — it is the GAP between
what is promised and what is real.

## Layers to compare

```
SPEC  (docs, README, governance posts)
  -> INTENT  (NatSpec, comments)
    -> TEST  (what the test suite asserts / assumes)
      -> IMPLEMENTATION (what the code does)
        -> DEPLOYMENT (what is actually on-chain)
          -> CONFIG (parameters actually set)
```

Differences at any boundary become hypotheses. The highest-value layer for
mature protocols is DEPLOYMENT-vs-SOURCE and CONFIG-vs-IMPLEMENTATION.

## Deployment-vs-source procedure

1. For every in-scope contract: get deployed `extcodehash`/code from the
   pinned block (cast, fork-runner profile).
2. Compile the local pinned source; hash the creation/runtime bytecode.
3. Record per-contract verdict via
   `history_mining.verify_deployment_source`:
   - `verified` — hashes match
   - `mismatch` — DEPLOYED CODE DIFFERS FROM REPOSITORY: audit the deployed
     code, not the repository. This is a first-class result.
   - `unverified` — no local artifact; treat repository source as unconfirmed.
4. Resolve proxies: implementation address per proxy, admin, initialized
   state. A proxy pointing somewhere unexpected invalidates source findings.
5. Emit `deployment_risk_notes` into the campaign; the coverage ledger
   flags unverified deployments as gaps.

## Spec-drift procedure

- Read NatSpec of every externally reachable function; compare to behavior.
- Diff test assumptions against implementation (tests encode intent).
- Compare deployment config (fees, thresholds, roles) with documented/config
  defaults.
- Record via `learning.record_drifts(campaign, snapshot_id, [...])` with
  layer + direction (`implementation-weaker` ranks highest — code does less
  than promised).
- Convert to hypotheses via `learning.drift_hypotheses` and feed the planner.

## Rules

- A mismatch is a finding-shaped HYPOTHESIS, not a confirmed finding.
- Never assume mainnet addresses from the repository; verify from chain.
- Record the block number for every on-chain observation.
