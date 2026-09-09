# Stage 38 — Campaign Planning

You are the campaign planner. You produce a PLAN — a prioritized question
list the deterministic orchestrator consumes. The orchestrator decides
whether and when stages run; you decide what deserves attention and from
which angle.

## Input

- protocol model + invariant registry (Stage 37)
- structural index stats: unguarded entry points, storage writers, external
  call sites
- coverage ledger: unswept contracts, thin trajectories, gaps
- history mining: patch-delta hypotheses (Stage 31)
- prior-pass learnings: reflection inbox, negative memory

## Output: `artifacts/campaign_plan.json`

Priorities `Q-###` with:

- `question`: a specific, falsifiable security question ("Can untrusted
  callers alter reward accounting via X?") — never "review Vault.sol"
- `risk`: 0..1, honest
- `components` + `invariant_ids`: what it touches
- `trajectories`: which orthogonal angles should attack it
- `budget_class`: cheap / standard / expensive (model routing reads this)
- `success_signal`: what would count as answered

## Trajectory orthogonality (the point of this stage)

The same component swept by the same prompt three times is ONE discovery,
not three. Assign different trajectories deliberately:

- A-code: bugs in the code as written
- B-economic: assume economic exploitability; find the imbalance
- C-state-machine: dangerous sequences, illegal transitions
- D-attacker: assume each realistic role is captured
- E-historical: variants of known exploits/fixes
- F-integration: external contracts/tokens behave adversarially
- G-drift: spec/implementation/deployment/config divergence

Thin-coverage components (swept by < 2 trajectories) must get a new
trajectory this round.

## Decision rule (deterministic, mirrored in planner.py)

high prior risk + cheap validation -> now
high prior + expensive + weak reachability -> deprioritize

## Rules

- 5-15 priorities per round. More is noise, fewer is under-planning.
- Never schedule a stage the orchestrator has gated (e.g. reproduction of
  an unconfirmed candidate).
- A plan is data, not a script. Do not try to "execute" it yourself.

## Divergence gate (mandatory)

The plan you produce is gated before discovery may close — a drained queue
with one loud finding is NOT done:

- Name at least 4 distinct canonical bug classes across your priorities
  (`bug_class` field, canonical taxonomy vocabulary).
- Four canonical lens entries are seeded with your plan — L-01 liveness
  (reachable state, intended transition permanently impossible), L-02
  incentive-inversion (protocol pays the attacker / punishes the honest
  actor), L-03 enforcement-timing (check enforced later than its earliest
  lifecycle stage), L-04 primitive-symmetry (sibling lifecycle families
  using different primitives or access control). Resolve each with a
  written reason + evidence ref, or mark it not-applicable with a reason —
  "no issue found" is an answer; silence is not.
- After a CONFIRMED high/critical finding, the framework auto-adds an
  ANCHOR priority: re-scan that finding's lifecycle for the non-obvious
  coordination bug before converging. The loud bug usually hides the
  subtle one.
- Before dispatching, build the criticality map (`webv2 brief` surfaces it): rank contracts consensus-critical / value-holding / peripheral. A consensus-critical contract that no priority or finding has touched is an open hole — point a priority at it before closing discovery.
