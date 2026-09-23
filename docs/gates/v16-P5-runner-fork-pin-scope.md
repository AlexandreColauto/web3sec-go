# P5 — the runner-level fork pin: scope

**Justified, not built.** This is a scope, not an implementation. Nothing here is claimed to work.

## The justification: silent pruning

A pruned node answers `eth_getCode` for a contract it no longer holds with `0x` — the same answer
it gives for an address that never had code. The two states are indistinguishable from the
client's side, and the failure is **silent**: the call succeeds, the response is well-formed, and
a harness reading it concludes the contract was not deployed yet.

That is the whole argument, and it is narrower than the one that was corrected earlier. The claim
is **not** that "no archive endpoint works" — endpoints change, and a statement about a provider's
retention policy ages badly. The claim is that **a fork run cannot tell, from inside the run,
whether the state it just read was real or pruned away**, and no amount of endpoint quality fixes
that, because the wire format does not distinguish the two answers.

This is the same class of defect the fork pin already exists for, one layer down. The pin was
built because a commit says nothing about which chain state was forked, and because forge's
`createSelectFork` silently beats `--fork-block-number` — so the height a run *asked for* is not
the height it *got* (`docs/gates/v16-P0-control-target.md` §3.1, three months apart). The pin
fixed the **height**. It does not fix the **state at that height**, and pruning corrupts the
second while leaving the first perfectly correct.

## What already exists, so the scope does not re-propose it

`internal/regression/forkpin.go` already carries the chain-side half of a run's pin:

- `ForkObservedSpec{Block, Source, ReportedBy, Reason, EndpointHost}`;
- `DeriveForkBlock(output)`, which reads the height out of the harness's **own output**
  (`(block: N)`) and refuses output that reports none or two different heights;
- three sources — `derived` / `declared` / `absent` — where `declared` always carries a reason
  for not being derived and `absent` refuses to fall back to the requested value;
- `checkEndpointHost`, which requires the endpoint to be a **host** (optionally `host:port`).

Nothing in it mentions pruning, archive state, or availability. `checkForkObserved` validates how
the height came to be known and where it was read from — not whether the state at that height was
ever there. That is the gap.

## What a runner-level pin would add

The distinction is **where the check happens**. Today's pin is a *record*: it is written after the
run and validated when read. A runner-level pin is a *precondition*: the runner refuses to start,
or refuses to accept the result, when the endpoint cannot demonstrate the state.

Candidate shape, deliberately not decided here:

1. **A state probe before the run.** For each address the run depends on, read `eth_getCode` at
   the pin's block and require non-empty. Empty is then a **refusal**, not "not deployed yet".
2. **A negative control.** Probe a known-deployed address from the same block. If the probe's own
   control comes back empty, the endpoint cannot serve that height at all, and the run is refused
   for that reason instead — which separates "pruned" from "wrong block" and from "wrong chain".
3. **A recorded outcome on the pin.** The pin gains the probe's result, so a later reader can see
   whether the run's state was demonstrated or merely assumed — the same discipline the height
   already follows, where an asserted height must carry a reason.

The probe is the load-bearing part and the control is what keeps it honest: without a negative
control, an endpoint that returns `0x` for *everything* looks like a clean, undeployed chain.

## Why it is a scope and not a build

- **The endpoint is not ours.** A runner-level pin's cost is a probe per address per run, and the
  public tier already rate-limits: the 10b spike drew `HTTP error 429 … exceeded its requests per
  second capacity` on 5 of 73 failures in one suite run. A precondition that fails on rate limits
  is worse than no precondition, so the design has to say what a 429 means — refuse, or retry, or
  degrade to `absent` with a reason — and that is a decision with real consequences.
- **It interacts with `ForkAbsent`.** If the probe cannot run, the pin already has a vocabulary
  for "nothing is known about this height": `absent` with a reason. The scope should decide
  whether an unprobeable state is `absent` (recorded, run proceeds) or a refusal (run stops), and
  those are different claims.
- **No target is blocked on it.** 10b is off the CONFIRMED path and `extractable_usd` is refused;
  nothing in P0 or P1 waits on this pin.

## Acceptance criteria, if it is built

- A run against an endpoint that cannot serve the pinned block is **refused**, with the reason
  distinguishing "the endpoint returned empty for the control address" from "the target address
  is empty".
- A run whose probe succeeded records that fact on the pin, so a reader can tell a demonstrated
  state from an assumed one.
- A 429 or transport failure is recorded as a named outcome, never silently treated as "empty".
- Tests run offline against a stub endpoint; no test requires a live RPC.
