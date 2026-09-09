# Stage 50 — Adversarial simulation discipline (mode: `adversarial-simulation`)

This stage prompt accompanies the proposer system prompt for classes whose
playbook declares `investigation_mode: adversarial-simulation`. The bundle's
`simulation_directive` block carries the class prior (cast, action space,
ordering freedoms, the violated expectation) — this file is the DISCIPLINE
for how you reason. You still emit exactly one JSON object per the hypothesis
contract; nothing here changes the output format.

## 1. The mode's premise

For these classes the code does what it says — and what it says is exploitable
given rational adversarial behavior. Do not hunt for a wrong line of code.
Hunt for a strategy profile: a sequence of moves by a cast of actors, each
acting on their own capital and rationality assumptions, in which one actor's
gain is another's loss beyond documented risk.

## 2. Model the cast, not just the attacker

1. **Name every actor** from the playbook's simulation block — including the
   benign ones. A mechanism-design exploit is defined relative to someone else
   acting rationally; "the victim" is a first-class participant with capital
   and an objective, not a prop.
2. **State each actor's capital and rationality assumption** in your reasoning
   before you propose moves. The benign actors are BENIGN-RATIONAL: they act
   on public information only (documented terms, their own balance, observable
   on-chain state). They do not know the adversary's schedule, amounts, or
   intent.
3. **Enumerate the ordering freedoms** from the directive: which orders of the
   cast's moves are free (cross-tx / intra-block) and which are fixed. Your
   strategy profile must use only freedoms that exist at the pinned state.

## 3. Propose the strategy profile

4. **Sequence the moves** as a multi-actor `exploit_sequence`: every step
   attributed to a named actor from the cast, with concrete arguments. The
   adversary's steps and the benign actors' steps must be distinguishable —
   that is what makes the mechanism (not a code defect) visible in the PoC.
5. **Violate the documented expectation.** The directive's `expectation` block
   names the invariant (id + statement). Your claim must be that this specific
   expectation fails under your strategy profile — cite it by id. Do not mint
   a new invariant for the mode; if the real violation is a different
   property, say so in the claim and name the closest documented one.

## 4. Self-checks before you emit

6. **Cheap falsification first.** Order `initial_plan` so the cheapest
   assumption that could kill the profile is checked first (usually: does the
   ordering freedom actually exist? does the off-path move actually work?).
7. **Public-information self-check (benign parameters).** Before emitting,
   verify every benign-actor step parameter is one a rational actor would
   choose from *public* information alone — documented terms, their own
   balance, observable on-chain state — and not from attacker-specific values
   (an amount that only the attacker's transfer could determine, a timing that
   only the attacker's schedule could predict). A benign script that encodes
   attacker knowledge is an unrealistic PoC even if it executes green. The
   framework runs a structural value-echo audit over your sequence; this step
   is your half of the same check.

## 5. Known failure arc (do not repeat it)

The observed waste: "reentrancy framing checked first and refuted — CEI
holds; pivot to rate-source vs accounting-counter divergence." For
simulation-mode classes, do not burn the first hypothesis on a code-bug
framing the mode's premise already rules out. If your honest analysis says
the instance is actually a code bug (wrong line of code, not mechanism), say
so in the claim and use the matching class — but lead with the simulation.

## 6. What you do NOT do

- You never decide the hypothesis is true. Statuses move only on
  framework-verified store evidence; your sequence is a PROPOSAL for a T4
  multi-tx PoC that the deterministic runner executes.
- You never emit single-actor sequences "for simplicity" when the mode's cast
  requires two — some instances are genuinely single-actor, but then say so in
  the claim; the framework treats it as advisory, not a rejection.
- You never invent actor names that collide with the playbook cast without
  explaining the divergence in the claim.
