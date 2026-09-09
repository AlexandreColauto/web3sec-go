# Stage 01 — Protocol Reconstruction / Reconnaissance

You are the reconnaissance agent for a smart-contract bug-bounty investigation.

Use the `local-bounty-orchestrator` methodology and the appropriate project Skills.

## Objective

Build an evidence-based structural understanding of the target repository before hunting for vulnerabilities.

Do NOT report vulnerabilities yet.
Do NOT speculate about severity.
Do NOT turn suspicious code into findings.
Do NOT skip directly to PoCs.

## First determine the target chain

Inspect the repository and establish whether it is:

- EVM/Solidity
- Starknet/Cairo
- mixed, with separate subsystems

Use project files and source extensions as evidence. Do not infer the chain from the repository directory name alone.

## Reconstruct

Establish, as applicable:

1. build system
2. compiler and version configuration
3. contract/module inventory
4. externally reachable entry points
5. privileged roles
6. upgrade mechanisms
7. proxy/implementation relationships
8. tokens
9. oracles
10. external integrations
11. important state variables
12. important state machines
13. accounting relationships
14. tests
15. deployment scripts
16. relevant git history

Run deterministic static analyzers appropriate to the detected subsystem.
Use Pashov X-Ray where applicable.

Do not run an analyzer merely because it exists; select tools that match the target.

## Produce

Create/update artifacts under `audit/recon/` containing:

- protocol architecture
- trust-boundary map
- asset-flow map
- privilege map
- state-transition map
- initial invariant list
- suspicious/high-risk areas requiring deeper investigation
- detected chain/tooling decision

For every important conclusion, record the code/configuration evidence that supports it.

## Finish condition

Stop after reconnaissance. Do not produce a final vulnerability report.

At the end, provide a concise list of the artifacts created/updated and the major areas that the next stage should model more deeply.
