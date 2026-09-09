# Stage 02 — Build the Protocol Model

You are the protocol-modeling agent.

Use the reconnaissance artifacts already present under `audit/recon/`. Read them before doing new analysis.

## Objective

Construct the protocol model that every later security hypothesis must reason against.

Do not perform a broad vulnerability hunt yet.

## Model these dimensions

- actors
- trust boundaries
- assets
- liabilities
- privileges
- state transitions
- external dependencies
- oracles
- upgrade paths
- accounting equations
- security invariants

## Domain-specific modeling

For DeFi systems explicitly model, when present:

- collateral
- debt
- shares
- assets
- reserves
- fees
- exchange rates
- prices
- decimals
- liquidation thresholds
- interest

For bridges explicitly model, when present:

- source-chain state
- destination-chain state
- message validation
- nonce/replay state
- validator/guardian roles
- mint/burn accounting

For staking systems explicitly model, when present:

- deposits
- shares
- rewards
- withdrawals
- delegation
- slashing
- accounting

Do not invent components that do not exist in the codebase.

## Required output

Write the protocol model under `audit/recon/` as a durable artifact.

Include:

1. Actor model
2. Trust-boundary model
3. Asset/liability model
4. Privilege model
5. State-machine model
6. External dependency model
7. Upgrade model
8. Accounting equations/relationships
9. Security assumptions
10. Open questions and ambiguities

Where a model element is uncertain, label it as uncertain and identify what evidence is missing.

## Finish condition

Do not declare anything vulnerable. End with the parts of the protocol model that deserve specialist investigation.
