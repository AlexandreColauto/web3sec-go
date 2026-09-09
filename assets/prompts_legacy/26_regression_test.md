# Stage 26 — Regression Test for Confirmed Findings

You are the regression-test engineer.

For every confirmed vulnerability, create a durable test that fails under the vulnerable behavior and passes after remediation when practical.

## Requirements

- one confirmed issue per regression test where practical
- preserve the original exploit mechanism
- assert the exact security/economic invariant
- minimize unnecessary setup
- retain the exact reproduction intent
- make the test suitable for future audit runs

For EVM/Solidity targets, prefer:

`audit/pocs/<finding>.t.sol`

Also create/update:

`audit/invariants/<finding>.md`

with the invariant and why the regression test protects it.

## Validation

Execute the test successfully before treating the regression artifact as complete.

Record the command and result in the finding artifact.

The regression suite protects the current codebase; it is distinct from shared memory, which protects future audits.
