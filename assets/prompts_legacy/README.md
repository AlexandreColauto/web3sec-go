# Qwen Bug-Bounty Prompt Pack

These prompts are designed to be pasted into the local Qwen/DeepSeek Harness session **one stage at a time**.

They assume the repository setup and initial environment work described in the runbook has already been completed.

## Operating rule

Do not paste the whole pack at once. Run the prompts sequentially and let the artifacts in `audit/` become the persistent state of the investigation.

The normal progression is:

`recon -> protocol model -> invariants -> specialist passes -> hypotheses -> deterministic validation -> critic -> reproduction -> finding gate -> report -> regression -> memory/detector`

## Chain gating

Prompt `01_protocol_reconstruction.md` determines whether the target is EVM/Solidity, Starknet/Cairo, or mixed.

Prompts that explicitly mention Foundry, Slither, Aderyn, Echidna, Medusa, Halmos, Scribble, or Pashov Solidity tools are intended for the relevant EVM/Solidity subsystem. Do not force EVM tooling onto a Cairo-only subsystem.

## Evidence discipline

A memory-recall result is evidence, not a verdict. A weak or empty recall result is inconclusive. Confirmed findings require deterministic evidence and adversarial review.

## Important state rule

Do not overwrite existing artifacts unless the prompt explicitly asks for an update. Prefer creating a new artifact or updating the existing artifact with a revision/history note.
