# Documentation index

The canonical map of what lives where in this repository's documentation, and what a
reader should pick up for a given question. **If you add a document, add it here.**

Last compacted: 2026-09-23 (96 files / 2.17 MB of port-era process archaeology collapsed
into `docs/archive/PORT-ERA-DIGEST.md`).

---

## 1. Start here

| question | read |
|---|---|
| What is this project, and how do I run it? | [`README.md`](../README.md) |
| What is it, what is it moving toward, what is unproven? | [`docs/REVIEW-BRIEF.md`](REVIEW-BRIEF.md) — the external-review brief |
| What is being worked on right now? | [`docs/gates/v16-prompt.md`](gates/v16-prompt.md) — the current phase: laws (§2), the ledger (§3), the work queue (§5) |
| What is the product specification? | [`framework-plan-v1.6.md`](../framework-plan-v1.6.md) — decisions D1–D9, the 14 stages, severity, C5–C9 |
| How do I operate the tool? | [`assets/runbook/RUNBOOK.md`](../assets/runbook/RUNBOOK.md) — every command, asserted by `scripts/runbook-walkthrough.sh` |
| What should an agent working in this repo know first? | [`assets/runbook/AGENT_BOOTSTRAP.md`](../assets/runbook/AGENT_BOOTSTRAP.md) |
| What has already been tried, and what did it cost? | [`LEARNINGS.md`](../LEARNINGS.md) — the durable lessons ledger |
| What is the threat model? | [`SECURITY.md`](../SECURITY.md) |

## 2. The plan of record

| document | role |
|---|---|
| [`docs/IMPROVEMENTS.md`](IMPROVEMENTS.md) | the wave ledger: what landed, with commit shas (waves A–R, the parked K, and the production-readiness wave). 5,236 lines — navigate by heading, not end to end |
| [`docs/CRITICAL_HUNTING_PLAN.md`](CRITICAL_HUNTING_PLAN.md) | the strategic gap analysis: six structural causes and a six-wave plan for finding criticals. **Its §2 numbers are stale at HEAD — re-measure before citing** |
| [`docs/LEANNESS_REVIEW.md`](LEANNESS_REVIEW.md) | the wave-F leanness review: what the port left behind and why the rest stayed |
| [`docs/gates/`](gates/) | per-phase gate reports. `P0…P4` are the port cutover; `v16-*` are the current phase |
| [`docs/sdd/v16-recon/`](sdd/v16-recon/) | the spec-versus-code audit, line by line (EXISTS / PARTIAL / ABSENT, with `path:line` evidence). **27 commits stale at the time of writing** |
| [`docs/sdd/v16-p0/`](sdd/v16-p0/), [`docs/sdd/v16-p1/`](sdd/v16-p1/) | the v16 task briefs, reports and adversarial reviews |

## 3. The prover lane

| document | role |
|---|---|
| [`docs/MINICERTORA_ARCHITECTURE.md`](MINICERTORA_ARCHITECTURE.md) | the proof loop: control plane / auto-prover / verifier, and what landed (§9 landing notes win over the prose) |
| [`docs/MINICERTORA_INTEGRATION.md`](MINICERTORA_INTEGRATION.md) | the operator guide: install, trust rails, the verified end-to-end loop, troubleshooting |
| [`docs/MINIPROVER_INTEGRATION.md`](MINIPROVER_INTEGRATION.md) | the host contract: what webv2 may assume about the auto-prover, what it must refuse |

## 4. Frozen history (read only to trace a decision)

| document | what it holds |
|---|---|
| [`docs/archive/PORT-ERA-DIGEST.md`](archive/PORT-ERA-DIGEST.md) | **the compaction target**: §I the Go rewrite design · §II the 2026-09-17/18 trust-boundary-hardening trail (rulings, F1 race derivation, the step-12 count ruling, every defect disposition) · §III the gold-findings closure trail · §IV the 21 closed wave plans, the cross-plan laws, the contradiction register and the deferral/refusal register |
| [`docs/archive/KNOWN_DIVERGENCES.md`](archive/KNOWN_DIVERGENCES.md) | every intentional divergence from the retired Python twin, with What/Why/Golden/Unblocks |
| [`docs/archive/python-twin-issues.md`](archive/python-twin-issues.md) | the twin-issue log from the port era |
| [`docs/archive/testmap-2026-09.json`](archive/testmap-2026-09.json) | the Python→Go test accounting map (1,378 rows) |
| [`docs/feedback-triage.md`](feedback-triage.md), [`-morph-r2`](feedback-triage-morph-r2.md), [`-morph-r3`](feedback-triage-morph-r3.md) | what the three real campaigns taught the framework, and which claims were refuted |
| [`docs/runbook-go-notes.md`](runbook-go-notes.md) | the RUNBOOK substitutions the Go binary needs (port-era history) |
| [`docs/RoundingAudit.md`](RoundingAudit.md), [`docs/eval-methodology.md`](eval-methodology.md) | the rounding audit; the claim-intake rubric for external numbers |
| [`docs/eval/`](eval/), [`docs/minicertora-eval/`](minicertora-eval/) | eval protocols and run artifacts |

## 5. What was removed, and why

On 2026-09-23, 96 files (2.17 MB) of port-era process archaeology were collapsed into
`docs/archive/PORT-ERA-DIGEST.md`:

| removed | count | why |
|---|---|---|
| `docs/sdd/*.md/*.txt/*.log` (top level) | 48 | the 2026-09-17/18 task trail: implementer reports, adversarial reviews, the rulings ledger, and re-runnable command logs. The port is closed; the durable claims are in digest §II |
| `docs/sdd/gold-plan/**` | 26 | the 2026-09-18 gold-findings closure trail → digest §III |
| `docs/superpowers/plans/2026-09-0*…09-20` | 21 | closed wave plans → digest §IV (the three `2026-09-21-v16-*` plans are live and stay) |
| `docs/superpowers/specs/2026-09-07-go-rewrite-design.md` | 1 | the port design → digest §I |

**Nothing was lost**: the full text of every removed file is in git history
(`git show <removal-commit>^:<path>`), and every durable claim — measured numbers, commit
shas, operator rulings, refusals, laws, defect dispositions — was preserved in the digest
rather than paraphrased. Frozen gate reports written before the removal still cite the old
paths; those citations are historical and were deliberately not rewritten. Live code
comments that cited a removed path were re-pointed (the table is in the digest header).

Untouched by the compaction, deliberately: everything under `docs/sdd/v16-*`,
`docs/gates/v16-*`, the three live v16 plans, `docs/archive/` (except the new digest),
`LEARNINGS.md`, `assets/runbook/**`, and the two untracked research essays at the root.

## 6. Conventions for new documents

1. **One canonical home per fact.** If a fact already lives in a document, link to it
   instead of restating it (the duplication register in the digest §IV lists the clusters
   that have bitten us: the control-target facts, the standing laws, the exit-code
   contract, the class count).
2. **A document that records a decision names its evidence.** "Measured, or refused with a
   recorded reason" applies to prose too.
3. **Frozen documents are frozen.** Gate reports and triage records are historical
   artifacts; correct them in place only when they contain a *false claim*, and say so.
4. **Live documents are listed in §1–§3 above.** Everything else is history.
5. **Large append-only ledgers** (`IMPROVEMENTS.md`, `LEARNINGS.md`) grow at the end; a
   reader navigates by heading.
