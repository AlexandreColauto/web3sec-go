# SDD ledger — plan: docs/superpowers/plans/2026-09-21-v16-p1-p2-record-and-evidence.md

Task 0 (P0a): complete (commit be2565a2, controller review — Part 4 quarantine guard)
Task 1: implemented (commit 5bcc168a) — task review pending (retro)
Task 2: implemented (commit 88653b81) — task review pending (retro)
Task 3+4: implemented (commit 5fe665e6) — task review pending (retro)
Task 5-8: implemented in worktree (uncommitted) — task review pending

Task 1: complete (commits 4addbc03..5bcc168a, review clean — spec ✅, quality approved; 4 minors deferred)
Task 2: fix round 1 (2 addressed: C1 artifactIDPattern, I1 recorder gate; commits 5bcc168a..fc03cab0)
Task 2: fix round 2 (1 addressed: unpinned sentinel regression; commits fc03cab0..377ba14a)
Task 3-4: fix round 1 (1 addressed: review_sessions lock + raw unwind; commits 88653b81..fc03cab0)
Task 3: fix round 2 (1 addressed: feed refusal recordability gate; commits fc03cab0..377ba14a)
Task 5-8: fix round 1 (3 addressed: replay help/RUNBOOK, ingest declared-field refusals, exec_ref poc_tier; commits 4b06c114..fc03cab0)

Controller resolutions of "cannot verify from diff" items:
- Task 2 boundary surfaces as used by the feed: resolved — the fix-round re-review verified the real-id and
  recordability paths end-to-end through internal/feed.
- Task 8 origin_stage consumption: resolved — internal/orchestrator/discovery.go:62,65 passes opts.Stage
  into LintHypothesis/IngestHypothesis, so the run path does supply a stage; the feed path passes the drop's
  stem. Task 9's coverage section is the consumer.
- Python-twin byte provenance: PARKED — the twin is not in this tree; the re-record was produced by replaying
  the scenario through dispatchGolden and TestGoldenVectors is green. Nothing further is verifiable here.
- Task 8 idempotent-twin question (step-0 finding 2 keeps origin_stage "11" while its hypo is staged 05):
  PARKED as a product decision — the brief does not cover it and the brief-specified behaviour was kept.
- BountyRemediation: resolved — tasks 5-8 add no gate check.
- Consumers of the new interfaces: resolved — Task 9 (the coverage section) is the designed consumer; it is
  not yet implemented.

Task 9: fix round 1 (2 addressed: chain-materialized population, e2e section pin; commits f854a599..9ff35798)
Task 11: complete (docs/gates/v16-P1.md written; commits f854a599..9ff35798)
Task 10: NOT RUN — operator-run spike (needs Docker + an RPC + a confirmed finding); the gate record says so.
Deferred minors for the final review: task-1-review.md (4), task-2-review.md (4), task-34-review.md (5),
task-5678-review.md (8), task-9-review.md (7).

Final whole-branch review (528b6ae9..9ff35798): fix-then-merge, 0 Critical, 2 Important.
Final fix wave (5630a900): I-1 feed now records the accepted invocation (boundary.LogRequest); I-2 gate record corrected.
Final re-review: clean, 0 open. 28 deferred minors triaged by the final reviewer: 0 must-fix.
Task 9: complete (commits 377ba14a..5630a900, review clean after 1 fix round)
Task 10: NOT RUN (operator-run spike: Docker + RPC + a confirmed finding). Recorded as such in docs/gates/v16-P1.md.
Branch state: all tasks 1-9 + 11 complete; P0a complete; Task 10 outstanding by design.
