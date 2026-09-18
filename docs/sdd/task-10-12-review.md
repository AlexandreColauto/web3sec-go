# Phase C Independent Review — Tasks 10, 11, 12

- **Reviewer:** independent read-only review (qwen3.8-flash reviewer lane, per plan Global Constraints)
- **Range:** `eb44603a..1a03c8ca` — `cbdd93d5` (Task 10), `c15a1291` (Task 11), `1a03c8ca` (Task 12)
- **Worktree:** `.worktrees/production-readiness` (clean; review artifacts under `.scratch/` only, untracked)
- **Method:** full diff read line-by-line; static verification of every claim below from the diff and
  surrounding code; `oracles.json` re-pin verified programmatically (before/after JSON parsed and
  walked). `go test` could not be re-run in this sandbox (read-only module cache); gate evidence was
  taken from `.scratch/sdd/task-10-12-{full-test,vet,golden,runbook}.txt`, which are internally
  consistent (full suite ok, VET/GOLDEN/RUNBOOK EXIT 0, 150 passed / 0 failed).

---

## Task 10 — open questions compile into the work queue (`cbdd93d5`)

**Spec compliance: PARTIAL** (queue half YES; "brief shows it" NO). **Quality: APPROVED WITH FINDINGS.**

What the diff delivers:

- `planner/plan.go` `bootstrapOpenQuestions` runs last in `DefaultPlanFromModel` (after roles), so
  pre-existing Q-numbers are byte-stable. It skips `resolved`, empty-text, and reference-free
  entries; `openQuestionRefs` reads `blocks` then the tolerated `applies_to`, deduped in declaration
  order → deterministic minting.
- Minted rows are risk 0.9 / `budget_class cheap` → `DecisionRule(0.9,"cheap")` = `now` slot
  (verified in `queue.go:16`). Every pre-existing row still gets its slot through the same rule.
- Supplied plans are never rewritten: `resolvePlan` returns an explicit plan untouched and
  `writePlan` never calls the bootstrap; the Task 12 orchestrator test drives an operator-authored
  plan through `Plan` and no `resolve open question` row is minted. ✓
- Empty / reference-free queue: `TestNoOpenQuestionsLeavesQueueUnchanged` proves the reference-free
  model's queue is row-for-row identical to the empty-list model's queue through the real `Plan`
  verb. Combined with untouched golden pins (no pin change in this commit) this satisfies the
  no-op law. ✓
- Red→green evidence honest: `task-10-red.txt` shows the witness failing with no
  `resolve open question` row; probe (`task-10-brief-probe.txt`) shows the minted row ranked **#1**
  of the whole queue in a real brief run (top-3 ✓ in the fixture).

### Findings (Task 10)

1. **"brief shows it" is not met — ruled a genuine spec gap, not a reading quibble.** The plan Law
   ends "brief shows it". Verified from the probe and `briefing.go`: the brief contains
   `attention` + `next_actions` only — there is no work-queue section. The open question's text is
   never rendered: `attention.queue.total/untouched` count the row (5/5 in the probe) but
   `attention.lines` names only the oldest untouched priority (`Q-001`). The row is visible via
   `webv2 plan --json` and via the debt counts, which is exactly what the report concedes. The plan
   **Test** ("Plan output contains it ranked in the top 3; empty → unchanged") is met as written;
   the Law clause "brief shows it" is not. The implementer recorded this honestly as a residual
   gap; it should be tracked to closure (either render the row in an attention/next-action line, or
   get an operator ruling that plan-JSON + debt counts satisfy the clause).
2. **Top-3 is emergent, not enforced.** The commit delivers named-component slotting (now-slot +
   additive score), not a top-3 mechanism. With Task 12's slot-class-primary ordering, a campaign
   with ≥3 higher-scoring `now` rows pushes the open question out of the top 3. The fixture and
   probe hold; the law's "ranked in the top 3" is not structurally guaranteed for all campaigns.
   Acceptable (the law's ranking condition is qualitative), but the review question is answered:
   **it is named-component slotting that happens to rank top-3 in fixtures, not a top-3 guarantee.**
3. Minor: the report says the minted risk is "0.8"; the code mints **0.9**. Report inaccuracy only.
4. Minor: plan Files line suggested the fixture live in `port_fixtures_test.go`; a dedicated
   `task10_open_questions_test.go` was used instead. Deviation is benign (better isolation, real
   `Plan` verb driven, model written to the campaign's own `protocol_model.json`).

---

## Task 11 — cold probe surface warning (`c15a1291`)

**Spec compliance: YES.** **Quality: APPROVED.**

- **Signal is the honest one.** `probes.Emitted` scans the ledger for `type == "probes.emit"`;
   verified that `probes/emit.go:159` logs exactly that event on the real `--emit` path. The
   `probe_surface.json` artifact is deliberately not consulted, so a stale artifact can neither
   silence nor fake the warning — matches the Law ("no `probes run --emit` exec exists in the
   ledger").
- **Advisory only — verified, not just asserted.** The line is appended to `next_actions` in
   `briefing.NextActions` and nothing else. Grep across `internal/completion`, `internal/harness`,
   `internal/cli`: no proof, floor, or phase transition reads `next_actions` (the only consumer,
   `cmd_brief.go:390`, renders it). `TestColdProbeWarningDuringDiscovery` additionally asserts the
   brief still reports and the line clears after an emit. No gate/proof/floor reads it. ✓
- **Command-first Task 7 law intact.** The line is `webv2 probes <cid> run --emit  # <reason>` via
   `webv2Action` (command, then `# `, then `noParens(reason)`); the reason carries an em-dash, no
   parentheses; the test asserts the command verbatim and that every action is `webv2 `-prefixed. ✓
- **Phase gate.** Warning only when the brief's phase is `DISCOVERY`;
   `TestColdProbeWarningOnlyDuringDiscovery` pins SCOPE / CAMPAIGN_PLANNING / COMPLETE silence. ✓
- Red→green evidence honest (`task-11-red.txt`: witness fails with the exact action list missing the
  line); independent probe shows the real rendered line. Gates green, no pin changes (correct —
  golden/runbook scenarios aren't in DISCOVERY-without-emit, so no drift).

### Findings (Task 11)

1. Minor doc/behavior mismatch: `probes/campaign.go`'s comment says an unreadable ledger is
   "an error, never a silent 'no': the caller renders it as unknown" — but the caller
   (`briefing.go`) silently **omits** the line on error (`err == nil && !emitted`). The commit
   message for `c15a1291` correctly states "with an unreadable ledger, it stays silent"; the code
   comment in `campaign.go` overstates the caller. Comment-only fix suggested; behavior
   (advisory, fail-silent) is defensible for a non-gate line.
2. Nit: the warning requires `campaign != nil`; a hand-built brief carrying a DISCOVERY phase with
   no campaign object gets no line. Edge case, consistent with `cid` fallback semantics.

---

## Task 12 — additive risk-weighted queue ordering (`1a03c8ca`)

**Spec compliance: YES.** **Quality: APPROVED.**

- **Strictly additive, named constants, ponytail comment.** `queueWeightUntouched = 1.0`,
  `queueWeightSeverity = 2.0`, `queueWeightOpenQ = 1.5`; `queueScore.weight()` is
  `untouched*1.0 + severity*2.0 + openQ*1.5` — no product anywhere; the `ponytail:` comment states
  the additive law and that there is no config key. `queueSeverityBands` is exactly
  critical=3/high=2/medium=1/low=0. ✓
- **Slot class primary, ties alphabetical, deterministic.** Comparator order is slot → weight →
  `priority_id` → `question`; `sort.SliceStable` over a fully-specified key. All lookups
  (`inScope`, `touched`, `severity`, `invSev`, `openQ`) are read by key; no map is ranged; the
  plan's own row order is the last tiebreak via stability. `TestQueueAdditiveRiskOrdering` runs the
  queue 25× and pins identical order. ✓
- **Never multiplicative is tested, not just commented.** `TestQueueScoreIsAdditiveNotMultiplicative`
  forces the exact zeroing case the law warns about (critical invariant, zero untouched, zero
  open questions) and requires it to still lead. ✓
- **Read-back/write-path symmetry.** `planQueueModel` fixes a real defect the commit introduced the
  possibility of: without it, a plan read back with no model argument scored every row zero and
  could reorder against the write. Absent model → empty object; present-but-unreadable model →
  error, never silent zero. ✓
- **oracles.json re-pin confined to work_queue order — verified programmatically.** Parsing
  `eb44603a:` vs `1a03c8ca:` versions: only the `planned` scenario changed, only steps 0/3/6
  (`op=plan`), only the `oracle` field, and inside each oracle only the `work_queue` array's ORDER
  differs — row multisets are identical (same rows, same content). `priorities`, `state`, `events`,
  and `plan_readonly_unchanged` are untouched. The pin reason is in the commit message as the
  Global Constraints require. ✓

### The coverage-ledger read-by-path: sound dodge, verified

- **The cycle is real.** `internal/coverage/zz_r40e_test.go` (in-package test) imports
  `audit/sections` → `completion` → `planner`. If `planner` imported `coverage`, the coverage test
  binary would be an import cycle ("import cycle not allowed in test"). Reading the artifact by
  path is therefore justified, not laziness.
- **The dodge is sound:** `validation.ReadJson` on `artifacts/coverage.json`; missing ledger →
  every in-scope contract untouched (correct cold-start); present-but-unreadable → **error**,
  never a silent re-rank (fail-closed). Rows are keyed by `path`, matching what the writer emits.
- **But it is not hole-free — it imports a drift risk.** `coverageSwept` duplicates the ledger's
  "has this been worked" predicate instead of sharing it, and the copies already diverge at the
  edges vs `coverage.RefreshGaps`: (a) a `status:"swept"` row with **zero** trajectory counts is
  swept-but-thin to coverage but **untouched** to the queue score; (b) `status:"excluded"` with no
  counts is invisible to coverage's gaps but counts as untouched (and therefore high-priority) in
  the queue. Both divergences rank things *higher*, i.e. conservative, and neither can occur in
  ledgers the writer currently produces — but a future coverage-side schema/predicate change will
  not break this reader at compile time. Recommend a small parity pin test (fixture ledger rows →
  assert `coverageSwept` agrees with `RefreshGaps`' classification) in a follow-up.

### Findings (Task 12)

1. Minor: `scoreRow` adds `openQ[ref]` per component, so one question naming two components of the
   same row counts twice (W3 doubled). Defensible reading of "per open question naming them";
   noting for the record.
2. Minor: `touched[path] = coverageSwept(row)` — last row wins if a ledger ever carried duplicate
   paths (the writer doesn't produce them today).
3. Nit: the plan's Files line pointed at `internal/orchestrator`; the sort actually lives in
   `internal/planner/queue.go` (orchestrator delegates to `planner.WorkQueue`). Correct location
   chosen; the deviation from the plan's Files hint is right.

---

## Verdict summary

| Task | Commit | Spec compliance | Quality |
|---|---|---|---|
| 10 — open questions → work queue | `cbdd93d5` | **PARTIAL** (queue law + empty-queue no-op + supplied-plan-untouched YES; "brief shows it" NO — text never rendered in the brief, only plan-JSON/debt counts) | APPROVED WITH FINDINGS (honest residual gap; top-3 emergent not enforced) |
| 11 — cold probe warning | `c15a1291` | **YES** | APPROVED (advisory-only verified; command-first intact; comment-vs-caller mismatch minor) |
| 12 — additive queue ordering | `1a03c8ca` | **YES** | APPROVED (additive law verified incl. anti-multiplicative test; re-pin confined to work_queue order — programmatically verified; read-by-path is a sound, verified-cycle dodge with a documented drift risk) |

**Recommended follow-ups (non-blocking):** (1) close Task 10's "brief shows it" gap or obtain an
operator ruling; (2) comment fix in `probes/campaign.go` (caller stays silent on ledger error);
(3) parity pin test between `coverageSwept` and `coverage.RefreshGaps`' swept semantics.
