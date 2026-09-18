# Task 7 review — `brief` next-actions are copyable commands

**Reviewer:** independent, read-only. **Commits:** f837a26a..dae1c42f (single commit `dae1c42f`).
**Verified by running, not by reading:** `go test ./internal/orchestrator -run TestNextActions`,
`go test ./internal/briefing -run TestBriefNextActions`, both green; full focused suites
(orchestrator 1.159s, briefing 0.822s) green; `scripts/golden.sh` → GOLDEN GREEN;
`scripts/runbook-walkthrough.sh` → 150 passed / 0 failed; `go vet` and `gofmt -l` clean on the
touched packages. `git diff f837a26a..dae1c42f -- testdata/oracles.json` → 28 added lines, all
`"oracle"` values (27 next_actions re-records + the file header); no other oracle touched.
A throwaway probe (`cli.Run` on an empty root) confirmed misspelled flags on
memory/rank/mint/verify/gate/index all exit 2 *before* campaign lookup — see §C.
Worktree left clean (probe test file created and deleted; `git status --porcelain` empty).

---

## VERDICTS

**Spec compliance: NO** (qualified — the adjudication in §A is the reason).
**Task quality: FINDINGS** — 1 Critical, 2 Important, 5 Minor. No Critical objection to what
the commit *did*; the Critical finding is about what the rewritten catalog *mints* for one phase.

---

## A. Ruling on the implementer's concern (1): does the law cover briefing.go's own mint?

**Ruling: YES — the plan's law covers briefing.go's own mint, not only the orchestrator's.
The implementer's narrower reading is not supported by the plan text.**

Evidence from the plan (Task 7, verbatim):

1. **Title:** "`brief` next-actions are copyable commands." The subject is the *brief's*
   next-actions list, not one minter.
2. **Law:** "every next-action line is a runnable `webv2 …` command" — unconditional over
   lines, qualified by nothing about which function minted them.
3. **Files:** "`internal/briefing` (or wherever next-actions render — locate via
   `grep -rn "next_action" internal/briefing`)". The plan's own compass points at
   internal/briefing. If only the orchestrator mint were in scope, the Files line and the
   grep hint would not point there.
4. **Test:** "fixture campaign → `brief` output next-actions all match `^webv2 ` and none
   match `\(`." The test is anchored at *brief output* — the union of every minter — with a
   regex (`\(`) that briefing.go's prose lines fail. A law tested at the render boundary
   covers whatever reaches that boundary.
5. **"The plan/replan code that MINTS those strings is the fix site, not the renderer"** —
   read correctly, this clause says *where* to fix a line that violates the law (at its
   minter, not by post-processing in `cmd_brief.go`). It does not carve out which minters
   are exempt. The implementer read it as a scope definition; the text does not say that.

**Do briefing.go's lines contain runnable commands inline (then they'd satisfy "copyable")?**
Only partly, and not enough:

- `internal/briefing/briefing.go:2064` — `"FIX INTEGRITY FIRST (trust issue, …): "` — pure
  prose, contains parentheses. Fails both teeth of the plan's own test regex.
- `briefing.go:2142` — `"work probe row %s — %s: %s (%s)"` — pure prose, parentheses, no
  command at all. Fails both teeth.
- `briefing.go:2152` — `"emit probe row %s — %s: \`webv2 probes %s run --emit\` turns it…"`
  — command embedded mid-prose; the line starts with "emit probe row", not `webv2 `. Fails
  `^webv2 `; copyable only after manual extraction.
- lens routing lines (M6 map, `lensMechanicalTable`, `webv2 enforce %s <cursor-variable>`)
  and `verify INV-…` lines — same shape: command buried after a prose prefix.
- `briefing.go:2479` — `"lens "+lens+" batting average — "+wilson.Format(…)` — pure prose.

So for any campaign with a probe surface, divergence rows, an open invariant, or an
attention lead, `webv2 brief` prints next-action lines that fail the plan's own test. The
plan's Test says "fixture campaign" (singular) and the fixture used is a fresh campaign, so
the literal test passes — but the Test is a *witness* to the Law, and the witness chosen
does not reach briefing.go's mint. The T35-parity-suite obstacle the implementer cites is
real but is not a valid reason to leave law-violating lines: the Global Constraints permit
exactly this — "deliberately update pinned expectations in the same commit with the reason
in the commit message."

**Mitigation credited:** the implementer did not silently skip; concern (1) is flagged in
the report with a "reviewer decision point," the fixture honestly hides the gap, and the
explicitly-named defect (`orchestrator.*` pseudo-API) is fully gone. That is why this is a
spec-compliance NO with a bounded remedy (Task 7b), not a rejected task.

**Remedy:** open Task 7b: convert the briefing.go-minted lines to command-first
(`webv2 …  # reason`) form at briefing.go's mint, re-pin the T35 assertions deliberately
with reasons in the commit body. Alternatively the operator may amend the plan with an
explicit carve-out — but that is a plan change, not a reviewer concession.

## B. Dispatcher-feed test (exit 2 = failure): sound oracle?

**Sound for what it claims, with a documented blind spot the tests do not claim to cover.**

- The contract is real: `internal/cli/cli.go:317-333` — usageError → stderr + exit 2;
  runtime errors (`mapRunError`) → exit 1. Campaign-not-found on an empty root is exit 1,
  so feeding lines against a root with no campaign is side-effect-free and deterministic.
- I probed the false-pass direction directly (untracked throwaway test, deleted after):
  misspelled flags `--approv` (memory), `--rankx` (rank), `--ex` (mint), `--ex` (verify),
  `--explaine` (gate), `--sr` (index) all exit **2 with "unrecognized arguments" before any
  campaign lookup**. So a wrong flag on the minted verbs surfaces as exit 2. The guard's own
  mutation case (`scope --polcy` → exit 2) generalizes across the sampled verbs.
- The blind spot: the oracle proves *parse-shape*, not *work-satisfaction*. A parseable,
  flag-correct line that names the wrong verb for the phase's proof passes — and that is
  exactly how the two semantic findings below (C-1, I-1) shipped. Concrete-fixtures pins
  only SCOPE/SNAPSHOT/CAMPAIGN_PLANNING/REPRODUCTION, so those two phases are unpinned
  verbatim. Fix: extend `TestNextActionsConcreteFixtures` to INDEPENDENT_VERIFICATION and
  RISK_CALIBRATION, and add a comment in `next_actions_cli_test.go` stating the oracle's
  boundary (parses ≠ closes the proof).

## C. The 27-oracle re-pin: deliberate, reasoned, still behavior-pinning?

**Deliberate: yes. Reason in commit body: yes. Still pins behavior: yes, with one caveat.**

- Commit body names the exact path, the 27 snapshots, the scenarios, and the reason
  ("the recorded Python bytes ARE the pseudo-API this task removes"). Satisfies the Global
  Constraint "deliberately update pinned expectations in the same commit with the reason in
  the commit message." `golden_test.go` provenance note follows the existing
  bounty_gate_all/Task-4 precedent. Diff confined to the 27 next_actions oracle values
  (verified mechanically, see header).
- The re-recorded values still pin behavior, not just strings: proof counts are
  state-dependent (`# 17 missing` vs `# 18 missing` across scenarios), the
  proof-holds/missing branch selection is exercised, and the HALTED/COMPLETE open-proof
  ordering (header line, status line, then per-stage proves, capped) is pinned. The loss is
  real but inherent: the old per-item prose ("[discovery missing] Q-001: …") was the
  pseudo-adjacent detail the law deliberately moved to `webv2 prove --stage`, and its
  printout is separately pinned by the completion package.
- Caveat (Minor, acknowledged by the implementer): these 27 snapshots are now Go-authored
  regression pins; a Python-twin regeneration would silently revert them, and the
  golden_test.go note is the only guard. Accepted — there is no better option without
  deleting the snapshots.

## D. The two latent shape-bug fixes: real?

Both are genuine, both fixed at the mint:

1. `webv2 gate explain <check>` → `webv2 gate --explain <check>`: verified real —
   `internal/cli/cmd_gate.go:34` pins `usage: webv2 gate <campaign> [FINDING] | webv2 gate
   --explain <CHECK>`. The old string was not a dispatchable form; the new one is, and the
   `# explain` line parses (exit 2 probe on `--explaine` confirms flag-level checking).
2. ladder slash-joined pseudo-usage → `webv2 ladder <C> start <finding>` +
   `webv2 ladder <C> waive <finding> --reason <reason> --actor <actor>`: verified real —
   `cmd_ladder.go` dispatches `start`/`waive` subcommands with `--reason`/`--actor`
   (lines 370-400); the old "start/add/explore/repro/set-maximal/complete" string was not
   runnable by any parser.

## E. Findings

### Critical

- **C-1 — RISK_CALIBRATION guidance dead-ends: its only minted line cannot advance the
  campaign.** `internal/orchestrator/status.go` (RISK_CALIBRATION case) mints only
  `webv2 rank <C>`, and `webv2 rank` is read-only by its own contract
  (`cmd_rank.go:8-9`: "Read-only: the score is recomputed from recorded fields; nothing is
  written"). The phase's proof (`completion/proofs2.go:108-131`) needs `risk.validated.band`
  per CONFIRMED finding; `risk-calibration` is a deterministic pipeline stage
  (`internal/pipeline/pipeline.go:63`), so the proof-closing command is `webv2 run <C>` —
  the exact pattern every sibling model/deterministic stage phase got
  (PROTOCOL_INTELLIGENCE, HOSTILE_REVIEW, MAXIMAL_EXPLOITATION, INDEPENDENT_VERIFICATION).
  No other emitted line compensates, and no CLI verb calls `CalibrateAll`
  (only `orchestrator.CalibrateAll`, MCP-side). An operator at RISK_CALIBRATION who follows
  the brief can never close the proof. **Fix:** mint `webv2 run <C>` as the first line for
  RISK_CALIBRATION (keep or drop `rank` as informational), re-record the two affected
  oracles deliberately with the reason.

### Important

- **I-1 — INDEPENDENT_VERIFICATION mints `webv2 mint`, but that command cannot close the
  phase's proof.** `status.go` mints `webv2 mint <C> <finding> --exec <EXEC-id>
  --description <description>` for INDEPENDENT_VERIFICATION. The proof
  (`proofs2.go:79-101`) requires `verification.independent_reproduction.status == "matches"`
  with a verifier — set only by `reproduction.MintIndependentEvidence`
  (`reproduction.go:453`, writes the `repro.independent` event), reachable from the CLI
  only via `webv2 verify <C> --finding <f> --exec <EXEC-id> [--verifier V]`
  (`cmd_verify.go:198-199` → `orchestrator.VerifyIndependently`). The old proof detail the
  catalog deleted even said so: "mint with webv2 verify --exec ...". The parse oracle
  cannot catch this (`webv2 mint` parses fine). Mitigation: the entry's first line is
  `webv2 run <C>`, which can run the stage. **Fix:** replace the mint line with
  `webv2 verify <C> --finding <finding> --exec <EXEC-id> --description <description>`
  (match verify's actual required flags); pin the phase in `TestNextActionsConcreteFixtures`.
- **I-2 — the scope gap of §A.** briefing.go's own mint (briefing.go:2064, 2142, 2152,
  lens routing lines, 2479) still emits prose-first next-action lines that fail the plan's
  law and its own test regex for populated campaigns. **Fix:** Task 7b as specified in §A;
  do not re-pin T35 assertions without reason — convert the lines and re-pin deliberately.

### Minor

- **M-1 — DISCOVERY catalog omits `webv2 run <C>`.** Its first line is the informational
  `webv2 plan <C>`; `ingest`/`prioritize` are real work, but no emitted line drives the
  discovery-specialist model stage that the proof (`# 17 missing`) demands. Add
  `webv2 run <C>` to match the sibling model-stage phases.
- **M-2 — MAINNET_FORK_POC line names only `webv2 exec`.** Closing the proof also needs
  `webv2 mint <C> <finding> --exec <EXEC-id> --description <description> --type fork-test`
  (the deleted old detail said exactly this; now it is only visible via `webv2 prove`).
  Both commands are copyable and deterministic — add the mint line rather than relying on
  the prove printout.
- **M-3 — `<same|distinct>` metavariable is a shell hazard if pasted literally** (status.go,
  resolve-candidate line): unquoted `|` in bash starts a pipe. Harmless when substituted,
  but `<same-or-distinct>` costs nothing and removes the foot-gun.
- **M-4 — residual pseudo-API in error strings** (`internal/orchestrator/triage.go:220`,
  `internal/sharedmem/sharedmem.go:385`): correctly out of this task's law (error messages,
  not next-action lines), correctly left untouched; track as follow-up. The triage one is
  oracle-pinned, so fixing it later is a deliberate re-pin like this one.
- **M-5 — `# n missing` comment suffix and the phase-driven staleness (report §8.4/8.5):**
  both are fine. The suffix is a shell comment and the guard does not depend on it; the
  staleness is pre-existing `SetPhase`-on-run behavior. No action needed; noting for the
  record that the copyable list is only as fresh as the phase.

## F. Cannot-verify items

- **Red-run logs** (`.scratch/sdd/task-7-logs/red-*.txt`): the 131-line red output and the
  claim that tests were written before the fix are taken from the report's logs; I verified
  green independently but cannot independently confirm authorship order.
- **The E2E §6 run** (real binary, real campaign, both commands exit 0): plausible and
  consistent with the code, but I did not re-run the operator walk-through on a fresh
  campaign; the automated equivalents (concrete fixtures, parse check, golden) all pass.
- **"Temporary dispatchGolden tooling deleted before commit":** consistent with the diff
  (no tooling file committed) but unverifiable from history alone.
- **The Python twin's current behavior** for these 27 oracles (whether it still emits the
  pseudo-API): assumed from the recorded bytes; no Python twin was run.

## G. Bottom line

The commit does what it says, at the mint, with honest red/green evidence, deliberate and
well-reasoned pins, and two real latent shape-bug fixes — the strongest single commit this
review has examined. It is not spec-compliant as written because (a) the plan's law, read
against its own test's render-boundary anchor, covers briefing.go's mint, and (b) the
rewritten catalog mints a dead-end line for RISK_CALIBRATION and a proof-blind line for
INDEPENDENT_VERIFICATION — semantic gaps the parse oracle structurally cannot see. Fix C-1
and I-1 (small, one-line-each catalog changes + deliberate oracle re-records), and open
Task 7b for I-2.
