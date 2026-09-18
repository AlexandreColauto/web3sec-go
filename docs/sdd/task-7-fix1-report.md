# Task 7 fix round 1 report — next-actions close their proofs

**Status:** DONE (C-1, I-1, I-2 closed; minors M-1/M-2/M-3 closed; M-4/M-5
unchanged per review)
**Commit:** `fix(orchestrator): next-actions close their proofs (review round 1)`
**Branch/worktree:** `production-readiness` @
`/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
**Base:** `ac11de2c` (HEAD after Task 13's deps bump)
**Scope:** the two interrupted-attempt files (`internal/orchestrator/status.go`,
`internal/orchestrator/next_actions_cli_test.go`) verified against the review,
completed, plus the I-2 surface (`internal/briefing/*`) and the oracle re-pins.
`scripts/*` untouched.

---

## 1. What the inherited uncommitted diff contained, and what I changed

The +304/−15 uncommitted diff (two interrupted deepseek attempts, per
progress.md) already held: the C-1 RISK_CALIBRATION fix, an INDEPENDENT_VERIFICATION
attempt, the DISCOVERY `run` line (M-1), the MAINNET_FORK_POC mint line (M-2),
the `<same-or-distinct>` metavariable (M-3), the dispatcher-feed oracle-boundary
comment, and a `TestNextActionsLeadWithTheProofClosingCommand` property over all
13 proof-bearing phases. It was internally inconsistent and red:

- `status.go` minted `[run, verify]` for INDEPENDENT_VERIFICATION while the test
  wanted `[verify, mint, run, …]` — and my brief specifies **verify leads,
  mint as follow-up** (the review's "replace" wording and the brief's "mint as
  follow-up" are reconciled by demoting mint below verify, not deleting it).
- The new property test flagged REPRODUCTION (leads `repro-queue`, closed by
  `mint`) — the same proof-closing law applied consistently.
- `TestNextActionsProofClosingPinIsNotVacuous` could not run (fixture finding
  description `'no check'` failed validation).
- 11 next_actions oracles were stale.

Fixes on top of the inherited work:

1. **status.go INDEPENDENT_VERIFICATION** → `[verify --finding <f> --exec
   <EXEC-id> --verifier <verifier> --description <description>`, `mint …`,
   `run]`. verify leads: `verify --exec` is the only CLI path to
   `reproduction.MintIndependentEvidence`, which writes
   `verification.independent_reproduction` — the field the phase proof reads
   (proofs2.go:79-101); cmd_verify.go:194-196 requires `--verifier` and
   `--description`, so the minted flags match the parser. mint stays as the
   evidence-recording follow-up; run drives the stage.
2. **status.go REPRODUCTION** → `[mint …, repro-queue]`: mint records the
   reproduction attempt the proof reads; repro-queue is the read-only view, so
   it follows. (New consequence of applying the proof-closing property to every
   phase; the review's C-1 rationale, generalized.)
3. **status.go RISK_CALIBRATION** → `[run, rank]` (inherited, kept): `rank` is
   read-only by contract (cmd_rank.go), the proof reads `risk.validated.band`
   per CONFIRMED finding written by the deterministic risk-calibration stage —
   `run` closes it. rank stays as the informational score view.
4. Test file: REPRODUCTION/INDEPENDENT_VERIFICATION concrete fixtures re-pinned
   to the new catalog order; `t7ConfirmedFinding` description lengthened past
   the validator floor.

## 2. Oracle re-record (deliberate, reasoned)

9 next_actions oracles re-recorded (deduped/step3, gates/step2, ingested/step4,
model/step1, planned/step1, phases/steps 5,6,8,11,12,13) by replaying every
scenario step through `dispatchGolden` in a temporary in-package test (deleted
before commit — same protocol as Task 7's tooling) and splicing only the
changed `oracle` strings into `testdata/oracles.json` (byte-level splice,
format-preserving; `git diff` = 18 lines, all `"oracle"` values). The
provenance note in `golden_test.go` documents the round-1 reason. No state,
event, or seam-call oracle moved.

## 3. I-2 — briefing.go's own mint is command-first now

Per the review's §A ruling (the law is render-boundary-wide), every
`briefing.NextActions` mint was converted to `webv2Action(command, reason)` =
`webv2 …  # reason` (prose moved into a paren-free `#` comment; `noParens`
maps `(`→`[`/`)`→`]` for interpolated data). Block → command mapping:

| mint (was prose-first) | command now |
|---|---|
| FIX INTEGRITY FIRST (both branches) | `webv2 doctor <C>` (runbook: doctor rebuilds a mismatched event chain) |
| campaign marked COMPLETE by … | `webv2 status <C>` |
| open completion proof (closed branch) | `webv2 prove <C> --stage <stage>` (items dropped — prove prints them; Task 7's trade-off) |
| work probe row (has priority_id) | `webv2 answered <C> <priority-id> answered --reason <reason> --actor <actor>` (the same verb the attention queue uses to work its oldest untouched question) |
| emit probe row | `webv2 probes <C> run --emit` |
| lens routing (both shapes) | the lens's mechanical table verbatim (`enforce`/`symmetry`) |
| framework skew | `webv2 snap <C> <target>` |
| consensus-critical uncovered / gate deficit / finish-for-submission | `webv2 run <C>` (the stage driver; the deficit names what is missing) |
| sibling priority | `webv2 answered <C> <pid> answered …` (run fallback if the row carries no id) |
| divergence gate open | `webv2 probes <C> run --emit` |
| materialize chain | `webv2 chain <C> <members…>` (≥2 members, else run) |
| E6 verification queue | `webv2 verify <C> --finding <fid> --exec <EXEC-id> --verifier <verifier> --description <description>` |
| memory recall pending / corpus | `webv2 recall <C> --finding <fid>` |
| structurally stuck | `webv2 floors <C> set --actor <actor> --reason <reason> <class_> <floor>` |
| submission ready / eligible-but-blocked | `webv2 report <C>` / `webv2 run <C>` |
| pending memory | `webv2 memory <C> --approve <memory-id>` |
| terminal reachable | `webv2 exploit <C> <last-path-member> --paid` (terminals when path is empty) |
| lens batting average | the lens's mechanical table, `webv2 run <C>` for table-less lenses |
| attention leads / displaced queue / high-consequence debt | the ledger's own `command` field, bare (the ledger block already renders the action prose beside it) |

The generic-item filter (fallback-suppression boundary) now classifies by the
reason suffix for the probe/lens/divergence families and by line identity for
attention lines — same semantics as the old line-prefix list.

Latent bug fixed on the way: the old emit-probe-row branch dereferenced
`campaign.CampaignID` and panicked on hand-built briefs (`NextActions(brief,
nil)`, briefing.go:2147 pre-fix); all open-branch mints now use
`lensActionCampaign(brief, campaign)`, nil-safe.

## 4. Red first, then green

- RED (inherited, captured before my edits): `red-orchestrator-inherited.txt`
  — 12 failing tests (IV fixture vs status.go disagreement, REPRODUCTION +
  INDEPENDENT_VERIFICATION lead properties, NotVacuous validation failure,
  8 stale oracles).
- RED (new, mine): `red-brief-law.txt` — `TestNextActionsMintIsCommandFirst`
  + `TestClosedPassMintIsCommandFirst` (new file
  `internal/briefing/brief_next_actions_law_test.go`, the I-2 law at the mint
  over a brief exercising every block, plus a real completed campaign) failed
  against the prose mints — and exposed the nil-campaign panic above.
- GREEN: focused suites, full suite, vet, golden, runbook (below).

## 5. Gates (logs appended under `.scratch/sdd/task-7-fix1-logs/`)

- `go test ./internal/orchestrator ./internal/briefing ./internal/cli
  -count=1` → ok ×3 (`green-focused.txt`)
- `go test ./... -count=1` → exit 0, zero FAIL (`green-full.txt`)
- `go vet ./...` → exit 0 (`vet.txt`)
- `scripts/golden.sh` → GOLDEN GREEN (`golden.txt`; gofmt gate clean)
- `scripts/runbook-walkthrough.sh` → 150 passed / 0 failed (`runbook.txt`;
  run with the task-13 repo-cache convention GOCACHE/GOPATH/GOMODCACHE —
  a first run without them died on the read-only default mod cache, noted
  in the log)

## 6. Deliberate re-pin inventory (test changes, with reasons)

Every changed test line re-pins a marker that moved into the `# reason`
suffix, or re-targets the ledger's `command` field now that next_actions mint
it. `internal/briefing`: `briefing_test.go` (attention leads matched by
command; divergence markers reason-based; closed-campaign nag check on the
command, not the prose prefix), `lens_batting_test.go` (exact pins: stat rides
its table command; CI brackets paren-free), `lens_routing_test.go`
(hasReasonAction/actionReason helpers; skew + routing markers reason-based;
silence checks stay sharp on the reason), `sweep_t35_probes_test.go`
(probe-row/divergence markers reason-based; row-id extraction from the reason;
attention lead = command), `sweep_t35_corpus_test.go` (corpus marker
reason-based; `(+1 more finding(s))` → `— 1 more findings`), 
`sweep_t35_workorder_test.go` (E6 mandatory-before-optional by reason marker),
`sweep_t35_reach_test.go` (floors pin splits command head from reason),
`sweep_t36_test.go` (sibling marker reason-based). `internal/cli`:
`cmd_t31_test.go` (recallRe matches the backticked gate-message form AND the
command-first next-action form). `internal/orchestrator/golden_test.go`
(provenance note only). The T35 parity pins were re-pinned deliberately, per
finding I-2's remedy: the parity being pinned is the set of minted lines and
their order, which the conversion re-shapes by design; the tests still assert
the same behavior (rank order, contiguity, lead precedence, suppression).

## 7. Concerns / notes for the reviewer

1. **Attention lines are bare commands.** I first minted
   `command + "  # reason"` for the attention lead, then chose the bare
   ledger `command` field: the attention block already renders the action
   prose right beside it, and bare commands kept the T35 lead-equality pins
   honest (acts[i] == ranked[i].command). If the round-2 reviewer wants the
   reason inline there too, it is a two-line change + pin updates.
2. **Carriers chosen for commandless advisories** (criticality/deficit →
   `run`, submission-ready → `report`, terminals → `exploit --paid`,
   batting → table-or-run) are judgment calls the plan's law permits
   (runnable, copyable) but a stricter reviewer may want different verbs.
   None of them is a phase's only line, so C-1's dead-end objection does not
   apply to them.
3. **`webv2 doctor` as the FIX INTEGRITY FIRST command** matches the
   runbook's own doc ("`webv2 doctor <C>` rebuilds the … event chain");
   the integrity block's detail text rides the reason.
4. **REPRODUCTION reorder** (mint before repro-queue) was NOT explicitly
   demanded by the review — it follows from the new
   TestNextActionsLeadWithTheProofClosingCommand property the inherited diff
   introduced. Flagging in case round 2 wants repro-queue first and the
   property scoped to the two flagged phases only.
5. `verify INV-…`/`work the oldest untouched question …` prose no longer
   appears in next_actions (it stays in the attention block, pinned by
   cmd_t31_test.go:290-295 and the ledger tests).
6. `scripts/` untouched; `git status` carries only the 15 source/test files
   listed in the commit below.
