# Task 3 + Task 4 review — `run --feed` and `review_session` events

Slice under review: `88653b81..5fe665e6` (single commit `5fe665e6`), 12 files, +1420/−12.
Reviewed against `task-3-brief.md`, `task-4-brief.md`, the Global Constraints, and the code
(not the report). Reviewed files are byte-identical to the slice commit in the current tree
(`git diff --stat 5fe665e6..HEAD -- <reviewed paths>` → empty), so all line citations below
are stable.

## Verdicts

**SPEC COMPLIANCE — Task 3 (`run --feed`): ✅ Spec compliant**, with two deviations from the
brief's letter, both documented by the implementer and both *forced* by the brief's own
internal contradictions (verified, not taken on trust — see Strengths). Nothing the brief
mandates is missing; the extras are listed and judged below.

**SPEC COMPLIANCE — Task 4 (`review_session` events): ✅ Spec compliant**, with three
documented deviations, all of which the brief either permits or whose premise the implementer
correctly found false.

**TASK QUALITY: Needs work** — one Important finding, labeled PLAN-MANDATED (the projection
read-modify-write omits the campaign lock that every sibling writer and the state package's
own law require). The rest of the slice is strong: the mandated tests are present and assert
real behaviour, the ledger/schema/manifest/ord laws all hold, and the two briefs' defects were
caught rather than inherited. If the controller accepts the plan-mandated lock omission, the
quality verdict flips to Approved on the strength of everything else.

### Task 3 requirement-by-requirement

| Requirement (task-3-brief.md) | Status |
|---|---|
| Create `internal/feed/feed.go` | ✅ `internal/feed/feed.go` — package `feed`, matching the brief's file list (`:22`); the brief's Step-3 code said `package pipeline` (`:253`), which is impossible (see Strengths) |
| Create `internal/feed/feed_test.go` | ✅ `internal/feed/feed_test.go` — all three mandated tests present (`:91`, `:156`, `:186`) with the mandated assertions intact |
| Create `internal/cli/cmd_run_feed_test.go` | ✅ `internal/cli/cmd_run_feed_test.go` — the four mandated tests verbatim (`:59`, `:71`, `:136`, `:174`) plus three extras |
| Modify `internal/cli/cmd_run.go`: `--feed` + usage/help + branch in `runRun` | ✅ `:23-35` (pinned constants), `:51` (`--feed` in `sp.vals` after `--max-stages`), `:64-72` (branch, resolved by name, empty value refused) |
| Produces `pipeline.FeedStage/FeedStages/FeedStageFor/FeedStageIDs/FeedUnwired` | ⚠️ produced as `feed.*` (`feed.go:34-40,43,159-174`); name-level deviation from the brief's Produces line, forced by the import cycle, plan doc updated in `4b06c114` |
| Drop carries the request record **and** the bundle it was built from | ✅ `feed.go:88-121` |
| File stem names the stage (no flag) | ✅ `cmd_run.go:125` (`TrimSuffix(filepath.Base(path), filepath.Ext(path))`), `:59` test |
| Feed **derives** `context_artifacts` from the bundle | ✅ `feed.go:114-116` (`boundary.BundleArtifacts(context)` → `SetOrAppend`) |
| `boundary.ContextHash(context) == request.context_hash` | ✅ `feed.go:109-113` (compared against the shipped bytes, refusal text asserted at `feed_test.go:228-243`) |
| `boundary.ValidateRequest` on the request with the derived set | ✅ `feed.go:117-120` |
| Undeclared / out-of-set drop refused **and recorded**, on the real path | ✅ `feed.go:126-131` → `boundary.RecordInputSetRefusal`; production reachability asserted at `cmd_run_feed_test.go:174-202` (`model.rejected` on the ledger) |
| Ingest `output` only after the invocation validates | ✅ `feed.go:72-81` |
| `run --feed` is the production caller Task 2's refusal lacked | ✅ `cmd_run.go:124-152`; nothing else in the tree calls the feed registry |
| Exit codes 0 / 1 / 2; never 3 | ✅ `cmd_run.go:124-152` returns only 0 (ingested), 1 (read/ingest/input-set refusal), 2 (unwired stage, outside-inbox, empty flag, campaign mismatch); asserted at `cmd_run_feed_test.go:34,59,71,174` |
| Refuse `--feed ""` rather than falling through | ✅ `cmd_run.go:66-70`, test `:34` |
| Resolve the flag **by name**, not by index | ✅ `cmd_run.go:65` |
| Update the pinned usage/help bytes | ✅ `cmd_run.go:23-35`; no test in `internal/cli` pins `run`'s bytes (checked: `rg 't30RunUsage|t30RunHelp|max-stages MAX_STAGES' internal/cli/*_test.go` → no hits) — see Minor 2 for the one surface that did move |
| RUNBOOK: convention, exit codes, wired stage list | ✅ `assets/runbook/RUNBOOK.md:198-222`, cheat-sheet line unchanged at `:1783` |
| Manifest synced in the same change | ✅ hashes verified at `5fe665e6`: `RUNBOOK.md` `68f55fb2…`/123485, `campaign_state.schema.json` `a0175ad8…`/14752 — both match the committed bytes |
| **Extra** (not requested) | optional campaign positional + campaign-from-path (`cmd_run.go:51,158-186`), `valNamed`/`flagNamed` rewrite (`cmd_p3_args.go:240-259`), `refusalRequest` (`feed.go:140-146`), 3 extra CLI tests. Judged: the first two are justified (below), the parser rewrite is not (Minor 1) |

### Task 4 requirement-by-requirement

| Requirement (task-4-brief.md) | Status |
|---|---|
| Create `internal/reviewsession/reviewsession.go` + test | ✅ both present |
| Create `internal/cli/cmd_review_session.go` + test | ✅ both present |
| Modify `assets/schema/campaign_state.schema.json` (`review_sessions`) | ✅ `:219-237`, byte-for-byte the brief's block (`required`, `additionalProperties: false`, `^RS-[0-9a-zA-Z]{4,16}$`, `loc` minimum 0) |
| Produces `Start` / `End` / `Open`; events `review_session.started` / `.ended` | ✅ `reviewsession.go:21,40,59`; event names `:33,52`; both asserted at `reviewsession_test.go:21-47` |
| One open session at a time; `End` refuses unknown/double-closed | ✅ `reviewsession.go:22-24,41-43`; tests `:49`, `:68` |
| `appendRow`/`replaceRow` on the paired-write + unwind pattern | ✅ `reviewsession.go:74-104,117-133` — with the lock caveat (Important 1) |
| `orDefault`/`strValues` as local copies, never exported | ✅ `reviewsession.go:135-149` |
| Schema key validated on the write path | ✅ `SaveState` → `validation.WriteJson(..., "campaign_state")` → `Validate` (`internal/validation/atomicio.go:34-39`) |
| Verb registered via `register(command{ord: N, …})` in its own `cmd_*.go` init, `ord` = max+1 | ✅ `cmd_review_session.go:252-256`, `ord: 93`; scanned every `ord:` at `5fe665e6` — 93 is unique and is the maximum (92 was the previous max) |
| `<verb> -h/--help`: stdout, exit 0, no campaign, no state access | ✅ `cmd_review_session.go:41-45` calls `helpRequested` before `parseReviewSession` and before any `state` call; `t14Dispatch` (`cmd_scope.go:73-93`) only maps the error |
| `end` resolves the open session itself; exit 2 "no open review session" | ✅ `cmd_review_session.go:233-251` |
| Campaign resolution copied from `cmd_audit.go` | ⚠️ deviation: the brief's premise is false — `cmd_audit.go:76` registers `audit <campaign>` (positional). Implemented as an optional positional with an ambiguous-root refusal (`cmd_review_session.go:195-216`), endorsed by the controller in `4b06c114` and covered by `cmd_review_session_test.go:42` |
| RUNBOOK line incl. the WEBV2_NOW test-pin warning | ✅ `RUNBOOK.md:1792` |
| Real-wall-clock test (cannot pass on a pinned clock) | ✅ `reviewsession_test.go:84-101`; honest, because `nowIso` reads `WEBV2_NOW` only when non-empty (`internal/state/id.go:20-27`), so `t.Setenv("","")` genuinely unpins |
| `--loc` optional | ✅ default 0; negative refused at `reviewsession.go:45-47` (`looksLikeOption` lets `-5` through as a value, `cmd_exec.go:43-46`) |
| Manifest + commit | ✅ verified above |
| **Extra** (not requested) | `TestReviewSessionNamesACampaignOnAnAmbiguousRoot` (`cmd_review_session_test.go:42`), the optional campaign positional (controller change) |

## Findings

Counts: **Critical 0 · Important 1 · Minor 5.**

### Critical

None. Every global constraint I could check from this diff holds: stdlib only (imports are
`fmt`, `os`, `path/filepath`, `strconv`, `strings`, `testing` + `websec/internal/*`), the asset
manifest is synced in the same commit (hashes verified), the schema key ships with its writer,
one hash-chained event per mutation, determinism routed through `state.NewID`/`state.NowIso`,
no gate/audit-section surface touched, tests are plain Go in-package over `t.TempDir()`
campaigns.

### Important

**1. [PLAN-MANDATED] The `review_sessions` projection read-modify-write runs without the
campaign lock — the exact lost-update class r14 closed for every sibling writer.**
`internal/reviewsession/reviewsession.go:74-85` (`appendRow`) and `:87-104` (`replaceRow`) call
`c.State()` unlocked, mutate, then `saveThenLog` (`:117-133`) calls `c.SaveState(next)`, which
takes the lock **only for its own write** (`internal/state/campaign.go:242-254`). A concurrent
writer that lands between the read and the write is silently clobbered: the ledger keeps its
event, the projection loses the other writer's row.

- The law is explicit in this repo: `internal/state/campaign.go:236-241` — "any
  read-modify-write of campaign_state holds the campaign lock for its whole duration
  (depth-counted re-entry)".
- Every other projection writer obeys it: `internal/floors/floors.go:152-160` (with the r14
  incident recorded in the comment: "a sibling `floors set` between our State() and our rename
  used to vanish (both exit 0, state says 39, ledger says 34)"), `internal/probes/blanks.go:171-183`,
  `internal/evalscore/adjudicate.go:301-305`, `internal/learning/learning.go:101`,
  `internal/coverage/coverage.go:102` — and `internal/planner/plan.go:164-169`, the very helper
  (`planWindow`) the brief tells the implementer to copy, opens with `LockProcess()`.
- Reachable in the intended workflow: `webv2 review-session start|end` in one terminal while
  `webv2 run` walks the pipeline in another (the pipeline writes campaign_state at every stage).
- Secondary, same block: the unwind re-saves a parsed prior `Value` (`:123`) instead of using
  the r17 raw-bytes door (`campaign.RawState()` / `campaign.UnwindState()`,
  `internal/state/processlock.go:157-161`; `floors.go:175`), so a restore bumps `updated_at` and
  re-validates rather than restoring bytes.

*Why PLAN-MANDATED:* `task-4-brief.md:182` prescribes exactly "read the projection with
`c.State()`, capture the previous bytes, … `c.SaveState(next)`, `c.Log(...)`, and on log failure
`c.SaveState(prior)`" and names only the paired-write half of the pattern. The implementer
followed the brief; the brief's prose dropped the lock that its cited helper takes.

*Fix:* wrap the read-modify-write in `campaign.LockProcess()` / `defer campaign.UnlockProcess()`
(`SaveState` re-enters by depth, as `floors.go:155-160` relies on) and unwind through
`campaign.UnwindState(campaign.RawState())`.

### Minor

**2. Unrequested rewrite of the shared parser's option lookup.**
`internal/cli/cmd_p3_args.go:240-259`: `valNamed`/`flagNamed` dropped `splitFlag` in favour of
token-prefix matching (`a == v.name || strings.HasPrefix(a, v.name+"=")`). I checked equivalence:
`splitFlag` (`internal/cli/cmd_budget.go:139-147`) only splits on `"--name="` and otherwise
returns the token unchanged, so both forms match exactly the same token set (`--src`,
`--src=x`; `-x5` matched under neither). So this is not a behaviour bug — but it touches the
parser of every P3 verb, neither brief asks for it, and it ships with no test pinning the
equivalence. Nothing in this slice needs it (`--feed` matched under the old form too).
*Fix:* revert, or add a small table test over both spellings; keep only if it is wanted for its
own sake.

**3. `run`'s argparse error precedence moved for the missing-campaign + unknown-token case.**
Making the positional `optional` (`internal/cli/cmd_run.go:51`, `cmd_p3_args.go:197`) means
`parseCheckMissing` no longer fires, so `parseCheckExtras` reports first
(`cmd_p3_args.go:116-119`). Live evidence:
`go run ./cmd/webv2 run --bogus` → `webv2: error: unrecognized arguments: --bogus` (exit 2),
where the pre-change spec (diff line 677: `pos: []*posOpt{{name: "campaign"}}`) reported
`the following arguments are required: campaign` first. The repo pins that exact rule for a
sibling verb — `internal/cli/cmd_sequence_test.go:65-69`, case
`run-unknown-flag-loses-to-missing`, asserts the missing-argument error wins
(confirmed live: `webv2 sequence run --bogus` → "the following arguments are required:
campaign, spec, --finding"). Exit code is unchanged and no test pins `run`'s text, so this is
Minor — but the change moved a deliberate surface without pinning it.
*Fix:* if the ordering matters, keep the positional required and give `runFeed` the campaign
from the path after the fact (or assert the new text in `cmd_run_feed_test.go`).

**4. `feed.FeedStage.Note` is written but never read.** `internal/feed/feed.go:38,47` — the
field is populated for the one wired stage and read by nothing (the wired-stage error text
prints ids only, `internal/cli/cmd_run.go:128-130`). PLAN-MANDATED: `task-3-brief.md:284` puts
`Note` in the Produces struct. Either print it in the `--feed` refusal (it is the operator-facing
one-liner) or drop the field.

**5. `request.stage` overrides the drop file's stem for attribution.**
`internal/feed/feed.go:151-156`, consumed at `:75-76` (`IngestHypothesis(..., stageOf(request,
"discovery"), ...)`). A `discovery.json` drop carrying `"stage": "learning"` records
`origin_stage=learning` — `assets/schema/finding.schema.json:1099-1103` types it as a free
non-empty string. The stem still fixes the *ingest path*, so the brief's invariant ("a
mislabelled file cannot be ingested as another stage's output", `task-3-brief.md:5`) holds for
the path but not for the attribution Task 8 reads. PLAN-MANDATED: the brief's Step-3 code is
verbatim this (`task-3-brief.md:354-359`). *Fix:* prefer the feed stage's own id, or validate
`stage` against `pipeline.StageIDs`.

**6. `reviewsession.Open` swallows a `State()` error.**
`internal/reviewsession/reviewsession.go:59-63` returns `(VNull, false)` when the state file is
unreadable or schema-invalid, so `review-session end` on a corrupt campaign reports
"no open review session in campaign X" (exit 2, `internal/cli/cmd_review_session.go:233-237`)
instead of the corruption. `Start` is safe — `appendRow` re-reads and surfaces the error
(`:75-77`). PLAN-MANDATED: the brief's interface `Open(c) (validation.Value, bool)`
(`task-4-brief.md:14`) has no error slot. *Fix (if the interface may grow):* an
`OpenErr(c) (validation.Value, bool, error)` variant used by the CLI.

## Cannot verify from diff

1. **Task 2's boundary surfaces** — `boundary.ValidateRequest`, `RecordInputSetRefusal`,
   `BundleArtifacts`, `ContextHash` (`internal/boundary/boundary.go:109,135,248,272`) and
   `trajectory.VerifyTrajectory` — are unchanged code from an earlier task. I confirmed they
   exist, that the feed drives them on the production path, and that
   `internal/feed/feed_test.go:245-269` asserts `verify_trajectory` `ok=true` over the two
   refusal events (green), but their own correctness is outside this diff. Controller should
   confirm Task 2's review covered the same functions.
2. **Task 8's consumption of `origin_stage`** written at `feed.go:75-76` — spans another task.
3. **Python-twin parity.** The repo's comments and golden data reference a Python twin
   (`cmd_p3_args.go:3`, `internal/cli/testdata/p3_args_golden.json`), but no twin source lives in
   this repo (no `*.py` present). Whether the twin needs matching `run --feed` / `review-session`
   surfaces, or a new golden recipe for `run`'s changed argparse surface, cannot be settled here.
4. **`state.ListCampaigns`' error contract** used by `reviewSessionCampaign`
   (`cmd_review_session.go:195-210`) is unchanged code; the ambiguous-root refusal is tested
   (`cmd_review_session_test.go:42-60`), the zero-campaign root is not.
5. **RUNBOOK prose truthfulness** beyond the mechanical runbook tests. The claims I could check
   from code hold (`runFeed` returns only 0/1/2; the wired stage list matches `FeedStageIDs()`
   and the `FeedUnwired` keys), but prose is not test-enforced.

## Strengths

- **The import-cycle deviation is correct, and I verified it rather than trusting the report.**
  `go list -deps websec/internal/boundary` includes `websec/internal/pipeline` (via
  `roles → corpus → archetypes → structidx → orchestrator → completion → pipeline`), so the
  brief's `internal/pipeline/feed.go` + `package pipeline` was impossible. Moving the registry
  to `internal/feed` and keeping the partition assertion over `pipeline.Stages`
  (`feed_test.go:91-112`) is the right resolution — and the brief's own file list
  (`task-3-brief.md:22`) already said `internal/feed/`.
- **The implementer caught a plan defect the mandated test would have failed on.**
  `FeedUnwired` as written in the brief omitted the MIXED stage `dedup`
  (`internal/pipeline/stages.go:25`); without the added entry
  (`feed.go:184-187`) `TestFeedStagesPartitionThePipeline` cannot pass. The registry now
  partitions the table exactly: 7 deterministic stages excluded, 10 model/mixed stages =
  `discovery` wired + 9 declared unwired.
- **`refusalRequest` (`feed.go:140-146`) makes the refusal event satisfy its own contract.**
  The brief's bare-drop branch passed `validation.VObj()` to `RecordInputSetRefusal`, whose
  event data is validated as `trajectory.schema.json#model_rejected`; the fix carries the
  stage's role/kind (a fact about the stage) and the hash of the bundle actually shipped. This
  is asserted, not asserted-about: `feed_test.go:245-269` runs `trajectory.VerifyTrajectory`
  and fails if the refusal events turn a healthy campaign red.
- **The mandated CLI tests are present verbatim, plus three that close real holes:** empty
  `--feed` must not fall through to a full pipeline run (`cmd_run_feed_test.go:34`), bare `run`
  still requires a campaign (`:48`), and an explicit campaign that disagrees with the drop path
  is refused (`:151`) — the last one is the test that makes "the path is the single source of
  truth" true rather than merely stated.
- **Task 4's paired-write is faithful and improves the failure message.** `saveThenLog`
  (`reviewsession.go:117-133`) mirrors `findings.SaveThenLog`
  (`internal/findings/storage.go:184-186`) including the "UNWIND ALSO FAILED … repair by hand"
  wording, and `withRows` (`:106-113`) copies the KV slice before `SetOrAppend` so the prior
  projection stays intact for the unwind — a subtle aliasing bug avoided by hand.
- **Ledger, schema and manifest discipline all hold.** One event per mutation through
  `c.Log`; the projection key ships with its writer and is validated on the write path
  (`internal/validation/atomicio.go:34-39`); `assets/testdata/asset_manifest.json` hashes match
  the committed bytes at `5fe665e6`.
- **Determinism is routed, not bypassed.** `RS-` ids from `state.NewID` (hex, so the schema
  pattern `^RS-[0-9a-zA-Z]{4,16}$` holds), timestamps from `state.NowIso`; no `time.Now()` or
  raw UUID in the new records. The real-clock test is honest because `nowIso` treats an empty
  `WEBV2_NOW` as unset (`internal/state/id.go:20-27`).
- **The new verb's surfaces cannot disagree with each other.** Help short-circuits before
  parsing and before any state access (`cmd_review_session.go:41-45`), argparse refusals render
  against `helpUsageText("review-session")` (`:180-183`), and the registry `line` is the single
  source of the usage string — so `-h`, the usage block and the error text are one string.
  `ord: 93` is unique and max+1 at the slice commit (scanned all `ord:` values).
- **Evidence I ran** (focused, not the full suite):
  `go test ./internal/feed ./internal/reviewsession -count=1` → `ok websec/internal/feed 0.018s`,
  `ok websec/internal/reviewsession 1.110s`;
  `go test ./internal/cli -run 'TestRunFeed|TestRunWithoutACampaign|TestReviewSession|TestEveryCommandAnswersHelp|TestRunbook|TestHelpPrecedes' -count=1`
  → `ok websec/internal/cli 0.049s`. No warnings or noise in any of the output.
