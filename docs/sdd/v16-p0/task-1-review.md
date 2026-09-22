# Task 1 review — one ScaBench target, end to end

**Scope reviewed:** the uncommitted Task 1 work for
`docs/superpowers/plans/2026-09-21-v16-p0-regression-suite.md` (Task 1, lines
275–2234) against the implementer's report
`.superpowers/sdd/2026-09-21-v16-p1-p2-record-and-evidence/task-1-report.md`.
Tree state at review time: `469d8425` + 9 modified files + 12 untracked paths;
every artifact the report claims was checked against the file on disk, not
against the report.

**Verdict: approve-with-fixes.** The feature is real and works: the records
validate, the verb's exit contract holds, the audit read-back is
presence-gated exactly as the two gate scripts require, and the operator run
pasted into `docs/gates/v16-P0.md` is genuine — I re-derived it from
`.scratch/p0/` (score-file sha256, target/run records, ledger seq 2/3/4,
`regress status` byte-for-byte) and re-ran `audit --json` on a copy of the
campaign. The two must-fix items are both about the **ledger law**, which is
the one law this task exists to uphold: the test that was supposed to prove the
unwind never reaches the code it tests, and the unwind itself destroys a
pre-existing record when the failing writer is `PinTarget` (the only writer
that rewrites). Both have reproductions below.

---

## 1. Findings

### MUST-FIX 1 — the ledger law has no test at all

`internal/regression/target_test.go:173`
(`TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails`) calls

```go
AddTarget(c, TargetSpec{Kind: "scabench", Program: "Acme", Shape: "vault-erc4626"})
```

with no `RecordID`, no `Repo` and an empty `CommitHint`. That spec is refused by
`checkTargetSpec` (`internal/regression/target.go:58-61`) **before `writeThenLog`
is ever reached** — the error the test sees is the spec refusal, and the empty
`targets/` glob is empty because nothing was written. The test is decoration.

Proof (scratch probe, since deleted — §12):

```
PLAN FIXTURE refusal = a scabench target with an empty dataset commit field must still
  name its --record-id and --repo: the dataset's commit field is empty for Initia
  Move_b36d06 and Starknet Perpetual_main, and an empty hint is a value to record, ...
```

Three mutations, none of which any test noticed:

| # | mutation | result |
|---|---|---|
| M1 | `os.Remove(path)` in the unwind replaced by a nil error | **all tests still pass** |
| M8 | the whole `err != nil` branch after `c.Log` made unreachable | **all tests still pass** (`./internal/regression ./internal/audit/... ./internal/cli` green) |
| M9 | `c.Log(...)` replaced by a no-op returning nil — **no hash-chained event is ever written** | **all tests still pass** (`./internal/regression ./internal/audit/... ./internal/cli ./internal/validation` green) |

M9 is the sharper one: "exactly one hash-chained event per mutation" has **zero**
test coverage in the new code. The only evidence that the three writers ledger
anything is the operator's pasted `events.jsonl` (which is genuine — see §5), and
that evidence exists for one target on one machine, not for the code.

The plan's own Step 4 snippet contains the same broken fixture, so this is an
inherited defect — but the report promotes it ("**None skipped; all 5 pass**",
"the ledger-law test the P1 self-review found missing") as proof the law holds,
which is the part that is wrong.

**Fix:** give the fixture a spec that survives `checkTargetSpec` (add
`RecordID`/`Repo`/`CommitHint`), and add one test per writer that counts the
events appended (read `events.jsonl`, assert exactly one new line with the
expected `type` and `ref`). A valid-spec probe against the current code does
reach the unwind and does remove the projection, so the *code* is fine here —
only the test is not.

### MUST-FIX 2 — the unwind deletes a pre-existing record: a failed `PinTarget` loses the target

`writeThenLog` (`internal/regression/regression.go:119-126`) unwinds by
`os.Remove(path)` unconditionally. `PinTarget` is the one writer that
**rewrites** an existing projection, so when its ledger write fails the unwind
removes the target record that was already committed by `AddTarget`, while the
`regression.target.added` event stays in the log. Reproduced with a scratch test
(campaign → `AddTarget` OK → block `EventsPath` → `PinTarget`):

```
pin refusal = read .../events-as-a-directory: is a directory
the target record still exists after the failed pin: ok=false err=<nil>
DATA LOSS: a failed pin removed the pre-existing target record T-70b3b0b2d54f
```

Consequences: the campaign is left with a ledger event for a target that no
longer exists, and `audit` then sees zero targets, `ErrSkip`s the
`regression_suite` section and reports `ok: true` — the suite's read-back
silently disappears instead of reporting a problem. This is the ledger law
failing in the direction that loses data.

The repo already has the correct pattern: `findings.SaveThenLog`
(`internal/findings/storage.go:166-206`) snapshots the previous bytes with
`prevBytes` and restores them with `restoreBytes`, which removes the file **only
when it did not exist before**. `writeThenLog` re-implements that law and gets
the rewrite case wrong.

**Fix:** adopt the same prev-bytes/restore dance in `writeThenLog` (or call a
shared helper); keep the "UNWIND ALSO FAILED" wording from `SaveThenLog` so a
failed restore cannot be laundered into a clean error.

### SHOULD-FIX 1 — the section documents a check it does not perform

`internal/audit/sections/regressionsuite.go:11-15` says `problems` carries four
states, the third being "a target whose bound snapshot records a DIFFERENT
commit". No code path reads a snapshot: `targetProblems`
(`regressionsuite.go:98-114`) checks only `sha == ""`, `!sha40`, `sid == ""`.
The equality is enforced at write time (`checkPin`), never re-verified on the
read-back surface — which is the surface the plan's exit criterion ("every
snapshot carries a resolved SHA") is supposed to be checked by. The RUNBOOK §11
text the implementer added is accurate (it lists five states, none of them the
snapshot check), so only the Go doc comment overclaims. Either implement the
check or cut the sentence.

### MINOR 1 — D8's justification is false, and the helper is a third copy

`internal/regression/run.go:65 kindName` is byte-for-byte the body of
`internal/pipeline/status.go:182 kindName` (a third, equivalent copy lives at
`internal/completion/support.go:110`). D8 says "**No such helper existed**"; the
new function's own comment says it mirrors `internal/pipeline/status.go`'s. The
duplication is defensible under the house rule ("small helpers are duplicated,
not exported"), and the plan's `%v` would indeed have printed a rune; the
deviation's stated reason is what is wrong.

### MINOR 2 — the gate record's `audit --json` paste is a re-shaped excerpt

The real command prints `{"campaign_id": ..., "ok": true, "sections": {..., "regression_suite": {...}}}`.
`docs/gates/v16-P0.md:201-233` presents it as
`{"ok": true, "regression_suite": {...}}` under the heading "Everything below is
pasted from the real run". The *section content* is exact — I re-ran the audit
on a copy of the campaign and every field, value and key order matches — but the
envelope is synthesized, so a reader cannot tell which parts of that block are
tool output. Worth one line of prose ("section extracted from `sections`") in a
file whose whole value is that its pastes are verbatim.

### MINOR 3 — the unpinned-target assertion cannot tell two states apart

`TestRegressionSuiteReportsAnUnpinnedTarget` asserts `len(problems) == 1` and
that the message contains `"resolved_sha"`. Collapsing the `sha == ""` branch
into the `!sha40` branch (mutation M4b) makes the problem read
`target T-… resolved_sha "" is not a 40-hex commit` — still one problem, still
contains `resolved_sha` — and the test **still passes**. The check fires, so this
is not a hole in the code, but the test does not pin *why*. (The plan's own
assertion has the same shape.)

### MINOR 4 — the report's diffstat does not match the tree

Report §1 lists 8 modified files (`git diff --stat`). The tree has **9**:
`.gitignore` carries a +5 hunk adding `node_modules/` with a comment about
`entropy_gate.py init`. The content is clearly the pre-existing JS-tooling work
the report lists as "not mine", so this is probably not Task 1's change — but
the report's own evidence block is inaccurate as printed, and the file's mtime
(2026-09-22 10:44) is *after* the operator run it describes. Either the diffstat
was captured before that edit or the change is unattributed.

### MINOR 5 — action validation happens after the campaign is opened

`regressCmd` calls `t14Open` (`internal/cli/cmd_regress.go:139`) before
`dispatchRegress` validates `st.pos[1]`. argparse validates the choice first, so
the port diverges on the combination:

```
$ webv2 --root R regress no-such-campaign bogus-action
error: malformed campaign id: 'no-such-campaign'      # exit 1
$ webv2 --root R regress C-a7844c6d23 bogus-action
usage: webv2 regress [-h] campaign {target,run,status} ...
webv2 regress: error: argument regress_cmd: invalid choice: "bogus-action" ...  # exit 2
```

Untested edge, exit code differs (1 vs 2). Cheap to make argparse-ordered by
dispatching on `st.pos[1]` before opening the campaign.

### OBSERVATIONS

- **The exit criterion is half met, and the record says so.** The plan's
  criterion is "Suite runnable end-to-end on one ScaBench target **via
  ScaBench's own baseline runner**". The runner half did not run (no
  `OPENAI_API_KEY`) and §5 of the gate record says so in bold, labels the target
  `PINNED, RUNNER NOT RUN — no OPENAI_API_KEY`, and explicitly declines to claim
  the judge path. That is the plan's own sanctioned fallback (Step 21) and it
  does not blur RAN vs NOT RUN. The report's "Status: COMPLETE" should be read
  with that qualification.
- **`NormalizeScore`'s doc overstates its refusals.** "It refuses an unknown
  scorer, a missing key, and an unknown key" — only `found`/`missed`/
  `false_positives`/`verdict` are required; `pass`, `bonus` and
  `operator_confirmed` are never read, so a scorer that *dropped* one would be
  accepted at runtime (the cross-language test would catch the drift, not the
  adapter). `normalizeJudge` accepts any object and leans on the schema.
- **Untested defensive branch:** `targetProblems`'s `sid == ""` case cannot be
  produced by any writer (PinTarget always writes both), so it has no test —
  same class as the hand-written orphan run, which *is* tested.
- **The scorer's per-gold detail is not in the campaign.** D3's array→count
  translation is necessary (M3 proves the plan's shape is impossible), but
  `missed: 7` is all the run record keeps; the seven ids live only in the
  `.scratch` score file whose sha256 is recorded. The operator run preserves
  them by pasting the file into the gate record; later suite runs will not.
  Task 10 should record the ids (a sidecar or `notes`).
- **`--found/--missed/--false-positives` are silently ignored** when
  `--scorer eval-gold` is given (they only feed the transcribed judge path). No
  refusal, no warning.
- **Duplicated git-setup test helpers** (`gitTarget`, `gitTreeWithCommit`,
  `gitInitCommit`) exist in three packages. House rule allows it; noting it
  because the review asked about duplicated helpers.

---

## 2. The mutations (every one applied to the real tree, then reverted)

Each mutation was applied to one file, the named test(s) run with
`-count=1`, and the file restored; the restored file's sha256 was compared to
the pre-mutation hash every time (§12).

| # | what I broke | test(s) run | result |
|---|---|---|---|
| M1 | unwind: `os.Remove(path)` → nil error | `TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails` | **STILL PASSED** → the test never reaches the unwind |
| M8 | unwind: whole `err != nil` branch unreachable | `./internal/regression ./internal/audit/... ./internal/cli` | **ALL PASSED** |
| M9 | `c.Log` never called (no event written) | `./internal/regression ./internal/audit/... ./internal/cli ./internal/validation` | **ALL PASSED** → no test sees a missing event |
| M2 | `checkPin`: snapshot `git_commit` equality check disabled | `TestPinTargetRefusesASnapshotThatDisagreesWithTheSHA` | FAIL: `target_test.go:164: err = <nil>, want a refusal naming the snapshot's git_commit` ✓ |
| M3 | adapter demands `Int` for `found`/`missed` (the plan's shape) | `TestNormalizeScoreAcceptsTheRealScorerOutput\|TestEvalGoldKeysMatchTheRealScorer` | FAIL: `run_test.go:83` and `:277` — `eval-gold output key "found" is list, want the scorer's array of gold ids` ✓ |
| M4 | `targetProblems` returns nil (section stops reporting an unpinned target) | `TestRegressionSuiteReportsAnUnpinnedTarget` | FAIL: `0 problem(s), want exactly the unpinned-target one` ✓ |
| M4b | collapse `sha == ""` into the `!sha40` branch | `TestRegressionSuiteReportsAnUnpinnedTarget` | **STILL PASSED** → minor 3 |
| M5 | `firstID`: `j := i + len(prefix)` → `j := i` (the plan's D6 bug) | `TestRegressOneTargetEndToEnd` | FAIL: `cmd_regress_test.go:19: target add printed no T- id` ✓ |
| M6 | drop the presence gate (`ErrSkip` when no target) | `TestRegressionSuiteIsPresenceGated` | FAIL: `a campaign with no regression target must ErrSkip, got <nil>` ✓ |
| M7 | drop the argparse-level `--record-id/--repo` rule (D7) | `TestRegressRefusalsAreExit1AndArgparseErrorsAreExit2` | FAIL: `code = 1 … want 2 with the usage block` ✓ |
| D9 | one `_, _ = fmt.Fprintln` → bare call, then `golangci-lint run ./internal/cli/... --new-from-rev HEAD` | — | `cmd_regress.go:250:15: Error return value of 'fmt.Fprintln' is not checked (errcheck)` → **D9 is necessary** |

Three of the task's load-bearing tests (the unwind test, the pin/snapshot
equality test, the presence gate) were mutated; the first cannot fail at all,
the other two fail for exactly the right reason. Five more tests were mutated
for coverage (M3, M4, M5, M7, M9).

## 3. Deviations D1–D11, judged

| # | deviation | verdict |
|---|---|---|
| D1 | shared `optionalStr`/`withOptional`/`readRecord`/`loadRecords` | **convenient, benign** — no behaviour change, no requirement weakened |
| D2 | functions split for `funlen`/`gocyclo`/`gocognit` | **necessary** — the plan's bodies are 40–90 lines against a 30-line cap, and the ratchet grades new files in full |
| D3 | `eval-gold` adapter reads arrays, not integers | **necessary** — M3 proves the plan's code refuses the scorer's real output; the operator run's `missed: 7` is the same fact |
| D4 | real fixtures replace the plan's invented ones | **necessary** (realism law) |
| D5 | cross-language test made to actually run | **necessary** — I reproduced the plan's fixture: `eval-gold: <gold> is not a JSON object` (exit 2), and without `events.jsonl`: `…/events.jsonl not found` (exit 2). The plan's version could only ever skip |
| D6 | `firstID` scans from `i + len(prefix)` | **necessary** — M5 |
| D7 | CLI enforces `--record-id`/`--repo` for an empty scabench hint | **necessary given the plan's own Step 13 test** (M7). The smell is real: the same rule now exists twice (argparse exit 2, `checkTargetSpec` exit 1) and the two can drift |
| D8 | `kindName` added | **convenient**, on a false premise — see minor 1 |
| D9 | `_, _ =` on 12 prints | **necessary** — verified against the repo's own gate command (see the table above); precedents `cmd_mint.go:101`, `cmd_run.go:148`; `t14Dispatch` itself uses the bare form but is grandfathered |
| D10 | Task 1 creates `docs/gates/v16-P0.md` | **necessary** — Step 21 says record into it and it did not exist; the ownership banner telling Task 11 to extend, not replace, is the right call |
| D11 | report path collision, original preserved | process note; the preserved `task-1-report.bounty-policy-booleans.md` is present and intact |

No deviation weakens a requirement the plan set. The one that changes what the
plan *intended* (D3) is forced by the real scorer, is proven by a mutation, and
is pinned by a test that executes the scorer.

## 4. Plan-wrong claims P1–P8

| # | claim | verification |
|---|---|---|
| P1 | dispatcher prints `error: unknown command "regress"`, not the plan's `unrecognized arguments` | **confirmed** — `internal/cli/cli.go:160` |
| P2 | `kvT` is test-only | **confirmed** — `internal/cli/cmd_dedup_test.go:127`, nowhere else |
| P3 | `campaignIDOf`/`firstID`/`gitInitCommit`/`gitRevParse` do not exist at HEAD | **confirmed** — `git grep … HEAD -- internal/cli` is empty |
| P4 | registering an 18th section breaks four audit tests + one validation test + the runbook gate | **confirmed** — all six exist and pin those lists (`audit_test.go:85,472`, `p1_sections_test.go:273`, `eval_test.go:263`, `schema_test.go:20`, `runbook_test.go:57`); the edits extend them without weakening them (I diffed all four) |
| P5 | Step 16's test cannot pass at Step 16 | **not independently verified** (would require replaying the step order); plausible and self-consistent |
| P6 | eval-gold's contract: arrays, and the campaign dir needs `events.jsonl` | **confirmed** — reproduced both refusals |
| P7 | no ERC4626 vault among the resolvable codebases; `--shape` must be justified from the tree | **structurally confirmed** (the dataset carries no shape/category field, so `--shape` cannot be derived from it). The "probed eight repositories" claim is corroborated by 12 probe checkouts under `.scratch/p0/probe/`, but not re-verified against GitHub |
| P8 | Step 21's heredoc/quoting is misdescribed | cosmetic; the implementer used the plan's invocation and it produced a valid gold file (4.0 KB, 7 rows) — no finding |

## 5. The operator run — checked against the machine, not the paste

Everything below was re-derived from `.scratch/p0/` and the live ScaBench
checkout:

- **Dataset.** The project exists once; `codebase_id`
  `…_90b1b5`, `commit` `ac46a2fc8baf6c827ee20c69eecae66561a5c65f`, `repo_url`
  `sherlock-audit/2024-08-perennial-v2-update-3`, 7 `high` findings whose
  `finding_id`s are exactly the seven in the pasted score file. ✓
- **The pin story.** `snapshot.json` records `git_commit` = the resolved SHA,
  `ladder` `git-clean`, `file_count` 846 — matching the pasted `snap` line. The
  target record and the run record on disk are identical to the pasted JSON,
  field for field and in order. ✓
- **The scorer.** `sha256sum .scratch/p0/score.json` =
  `980437467e4b2e1e0167fbe63bb7cc596cdc123a1c801e9fa14e1774b395b003`, byte-equal
  to the `score_file_sha256` in the pasted run record. The score file is a real
  `eval-gold.py` capture (`found: []`, 7-element `missed`, `operator_confirmed: {}`). ✓
- **The ledger.** `events.jsonl` has exactly one event per mutation, chained:
  seq 2 `regression.target.added`, seq 3 `regression.target.pinned`, seq 4
  `regression.run.recorded`, each `prev_hash` equal to the previous
  `event_hash`. ✓
- **The read-back.** I copied the campaign, rebuilt the CLI from the working
  tree, and re-ran `audit C-a7844c6d23 --json`: exit 0, top-level `ok: true`,
  `sections.regression_suite` **identical** to the pasted section (only the
  envelope differs — minor 2). `regress status` reprints the pasted two lines
  byte for byte. ✓
- **RAN vs NOT RUN.** §5 is explicit and does not blur them: baseline runner NOT
  RUN, judge arm NOT RUN, and the network-free cross-check (the shipped
  baseline for this project) is cited as *not* a score for our campaign. I
  confirmed that file exists: `total_findings: 5`, `files_analyzed: 4`,
  `timestamp 2025-09-02T06:53:52`. ✓
- **Unpinned-target facts the code comments rest on.** 10 of 32 codebases carry
  no 40-hex commit, and the two empty strings are exactly `Initia Move_b36d06`
  and `Starknet Perpetual_main` — the two the refusal message names. ✓

## 6. Laws checklist

- **Ledger law** — *fails*: exactly-one-event-per-mutation is untested (M9) and
  the unwind is untested (M1/M8) and wrong for the rewrite path (must-fix 2).
  The real ledger on disk is correct.
- **Realism law** — *passes*. The adapter's key set is pinned by a test that
  executes `scripts/eval-gold.py` and normalizes its live output; the fixture is
  a real capture, not an invention; the two literals the code matches on that
  come from outside (`source.git_commit`, the dataset's `commit`) were checked
  against the real producer's records; the empty-commit and unpinned-codebase
  claims are true of the real dataset.
- **Schema discipline** — *passes*. Both schemas are `additionalProperties:
  false`, both are validated on the write path with
  `validation.Validate(v, name, 1)` before any file lands, both names were
  **appended** to `knownSchemas` (order preserved), and
  `python3 scripts/sync-asset-manifest.py` is idempotent (same sha256 before and
  after a re-run; the pack test is green).
- **Byte-pinned surfaces** — *passes, and nothing moved that should have*:
  `scripts/verify-full.sh`, `scripts/check-golden.py` and
  `internal/cli/testdata/p3_args_golden.json` show no diff; the registry-pinning
  Go tests were updated (correct — they pin `SectionNames()`, not a rendered
  campaign, and the presence gate is what keeps rendered output unchanged, which
  `TestRegressionSuiteIsPresenceGated` + M6 establish); the RUNBOOK moved because
  `TestRunbookDocumentsEveryRegisteredVerb` requires it. The top-level help text
  is generated and not golden-pinned.
- **Exit criterion** — "runnable end-to-end on one ScaBench target" is proven for
  the records/read-back path; the "via ScaBench's own baseline runner" half is
  NOT RUN and recorded as such.

## 7. What I could not verify

- `scripts/verify-full.sh` was not run (14 steps, heavy). The presence-gate
  claim it would settle was instead verified structurally: both gate scripts
  assert "no unexpected sections" against fixture campaigns that predate the
  verb, and the section `ErrSkip`s without a target (M6).
- ScaBench's baseline runner and the Nethermind judge arm (no `OPENAI_API_KEY`),
  as the report itself states.
- P5 (the Step-16 red) and P7's repository probing — see §4.
- `go test ./...` (Step 20's first half, which the report did not run) **was**
  run by me: green, with the only failure being my own scratch probe. Re-run
  after deleting it: green.
- `golangci-lint run … --new-from-rev HEAD` **was** run by me on the four
  touched package trees: exit 0, no findings (matching the report).

## 8. Scratch edits, and the state I left

Every mutation was reverted and every file's sha256 re-checked against its
pre-review hash (`regression.go d41b2012…`, `target.go 30b5a99f…`,
`run.go 843a31ec…`, `regressionsuite.go 71cba6a3…`, `cmd_regress.go 964b6946…`,
`cmd_regress_test.go d557817b…`). One scratch test file,
`internal/regression/zz_review_scratch_test.go`, was created for the unwind and
data-loss probes and deleted; `ls internal/regression/` shows the five files the
implementer wrote. No implementation file, no test and no record was left
modified; nothing was committed. Artifacts of this review live under
`.scratch/review/` (git-ignored).
