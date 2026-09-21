# Final re-review — fix wave for `final-review.md` I-1 / I-2

Base `9ff35798` → head `5630a900` (`fix(v16): the feed records the accepted invocation; correct
the gate record`). The fix is **committed** — `git log` shows `5630a900` as HEAD and
`git status --porcelain` lists no modified tracked file, so the fix report's "No commit was made;
the working tree carries the fix" is stale (report nit, not a defect).

Read-only on the checkout: I read the diff, the code, the review/ledger files, ran focused tests,
and drove the **shipped binary** (`go build -o .scratch/rr-bin/webv2 ./cmd/webv2`, HEAD) against
scratch campaigns under the gitignored `.scratch/`. No tracked file, index or HEAD was touched.

## Finding Verdicts

**I-1 — the feed validated a drop's declared input_artifacts and then discarded the request, so no
`model.request` event was ever written on the sanctioned transport — ADDRESSED.**

- Accepted path writes the request: `internal/feed/feed.go:85`
  (`if err := boundary.LogRequest(c, request); err != nil { return "", err }`), after
  `invocationRequest` (`:77`) and the output-shape read (`:81-84`), before
  `findings.IngestHypothesis` (`:88`).
- One writer, not two: `internal/boundary/ingest.go:99` (`campaign.Log("model.request", nil,
  &request)`) is the tree's only non-test write of that type (`rg '"model\.request"'` → writer
  `boundary/ingest.go:99`; readers `audit/sections/v16coverage.go:185`,
  `sft/backfill.go:123`, `trajectory/trajectory.go:35`). `logHypothesisRequest`
  (`ingest.go:61-67`) is now a three-line kind guard that delegates; its old body moved wholesale
  into `LogRequest` (`ingest.go:82-101`) — no copied logic, no second validation rule.
- Covering tests exist and are the ones I ran:
  `internal/cli/cmd_run_feed_test.go:222` (`TestRunFeedRecordsTheAcceptedInvocation`, asserting
  exactly one `model.request` with the declared set and the feed-derived cited set via
  `requireOneDeclaredRequest`, then `audit --json` via `requireCoverageDeclared` `:276`), and
  `internal/feed/feed_test.go:162` (package-level twin + `requireTrajectoryOK`). The refusal test
  was strengthened with the order assertion at `cmd_run_feed_test.go:212` (`requested != 0`).

**(a) exactly-once — one event, not two, not zero.** End-to-end through the shipped binary on a
real accepted drop (a real drop file from `.scratch/fr-root`, declaration made to cover the cited
bundle):

```
$ webv2 --root …/rr-e2e/root run --feed …/C-e3e4267165/inbox/discovery.json
exit=0  ingested F-7db027650b63 from …/inbox/discovery.json (stage discovery, contract model_request + finding)
events: campaign.created 1 | model.request 1 | finding.ingested 1 | finding.intake_warnings 1
        seq 0 campaign.created, seq 1 model.request, seq 2 finding.ingested, seq 3 finding.intake_warnings
```

`model.request` count = **1** (the CLI test's own `len(reqs) != 1` assertion agrees, and
`cmd_run_feed_test.go:252` would fail on 2). The output ingest cannot add a second one:
`findings.IngestHypothesis` writes only `finding.ingested` / `finding.intake_warnings`
(`internal/findings/ingest.go:429`, `:452`), and `runFeed` returns before the pipeline
(`internal/cli/cmd_run.go:69`). No other production caller writes the type.

**(b) ordering and refusal semantics — request before ingest; every refusal writes zero
`model.request`.** All five refusal branches in `invocationRequest`
(`feed/feed.go:106-134`: no request record, no bundle, `context_hash` mismatch, undeclared set,
out-of-set citation) return before `:85`, as does the no-output-payload branch (`:82`). Verified
against the shipped binary, one fresh campaign per variant:

```
out-of-set citation      exit=1  model.request 0  model.rejected 1
no request record        exit=1  model.request 0  model.rejected 1
context_hash mismatch    exit=1  model.request 0  model.rejected 0   (plain refusal, pre-existing)
no context bundle        exit=1  model.request 0  model.rejected 0   (plain refusal, pre-existing)
```

The orphan direction is real and I exercised it: a valid declaration with an invalid response
payload (`title` deleted) gives `exit=1`, `model.request 1`, `model.rejected 0`,
`finding.ingested 0`. **That is honest, not a defect.** The event records the *invocation*, which
was validated and accepted — the fact v1.6 Part 1 makes a ledger fact and the fact
`v16_coverage` counts. The alternative ordering (log after the finding) fails worse: a log failure
there would refuse a drop whose finding had already landed, and a refused response would erase an
accepted declaration. The orphan row also does not turn anything red — `webv2 verify <C>` on that
campaign: `{"events": 2, "ok": true, "problems": [], "chained": 2}` (the row satisfies
`trajectory.schema.json#model_request`, and its `ref` is nil so no finding probe fires).

**(c) the exported `boundary.LogRequest` — same writer, no cycle, minimal widening.** It *is* the
writer `logHypothesisRequest` used to be (that function now returns `LogRequest(...)`,
`ingest.go:66`), so "one `model.request` per accepted request" is one function. No import cycle:
`internal/feed` already imported `internal/boundary` (`feed/feed.go:19`) and `boundary` imports
no feed package (`rg 'websec/internal/feed' internal/boundary/*.go` → none); `go build`/tests
compile. The export is required cross-package and sits beside the already-exported
`ValidateRequest` / `InputSetRecordable` / `RecordInputSetRefusal`, which exist for the same
reason (`boundary/boundary.go:343-348`) — not a gratuitous widening. One observation, not a
defect: the feed path now runs `ValidateRequest` twice on the same value
(`feed/feed.go:132`, then `boundary/ingest.go:83`) — the same pure function, same value, so it is
redundant work, not a second validation path; `LogRequest`'s `model.rejected` branch is
unreachable from the feed because the request is already admitted.

**(d) `v16_coverage` on a CLI-built campaign — 1, not 0.** `audit --json` over the campaign built
above by `init` + `run --feed` only:

```
v16_coverage.ok = True   checked = 1
model_requests = 1   requests_declared = 1   model_rejections = 0
audit ok = True   all sections ok: True   webv2 verify: ok true, 4 events, chained 4
```

The fix report's mutation evidence is consistent with what I measured: the counter is now driven
by the shipped transport, not only by an out-of-repo library caller.

**(e) byte-pinned surfaces — none moved, so none is missing its test.** The diff touches five
files (`docs/gates/v16-P1.md`, `internal/boundary/ingest.go`, `internal/cli/cmd_run_feed_test.go`,
`internal/feed/feed.go`, `internal/feed/feed_test.go`) — no help text (`internal/cli/cmd_run.go` is
untouched), no golden fixture, no asset (`assets/testdata/asset_manifest.json` is unaffected).
Checked the surfaces the new event could have moved indirectly: `rg -- '--feed'` finds no
invocation in `scripts/` (golden recipes, `verify-full.sh`, `p2-docker-e2e.sh` never drive the
feed), `scripts/check-golden.py` validates 15 audit sections and the event chain but no per-type
count, and `internal/feed` is imported by exactly one package (`internal/cli/cmd_run.go`), whose
only feed-aware test files are the two the diff updated.

**I-2 — the gate record asserted `task-9-review.md` does not exist when it does — ADDRESSED.**

- §8.2 (`docs/gates/v16-P1.md:442-451`) now states the review exists, with the two Important
  findings, the fix round and the re-review verdict. Every claim checks out against the files it
  cites: base/head `377ba14a → f854a599` (`task-9-review.md:3`), I1 chain-materialized population
  (`task-9-review.md:105`), I2 `p2-docker-e2e.sh` rendered-count pin
  (`task-9-review.md:123-125`), fix round `f854a599..9ff35798` (`progress.md:30`), and the quoted
  verdict "All findings addressed, no new Critical/Important breakage — **clean (0 open)**"
  (`task-9-rereview.md:132`, verbatim).
- §8.7 (`:467-469`) replaces "**Task 9 has no review file**" with the ❌ → two Important → fixed in
  `9ff35798` → re-review clean line. No stale claim survives: `rg 'task-9|Task 9|review file'` over
  the document returns only the corrected passages.
- §5's new provenance sentence (`:276-281`) is **verified, not taken on faith**: the pasted object
  is reproducible. Rebuilding at HEAD and re-running the recorded command
  (`webv2 --root .scratch/v16camp/root audit C-v16p1gate --json`) returns the same campaign
  (`ok: true`, `checked: 3`, `problems: []`) with every counter identical — `findings 3`,
  `model_requests 3`, `requests_declared 3`, `model_rejections 1`, the rest as printed — and the
  same section order with `v16_coverage` last. The "produced at `f854a599`" claim is also
  consistent with the artifact: `.scratch/bin/webv2` is stamped 18:16:23, between `f854a599`
  (18:12:09) and `9ff35798` (18:36:49).

## New Breakage in the Fix Diff

**None Critical or Important.** The three things I looked at hardest, all clean:

- No double-write and no lost write on the accepted path (a); refusals still write zero requests
  (b); the new row satisfies the trajectory contract and turns no section red — `audit ok: true`,
  every section ok, `verify ok: true` on both the accepted-drop and the orphan-request campaigns.
- The boundary transport's behaviour is unchanged: `logHypothesisRequest` keeps its non-object
  early return and delegates to the identical body; `./internal/boundary/...` passes (1.7s).
- The other in-tree reader of `model.request`, the SFT backfill
  (`internal/sft/backfill.go:100-140`), keys off a matching `model.response` with the finding ref
  and returns early without one, so the new response-less row cannot change SFT provenance.

Test evidence I ran myself at HEAD (not the report's): `GOCACHE=$PWD/.scratch/gocache go test
./internal/feed/... ./internal/boundary/... ./internal/cli/... -count=1` → `ok` for all three
(`feed 0.031s`, `boundary 1.708s`, `cli 33.949s`), and the focused `-run
'TestFeedRecordsTheAcceptedInvocation|TestRunFeed' -v` run → every listed test PASS.

## Out-of-Scope Observations

Non-blocking; for the final review's ledger, not for another fix wave.

1. **Minor — the response-side refusal is not a ledger event on the feed path.** With the new
   row, a refused *response* now leaves `model.request` with no counterpart and no
   `model.rejected` (measured above: `1 / 0 / 0`), whereas `boundary.IngestModelHypothesis`
   validates the response first and records `model.rejected` *without* ever logging a request
   (`boundary/ingest.go:25-34`). The asymmetry predates this diff — the feed never called
   `ValidateResponse` or `RecordRejection` — and the fix neither caused nor worsened it beyond
   making an accepted invocation visible. Flagged only because the two transports now disagree
   about what "accepted declaration, refused response" looks like on the ledger.
2. **Minor — the embedded RUNBOOK does not mention the accepted-side event.**
   `assets/runbook/RUNBOOK.md:198-215` describes the drop-file handoff and its refusal recording
   but not that an accepted invocation is now recorded as `model.request`. Nothing there is
   falsified ("validated before the output is ingested" still holds), and the file is manifest-
   pinned, so touching it would require `scripts/sync-asset-manifest.py`. Documentation
   completeness only.
3. **Nit — fix-report accuracy.** Beyond the stale "No commit was made", the report claims no
   `x, _ :=` discard was introduced, while the new test opens with
   `fs, _ := FeedStageFor("discovery")` (`internal/feed/feed_test.go:168`). It matches the two
   pre-existing occurrences in the same file (`:232`, `:259`), so it is house style, not a defect —
   the report sentence is just wrong.

## Verdict

**Fix round: All findings addressed, no new Critical/Important breakage — clean (0 open).**
I-1 and I-2 are both closed with file:line evidence and executed end-to-end verification through
the shipped binary; the three deferred observations above are Minor and out of this diff's scope.
