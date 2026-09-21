# Final fix report — v1.6 P1/P2 record-and-evidence

Fix wave for the two **Important** findings of `final-review.md`. The 28 deferred minors
(including the three flagged opportunistic) are untouched. No commit was made; the working
tree carries the fix.

---

## I-1 — the file-drop transport now records the request it validated — **FIXED**

### What was wrong (confirmed by reading the code, not the review)

`internal/feed/feed.go` validated the drop's declaration and threw the record away.
`invocationRequest` derived `context_artifacts` from the shipped bundle and ran
`boundary.ValidateRequest`, but `ingestDiscovery` handed only `doc["output"]` to
`findings.IngestHypothesis`, which writes `finding.ingested` and no `model.request`
(`internal/findings/ingest.go:428`). The ledger's only `model.request` writer,
`boundary.IngestModelHypothesis` → `logHypothesisRequest`
(`internal/boundary/ingest.go:82`), had **no non-test caller in the tree** — exactly as the
review reported. Consequence: `v16_coverage.coverage.model_requests` and
`requests_declared` were a permanent `0` on every campaign the CLI can build, so the
section built to make a stopped writer visible could not distinguish "no model stage yet"
from "the writer is gone".

I did **not** conclude that the request must stay unlogged. The opposite: the declaration
is the load-bearing artifact of this transport (non-negotiable 4), and the feed is the one
production caller `IngestModelHypothesis` was written for. Recording it is the plan's
intent, not a new feature.

### What changed

1. `internal/boundary/ingest.go` — the writer is now reachable from both transports.
   `logHypothesisRequest` is a three-line guard that delegates to a new exported
   `boundary.LogRequest(c, request)`, which keeps the validate-before-write posture and the
   `InputSetRecordable` admission test for the declared-input-set refusal. Behaviour of the
   boundary path is byte-identical (its callers' tests still pass); the export exists so
   "one `model.request` per accepted request" is a fact about **one function** rather than a
   convention two transports must each remember.
2. `internal/feed/feed.go` — `ingestDiscovery` calls `boundary.LogRequest(c, request)` on
   the accepted path, after the invocation validated and after the drop's shape was read,
   and **before** `findings.IngestHypothesis`.

### The order rule (and why this is the honest one)

- Every refusal in `invocationRequest` (no request record, no context bundle,
  `context_hash` mismatch, undeclared set, out-of-set citation) returns **before** the log
  line, so a refused drop keeps the behaviour the task reviews pinned: one `model.rejected`
  event and **no** `model.request`. The new CLI assertion pins that direction too.
- The event belongs to the **invocation**, so it is written when the declaration has been
  accepted and checked — a downstream ingest failure must not erase the fact that the
  declaration was accepted (that is the fact Task 9 counts).
- The ledger write precedes the finding write, so a log that cannot land fails the drop
  instead of leaving a finding nothing declares.

The alternative (log only after the finding is written) was rejected: a failed log there
would report a refusal for a drop that had already landed, and a drop whose output was
rejected would leave the accepted, validated declaration unrecorded — the original gap
narrowed rather than closed.

### Covering tests (both fail without the fix — see mutation below)

- `internal/cli/cmd_run_feed_test.go::TestRunFeedRecordsTheAcceptedInvocation` — the
  requested CLI-level test: writes an accepted drop into the campaign inbox, drives
  `run --feed` through `cli.Run` (exit 0, `ingested F-…` printed), then asserts
  - exactly **one** `model.request` event exists and its `data.input_artifacts` is the
    declaration the drop made (`ART-aaaa1111`), with the feed-derived
    `context_artifacts` beside it (`requireOneDeclaredRequest`);
  - `audit --json` renders `v16_coverage` with `model_requests = 1` and
    `requests_declared = 1`, not 0 (`requireCoverageDeclared`).
- `internal/cli/cmd_run_feed_test.go::TestRunFeedRefusesAnOutOfSetDrop` — strengthened: the
  refusal still records exactly one `model.rejected` **and now asserts zero
  `model.request`** (the order half of the finding).
- `internal/feed/feed_test.go::TestFeedRecordsTheAcceptedInvocation` — package-level twin of
  the ledger assertion, plus `requireTrajectoryOK`: the new writer's row satisfies the
  contract `verify_trajectory` re-validates, so the fix cannot turn a healthy campaign red.

### Mutation evidence (proves the tests would have caught it)

Unwiring the call (deleting the `boundary.LogRequest` block from `ingestDiscovery`) and
running the covering tests:

```
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/feed/... ./internal/cli/... \
    -run 'TestFeedRecordsTheAcceptedInvocation|TestRunFeedRecordsTheAcceptedInvocation|TestRunFeedRefusesAnOutOfSetDrop' -count=1
--- FAIL: TestFeedRecordsTheAcceptedInvocation (0.01s)
    feed_test.go:183: model.request events = 0, want exactly 1 for an accepted drop (the declaration is a ledger fact)
FAIL	websec/internal/feed	0.017s
--- FAIL: TestRunFeedRecordsTheAcceptedInvocation (0.01s)
    cmd_run_feed_test.go:227: model.request events = 0, want exactly 1 for an accepted drop (the declaration is a ledger fact)
FAIL	websec/internal/cli	0.029s
```

With the ledger assertion temporarily skipped so the **coverage** half runs under the same
mutation, the reviewer's exact symptom reproduces through the CLI:

```
--- FAIL: TestRunFeedRecordsTheAcceptedInvocation (0.01s)
    cmd_run_feed_test.go:230: model_requests = 0, want 1
FAIL	websec/internal/cli	0.022s
```

The wiring and the test were then restored verbatim (`rg -n 'MUTATION' …` → no matches) and
the same selection passes.

---

## I-2 — the gate record's Task 9 review history — **FIXED**

`docs/gates/v16-P1.md` §8.2 and §8.7 asserted that `task-9-review.md` "does not exist" and
that "Task 9 has no review file". The file exists (`.superpowers/sdd/…/task-9-review.md`,
13.0K) and `progress.md` records the review and its fix round. I read `task-9-review.md` and
`task-9-rereview.md` before writing, so the sentence states the real position:

- §8.2 now reads: **`task-9-review.md` exists, and Task 9 WAS independently reviewed** —
  base `377ba14a` → head `f854a599`, two Important findings (I1 `listedFindings` did not
  enumerate chain-materialized super-findings, so they escaped all eight counters and the
  three impossible-state checks; I2 `scripts/p2-docker-e2e.sh` hard-asserted the pre-v1.6
  rendered count 14), **both fixed in Task 9's fix round** (`f854a599..9ff35798`, recorded
  in `progress.md`), re-review `task-9-rereview.md`: "All findings addressed, no new
  Critical/Important breakage — **clean (0 open)**". The entry also says the earlier
  statement was written before the review landed and is corrected here.
- §8.7 now reads "Task 9 ❌ → two Important findings (I1 chain-materialized population,
  I2 `p2-docker-e2e.sh` rendered-count pin), both fixed in `9ff35798`, re-review
  `task-9-rereview.md` clean (0 open)" in place of "**Task 9 has no review file** (see 2)".
- §5 gained the provenance sentence the review asked for: the pasted audit object was
  produced at HEAD `f854a599`, i.e. before the fix round the same commit range lands; it
  notes neither fix moves a counter in that campaign (no chain-materialized finding; I2 is a
  gate script), so the numbers read the same at `9ff35798`.

Deliberately **not** changed: §8.5 ("the harness contract is out of repo") stays true — a
real model stage still builds its request record outside this binary. The gate record
therefore needs no I-1 documentation change: with the fix, the record's
`requests_declared: 3` is no longer merely reproducible by a scratch program, it is the
behaviour of the shipped transport.

---

## Commands run, and their output

Only the packages the brief named were run; no `go test ./...`, no Docker, no network, no
model.

```
$ GOCACHE=$PWD/.scratch/gocache go build ./...                       # clean, no output
$ GOCACHE=$PWD/.scratch/gocache gofmt -l internal/feed internal/boundary internal/cli
                                                                    # empty
$ GOCACHE=$PWD/.scratch/gocache go vet ./internal/feed/... ./internal/boundary/... ./internal/cli/...
                                                                    # clean, no output
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/feed/... ./internal/boundary/... \
      ./internal/cli/... ./internal/audit/... ./internal/trajectory/... -count=1
ok  	websec/internal/feed	0.030s
ok  	websec/internal/boundary	1.823s
ok  	websec/internal/cli	34.666s
ok  	websec/internal/audit	0.436s
ok  	websec/internal/audit/sections	0.983s
ok  	websec/internal/trajectory	0.410s
```

New/strengthened tests, verbosely:

```
$ GOCACHE=$PWD/.scratch/gocache go test ./internal/feed/... ./internal/cli/... \
      -run 'TestFeedRecordsTheAcceptedInvocation|TestRunFeed' -count=1 -v
--- PASS: TestFeedRecordsTheAcceptedInvocation (0.01s)
--- PASS: TestRunFeedRefusesAnEmptyPath … TestRunFeedRefusesUnwiredStage …
--- PASS: TestRunFeedRefusesADropOutsideTheInbox … TestRunFeedIngestsADiscoveryDrop …
--- PASS: TestRunFeedCampaignPositionalMustAgree … TestRunFeedRefusesAnOutOfSetDrop …
--- PASS: TestRunFeedRecordsTheAcceptedInvocation (0.01s)
ok  	websec/internal/feed	0.021s
ok  	websec/internal/cli	0.037s
```

Working-tree surface (`git diff --stat`, no `git add`/`commit` run):

```
docs/gates/v16-P1.md              |  26 ++++++---
internal/boundary/ingest.go       |  17 ++++++
internal/cli/cmd_run_feed_test.go | 110 +++++++++++++++++++++++++++++++++++---
internal/feed/feed.go             |  21 ++++++--
internal/feed/feed_test.go        |  40 ++++++++++++++
5 files changed, 198 insertions(+), 16 deletions(-)
```

House lint: every function added or touched is well inside the limits (largest is
`requireOneDeclaredRequest`, 14 statements / 6 branches; `LogRequest` 7 statements; no
`x, _, :=` discard was introduced — the two `run(...)` calls in the tests I touched now
consume all three returns).
