# Task 9 re-review — fix round 1 (`f854a599..9ff35798`)

Scoped re-review of the two Important findings from `task-9-review.md`. Read-only on the
checkout (HEAD `9ff35798`, tracked tree clean). Commands run: focused Go tests, `gofmt -l`,
`bash -n`, `sync-asset-manifest.py --check`, a `go build` into `.scratch/rr-bin`, one real
`audit --json` render of the docker campaign's shape, and the shipped step-4 assertion block
extracted with `sed` and executed against that render.

### Finding Verdicts

- **I1 — `listedFindings` enumerated only `finding.ingested` refs, so chain-materialized
  super-findings were counted by none of the eight counters and escaped the impossible-state
  checks** — **ADDRESSED**.
  - `internal/audit/sections/v16coverage.go:228-250` now enumerates `v16FindingIDs(events)`
    (`:252-264`) = `refsOf(events,"finding.ingested") ∪ superOf(events)` — exactly the pair
    `projectionFindings` treats as legitimate (`internal/audit/sections/projection.go:109-110`,
    checked at `:122-124`). Every enumerated row goes through `countFinding`
    (`v16coverage.go:62-64`) → all six finding counters plus `checkImpossible` (`:82-89`,
    `:128-143`), so the chain row now feeds every counter and every law check.
  - **(a) can a finding be neither an ingest ref nor a super id?** No producer was found. The
    only writer of `finding.ingested` is `internal/findings/ingest.go:429`; the only other
    creator of a finding file is the PROVEN chain branch — `internal/chainengine/materialize.go:116-131`
    (bare `findings.SaveFinding`, then a `chain.materialized` event carrying
    `data.super_finding`). The unproven branch writes **no** super-finding and no
    `super_finding` key (`materialize.go:94-103`, `:129-131`, event type `:132-135`), so
    `superOf`'s `chain.materialized`-only filter is exactly right. Every other `SaveFinding`
    caller loads the finding first and mutates it — `transitions_dedup.go:22`,
    `ingest_evidence.go:67`, `assumptions.go:61,260`, `exploitability.go:52`,
    `adversarial.go:146`, `immunize.go:197`, `maximization_ladder_store.go:173`,
    `maximization_ladder_disposition.go:76,166,228,297`, `reproduction_attempt.go:264`,
    `cli/cmd_verify_postpatch.go:60` — so no creation path is missed.
  - No new false RED on real chains: the super-finding carries `evidence: []`, no
    `deployment_facts` and no `replay` (`materialize_doc.go:119-121`), so none of the three
    impossible-state laws can fire on it; the union adds only +1 to `findings`/`checked`.
    `superOf` drops empty ids (`projection.go:355-357`).
  - Regression test is real and would have caught it:
    `TestV16CoverageCountsChainMaterializedSuperFindings`
    (`internal/audit/sections/v16coverage_test.go:361-388`) materializes a two-member chain
    through the real writer, first asserts the super id is **not** in the ingested refs
    (`:363-366`, fails loudly if the premise changes), then requires `checked == 3`,
    `coverage.findings == 3`, `coverage.confirmed == 2` (`:376-377`). Pre-fix, only the two
    members are enumerated, so the assertion fails at 2 — the report's mutation claim is
    consistent with the code. Ran it: PASS.
  - No existing capture changes: 0 `chain.materialized` events in the golden campaign trees
    and 0 in the `scripts/legacy` fixture (which carries 2 `finding.ingested`).

- **I2 — `scripts/p2-docker-e2e.sh` hard-asserted the pre-v1.6 rendered count (14)** —
  **ADDRESSED**.
  - `scripts/p2-docker-e2e.sh:330-331` is now `if len(secs) != 15` / `"want 15"`, with the
    comment re-pinned at `:321-323` ("17 registered; `eval` and `price_table` are
    presence-gated, `v16_coverage` is unconditional and registered last").
  - **(c) is 15 the count this campaign shape renders?** Yes, verified from the code and from a
    real render, not from the report. `register.go:26-47` registers 17 names (pinned by
    `internal/audit/audit_test.go:85`); the only sections that can `ErrSkip` are `eval`
    (`internal/audit/sections/eval.go:140`, gate = `evalscore.Score`'s `GoldTotal == 0`,
    `internal/evalscore/evalscore.go:431-433` — the docker program `P2Docker` matches none of
    the `ES01..ES19` suite programs) and `price_table`
    (`internal/audit/sections/pricetable.go:34` — no `prices.json` and no `price.set` events;
    `prices.json` has exactly one writer, `pricing.SetPrice` ← `cli/cmd_price.go:68`, and the
    docker script contains no `price`/`eval` step at all). 17 − 2 = 15.
    Reproduction: `go build -o .scratch/rr-bin/webv2 ./cmd/webv2`, then
    `init --program P2Docker` → `snap` → `ingest scripts/golden/h1-withdraw-double-count.json
    --stage docker-e2e --trajectory code` → `audit --json` (the same campaign shape
    `run_campaign` builds, `p2-docker-e2e.sh:203-270`; the omitted container legs touch no
    presence gate) → `ok=true`, **15** sections, order ending `probe_surface, unpriceable,
    v16_coverage`, with `eval` and `price_table` absent. Independently corroborated by
    `internal/audit/eval_gate_test.go:76` (15 for an unmatched campaign) and
    `scripts/verify-full.sh:261-290` (14 base + `v16_coverage` required).
  - **Assertion kept meaningful, not loosened:** the shipped step-4 block, extracted verbatim
    with `sed` and run against that real report, yields `{"fails": [], "sections": 15}`; the
    pre-fix pin (`!= 14`) yields `{"fails": ["15 audit sections, want 14"]}` (the old gate was
    genuinely red); the same report with `v16_coverage` deleted yields
    `{"fails": ["14 audit sections, want 15"]}`. Strict equality is retained.

### New Breakage in the Fix Diff

**None (no Critical, no Important).** The diff is exactly 4 files (stat in the package:
`docs/gates/v16-P1.md`, `v16coverage.go`, `v16coverage_test.go`, `p2-docker-e2e.sh`); HEAD is
`9ff35798` and no tracked file is modified, so what was read is the fix. Checks on the diff
itself:

- **(b) no double counting.** `v16FindingIDs` is one `map[string]struct{}` union
  (`v16coverage.go:258-263`): an id present as both an ingested ref and a super id is a single
  key, ids are sorted (`:237`) and each is loaded exactly once (`:239-248`); `checked` and
  `coverage.findings` are both `len(rows)` (`:60`, `:199`) and `countFinding` runs once per row.
- Test-only `chainengine` import creates no cycle (`chainengine` imports
  findings/capabilities/state/validation only) — the package builds and its tests pass.
- `gofmt -l internal/audit/sections/v16coverage.go internal/audit/sections/v16coverage_test.go`
  → empty; `bash -n scripts/p2-docker-e2e.sh` → OK.
- `GOCACHE=$PWD/.scratch/gocache go test ./internal/audit/... -count=1` → `ok` ×2;
  `-run TestV16Coverage -v` → 5/5 PASS including the new test.
- `python3 scripts/sync-asset-manifest.py --check` → "asset manifest is current" (the added
  doc does not disturb the manifest).
- **(d) the extra file.** `docs/gates/v16-P1.md` is present (459 lines, `git show --stat HEAD`)
  and ledgered as Task 11 in `progress.md`. Consistency, not prose: every test it names exists
  in the tree (spot-checked 13 of them, e.g. `TestPolicyBooleansAreReferencedByTheirGate`,
  `TestInputSetRefusalIsRecorded`, `TestRunFeedRefusesAnOutOfSetDrop`,
  `TestImpactReplayableComputesAndRefusesOneRound`), its §5 section order matches the render I
  reproduced, and its stated absences hold (`docs/gates/v16-P2-spike.md` and
  `scripts/v16-spike.sh` are indeed absent). Nothing in it was changed by this diff beyond its
  addition.

### Out-of-Scope Observations

Non-blocking; no finding here extends the loop.

- **(a) residual, pre-existing and unchanged by this diff.** A finding file with neither an
  `finding.ingested` ref nor a `chain.materialized` super id — a hand-planted file, or an
  event-less legacy campaign — is still not enumerated, while `sections.findings.checked`
  (`internal/audit/sections/findings.go:33-40`) and `findings.LoadLiveFindings`
  (`internal/findings/storage.go:94-108`) glob it. That set is what `projectionFindings` calls
  illegitimate (`projection.go:124-128`), flagged RED whenever its gate is open
  (`projection.go:111`); only the presence-gated event-less case leaves both readers silent, and
  it is the deliberate "the projection's ids, not a directory glob" choice documented at
  `v16coverage.go:220-227`. No gate fixture reaches it.
- **Minor (test depth).** The new test pins the chain row's *population* but not that the
  impossible-state checks actually fire on it (no fixture chain row carries an unpinned fact or
  an unprofitable replay). The structural path `countFinding` → `checkImpossible`
  (`v16coverage.go:82-89`) makes it true today; nothing would notice a future early-return that
  skipped it.
- **Minor (prose, already ledgered by the prior review as M1/M7).** Stale rendered-count claims
  outside this diff: `README.md:62,132` ("14 sections here (16 registered)"),
  `scripts/legacy/README.md:23`, `scripts/golden.sh:9`. Note `scripts/check-golden.py:14,216`
  ("all 15 rendered sections") is in fact correct now — 15 required plus optional `price_table`.
- **Minor (record staleness).** `docs/gates/v16-P1.md` §8.2/§8.7 still say "`task-9-review.md`
  does not exist / Task 9 has no review file" and stamp HEAD `f854a599`; both were true when the
  record was authored, and the review file postdates the commit (18:26 > 18:12), so the record
  is now stale on that one point. It does not affect the code or the gates.

### Verdict

**Fix round:** All findings addressed, no new Critical/Important breakage — **clean (0 open)**.
