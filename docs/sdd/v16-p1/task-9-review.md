# Task 9 review — `v16_coverage` (v1.6 P1/P2 record coverage)

Base `377ba14a` → head `f854a599`, one commit, 12 files, +999/−218. Read-only review;
the only commands run were focused tests, `python3 scripts/sync-asset-manifest.py --check`,
`bash -n`, `py_compile`, and an in-memory/temp-dir replay of the old vs new
`check-golden.py` (no checkout mutation).

### Spec Compliance

- ❌ **Issues found** — one gap: `listedFindings` does not enumerate the finding set the
  plan names ("the projection's finding ids"), so a class of live findings is invisible to
  all eight counters and to all three impossible-state checks (I1 below). Everything else
  the brief demands is present and correct:
  - all eight fields are counted **from their real sources** (not faked from finding rows) —
    verified field-by-field against the writers: `deployment_facts` (`fact_read.go:115-122`),
    `poc_tier` on evidence (`poc_tier.go:40-47`), `replay` (`risk/replay.go:108`),
    `fork_dependence` (`fork_dependence.go:54`), `origin_stage`/`contributing_stages`
    (`ingest.go:139-145`), `review_sessions` from **`campaign_state`** via `State()`
    (`reviewsession.go:16,44`), and `input_artifacts` from **`model.request` events**
    (`boundary/ingest.go:82` + `boundary.go:245`). `v16coverage.go:166-195` reads
    `proj`/`events` for exactly the two non-finding fields — no finding-row stand-in.
  - `problems` carries exactly the three impossible states (`v16coverage.go:128-145`), each
    reusing the writers' own law: `findings.ValidatePocTierOrder` (`poc_tier.go:64`) and
    `risk.ValidateReplayProfitability` (`risk/replay.go:72`, which honours the
    `replay_blockers` escape at :79-81 — so a *legal* unprofitable replay with a blocker is
    not false-flagged), plus the inline `block <= 0` scan. Messages are prefixed
    `v16_coverage:` (`:147-151`); section key order is the house shape
    (`checked, problems, ok`, +`coverage`), matching `unpriceable.go:37-39`.
  - the three impossible-state rows are written **directly**, with no public setter and no
    weakened guard (see Strengths).
  - registered **last** (`register.go:47`, appended after `price_table:43`), section appended
    at the END of `RegisterAll`, never interleaved.
  - assets: `RUNBOOK.md` documents the section and `sync-asset-manifest.py` was re-run —
    I recomputed the manifest entry: actual `0d4bfb55…`/128477 == manifest
    (`assets/testdata/asset_manifest.json` packs.runbook), and `--check` prints
    "asset manifest is current".
- ⚠️ **Cannot verify from the diff (1):** the reported "byte-identical output on 52+14
  fixtures" for the `check-golden.py` refactor cannot be reproduced as stated, because the
  checked-in `.scratch/golden` captures **predate this commit** (running the new script
  against them is RED: `step 07/164/194 audit-json: missing audit section(s): v16_coverage`).
  I substituted a stronger, isolated measurement (see Verification), but a real
  `scripts/golden.sh` re-run — which regenerates the captures — is the outstanding
  end-to-end validation for the controller.

### Verification performed

- `GOCACHE=$PWD/.scratch/gocache go test ./internal/audit/sections -run TestV16Coverage -count=1 -v`
  → 4/4 PASS (the two load-bearing properties are exercised by real writers, not mocks:
  `reviewsession.Start`, `boundary.RecordInputSetRefusal`, `boundary.BuildRequest`,
  `findings.IngestHypothesis` + the Task 5-8 setters).
- **check-golden.py equivalence, measured three ways.** I extracted the pre-change script
  (`git show 377ba14a:scripts/check-golden.py`), the head script, and a "refactor-only"
  variant (head with `EXPECTED_SECTIONS` reverted to the old 15 names, so only the
  `core/tail → OPTIONAL_SECTIONS` rewrite differs), then ran all three as subprocesses:
  (a) against the **real 588-capture golden fixture set** — old vs refactor-only:
  byte-identical stdout/stderr/exit (rc 0, 1063 bytes, zero diffs); (b) against **25
  synthetic scenarios** (missing/extra/out-of-order/not-JSON/not-object audit reports;
  missing state file, missing events file, bad JSON line, bad `prev_hash`, missing
  `event_hash`; sites=0, missing axis, extra axis, blind axis firing, blind without
  `blind_total`, rows axis at 0, unreadable probes JSON; report without the section /
  without the reason / without the override; exit mismatch; missing output marker) —
  byte-identical on all 25; (c) head vs refactor-only differs **only** in the four
  section-shape scenarios, and exactly as intended: a 15-section report without
  `v16_coverage` now fails with `missing audit section(s): v16_coverage` (rc 1), while
  14 + `v16_coverage` and 14 + `price_table` + `v16_coverage` pass (rc 0). Failure-message
  order, the `GOLDEN RED — failures:` block and exit code are preserved.
- No false RED on real campaigns: the three checks flag 0 of the 7 findings in the golden
  campaign tree and 0 of the 2 in `scripts/legacy/` (so verify-full step 9's legacy audit
  and the golden audits stay green).
- `python3 -m py_compile scripts/check-golden.py`, `bash -n scripts/verify-full.sh` → OK.

### Strengths

- The direct-write fixture is honest, and its premise is **true**: `finding.schema.json`
  really carries `deployment_facts.block: {"type":"integer","minimum":1}`, `SaveFinding`
  really validates (`storage.go:30`), and `factReadChecked` really refuses `block <= 0`
  (`fact_read.go:88-91`). `coverageWriteDirect` (`v16coverage_test.go:133-176`) asserts the
  refusal and `t.Fatal`s with "the finding schema accepted an unpinned deployment fact" if
  it ever stops holding — the fixture fails loudly rather than silently weakening. The
  explicit `coverageRow.direct` flag makes the bypass visible at each call site, and no
  public setter was used for any of the three rows.
- The replay row cannot be produced legally either: `RecordReplay` validates before writing
  (`replay.go:94`), and the only other caller of `SetReplayAssumptions`
  (`cmd_impact.go:360`) validates immediately after — so stripping blockers off a recorded
  unprofitable replay is not a public path.
- The extra fourth test (`TestV16CoverageCountsTheDeclaredInputSets`) closes a real hole in
  the brief's own sketch: the brief's second test asserts `model_requests == 0`, which would
  pass even if the event half were never counted — the silent-rot failure the brief's point 1
  is about. The new test drives the real `boundary` writers and asserts
  `requests_declared == 1` / `model_rejections == 1`.
- Deterministic: no `time.Now()`, no raw UUID; ids are sorted (`v16coverage.go:231`) and
  problems are appended per finding in a fixed check order; counters are emitted in a pinned
  order (`:34-41`) so the rendered report does not depend on Go map iteration.
- Every counter is emitted even at zero (`coverageValue`), so "the field stopped being
  written" is a visible `0` rather than an absent key — the point of the section.

### Issues

#### Critical (Must Fix)

None.

#### Important (Should Fix)

- **I1 — `listedFindings` misses chain-materialized findings, so the one reader has a blind
  spot.** `internal/audit/sections/v16coverage.go:222-245` builds its row set from
  `refsOf(events, "finding.ingested")` only. The audit's own projection section defines a
  legitimate on-disk finding as `finding.ingested` **∪** `chain.materialized`
  `data.super_finding` (`projection.go:104-130`; the helper `superOf` already exists at
  `projection.go:347-355`), and `chainengine` writes that super-finding with a bare
  `findings.SaveFinding` + a `chain.materialized` event and **no** `finding.ingested`
  (`materialize.go:112-137`, status `"CHAIN"`, `materialize_doc.go:112`). `"CHAIN"` is not in
  the junk set (`v16JunkStatus`, `:248-251`; same set as `storage.go:101-104`), so every
  other reader counts it — `sections.findings.checked` globs *all* files
  (`findings.go:33-35`) — while `v16_coverage.coverage.findings` silently omits it, and none
  of the three impossible-state checks ever run on it. This is precisely the "field with no
  reader" failure the section exists to catch, one level up, and it is reachable through a
  shipped verb (`webv2 chain <campaign> <f> <f> …`, `cmd_chain.go:38-52`). Fix is two lines:
  union `refsOf(events, "finding.ingested")` with `superOf(events)` in `listedFindings`
  (and say so in the doc comment, which currently claims "the projection" while reading half
  of it). Not exercised by any current test — the golden tree and the legacy fixture contain
  0 chain super-findings — which is exactly why it will not be noticed by a green suite.
- **I2 — `scripts/p2-docker-e2e.sh` still hard-asserts the pre-v1.6 rendered count.**
  `scripts/p2-docker-e2e.sh:328-330` fails the docker E2E gate with
  `f"{len(secs)} audit sections, want 14"`; with `v16_coverage` unconditional the step-10
  audit now renders 15, so that gate is red on the next run (comment at :321 is stale too).
  This is the same class as the two gate scripts this commit *did* update
  (`check-golden.py`, `verify-full.sh:p2_sections_ok`) and the same class the plan's file
  list did not enumerate — so it reads as a miss rather than a deliberate exclusion. It is
  outside the 13-step gate (README.md:225) and cannot be run here (no Docker), but it is a
  shipped, documented gate (`README.md:45,131`). Fix: `14 → 15` and the comment.

#### Minor (Nice to Have)

- **M1 — stale counts inside the files this commit touched.** `scripts/check-golden.py:14`
  and `:216` still say "all **15** rendered sections" while `EXPECTED_SECTIONS` now carries
  16 names (the new comment at `:32-41` says the registry carries 17). `scripts/golden.sh:9`
  still says "14 audit sections". Same-file drift, one-line fixes.
- **M2 — the ledger is read and parsed twice per audit.** `listedFindings` calls
  `c.Events()` (`v16coverage.go:223`) and `V16Coverage` calls it again (`:54`); `Events()`
  re-reads and re-parses the whole log with no cache (`state/eventlog_read.go:37-57`). Pass
  the slice in. Cosmetic today; it doubles the new section's I/O on a 179-step campaign.
- **M3 — the "refused by construction" claim is 2/3 airtight.** The file header
  (`:10-15`) and the fixture comment (`v16coverage_test.go:340-350`) say the write paths
  cannot produce these states at all. True for the unpinned fact and the unprofitable
  replay; for the tier it is enforced at mint (`reproduction_mint.go:87`, `cmd_mint.go:100`)
  but **not** in `findings.AddEvidence` (`ingest_evidence.go:12-79` has no
  `ValidatePocTierOrder` call; `v16coverage_test.go:376-385` is where the claim is written),
  and `SetForkDependence` (`fork_dependence.go:40-68`) can flip
  a finding to fork-dependent after a legal fork-independent maximized mint. The audit's
  flag is still *right* — the record then violates §2.2 as it stands — but the comment should
  say "violates the law on the record", not "unreachable". No code change needed.
- **M4 — RUNBOOK wording drops the fork-dependence qualifier.** `assets/runbook/RUNBOOK.md`
  (the `webv2 audit` line) describes the first impossible state as "a maximized tier with no
  existence tier under it"; `ValidatePocTierOrder` returns nil for fork-independent findings
  (`poc_tier.go:68-70`), so the doc is stricter than the code.
- **M5 — the ~200-line `check-golden.py` refactor is unrelated to this feature.** Only the
  `core = want[:-1] / tail = want[-1:]` → `OPTIONAL_SECTIONS` split was forced by appending
  `v16_coverage`; the `_check_state_file` / `_check_events_chain` / `_check_axis_*` /
  `_report_probe_axes` / `_override_argv` / `_check_disposition_lines` extractions are
  drive-by. I verified they are output-preserving (see Verification), so this is a
  reviewability/scope note, not a behaviour risk.
- **M6 — `contributing_stages` cannot rot independently.** `ingest.go:139-145` always sets
  it to `[origin_stage]`, so the counter tracks `origin_stage` exactly and can never reveal
  that the multi-stage list stopped being passed. Brief-mandated (the brief asserts the count
  is 1 for that reason); noted so the number is not over-read.
- **M7 — other stale rendered-count claims outside the brief's file list.**
  `README.md:62,132` ("14 sections here (16 registered)"), `scripts/legacy/README.md:23`
  ("all 14 rendered sections"). Not required by the plan, but they now contradict
  `verify-full.sh:21` which this commit updated.

### Assessment

**Task quality:** Needs fixes

**Reasoning:** The two load-bearing properties are genuinely met — all eight fields are read
from their real sources (the campaign_state array and the ledger events, not finding rows),
and the impossible-state rows are hand-written with a loud assertion that the guards still
refuse them, with no guard weakened. The single spec gap is that the row enumeration is
narrower than the plan's "the projection's ids": chain-materialized super-findings are
counted by every other reader and by none of these counters, and the miss is invisible to
the green suite. Alongside it, one shipped gate script (`p2-docker-e2e.sh`) was left pinning
the old rendered count. Both are small, targeted fixes; the `check-golden.py` refactor, the
oracle count changes and the asset sync are all verified correct.
