# Task 5–8 review — fact reads, PoC tiers, replay, fork dependence

Slice: `4b06c114..3644d53c` (single squashed commit `3644d53c`), 36 files, +1640/−54.
Method: full diff read; focused tests run for every claim I doubted (commands and output cited
below). No full-suite run (controller has it green).

## Verdicts

- **SPEC COMPLIANCE: ❌ Issues found** — every explicitly mandated step of all four briefs is
  present and tested; the failures are (a) one implementer-flagged deviation (Task 7's pinned
  `impact` help/usage/runbook surfaces) and (b) two gaps the briefs did not cover, both of which
  leave the new keys writable through `ingest` without the laws the same briefs declare
  load-bearing. Nothing mandated is missing; nothing unrequested was built beyond small,
  benign additions (listed under Strengths).
- **TASK QUALITY: Needs fixes** — the core implementation is solid (real tests, ledger/projection
  discipline, determinism pins respected, a deliberate and provenance-documented golden
  re-record), but a declared PoC tier can be silently dropped and a declared `fork_dependence`
  can bypass the reason/event law; both are small, local fixes.

Deviations from the briefs' literal text (checked individually; all behaviorally equivalent, none
a defect on its own): Task 5 passes 8 args where the brief's *Interfaces* line says 7 (its own
Step-1 test and Step-3 code pass 8 — the brief contradicts itself); Task 6 adds `pocTier` as a
trailing parameter on `MintReproEvidence`/`AttemptAndMint` (30 call sites) instead of threading it
through "the mint options struct it already carries" — no such struct exists; Task 6 fixes the
second caller in `exec_evidence.go` rather than `ingest.go:288` (the brief's line number is stale,
the real call site is `IngestExecRefEvidence`); Task 6's CLI test uses `t20Setup`, the helper the
existing mint tests actually use, not the brief's non-existent `mintTestExec`; Task 5 uses the
shared `argSpec` because `cmd_impact.go` (the brief's stated model) does not use it; Task 7's
test adds a `findings` import for its extra test.

Evidence base (all run with `GOCACHE=$PWD/.scratch/gocache`):

```
go build ./...                                   → ok
go vet ./internal/{findings,cli,risk,reproduction,orchestrator} → clean
go test ./internal/findings -run 'TestFactRead|TestPocTier|TestForkDependent|TestValidatePocTierOrder|TestForkDependence|TestSetForkDependence|TestIngestAttributesTheOriginStage' -count=1 → ok (9 PASS)
go test ./internal/risk -run 'TestComputeReplay|TestReplayProfitability|TestRecordReplay' -count=1 → ok (4 PASS)
go test ./internal/cli -run 'TestFactRead|TestForkDependence|TestMint|TestImpact|TestEveryCommandAnswersHelp|TestRunbook|TestIngestExample' -count=1 → ok
go test ./internal/reproduction -run 'TestAttemptAndMintRefusesMaximizedWithoutExistence|TestRollbackRestoresPriorAttemptState' -count=1 → ok (2 PASS)
go test ./internal/orchestrator -run TestGoldenVectors -count=1 → ok (1.03s) — the re-recorded oracles replay clean
go test ./assets/... -count=1 → ok (manifest)
```

Manifest hashes recomputed independently (not trusted from the report):

```
finding.schema.json  manifest 54822/e8d2d205d494  real 54822/e8d2d205d494  MATCH
RUNBOOK.md           manifest 127589/2c2b95456125  real 127589/2c2b95456125  MATCH
```

`rg -n "ord: [0-9]+," internal/cli/` sorted: the maximum before this slice was 93
(`cmd_review_session.go:253`); Task 5 took 94 (`cmd_fact_read.go:92`), Task 8 took 95
(`cmd_fork_dependence.go:67`) — "current maximum + 1" holds, both unique.

## Findings

### Critical (Must Fix)

None.

### Important (Should Fix)

**I-1 — Task 7: the whole `--replayable` family is missing from every pinned operator surface.**
`internal/cli/cmd_t23_shared.go:29-35` (`t23ImpactUsage`) and `:79-113` (`t23ImpactHelp`) are
unchanged, and `assets/runbook/RUNBOOK.md:1805` (the `impact` cheat-sheet line) is unchanged.
Verified by running the verb:

```
$ go run ./cmd/webv2 impact --help
usage: webv2 impact [-h] [--extractable EXTRACTABLE] [--max-loss MAX_LOSS]
                    ... [--actor ACTOR] [--reversibility REVERSIBILITY]
                    campaign finding
```

No `--replayable`, `--extractable-per-round`, `--gas-cost`, `--frequency`, `--rounds-run`,
`--replay-assumption`, `--replay-blocker`. Consequences: (i) the flags are undiscoverable from
the CLI and from the runbook (`runbook_test.go` passes only because `impact` is already
documented); (ii) every usage error for the verb — including the new `--gas-cost` "expected one
argument" path, which routes through `t23ValueArg(..., t23ImpactUsage, ...)` at
`cmd_impact.go:505` — prints a signature that omits flags the parser accepts. Sibling tasks all
did this correctly (mint: `cmd_dedup.go:159-168`, `mintHelp` in `cmd_mint.go:31-63`,
`RUNBOOK.md:1122`, `RUNBOOK.md:1799`), so the omission is an inconsistency, not a house style.
The brief's Step 7/Step 9 file list does not name `cmd_t23_shared.go` or `RUNBOOK.md`, so this is
**PLAN-MANDATED-ADJACENT** (a plan-shaped gap the implementer correctly flagged as
`[CONTROLLER: unresolved]`): the controller must decide whether to extend the scope by one file
plus the runbook, or accept an undocumented flag family. Fix: add the flags to both constants and
to the pinned `TestImpact*` expectations in the same commit.

**I-2 — Task 6+8: `ingest` is a second write path that bypasses the two new laws it makes
load-bearing.** `ingestBuildPayload` copies the caller's payload keys verbatim
(`internal/findings/ingest.go:117-118`) and only overwrites the fields it owns
(`finding_id`, `campaign_id`, `snapshot_ids`, `created_at`, `updated_at`, `status`,
`trajectory`, `evidence`/`risk`/`dedup`), so a payload-declared value survives to the write:

- `fork_dependence`: the key is now schema-legal (this commit, `finding.schema.json` top-level
  `properties.fork_dependence`, enum-checked), the whole payload is validated as a finding
  (`ingest.go:268`), and `ingestWriteFinding` writes it as-is (`ingest.go:359`). Result: a
  payload can declare `"fork_dependence": "none"` with **no `--reason` and no
  `finding.fork_dependence_set` event**, which is exactly the "an override without a recorded
  reason is a guess" law `SetForkDependence` enforces (`fork_dependence.go:46-48`), and it is
  exactly the class of hole Task 6's own brief names ("a spec-level invariant enforced at the
  argparse layer is not enforced"). It is not cosmetic: `ForkDependent` gates both
  `ExistenceFundingRequired` and the §2.2 maximized-ordering law (`poc_tier.go:64-76`).
- `poc_tier` on a non-`exec_ref` evidence item: the enum is now schema-legal on
  `definitions.evidence_item` (14 properties, `additionalProperties: false`), and pre-loaded
  non-execution items pass `checkExecGate` (`ingest_evidence_gate.go:61-63`: `!exec → return nil`;
  E4+ is refused at ingest, so the reachable case is an E0–E3 item), so a payload can land a
  `maximized` item — on evidence with no execution behind it at all — with no existence tier ever
  demonstrated; `PocTierOf` then reports `maximized` for that finding.

Fix (mirrors precedent in the same package): refuse a payload-declared `fork_dependence`
and `poc_tier` the way `IngestExecRefEvidence` already refuses a declared `type`/`level`
(`internal/findings/exec_evidence.go:281-294`), or route them through the setters. Brief did not
ask for this — **PLAN-MANDATED-ADJACENT**, controller decides.

**I-3 — Task 6: a `poc_tier` declared on an `exec_ref` item is silently dropped.**
`internal/findings/exec_evidence.go:295-296` mints the item with `""`, discarding every declared
field except `description`; the same function *refuses* a declared `type` (line 281) or `level`
(line 289) mismatch because those feed gate reads. `poc_tier` feeds the §2.2 law, so the same
argument applies. Concrete failure: an operator ingests an item declaring
`"level":"E4","type":"foundry-test"` (the pair `MintEvidenceLevelType` derives for an untiered
finding, `exec_evidence.go:62-76`) plus `"exec_ref":"EXEC-x","poc_tier":"existence"`: ingest
succeeds, the item lands untiered, and the later `mint --poc-tier maximized` is refused with
"requires an existence-tier PoC first" — a refusal caused by a silent drop the operator cannot see.
Partly **PLAN-MANDATED**: Task 6 Step 5 says to pass `""` at that caller (the brief names
`ingest.go:288`; the real caller is `exec_evidence.go`), but it never considers a payload that
declares the tier it just made schema-legal. This is the implementer's own deviation-1 note,
still `[CONTROLLER: unresolved]`. Fix: add the matching refusal, or thread the declared tier.

### Minor (Nice to Have)

**M-1 — Task 5: the ledger half of a fact read is untested.** No test asserts that exactly one
`finding.fact_read` event is written, and `TestFactReadIsRecordedWithItsBlock`
(`fact_read_test.go:36-54`) reads only the returned in-memory value, never a reload from disk —
so neither the event count nor the projection write is verified. Task 7's implementer added
exactly that test for its own writer (`internal/risk/replay_test.go:71-96`: projection kind +
`r40dEventCount == 1` + unchanged SHA after a refusal); the asymmetry is the gap.
**Plan-mandated**: the brief's Step-1 test is reproduced verbatim and asserts no event.

**M-2 — Task 5: the attestation refusal is asserted loosely.** `cmd_fact_read_test.go:68` is
`if code != 2 || errS == ""` while the two other refusals are exact-text (lines 41-43, 53-54).
The brief asked for "both refusals (exit 2, exact text)"; the two it names are exact, so this is
an extra third case asserted weakly rather than a missed requirement.

**M-3 — Task 5: `command` schema floor is not enforced on the write path.**
`fact_read.go:74-92` refuses an empty command but not a short one, while the schema requires
`minLength: 10`. `fact-read --command "solana x" --value 1 --block 1 --read-only` passes the
library check and then fails inside `SaveFinding` as a raw schema error (generic exit, not the
exit-2 refusal text). `--chain ""` is safe (`orDefault` at `ingest_payload.go:20-25` substitutes
`ethereum`).

**M-4 — Task 7: prefix matching accepts near-miss options.** `cmd_impact.go:404-419` dispatches
on `strings.HasPrefix(arg, "--replay-")` / `"--extractable-per-round"` / `"--gas-cost"` /
`"--frequency"` / `"--rounds-run"`, so `--replay-anything X`, `--gas-costX 1` and
`--rounds-runZ 3` are silently accepted as their prefixes instead of failing as unrecognized
arguments the way every other unknown flag does. A typo therefore changes what is recorded
rather than erroring.

**M-5 — Task 7: the exact printed replay lines are untested.**
`cmd_impact_test.go:243-273` (the brief's test verbatim) only checks that stdout contains the
words `demonstrated` and `computed`, though the brief pins the two-line format in
`cmd_impact.go:371-401`. Plan-mandated.

**M-6 — Task 6: the declared tier is discarded on the idempotent no-op path.**
`cmd_mint.go:80` runs `mintPocTierRefusal` *after* `mintIdempotentNoop` (`cmd_mint.go:268-297`),
and `MintReproEvidence` returns early for an already-minted `(exec, type)`
(`reproduction_mint.go:57-60`) before the law at line 87. So `mint --poc-tier existence` on an
already-minted exec exits 0 with "idempotent no-op" and records no tier and no notice — the
operator has no way to attach the tier afterwards except a new exec or a different `--type`. The
same is pre-existing for `--tier`, which is why this is Minor: the no-op message does say
nothing was written.

**M-7 — Task 6: stale doc comment.** `remediationFlags["mint"]` gained `--poc-tier`
(`gate_remediation_guard_test.go:116-117`) but the comment block that documents each verb's
accepted flags (lines 85-91) still lists mint without it. The addition itself is harmless (the
table is a superset vocabulary; the guard only requires coverage of verbs the catalog names).

**M-8 — Task 7: line ordering is cosmetic.** `cmd_impact.go:90-105` prints the two replay lines
before the pre-existing `<F-id>: impact recorded — …` summary, so the line that names the
finding comes last. The brief fixed no order; noting it because the implementer raised it.

## Cannot verify from diff

1. **Python-twin byte provenance.** `gen-vectors.py` / `cli.py` are not in this tree, so I cannot
   confirm that the three re-recorded `oracles.json` strings (lines 767, 818, 848) equal what the
   twin would emit, nor that the pinned `mintHelp` / `t23ImpactUsage` bytes match a live argparse
   capture. What I *could* verify: only those 3 oracle lines moved (stat `6 +-`), step 0 shows
   `origin_stage` 11/11/06 and steps 5/6 show 11 (extracted from the file), `finding_placeholders`
   is still 3, `fork_poc` unchanged, and `TestGoldenVectors` passes — i.e. the recorded bytes are
   consistent with the replayed Go behavior. Controller should confirm the twin is deliberately
   out of tree (I-1's severity partly depends on it).
2. **`webv2 run`'s stage plumbing** (RUNBOOK claim "A pipeline run (`webv2 run`) passes its
   stage"). Only `internal/orchestrator/discovery.go:65` (`IngestHypothesis(..., opts.Stage, ...)`)
   is visible here; the rest of the run path is unchanged code.
3. **Consumers of the new produced interfaces** — `ExistenceFundingRequired`, `PocTierOf`,
   `MaximizedEvidence`, `ComputeReplay`'s report rendering. No production caller in this diff
   (Phase 5 work); the briefs only require the interfaces to exist.
4. **`BountyRemediation` / `gate explain`** (global constraint): no gate check is added by any of
   these four tasks, so there is nothing to carry an entry. If the controller expected the new
   refusals to be gate-explainable, that is a plan question, not a diff defect.
5. **Task 8's idempotent-twin question** (step-0 finding 2 keeps `origin_stage: "11"` while its
   hypothesis is staged `05`): whether a re-ingest should extend `contributing_stages` to
   `["11","05"]` is a product decision the brief does not cover; the implemented behavior is what
   Step 4's code specifies, and the report flags it rather than hiding it.

## Strengths

- **Every mandated step of all four briefs is present**, and the deviations are the right calls:
  `appendFactRead` (`fact_read.go:115-122`) is a necessary fix — the brief's own snippet leaves
  `Kind == Null` through `append`, which serializes as `null` and fails the array schema; the
  brief's 7-arg `RecordFactRead` interface line contradicts its own 8-arg test/code, and the
  implementer followed the only compiling reading; `t20Setup`/`g15MintItem` were reused instead
  of inventing `mintTestExec`; `argSpec`+`helpUsageText` were used because `cmd_impact.go` really
  does not use `argSpec` (it hand-rolls the loop at `cmd_impact.go:196-224`).
- **The laws live in the write path, not the CLI**: `ValidatePocTierOrder` is called from
  `MintReproEvidence` (`reproduction_mint.go:87`), so `AttemptAndMint`, the ladder
  (`maximization_ladder_rungs.go:184`) and `sequencepoc` inherit it, and
  `TestAttemptAndMintRefusesMaximizedWithoutExistence` proves the CLI bypass is still refused.
  `ValidateReplayProfitability` and `RecordFactRead`'s refusals likewise run before any write.
- **Ledger/projection discipline is exactly the house law**: all three new writers use
  `SaveThenLog` with one event each (`finding.fact_read`, `finding.replay_recorded`,
  `finding.fork_dependence_set`), and the replay test proves a refused record leaves the finding
  byte-identical (`replay_test.go:89-96`).
- **Determinism and schema discipline hold**: no `time.Now()`/raw UUID in the new code
  (`state.NowIso()` in `fact_read.go:104`, `state.NewID` untouched), `additionalProperties: false`
  and enums on every new key, and `SaveFinding` re-validates the whole finding on every write
  (`storage.go:28-32`), so the new keys are validated on the write path, not just declared.
- **Tests verify behavior, not mocks**: refusals are asserted on exact stderr text and exit code
  (Task 5's and 8's CLI tests), the re-set test reads the *second* ledger event's
  `prior_fork_dependence` (`cmd_fork_dependence_test.go:57-72`), and the extra tests the
  implementers added beyond the briefs (`TestMintMaximizedAfterExistenceLands`,
  `TestRecordReplayWritesProjectionAndOneEvent`, `TestIngestAttributesTheOriginStage`) cover the
  happy paths the briefs' tests skipped — including the "omit, never `unknown`" law.
- **The golden re-record was done the honest way**: 3 lines of `oracles.json` replayed through
  `dispatchGolden` (not hand-edited), state/events oracles byte-identical, placeholders still 3,
  tooling deleted, and an 18-line provenance paragraph added to the test header
  (`golden_test.go:60-77`) that states what moved and why.
