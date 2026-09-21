# Fix-round re-review — v1.6 P1/P2 record-and-evidence (3644d53c..fc03cab0)

Scope: the seven open findings plus new breakage in the fix diff. Read-only on the checkout;
focused tests only (no package-wide suite, no full run). Probes ran through
`go test -overlay=…` with backing files under the gitignored `.scratch/reprobe/` — no tracked
file, index, or HEAD was touched.

## Finding Verdicts

**1. C1 (Task 2) — `artifactIDPattern` matched no id the framework mints; the id-bearing KEY is now the scoping rule — ADDRESSED.**
`internal/boundary/boundary.go:114-118` (the `artifactIDPattern` regex is deleted; only
`artifactKeyPattern` remains), `:134-139` (`saneArtifactID`: 3..64 bytes, no whitespace — the only
bound the derivation puts on a string), `:153-181` (walk scoped to id-bearing keys), `:187-200`
(`collectIDs` now also descends arrays and objects, for the `snapshot_ids` mapping).
Verified against the REAL mint paths, not fixtures. A real campaign state
(`scripts/legacy/campaigns/C-45488bdaf5/campaign_state.json`) carries artifacts `PRO-8a7fd208`,
`PLA-f43186bb`, `REP-adc3248d`, `VAL-2571d3b4`, `ARC-7984d47d` and snapshot
`src-1684fd7b-b868c7cd06e0` — exactly the shapes the old regex rejected. Overlay probe with the
real builders: `state.RegisterArtifact` mints `POL-…`; `roles.BuildProposerContext` on a pinned
campaign → `BundleArtifacts = ["src-content-9987fc4e3bed"]` (pre-fix: `[]`); a feed drop declaring
that id ingests (`F-8c050c8cbb32`, err nil) while a drop declaring a different id is refused naming
the real id (`model request cites artifact src-content-9987fc4e3bed outside its declared input
set`). Tests `TestBundleArtifactsReachesRealMintedIDs` (`internal/boundary/input_artifacts_test.go:168`)
and `TestInSetRealIDsPass` (`:200`) pass.
The property the key-scoping exists for still holds: prose under a non-id key is not collected
(`input_artifacts_test.go:186-190`), and prose containing whitespace under an id-bearing key is
rejected by `saneArtifactID` (probe: `evidence_id: "see ART-99999999 for context"` → not
collected). The residual hole is the new Important below.

**2. I1 (Task 2) — the recorder gate dropped the empty-declaration refusal — ADDRESSED.**
`internal/boundary/boundary.go:294-324` (`InputSetRecordable`: `validation.Validate(
withoutDeclaration(request), "model_request", 1)` AND the derived event validated against
`trajectory#model_rejected`), `:328-336` (`withoutDeclaration`, a copy), `:280-292` (`refusalData`,
shared by the writer and the gate); `internal/boundary/ingest.go:66-80` (the gate at `:75`).
Evidence: `TestEmptyDeclarationRefusalIsRecorded` (`input_artifacts_test.go:292`) and
`TestDeclarationEntryWithoutIDIsRecorded` (`:312`) pass — 1 `model.rejected` each, `declared: []`,
`verify_trajectory` ok; the converse `TestMalformedRecordWithEmptyDeclarationIsNotRecorded`
(`:325`) passes with 0 events. Overlay probe on the FEED path: a drop with `input_artifacts: []`
→ refused with the schema's `minItems` message and exactly 1 `model.rejected` row, so the widened
gate reaches both transports, not just `logHypothesisRequest`.

**3. I1 (Tasks 3-4) — the `review_sessions` read-modify-write ran unlocked; the unwind re-saved a parsed Value — ADDRESSED.**
`internal/reviewsession/reviewsession.go:30-34` (`Start` takes `LockProcess` before the one-open
check), `:55-58` (`End` likewise), `:95-97` and `:110-112` (`RawState()` taken before the first
write, under the caller's lock), `:144-155` (`UnwindState(priorRaw, hadRaw)` in place of
`SaveState(prior)`). `Start`/`End` are the projection's only writers
(`internal/cli/cmd_review_session.go:219,240`); `SaveState`/`Log`/`UnwindState` re-enter the lock
by depth (`internal/state/processlock.go:123-129`, `internal/state/campaign.go:242-254`,
`internal/state/campaign_snapshot.go:213-219`).
Evidence: `TestStartHoldsTheCampaignLockAcrossTheReadModifyWrite`
(`internal/reviewsession/reviewsession_test.go:127`) and
`TestRefusedStartRestoresThePreWriteStateBytes` (`:160`) pass
(`ok websec/internal/reviewsession 0.210s`). The first contends with a real flock (a second
`*state.Campaign` over the same dir, not a depth re-entry); the second pins `WEBV2_NOW` on both
sides of the refused start, so only a byte-identical restore can pass.

**4. I-1 (Task 7) — the `--replayable` family was absent from the pinned usage/help and the RUNBOOK — ADDRESSED.**
`internal/cli/cmd_t23_shared.go:29-40` (`t23ImpactUsage`) and `:85-…` (`t23ImpactHelp`, with a
description per flag); `assets/runbook/RUNBOOK.md:1805` (the cheat-sheet line, now naming all seven
flags). The pinned asset stays consistent: `assets/testdata/asset_manifest.json`
(`packs.runbook["RUNBOOK.md"]`) = `47578e85e09b5310a34e13da2cae705b00430f36fa65eeb6ad04d6d39fd556b7`,
size 128023 — recomputed from disk: MATCH. Live `go run ./cmd/webv2 impact --help` prints the whole
family, and every accepted spelling is in the parser (`internal/cli/cmd_impact.go:407-425,465-493`).
`TestImpactHelpDocumentsTheReplayFamily` (`internal/cli/cmd_impact_test.go:284`, both `--help` and
the `--gas-cost` usage-error path) and `TestRunbookDocumentsTheReplayFamily`
(`internal/cli/runbook_test.go:259`) pass.

**5. I-2 (Tasks 6+8) — `ingest` accepted a payload-declared `fork_dependence` with no reason and no event, and a declared `poc_tier` on a non-exec item — ADDRESSED.**
`internal/findings/ingest.go:286-291` (`refuseDeclaredFields` in `ingestValidateAndGate`, after
SCHEMA, before the LEDGER/GATE half and before any write), `:353-373` (the gate),
`:376-392` (fork_dependence refusal, naming `webv2 fork-dependence --set V --reason R` and the
`finding.fork_dependence_set` event), `:394-410` (poc_tier on an item with no `exec_ref`).
`TestIngestRefusesDeclaredForkDependence` (`internal/findings/ingest_test.go:744`, also asserts no
finding was written) and `TestIngestRefusesDeclaredPocTierWithoutAnExec` (`:763`) pass. The model
path is untouched: `assets/schema/model_response.schema.json` `definitions.hypothesis` has no
`fork_dependence`/`poc_tier` property, so no model output can trip the new gate.

**6. I-3 (Task 6) — a `poc_tier` declared on an `exec_ref` item was silently dropped — ADDRESSED.**
`internal/findings/exec_evidence.go:295-302`: the declared tier is refused before
`MintedExecEvidenceItem` (`:302`) lands the untiered mint shape, and the message names the door
that records a tier (`webv2 mint --poc-tier <V>`). `TestIngestExecRefRejectsDeclaredPocTier`
(`internal/findings/ingest_exec_ref_test.go:278`) passes.

**7. Cross-task defect found during the fix round — `feed` recorded a refusal whose request violated the record contract — ADDRESSED.**
`internal/feed/feed.go:139-144` (`refuseFileRequest` gates on the now-exported
`boundary.InputSetRecordable`), `internal/boundary/boundary.go:311-324`,
`internal/boundary/ingest.go:75` (the same predicate on the record-contract path).
Verified on BOTH paths by overlay probe: feed drop with role `gremlin` → refused, **0**
`model.rejected`; feed drop with `input_artifacts: []` → refused, **1**; feed out-of-set drop →
refused, **1**. `TestFeedRefusesAMalformedRecordWithoutRecording` (`internal/feed/feed_test.go:213`)
and `TestFeedRefusesAnUndeclaredRequest` (`:186`, whose `requireRefusalsRecorded` still pins
exactly 2 rows plus `verify_trajectory` ok) pass, as do the boundary-side
`TestMalformedRecordWithEmptyDeclarationIsNotRecorded` and
`TestSchemaFailureIsNotRecordedAsARejection`. The bare-drop path keeps its intentional bypass
(`feed.go:97-98`, `:146-174`): `refusalRequest` is the framework's own synthesized record, not the
file's, and its event satisfies `model_rejected`.

## New Breakage in the Fix Diff

**Important — the widened walk now treats the framework's own "no pin" sentinel as a cited artifact id, so an honest bundle is refused and a false `model.rejected` row is written.**
`internal/boundary/boundary.go:187-200` (`collectIDs` descends objects) + `:134-139`
(`saneArtifactID` bounds only length and whitespace).
- `snapshot_ids.source` is the string `"unpinned"` whenever no snapshot is pinned — written by the
  framework itself (`internal/findings/ingest_payload.go:11-16`, landed at
  `internal/findings/ingest.go:121-125`), and the framework's own readers filter it out as "not an
  id" (`internal/report/report_finding_verify.go:53`,
  `internal/audit/sections/snapshots.go:241`). The schema even blesses it: `snapshot_pins.source`
  is `minLength: 8`, and `"unpinned"` is exactly 8 bytes.
- Overlay probe with the real builder: `roles.BuildCriticContext` on an unpinned campaign →
  `BundleArtifacts = ["F-aa85567a1843" "unpinned"]` (the critic bundle carries `snapshot_ids`
  verbatim at `internal/roles/context_critic.go:203`, and each evidence item's `snapshot_id` at
  `context_critic.go:85-90`). Feed-ingesting an honest drop whose bundle carries that shape →
  `model request cites artifact unpinned outside its declared input set`, plus exactly 1
  `model.rejected` row with `"outside":["unpinned"]` — a ledger accusation naming a non-artifact.
  The only way past it is declaring `{"kind":"snapshot","id":"unpinned"}`, i.e. a ghost id, the
  class non-negotiable 4 forbids.
- Same root cause, smaller blast radius: every whitespace-free token under an id-bearing key is now
  an id (probe: `finding_id:"unknown"`, `plan_id:"none"` → collected), where the old prefix regex
  rejected them.
- Reachability: NOT reachable through today's single wired feed stage (`discovery`, whose proposer
  bundle has no `snapshot_ids` key and whose pin keys are `null` when unpinned — probe: `[]`), but
  reachable for any bundle carrying the finding's pin, which is the shape the fix's own comment
  blesses (`boundary.go:183-186`) and the shape the critic/reproducer stages ship.
- Fix direction: skip the `unpinned` sentinel (and the `deployment`/`chain` mapping values, which
  the same recursion now collects) inside `collectIDs`, or resolve candidates against the
  campaign's registries as C1 suggested. `boundary` has no campaign handle, so the sentinel filter
  is the small fix; the important thing is that the derived set may not contain a value the
  framework's own readers treat as "no pin".

## Out-of-Scope Observations

- `internal/findings/ingest_evidence.go:13-90` (`AddEvidence`) still accepts a payload item that
  declares `poc_tier` and appends it verbatim (`:63-65`): the same hole I-2 closed for `ingest`, on
  the sibling evidence write path this fix did not touch. A follow-up task, not this loop.
- The schema-walked ingest legend still advertises `evidence[]/poc_tier: existence|maximized`
  (`internal/cli/cmd_ingest_print.go:141-149`, walking `finding.schema.json`; pinned in
  `internal/cli/cmd_ingest_test.go:85`) while the write path now refuses every payload-declared
  tier. Minor operator-surface mismatch created by the I-2/I-3 fixes — the schema must keep the key
  for grandfathered findings, so the legend is not strictly false.
- Prior-review M-4 (prefix matching at `internal/cli/cmd_impact.go:412-415` accepts `--gas-costX`
  as `--gas-cost`) is untouched by this diff and still open.
- The pinned `t23ImpactUsage`/`t23ImpactHelp` bytes still cannot be checked against the Python twin
  (`gen-vectors.py`/`cli.py` are not in this tree); only their presence and self-consistency with
  the Go parser are verifiable here.

## Checks Run

- `GOCACHE=$PWD/.scratch/gocache go test ./internal/boundary -run 'TestBundleArtifactsReachesRealMintedIDs|TestInSetRealIDsPass|TestEmptyDeclarationRefusalIsRecorded|TestDeclarationEntryWithoutIDIsRecorded|TestMalformedRecordWithEmptyDeclarationIsNotRecorded|TestSchemaFailureIsNotRecordedAsARejection' -count=1` → ok
- `… ./internal/feed -run 'TestFeedRefusesAMalformedRecordWithoutRecording|TestFeedRefusesAnUndeclaredRequest'` → ok
- `… ./internal/reviewsession -run 'TestStartHoldsTheCampaignLockAcrossTheReadModifyWrite|TestRefusedStartRestoresThePreWriteStateBytes'` → ok
- `… ./internal/cli -run 'TestImpactHelpDocumentsTheReplayFamily|TestRunbookDocumentsTheReplayFamily|TestImpact'` → ok
- `… ./internal/findings -run 'TestIngestRefusesDeclaredForkDependence|TestIngestRefusesDeclaredPocTierWithoutAnExec|TestIngestExecRefRejectsDeclaredPocTier'` → ok
- 4 overlay probes (`-overlay` + backing files in `.scratch/reprobe/`, no tracked file touched):
  real `RegisterArtifact`/`src-content-*` ids end-to-end through the feed (accept + refuse);
  real `roles.BuildProposerContext`/`BuildCriticContext` bundles on pinned and unpinned campaigns;
  the sentinel and word-under-key cases; the feed gate on malformed / empty-declaration /
  out-of-set drops.
- RUNBOOK sha256 and size recomputed against `assets/testdata/asset_manifest.json` → MATCH.

## Verdict

**All seven findings ADDRESSED. 1 new Important breakage introduced by the fix diff** — the
`unpinned` sentinel (and other non-id words) now collected as cited artifact ids,
`internal/boundary/boundary.go:187-200`. No new Critical. The controller decides whether the
sentinel filter is fixed in this loop or ledgered for the next round; nothing else in the fix diff
needs another pass.
