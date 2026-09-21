# Fix-round 2 re-review — v1.6 P1/P2 record-and-evidence (fc03cab0..377ba14a)

Scope: the one open finding (sentinel collected as a cited artifact) plus new breakage in this fix
diff. Read-only on the checkout: probes ran through `go test -overlay=…` with backing files under the
gitignored `.scratch/reprobe2/`, so no tracked file, index, or HEAD was touched
(`git status --porcelain | rg -v '^\?\?'` → empty).

## Finding Verdicts

**1. The widened cited-artifact walk collected the framework's own "unpinned" pin sentinel as a
cited artifact id, so a real BuildCriticContext bundle yielded `["F-…","unpinned"]`, an honest feed
drop was refused, and a false `model.rejected` row was written — ADDRESSED.**

- The sentinel now has one owner and one skip. `internal/findings/ingest_payload.go:23`
  (`const SourcePinUnpinned = "unpinned"`, returned by `sourcePinOrUnpinned` at `:29`);
  `internal/boundary/boundary.go:167-169` (`isNonArtifactID` → `s == findings.SourcePinUnpinned`);
  `internal/boundary/boundary.go:188` — the skip sits in the walk's SINGLE funnel (`add`), which
  `collectIDs` (`:219-231`) uses for every id-bearing key, so it is not keyed to `snapshot_ids`.
- Non-vacuity, verified independently on the REAL builder, not on the fixer's test: overlay probe
  `TestZZProbeCriticUnpinned` (`.scratch/reprobe2/zz_probe_test.go`, package `boundary`) →
  `newCamp` (unpinned) → `mustIngest` → `roles.BuildCriticContext` gives
  `snapshot_ids = {"chain": null, "deployment": null, "source": "unpinned"}`, and
  - fixed walk `BundleArtifacts = ["F-48d45eba3c75"]`,
  - a locally re-implemented PRE-FIX walk = `["F-48d45eba3c75" "unpinned"]` — byte-for-byte the
    finding's observation,
  - `ValidateRequest(BuildRequest(b, declaration(fid), "critic", …))` = `<nil>`: the honest
    declaration passes, so `feed`/`logHypothesisRequest` never reaches the refusal, and the false
    `model.rejected` row is unreachable (refusal requires a non-empty
    `InputArtifactsOutsideDeclaration`, `boundary.go:349` gate + `feed.go:116-121`).
- The reachability of the defect was WIDER than the prior review recorded, and the fix covers it
  because the skip is by value, not by key. `TestZZProbeProposerLegacyCampaign` opens a copy of the
  real `scripts/legacy/campaigns/C-45488bdaf5` and builds the proposer bundle:
  `campaign_plan.snapshot_id = "unpinned"` and `protocol_model.snapshot_id = "unpinned"` (both
  artifacts are carried verbatim, `roles/context.go:146-147`; written at
  `planner/plan_builder.go:123`, `cli/cmd_model.go:59`). Pre-fix walk =
  `["src-1684fd7b-b868c7cd06e0" "unpinned" "INV-1" "INV-2" "F-df01bb454ed5" "F-ee0311c3397a"]`;
  fixed walk drops only `unpinned`; `ValidateRequest` on the honest declaration = `<nil>`. So the
  `discovery`/proposer feed path was already poisoned whenever the campaign had a bootstrapped
  plan + protocol model — the prior review's "NOT reachable through today's single wired feed stage"
  was wrong on that point, and the fix closes the wider case too.
- Regression tests land on the real path: `input_artifacts_test.go:216` (`unpinnedCriticBundle`,
  real `roles.BuildCriticContext`), `:232` (exact `[]string{fid}` + honest `ValidateRequest` nil),
  `:255` (sentinel under an evidence item's `snapshot_id`, real ids survive). The first one is not
  vacuous: it fails if the constant's value ever drifts, because the bundle carries the stored
  literal.
- All comment line references are accurate: `ackscan.go:183`, `report/report_finding_verify.go:53`,
  `audit/sections/snapshots.go:241`, `roles/context_critic.go:85-90,203`, `findings/ingest.go:121-125`,
  `findings/exec_evidence.go:205-215` (checked each against the files).

## New Breakage in the Fix Diff

**None Critical or Important.** The diff is behaviour-preserving where it claims to be and the two
edits I could falsify (the `add` funnel refactor, `sigOpt`) are equivalent; see the checks below.

## Out-of-Scope Observations

- The "reference, do not re-spell" rationale is only half-applied: `report/report_finding_verify.go:53`
  and `audit/sections/snapshots.go:241` still re-spell `"unpinned"`, so the drift the new constant
  exists to prevent remains in two of the three readers the constant's own doc names. Both files are
  outside this diff → non-blocking, but the follow-up is one `grep`-sized edit.
- The same literal also survives in five writers (`planner/plan_bootstrap.go:234`,
  `structidx/index.go:101`, `coverage/coverage_init.go:30`, `histmining/recency.go:255`,
  `cli/cmd_model.go:59`). Correctness is unaffected — the boundary skip is by VALUE, so every one of
  them is covered — but the sentinel now has six definitions and a future value change must touch all
  six. The fixer disclosed this rather than hiding it.
- Pre-existing, untouched: the boundary never validates DECLARED ids against the campaign's
  registries, so a stage may still declare a ghost id (e.g. `{"kind":"snapshot","id":"unpinned"}`, which
  the schema's 8-byte `minLength` admits). The fix removes the *need* for that ghost declaration; it
  does not remove the possibility. No campaign handle exists in `boundary` to close it.
- Prior-review M-4 (`internal/cli/cmd_impact.go:412-415` prefix matching) and the `AddEvidence`
  `poc_tier` hole remain untouched by this diff.

## Checks Run

- **(a) import cycle / coupling — no cycle, no new edge, verified by the compiler.**
  `go build ./internal/boundary/... ./internal/findings/...` → OK;
  `go vet ./internal/boundary/... ./internal/findings/...` → exit 0 (vet compiles the test files too).
  `go list -deps websec/internal/findings` → contains NO `websec/internal/boundary`; likewise
  `go list -deps websec/internal/roles` → none, so the new test's `roles` import in package `boundary`
  is not a cycle either. The `boundary → findings` edge is pre-existing: the diff adds the import to
  `boundary.go` only, while `boundary/ingest.go`, `boundary_critic.go`, `boundary_plan.go`,
  `boundary_reproducer.go` are unchanged files that already carried it. The only reverse path is
  test-only and pre-existing: `findings_test` (external) → `internal/cli` → `boundary`, which Go
  permits precisely because it is an external test package.
- **(b) sentinel completeness — complete for this tree, and the siblings claim holds.**
  Independent scans, not the report's: every `.json` in the repo (335 files, incl. campaign memory
  and testdata) walked for keys matching `artifact|evidence|finding|snapshot|exec|invariant|plan` +
  `_id(s)` / `active_snapshot_id` → the ONLY placeholder value found is `snapshot_id = "unpinned"`
  (49 files). A writer scan of non-test Go (`kv(…)`, `SetOrAppend(…)`, JSON literals) for the same
  keys → the only non-id literals are `"unpinned"` and `null`/derived ids. Siblings verified by probe:
  `saneArtifactID("") = false` (the 3-byte floor, `boundary.go:135-137`), `null` is a non-string leaf
  so `collectIDs` (`:219-231`, cases Str/Arr/Obj only) never adds it — probe bundle with
  `source: ""`, `deployment: null`, `chain: null`, `snapshot_id: null` → derived `["PRO-8a7fd208"]`.
  The one honest caveat: the skip is value-specific by design, so a FUTURE writer introducing a new
  placeholder under an id-bearing key would need a new entry (recorded above as non-blocking).
- **(c) prose exclusion still holds.** `TestBuildRequestDerivesTheCitedSet` (`:66-84`, asserts the
  `ART-99999999` quoted under `note` is not collected) PASSES, as does
  `TestBundleArtifactsReachesRealMintedIDs`; the probe's `note` prose is likewise not collected while
  the sibling `artifact_id` is. The `add` refactor changed only the skip, not the key scoping
  (`boundary.go:196-206`).
- **(d) `sigOpt` is behaviour-identical — confirmed, not refuted.** `fieldAt`
  (`findings/ingest_evidence_gate.go:22-29`) returns `validation.VNull()` with `ok=false` when the key
  is absent, and `VNull()`'s kind is 110 (`Null`) ≠ `Str` (115), so `!ok` and `v.Kind != Str` coincide.
  Overlay probe `TestZZSigOptOldVsNew` (`.scratch/reprobe2/zz_sigopt_probe_test.go`, package
  `findings`) compared the current body against a re-implementation of the pre-fix body across nine
  shapes — absent key, null, `""`, string, int, bool, obj, non-obj block, empty obj — all nine
  `equal=true`, e.g. `absent key fieldAt: kind=110 ok=false | new="" old="" equal=true`.
  `TestTechnicalSignatureVectors` and `TestIngestStampsProvenanceAndSignature` PASS.
- Focused suites (never `./...`): `go test ./internal/boundary -run
  'TestBundleArtifactsSkipsTheUnpinnedPinSentinel|TestBundleArtifactsSkipsTheSentinelUnderAnEvidenceItem|TestBuildRequestDerivesTheCitedSet|TestBundleArtifactsReachesRealMintedIDs|TestInSetRealIDsPass'`
  → PASS 5/5; `./internal/boundary -run 'TestInputSetRefusalIsRecorded|TestEmptyDeclarationRefusalIsRecorded|TestDeclarationEntryWithoutIDIsRecorded|TestMalformedRecordWithEmptyDeclarationIsNotRecorded|TestSchemaFailureIsNotRecordedAsARejection|TestDeclaredInputSetIsRequired|TestInSetRequestPasses'`
  → ok; `./internal/feed -run 'TestFeed…'` → ok; `./internal/findings -run 'TestZZSigOptOldVsNew|TestTechnicalSignatureVectors|TestIngestStampsProvenanceAndSignature'`
  → ok; `gofmt -l internal/boundary internal/findings` → empty.
- Report claims spot-checked against the code: the const value, the four writer/reader line numbers,
  the single-funnel skip, and the two new tests all match the diff. The fixer's mutation claim is
  reproduced independently by the pre-fix walk re-implementation above (same derived set, same
  symptom), so it is no longer merely a claim.

## Verdict

**Fix round 2: all findings addressed, no new Critical/Important breakage — clean (0 open).** The
one open finding is ADDRESSED with independent, real-builder evidence, and the fix additionally
covers the wider proposer-path reachability the prior review had missed.
