# Task 2 review — declared input artifact sets and out-of-set refusal

Reviewed: `5bcc168a..88653b81` (one commit: `88653b81 feat(boundary): declared input artifact sets and out-of-set refusal (v1.6 P1)`).
Method: diff read in full, then focused checks against the repo for four named risks (does the derivation reach real
bundle ids; is the recorder's gate equivalent to the brief's; are the two schema files required to stay in sync; are
the brief's migration targets real). No file in the checkout was modified.

## Verdicts

**SPEC COMPLIANCE: ❌ Issues found.** Every deliverable the brief names is present, the four interfaces and both
refusal texts are byte-exact, the schema discipline holds and the manifest is correctly synced. But the mechanism the
brief calls the anti-decoration guarantee does not bind to any id the framework actually mints (Critical 1), and the
recorder drops one of the two declared-input-set refusals (Important 1).

**TASK QUALITY: Needs work.** The work is careful — three of the four documented deviations are real defects in the
plan that the implementer caught by reading the code, and the extra `verify_trajectory` assertion is the strongest
thing in the change. But the feature's core promise ("no hand-written list can drift from what was sent") is not
delivered for snapshots or artifacts, and the test suite is structurally unable to notice.

## Requirement-by-requirement (brief)

| Brief requirement | Verdict |
| --- | --- |
| Step 1/6 test file `internal/boundary/input_artifacts_test.go` | ✅ present; all five brief tests present in substance, plus two justified extras |
| Step 3 two schema keys, both **optional**, `required` untouched | ✅ `assets/schema/model_request.schema.json:7-14` (required unchanged), `:49-67` (keys added, `minItems: 1`, `items.additionalProperties: false`) |
| Step 3 `python3 scripts/sync-asset-manifest.py` in the same change | ✅ recomputed at 88653b81: RUNBOOK.md `58358e4e…`/121344, model_request `b8ec8c39…`/3291, trajectory `3b8e6ecb…`/13999 — all three match `assets/testdata/asset_manifest.json` exactly |
| Step 4 `BundleArtifacts`, `BuildRequest`, `DeclaredInputArtifacts`, `InputArtifactsOutsideDeclaration` | ✅ signatures exact (`internal/boundary/boundary.go:135,183,199,213`); refusal texts exact (`:280`, `:283-285`) — but see Critical 1 for the derivation's reach |
| Step 4 `ValidateRequest` clauses before the `nil` return | ✅ `internal/boundary/boundary.go:276-286` |
| Step 6 `RecordInputSetRefusal` mirroring `RecordRejection`, wired at the one call site | ⚠️ present (`boundary.go:248`, `ingest.go:66-80`) but gated on a re-validation — Important 1 |
| Step 7 migrate the in-repo callers | ✅ two real migrations (`internal/boundary/sweep_t35_test.go:359,514`), one the brief missed (`internal/trajectory/trajectory_test.go:107-115`); the brief's list was otherwise wrong (see Strengths) |
| Step 8 RUNBOOK line incl. explicit grandfathering | ✅ diff lines 35-52: "requests logged before this change have no declaration and still validate … requests written after it are refused without one" |
| Extra: `assets/schema/trajectory.schema.json` | ✅ required by `TestModelRequestDefinitionMatchesBoundarySchema` (Deviation 1) |
| Extra: `model_rejected` gains `payload_sha256` + 3 optional keys | ✅ required by that definition's own contract (Deviation 2) |
| Extra: `TestSchemaFailureIsNotRecordedAsARejection` | ✅ justified — it pins the gate's boundary |

Nothing is present that the brief did not ask for beyond those four justified extras.

## Issues

### Critical (Must Fix)

**C1 — `artifactIDPattern` matches none of the ids the framework mints for artifacts or snapshots, so `context_artifacts`
is empty on real bundles and the out-of-set refusal can never fire on a stage's real inputs. [PLAN-MANDATED]**

`internal/boundary/boundary.go:114-117`:

```go
var artifactIDPattern = regexp.MustCompile(
	`^(ART|EXEC|EV|F|INV|SNAP|PRC)-[0-9a-zA-Z_-]{4,48}$`)
```

This is verbatim from the brief (brief lines 191-192), so the defect is the plan's; the human decides which side moves.

What the framework actually mints:

- **Artifacts** — `internal/state/artifacts.go:56`: `strings.Replace(newId("ART", 8), "ART-", first3Upper(kind)+"-", 1)`.
  Real ids are `<KIND3>-<8hex>`: `POL-171165a6`, `STR-35c89f41`, `PRO-9f4a4d4d`, `PLA-98683f66` (all four observed in
  `internal/orchestrator/testdata/oracles.json`). No 3-letter kind prefix is in the alternation; `ART-` is a shape that
  appears only in tests (`internal/state/artifacts_unknown_artifact_test.go:25`).
- **Snapshots** — `internal/snapshot/dryrun.go:137-141` mints `src-<12hex>`, `src-<8hex>-<12hex>`, `src-content-<12hex>`;
  `internal/snapshot/pin.go:334` documents `"src-content-"+content_hash[:12]`. Real ids in testdata:
  `src-content-9987fc4e3bed`, `src-1684fd7b-b868c7cd06e0`, `src-replay-g01`. `SNAP-` is never minted anywhere.

Regex probe (Python `re`; identical semantics for this pattern) over those strings: every `src-*` and every
`POL-/STR-/PRO-/PLA-` id → **no match**; `EXEC-<10hex>`, `EV-<8hex>`, `F-<12hex>`, `PRC-<8hex>` → match.

The keys are not the problem — the id shape is. The three role builders put ids under exactly the keys
`artifactKeyPattern` (`boundary.go:119-123`) accepts: `target.active_snapshot_id` (`internal/roles/context.go:133`),
`snapshot.snapshot_id` (`internal/roles/roles.go:151`), the same `snapshot_id` inside the reproducer's `active_snapshot`
block (`internal/roles/context_reproducer.go:32,45`), and `finding_id` (`internal/roles/context_advisory.go:144`,
`context_reproducer.go:75`). Of those, only `F-…` survives the id pattern. **So on a real bundle the derived cited set
contains finding ids and nothing else** — never the pinned snapshot a stage is about to reason over, never an artifact.

The tests cannot see this because the fixture id is hand-written in a shape the framework does not produce:

- `internal/boundary/boundary_test.go:29` — `const snapID = "SNAP-0001"`, used by `pin(t, c)` (`:31-43`).
- `internal/boundary/sweep_t35_test.go:344-360` — fresh campaign, `pin(t, c)`, then
  `BuildRequest(bundle, declaredFromBundle(bundle), …)`. At that point the campaign has no findings and no queued
  memory, so `SNAP-0001` is the *only* collectable id. I ran
  `GOCACHE=$PWD/.scratch/gocache go test ./internal/boundary -run 'TestTrajectoryIntegrityEndToEnd|TestBuildRequestDerivesTheCitedSet|TestInSetRequestPasses|TestInputSetRefusalIsRecorded|TestSchemaFailureIsNotRecordedAsARejection' -count=1`
  → `ok websec/internal/boundary 0.160s`. That green depends entirely on `SNAP-0001`: with a production id the derived
  set is empty, `declaration()` (`input_artifacts_test.go:36-45`) yields `[]`, and the schema's `minItems: 1` refuses the
  request outright. Either way the feature fails on real input — a harness that declares anything gets a check that can
  never fire, and a harness that follows the migration idiom the implementer introduced (`declaredFromBundle`,
  `input_artifacts_test.go:52`) is refused on every fresh campaign.
- `TestBuildRequestDerivesTheCitedSet` (`input_artifacts_test.go:61-88`) is green on `ART-aaaa1111`/`ART-bbbb2222` —
  ids chosen to match the regex — so no test in this diff can catch the mismatch.

Live at HEAD (`git show HEAD:internal/boundary/boundary.go | rg -n artifactIDPattern` → identical lines 114-123), and
inherited by the next task: `internal/feed/feed.go:115-119` derives `context_artifacts` with
`boundary.BundleArtifacts(context)` and then validates — see "cannot verify" #1.

Why it matters: the brief's own argument is that derivation is what stops the declaration from being decorative, and
Non-negotiable 4 makes an undeclared consumed artifact "the same class of fabrication as a ghost id". As written, a
stage can consume the pinned snapshot, or any artifact, without declaring it and `ValidateRequest` will not notice.
Fix: derive the id vocabulary from what the framework mints (e.g. `^[A-Z][A-Z0-9]{2}-[0-9a-f]{6,}$` plus
`^src-[0-9a-z][0-9a-z-]*$`), or better, collect ids by resolving candidate strings against the campaign's own
artifact/snapshot/exec/finding registries instead of a hardcoded prefix list.

### Important (Should Fix)

**I1 — the recorder's gate silently drops the EMPTY-declaration refusal, so one of the two declared-input-set refusals
never reaches the ledger. [deviation from brief Step 6]**

`internal/boundary/ingest.go:66-80` records only when a second validation passes:

```go
if err := ValidateRequest(request); err != nil {
	if validation.Validate(request, "model_request", 1) == nil {
		if logErr := RecordInputSetRefusal(campaign, request, err.Error()); logErr != nil {
```

Everything the gate admits has already passed that same check at the top of `ValidateRequest`
(`boundary.go:276`), so the gate is exactly "the failure was not the record contract". For a request with a bad `role`
or a missing `context_hash` that is right, and the implementer's rationale checks out: `model_rejected` fixes
`role`/`kind` enums and sets `additionalProperties: false` (`assets/schema/trajectory.schema.json:74-79`), and
`VerifyTrajectory` re-validates every `model.*` event (`internal/trajectory/trajectory.go:330-336`), so the brief's
literal wiring would have written an event violating its own definition on a healthy campaign.

But the same gate also suppresses the case the brief treats as part of this feature: `input_artifacts: []`, refused by
the schema's `minItems: 1`. Brief lines 115-123 call the two clauses "complementary, not redundant" and Step 6's stated
purpose is "a refusal that is only returned is an orphan: the caller prints it and the next session never sees it".
`input_artifacts: [{kind: "artifact"}]` (schema-required `id` absent) behaves the same way and is read by
`DeclaredInputArtifacts` as "declares no input artifact set" — a declared-input-set refusal that is never recorded.

Fix: widen the gate to "the record schema passed, OR the only schema failure is on `input_artifacts`" (equivalently,
record whenever `err` is one of the two input-set refusals plus the minItems/required failures on that key). Note the
RUNBOOK text added by this diff binds "declares nothing" to the Go clause's message, so the prose is not strictly
false — the gap is against Step 6's intent.

### Minor (Nice to Have)

**M1 — `strValues` re-implements the already-exported `validation.StrArr`. [PLAN-MANDATED]**
`internal/boundary/boundary.go:232-238` is behaviourally identical to `internal/jval/accessors.go:60-66`, re-exported as
`validation.StrArr` (`internal/validation/jval_alias.go:66`) and already used as `validation.StrArr(actors)`
(`internal/roles/context_advisory.go:55`). `validation.VArr(strValues(x)...)` ≡ `validation.StrArr(x)`. The brief
(line 307) mandates the helper and the Global Constraints sanction duplicated small helpers, so this is plan-mandated
duplication of a helper that already exists in the same module.

**M2 — `RecordInputSetRefusal` logs without validating its own event against `model_rejected`. [PLAN-MANDATED]**
`internal/boundary/boundary.go:248-263` builds the data and calls `c.Log` directly; conformance rests on a caller
precondition stated only in the doc comment. `trajectory.RecordModelEvent` (`internal/trajectory/trajectory.go:101-128`)
is this module's validate-before-log path for exactly that definition and would have made the event conformant by
construction and loud on a bad caller. Two ways to violate the contract today: a request whose `context_hash` is not a
64-hex digest (`trajectory.schema.json:100-104` patterns it), and an `error` over 1000 runes (guarded — `pyTrunc` is
rune-based, `internal/boundary/boundary_values.go:45-51`). `internal/feed/feed.go:133-139` synthesizes a request for
precisely the no-request case, so the precondition is already load-bearing outside this diff. The brief mandated
`c.Log`, hence plan-mandated.

**M3 — `TestInputSetRefusalIsRecorded` does not assert the event's payload.**
`internal/boundary/input_artifacts_test.go:122-146` asserts `ref == null`, `len(outside) == 1` and
`verify_trajectory` ok. It never asserts `declared`, `error`, `context_hash` or `payload_sha256`, so a recorder that
wrote an empty `declared` or the wrong hash would still pass.

**M4 — no test pins the derivation's key scope or id shapes.**
`input_artifacts_test.go:20-31`'s `bundle()` only ever uses `artifact_id`. Nothing covers `active_snapshot_id` /
`snapshot_id` collection, dedup order, or non-`ART-` id shapes — which is why C1 is invisible to the suite. A table
test over the shapes the framework mints would have caught it.

## Cannot verify from diff

1. **`internal/feed` (Task 3) and C1's blast radius.** `internal/feed/feed.go:115-119` derives `context_artifacts` with
   `boundary.BundleArtifacts(context)`; that file is not in this diff (it landed at `5fe665e6`, after 88653b81). Whether
   the production drop path inherits C1 depends on the ids in Task 3's bundle fixtures — `internal/feed/feed_test.go:31,162,219`
   uses the same synthetic `ART-…` ids, so its green does not settle it. Controller should check Task 3 against C1.
2. **`trajectory.RecordModelEvent` as a second `model.request` write path.** It validates against the schema only
   (`internal/trajectory/trajectory.go:113-127`), where both new keys are optional by design, so it does not require a
   declaration. Its only in-repo callers are tests (`internal/sft/sft_backfill_test.go:136,207` and
   `internal/trajectory/trajectory_test.go`); whether the out-of-repo harness uses it is not visible here.
3. **The harness contract change itself** (brief line 7: the request record is built outside the binary). "New requests
   must declare" cannot be verified in-repo.
4. **`go test ./...` at 88653b81.** Not re-run (controller has it green) and HEAD is `3644d53c`. `internal/boundary` is
   byte-identical between the two (`git diff --stat 88653b81..HEAD -- internal/boundary` → no output), so the focused
   run above is representative for this package; `internal/trajectory` and `internal/sft` were not re-run.

## Strengths

- **The brief's migration inventory was wrong and the implementer found it by reading, not by trusting.** All six
  `boundary_test.go` lines the brief named (`:251,280,317,352,367,386`) pass `HypothesisOpts{}` with no `Request`
  (helper at `boundary_test.go:249-256`), so `logHypothesisRequest` returns at `ingest.go:63` before validating;
  `internal/sft/sft_backfill_test.go:118` likewise. Verified independently — no migration was needed there, and the
  real migrations were `sweep_t35_test.go:359,514`.
- **Deviation 1 is correct and load-bearing.** `internal/trajectory/trajectory_test.go:648-675` asserts `properties`
  equality between `trajectory.schema.json#model_request` and `model_request.schema.json`. Adding the keys to only one
  file would have failed that test; the two additions are textually identical.
- **Deviation 2 is correct.** `model_rejected` requires `payload_sha256` and forbids extra properties
  (`trajectory.schema.json:74-79`) while `VerifyTrajectory` re-validates every `model.*` event — the brief's data shape
  would have written a schema-violating event on the framework's own refusal.
- **`TestInputSetRefusalIsRecorded` runs `trajectory.VerifyTrajectory` over the campaign** (`input_artifacts_test.go:139-146`)
  — an assertion beyond the brief that turns "an event was written" into "the ledger still verifies". No import cycle
  (trajectory does not import boundary; verified).
- **`TestSchemaFailureIsNotRecordedAsARejection`** (`input_artifacts_test.go:174-201`) pins the gate's boundary with a
  concrete non-record, so I1's deviation is at least tested rather than merely asserted.
- **Schema discipline held.** `additionalProperties: false` retained and `required` untouched
  (`model_request.schema.json:7-14`), both keys optional, `minItems: 1` on the declaration,
  `items.additionalProperties: false` on its entries; the new `model_rejected` keys are optional and documented.
- **Manifest correctly synced in the same change** (verified by recomputing sha256 of all three blobs at 88653b81).
- **Determinism and ledger law held.** No `time.Now()`, no raw UUID mint; exactly one `c.Log` event per refusal
  (`boundary.go:262`); `ref` nil as mandated; the log error wins over the validation error (`ingest.go:75-79`).
- **Honest reporting.** All four deviations are documented with reasons rather than hidden, and three of the four are
  defects in the plan that the implementer caught.

## Assessment

**Task quality:** Needs fixes.

**Reasoning:** The plumbing is correct, the schema discipline and manifest are exact, and three of the four deviations
are the implementer correctly overriding a defective brief. But C1 means the change does not deliver the guarantee it
exists for — a stage's snapshot and artifact inputs are invisible to the derivation, so an undeclared consumption of
either is never refused — and the migrated fixtures hide that behind a test-only id shape (`SNAP-0001`) that the
framework never mints. I1 compounds it by leaving the empty-declaration refusal unrecorded. Fix C1's id vocabulary (and
add a test over the real minted shapes), widen the recorder gate, and this is a strong change.
