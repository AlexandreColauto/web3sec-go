# Independent Read-Only Review — Task 2 (sandbox network label honesty) & Task 3 (per-machine liveness gate)

Worktree: `.worktrees/production-readiness` @ HEAD 16b3bc3a (clean, no tracked changes by reviewer).
Plan: `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` (v3 header, Global Constraints v3).

## Commit-ID correction (matters for the record)

The dispatch brief named commits `115ba97f` and `b47d893e` for Tasks 2/3. Verified by
`git log`: **`115ba97f` is Task 1** (`fix(jval): reject duplicate JSON object keys`, committed
*before* the plan commit e4a3dc01). The real Task commits are:

- **Task 2** = `b47d893e` — `fix(sandbox): honest network labels for host profiles`
- **Task 3** = `bbe5a030` — `fix(invariants): per-machine liveness coverage gate`

This review covers the correct commits. The brief also attributed "artifact-reference
enforcement" to Task 3; that is **Task 4** (`37511ec8`, evidence relevance binding on
invariant-verify). Because it was explicitly named, it was additionally spot-checked
(see Appendix A) — it is NOT counted in Task 3's verdict.

---

## Task 2 — Honest network labels for host profiles (b47d893e)

### Spec compliance: **YES**

| Plan requirement | Evidence | Verdict |
|---|---|---|
| New `networkLabel(profile) string` helper | `internal/sandbox/profiles.go:73-79` | ✅ |
| Host profiles → `"host (unconfined — nothing enforces network-off)"` | Byte-exact match to the plan's Interfaces wording (em dash included) | ✅ |
| Container profiles → `profileNetwork[profile]` verbatim | `profiles.go:79`; tests pin `docker-networkless`="none", `fork-runner`="bridge-host-gateway" | ✅ |
| Both call sites routed through the helper | `exec.go:1122` (Preview `network`), `exec.go:1283` (`environment.network_access`) — the diff shows both `profileNetwork[profile]` reads replaced | ✅ |
| No other dishonest surface left | `rg 'profileNetwork\['` over `internal/` → exactly one hit, inside `networkLabel` itself | ✅ |
| `HostProfile()` is the switch | `profiles.go:265-272` covers exactly the four host profiles | ✅ |
| Schema enum widened **deliberately** | `assets/schema/sandbox_execution.schema.json:40` adds the honest string as a 5th enum member; required (not optional) is correct: `validation.WriteJson` validates before write, so without widening every host-profile record write failed (commit body documents 13 red tests; `.scratch/red-sandbox-preschema.txt` no longer exists but the commit narrative + test shape corroborate) | ✅ |
| Enum value byte-identical to code label | Verified programmatically: schema JSON `enum[4]` == Go string literal, em dash exact | ✅ |
| Asset manifest resynced deliberately | `assets/testdata/asset_manifest.json` sha256/size updated; re-verified at HEAD: file sha256 `0a22d3ee…` == manifest entry, size 5225 == manifest; `python3 scripts/sync-asset-manifest.py` is a no-op at HEAD (zero diff) — resync is honest, not hand-hashed | ✅ |
| Test expectations updated deliberately, documented | Commit body names both moved pins (`TestHostProfilesAreHostOnly`, `TestMinicertoraProfilePolicy`) with old/new shape; correct: they read the raw map before (passed pre-fix) and now pin the honest label at the API boundary | ✅ |
| New tests per plan sketch | `TestNetworkLabelIsHonestForHostProfiles` (4 host + 2 container rows), plus two beyond-plan tests at both consumer boundaries: `TestPreviewHostProfileNetworkIsHonest`, `TestHostProfileRecordNetworkIsHonest` (which also re-pins the filesystem twin) | ✅ |
| Golden pins | `scripts/golden-run.py:324` and `scripts/verify-full.sh:222` seed **docker-networkless** only ("none" remains a valid enum member); `runbook-walkthrough.sh` exercises no host profile; legacy exec records keep `"none"` and stay schema-valid — no pin moved, none needed to. Commit body's golden-pin audit statement is accurate | ✅ |
| Legacy fixtures untouched | `git show b47d893e --stat` touches only the 5 task files; `go test ./internal/state -run Legacy` green at HEAD | ✅ |
| Gates | Reviewer-reproduced at HEAD: `gofmt -l` clean, `go vet` clean, `go test ./internal/{sandbox,invariants,orchestrator,cli,validation,state} -count=1` all ok (sandbox 50.1s) | ✅ |
| File-ownership constraint | Only the 5 declared files touched | ✅ |

### Quality: **APPROVED**

Two non-blocking observations:

1. **Helper placement** — plan said "add one helper near `profileFilesystemLabel`'s twin in
   exec.go — keep both label helpers adjacent", but `networkLabel` landed in `profiles.go`
   while `profileFilesystemLabel` lives in `exec.go:1290+`. The plan's own Files list said
   "Modify: internal/sandbox/profiles.go", so the instruction was self-contradictory; the
   chosen placement (map + honest accessor co-located) is arguably the better cohesion call.
   Cosmetic only.
2. `profileNetwork` still carries `"none"` for the four host profiles. This is now correct
   and documented: the map was re-commented as the *container-argv* label, and the map's doc
   comment warns future readers to go through `networkLabel`. Good defensive documentation.

---

## Task 3 — Per-machine liveness coverage gate (bbe5a030)

### Spec compliance: **YES**

| Plan requirement | Evidence | Verdict |
|---|---|---|
| Coverage computed per machine from registry liveness entries' `applies_to` | `invariants.go:470-480` (`covered` set), replacing the old global `kinds["liveness"]` presence check — the exact G-01 hole | ✅ |
| Model-carried liveness entries count toward coverage | `SeedFromModel` (`invariants.go:383-399`) registers model invariants via `freshEntry` (which copies `applies_to` verbatim, `invariants.go:426`) *before* `seedLiveness` is called | ✅ |
| Zero coverage → synthesis unchanged | `invariants.go:494+`: same statement text, same `applies_to = machines`, same `invariants.liveness_template` event, `synthesized: liveness-template` intact | ✅ |
| Partial coverage → refuse naming uncovered machines, exact stage-37 wording | `invariants.go:489-492`: `"protocol model: state machine(s) %s have no liveness invariant (one per machine — stage 37)"` — byte-exact vs the plan's Interfaces section; test pins the full string incl. the comma-joined pair `relay, staking` | ✅ |
| Refusal before any write | Code path: `LinksThenLog`/`SaveLinks` only run *after* `seedLiveness` returns nil (`invariants.go:407-415`); test additionally asserts zero registry entries, no `invariant_links.json` file on disk, and no template event after a refused load | ✅ |
| Full coverage → no refusal, no template | `TestFullLivenessCoverageNeedsNoTemplate` (beyond-plan bonus) also proves re-seed idempotency (no INV-5); idempotency holds structurally because the synthesized template's `applies_to` is exactly `machines` | ✅ |
| Tests: full literal, no placeholders | Plan's sketch had `/* … */` placeholders; the landed fixture is two spelled-out literal builders (`livenessMachinesModel`, `livenessModelCovering`) — plan explicitly required this expansion | ✅ |
| Refusal names only uncovered machines | Test asserts the covered machine (`vault-lifecycle`) does NOT appear in the error | ✅ |
| Orchestrator/cli green untouched | `go test ./internal/{orchestrator,cli} -count=1` ok at HEAD — synthesis-reliant fixtures did not regress | ✅ |
| Legacy fixture check | `go test ./internal/state -run Legacy` green; commit touches only `internal/invariants/`; no fixture bytes moved | ✅ |
| Gates | Reviewer-reproduced: gofmt clean, vet clean, packages green (see above) | ✅ |
| File-ownership constraint | Only `invariants.go` + `invariants_test.go` — exactly the two declared files | ✅ |
| `.scratch` evidence | `.scratch/task3-e2e/` (partial.json, zero.json + a full campaign dir) and `.scratch/task3-legacy/` exist — implementer did e2e + legacy sweeps beyond the unit tests | ✅ |

### Quality: **APPROVED**

Two non-blocking observations:

1. **Behavior nuance (per plan, worth recording):** a registered `kind=liveness` entry with an
   EMPTY `applies_to` no longer suppresses synthesis — the old presence check did. The plan's
   law explicitly defines coverage via `applies_to`, so this is the specified behavior, and
   synthesizing a per-machine template when nothing is actually covered is strictly more
   honest than the old silence.
2. `covered[pyStr(a)]` in `seedLiveness` does not check `a.Kind == validation.Str`, whereas
   Task 4's `referenceTokens` does. A non-string `applies_to` element would mint a garbage
   coverage key that can never match a machine name — harmless, but the two sites now
   disagree stylistically. Cosmetic.

---

## Verdicts

- **Task 2 (b47d893e): Spec YES — quality APPROVED.** No findings. Honest label is the exact
  plan wording; schema widening is deliberate, required-not-optional, and byte-matched;
  manifest resync reproduces from the sync script; no golden/legacy pin moved and none
  needed to.
- **Task 3 (bbe5a030): Spec YES — quality APPROVED.** No findings. Gate is per-machine with
  the exact stage-37 refusal text, refuses before any write, keeps zero-coverage synthesis
  and full-coverage silence, and is idempotent on re-seed. Fixtures were resynced/spelled
  deliberately (full literal, not the plan's placeholders).
- Dispatch-brief commit IDs were misattributed (`115ba97f` is Task 1, not Task 2/3); the
  review was performed against the correct commits.

## Appendix A — out-of-scope spot check: Task 4's artifact-reference enforcement (37511ec8)

Named in the brief, so verified briefly (not scored): `VerifyInvariantStatement`
(`invariants.go:835-880`) now gates on `artifactReferencesInvariant` — reads artifact bytes
via the exported `ResolveArtifactPath`, fail-closed on unreadable file, matches
`(?i)\b<token>\b` over {inv id, `NormalizeInvID` canonical form, every string `applies_to`
target}, deduplicated, empty tokens dropped. An artifact citing `INV-20` cannot satisfy
`INV-2` (word boundary); empty `applies_to` cannot bypass (the id token is always required).
Refusal text matches the plan's Task 4 wording verbatim. Golden (`artifact.md` → INV-2) and
verify-full (`note.md` → INV-1) pins were updated in-commit with proven rationale; the
runbook's h1 artifact matches via `applies_to: "Vault"`. Consistent with the plan.

## Verification commands run by the reviewer (all in the worktree, repo-cache convention)

```
GOCACHE=$PWD/.scratch/gocache GOMODCACHE=$PWD/.scratch/gomod/pkg/mod \
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod
gofmt -l internal/sandbox internal/invariants        # empty
go vet ./internal/sandbox ./internal/invariants      # no issues
go test ./internal/{sandbox,invariants,orchestrator,cli,validation,state} -count=1  # all ok
go test ./internal/state -run Legacy -count=1        # ok
python3 scripts/sync-asset-manifest.py               # no-op at HEAD (verified)
```

