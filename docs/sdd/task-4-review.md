# Task 4 review — invariant verification artifact reference (37511ec8)

Scope: original Task 4 acceptance ("Artifact attribution on invariant-verify",
`docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` L180-225) judged
against the v3 operator-approved correction (plan L182: the word-boundary check
proves only that text NAMES an invariant or target — attribution, never
mechanical proof). Commit under review: `37511ec8` ("fix(invariants): evidence
relevance binding on invariant-verify"). Task 4A provenance (521eecfd) is out of
scope here (already reviewed in `task-4a-fix1-review.md`).

## Verdicts

- **Spec: YES.** Every original Task 4 step is implemented as specified, and the
  implementation is fully consistent with the v3 correction's characterization
  of the mechanism (text match = attribution only; no mechanical claim is
  manufactured by this commit; provenance labeling correctly left to 4A).
- **Quality: APPROVED.** Three non-blocking observations below; nothing blocks.

## Acceptance mapping (checked against the commit tree, not the report)

| Plan requirement | Evidence | OK |
|---|---|---|
| Gate in `VerifyInvariantStatement` after artifact lookup (invariants.go:751-787 region) | `artifactReferencesInvariant` called between registry entry load and the status flip; refusal returns before any mutation | ✔ |
| Export `ResolveArtifactPath` as a one-line wrapper over `resolveArtifactPath` | state/artifacts.go — exact shape; `TestResolveArtifactPath` pins wrapper == seam (abs + relative) | ✔ |
| Token set {normalized inv id} ∪ applies_to, `os.ReadFile(ResolveArtifactPath(a))` | `referenceTokens` adds `invariantID`, every string `applies_to` entry, plus `NormalizeInvID` of each; dedup; empty tokens dropped | ✔ |
| Word-boundary regex `\b<escaped>\b` case-insensitive (INV-20 must not satisfy INV-2) | `(?i)\b` + `regexp.QuoteMeta(tok)` + `\b`; `TestVerifyRefusesNearMissInvariantID` covers INV-20, INV-22, `recheckINV-2`, `INV-2x` | ✔ |
| Refusal text byte-exact per plan "Produces" | `irrelevantArtifact` matches the plan string verbatim; test asserts the full byte-exact message | ✔ |
| Refusal is inert: axis does not move, no event | TestVerifyRefusesIrrelevantArtifact pins status UNVERIFIED, empty verified_by, zero `invariant.verified` events | ✔ |
| Fail-closed on unreadable bytes | `artifactReferencesInvariant` returns false on read error; `TestVerifyRefusesUnreadableArtifact` | ✔ |
| Empty applies_to must not bypass (plan Step 6 reviewer check) | `TestVerifyEmptyAppliesToDoesNotBypass` — id-only artifact passes, prose is refused | ✔ |
| Registry vs canonical spelling both accepted (INV-002 / INV-2) | `TestVerifyAcceptsRegistrySpellingOfZeroPaddedID`, plus negative: INV-020 ≠ INV-002 | ✔ |
| applies_to match, case-insensitive | `TestVerifyAcceptsAppliesToArtifact` (exact + lowercased) | ✔ |
| Step 4 call-site sweep | All `VerifyInvariantStatement` test call sites re-checked: reproduction, orchestrator port, gate-checklist, guard, r40d, roles, audit p1 already write honest bytes naming the id; unchanged fixtures that named nothing were updated (7 files) | ✔ |
| --exec path still works; note is metadata, never evidence | `TestInvariantVerifyExecRelevanceGate`: generic stdout refused (exit 2), honest stdout lands; the registry note (which always carries the id) is deliberately not consulted — plan Step 6 calls this "the law working" | ✔ |
| Documented-invariant exemption unchanged | guard.go / `AssertInvariantsVerified` not touched by the commit | ✔ |
| Legacy fixture check / deliberate pin updates | `scripts/golden/artifact.md` and `scripts/verify-full.sh` fixture bytes changed BECAUSE the gate refuses the old content (commit message: old bytes → exit 2, proved both ways); historical campaign records untouched; this is the plan's sanctioned deliberate-pin-update discipline | ✔ |
| TDD: red → green, full gates | Re-run independently by this reviewer (see below) | ✔ |

## Reviewer-run gates (independent, writable GOCACHE/GOMODCACHE)

- `go test ./internal/{invariants,cli,state,roles,audit} -count=1` — all ok
  (invariants 0.47s, cli 32.5s, state 10.9s, roles 0.4s, audit 0.2s).
- `go vet` on the touched packages — clean.
- `scripts/golden.sh` — **GOLDEN GREEN** (re-run end to end).
- (Runbook 150/150 claimed by the commit; not re-run here — golden covers the
  same walk-through path including the h1 artifact that matches applies_to
  "Vault" on a word boundary, which the golden green run exercises.)

## Spec-fit under the v3 correction

The correction demotes the mechanism, not the acceptance: the token gate is
retained as *attribution*, and this commit neither claims nor encodes mechanical
verification — `CHECKED_AGAINST_CODE` semantics, the event/save/unwind flow, and
the documented exemption are all unchanged, exactly as the correction demands
for the already-landed change ("The original task below documents the
already-landed change"). Provenance labeling, digest binding, and the
attestation/harness separation were correctly deferred to the follow-up (4A).
No solver or discovery capability was broadened; the change is purely a refusal
gate.

## Non-blocking observations

1. **Digest not checked at the gate (open, owned by the correction).** The gate
   reads the artifact's *current* bytes via `os.ReadFile` without comparing to
   the row's registered `sha256` (stored at registration, artifacts.go:139-152).
   Content swapped between registration and verify would be judged by its new
   bytes. The v3 correction explicitly assigns "bind artifact digest" to the
   follow-up; 4A added provenance labeling but the digest binding itself remains
   open work — tracked here so it is not lost. Not a Task 4 defect: the plan's
   own consumes line specifies plain `os.ReadFile`.
2. **Plan-internal wording conflict resolved toward the stricter reading.** The
   law paragraph (L184) says "case-insensitive substring" while Step 3 (L222)
   mandates word boundaries. The implementer took the word-boundary variant —
   the only one that satisfies the plan's own INV-20 negative test — and the
   deviation is documented in the commit message and code comment. Correct call;
   noted for the record.
3. **Minor: per-call regex compilation.** `artifactReferencesInvariant`
   compiles one regex per token per verify (typically ≤ 4 tokens). Negligible at
   CLI cadence; would only matter if this seam ever moved into a hot loop.

## File-scope note

The review request lists `internal/cli/cmd_invariant_verify.go` among the files;
commit 37511ec8 does not touch it (correctly — the plan says existing callers
need no change, and the CLI's stdout contract is preserved byte-for-byte). That
file's attestation disclosure and header comment arrive with Task 4A
(521eecfd/f13ae1df) and were reviewed there.

## Conclusion

**Spec YES / Quality APPROVED.** The Task 4 gate is a faithful, well-tested
implementation of the original acceptance, correctly subordinated to the v3
correction's attribution-only semantics, with the gate failing closed and the
verification axis provably inert on refusal.
