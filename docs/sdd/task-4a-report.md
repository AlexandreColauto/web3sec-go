# Task 4A report — operator-attestation provenance

**BASE** `b00532ca969729291e94c7cec7c2b234de161abf`
**HEAD** `521eecfdac37a4f6c914ff573e3fda159caa100b`
**Commit** `fix(invariants): disclose operator attestation provenance` — 4 files, +342/-10
**Worktree** `.worktrees/production-readiness`, branch `production-readiness`
**Not done, per instructions:** no push, no merge, no delegation, no plan edit, no fixture edit.

Files in the commit (the brief's owned set, exactly):

| file | delta |
| --- | --- |
| `internal/invariants/invariants.go` | +65/-5 |
| `internal/invariants/invariants_test.go` | +209/-0 |
| `internal/cli/cmd_invariant_verify.go` | +19/-5 |
| `internal/cli/cmd_invariant_verify_test.go` | +49/-0 |

---

## 1. What the interrupted implementer left, and what I changed

**Left behind (uncommitted, complete):** the whole functional slice. The four files
already carried the `verification_method` write on the entry and on the event, the
exported `VerificationMethod` helper, the reworded doc comments, the CLI stderr
disclosure, and the five new invariants tests plus one new CLI test.

**What I changed in the four files: nothing.** I audited the diff against every line of
`.scratch/sdd/task-4a-brief.md` and found no functional gap to close; the brief's
"smallest change" rule therefore means leaving the code as the interrupted agent wrote
it. Everything I added is evidence under `.scratch/sdd/task-4a-logs/` (no existing log
was overwritten — the two logs the interrupted agent left are intact):

- `red-focused-repro.txt` — independently reconstructed red run (see §4).
- `base-twin-check.txt` — the two Python-twin tests **pass** at BASE.
- `green-focused-final.txt`, `full-suite-final.txt`, `vet-final.txt` — first gate runs.
- `gate-runs.txt` — all gates re-run against the committed tree.
- `backup/` — md5-pinned copies of the four files plus the pre-stash patch, taken before
  any `git stash` so the work could be restored byte-for-byte.

**Restoration proof:** all four files hash identically before and after the two stash
cycles (`3fe8e6db…`, `6b2c2cf0…`, `0b972e27…`, `d692f43b…`); `git stash list` is empty
and `git status --porcelain` is clean at HEAD.

## 2. Requirement-by-requirement verification

| # | Brief requirement | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | Success writes `verification_method: "operator-attestation"` into the **registry entry** | MET | `invariants.go:856-857` `SetOrAppend(entry.O, verificationMethodKey, VStr(verificationMethodAttestation))`; `TestVerifyRecordsOperatorAttestationProvenance` reads it back through `LoadLinks` |
| 2 | …and into the **`invariant.verified` event's data**, keeping `artifact` | MET | `invariants.go:863-866` `VObj(pair("artifact",…), pair(verificationMethodKey,…))`; same test asserts both keys on the single matching event |
| 3 | Status stays `CHECKED_AGAINST_CODE` for compatibility | MET | unchanged `invariants.go:853-854`; asserted in the same test |
| 4 | Exported `VerificationMethod(entry)` → only `operator-attestation` / `legacy-unspecified` / `unrecognized` | MET | `invariants.go:799-808` + label consts `:780-791`; `TestVerificationMethodLabels` covers absent, exact, case-variant, other string, empty, null, int, bool, object, array, non-object entry |
| 5 | No inference from status / artifact token / log words | MET | helper reads one key through `fieldAt` and returns; no status, `verified_by` or event input |
| 6 | Label helper is not an authorization decision | MET | no gate reads it; the only callers are the new tests (repo-wide `rg verification_method` hits the four owned files only) |
| 7 | No overwrite/manufacture of `verification.harness`, `bounded_k`, proof sidecars or test outcomes | MET | `TestVerifyPreservesExistingVerificationHarness` (byte-compares the `verification` subtree via `CanonCompact`, checks no top-level `bounded_k`/`proof`/`harness`, `tests` stays empty); the write path touches only `status`, `verified_by`, `verification_method`, `contradiction`, `modified_by`, `updated_at` |
| 8 | CLI stdout summary preserved | MET | `cmd_invariant_verify.go:105-106` untouched; `TestInvariantVerifyDisclosesOperatorAttestation` asserts the exact stdout line |
| 9 | CLI stderr disclosure on **success only**, exact text | MET | `cmd_invariant_verify.go:107-110`, `Fprintln` of the exact sentence; test asserts exact stderr on success and that refusal stderr contains no "operator attestation" and stays one line |
| 10 | Misleading function/header comments updated; no claim regex establishes correctness | MET | file header `:3-22`, `VerifyInvariantStatement` doc `:810-834`, `artifactReferencesInvariant` doc `:882-887` all say ATTRIBUTION ONLY / not mechanical proof |
| 11 | Historical entries read without mutation, never auto-acquire provenance | MET | `VerificationMethod` is a pure lookup; `TestVerificationMethodReadsOldEntryWithoutMutation` asserts `CanonCompact` is unchanged across the call |
| 12 | Refusal leaves the method absent and logs no new event | MET | gate returns at `invariants.go:850-852`, before any write; `TestVerifyRefusalLeavesAttestationAbsent` checks key absence, `legacy-unspecified`, and an unchanged `invariant.verified` count via `r40dEventCount` |
| 13 | No solver / discovery / scheduling / evidence-floor change | MET | diff touches no other symbol; `go vet ./...` clean; no other package fails |
| 14 | No resource-exhaustion or target-vulnerability tests | MET | new tests are fixture-only |
| 15 | Tests first (red before code), then green | MET (red re-proven) | §4 |
| 16 | Fixtures preserved | MET | `git status` clean; no `testdata/` or `scripts/` file in the commit — see §5 for the consequence |

## 3. Test transcripts and exact exits

All runs use `GOCACHE=$PWD/.scratch/gocache` in
`/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`.

All four gate commands were run **twice**: once against the uncommitted tree (whose bytes
are identical to the commit) and once against the committed tree `521eecfd`. Both runs
agree; `gate-runs.txt` holds the post-commit transcript.

| command | exit | log |
| --- | --- | --- |
| `go test ./internal/invariants ./internal/cli -count=1` | **1** | `task-4a-logs/gate-runs.txt` §1 (also `green-focused-final.txt`) |
| `go test ./... -count=1` | **1** | `task-4a-logs/gate-runs.txt` §2 (also `full-suite-final.txt`) |
| `go vet ./...` | **0** | `task-4a-logs/gate-runs.txt` §3 (also `vet-final.txt`) |
| `gofmt -l <the four owned files>` | **0**, empty output | `task-4a-logs/gate-runs.txt` §4 |
| `go test ./internal/invariants ./internal/cli -run '<the 5 new invariants tests + the invariant-verify CLI tests>' -count=1 -v` | **0** / **0** | `task-4a-logs/gate-runs.txt` §5 — all six new tests `PASS`, every pre-existing `invariant-verify` CLI test still `PASS` |

Exact failure set of the two `go test` runs — and the **only** failures in the whole
tree: `internal/invariants` → `TestGuardMessagesMatchPythonTwin`,
`TestLinkScenarioMatchesPythonTwin`. Every other package reports `ok` (72 `ok` lines);
`internal/cli` is `ok 28.5s`. The new tests all pass. `go vet` and `gofmt` are clean.

## 4. Red-first evidence

**A red log existed** — the interrupted agent left `.scratch/sdd/task-4a-logs/red-focused.txt`
(895 B, mtime 23:22:28, one minute before its green attempt). I did not have to fall back
on "red evidence is missing". I still re-derived it independently, because a red log that
cannot be reproduced is not evidence. Method: back up all four files + the diff to
`backup/` with md5 pins, then
`git stash push -- internal/invariants/invariants.go internal/cli/cmd_invariant_verify.go`
— i.e. the **tests are present, the implementation is absent**, which is the honest
red-first state:

```
# websec/internal/invariants [websec/internal/invariants.test]
internal/invariants/invariants_test.go:1193:12: undefined: VerificationMethod
internal/invariants/invariants_test.go:1200:12: undefined: VerificationMethod
internal/invariants/invariants_test.go:1276:13: undefined: VerificationMethod
internal/invariants/invariants_test.go:1294:12: undefined: VerificationMethod
internal/invariants/invariants_test.go:1368:12: undefined: VerificationMethod
FAIL	websec/internal/invariants [build failed]
--- FAIL: TestInvariantVerifyDisclosesOperatorAttestation (0.01s)
    cmd_invariant_verify_test.go:241: stderr "", want "invariant-verify: operator attestation recorded; artifact attribution is not mechanical proof\n"
FAIL
FAIL	websec/internal/cli	29.195s
FAIL
### exit: 1
```

Byte-for-byte the same failure set, at the same five line numbers, as the recorded
`red-focused.txt` → the recorded red run is genuine. Transcript:
`task-4a-logs/red-focused-repro.txt`. The stash was popped immediately and all four files
verified against their md5 pins.

**BASE twin check** (`task-4a-logs/base-twin-check.txt`): with all four files stashed
(pure BASE `b00532ca`) the two twin tests **pass**:

```
--- PASS: TestGuardMessagesMatchPythonTwin (0.01s)
--- PASS: TestLinkScenarioMatchesPythonTwin (0.01s)
ok  	websec/internal/invariants	0.021s
### exit: 0
```

That is the necessity proof for §5: the parity break is caused by this change, not
pre-existing.

## 5. Blocking concern — Python-twin byte parity (NOT fixed, deliberately)

`TestLinkScenarioMatchesPythonTwin` and `TestGuardMessagesMatchPythonTwin` assert that the
campaign files the Go code writes (`artifacts/invariant_links.json`, `events.jsonl`) are
**byte-identical** to frozen fixtures under `internal/invariants/testdata/`:
`scenario_links.json`, `scenario_events.jsonl`, `guard_links.json`, `guard_events.jsonl`.
Those four files have not been touched since the original port commit `32641d7f`
("P1 Task 8: invariants package") — they are the retired Python twin's recorded bytes.

The brief mandates a new key on the entry **and** on the event's data. Byte-identity with
the pre-change twin bytes is therefore impossible. The failure output isolates the delta
to exactly that key — `INV-2` gains `"verification_method": "operator-attestation"`
immediately after `"verified_by"` — and nothing else moves. `scenario_coverage.json`,
`scenario_uncovered.json` and `guard_messages.json` are unaffected.

I did **not** re-pin the fixtures, for three reasons:

1. the brief says "Preserve historical fixtures" and "Never weaken historical fixtures for
   green", and the dispatch says not to touch fixtures;
2. re-pinning would make the test name a lie — afterwards
   `TestLinkScenarioMatchesPythonTwin` would no longer compare against the twin's bytes but
   against bytes this build produced, i.e. exactly the weakening the brief forbids;
3. the change needed (a decision about the parity oracle for the invariants package) is
   outside the brief's four owned files, and the brief says to stop with concrete evidence
   rather than widen scope silently.

**This needs an explicit decision by the orchestrator/operator.** Options: (a) authorize a
reviewed re-pin of the four fixtures, renaming/annotating the two tests as Go regression
pins rather than twin parity; (b) scope the provenance write so the twin-compared path is
untouched — which contradicts the brief; or (c) record the deviation in the plan and
accept two known-red tests. Until one is chosen, the tree is **not green** and this slice
must not be reported as passing its gates.

## 6. Limitations (do not oversell this slice)

- **Attribution, not proof.** The relevance gate is a case-insensitive word-boundary regex
  over the artifact's bytes. Nothing here establishes that a check is correct, that it ran,
  that it passed, or that the invariant holds. The label and the stderr line say precisely
  that, and nothing more.
- **Digest/source binding still open.** The artifact is cited by id/path; no content digest
  or source-range binding is written or re-verified on this path, so a later edit of the
  artifact's bytes is undetected. The brief explicitly leaves this as a separate unresolved
  item.
- **No admission-semantics change.** No gate reads `verification_method`;
  `CHECKED_AGAINST_CODE` keeps exactly the force it had. Making a gate require
  `operator-attestation` would be a different decision with its own blast radius.
- **`legacy-unspecified` is a statement about the record, not about the check.** It means
  the record does not say how it was established — never that it was established weakly.
- **Gates not run:** `scripts/golden.sh`, `scripts/verify-full.sh`,
  `scripts/runbook-walkthrough.sh` (not required by the brief). Inspection says the new
  stderr line is safe there — `verify-full.sh`'s `p1_ok`/`p2_ok`/`p3_ok` merge stderr into
  stdout and assert only exit codes, and `check-golden.py` never inspects
  `invariant.verified` — but that is inspection, not a run.
- **Residual (parked, deliberate):** the command-registry help line at
  `cmd_invariant_verify.go:239` still reads "mark an invariant verified". It is
  user-visible and arguably still misleading, but it is not a comment, it belongs to the
  CLI surface the brief asked to preserve for compatibility, and nothing pins it. Left
  unchanged under "smallest change"; flagged for the docs wave.

