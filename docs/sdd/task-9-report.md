# Task 9 report — classify maps missing-compiler to ENVIRONMENT

- **Plan:** `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` §Task 9 (lines 254-257), read with the header (1-9), Global Constraints v3 (11-23) and the Phase B preamble (229-231)
- **BASE:** `b77eb7fa` ("fix(orchestrator): next-actions close their proofs (review round 1)") — branch `production-readiness`, worktree `.worktrees/production-readiness`, nothing pushed or merged
- **Status:** implementation complete, all gates green, committed
- **Commit:** `eb44603a` — `fix(envgo): missing toolchain classifies ENVIRONMENT per runbook` (exact paths in §9); worktree clean after the commit

## 1. The law, and the runbook row read FIRST

Plan §Task 9, verbatim:

> **Files:** `internal/envgo` failure classifier (locate the SETUP classification of tool-absent), its test table.
> **Law:** missing toolchain/dependency (solc, forge, docker binary) → ENVIRONMENT per the runbook's own vocabulary; only hypothesis-space failures stay SETUP. Read the runbook row FIRST and make the code match the documented law.
> **Test:** table row `missing solc` → class ENVIRONMENT; note text names the fix.

**The runbook row was read before any code was touched** — `assets/runbook/RUNBOOK.md` §0, lines 46-53:

> `solc` is downloaded by the container on first use. With the network cut (networkless / gvisor / vm-snapshot profiles), a missing solc binary is an **environment failure, not a harness bug**. Provision it one of two ways: preinstall the svm layout (`~/.svm/<version>/solc-<version>`) into a custom image, or point `WEBV2_SOLC_DIR` at a host dir with that layout — it is bind-mounted into every container at `/home/foundry/.svm`. A failed exec is classified on the spot (`classify`, §6): an environment failure says so and tells you NOT to spend a fresh-context retry.

and §6a, lines 942-945:

> A FAILED exec is classified on the spot: **ENVIRONMENT** (daemon down, image missing, solc download cut — fix the environment, do NOT spend a fresh-context retry), **SETUP** (retry in a fresh context with the failure record), **LOGIC** (the only class that argues the hypothesis).

`assets/runbook/AGENT_BOOTSTRAP.md:63-67` says the same ("with the network cut, a missing solc is an environment failure, not a harness bug: preinstall it into the image's svm cache or point `WEBV2_SOLC_DIR` at a host dir with the svm layout").

**STOP-condition check: not triggered.** The runbook never says SETUP for a missing tool. The three rows that mention an absent toolchain (RUNBOOK §0, §6a, BOOTSTRAP §4) all name ENVIRONMENT. The code was changed to match the documented law.

## 2. What was actually red (measured, not assumed)

The classifier is `envgo.ClassifyFailure` (`internal/envgo/classifier.go`), installed over the sandbox seam by `ensureSeams` (`internal/cli/cmd_dedup.go:303`) and `cmd/webv2/main.go`, so it is what `webv2 exec` / `webv2 classify` speak. Its class switch ordered `solc-download > docker/daemon > setup > logic`, where "setup" is a broad heuristic (`setupErrRe`, plus `Error: <anything without assert>` via `errorNotAssert`). A missing binary therefore fell through to SETUP or UNKNOWN:

- `Error: solc 0.8.24 is not installed. Install it with \`svm install 0.8.24\`` → **setup** (the `Error: ` heuristic), note "retry in a fresh context with this failure record"
- `Error: solc not found` → **setup**, same note
- `solc 0.8.24 pinned by foundry.toml but missing from the svm cache …` → **unknown** ("routed as setup")
- `sh: 1: forge: not found` (exit 1, not a docker-level code) → **unknown** ("routed as setup")
- `forge: command not found` → **unknown**
- `docker: command not found` / `exec: "docker": executable file not found in $PATH` → **unknown**
- `Error: docker image ghcr.io/…:latest not found` → **setup**

i.e. exactly the case the runbook forbids: a box that lacks the binary spent the finding's fresh-context retry. Before/after, reproduced with `.scratch/task-9-probe` (sources stashed/unstashed around the run): `.scratch/sdd/task-9-logs/probe-before.txt` vs `probe-after.txt`.

## 3. What changed

Two new pieces of evidence in the classifier, both taken from the runbook's vocabulary:

1. **`toolAbsentNote(text)`** — tool-absent evidence for a *named* binary (`solcAbsentRe`, `forgeAbsentRe` over `forge|cast|anvil`, `dockerAbsentRe`) plus `shellAbsentRe` for the shell/exec layer's own "I could not find the command" (`command not found`, `executable file not found`, `sh: 1: jq: not found`). Returns a fix-naming note, or `""` when there is no absence evidence.
2. **Class precedence** — `toolAbsent != ""` is `environment`, checked *before* the setup heuristic (so `Error: solc … is not installed` can no longer be swallowed by `errorNotAssert`), and its note is returned instead of the generic "fix the environment" shrug.

The signal `toolchain binary absent (not found / not installed)` is appended whenever absence evidence fires, so the class never travels without what produced it.

The note is per-binary and names the fix (plan: "note text names the fix"):

| absent binary | note names |
| --- | --- |
| solc | svm cache layout `~/.svm/<version>/solc-<version>` or `WEBV2_SOLC_DIR`, then `webv2 env doctor` |
| forge/cast/anvil | `foundryup` (or preinstall in the image), then `webv2 env doctor` |
| docker | install the docker CLI or use `host-readonly`; pull the pinned image; `webv2 env doctor` |
| unnamed shell binary | all three fixes |

Every one of them ends with the §6a retry discipline: "do NOT spend a fresh-context retry".

### 3a. Deliberate boundary decisions (for the reviewer)

- **`forge-std` is not "forge".** The tool token requires a trailing delimiter (`[\s:,;)"'\]}]`), so `forge-std`, `forge-std/Test.sol` and `lib/forge/` do **not** match: a missing Solidity *library* is repository setup (already a `setupErrRe` signal) and stays SETUP. A bare `\bforge\b` would have swallowed it. Pinned by the `hypothesis-missing-solidity-library` and `hypothesis-module-not-found` rows.
- **`missing` is admitted for solc/foundry but not for docker.** "solc 0.8.24 missing from the svm cache" is a missing compiler; "docker image X missing" is a missing *image*, not a missing CLI — so the docker note names **both** readings ("either the docker CLI is not on this box's PATH or the image it needs is not there") and points at `webv2 env doctor` instead of asserting a diagnosis the evidence does not carry. Pinned by the `missing-docker-image` row (class ENVIRONMENT per §6a's "image missing", note honest about which fix applies).
- **`shellAbsentRe` is broader than the three named binaries.** `sh: 1: jq: not found` now classifies ENVIRONMENT with the generic note. Rationale: an absent binary is not hypothesis-space, and the runbook's ENVIRONMENT row is "the box cannot run this", not "the box cannot run exactly solc/forge/docker". Flagged here because it is wider than the plan's parenthetical. If the reviewer wants the narrower reading, the fix is to drop the `shellAbsentRe` case from `toolAbsentNote` (one line) — the solc/forge/docker rows do not depend on it.
- **Docker/daemon and solc-download notes keep precedence** when their patterns also fire (`&& !dockerHit`): the two families only co-occur in contradictory captures, and the existing, more specific note wins.

### 3b. The sandbox default had to be mirrored (r38 rail)

`internal/sandbox/envseam.go`'s `defaultClassifyFailure` is a *transcription* of the same classifier and is the seam fallback (what the verbs speak when envgo is not installed). `internal/envgo/zz_r38a_test.go:TestR38WiredCopyMatchesSandboxDefault` and the seam-audit table in `internal/cli/zz_r38a_test.go` (line 279: `sandbox.SetClassifyFailure(envgo.ClassifyFailure)  copy (r36 bug — FIXED)`) exist precisely because a stale second copy of this algorithm is the r36 bug class. Changing only the envgo copy would have left the fallback speaking the old law — the exact defect that rail was built to prevent.

So the identical hunks were applied to both files — verified byte-identical after the fact (helper block `sha256 fd9bf0a11d0e16d7`, 3214 bytes in both; the `solcAbsentRe…shellAbsentRe` var block identical; both integration hunks identical) — and the rail was extended for the new law:

- `TestToolchainAbsenceIsMirroredInTheSandboxDefault` (new, `internal/envgo/classifier_toolabsent_test.go`) — 7 rows; the r38 differential table predates Task 9 and therefore cannot see a divergence on tool-absent text. Note this test is a *mirror* check, not a law check: under the pre-fix sources it passes (both copies are stale together), which is why the law reds are the table tests below.
- `internal/sandbox/envseam_test.go` — 4 additive rows in `TestClassifyFailureVerdicts` (missing-solc / missing-forge / missing-docker / missing-library-stays-setup) and a fix-naming assertion in `TestClassifyFailureNotes`. No existing row was modified.

## 4. Tests first: red, then green

Tests were written before the implementation. The envgo table is the law; the CLI test is the operator surface; the sandbox rows are the mirrored default.

**Red #1 — the law table, against the unmodified sources** (`.scratch/sdd/task-9-logs/red-focused.txt`, `go test ./internal/envgo -run TestToolchainAbsence -count=1`):

```
--- FAIL: TestToolchainAbsenceClassifiesEnvironment/missing-solc-not-installed
    class = "setup", want "environment" (signals compilation/setup error pattern, note "retry in a fresh context with this failure record")
--- FAIL: .../missing-solc-not-found            class = "setup"
--- FAIL: .../missing-solc-missing-from-cache   class = "unknown"
--- FAIL: .../missing-forge-not-found           class = "unknown"
--- FAIL: .../missing-forge-command-not-found   class = "unknown"
--- FAIL: .../missing-docker-command-not-found  class = "unknown"
--- FAIL: .../missing-docker-executable-file-not-found  class = "unknown"
--- FAIL: .../missing-tool-generic-shell        class = "unknown"
--- FAIL: TestToolchainAbsenceSignalIsRecorded  signals = "compilation/setup error pattern"
```

The hypothesis-space rows (`hypothesis-compile-error`, `hypothesis-missing-solidity-library`, `hypothesis-module-not-found`, `hypothesis-logic`, `unclassified-stays-unknown`) and the pre-existing `missing-forge-exit127-host` row **passed before the change** — they are the boundary, and they never moved.

**Red #2 — every new test against the pre-fix sources (mutation run).** `git stash push -- internal/envgo/classifier.go internal/sandbox/envseam.go`, run the new tests, `git stash pop` (source hashes verified identical after the pop):

- `.scratch/sdd/task-9-logs/red-mutation.txt` — envgo table + `TestToolchainAbsenceSignalIsRecorded` + the CLI verb test, all red against the pre-fix classifier:
  ```
  --- FAIL: TestClassifyVerbMissingToolchainIsEnvironment/missing-solc
      class line = "exec EXEC-d8636f116a (exit 1): SETUP\n  signal: compilation/setup error pattern\n  retry in a fresh context with this failure record\n", want ENVIRONMENT
  --- FAIL: .../missing-forge   class line = "exec EXEC-… (exit 1): UNKNOWN\n  unclassified; routed as setup (the cheap error)\n"
  --- FAIL: .../missing-docker  class line = "exec EXEC-… (exit 1): UNKNOWN\n  unclassified; routed as setup (the cheap error)\n"
  ```
- `.scratch/sdd/task-9-logs/red-mutation-sandbox.txt` — the mirrored default's own rows:
  ```
  --- FAIL: TestClassifyFailureVerdicts
      missing-solc: class = "setup", want "environment"
      missing-forge: class = "unknown", want "environment"
      missing-docker: class = "unknown", want "environment"
  --- FAIL: TestClassifyFailureNotes
      absent solc = {"class":"setup","note":"retry in a fresh context with this failure record",…}
  ```

The CLI test (`internal/cli/cmd_classify_toolabsent_test.go`) was written after the fix, so its red is Red #2 (the same code path, sources stashed), not a pre-implementation run. Stated plainly rather than implied.

**Green.** `TestToolchainAbsenceClassifiesEnvironment` is 15 rows (9 tool-absence → ENVIRONMENT, 1 pre-existing exit-127 shape, 5 hypothesis-space/unclassified); plus `TestToolchainAbsenceSignalIsRecorded` (2 assertions), `TestToolchainAbsenceIsMirroredInTheSandboxDefault` (7 rows), the sandbox table's 4 new rows + the note assertion, and the CLI verb test (3 sub-cases asserting the class line, the absence signal, the named fix, and the absence of "retry in a fresh context").

## 5. Gates (all logs in `.scratch/sdd/task-9-logs/`)

| Gate | Log | Result |
| --- | --- | --- |
| `go test ./internal/envgo ./internal/cli -count=1` | `green-focused.txt` | `ok envgo 0.600s`, `ok cli 33.637s`, `[exit 0]` |
| `go test ./... -count=1` | `full-test.txt` | all packages `ok` / no test files, `[exit 0]` (no `FAIL` line) |
| `go vet ./...` | `vet.txt` | `[exit 0]` |
| `bash scripts/golden.sh` (incl. `python3 scripts/check-golden.py`) | `golden.txt` | `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)`, `[exit 0]` |
| `bash scripts/runbook-walkthrough.sh` | `runbook.txt` | `walkthrough: 150 passed, 0 failed … WALKTHROUGH GREEN`, `[exit 0]` — including the `§6a classify ok` step |
| `gofmt -l internal cmd` | — | empty (also enforced inside `golden.sh`) |
| `go test ./internal/envgo ./internal/cli -count=1` on the committed tree | `green-postcommit.txt` | `ok envgo 0.585s`, `ok cli 32.966s`, `[exit 0]` at `eb44603a` |

**Cache note.** The briefed command is `GOCACHE=$PWD/.scratch/gocache go test …`; on this box the Go module cache at `/home/xand/go/pkg/mod` is read-only to the session and does **not** carry `golang.org/x/text v0.39.0` (required since `ac11de2c`), so the gates were run with the repo-cache convention used by Tasks 1/4/5/13: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`. Every log records the exact command line.

## 6. Pins: nothing asserted the old class, so nothing was re-pinned

Global Constraint 20 required checking whether any golden/runbook pin asserted the old class for a missing-tool fixture. Checked, and none do:

- `scripts/golden-run.py:631` runs `classify` on the *failing* golden exec (`{"name": "exec-fail", "argv": ["exec", cid, "--command", "exit 7", …]}`) — its captured output is `exit 7` with no tool-absent text, so the class is unchanged by this task.
- `scripts/check-golden.py` carries **no** classify/class assertion at all (grep for `classif|ENVIRONMENT|SETUP` → 0 hits); it validates declared exit codes, the tree and the event chain, and the 14 audit sections.
- `scripts/runbook-walkthrough.sh:384` checks `classify` exit 0 only (`check classify ok "exec EXEC-" §6a`), no class text.
- No golden/legacy fixture contains missing-tool exec text (grep for `not found|not installed|command not found` across `scripts/golden/**/*.json` → 0 hits).

Both pin suites were re-run anyway (§5) and are green, so **no pin file was modified** in this commit. No `scripts/legacy` file was touched (`git status --porcelain -- scripts/legacy scripts/golden assets/runbook docs` is empty).

## 7. Historical fixtures and out-of-bounds files

- `scripts/legacy/**` untouched: no sanitizing, re-registering, hash regeneration or assertion rewriting. The task's changes are confined to the classifier and its tests, and the reader/audit surfaces are exercised green by the full suite and the golden replay.
- The Global Constraints' out-of-bounds list (`LEARNINGS.md`, RUNBOOK, asset manifest, docs) is untouched — this worktree was clean at hand-off and no doc needed changing (the code now matches the runbook as written; the runbook was *not* wrong).
- `git status --porcelain` shows exactly the five task files (§9).

## 8. Concerns / for the reviewer

1. **`internal/sandbox/envseam.go` was changed too.** The plan's `Files:` line names only `internal/envgo`. It was unavoidable: the r38 rail (`internal/envgo/zz_r38a_test.go`, `internal/cli/zz_r38a_test.go:279`) requires the envgo copy and the sandbox default to agree, and the sandbox default is the seam fallback the verbs speak when envgo is not installed. Leaving it stale would have shipped the exact r36 defect ("default fixed, copy stale") in reverse. The two hunks are identical; the mirror test pins them together. A reviewer who disagrees can drop the sandbox hunk and the mirror test — the envgo law tests stand alone.
2. **`shellAbsentRe` is wider than the plan's parenthetical** (solc/forge/docker): any `command not found` / `sh: 1: x: not found` now routes ENVIRONMENT. Deliberate (an absent binary is not hypothesis-space), but it is the one place the change is broader than the literal Task 9 scope. One-line revert path noted in §3a.
3. **`docker image … not found` changed class** from SETUP to ENVIRONMENT (with a hedged note). It is arguably §6a-correct ("image missing") but it is outside the plan's named fixtures; pinned explicitly by the `missing-docker-image` row so it cannot drift silently.
4. **Red evidence for the CLI test is mutation-based** (§4, Red #2), not a pre-implementation run — the test was authored after the fix, and the pre-fix red was re-established by stashing the source hunks and verifying the restored hashes.
5. **No run_code/delegation was used**, no push/merge, no new dependencies, no new status enum, no new scheduler (Global Constraints 15) — the change reuses the existing `classifyResult` shape, the existing regex/note idiom, and the existing seam.

## 9. Commit

Exact paths (no `git add -A`):

```
internal/envgo/classifier.go                 (modified: +108/-1)
internal/envgo/classifier_toolabsent_test.go (new, 208 lines)
internal/cli/cmd_classify_toolabsent_test.go (new, 68 lines)
internal/sandbox/envseam.go                  (modified: +110, the mirrored default)
internal/sandbox/envseam_test.go             (modified: +22, additive rows)
```

Message: `fix(envgo): missing toolchain classifies ENVIRONMENT per runbook`

