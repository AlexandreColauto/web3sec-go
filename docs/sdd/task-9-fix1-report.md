# Task 9 fix round 1 — tool-absence boundaries + precedence (F1/F2)

- **Worktree:** `.worktrees/production-readiness`, branch `production-readiness`
- **Base:** `1a03c8ca` (clean) → **commit:** `6fdec840` `fix(envgo): tighten tool-absence matching boundaries and precedence`
- **Scope:** 5 files, +141/−18; stdlib only, no new dep/status/scheduler, no out-of-bounds file touched
- **Verdict:** F1 fixed, F2 fixed (precedence option); all gates green

## Findings as addressed

### F1 — `toolAbsentRe` had no leading word boundary
- **Cause:** `tok := (?:forge|cast|anvil)[\s:,;)"'\]}]` matched `cast` inside
  `broadcast`/`forecast`/`recast` → `forgeAbsentRe` → ENVIRONMENT.
- **Fix:** `tok := \b(?:…)[\s:,;)"'\]}]` in **both** copies (`internal/envgo/classifier.go:70`,
  `internal/sandbox/envseam.go:84`); doc comment updated to name both load-bearing boundaries
  (trailing delimiter keeps `forge-std`/`lib/forge/` out; leading `\b` keeps `broadcast` out).
- **Effect (probed):** `Error: broadcast not found for script deploy` → **SETUP** (+ fresh-context
  retry); `forecast data not found` → **unknown**; `Error: recast not found` → SETUP. Real absence
  forms unchanged: `cast not found`, `/usr/bin/cast: not found`, `no forge installed`,
  `sh: 1: forge: not found` → ENVIRONMENT.

### F2 — `toolAbsent` arm outranked `logicHit`
- **Cause:** `case toolAbsent != "":` sat above `case logicHit:`, so a capture that merely *echoes*
  a subprocess not-found while an assertion fails routed ENVIRONMENT and denied the retry.
- **Fix (review option b):** `case logicHit:` moved **above** `case toolAbsent != "":` in both
  copies (`classifier.go:178`, `envseam.go:217`). Order is now `solcFailed → dockerHit → logicHit →
  toolAbsent → setupHit → unknown`.
- **Why the reorder, not the shell-prefix anchor (review option a):** anchoring `shellAbsentRe` to
  `sh:`/`bash:`/`exec:` prefixes would *narrow the law's own evidence* — a real missing binary
  reported as `jq: command not found` (no shell prefix) would drop out of ENVIRONMENT. The law
  clause the finding broke is precedence ("hypothesis-space assertion failure = its own class"), so
  the precedence fix is the one that preserves both clauses. `shellAbsentRe` is untouched.
- **Effect (probed):** `sh: 1: helper.sh: command not found` + `assertion failed: x != y` →
  **LOGIC**, signals list **both** patterns (`toolchain binary absent …` + `assertion/logic failure
  pattern in output`), note = the LOGIC note (no "do NOT spend a fresh-context retry"). A pure
  echoed not-found with no logic signal stays ENVIRONMENT (the previously disclosed widening is
  retained, now bounded by precedence).

## Tests first (red) → fix (green)

Red was captured before the source change on all three surfaces:

- `red-envgo-sandbox.txt` — `broadcast-not-found-stays-setup` class `environment` (want setup),
  `forecast-word-stays-unknown` `environment` (want unknown),
  `echoed-subprocess-not-found-with-assertion` `environment` (want logic),
  `TestToolchainAbsenceSignalIsRecorded` broadcast case invents the absence signal;
  sandbox `TestClassifyFailureVerdicts` 2 FAILs (same two rows).
- `red-cli.txt` — `TestClassifyVerbToolAbsenceBoundaries` 2 FAILs (ENVIRONMENT for both).

Pins added (all green after the fix):

| Surface | Rows |
| --- | --- |
| `internal/envgo/classifier_toolabsent_test.go` | `broadcast-not-found-stays-setup` (SETUP, note lacks `foundryup`), `forecast-word-stays-unknown` (unknown), `echoed-subprocess-not-found-with-assertion` (LOGIC, note must not deny the retry), `missing-solc-colon-not-installed` (ENVIRONMENT); broadcast row added to `TestToolchainAbsenceSignalIsRecorded` (no absence signal); 3 rows added to the sandbox-mirror differential (`solc-colon`, `broadcast`, `echoed+assertion`) |
| `internal/sandbox/envseam_test.go` | `broadcast-not-found-stays-setup` (setup), `echoed-not-found-with-assertion-stays-logic` (logic), `missing-solc-colon-not-installed` (environment) |
| `internal/cli/cmd_classify_toolabsent_test.go` | new `TestClassifyVerbToolAbsenceBoundaries` drives the wired `classify` verb: SETUP / LOGIC / ENVIRONMENT with note and forbidden-string assertions |

## Gates

Cache note: the briefed `GOCACHE=$PWD/.scratch/gocache go test …` fails on this box
(`golang.org/x/text v0.39.0` absent from the read-only module cache; see
`briefed-command-as-written.txt`, exit=1, `[setup failed]`). Gates were therefore run with the
repo-cache convention already documented in `task-9-report.md`:
`GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`.

| Gate | Command (prefix as above) | Result | Log |
| --- | --- | --- | --- |
| Focused | `go test ./internal/envgo ./internal/sandbox ./internal/cli -count=1` | **exit 0** — ok 0.685s / 50.039s / 32.710s | `green-focused.txt` |
| Full | `go test ./... -count=1` | **exit 0**, 71 ok, 0 FAIL | `full-test.txt` |
| Vet | `go vet ./...` | **exit 0**, no output | `vet.txt` |
| gofmt | `gofmt -l internal/envgo internal/sandbox internal/cli` | empty | (focused run) |

`full-test.txt` was re-run on the final tree (after the probe file below was deleted), so the log
matches the committed content.

## Independent verification

- **Adversarial probe (temporary, deleted after the run; source not committed):**
  `internal/envgo/zz_t9fix1_probe_test.go`, 16 rows + mirror equality + r38 law check — **PASS**,
  log `probe.txt`. It covers rows the tables do not all carry (`broadcast` without an `Error:`
  prefix, `recast`, bare/absolute-path `cast`, `no forge installed`, `forge-std` library,
  `module not found`, assertion alone, echoed not-found alone, container exit 127). Every row also
  asserts `CanonCompact(envgo) == CanonCompact(sandbox default)`.
- **Byte-identity of the shared code:** extracted blocks compared programmatically after the fix —
  `toolAbsentRe` doc+func block identical (1208 B, sha256 `9afec014…`), class switch block
  identical (246 B, sha256 `4c6e4911…`), var-addition block identical (607 B). Only the sandbox
  copy's pre-existing provenance comment differs.
- **r38 rail:** `TestR38WiredCopyMatchesSandboxDefault` + `TestR38WiredClassifierIsHonest` pass in
  the focused run; `internal/cli/zz_r38a_test.go` passes in the CLI package run. The exit-127
  container path (`classifyDockerLevelExit`, early return) is untouched — the probe re-pins its
  "RAN inside the container" note.

## Not changed / residual

- `shellAbsentRe` (see F2 rationale). A pure echoed not-found with no logic signal still routes
  ENVIRONMENT — the widening disclosed in `task-9-report.md` §3a, now subordinate to logic
  evidence.
- **Precedence side effect of F2, documented here because this report did not say it:** moving
  `case logicHit:` above `case toolAbsent != "":` also moved it above `case setupHit:`, so a
  capture carrying BOTH setup and logic text (`Error: compilation failed` + `assertion failed`)
  now routes LOGIC where `eb44603a` routed SETUP. The direction is law-consistent (LOGIC is the
  only class that argues the hypothesis, the same rationale as F2) and no pinned row exercises
  the co-occurrence, but it is a second precedence change beyond F2's letter. (Re-review
  observation 1, `.scratch/sdd/task-9-fix1-review.md` §3.)
- The review's second F2 path (`sh: 1: /tmp/ffi-probe.sh: not found`, a missing *repository
  script*) is unchanged: shell-prefix anchoring does not address it, and tightening it would
  require a script-vs-binary rule the runbook does not state. Left as a documented routing hint.
- Review §4 cosmetic (`sha256 fd9bf0a1…` not reproducible) is report text, not code; not touched.
- No push, merge, delegation, or out-of-scope file edit. Only the 5 listed paths are committed;
  `.scratch/**` logs stay untracked.
