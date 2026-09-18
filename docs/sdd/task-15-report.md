# Task 15 report — docs and pins reconcile

**Status:** DONE. Commit `a79c3fb6` — `docs: reconcile README and runbook with hardened behavior`.

## Rows fixed (each verified against shipped code before writing)

| # | file / row | claim before | shipped behavior (source) |
|---|---|---|---|
| 1 | RUNBOOK §3 "the pin sets scope" | "the **top-level names** land in `source.excluded` … and an `EXCLUDED from the pin` console line" | `excludedNamesIn` records the **relative subpath** of every match at any depth (`internal/snapshot/pin.go:155-176`, written at `:466-471`); the console line is capped at `excludedInlineCap = 10` (`internal/cli/cmd_snap.go:22,180-193`) → `N paths excluded (first 10): … (+M more …)` |
| 2 | RUNBOOK §6a classify | ENVIRONMENT = "daemon down, image missing, solc download cut" | Task 9: an absent `solc` / `forge|cast|anvil` / docker CLI, or a shell's "command not found", is ENVIRONMENT with a fix-naming note (`internal/envgo/classifier.go:38-129`). Added the two boundaries the code keeps: a missing Solidity **library** stays SETUP (`forge-std`/`module not found` → `setupErrRe`), and `logicHit` outranks tool-absence |
| 3 | RUNBOOK §0 `scripts/release.sh` | "build + static proof + standalone walkthrough" | release.sh runs 4 steps **then** `bash "$SCRIPT_DIR/security-check.sh"` (strict, no args) before declaring the release (`scripts/release.sh:156-158`) |
| 4 | RUNBOOK §cheat `brief` row | "operator cockpit (…; pure view)" | Task 7 law: every next-action line is a copyable `webv2 …` command; the per-item detail is no longer inlined, the named `webv2 prove <C> --stage <stage>` prints it and a `# n missing` comment carries the size (`internal/orchestrator/status.go:113-197`). No contradicting row existed — this row *added* the shipped law |
| 5 | README Quick start | "Requires Go 1.26+" | `go.mod`: `go 1.26.2` + `toolchain go1.26.6` (Task 13's bump) |
| 6 | README Verification: release row | "static binary, embedded assets, standalone" | same as #3 |
| 7 | README Verification: verify-full sentence | "runs **every gate above** except the release build" | false twice over: verify-full is 13 steps and runs **no** dependency scan (`TOTAL_STEPS=13`, `scripts/verify-full.sh`); `security-check.sh` is called by `release.sh`. Rewritten to name what it covers and what it excludes (release build, real containers, prover scorecard, dependency scan) |

Historical rows left alone. `docs/IMPROVEMENTS.md` is **untouched** (see
Concerns 1). No marketing claims added; no new claims invented — every edited
row cites the code that ships it.

## Deliberate pin update

`assets/testdata/asset_manifest.json` re-synced with
`python3 scripts/sync-asset-manifest.py` because the embedded `RUNBOOK.md`
bytes changed: 130 files in 9 packs; only the `RUNBOOK.md` `sha256`/`size`
differ. Staged by exact path together with `README.md` and
`assets/runbook/RUNBOOK.md`. `scripts/legacy` untouched (`git status` clean).

## Gates

| gate | command | exit | log |
|---|---|---|---|
| doc contract | `go test ./internal/cli ./assets/... -count=1` | **0** | — (D7 registry↔runbook + asset manifest) |
| runbook | `scripts/runbook-walkthrough.sh` | **0** — 150 passed, 0 failed | `commit3-runbook-walkthrough.txt` |
| golden | `scripts/golden.sh` | **0** — GOLDEN GREEN | `commit3-golden.txt` |
| vet (final HEAD) | `go vet ./...` | **0** | `final-vet.txt` |
| full suite (final HEAD) | `go test ./... -count=1` | **0** — 71 ok, 0 FAIL | `final-gotest.txt` |

Both script gates were re-run **after** the last RUNBOOK byte change (the
manifest was re-synced between the two runs); the results above are the
post-change runs.

## Concerns

1. **`docs/IMPROVEMENTS.md` "production-readiness wave" section was NOT added.**
   The plan's Task 15 names it; the dispatch's commit-3 scope names only
   `README.md` + `assets/runbook/RUNBOOK.md` and says to fix only rows that
   drifted. The dispatch was followed; the wave section is a one-commit
   follow-up listing Tasks 1–16 as shipped.
2. **`scripts/runbook-walkthrough.sh` (and `scripts/release.sh`) still use
   `${VAR:-…}` cache defaults**, so this harness's read-only
   `GOPATH=/home/xand/go` defeats the repo-cache convention and both die with a
   mechanical build failure — the same defect class commit 1 fixed for
   `security-check.sh`. The walkthrough only ran green here with
   `GOCACHE`/`GOPATH`/`GOMODCACHE` forced to the `.scratch` paths. Out of scope
   for a docs commit; worth the same one-line fix.
3. **`verify-full.sh` does not run the dependency scan.** The plan's Task 13
   said to add it as an optional step 14; the shipped wiring put it in
   `release.sh` instead. The docs now describe the shipped wiring (that is the
   dispatch's rule); if the intent was for the full gate to fail on findings,
   the script — not the docs — is what needs changing.
4. **`README.md`'s "thirteen ordered steps" list was left as-is** (it is
   accurate: 13 steps, and the list matches). The pre-existing looseness of
   "every gate above" for the *prover scorecard* and *real containers* rows was
   already corrected elsewhere (line 219-220 for docker); the sentence now names
   all four exclusions explicitly.
