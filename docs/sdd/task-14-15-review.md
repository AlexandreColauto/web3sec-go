# Independent Review — Task 14 (SECURITY.md) and Task 15 (docs reconcile)

Scope: commits `7287e5bb` (SECURITY.md), `a79c3fb6` (README/RUNBOOK/manifest), `16b3bc3a` (IMPROVEMENTS wave section), reviewed against
`docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` Tasks 14/15 + Global Constraints.
Method: read-only. Every check below was performed against the shipped code/evidence in the worktree, not against commit messages.

---

## Task 14 — SECURITY.md (7287e5bb)

**Spec compliance: YES.**

- Plan asks for: trust core (hash chain, atomic writes, process lock, one-writer law) / sandbox IS + IS NOT / E-cap semantics + floors / supported versions / how to report. All present (§"What the trust core protects", §"What the sandbox is — and is not", §"Evidence caps and floors", §"Supported platforms and toolchain", §"Reporting a vulnerability") plus two extra factual sections (attestation-vs-proof, dependency scanning) consistent with the commit message's "every extra line is one of the mandated rows" framing. 121 lines vs the plan's ~80 estimate — estimate, not a cap; no padding.
- Commit touches exactly `SECURITY.md` (task-owned file only). Global Constraints respected: no score claimed, no marketing.

**Claim verification (spot-checks, all traced to code):**

| SECURITY.md claim | Verified at |
|---|---|
| Hash over `seq/at/type/ref/data/prev_hash`, anchored at 64 zero bytes | `internal/state/chain.go:7,37` |
| Atomic tmp-in-dir + `os.Rename` | `internal/validation/atomicio.go:48,72` |
| `flock(LOCK_EX|LOCK_NB)`, 5s budget, depth-counted re-entry, fails loudly | `internal/state/processlock.go:38,50-68` |
| Host labels `host (unconfined — nothing enforces network-off)` / `…deny-rule tripwires only` | `internal/sandbox/profiles.go:77`, `internal/sandbox/exec.go:1297` (byte-identical) |
| Host profiles can never back E4+ (`e4_capable`) | `profiles.go:262`, `internal/envgo/env.go:407` |
| Containers cap E4; only fork-runner reaches E5 | `env.go` `profileMaxLevel` (docker-networkless/docker-gvisor/vm-snapshot → E4, fork-runner → E5) |
| Floor override E4–E7 only, hash-chained `floor_policy.set`/`cleared` | `internal/cli/cmd_floors.go:44`, `internal/floors/floors.go:187` |
| Attestation gate only proves the artifact *names* the invariant | `internal/invariants/invariants.go:835` (`VerifyInvariantStatement`) |
| `run` halts at first model stage, exit 3 | `internal/cli/cmd_run.go:105,122` |
| One JSON-RPC POST is the only outbound call; no telemetry | `internal/envgo/env.go:241` is the **only** non-test `http.*` call site in `internal/` |
| Strict scan: missing scanner → exit 2; dev skips only missing scanner; PASS only on scan exit 0 | `scripts/security-check.sh:7-9,64-92` |
| Linux only; darwin/windows fail to build | `.scratch/sdd/task-14-15-logs/crossbuild.txt` (linux exit=0; darwin fails on `setProcGroup/killGroup`; windows fails on `syscall.Flock/Pwrite`) — matches the two cited root causes |
| Go floor 1.26.2 / toolchain go1.26.6 | `go.mod:4-5` |

**govulncheck PASS wording: accurate.** §"What PASS means" states exit 0 = no known vulnerability reachable by a CALLED symbol, import/require-level advisories don't fail the gate, and PASS is explicitly "not a claim that the dependency graph is clean". This matches govulncheck's called-symbol semantics and the script's behavior (PASS printed only on scan exit 0; INCOMPLETE/failed otherwise). No overstatement found.

**Findings (minor, non-blocking):**

1. **Untraceable env var name `WEBV2_FORK_RPC_URL`** (§"What this tool does not do"). The code reads only `FORK_RPC_URL` (`env.go:266`, `profiles.go:340-345`); `WEBV2_FORK_RPC_URL` appears nowhere in the repo. The `WEBV2_` prefix exists only for `WEBV2_SOLC_DIR` (`env.go:650`). Drop the second name or cite the actual variable — this is the one claim in the file I could not trace.
2. **`vm-snapshot` precision** (§"What the sandbox is"). It is listed among container profiles that "execute a real `docker run`". It *is* classified container-side (in `containerProfiles`, `profileNetwork`/`profileFilesystem` maps, E4 ceiling), but `ProfileAvailable` returns `false` unconditionally for it ("requires external VM infrastructure", `profiles.go:282`) — it can never execute — and `BuildContainerArgv` has no `vm-snapshot` branch: if it ever reached the argv builder it would take the fork-runner `else` arm (bridge + host-gateway), contradicting its recorded `profileNetwork: none`. A one-clause honesty note ("declared, never available today") would make the section airtight. As written it slightly *overstates* shipped behavior for one profile that cannot run.

**Quality: APPROVED** (with the two minor findings above; both are one-line fixes, neither changes the threat-model substance).

---

## Task 15 — docs reconcile (a79c3fb6 + 16b3bc3a)

**Spec compliance: YES** (one process note, below).

- Plan files: README command table, RUNBOOK rows for changed behavior, IMPROVEMENTS "production-readiness wave" section, manifest resync if RUNBOOK changed. All four landed. Changes are restricted to rows the branch actually invalidated — no marketing, no historical rewrites.
- Tests the plan names: runbook walkthrough green (evidence `.scratch/sdd/task-14-15-logs/commit3-runbook-walkthrough.txt`: **150 passed, 0 failed** against the post-commit binary) and manifest test green (equivalently: `python3 scripts/sync-asset-manifest.py --check` → "asset manifest is current").

**Process note (not a violation):** the plan put `docs/IMPROVEMENTS.md` inside Task 15's file list, but `a79c3fb6` deliberately did not touch it — its commit message says so and points at the task-15 report — and the wave section landed in the follow-up commit `16b3bc3a`, after the wave's code, with every referenced hash verified to be a commit in `b0006c4a..HEAD` (I checked all 30 hashes: all OK). The deferral is documented, the deliverable exists, and the IMPROVEMENTS change is a pure append (+140/−0 at EOF). Acceptable sequencing; noting it for the record.

**Row-level verification:**

- *README Quick start:* `go 1.26.2` / `toolchain go1.26.6` matches `go.mod:4-5`. ✔
- *README verify-full sentence:* the replaced claim ("runs every gate above except the release build") was indeed false — `verify-full.sh` declares `TOTAL_STEPS=13` with exactly 13 `step N` lines (1 vet, 2 build, 3 test, 4 race, 5 determinism, 6 asset-pack manifest, 7 golden, 8 crash smoke, 9 legacy, 10-12 CLI smokes, 13 walkthrough) and no security-check/release/scorecard step. The new wording ("thirteen ordered steps … deliberately excludes the release build, the operator-run scans … and the dependency scan") is exact. ✔
- *README/RUNBOOK release row:* `scripts/release.sh` calls `bash "$SCRIPT_DIR/security-check.sh"` (no arguments = strict) as its final step before printing RELEASE OK, with a comment naming T13A. ✔
- *RUNBOOK §3 snapshot prune:* `excludedNamesIn` returns full relative subpaths at any depth (`internal/snapshot/pin.go:155-168`, A10 comment), `excludedInlineCap = 10` (`internal/cli/cmd_snap.go:22`), and the console format matches the RUNBOOK text verbatim including "(+%d more — the full list is in the record's source.excluded)" (`cmd_snap.go:182-186`). ✔
- *RUNBOOK §6a classify:* absent `solc` / `forge|cast|anvil` (word-bounded) / docker plus the shell's "command not found"/"executable file not found" route to ENVIRONMENT with a fix-naming note (`internal/envgo/classifier.go:47-56,88,115-117`); a missing Solidity *library* stays SETUP (`forge-std`/`module not found` in `setupErrRe`, excluded from the tool-absence pattern by the delimiter comment at :62); `logicHit` is checked before the `toolAbsent` arm in the outcome switch (:178-182), so an echoed not-found cannot outrank an assertion failure. All three RUNBOOK sentences map to code. ✔
- *RUNBOOK §cheat brief row:* per-item detail via `webv2 prove <C> --stage <stage>` matches the minter at `internal/briefing/briefing.go:2118-2120`. ✔
- *Asset manifest resync deliberate:* the manifest diff changes only the `RUNBOOK.md` entry; recomputed `sha256sum assets/runbook/RUNBOOK.md` = `f1843f46…b807`, size 110383 — both match the new manifest row exactly, and `--check` reports current. The resync reason (embedded RUNBOOK bytes changed) is in the commit message. ✔
- *Historical rows untouched:* `a79c3fb6` touches only README/RUNBOOK/manifest; `7287e5bb` only SECURITY.md; `16b3bc3a` only appends to IMPROVEMENTS; `git diff 16b3bc3a -- scripts/legacy` is empty. ✔

**16b3bc3a IMPROVEMENTS quality:** one row per commit class, each with commit hashes (all verified in-range); spot-checked rows match shipped state — `ac11de2c` bumps `golang.org/x/text v0.39.0` (go.mod:12) and its message records the 10 called advisories (9 stdlib + GO-2026-5970) exactly as the row states; `0f881e55`'s forced repo Go caches are present in `scripts/runbook-walkthrough.sh:96-98`; `4fa0aef0` is the planner coverage-parity pin test. The section closes with the honest-limitations note the plan's Definition of Done requires (discovery performance not claimed fixed, `coverageSwept` pinned duplicate, container-is-the-boundary) — no score anywhere.

**Quality: APPROVED.** No findings beyond the process note. (The runbook-walkthrough cache defect the `a79c3fb6` commit message flagged was subsequently fixed by `0f881e55`, so nothing is left dangling.)

---

## Verdict summary

| Task | Spec | Quality |
|---|---|---|
| 14 — SECURITY.md (7287e5bb) | YES | APPROVED — 2 minor findings: phantom `WEBV2_FORK_RPC_URL` name; `vm-snapshot` "executes a real docker run" precision |
| 15 — docs reconcile (a79c3fb6 + 16b3bc3a) | YES | APPROVED — process note only (IMPROVEMENTS section deferred to the follow-up commit, documented, append-only) |

Worktree left clean (no tracked changes made by this review).
