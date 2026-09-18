# Task 14 report — SECURITY.md (honest release assurance summary)

**Status:** DONE. Commit `7287e5bb` — `docs: add SECURITY.md release assurance summary`.

## Deliverable

`SECURITY.md` at repo root, 121 lines (plan target ~80; every extra line is one
of the mandated rows — see Concerns 1). Facts only; each claim carries the file
that enforces it. Sections:

| mandated row | where | source verified against |
|---|---|---|
| supported platforms | "Supported platforms and toolchain" | `GOOS=linux` builds; `GOOS=darwin`/`GOOS=windows` fail (evidence below) |
| Go floor + toolchain go1.26.6 | same | `go.mod`: `go 1.26.2`, `toolchain go1.26.6` |
| how to run the release scan | "Dependency and release scanning" | `scripts/security-check.sh`; called last by `scripts/release.sh:158` |
| advisory-driven dependency policy | same | `scripts/security-check.sh` header (no `go get`, no tool install, no latest-bumps) |
| attestation-vs-proof disclosure | "Attestation is not proof" | `VerifyInvariantStatement`, `internal/invariants/invariants.go`; Task 4's acceptance correction |
| no offensive-automation claims | "What this tool does not do" | `internal/cli/cmd_run.go` (halts at first model stage, exit 3); only outbound call is the operator's fork JSON-RPC POST (`internal/envgo/env.go`) |
| trust core | "What the trust core protects" | hash chain `internal/state/chain.go` + `verifylog.go`; atomic tmp+rename `internal/validation/atomicio.go`; flock lock `internal/state/processlock.go`; one-writer law |
| sandbox IS / IS NOT | "What the sandbox is — and is not" | `internal/sandbox/profiles.go` (container flags; `HostProfile`; honest `networkLabel`); `internal/sandbox/exec.go` (`profileFilesystemLabel`); deny rules = static regex tripwires |
| E-cap semantics, floors don't lower | "Evidence caps and floors" | `HostProfile` + `e4_capable` (`internal/envgo/env.go`); floors table `internal/findings/levels.go`; E4–E7 overrides + `floor_policy.set`/`cleared` (`internal/cli/cmd_floors.go`, `internal/floors/floors.go`) |
| how to report | "Reporting a vulnerability" | no remote is configured in this worktree, so no URL is invented |

**Explicitly not overstated:** `govulncheck` PASS = no **CALLED** known
vulnerability; import-level and require-level uncalled advisories are reported
and do not fail the gate — not a clean dependency graph (Task 13 report §8.5).

## Verification

- Every claim was checked against code with `rg`/`read` **before** writing; the
  two claims that needed empirical proof were run, not read:
  - `.scratch/sdd/task-14-15-logs/crossbuild.txt` — `GOOS=linux` exit 0;
    `GOOS=darwin` exit 1 (`undefined: setProcGroup`/`killGroup`, the sandbox
    procsig files are `//go:build linux`); `GOOS=windows` exit 1
    (`syscall.Flock`/`LOCK_EX`/`Pwrite` undefined in `processlock.go`).
- No code, golden pin, or asset-manifest change: `SECURITY.md` is a repo-root
  file and is **not** embedded (`scripts/sync-asset-manifest.py` covers
  `assets/` only). Task 14's test contract is "none"; `scripts/verify-full.sh`
  is unaffected.
- Final HEAD gates: `go vet ./...` exit 0; `go test ./... -count=1` exit 0
  (71 packages ok, 0 FAIL) — logs `final-vet.txt`, `final-gotest.txt`.

## Concerns

1. **Length 121 lines vs the plan's "~80".** No padding: the six mandated rows
   plus the three threat-model sections the plan names do not fit in 80 without
   dropping file refs. Trim only by dropping evidence.
2. **No security contact exists in the repo** (no remote configured in this
   worktree, no prior SECURITY.md/CONTRIBUTING.md). The reporting section names
   the mechanism (hosting forge's private vulnerability reporting) rather than
   an address; if the project has a real contact, add it.
3. **The Linux-only statement is scoped to what was tested**: `linux/amd64`
   builds; other Linux architectures were not cross-built, and SECURITY.md says
   so rather than claiming the whole GOOS.
4. **SECURITY.md covers the chain via `verify`, but does not document `audit`**
   — the wider command that re-hashes every registered artifact and exec output
   and cross-checks the state projection against the log (RUNBOOK §10). The doc
   therefore names the chain-integrity command only; a reader wanting the
   everything-on-disk check must read the RUNBOOK. Adding one `audit` sentence
   is a cheap follow-up, deferred here to keep the commit scope as dispatched.
