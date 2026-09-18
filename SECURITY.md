# Security policy and honest threat model

`webv2` is a **deterministic control plane** for Web3 bug-bounty campaigns: it
records what was claimed, what was run, and what backs each claim. It is not a
scanner, not a prover, and not a boundary between you and the code you audit.

Everything below is stated against the shipped code, with the file that
enforces it. Where the tool cannot guarantee something, this file says so
instead of implying a guarantee.

## Supported platforms and toolchain

- **Linux only.** `GOOS=linux GOARCH=amd64 go build ./...` succeeds;
  `GOOS=darwin` and `GOOS=windows` both fail (the sandbox process-group code is
  `//go:build linux` in `internal/sandbox/procsig_unix.go`, and the campaign
  lock uses `syscall.Flock`/`Pwrite` in `internal/state/processlock.go`).
  Other Linux architectures are untested.
- **Go floor 1.26.2, toolchain `go1.26.6`** — `go.mod` declares
  `go 1.26.2` and `toolchain go1.26.6`. The release build is static and
  CGO-free (`scripts/release.sh`).
- Container-backed profiles additionally need a **running Docker daemon**;
  `webv2 env doctor` reports per-profile readiness.

## What the trust core protects

- **Hash-chained event log.** Every event carries a SHA-256 over its
  `seq/at/type/ref/data/prev_hash` fields in canonical spaced-JSON form; the
  chain is anchored at 64 zero bytes (`internal/state/chain.go`). `webv2
  verify` re-walks and re-hashes the chain (`internal/state/verifylog.go`), and
  a torn tail is refused rather than repaired silently.
- **Atomic writes.** JSON is written to a temp file in the destination
  directory and `os.Rename`d into place (`internal/validation/atomicio.go`),
  so a crash cannot leave a half-written record.
- **Cross-process lock.** Any read-modify-write window takes an OS advisory
  lock — `flock(LOCK_EX|LOCK_NB)` with a 5-second budget, depth-counted for
  same-process re-entry (`internal/state/processlock.go`). A lock that cannot
  be taken fails loudly instead of proceeding unlocked.
- **One-writer law.** The event log assumes a single writer per campaign: do
  not run two `webv2` processes against the same campaign concurrently. The
  lock makes honest concurrent use safe; it does not make divergent intent
  correct.

## What the sandbox is — and is not

**Is:** container profiles (`docker-networkless`, `docker-gvisor`,
`vm-snapshot`, `fork-runner`) execute a real `docker run` whose network and
filesystem policy are the flags in `internal/sandbox/profiles.go`
(`profileNetwork`, `profileFilesystem`). For those profiles the container is
the enforcement mechanism.

**Is not:** host profiles (`host-readonly`, `halmos`, `forge-fuzz`,
`minicertora`) run **on your host, unconfined** (`HostProfile`,
`internal/sandbox/profiles.go`). The record says so rather than claiming
isolation it does not have: `host (unconfined — nothing enforces network-off)`
(`networkLabel`) and `host (unconfined — nothing enforces readonly; deny-rule
tripwires only)` (`profileFilesystemLabel`, `internal/sandbox/exec.go`).

The deny rules are **static regex tripwires, not a boundary**. Do not run
host-profile execs against code you would not run yourself.

## Evidence caps and floors

The E0–E7 ladder is monotonic and is defined in the RUNBOOK ("Evidence levels,
floors, and the gate"). Two properties matter for trust:

- **Host profiles can never back E4+ evidence** (`internal/sandbox/profiles.go`;
  the `e4_capable` filter in `internal/envgo/env.go`). Container profiles cap
  at E4; only `fork-runner` reaches E5.
- **Floors do not lower on their own.** The per-class CONFIRMED floor table
  lives in `internal/findings/levels.go`; a campaign may override a class floor
  (E4–E7, `internal/cli/cmd_floors.go`) with an actor, a written reason, and a
  hash-chained `floor_policy.set` / `floor_policy.cleared` event
  (`internal/floors/floors.go`) — and may `unset` it back to the default. An environment-blocked verification is recorded as an annotation,
  never as a lower bar.

## Attestation is not proof

`CHECKED_AGAINST_CODE` records are **operator attestations**. The gate
(`VerifyInvariantStatement`, `internal/invariants/invariants.go`) only proves
that the cited artifact's bytes reference the invariant id or one of its
`applies_to` tokens. That establishes that the artifact *names* what it
verifies — not that the property was checked. Historical records with no
method provenance are legacy/unspecified and are never retroactively upgraded.
A token match never creates a mechanically verified outcome.

## Dependency and release scanning

- **Policy: advisory-driven, not "latest".** Dependency changes are made for a
  named advisory or a verified need and are reviewed separately. Verification
  never runs `go get` and never installs tools
  (`scripts/security-check.sh` header).
- **Run the scan:** `bash scripts/security-check.sh` (needs `govulncheck` on
  PATH: `go install golang.org/x/vuln/cmd/govulncheck@latest`), or
  `bash scripts/release.sh`, which runs the strict scan as its final step
  before declaring a release.
- **Strict by default.** A missing scanner is INCOMPLETE (exit 2); findings and
  scanner failures keep the scanner's nonzero status; nothing is ever reported
  as PASS without a successful scan. `--development` may skip *only* a missing
  scanner, and says so.
- **What PASS means:** `govulncheck` exited 0, i.e. **no known vulnerability
  reachable by a CALLED symbol**. Import-level and require-level advisories that
  are not called are reported but do not fail the gate. PASS is **not** a claim
  that the dependency graph is clean.

## What this tool does not do

No target-specific detection, no exploit reproduction, and no autonomous
hunting: `run` executes the deterministic stages and **halts at the first model
stage** (exit 3, `internal/cli/cmd_run.go`), requiring an operator-supplied
artifact to continue. The campaign path makes no outbound network call except
one JSON-RPC POST to the operator-supplied fork endpoint
(`FORK_RPC_URL`/`WEBV2_FORK_RPC_URL`, `internal/envgo/env.go`). There is no
telemetry.

## Reporting a vulnerability

Report suspected vulnerabilities in **this tool** privately to the repository
owner through the hosting forge's private vulnerability reporting — do not open
a public issue. There is no bug-bounty program here and no reward is promised.
Findings in a *target* under audit are the campaign's business, not this
project's.
