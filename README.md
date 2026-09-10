# web3sec-go

The deterministic control plane for Web3 bug-bounty campaigns: one static
`webv2` binary, embedded assets, hash-chained campaign state, and a test
surface that proves "same inputs → same bytes" without a model in the loop.

**Go is the source of truth.** The Python twin (`web3sec-final`) was retired
at the P4 cutover on 2026-09-09 (`docs/gates/P4-gate.md` §9.1). Campaign
directories written by the reference stay readable forever — that promise is
kept by a committed legacy fixture (`scripts/legacy/`) that `verify-full`
step 9 audits with the Go binary. The port-era records (divergence ledger,
twin-issue log, test accounting map) live frozen under `docs/archive/`.

## Quick start

Requires Go 1.26+ and, for the sandboxed-exec paths, a running Docker daemon.

```bash
git clone <this repo> && cd web3sec-go

# 1. One-command self-check: asset sweep + deterministic walkthrough +
#    in-process CLI audit. ~2 s; --full adds `go test ./...`.
go run ./cmd/webv2 selftest
go run ./cmd/webv2 selftest --full

# 2. Build the static release binary (CGO_ENABLED=0, -trimpath, stripped) and
#    prove it is standalone: assets embedded, no shared libraries, runs from
#    any directory.
scripts/release.sh                     # -> dist/webv2 + sha256 + size

# 3. Walk the whole RUNBOOK against the binary: every documented command,
#    each asserted against its exit code and output markers.
scripts/runbook-walkthrough.sh         # green = every runbook command matches

# 4. The full gate (thirteen ordered steps: vet, build, tests, race,
#    determinism x2, asset-pack manifest, golden suite, crash smoke, legacy
#    cross-audit, P1/P2/P3 CLI smokes, runbook walkthrough):
scripts/verify-full.sh

# ...or any subset:
scripts/golden.sh                      # golden recipe + well-formedness
scripts/p2-docker-e2e.sh               # real docker exec + real anvil sequence
go test ./... -count=1                 # the unit + integration suite
```

A first campaign, end to end (no model calls needed):

```bash
./dist/webv2 --root . init --program "Acme Immunefi"
CID=$(ls campaigns | head -1)
./dist/webv2 --root . scope $CID --policy policy.json
./dist/webv2 --root . snap  $CID ./target --deployment deployment.json
./dist/webv2 --root . model $CID model.json
./dist/webv2 --root . index $CID --src target
./dist/webv2 --root . plan  $CID
./dist/webv2 --root . ingest $CID --json-file finding.json
./dist/webv2 --root . status $CID
./dist/webv2 --root . brief  $CID     # what matters now
./dist/webv2 --root . audit  $CID     # 14-section integrity audit
```

Campaign state lands in `campaigns/<C-id>/`: `events.jsonl` (hash-chained
log), `campaign_state.json` (projection), `findings/F-*.json`, `artifacts/`,
`execs/`, `report.md`. The event log assumes **one writer** per campaign —
never run two tools against the same campaign concurrently.

## Commands

`webv2` covers the campaign lifecycle (`init`, `scope`, `snap`, `model`,
`plan`, `ingest`, `move`, `mint`, `verdict`, `verify`, `impact`, `gate`,
`complete`), the deterministic hunting surfaces (`index`, `sinks`,
`prescreen`, `forkdiff`, `recency`, `probes`, `relations`, `resemble`,
`corpus-surface`, `dedup`, `prioritize`, `rank`, `brief`, `report`), the
knowledge stores (`memory`, `publish`, `globalize`, `shared`, `ladder`,
`immunize`, `sft`), and the operational tooling (`doctor`, `env doctor`,
`audit`, `execs`, `budget`, `floors`, `price`, `cost`, `yields`, `run`,
`selftest`).

```bash
./dist/webv2 help                 # every command, in fixed order
./dist/webv2 <command> --help     # argparse-shaped usage
```

`WEBV2_NOW` and `WEBV2_UUID` pin the clock and id stream for reproducible
artifacts; `WEBV2_GLOBAL_MEMORY_DIR`, `WEBV2_EVAL_DIR`, `WEBV2_POC_ROOT`,
`WEBV2_BASELINES_DIR`, `WEBV2_SOLC_DIR`, `WEBV2_DOCKER_IMAGE` and
`WEBV2_DOCKER_TESTS` repoint the external stores and the sandbox. The full
list is in `docs/runbook-go-notes.md`.

## Repository layout

```
cmd/webv2/          the binary: seam wiring + main
internal/           one package per module group (state, validation,
                    orchestrator, structidx, probes, corpus, chainengine,
                    sharedmem, ...) — counts: see `selftest --full` output
assets/             embedded via go:embed (schema, prompts, playbooks,
                    archetypes, runbook), pinned by a SHA-256 manifest
sft/                the live SFT example store — committed on purpose:
                    VCS is its integrity layer (internal/sft)
scripts/            release.sh, runbook-walkthrough.sh, golden.sh,
                    verify-full.sh, p2-docker-e2e.sh, sync-asset-manifest.py,
                    legacy/ (reader-compatibility fixture), archive/
docs/gates/         per-phase gate reports (P0-P4)
docs/archive/       frozen port-era records: the divergence ledger, the
                    twin-issue log, the Python-test accounting map
docs/IMPROVEMENTS.md  the active campaign-improvement plan (waves A-E)
docs/LEANNESS_REVIEW.md  the port-scaffolding removal plan (wave F)
```

## Verification

| gate | command | what it proves |
|------|---------|----------------|
| self-check | `webv2 selftest [--full]` | assets, walkthrough, CLI audit, full suite |
| unit + integration | `go test ./... -count=1` | the whole in-process suite, incl. the asset-pack manifest test |
| golden suite | `scripts/golden.sh` | the deterministic recipe: exit codes, tree + event chain, 14-section audit surface |
| RUNBOOK walkthrough | `scripts/runbook-walkthrough.sh` | every runbook command, documented exit code |
| real containers | `scripts/p2-docker-e2e.sh` | docker exec (pass+fail) + anvil sequence end to end, plus the four `WEBV2_DOCKER_TESTS=1` package e2e tiers |
| legacy compatibility | `scripts/verify-full.sh` step 9 | Go reads a reference-written campaign, all 14 sections clean |
| release | `scripts/release.sh` | static binary, embedded assets, standalone |

`scripts/verify-full.sh` runs every gate above except the release build in
one fail-fast sequence — a clone of this repo alone is enough to run it.

## Docs

- `assets/runbook/RUNBOOK.md` — the operator runbook (a test: the D7
  registry↔document check keeps it honest).
- `docs/IMPROVEMENTS.md` — the improvement plan driven by real campaigns
  (waves A–E) and its design principles, incl. the surface budget.
- `docs/LEANNESS_REVIEW.md` — the wave-F leanness review (what was removed
  from the port scaffolding, and why the rest stayed).
- `docs/runbook-go-notes.md` — RUNBOOK substitutions the Go binary needs
  (port-era history).
- `docs/gates/P4-gate.md` — the cutover gate report; `docs/archive/` holds
  the divergence ledger and other frozen port records.
