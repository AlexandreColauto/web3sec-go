# web3sec-go

The Go twin of `web3sec-final` — the deterministic control plane for Web3
bug-bounty campaigns. Same state, same artifacts, same bytes: every command
here is a 1:1 port of a Python module, verified by a cross-twin golden suite
that runs both implementations side by side and byte-diffs the result.

**Python wins.** Until the cutover rule in `docs/GO_REWRITE_SPEC.md` §14 is
satisfied (P4 golden green for two consecutive weeks of real use), the Python
tree in `../web3sec-final` remains the reference implementation. Where this
port and the reference disagree, the reference is right and this repo has a
bug — except for the declared rows in `KNOWN_DIVERGENCES.md`.

## Quick start

Requires Go 1.26+ and, for the sandboxed-exec paths, a running Docker daemon.

```bash
git clone <this repo> && cd web3sec-go

# 1. One-command self-check (the verify.py port): asset sweep + deterministic
#    walkthrough + in-process CLI audit. ~2 s; --full adds `go test ./...`.
go run ./cmd/webv2 selftest
go run ./cmd/webv2 selftest --full

# 2. Build the static release binary (CGO_ENABLED=0, -trimpath, stripped) and
#    prove it is standalone: assets embedded, no shared libraries, runs from
#    any directory.
scripts/release.sh                     # -> dist/webv2 + sha256 + size

# 3. Walk the whole RUNBOOK against the binary: ~140 commands, each asserted
#    against the exit code and output markers the runbook documents.
scripts/runbook-walkthrough.sh         # green = every runbook command matches

# 4. Full parity gates (both twins, byte-diffed):
scripts/golden.sh                      # cross-twin golden suite
scripts/verify-full.sh                 # cross-audit + CLI surface smoke (P3)
scripts/p2-docker-e2e.sh               # real docker exec + real anvil sequence
go test ./... -count=1                 # 1,963 test functions, 62 packages
python3 scripts/cap-analysis.py        # D27 chain-cap parity evidence
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

Campaign state lands in `campaigns/<C-id>/` exactly as the Python twin writes
it: `events.jsonl` (hash-chained log), `campaign_state.json` (projection),
`findings/F-*.json`, `artifacts/`, `execs/`, `report.md`. The two
implementations are byte-compatible on disk — but **never run both against the
same campaign concurrently** (single-operator doctrine; the event log assumes
one writer).

## Commands

`webv2` implements the full CLI surface of the reference: the campaign
lifecycle (`init`, `scope`, `snap`, `model`, `plan`, `ingest`, `move`, `mint`,
`verdict`, `verify`, `impact`, `gate`, `complete`), the deterministic
surfaces (`index`, `sinks`, `prescreen`, `forkdiff`, `recency`, `probes`,
`relations`, `resemble`, `corpus-surface`, `dedup`, `prioritize`, `brief`,
`report`), the knowledge stores (`memory`, `publish`, `globalize`, `shared`,
`ladder`, `immunize`, `sft`), and the operational tooling (`doctor`, `env
doctor`, `audit`, `execs`, `budget`, `floors`, `price`, `cost`, `yields`,
`selftest`).

```bash
./dist/webv2 help                 # every command, in fixed order
./dist/webv2 <command> --help     # argparse-shaped usage
```

`WEBV2_NOW` and `WEBV2_UUID` pin the clock and id stream for reproducible
artifacts; `WEBV2_GLOBAL_MEMORY_DIR`, `WEBV2_EVAL_DIR`, `WEBV2_POC_ROOT`,
`WEBV2_BASELINES_DIR`, `WEBV2_SOLC_DIR`, `WEBV2_DOCKER_IMAGE` and
`WEBV2_DOCKER_TESTS` repoint the external stores and the sandbox. The full
list, with the Python-side equivalents, is in `docs/runbook-go-notes.md`.

## Repository layout

```
cmd/webv2/          the binary: seam wiring + main
internal/           62 packages, 79.6k non-test lines — one package per ported
                    Python module group (state, validation, orchestrator,
                    structidx, probes, corpus, chainengine, sharedmem, ...)
assets/             embedded via go:embed (schema, prompts, playbooks, archetypes)
scripts/            release.sh, runbook-walkthrough.sh, golden.sh,
                    verify-full.sh, cap-analysis.py, check-golden.py, ...
docs/gates/         per-phase gate reports (P0-P4)
testmap.json        1,378 Python test functions -> Go test functions, 1:1
KNOWN_DIVERGENCES.md  every place the port is intentionally not byte-identical
```

## Verification

| gate | command | what it proves |
|------|---------|----------------|
| self-check | `webv2 selftest [--full]` | assets, walkthrough, CLI audit, full suite |
| unit + integration | `go test ./... -count=1` | 1,963 test functions across 62 packages |
| testmap | `python3 scripts/check-testmap.py` | every Python test maps 1:1, 0 deferred |
| cross-twin golden | `scripts/golden.sh` | both twins, byte-diffed artifacts + tree |
| RUNBOOK walkthrough | `scripts/runbook-walkthrough.sh` | every runbook command, documented exit code |
| release | `scripts/release.sh` | static binary, embedded assets, standalone |
| cap parity | `python3 scripts/cap-analysis.py` | D27 chain-cap semantics |

## Docs

- `docs/runbook-go-notes.md` — the RUNBOOK substitutions the Go binary needs,
  and the four runbook/code discrepancies the walkthrough proved.
- `docs/python-twin-issues.md` — issues found in the reference while porting
  (faithfully reproduced here; fixed upstream or in the runbook).
- `KNOWN_DIVERGENCES.md` — the permanent divergence ledger.
- `docs/gates/P4-gate.md` — the cutover gate report.
