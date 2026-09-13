# web3sec-go

The deterministic control plane for Web3 bug-bounty campaigns: one static
`webv2` binary, embedded assets, hash-chained campaign state, and a test
surface that proves "same inputs → same bytes" without a model in the loop.

**Go is the source of truth.** The Python twin (`web3sec-final`) was retired
at the P4 cutover on 2026-09-09 (`docs/archive/README.md`; the as-built notes
for every ported wave are in `docs/IMPROVEMENTS.md`). Campaign
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
./dist/webv2 --root . audit  $CID     # 15-section integrity audit
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

`WEBV2_ROOT` sets the default workspace root — the directory that holds
`campaigns/`. It is consulted whenever `--root` is absent, with this
precedence: `--root` flag > `$WEBV2_ROOT` > the nearest ancestor of the
working directory carrying a `campaigns/` directory (up to five levels up,
cwd included) > the working directory itself. The walk-up is what lets
`webv2 status` work from a subdirectory of the workspace.

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
                    minicertora-scorecard.py (prover scorecard over the
                    evalsuite; fixture under golden/scorecard-fixture/),
                    legacy/ (reader-compatibility fixture), archive/
docs/gates/         per-phase gate reports (P0-P4)
docs/archive/       frozen port-era records: the divergence ledger, the
                    twin-issue log, the Python-test accounting map
docs/IMPROVEMENTS.md  the active campaign-improvement plan (waves A–J; K parked)
docs/LEANNESS_REVIEW.md  the port-scaffolding removal plan (wave F)
```

## Verification

| gate | command | what it proves |
|------|---------|----------------|
| self-check | `webv2 selftest [--full]` | assets, walkthrough, CLI audit, full suite |
| unit + integration | `go test ./... -count=1` | the whole in-process suite, incl. the asset-pack manifest test |
| golden suite | `scripts/golden.sh` | the deterministic recipe: exit codes, tree + event chain, 15-section audit surface |
| RUNBOOK walkthrough | `scripts/runbook-walkthrough.sh` | every runbook command, documented exit code |
| real containers | `scripts/p2-docker-e2e.sh` | docker exec (pass+fail) + anvil sequence end to end, plus the four `WEBV2_DOCKER_TESTS=1` package e2e tiers |
| legacy compatibility | `scripts/verify-full.sh` step 9 | Go reads a reference-written campaign, all 14 rendered sections clean (15 registered; `eval` is presence-gated) |
| prover scorecard | `python3 scripts/minicertora-scorecard.py --self-test` | the L6b instrument parses tool lines, joins them to evalsuite cases, and reproduces its pinned fixture rows byte-for-byte (plus a shape audit of every fixture line) |
| release | `scripts/release.sh` | static binary, embedded assets, standalone |

### Prover scorecard (L6b, operator-run)

`scripts/minicertora-scorecard.py` grades minicertora on the evalsuite: point it
at a directory of raw tool report lines (one JSON object per line, exactly what
`cli.py` prints) plus `assets/evalsuite/cases.json`, and it prints one row per bug
class — `class  cases  detected  proven_silence  refused  clean_agreed  refusal_histogram`
(`--json` for objects; exit 0 means "the scorecard ran", not "the prover is good"):

```bash
# 1. run the sweep + verify chain, collect each target's report lines into the
#    results dir as `results/<Contract>.jsonl` — one JSON object per line, in
#    the order the tool printed it (`... --format json >> results/Packed.jsonl`).
#    Name the file for the Solidity contract: a whole-target refusal envelope
#    (`{"verdict","reason","details"}`, e.g. the packed-storage reject) carries
#    no rule and no contract, so its FILE STEM is the only key that can join it
#    to a case.  Write several targets' lines to one file only if you accept
#    that a refusal envelope in it is unjoinable.
# 2. score them.  The evalsuite carries no contract/rule id, so the operator
#    supplies the join: a TSV of `tie_key<TAB>case_id`, where tie_key is the one
#    key a line offers — its rule, else its contract, else the results-file stem.
#    A duplicate tie_key, or a case_id absent from cases.json, is a hard error.
python3 scripts/minicertora-scorecard.py \
    --results results/ --cases assets/evalsuite/cases.json --class-map class-map.tsv
# CI-free smoke: runs the pinned hand-made fixture and byte-compares its rows
# and its line-shape audit.
python3 scripts/minicertora-scorecard.py --self-test
```

**Key that table by rule id:** a rule id is what ties a report line to a case,
and a **contract-name row matters only for that target's rule-less abort
envelope**, which joins on the results-file stem. A case counts as
**detected** when a tied line is `VIOLATED`, as
**proven_silence** when it is a known-bad row whose tied lines are all `PROVEN`,
as **refused** when a tied line is `UNKNOWN` with an honest-refusal /
tool-error / model-bug reason — a tied whole-target refusal envelope counts as
refused too, with its reason in the histogram — and as **clean_agreed** when it
is a CLEAN gold row (the same clean set `proven_silence` excludes —
`confirmed-not-exploitable` on the evalsuite) whose tied lines are all `PROVEN`:
the exact mirror of `proven_silence`, which is the specificity signal the three
other columns cannot show — a control the prover proved clean scores, while one
it only reached as `UNKNOWN` (a refusal) or never reached at all does not.
**Tie-collision law:** a rule-bearing line whose rule ties case X while its
results-file stem ties a different case Y is **excluded** and named on stderr
with the line and both cases (`<file>:<line>: rule '...' ties ... but the
results-file stem '...' ties ...`), never scored — the file and the line
disagree about the target, so neither side is picked silently (the same
loud-partial accounting as the shape law). **Law:** a template-seeded
scaffold is starting content, never evidence — and no minicertora rung moves any
gate until an operator has run this scorecard on the REAL evalsuite with the
REAL tool. The self-test proves the instrument only; its rows are hand-made
(shape-audited against what `cli.py` can print), not a prover measurement.

The audit registers **15** sections; the 15th, `eval` (Wave G4), is
presence-gated — it renders only when the campaign's program matches the
gold-eval suite. Every other campaign's audit therefore shows the original
**14**, which is why `scripts/check-golden.py` pins 14 and the golden /
legacy fixtures carry no `eval` row.

`scripts/verify-full.sh` runs every gate above except the release build in
one fail-fast sequence — a clone of this repo alone runs it green (the two
ambient fixtures below add coverage, they are not required to pass).

Two ambient prerequisites are *not* part of a default clone, and the tests
that need them SKIP with a reason rather than fail without them:

- **forge libs** for the harness compile proof
  (`internal/harness/harness_compile_test.go`): a directory holding both
  `forge-std/src/Test.sol` and `halmos-cheatcodes/src/SymTest.sol`, looked up
  as `$T16_LIBS`, then `<repo>/.scratch/t16-libs`, then `~/.foundry` /
  `~/.config/.foundry` (each with or without a `lib/` level). Provision the
  scratch copy with `git clone --depth 1
  https://github.com/foundry-rs/forge-std .scratch/t16-libs/forge-std` and
  `git clone --depth 1 https://github.com/a16z/halmos-cheatcodes
  .scratch/t16-libs/halmos-cheatcodes` — nothing third-party is vendored
  into this repository.
- **the `sharevault` fixture checkout** for the corpus-surface e2e
  (`internal/corpus/e2e_test.go`): a sibling directory
  `<parent-of-repo>/sharevault/src`. It is a separate repository on purpose;
  the test skips when it is absent, and nothing here moves it inside.

Step 9 is also daemon-free by design: the docker e2e tiers live in
`scripts/p2-docker-e2e.sh` and are never part of the 13-step gate.


Live runs also enforce the tool's line-shape law: verdict-bearing lines that match no real `cli.py` shape are excluded and named per line on stderr (loud partial, exit 0) — the grade can never be fabricated by a pasted or truncated line.
## Docs

- `assets/runbook/RUNBOOK.md` — the operator runbook (a test: the D7
  registry↔document check keeps it honest).
- `docs/IMPROVEMENTS.md` — the improvement plan driven by real campaigns
  (waves A–J, with Wave K parked; navigate by heading — `## Wave G`, `## Wave H
  — review backlog`, `## Wave I`, `# Wave J — definitive close-out`, `# Wave K`)
  and its design principles, incl. the surface budget.
- `docs/LEANNESS_REVIEW.md` — the wave-F leanness review (what was removed
  from the port scaffolding, and why the rest stayed).
- `docs/runbook-go-notes.md` — RUNBOOK substitutions the Go binary needs
  (port-era history).
- `docs/gates/P4-gate.md` — the cutover gate report; `docs/archive/` holds
  the divergence ledger and other frozen port records.
