# MiniCertora × web3sec-go — host integration guide

The DESIGN lives in `MINICERTORA_ARCHITECTURE.md` (what the seam is and
why). This file is the OPERATIONAL half: how the prover gets onto a box,
how web3sec finds and trusts it, what was verified end-to-end, and where
it bites when it is wrong. Every command below was run on this box
(2026-09-14); the transcript facts are marked ✅.

## 0. One-screen map

```
 model / operator                webv2 (Go)                    minicertora (Python)
 ─────────────────               ──────────                    ────────────────────
 INV ledger (protocol   ──model──▶ verify --scaffold minicertora   render INV.mspec
   model invariants)                                (BODY markers, rule name scaffold-owned)
 operator fills BODY  ──────────▶ artifacts/harness/<INV>/INV.mspec
                                  exec --profile minicertora ────▶ PATH shim `minicertora`
                                    (host profile: network none, unconfined host filesystem — the record says
                                    so; only deny-rule tripwires apply)
                                    ◀──── one JSON line per rule (build_report)
                                  verify --harness-result INV-x --exec EXEC-x
                                    → rung on verification.harness
                                    (counterexample / PROVEN-BOUNDED k / inconclusive)
```

## 1. Installing the prover CLI

The repo is a Python package (`pyproject.toml`, entry point
`minicertora = "cli:main"`), installed **editable** so the live source is
always what runs (the same tree its 976-test suite runs in):

```bash
uv venv /home/xand/Projects/minicertora/minicertora/.venv
uv pip install -e /home/xand/Projects/minicertora/minicertora   # in that venv
```

The venv's own `bin/` is NOT on PATH; expose one stable shim:

```bash
ln -sf /home/xand/Projects/minicertora/minicertora/.venv/bin/minicertora \
       ~/.local/bin/minicertora
```

✅ Verified from a CLEAN environment and a directory outside the repo:

```bash
env -i PATH=$HOME/.local/bin:/usr/bin:/bin HOME=$HOME minicertora --help
env -i PATH=$HOME/.local/bin:/usr/bin:/bin HOME=$HOME minicertora --version
#  minicertora, version 0.1.0
```

**Fragility (know this):** the link points INTO the venv. If the venv is
deleted/recreated or the repo moves, `minicertora` silently becomes a
dangling symlink — and because `exec.LookPath` follows it, web3sec's
version probe then fails OPEN to an honest omit (§2), not a crash.
Relink, or switch to an isolated tool venv that survives repo churn and
still tracks live source:

```bash
uv tool install --editable /home/xand/Projects/minicertora/minicertora
```

## 2. How web3sec consumes it (the trust rails)

Three independent surfaces bind the tool into the control plane:

1. **The sandbox profile** (`internal/sandbox/profiles.go`):
   `minicertora` is a HOST profile — network `none`, filesystem
   `readonly`, `HostProfile() == true`. That last flag is what forces the
   E3 evidence cap: a prover run can produce a rung and a witness, but
   NEVER E4+ "money-real" evidence by itself (that stays fork-runner's
   lane, §L5 of the architecture doc).
2. **The version probe** (`internal/sandbox/exec.go: toolVersions`): every
   EXEC records `environment.tool_versions`; the probe list includes
   `minicertora --version` alongside forge/cast/slither/aderyn/halmos.
   Absent from PATH → key honestly omitted. The `--version` flag exists
   in the CLI **because of this probe** (added 2026-09-14, prover commit
   `fc0316d`): before it, click's usage-error stderr leaked into records
   as `"Usage: minicertora [OPTIONS] SOL_FILE SPEC_FILE"`. If you see a
   usage line in a fresh record, the shim is older than `fc0316d`.
3. **The result mapper** (`internal/harness/minicertora.go`, driven by
   `verify --harness-result`): one JSON line per rule; attribution is the
   EXACT rule name the scaffold minted (`rule inv_<n>(env e)`), so
   hand-renamed rules attribute to nothing — the refusal names the rule.

**Exit-code law** (tool and mapper agree): `0` everything PROVEN,
`1` a VIOLATED counterexample, `2` UNKNOWN/refusal/tool-error. The worst
verdict wins the process exit; per-rule truth is the JSON lines.

**Runner-up facts pinned live:**
- malformed spec → one `UNKNOWN / malformed-spec` line, exit 2, the parse
  error quoted with line:col — never a crash and never a silent skip;
- the scaffold's BODY window is where only model bytes may live; the
  mapper's `--harness-result` step RE-renders the scaffold and refuses on
  any byte moved outside it (G8 BODY law, `harness.Validate`).

## 3. The operational loop, verified end-to-end (2026-09-14)

From an empty directory (transcript kept in
`.scratch/mc-integration/campaigns/`):

```bash
webv2 --root . init --program "https://github.com/x/mint"        # C-ff4638495c
webv2 --root . model $CID model.json      # protocol_model: invariants[] INV-1
webv2 --root . verify $CID --scaffold minicertora --invariant INV-1
#  HARNESS-INV-1-minicertora: scaffolded artifacts/harness/INV-1/INV.mspec
#    (operator/model fills the BODY window: require/assert/call lines ONLY)
webv2 --root . exec $CID --profile minicertora --command \
  "minicertora target/Minting.sol campaigns/$CID/artifacts/harness/INV-1/INV.mspec \
   --solc-path $HOME/.local/bin/solc --loop-bound 4 --timeout-ms 30000"
#  EXEC-749bc7f584 [minicertora] exit=1            ← a real counterexample
webv2 --root . verify $CID --harness-result INV-1 --exec EXEC-749bc7f584 --kind minicertora
#  INV-1: counterexample (minicertora, EXEC-749bc7f584)
#  stderr: verify: poc for 'INV-1' not written: unbridgable step: call 1 lacks target
```

Every step ✅ ran green on this box with the §1 shim. Notes on the faces:

- `model.json` must satisfy `protocol_model.schema.json`
  (`additionalProperties:false`; invariants need
  `id/statement/severity_if_broken`), else exit 2 with the schema path in
  the message.
- `--solc-path` with an ABSOLUTE path is the documented convention: the
  corpus pins a solc per target and the report line's `solc_version`
  (`"0.8.36"` ✅) is how a run is judged against that pin.
- The PoC-bridge stderr is the honest skip: the witness's single `mint`
  call carries no `target`, so `sequence_poc` refuses to pretend it is
  replayable. The rung still lands; only the promoted-PoC artifact is
  withheld, with its reason.
- `exec` under a RELATIVE `--root .` records a CWD-relative
  `stdout_path`. `verify --harness-result` reads the CANONICAL
  `<execs>/EXEC-*/stdout.log` (the audit's derivation law) — pinned by
  `TestHarnessResultReadsRelativeRootExec`; before that fix a
  plainly-present capture reported "no captured stdout to map". A truly
  missing file says `stdout file unreadable (...no such file...)`
  (`TestHarnessResultUnreadableSaysUnreadable`).

## 4. Scorecard & eval flow

`scripts/minicertora-scorecard.py` grades RAW tool output (one JSON line
per rule, exactly what §3's exec captures on stdout) against the eval
suite (`assets/evalsuite/cases.json`). It is operator-side: no gate moves
on a scorecard nobody ran. Flags: `--results DIR` (a directory of
`*.jsonl` tool report lines), `--cases FILE` (evalsuite-shaped),
`--class-map FILE`, `--json`, `--self-test`:

```bash
mkdir -p runs && minicertora contract.sol spec.mspec --format json \
  > runs/lines.jsonl
scripts/minicertora-scorecard.py --results runs \
  --cases assets/evalsuite/cases.json --json
```

## 5. Troubleshooting matrix

| symptom | cause | fix |
|---|---|---|
| `exec` exit 2, `command not found` | shim absent/dangling (§1 fragility) | `ln -sf …venv/bin/minicertora ~/.local/bin/` or `uv tool install --editable` |
| record's `tool_versions.minicertora` = a `Usage:` line | shim older than prover `fc0316d` | pull the repo (editable install is live), nothing to reinstall |
| `UNKNOWN / malformed-spec` | BODY bytes not grammar-legal | read `details` (line:col); `minicertora X.sol Y.mspec` by hand |
| rung inconclusive, rule never attributed | rule renamed away from scaffold-owned `inv_<n>` | re-scaffold or restore the name — attribution is exact-match by design |
| "no captured stdout to map" with the file present | (pre-r13) relative-root record | HEAD derives the canonical path; if seen, file a defect |
| poc "not written: unbridgable step: …" | witness genuinely not replayable | expected for single-call/no-target rules; promote via fork repro instead |
| prover tests: `test_tier_partition_sums_to_the_full_suite` red | pre-existing docs honesty check (tight `~9 s` band in a plan doc) | unrelated to integration; fix by rewording the claim |

## 6. What is NOT integrated (open edges, honest list)

- `MINIPROVER_REQUIREMENTS.md` (untracked, minicertora repo root): the
  MiniProver ↔ MiniCertora interface contract — next piece of work, not
  consumed by anything today.
- ~~Cross-checking report-line `solc_version` against the pinned
  compiler~~ CLOSED r18: `verify --harness-result` now refuses exit 2
  with `toolchain-mismatch` naming both versions, and the stored proof
  carries `compiler_pin` (checked against what, or honestly unchecked).
  See `MINIPROVER_INTEGRATION.md` §4 — one law serves both harnesses.
- ~~A `minicertora` presence row in `webv2 env doctor`~~ CLOSED r18:
  `prover minicertora:` / `prover miniprover:` rows print on STDERR
  (the docker surface on stdout stays twin-pinned) and the JSON report
  carries `host_provers`.
