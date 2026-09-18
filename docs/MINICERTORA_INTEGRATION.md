# MiniCertora × web3sec-go — host integration guide

The DESIGN lives in `MINICERTORA_ARCHITECTURE.md` (what the seam is and
why). This file is the OPERATIONAL half: how the prover gets onto a box,
how web3sec finds and trusts it, what was verified end-to-end, and where
it bites when it is wrong. Every command below was run on this box
(2026-09-14); the transcript facts are marked ✅. **Re-measured
2026-09-17** against the verifier tree at HEAD `be14d3a`: §2.1 lists the
CLI surface that landed since (R16–R24), §5's troubleshooting rows were
re-derived, and §7 records the capability measurement and where it now
lives.

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
always what runs — the same tree its test suite runs in (measured
2026-09-17: 1308 tests collected, of which the default fast tier is 318;
the tier table is the prover README's §2c, and it is re-measured there
whenever tests move):

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

### 2.1 Capability surface, re-measured 2026-09-17

The frozen MiniProver-facing contract (`MINIPROVER_REQUIREMENTS.md`, target
v0.4) grew past the R1–R15 set this guide was first written against, and
the verifier implements the growth. Measured on this box against the tree
at HEAD `be14d3a` (`minicertora --version` is still `0.1.0`; the editable
shim makes the live source what runs):

| id | surface | what it buys web3sec |
|---|---|---|
| R16 | `--solc-path PATH` | the run's compiler pin, which `verify --harness-result` resolves and enforces (`MINIPROVER_INTEGRATION.md` §4) |
| R17 | `--evm-version NAME` | a `cancun`-only target compiles; the resolved value is echoed as `evm_version` on every report line, so the record cannot contradict the compile |
| R18 | `--source GLOB` / `--exclude GLOB` | a built Foundry tree is pointable as shipped: directories named `*.sol` (a `forge-artifacts/<C>.sol/`) are skipped, never read as sources |
| R19 | fixed-size arrays (`uint256[N]`, the `__gap` idiom) | OZ storage-gap contracts load; an out-of-range constant index refuses per rule, not per document |
| R20 | bounded `bytes(N)` parameters | `onDropMessage(bytes calldata)` becomes nameable from a rule; the tool-imposed bound is declared in the line's `assumptions` |
| R21 / R23 | struct parameters; entry-point call depth | `commitBatch` dispatches instead of refusing `unrecognized-dispatcher`, and the depth bound names itself |
| R22 | struct-in-mapping storage, whole-word members first | a whole-word member decides; a packed member behind a mapping keeps refusing, by name |
| R24 | packed-slot geometry at any pinned solc (0.8.24 + 0.8.36) | targets pinning an older pragma stop refusing on an inherited sub-word member |

Every verdict line carries `rules` (R11) and `evm_version` alongside the
`tool_version`/`spec_version`/`solc_version` this guide already named. The
sidecar web3sec stores is unchanged in shape: `mcProof` has carried
`evm_version` since the G8 mapping landed (`49a2d02e`) — 12 keys, values
verbatim, an absent key admitted as null rather than invented.

Also on the CLI and deliberately **not** consumed by web3sec (named here so
nobody assumes they are wired): `--multi-call`, `--path-cap`, `--lowering`,
`--entry-binding`, `--trust-unchecked-summaries`, `--assume-direct-calls`,
`--solver`, `--emit-diagnostic-bundle`, `--remapping`. The host names a
compiler and a bound; it does not pick the verifier's internal lowering.

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
| `--parse-only` refuses `--evm-version` / `--cache-dir` | by design (R17/R15): the cheap gate invokes no compiler, so the flag is refused rather than silently ignored | run the full command, or `--check-only`, which does compile |
| every line says `evm_version: paris` on a `cancun` target | the R17 flag was not passed | add `--evm-version cancun`; the line echoes the version that really compiled |
| `--project-root` load breaks on a built Foundry tree | pre-R18 the walk read `*.sol` **directories** as sources | pass `--source 'src/**' --exclude 'forge-artifacts/**'` (R18), or point `--project-root` at the narrowest directory that still holds the imports |
| an old-pragma target refuses on an inherited sub-word member | pre-R24 packed-slot geometry was resolved at 0.8.36 only | pass `--solc-path` at the pinned version — R24 resolves the geometry at 0.8.24 and 0.8.36 alike |

## 6. What is NOT integrated (open edges, honest list)

- ~~`MINIPROVER_REQUIREMENTS.md` (untracked, minicertora repo root): the
  MiniProver ↔ MiniCertora interface contract — next piece of work, not
  consumed by anything today.~~ NOW a **tracked mirror**: the authoritative
  copy is the MiniProver repo's `docs/MINIPROVER_REQUIREMENTS.md` (it
  carries R16–R24 and that document's own §2.1 handoff order) and the
  verifier root's copy is re-synced to it
  byte-for-byte (verifier commit `be14d3a`, 2026-09-17). It is consumed for
  real now — MiniProver's `--invariants` ledger mode, its capability probe
  and the corpus matrix all key on it. See §7.
- ~~Cross-checking report-line `solc_version` against the pinned
  compiler~~ CLOSED r18: `verify --harness-result` now refuses exit 2
  with `toolchain-mismatch` naming both versions, and the stored proof
  carries `compiler_pin` (checked against what, or honestly unchecked).
  See `MINIPROVER_INTEGRATION.md` §4 — one law serves both harnesses.
- ~~A `minicertora` presence row in `webv2 env doctor`~~ CLOSED r18:
  `prover minicertora:` / `prover miniprover:` rows print on STDERR
  (the docker surface on stdout stays twin-pinned) and the JSON report
  carries `host_provers`.

## 7. The installed verifier, re-measured 2026-09-17

The capability probe belongs to MiniProver (`tools/minicertora_conformance.py`
in that repo); its two tables are quoted in `MINIPROVER_INTEGRATION.md` §7
and nowhere else, so the two guides cannot drift apart. What this refresh
measured on the verifier's own tree (HEAD `be14d3a`) and this box:

- **R16–R24 are implemented.** The `feat(r17)`…`feat(r24)` commits of
  2026-09-16/17 are ancestors of HEAD, and each requirement has a
  discriminating corpus target under `minicertora/corpus/targets/`:
  `evm-version-cancun` (R17), `project-selection-exclude` /
  `project-foundry-tree` (R18), `fixed-array-gap`,
  `fixed-array-constant-index`, `fixed-array-symbolic-index-refused` (R19),
  `bytes-param`, `bytes-param-unbounded-refused` (R20), `struct-param-entry`
  and `inline-depth-named` (R21/R23), `struct-in-mapping-whole-word` (R22),
  `immutable-guard` plus the pinned-0.8.24 test (R24). `corpus/MATRIX.md`
  is the pinned table; the CLI flags are in §2.1 above.
- **The contract document's own status paragraph lags its code.**
  `MINIPROVER_REQUIREMENTS.md` §2 still classifies R17–R24 as plan ("the §3
  sections for R17–R24 are still owed"). That is documentation debt inside
  the tool's tree, not a fact about the installed binary — judge capability
  by the probe, never by that paragraph.
- **The report line grew one key.** A verdict line is now 24 keys (25 on an
  invariant line) because `evm_version` joined `build_report`; measured by
  running `wrap-unchecked` from the corpus on this box. web3sec already
  copies it (`internal/harness/minicertora.go`, `mcProof`), so no bind
  moved, and an older line without the key stores null rather than an
  invented version.
- **The cheap gates now agree with the full run** (R12 fix `f9fbbd2`):
  `--check-only` prints the full run's name-binding refusal, and the
  conformance probe's accept-drift row PASSes. MiniProver's own guide still
  lists that row as failing in its "Known limits" section, which is dated
  2026-09-16 — re-run the probe before believing it.
