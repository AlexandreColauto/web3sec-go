# RUNBOOK notes for the Go binary

The operator runbook lives in the **Python reference repo**
(`web3sec-final/RUNBOOK.md`) and stays authoritative until cutover. This file
is the patch the runbook needs to be executable against `webv2` (the Go
binary), plus every place where the runbook's literal text and the code
disagree. It is generated from `scripts/runbook-walkthrough.sh`, which runs
all ~140 documented commands against the Go binary and asserts the exit code
and output markers the runbook promises.

Current status: **walkthrough green, 140/140 commands**, 2026-09-09, binary
HEAD `1254db0` + T37 working tree, reference `web3sec-final` HEAD `2e41cd2`.

## 1. One binary at a time

The runbook's opening rule (L3-6) says *one operator, one campaign at a
time*. The Go binary keeps the same rule and adds one hard constraint:

> **Never run `webv2` and `python3 -m webv2.cli` against the same campaign
> root concurrently.** The event log is a single-writer append-only chain;
> two writers fork it and `verify`/`audit` will (correctly) report a broken
> chain. The on-disk format is byte-compatible, so a campaign can be handed
> between the twins — just not while either is writing.

## 2. Command substitution table

| # | runbook form | Go form | why |
|---|--------------|---------|-----|
| S1 | `python3 -m webv2.cli --root ROOT <cmd>` | `webv2 --root ROOT <cmd>` | one static binary, no module/venv. `--root` semantics and every flag after the interpreter are unchanged. |
| S2 | `python3 verify.py` (L16) | `webv2 selftest` | verify.py ported as a subcommand (fast mode). |
| S3 | `PYTHONPATH=src python3 -m pytest tests/ -q` (L17) | `webv2 selftest --full` | the ported suite is `go test ./...`; pytest is never run on the Go side. Contract is identical: all green. |
| S4 | `PYTHONPATH=src python3 examples/example_campaign/walkthrough.py` (L18) | the walkthrough check inside `webv2 selftest` | the deterministic end-to-end walkthrough is a selftest check, not a script. |
| S5 | `python3 -m venv .venv && pip install -e .` (L14-15) | `scripts/release.sh` → `dist/webv2` | no interpreter, no venv; a CGO-free static binary. |
| S6 | `PYTHONPATH=src python3 - <<PY …` API snippets (§1 L73, §3 L…, §5, §6 L418-425, §7 L522-536, §9) | the CLI form the runbook itself documents for the same operation (cheat sheet L684-750) | the Go twin is CLI-first; the Python API blocks are covered by the ported test suite. Where a block has no CLI equivalent, it is listed in §5 below. |
| S7 | `--root ROOT` | `--root .` in a scratch root | runbook convention (L3-6): commands assume you run from the workspace. |
| S8 | fixtures (`policy.json`, `model.json`, `deployment.json`, `chain.json`, finding payloads) | copied from `scripts/golden/` into the scratch root | the golden fixtures are the repo's canonical toy campaign. |
| S9 | docker/fork-runner commands (L21-26, §6a L483-493, §7) | same commands; without a live daemon the documented preflight refusal is asserted instead | the runbook says absence "degrades, does not block". |
| S10 | user-global store `~/.webv2/shared-memory` (L730-732) | `WEBV2_GLOBAL_MEMORY_DIR=<dir>` | the var is honoured by both twins; the walkthrough points it at its own scratch dir so the operator's real store is never touched. |

Not substitutable, and why:

- `python3 -m webv2.cli --help` (README) → `webv2 help` / `webv2 <cmd> --help`.
  Same argparse-shaped text, different process.
- `WEBV2_PYTHON` / `PYTHONPATH` knobs have no Go meaning; the Go binary
  embeds its assets (`go:embed`) instead of reading `src/`.

## 3. Runbook text vs. code — four discrepancies (both twins)

Each row was executed **verbatim** by `scripts/runbook-walkthrough.sh` and is
asserted for the *documented refusal*, then re-run in the working form. All
four behave identically in `python3 -m webv2.cli` — these are runbook bugs or
reference bugs, not port divergences. Per the runbook's own rule ("if this
document and the code disagree, the code wins and this file is a bug"), the
runbook is what needs the edit.

### R1 — §6a skips the `POSSIBLE` transition (L488 vs L425)

§6 (API) does `F.transition(c, fid, "POSSIBLE", "triage passed")` at **L425**
before the evidence ladder. §6a (CLI) goes straight from ingest to
`webv2 move C-xxx F-xxx CONFIRMED --reason "gates passed"` at **L488**. Both
twins refuse the jump:

```
$ webv2 move C-xxx F-xxx CONFIRMED --reason "gates passed"
move failed: … not a legal transition HYPOTHESIS -> CONFIRMED   (exit 2)
```

**Fix:** insert between L487 and L488:

```bash
webv2 move    C-xxx F-xxx POSSIBLE --reason "triage: the mechanism is falsifiable"
```

### R2 — the `immunize` example fails its own validation (L746)

The cheat sheet documents
`immunize C-xxx F-xxx --poc-exec EXEC-xxx --patch P --mutations "M1;M2;M3"`.
Both twins require **>=5 characters per mutation description**
(`immunize._validate_inputs`), so the literal example exits 2:

```
immunize failed: each boundary mutation needs a written description (>=5 chars):
what input/path variant was tested and what it extracted   (exit 2)
```

**Fix:** use descriptions, e.g.
`--mutations "M1 dust one wei;M2 adjacent path via rescue;M3 boundary amount zero"`.
(The `>=5 chars` rule and the three-mutation minimum are correct; only the
example is not.)

### R3 — `ladder explore` positional order (L693)

The cheat sheet writes
`ladder C-xxx … explore|… F-xxx [RUNG|AXIS] … explore: AXIS --note`. The
argparse shape is positional `finding rung axis`, so `explore F-xxx AXIS`
binds AXIS to **rung** and leaves axis empty. Both twins exit 2:

```
ladder explore failed: unknown axis None; the axes are ('capital-minimization',
'precondition-removal', 'role-conflation', 'ordering-permutation', 'cap-saturation')
```

**Fix:** name a rung placeholder, then the axis (the rung is ignored by
`explore_axis`), and give a `--note` of at least 10 characters:

```bash
webv2 ladder C-xxx explore F-xxx R-any capital-minimization --note "already the cheapest variant"
```

### R4 — `snap` promises a toolchain line for any `foundry.toml` (L685)

The cheat sheet says "a foundry.toml is read automatically (toolchain line +
config recorded)". Both twins read **`profile.default.sol`**, while real
Foundry configs use **`solc`**:

```bash
$ printf '[profile.default]\nsolc = "0.8.24"\n' > target/foundry.toml
$ webv2 --root . snap C-xxx target
pinned src-… (git-dirty, 2 files)          # no toolchain line
$ printf '[profile.default]\nsol = "0.8.24"\n' > target/foundry.toml
$ webv2 --root . snap C-xxx target
pinned src-… (git-dirty, 2 files)
  toolchain: foundry — solc 0.8.24 (detected from the pinned tree)
```

Confirmed identical in Python (`webv2.snapshot._detect_toolchain` returns
`None` for the `solc` key). See `docs/python-twin-issues.md` P1. Until the
reference reads `solc`, treat the toolchain line as opt-in via `sol =` and do
not rely on it for pre-provisioning the solc cache.

### R5 (minor) — `resolve-candidate --note` is unusable in both twins

Cheat sheet L695 documents `--note N`; both twins exit 2 with the byte-exact
schema error recorded as **D14** in `KNOWN_DIVERGENCES.md`
(`dedup_meta/candidate_notes` is declared `string`, written as a dict). Omit
`--note` — that is what `scripts/golden-run.py` and `scripts/verify-full.sh`
do — and the verdict is recorded.

## 4. Exit codes asserted by the walkthrough

The runbook's CLI contract (L7-9) is `0` success / `1` handled error /
`2` usage or refused transition; the walkthrough asserts these plus every
code the runbook names explicitly:

| exit | commands (documented) |
|------|-----------------------|
| 0 | everything not listed below |
| 1 | `prove --stage S` while the stage is not done (L691); `gate C F` while checks fail (L742); `env doctor` while the box cannot run the campaign (L689); `move DISPROVED` on a lifecycle finding without `--adjacent`/`--adjacent-clear` (L502-507) |
| 2 | refused transitions (R1), `probes blank` on a non-blind axis (L710/L252), `ladder explore` with no axis (R3), `immunize` with short mutation descriptions (R2), `resolve-candidate --note` (R5), `answered` with a probe row and no `--anchor` (L724), a plan priority id that does not exist |
| 3 | `run` halting at the first model stage (L58) |

`run --max-stages N` is not pinned by the runbook: its code is state-dependent
(0 when every runnable stage is already complete, 2 when a stage fails,
3 when it halts at a model stage). The walkthrough asserts `2|3` + the
`HALTED at model stage` block for the full `run`, and `nonzero` + the JSON
`"ran"` field for `--max-stages 1`.

## 5. API-only blocks (no CLI equivalent)

These runbook snippets are Python-API only; the Go twin covers them with the
ported test suite, not with a CLI command. They are *not* gaps in the CLI
surface:

- §2 protocol-model object construction (`webv2.protocol_model`).
- §3 `ScopePolicy` / program identity helpers.
- §5 `budget`/`floors` internals (the CLI forms are `budget`, `floors`).
- §7 `independent_verification_queue()` (CLI: `verify --queue`),
  `register_artifact` + `mint_impact_evidence` (CLI: `artifact-register` +
  `impact --artifact`).
- §9 `learning` reflection helpers (CLI: `memory`, `hint`).

## 6. Toolchain expectations (L21-26)

`git`, `forge`, `cast`, `slither`, `aderyn`, `python3`, `docker` are probed
the same way in both twins (`env doctor`, `exec` preflight). On a box without
a docker daemon:

- `env doctor` exits 1 and names the fix (`env doctor --json` is machine
  readable);
- `exec` refuses before burning a run — the walkthrough asserts that
  refusal when no daemon is present and the real EXEC record when one is;
- `sequence run` additionally needs a fork-runner RPC (`WEBV2_FORK_RPC_URL`);
  `sequence verify` works without it.

`WEBV2_SOLC_DIR` / `WEBV2_DOCKER_IMAGE` / `WEBV2_DOCKER_TESTS` behave as the
runbook documents; the Go binary never reaches the network itself.
