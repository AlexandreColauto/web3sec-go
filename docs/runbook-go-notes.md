# RUNBOOK port notes (historical)

**The operator runbook is `assets/runbook/RUNBOOK.md`** (embedded into the
binary and dropped into every campaign by `init`). The Python repo it was
ported from is deprecated; the **cutover happened** (`docs/gates/P4-gate.md`,
commits `313e07e`/`1684fd7`), so the Go runbook is the source of truth and the
`web3sec-final` copy is archive material.

This file is the **port history**: the substitutions that made the reference
runbook executable against `webv2` (the Go binary), and every place where the
reference's literal text and the code disagreed.

**Read the tense carefully.** Every "both twins" in this file is a record of
what was true while the reference was alive; the twin retired 2026-09-09 and
the live contract is `assets/runbook/RUNBOOK.md` plus the walkthrough gate
(`scripts/runbook-walkthrough.sh`, verify-full step 13). Nothing here is a
current requirement — it is why the current text reads the way it does. It was generated from
`scripts/runbook-walkthrough.sh` — a T37/P4-era artifact written against the
*Python* runbook, kept for the record, **not re-run by any gate** (release.sh
has its own mini walkthrough; `selftest` runs the small Go one).

Current status (2026-09-10, HEAD `243c0e6`): **76/76 registered verbs are
documented in the runbook**, pinned by `TestRunbookDocumentsEveryRegisteredVerb`
and `TestRunbookCommandsAreRegistered` (`internal/cli/runbook_test.go`) — that
test, not this file, is what keeps the doc honest now. See §7.

## 1. One binary at a time

The runbook's opening rule (L3-6) says *one operator, one campaign at a
time*. The Go binary keeps the same rule and adds one hard constraint:

> **Never run `webv2` and `python3 -m webv2.cli` against the same campaign
> root concurrently.** The event log is a single-writer append-only chain;
> two writers fork it and `verify`/`audit` will (correctly) report a broken
> chain. The on-disk format is byte-compatible, so a campaign can be handed
> between the twins — just not while either is writing.

## 2. Command substitution table

> **On the `L###` citations in this file:** they refer to the RETIRED Python
> runbook as it stood at port time and are kept as the historical record of
> what was compared. They do NOT resolve against today's
> `assets/runbook/RUNBOOK.md` (which has been restructured several times
> since, and whose prose now lives in numbered sections). For current
> locations use the section anchors — `§0`, `§4a`, `§6a`, `§7p`, `§cheat`, …
> — which is what `scripts/runbook-walkthrough.sh` cites and what
> `TestWalkthroughAnchorsPointAtTheRunbook` validates.

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

## 3. Runbook text vs. code — four discrepancies

Each row was executed **verbatim** by `scripts/runbook-walkthrough.sh` and is
asserted for the *documented refusal*, then re-run in the working form. All
four originally behaved identically in `python3 -m webv2.cli` — runbook bugs
or reference bugs, not port divergences. Per the runbook's own rule ("if this
document and the code disagree, the code wins and this file is a bug"), the
runbook is what needs the edit.

Since the Python twin is **deprecated and no longer maintained**, three of the
four reference bugs are now fixed in the Go twin only and are flagged
**FIXED-IN-GO, 2026-09-09** (R3 ladder `explore`, R4 `solc` detection, R5
`resolve-candidate --note`). R1 (the skipped `POSSIBLE` transition) is a pure
runbook typo, not a code bug, and stays as-is in both twins.

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

### R3 — `ladder explore` positional order (L693) — FIXED-IN-GO, 2026-09-09

The cheat sheet writes
`ladder C-xxx … explore|… F-xxx [RUNG|AXIS] … explore: AXIS --note`. The
reference argparse shape is positional `finding rung axis`, so
`explore F-xxx AXIS` binds AXIS to **rung** and leaves axis empty — the
**Python twin** still exits 2:

```
ladder explore failed: unknown axis None; the axes are ('capital-minimization',
'precondition-removal', 'role-conflation', 'ordering-permutation', 'cap-saturation')
```

The **Go twin is fixed** (python-twin-issues P3 / divergence D30): a trailing
positional after the finding now binds to the axis for the `explore` action,
so the documented natural form works:

```bash
webv2 ladder C-xxx explore F-xxx capital-minimization --note "already the cheapest variant"
```

The legacy dummy-rung form `explore F-xxx R-any capital-minimization --note …`
still works in both twins (give a `--note` of at least 10 characters).

### R4 — `snap` promises a toolchain line for any `foundry.toml` (L685) — FIXED-IN-GO, 2026-09-09

The cheat sheet says "a foundry.toml is read automatically (toolchain line +
config recorded)". The reference reads only **`profile.default.sol`**, while
real Foundry configs use **`solc`** — so the **Python twin** still needs
`sol =`:

```bash
$ printf '[profile.default]\nsolc = "0.8.24"\n' > target/foundry.toml
$ python3 -m webv2.cli --root . snap C-xxx target
pinned src-… (git-dirty, 2 files)          # no toolchain line (reference)
```

The **Go twin is fixed** (python-twin-issues P1): it reads **`solc`** first
and falls back to legacy **`sol`**, so the documented promise now holds:

```bash
$ printf '[profile.default]\nsolc = "0.8.24"\n' > target/foundry.toml
$ webv2 --root . snap C-xxx target
pinned src-… (git-dirty, 2 files)
  toolchain: foundry — solc 0.8.24 (detected from the pinned tree)
```

Pinned by `TestToolchainSolcKeyDetected`
(`internal/snapshot/toolchain_test.go`). `sol`-only configs are unaffected.

### R5 (minor) — `resolve-candidate --note` — FIXED-IN-GO, 2026-09-09

Cheat sheet L695 documents `--note N`. The **Python twin** still exits 2 with
the schema error recorded as **D14** in `KNOWN_DIVERGENCES.md`
(`dedup_meta/candidate_notes` was declared `string`, written as a dict).

The **Go twin is fixed** (python-twin-issues P2): the schema now declares
`candidate_notes` as a string map, so `--note` records cleanly on both sides:

```bash
webv2 resolve-candidate C-xxx F-xxx F-yyy --verdict distinct --note "different root cause"
```

Pinned by `TestResolveCandidateNoteRecordsOnBothSides`
(`internal/cli/cmd_resolve_candidate_test.go`). The golden recipe and
`verify-full.sh` still omit `--note` so the byte-diff against the (buggy,
deprecated) reference stays green.

## 3a. The `-h` gap (FIXED 2026-09-10)

The reference's argparse answered `<cmd> -h` with the command's help and exit
**0** for every verb. The Go twin did so for 53 of 76 verbs; **23 diverged**:

| behaviour | verbs |
|---|---|
| usage printed, **exit 2** (required-arg check runs before help) | `exploit`, `ack`, `rank`, `move`, `immunize` |
| `error: unrecognized arguments: -h` (the flat parsers never learned the flag) | `init`, `status`, `snap`, `log`, `audit`, `prioritize`, `repro-queue`, `waive`, `artifact-list`, `artifact-register`, `invariant-verify`, `invariant-contradict`, `dedup`, `recall`, `resolve-candidate`, `gate`, `prove`, `verdict` |

**Fixed:** all 76 verbs now answer `-h`/`--help` with their usage block and exit
0, before any argument validation or state access. One shared entry guard
(`helpRequested` in `internal/cli/cli.go`) is called first by the 23 — the 18
flat parsers and the 5 that validated required arguments first — plus `selftest`,
which used to *run the whole self-check* on `-h` because it ignored unknown
tokens. The usage text comes from the captured argparse block when the verb has
one, its existing usage constant otherwise, and for the four verbs with neither
(`init`, `status`, `log`, `snap`) it is derived from the command registry, so the
help line cannot drift from the registered signature.

Pinned by `TestEveryCommandAnswersHelp` and
`TestHelpPrecedesArgumentValidation` (`internal/cli/help_test.go`), which run
every registered verb with both flags against an empty workspace and assert exit
0, a `usage: webv2 <name>` line, and no error on stderr.

## 4. Exit codes asserted by the walkthrough

The runbook's CLI contract (L7-9) is `0` success / `1` handled error /
`2` usage or refused transition; the walkthrough asserts these plus every
code the runbook names explicitly:

| exit | commands (documented) |
|------|-----------------------|
| 0 | everything not listed below |
| 1 | `prove --stage S` while the stage is not done (L691); `gate C F` while checks fail (L742); `env doctor` while the box cannot run the campaign (L689); `move DISPROVED` on a lifecycle finding without `--adjacent`/`--adjacent-clear` (L502-507) |
| 2 | refused transitions (R1), `probes blank` on a non-blind axis (§4a), `ladder explore` with no axis (R3), `immunize` with short mutation descriptions (R2), `resolve-candidate --note` (R5), `answered` with a probe row and no `--anchor` (§4a), a plan priority id that does not exist |
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

## 7. Runbook drift is a test now (2026-09-10)

The runbook fell 9 verbs behind (all of ords 68-76 — every capability the
improvement programme added) without any gate noticing, because nothing
compared the registry against the document. Two tests now do, in
`internal/cli/runbook_test.go`, against the **embedded** runbook (the bytes
`init` copies into a campaign):

- `TestRunbookDocumentsEveryRegisteredVerb` — every `register(command{…})`
  name must appear in the runbook as `webv2 <name>`. A new verb with no
  documentation fails the suite.
- `TestRunbookCommandsAreRegistered` — every `webv2 <name>` in the runbook must
  resolve to a registered command (or `help`). A renamed or deleted verb with a
  stale doc entry fails the suite.

Neither test checks that the *prose* is true — that is the operator's and the
reviewer's job. They check the two mechanical failure modes: a capability no
operator can discover, and a documented command that no longer exists.

Also refreshed with this pass: §4b (the `enforce`/`symmetry` tables), the
triage verbs (`rank`, `ack`, `dedup-signature`), `exploit`,
`chain`/`adversarial-game`, the memory flags (`--reflect`/`--reject`),
`artifact-reconcile`, the all-findings table and the unscoped-campaign notice
in §9, and the one-row-per-path artifact rule in the hard rules.
