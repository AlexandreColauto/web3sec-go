# Python twin issues found while porting

The Go port is 1:1 by rule ("Python wins"), so every reference bug was
reproduced, not fixed. This file records the issues the port surfaced in
`web3sec-final` so they can be fixed upstream (or in `RUNBOOK.md`) once,
rather than living as folklore in two codebases.

Each entry names the reference location, the observed behavior, whether the
Go twin reproduces it (it does unless stated), and the fix that would close
it. Line numbers are `web3sec-final` HEAD `2e41cd2`.

---

## P1 — `snapshot._detect_toolchain` reads the wrong TOML key

**Where:** `src/webv2/snapshot.py::_detect_toolchain` (L267-291) reads
`profile.default.sol`; the docstring at L271 says "foundry.toml
profile.default.sol is the solc the build will ask for".

**Observed:** real Foundry projects write `solc = "0.8.24"` under
`[profile.default]`, not `sol`. With a real `foundry.toml` the detector
returns `None`, so the snapshot's `config` layer is null and `snap` never
prints the toolchain line the RUNBOOK promises (cheat sheet L685: "a
foundry.toml is read automatically (toolchain line + config recorded)").

```
$ printf '[profile.default]\nsolc = "0.8.24"\n' > target/foundry.toml
$ python3 -c "from webv2.snapshot import _detect_toolchain; print(_detect_toolchain('target'))"
None
$ printf '[profile.default]\nsol = "0.8.24"\n' > target/foundry.toml
$ python3 -c "from webv2.snapshot import _detect_toolchain; print(_detect_toolchain('target'))"
{'compiler': '0.8.24', 'build_system': 'foundry'}
```

**Go twin:** reproduces exactly (`internal/snapshot/toolchain.go`, same key).
No divergence row is needed.

**Impact:** `WEBV2_SOLC_DIR` pre-provisioning and the `env doctor` solc-cache
check see "no pinned compiler" for every real project.

**Fix:** read `solc` (Foundry's key), optionally falling back to `sol` for
backwards compatibility, then update the RUNBOOK sentence. The Go twin then
follows in one line.

---

## P2 — `resolve-candidate --note` writes a value its own schema rejects

**Where:** `src/webv2/dedup.py` writes `dedup_meta.candidate_notes` as a dict
`{other_finding_id: note}`; `schema/finding.schema.json` declares
`dedup_meta.additionalProperties: {"type": "string"}`.

**Observed:** the command validates its own write and rejects it:

```
$ python3 -m webv2.cli resolve-candidate C-xxx F-aaa F-bbb --verdict distinct --note "different root cause"
resolve-candidate failed: finding validation failed at dedup_meta/candidate_notes:
{'F-bbb': 'different root cause'} is not of type 'string'   (exit 2)
```

**Go twin:** byte-identical error (exit 2). Recorded as **D14** in
`KNOWN_DIVERGENCES.md`; `scripts/golden-run.py` and `scripts/verify-full.sh`
deliberately omit `--note`.

**Fix (upstream choice):** either widen the schema to
`additionalProperties: {"type": "string"}` → `{"type": "object"}` (or drop the
`additionalProperties` constraint for `candidate_notes`) and keep the writer,
or make the writer store a plain string keyed per other finding. Then delete
D14 and re-enable `--note` in the harnesses.

---

## P3 — `ladder explore` cannot be invoked as documented

**Where:** `src/webv2/cli.py` L3209-3214 — the `ladder` subparser declares
positionals `finding`, `rung`, `axis`, but `cmd_ladder`'s `explore` branch
(L2358-2363) only reads `args.axis`.

**Observed:** the documented form (`RUNBOOK.md` L693 and the usage line
`explore F-xxx [RUNG|AXIS]`) binds the axis to `rung`:

```
$ python3 -m webv2.cli ladder C-xxx explore F-xxx capital-minimization --note "…"
ladder explore failed: unknown axis None; the axes are ('capital-minimization',
'precondition-removal', 'role-conflation', 'ordering-permutation', 'cap-saturation')   (exit 2)
```

The working invocation needs a dummy rung: `explore F-xxx R-any
capital-minimization --note "<>=10 chars>"`.

**Go twin:** reproduces (same parser shape, same error). See R3 in
`docs/runbook-go-notes.md`.

**Fix:** either make `axis` the 4th positional and `rung` the 5th for the
`explore` action, or accept `--axis`. Then fix the cheat sheet.

---

## P4 — bare `webv2 env` prints the `sft` help

**Where:** `src/webv2/cli.py::build_parser` (around L3280) gives the `env`
parser `set_defaults(func=lambda a: s.print_help())` where `s` is
late-bound; by the time the lambda runs, `s` is the LAST subparser built
(`sft`).

**Observed:** `python3 -m webv2.cli env` prints the `sft` usage block
(exit 0). The Go twin deliberately prints the `env` usage block — recorded as
**D23**, whose "Unblocks" said "porting `sft`, then printing that parser's
help from `runEnv`".

**Status 2026-09-09:** `sft` IS ported, so the stated blocker is gone; D23 is
now a deliberate non-reproduction awaiting a decision (reproduce the quirk in
`cmd_env.go`, or drop the row and declare it a fixed papercut).

**Fix:** bind the closure to the `env` parser object
(`lambda a, s=env_parser: s.print_help()`) — a one-line upstream fix that
makes D23 deletable.

---

## P5 — `RUNBOOK.md` §6a skips the `POSSIBLE` transition

**Where:** §6 (API) performs `F.transition(c, fid, "POSSIBLE", "triage
passed")` at L425; §6a (CLI) goes from ingest straight to
`webv2 move C-xxx F-xxx CONFIRMED --reason "gates passed"` at L488.

**Observed:** both twins refuse the jump (`not a legal transition HYPOTHESIS
-> CONFIRMED`, exit 2). The state machine is right; the runbook block is
incomplete.

**Fix:** add `webv2 move C-xxx F-xxx POSSIBLE --reason "triage: …"` between
L487 and L488 (see R1 in `docs/runbook-go-notes.md`).

---

## P6 — `RUNBOOK.md` L746 documents an `immunize` invocation that always fails

**Where:** cheat sheet L746:
`--mutations "M1;M2;M3"`. `src/webv2/immunize.py::_validate_inputs`
(L32-47) requires at least three mutations, each with a written description
of **>=5 characters**.

**Observed:** the literal example exits 2 in both twins:

```
immunize failed: each boundary mutation needs a written description (>=5 chars):
what input/path variant was tested and what it extracted
```

**Fix:** change the example to
`--mutations "M1 dust one wei;M2 adjacent path via rescue;M3 boundary amount zero"`.
The validation itself is intentional (a patch must be tested against named
boundary variants).

---

## P7 — `RUNBOOK.md` L685 over-promises the snapshot toolchain line

Same root cause as P1: the sentence promises a toolchain line for any
`foundry.toml`; the code only recognizes the `sol` key. Fix P1 and the
sentence becomes true.

---

## P8 — reference-only behavior the Go twin intentionally does not copy

For completeness, the divergences where the reference is the odd one out are
tracked in `KNOWN_DIVERGENCES.md`, not here:

| row | reference behavior | Go behavior |
|-----|--------------------|-------------|
| D15 | `WEBV2_GLOBAL_MEMORY_DIR` read by the Python twin's recall path | Go reads the ported shared store (both tiers) via `internal/sharedmem` |
| D23 | bare `env` prints `sft` help | prints `env` help |
| D24 | `baselines` store is source-relative | cwd-relative + `WEBV2_BASELINES_DIR` seam |
| D28 | `sft` store is source-relative | cwd-relative + `sft.SetStorePath` seam |

D15 and D23 are flagged in `docs/gates/P4-gate.md` as rows whose stated
blockers have since been satisfied and which need a decision.

---

## Reproduction

Everything above was observed live on 2026-09-09 with reference HEAD
`2e41cd2`. The RUNBOOK rows are re-verified on every
`scripts/runbook-walkthrough.sh` run; the snapshot-key and sft-store checks
are reproducible with the one-liners shown in P1 and D28.
