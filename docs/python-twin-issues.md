# Python twin issues found while porting

This file records the issues the port surfaced in `web3sec-final`. Each entry
names the reference location, the observed behavior, whether the Go twin
reproduces it, and the fix that would close it. Line numbers are
`web3sec-final` HEAD `2e41cd2`.

> **Status 2026-09-09 — the Python twin is deprecated and no longer
> maintained.** The Go twin is the active codebase. Where a reference bug
> blocks the operator, it is now **fixed in the Go twin only** (an intentional
> divergence, tracked in `KNOWN_DIVERGENCES.md`) rather than fixed upstream in
> `web3sec-final`. The original 1:1 "Python wins" rule (reproduce, don't fix)
> no longer applies to these items. Items marked **FIXED-IN-GO** below carry a
> divergence row and a regression test; the reference behavior is preserved as
> documented for the record.

---

## P1 — `snapshot._detect_toolchain` reads the wrong TOML key — **FIXED-IN-GO, 2026-09-09**

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

**Go twin:** reproduced exactly at first port (`internal/snapshot/toolchain.go`,
same key).

**Impact:** `WEBV2_SOLC_DIR` pre-provisioning and the `env doctor` solc-cache
check see "no pinned compiler" for every real project.

**Fix (applied, Go only):** `internal/snapshot/toolchain.go` now reads
**`solc`** (Foundry's key) first and falls back to legacy **`sol`**. This is an
intentional divergence from the deprecated reference (see R4 in
`docs/runbook-go-notes.md`). Pinned by `TestToolchainSolcKeyDetected`
(`internal/snapshot/toolchain_test.go`), which also locks the faithful
semantics: a present-but-unusable `solc` suppresses the `sol` fallback.
`sol`-only configs are unchanged, so no golden normalization was needed.

---

## P2 — `resolve-candidate --note` writes a value its own schema rejects — **FIXED-IN-GO, 2026-09-09**

**Where:** `src/webv2/dedup.py` writes `dedup_meta.candidate_notes` as a dict
`{other_finding_id: note}`; `schema/finding.schema.json` declares
`dedup_meta.additionalProperties: {"type": "string"}`.

**Observed:** the command validates its own write and rejects it:

```
$ python3 -m webv2.cli resolve-candidate C-xxx F-aaa F-bbb --verdict distinct --note "different root cause"
resolve-candidate failed: finding validation failed at dedup_meta/candidate_notes:
{'F-bbb': 'different root cause'} is not of type 'string'   (exit 2)
```

**Go twin:** reproduced the byte-identical error (exit 2) at first port.
Recorded as **D14** in `KNOWN_DIVERGENCES.md`.

**Fix (applied, Go only):** widened the Go schema —
`assets/schema/finding.schema.json` now declares
`dedup_meta.properties.candidate_notes` as
`{"type": "object", "additionalProperties": {"type": "string"}}`, so the
writer's dict passes (JSON-Schema precedence: a named property wins over
`additionalProperties`). A valid `--note` now records on both sides. The
reference is deprecated and still rejects it, so **D14 now documents the
permanent reference divergence** and the golden recipe / `verify-full.sh`
STILL omit `--note` to keep the byte-diff green. Pinned by
`TestResolveCandidateNoteRecordsOnBothSides`
(`internal/cli/cmd_resolve_candidate_test.go`).

---

## P3 — `ladder explore` cannot be invoked as documented — **FIXED-IN-GO, 2026-09-09**

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

**Go twin:** reproduced (same parser shape, same error) at first port. See R3
in `docs/runbook-go-notes.md`.

**Fix (applied, Go only):** `parseLadder`
(`internal/cli/cmd_ladder.go`) now treats a trailing positional as the **axis**
when the action is `explore` and no axis positional follows it, so the
documented natural form `explore F-xxx capital-minimization --note "…"` works.
The legacy dummy-rung form is unchanged. No usage/help text changed, so no
golden normalization was needed. Tracked as **D30** in `KNOWN_DIVERGENCES.md`.
Pinned by `TestLadderExploreNaturalAxisForm`
(`internal/cli/cmd_ladder_test.go`), which covers both the natural and the
legacy form.

---

## P4 — bare `webv2 env` prints the `sft` help — **CLOSED, 2026-09-09 (fixed papercut)**

**Where:** `src/webv2/cli.py::build_parser` (around L3280) gives the `env`
parser `set_defaults(func=lambda a: s.print_help())` where `s` is
late-bound; by the time the lambda runs, `s` is the LAST subparser built
(`sft`).

**Observed:** `python3 -m webv2.cli env` prints the `sft` usage block
(exit 0). The Go twin deliberately prints the `env` usage block — recorded as
**D23**, whose "Unblocks" said "porting `sft`, then printing that parser's
help from `runEnv`".

**Status 2026-09-09:** `sft` IS ported, so the stated blocker is gone; D23 was
a deliberate non-reproduction awaiting a decision (reproduce the quirk in
`cmd_env.go`, or drop the row and declare it a fixed papercut).

**Resolution (Go only):** the decision is that the Go behavior is CORRECT — a
bare `webv2 env` must print the `env` usage block. The reference is deprecated
and the bug is permanent, so **D23 is CLOSED as a fixed papercut** (the row
stays in `KNOWN_DIVERGENCES.md` to document the permanent reference
divergence). No code change was needed in Go; no golden normalization was
needed (no recipe runs bare `webv2 env`).

**Upstream fix (reference, not applied):** bind the closure to the `env`
parser object (`lambda a, s=env_parser: s.print_help()`).

---

## P5 — `RUNBOOK.md` §6a skips the `POSSIBLE` transition — **RUNBOOK-only, N/A in the Go repo**

**Where:** §6 (API) performs `F.transition(c, fid, "POSSIBLE", "triage
passed")` at L425; §6a (CLI) goes from ingest straight to
`webv2 move C-xxx F-xxx CONFIRMED --reason "gates passed"` at L488.

**Observed:** both twins refuse the jump (`not a legal transition HYPOTHESIS
-> CONFIRMED`, exit 2). The state machine is right; the runbook block is
incomplete.

**Status 2026-09-09:** the RUNBOOK lives in the deprecated Python repo, so the
text edit belongs there and is **not actionable in the Go repo** (there is no
code bug — the transition machine is correct in both twins). The Go-side
equivalent is already documented as **R1** in `docs/runbook-go-notes.md`,
which the operator follows when running `webv2`. The one-line runbook fix is
still: add `webv2 move C-xxx F-xxx POSSIBLE --reason "triage: …"` between L487
and L488.

---

## P6 — `RUNBOOK.md` L746 documents an `immunize` invocation that always fails — **RUNBOOK-only, N/A in the Go repo**

**Where:** cheat sheet L746:
`--mutations "M1;M2;M3"`. `src/webv2/immunize.py::_validate_inputs`
(L32-47) requires at least three mutations, each with a written description
of **>=5 characters**.

**Observed:** the literal example exits 2 in both twins:

```
immunize failed: each boundary mutation needs a written description (>=5 chars):
what input/path variant was tested and what it extracted
```

**Status 2026-09-09:** RUNBOOK-text bug in the deprecated Python repo — **not
actionable in the Go repo** (no code bug; the `>=5 chars` validation is
intentional in both twins). The Go-side equivalent is documented as **R2** in
`docs/runbook-go-notes.md`. The one-line runbook fix is still: change the
example to
`--mutations "M1 dust one wei;M2 adjacent path via rescue;M3 boundary amount zero"`.

---

## P7 — `RUNBOOK.md` L685 over-promises the snapshot toolchain line — **true in the Go repo**

Same root cause as P1: the sentence promises a toolchain line for any
`foundry.toml`; the reference code only recognizes the `sol` key.

**Status 2026-09-09:** the Go twin is fixed (P1), so the RUNBOOK sentence is
**already true for the Go binary** — a `foundry.toml` with `solc` yields the
toolchain line. No edit is needed in the Go repo. The RUNBOOK sentence remains
over-promising for the deprecated Python twin only; the Go-side behavior is
documented in **R4** of `docs/runbook-go-notes.md`.

---

## P8 — reference-only behavior the Go twin intentionally does not copy

For completeness, the divergences where the reference is the odd one out are
tracked in `KNOWN_DIVERGENCES.md`, not here:

| row | reference behavior | Go behavior |
|-----|--------------------|-------------|
| D14 | `resolve-candidate --note` rejected by its own schema | **fixed** — schema widened, note records (P2) |
| D15 | `WEBV2_GLOBAL_MEMORY_DIR` read by the Python twin's recall path | Go reads the ported shared store (both tiers) via `internal/sharedmem` |
| D23 | bare `env` prints `sft` help | prints `env` help — **CLOSED as fixed papercut** (P4) |
| D24 | `baselines` store is source-relative | cwd-relative + `WEBV2_BASELINES_DIR` seam |
| D28 | `sft` store is source-relative | cwd-relative + `sft.SetStorePath` seam |
| D30 | `ladder explore F AXIS` binds AXIS to rung | **fixed** — natural axis form works (P3) |

D15 was flagged in `docs/gates/P4-gate.md` as a row whose stated blocker has
since been satisfied and needs a decision. D23's decision was taken
2026-09-09 (closed as a fixed papercut); D14 and D30 are the FIXED-IN-GO rows
added the same day.

---

## Reproduction

Everything above was observed live on 2026-09-09 with reference HEAD
`2e41cd2`. The RUNBOOK rows are re-verified on every
`scripts/runbook-walkthrough.sh` run; the snapshot-key and sft-store checks
are reproducible with the one-liners shown in P1 and D28.
