# MiniProver × web3sec-go — host integration guide

MiniProver (`/home/xand/Projects/miniprover`, Python) is the **auto-prover**:
LLM agents analyse a contract, author `.mspec` properties, and drive
**MiniCertora** (the verifier, see `MINICERTORA_INTEGRATION.md`) in a
verify/revise loop until the spec publishes. web3sec-go is the **control
plane**: it decides what counts as evidence and keeps the ledger.

Three services, three contracts between them — no repo merging, no shared
state beyond files each service OWNS:

```
 webv2 (Go)                    miniprover (Python)          minicertora (Python)
 ──────────                    ───────────────────          ────────────────────
 INV ledger + DESIGN text ──▶  autoprove run dir      ──drives──▶  verdict lines
 (scaffold or design doc)       reports/report.json                  (per rule)
                               reach.json, final .mspec
 verify --autoprove ◀───────   parsed ONLY from the JSON
 EXEC record + report.json     (exit code = tripwire,
 → rung / counterexample /         never a verdict)
   recorded gap, E3 cap
```

| File | Owner | Consumers | Frozen by |
|---|---|---|---|
| verdict JSON lines | minicertora | miniprover (`verifier/parse.py`), webv2 (`internal/harness`) | §1 of each guide; `rules` field is the v0.4 contract |
| `reports/report.json` | miniprover | webv2 (`verify --autoprove`) | prover honesty rules below |
| scaffolded `INV.mspec` | webv2 | minicertora, (later) miniprover | rule name `inv_<n>` is scaffold-owned |

## 1. Installing the prover CLI

Same rail as minicertora: editable install so the live source is what
runs, then ONE stable PATH shim.

```bash
uv tool install --editable /home/xand/Projects/miniprover
# or the venv shim:
ln -sf /home/xand/Projects/miniprover/.venv/bin/miniprover ~/.local/bin/miniprover
```

✅ Verified from a clean environment:

```bash
env -i PATH=$HOME/.local/bin:/usr/bin:/bin HOME=$HOME miniprover --version
#  miniprover, version 0.1.0
```

The `--version` flag exists **because of web3sec's probe** (same reason
minicertora got `fc0316d`): every EXEC record pins
`environment.tool_versions`, `miniprover` joined the probe list, and the
probe reads the FIRST line of `--version`. Running from an uninstalled
checkout prints `0+source` instead of lying about a version.

Presence is visible in three places, all honest:
- `webv2 env doctor` prints `prover minicertora: …` / `prover miniprover: …`
  rows on **stderr** (stdout is the twin-pinned docker surface; the JSON
  report carries `host_provers` for machines);
- every EXEC record's `tool_versions` (absent binary = key omitted);
- `exec` failing with `command not found`, which is now the LAST resort,
  not the first discovery.

## 2. Endpoint configuration (what a run needs)

MiniProver speaks OpenAI wire format with NO baked-in vendor (README):

```bash
export MINIPROVER_BASE_URL="http://127.0.0.1:1234/v1"   # e.g. LM Studio
export MINIPROVER_MODEL_EXTRACTION=<id> MINIPROVER_MODEL_AUTHORING=<id>
export MINIPROVER_MODEL_REVIEW=<a DIFFERENT id>         # independence is the point
export MINIPROVER_API_KEY=...   # omit for local servers
```

A run with no endpoint configured fails fast naming the variables —
that failure is an honest `INCONCLUSIVE(tool-error)` rollup, not a verdict.

## 3. The trust rails webv2 relies on (prover-side, by contract)

The prover's own honesty rules (§ README) are exactly the rails this
control plane enforces elsewhere:

1. **Exit codes never decide a verdict.** `0` = published, `2` = not
   published, `1` = usage error — run-level tripwires only. Per-property
   truth is `reports/report.json`.
2. **A rule with no verifier line is never PROVEN** — it is `REFUSED` or
   `UNATTRIBUTED`. webv2 maps only `rule`-keyed outcomes.
3. `OUT_OF_FRAGMENT` / `INCONCLUSIVE` are **gaps, not passes**: mapped to
   the inconclusive rung shape, recorded, and they gate nothing silently.
4. **A gate that did not run says `unavailable`.** Capability probes
   (`--parse-only`, `--check-only`, `--project-root`, the `rules` field —
   the R11–R14 v0.4 contract) degrade runs, they do not fake them.
5. `review_independent: false` is recorded when the budget could not buy a
   DIFFERENT model for review — one model's opinion is never presented twice.
6. **PROVEN next to a SUSPECT review finding is the most expensive state
   there is** — the prover shouts it in its summary; webv2's mapper
   refuses to bless it (§4, phase B).

## 4. Compiler provenance: recorded, and NOW enforced

The old open edge (`MINICERTORA_INTEGRATION.md` §6.2): the result mapper
COPIED each line's `solc_version` into the stored proof but nothing
compared it — a mismatched-compiler run bound its rung. Shipped (r18):

- `solc` joined the EXEC probe list; its record row stores the PARSED
  version (`0.8.36`), not solc's banner first line;
- `verify --harness-result` resolves the run's compiler pin — the
  `--solc-path` binary named by the exec's own command (probed at verify
  time), else `tool_versions.solc` — and REFUSES exit 2 with
  `toolchain-mismatch` naming BOTH versions when any attributed line
  disagrees;
- no visible pin still maps, but the proof records
  `compiler_pin: "unchecked (no compiler pin visible on this record)"` —
  loud honesty, not silent leniency;
- when minicertora v0.4 ships `--require-solc-version` (R13), that flag
  becomes the belt; this webv2 check remains the braces.

## 5. The `verify --autoprove` mapper (SHIPPED)

Machine input is ONE file: the run's `reports/report.json` (schema
versioned; unknown versions refuse). Mapping law, per invariant:

| prover state | webv2 rung |
|---|---|
| published, every attributed rule PROVEN | PROVEN-BOUNDED (k from flags) |
| any VIOLATED attributed to the property | counterexample (params + failed assertion carried) |
| OUT_OF_FRAGMENT / INCONCLUSIVE / REFUSED / UNATTRIBUTED | inconclusive — recorded, never passed |
| published=false, or PROVEN + SUSPECT review finding | **not blessed** — mapper exits 2 like the compiler check |

Usage (attribution is exact-match; `--property` names the prover's
agent-authored title verbatim):

```bash
webv2 verify <C> --autoprove INV-1 --property total_monotonic_after_add        --report <run>/reports/report.json
# INV-1: proved-bounded — autoproved bounded (k=4, 1 rules)
#   verifier gaps at run time: 7 capabilities missing (degraded run; ...)
```

Live-verified against the prover's committed counter evidence (all three
arms): a genuine PROVEN rollup bound `proved-bounded` with the run's
loop bound; VIOLATED rollups named their refuted rules as
`counterexample`; the SUSPECT-flagged property was REFUSED exit 2 quoting
the reviewer's reasoning — the "PROVEN next to suspect" state cannot
bind. `report.json` registers as a `harness` artifact (the unwind-safe
`RegisterOrRefresh`), the binding logs `harness_run` with the report's
sha256, and `audit` stays PASS over the whole flow. Reports carry
`schema_version` (prover side, r18): major "1." speaks; anything else
refuses rather than best-efforts a contract change.

`stale_outcomes` (rules written, verified, then edited out) are display
context only: the deliverable is what SURVIVED in the final spec, and the
runbook for a real campaign should read rule count and decision count as
different numbers on purpose.

## 6. Troubleshooting matrix

| symptom | cause | fix |
|---|---|---|
| `prover miniprover: ABSENT` in env doctor | no shim (§1) | `uv tool install --editable …` |
| run exits 1 at construction | no `MINIPROVER_BASE_URL` | §2 — the fail-fast names the variables |
| every property `INCONCLUSIVE(tool-error)` | verifier shim dangling or endpoint dead | check `minicertora --version` and curl the base URL |
| `review_independent: false` in report.json | review model == authoring model | set `MINIPROVER_MODEL_REVIEW` to a DIFFERENT id |
| `--parse-only`/`--check-only` rows say unavailable | minicertora is pre-v0.4 (R12/R14 unshipped) | expected degradation; run `tools/minicertora_conformance.py` to see the full gap |
| `toolchain-mismatch` on a harness result | the run's solc ≠ the pin | re-exec with `--solc-path` pointing at the reported version, or fix PATH solc |

## 7. What is NOT integrated (open edges, honest list)

- **Phase C profile**: an `autoprove` exec profile needs WRITE (run dir)
  + network to the LLM endpoint (loopback for LM Studio) + env passthrough
  of `MINIPROVER_*` — strictly wider than the read-only `minicertora`
  profile. Until it exists, miniprover runs are launched by the operator
  and only their artifacts are consumed; the E3 host cap is unaffected.
- DESIGN.md generation FROM the INV ledger (webv2 → prover input) is not
  wired; today the operator passes `--design` by hand.
- The prover's `--cache-dir` is built-but-unwired upstream (their Known
  Gaps): no webv2-side assumption may depend on caching.
- minicertora v0.4 (R1–R15 contract) is unshipped; the conformance table
  is the source of truth for what the installed verifier can do today.
