# P2 Gate — Sequence PoC, Fork Proof, Privileged Track (Python → Go)

**Verdict: ALL SIX ITEMS PASS — the P2 gate is OPEN (2026-09-09).**

Spec gate (GO_REWRITE_SPEC.md §14, P2): *"sequence PoC + fork proof +
privileged track: the docker e2e run is byte-identical across twins,
and the `sequence_coverage` audit section is live in both."* — plus the
cross-twin byte-identity, cross-audit and testmap items that apply at
P2 scope.

Reference state: web3sec-final HEAD `4fcf779` (1378 test functions,
pytest: 1446 passed / 1 skipped incl. parametrize).

| # | item | verdict |
|---|------|---------|
| 1 | D2 closed: `sequence_coverage` section byte-identical (no Python-only section) | **PASS** |
| 2 | Golden v3 cross-twin walkthrough (102 steps, P2 recipe) | **PASS** |
| 3 | Cross-twin DOCKER e2e: real exec/classify/mint + real anvil sequence run | **PASS** |
| 4 | verify-full P2 steps + P2 cross-audit in both directions | **PASS** |
| 5 | testmap.json P2 reconciliation | **PASS** |
| 6 | Ported suite green (incl. `-race` and determinism double-run) | **PASS** |

---

## 1. D2 closed — `sequence_coverage` is no longer Python-only — PASS

`KNOWN_DIVERGENCES.md` D2 recorded that `scripts/check-golden.py`
compared only 13 audit sections and skipped `sequence_coverage` via
`PY_ONLY_SECTIONS = {"sequence_coverage"}`. The P2 port makes the
section real in Go (`internal/audit/sections/sequencecoverage.go`), so
the exception is deleted:

```python
PY_ONLY_SECTIONS: set[str] = set()   # empty-set guard kept for the next phase
```

Evidence: every golden run now reports
`step 07 audit-json: 14 audit section(s) + ok MATCH (py-only: none)`
and the same at `step 99 audit-json-final`. The docker e2e asserts the
section's *content* as well (`sequence_coverage required=0, covered=0`
in both twins — see §3). D2 is marked **CLOSED** in
`KNOWN_DIVERGENCES.md`; the only remaining open rows are D18/D19
(below) and the P3 seams.

## 2. Golden v3 cross-twin walkthrough — PASS

Command: `scripts/golden.sh` = `scripts/golden-run.py` +
`scripts/check-golden.py`. Recipe and full step table:
`docs/gates/golden-v3.md`.

Evidence (settled run, 2026-09-09):

```
tree: 34 files byte-MATCH (normalized)
steps: 102 commands x 2 twins (declared nonzero: gate-h1=1, gate-h3=1,
       prove-learning=1, ladder-disprove-short-reason=2,
       ladder-disprove-reproduced=2, impact-unpriceable-incomplete=2)
step 07 audit-json: 14 audit section(s) + ok MATCH (py-only: none)
step 99 audit-json-final: 14 audit section(s) + ok MATCH (py-only: none)
GOLDEN GREEN: all artifacts and command outputs byte-match
```

What the P2 recipe adds on top of v2 (ordinals from the v3 table):

- **h6/h7 ingest pair** (steps 48–59): a capability-granting finding
  (`capabilities.granted=["pause"]`) and a finding that *requires* it
  (`capabilities.required=["pause"]`), so the capability graph, the
  chain link proposal and the privileged/terminal views have real rows.
- **exec / mint / ladder / chains / terminals / privileged / impact /
  sequence** (steps 66–96): `exec` dry-run + host + failing run,
  `execs` list/`--json`/`--id`, `classify`, seeded-exec `mint`,
  the full ladder lifecycle (`start/add/explore×4/repro/set-maximal/
  complete/report`), `chains`, `terminals`, `privileged`, `sequence
  verify`, and the four `impact` paths (priced, artifact-backed,
  unpriceable, incomplete).
- **Two `ladder disprove` guard branches** (short reason; reproduced
  rung) — both exit 2, byte-identical. The happy path is deferred to
  P3 with D18.
- **Per-step id pin** (v3 change): `WEBV2_UUID=<seed>:<step>` replaces
  the single per-run seed, because each CLI process restarts its
  `new_id` counter at 0 and the first id of every command collided
  (two `exec` calls minted the same `EXEC-`). The per-step pin makes
  `EXEC-/ATT-/EV-/R-` families collision-free *and* still identical
  across twins.
- **Seeded exec records**: `seed_exec()` writes externally-reported
  `docker-networkless` records into both trees with
  `stdout = "Suite result: ok. 1 passed; 0 failed\n"` — the exact text
  the mint forge-meaningfulness check requires.

Determinism: two consecutive full runs produce byte-identical trees and
captures (normalized only by D4 root paths and D3 `environment_hash`).

## 3. Cross-twin DOCKER e2e — PASS

Command: `scripts/p2-docker-e2e.sh` (opt-in infrastructure; exits 0 with
`SKIP` when docker or the images are absent).

The golden suite is deliberately docker-free (its E4 records are
harness-seeded). This script closes that gap: the same P2 command
sequence runs through both twins against a **real docker daemon** and a
**real anvil fork endpoint**, and the resulting campaign trees are
byte-diffed.

Evidence (2026-09-09):

```
P2 DOCKER E2E GREEN: 11 commands x 2 twins, 21 tree files,
real docker exec + real anvil sequence, byte-identical
```

- **(a) exec / classify / mint** — a real `forge test` inside
  `foundry-solc-0824:latest` under `docker-networkless`: one passing
  run (exit 0, minted as E4 `foundry-test`) and one failing run
  (exit 1, fed to `classify`). The compared bytes include
  `exec_record.json`, `stdout.log`/`stderr.log`, the `ATT-`/`EV-`
  records and the `sandbox.exec`/`finding.evidence_added` events.
- **(b) sequence run / sequence verify / audit** — a 2-step sequence
  PoC executed by the generated POSIX-sh driver under `fork-runner`
  against an anvil container (`FORK_RPC_URL`, actors resolved through
  `eth_accounts`), so `sequence_result.json`, `spec_hash`, the driver
  stdout and the `sequence_coverage` audit section are compared from a
  real multi-transaction run.

Pinned/normalized: clock (`WEBV2_NOW`), per-command id stream
(`WEBV2_UUID=<seed>:<step>`), finding ids (`WEBV2_FINDING_IDS`), a
fresh anvil container per twin, and forge's own wall-clock timing
fields filtered with `sed` **inside the container** (they vary per run
in the same image; the filtered text is what the record hashes). The
only tree normalizations are D4 root paths and D3 `environment_hash` —
the exec record's `environment` block is **not** normalized: both twins
probe the same host, so `tool_versions` is byte-identical.

Coverage assertion: both twins report `sequence_coverage required=0,
covered=0` and the script fails if either reports otherwise. This is
vacuous by construction today — see D19 (no fork pin is attachable
through the Go CLI), so the assertion pins the *agreement*, and a
future chain-pin wiring flips it into a real coverage check.

## 4. verify-full P2 steps + P2 cross-audit — PASS

Command: `scripts/verify-full.sh` (14 steps).

Evidence (2026-09-09): **`VERIFY-FULL GREEN: all 14 steps pass`**.

- **step 11** builds a campaign with the LIVE Python CLI and audits it
  with Go; **step 12** builds the same campaign with Go and audits it
  with the live Python CLI. Both directions now carry P2 state: two
  real `exec` records + one seeded E4 record, a completed ladder,
  impact rows and the sequence verdict. Each direction asserts:
  `audit` exit 0, `audit --json` `ok: true` with **14 sections incl.
  `sequence_coverage`**, `verify` exit 0, and a cross-twin **read** of
  the other twin's P2 state (`execs --json` returns 3 records; the
  ladder report reads the other twin's completed ladder).
- **step 14** is a 37-invocation P2 CLI smoke on a scratch Go campaign
  (`init` → `audit --json`, all P2 verbs in a valid shape, documented
  exit codes: everything 0 except `ladder disprove` guard = 2 and
  `impact --unpriceable` incomplete = 2), followed by the same
  14-section assertion. 38 assertions in total.
- Steps 1–10 and 13 are unchanged (build/vet/gofmt, ported suite,
  `-race`, determinism double-run, asset sync, check-testmap, golden,
  crash smoke, P1 smoke).

**Harness bug found by this gate.** The P1/P2 cross-audit helpers used
a single `WEBV2_UUID` seed for every CLI invocation, so — exactly as in
golden v2 — the first id of each command collided (the two `exec` runs
minted one `EXEC-`, and the second overwrote the first). The fix is the
same per-step pin as golden v3, carried in a *file* counter because
every `run_p1` call sits inside a command-substitution subshell and
cannot mutate a shell variable.

## 5. testmap.json P2 reconciliation — PASS

Commands: `python3 scripts/check-testmap.py`;
`python3 .scratch/t24/reconcile-p2.py` (the reconciliation script).

Evidence (2026-09-09):

```
rows total           : 1378 (matches count-python-tests.py grand total 1378)
real rows            : 521  [1:1=509, merged=12]
deferred stubs       : 857  deferred-P1=233  deferred-P2=7  deferred-P3=505  deferred-P4=112
P0 10-file slice     : fully real (no deferred stubs)
go_file/go_func refs : all exist in the Go test tree
```

The P2 wave flipped **137 of the 144** deferred-P2 rows: 135 became 1:1
real rows and 2 became `merged_into` rows (two Python assertions of one
behaviour absorbed by a single Go test — `TestMintImpactEvidenceErrors`
also covers the unknown-artifact `KeyError`, and
`TestGateSequenceCoverageFailsClosed` also covers the covered-attempt
half). Rows flipped per file: `test_sequence_coverage.py` 25,
`test_sequence_spec.py` 20, `test_sequence_runner.py` 18,
`test_fork_poc_immunize.py` 16, `test_sequence_guidance.py` 12,
`test_planner_privileged.py` 11, `test_chain_engine.py` 7,
`test_sequence_pin_gate.py` 7, `test_independent_verification.py` 5,
`test_privileged_bands.py` 5, `test_privileged_baseline.py` 5,
`test_audit_sequence_coverage.py` 3, `test_cli_privileged.py` 3.

Two Go tests were **added** to make the mapping honest rather than
merely name-matched:

- `TestBridgeClassIsDeadEndWithoutE6`
  (`internal/reproduction/reproduction_test.go`) — the negative half of
  the E6 bridge confirmation.
- `TestIndependentVerificationQueueOrdersMandatoryFirst`
  (`internal/orchestrator/verify_queue_test.go`) — the queue was ported
  (`orchestrator/verify.go`) but had no unit test.
- `TestPrivilegedPrinterTwoRunDeterminism`
  (`internal/cli/cmd_privileged_test.go`) — the two-run byte-identity
  property of the Python CLI test.

The **7 rows that stay deferred-P2** are all `internal/roles` /
model-boundary work that this wave did not port (P3 scope):

| file | rows | why |
|------|------|-----|
| `tests/test_model_integration.py` | 5 | proposer/critic/reproducer bundle builders (`internal/roles`) are not ported |
| `tests/test_sequence_guidance.py` | 2 | `build_proposer_context` / `build_critic_context` have no Go twin yet |

Each carries that reason in its `notes` field. They are **not** hidden
stubs: the deferred count is visible in `check-testmap.py` output and
`internal/orchestrator/seqguidance_test.go` documents the same gap in
its header comment.

## 6. Ported suite green — PASS

Commands: `go vet ./...`; `go test ./... -count=1`;
`go test -race ./... -count=1`; determinism double-run
(verify-full step 5).

Evidence: full suite green across all packages including the new P2
modules (`maximization`, `chainengine`, `sequencepoc`, `forkpoc`,
`immunize`, `privileged`, `planner`, `audit/sections`), `-race` clean,
two consecutive `-count=1` runs byte-identical (durations stripped),
`gofmt -l internal cmd` empty.

**Parity defects the P2 suite caught and fixed** (also recorded in
`docs/gates/golden-v3.md` §3):

1. `RecordAttempt` wrote the `attempts` key *after* `tier_reached` in
   the reproduction record, so the byte order differed from Python.
   Fixed in `internal/reproduction/reproduction.go`.
2. `Sandbox.Execute` defaulted to a zero timeout, which
   `time.NewTimer(0)` turns into instant death. The default is now
   `defaultRunTimeout = 300` s, and `sequencepoc` passes an explicit
   timeout (`internal/sandbox/exec.go`, `internal/sequencepoc/run.go`).
3. The golden comment claimed `chains` materialises a `CHAIN-<8>` file;
   no CLI verb exists for `MaterializeChain`, so no such file is
   written. The comment was corrected (doc defect, no behaviour change).

---

## Known divergences added or closed by this phase

`KNOWN_DIVERGENCES.md`:

- **D2 — CLOSED.** The `sequence_coverage` audit section is ported; the
  golden checker's Python-only exception is gone and all 14 sections are
  compared byte-for-byte.
- **D18 — ADDED.** `ladder disprove`'s happy path writes a negative
  memory row; `learning.queue_memory` is a no-op in Go until the P3
  memory-lifecycle port, so the happy path cannot be byte-identical yet.
  The golden exercises the two *guard* branches (short reason; already
  reproduced rung) instead, both exit 2 and byte-identical. Unblocks
  with the P3 `learning.queue_memory` port.
- **D19 — ADDED.** `snap --deployment/--chain` is parsed and then
  dropped by the Go CLI: the library functions behind the snapshot fork
  pin are ported, but the CLI wiring is deferred, so
  `snap_has_fork_target` cannot become true through the Go CLI and the
  `sequence_coverage` section stays vacuously satisfied in both twins.
  The docker e2e pins that agreement (§3). The wiring is ~20 lines; a
  P1 deferral record already exists.

## Residuals (out of P2 scope)

- `internal/roles` (proposer/critic/reproducer bundle builders) — the
  7 deferred-P2 testmap rows and the sequence-guidance role tests
  (§5); P3.
- `learning.queue_memory` and the negative-memory lifecycle — D18; P3.
- `snap --deployment/--chain` CLI wiring — D19; ~20 lines, deferred by
  the P1 record.
- `WEBV2_GLOBAL_MEMORY_DIR` remains Python-only (D15); the shared /
  published memory tiers are P3.
- No golden step materialises a `CHAIN-` file: `chains` reports the
  capability graph and link proposals, but `MaterializeChain` has no CLI
  verb (§6.3).

## Reproduce

```bash
cd web3sec-go
export GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gopath \
       GOMODCACHE=$PWD/.scratch/gomodcache GOFLAGS=-mod=mod
go test ./... -count=1 && go test -race ./... -count=1
bash scripts/golden.sh                 # 102 steps x 2 twins, ~2 min
bash scripts/p2-docker-e2e.sh          # real docker + anvil, ~25 s
bash scripts/verify-full.sh            # 14 steps, ~4 min
python3 scripts/check-testmap.py
```

Artifacts: `.scratch/golden/` (tree-py, tree-go, captures),
`.scratch/p2-docker/`, `.scratch/verify-p1/`, `.scratch/t24/`.


