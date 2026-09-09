# Golden Gate v3 — the ported P2 evidence-execution surface (Python → Go)

**Verdict: GOLDEN GREEN — 102 commands × 2 twins byte-identical, 34
artifact files byte-identical, 14/14 audit sections matched in both
directions, deterministic across runs (2026-09-09).**

`scripts/golden.sh` (= `golden-run.py` + `check-golden.py`) drives the
SAME scripted op-sequence through both twins — the Python reference
(`python3 -m webv2.cli`) and the Go port (`webv2`) — and byte-diffs every
artifact and every captured stdout/stderr/exit. Exit 0 = GREEN.

v3 keeps v2's 59 steps **verbatim** as steps 00–58 (nothing regresses; see
`docs/gates/golden-v2.md` and `docs/gates/P0-gate.md`) and extends them
with the ported P2 surface (steps 59–101).

```
$ ./scripts/golden.sh
tree: 34 files byte-MATCH (normalized)
steps: 102 commands x 2 twins (declared nonzero: gate-h1=1, gate-h3=1,
       prove-learning=1, ladder-disprove-short-reason=2,
       ladder-disprove-reproduced=2, impact-unpriceable-incomplete=2)
step 07 audit-json: 14 audit section(s) + ok MATCH (py-only: none)
step 99 audit-json-final: 14 audit section(s) + ok MATCH (py-only: none)

GOLDEN GREEN: all artifacts and command outputs byte-match (normalized per KNOWN_DIVERGENCES)
```

## 0. What changed from v2

| change | why |
|--------|-----|
| **D2 closed**: the Go audit registry carries all 14 sections; `check-golden.py`'s `PY_ONLY_SECTIONS` is now the **empty set** and both audit directions are compared byte-for-byte | `sequence_coverage` was the last Python-only section (KNOWN_DIVERGENCES D2) |
| **Per-step id pin**: `WEBV2_UUID = "<seed>:<step>"` instead of one global seed | every CLI invocation is a fresh process whose `new_id` counter restarts at 0, so a single seed makes the first id of *every* command identical (two `exec` calls would mint the same `EXEC-` id) |
| **New id families exercised**: `EXEC-`, `EV-`, `ATT-`, `LAD-`, `R-`, `ECO-` | P2's exec ledger, minting, ladder and impact surfaces |
| **Out-of-band exec seeding**: `seed-exec` steps mint harness-side exec records in both trees | `mint` and `ladder repro` consume an `EXEC-` record whose command was run by the harness (the golden has no docker/anvil); both twins must read the same record identically |
| **`reproduction.RecordAttempt` key order fixed** | see §3.1 |
| **`sandbox` default timeout fixed** | see §3.2 (found by the docker e2e, fixed here) |

## 1. What the P2 recipe walks

v3 inserts the h6/h7 block at position 48, so v2's steps 48–53
(`invariant-verify` … `answered-lens`) shift to 60–65 and v2's closing
view shifts to 97–101. Steps 00–47 are byte-identical to v2.

| step(s) | command(s) | what it proves |
|---------|-----------|----------------|
| 48–53 | `ingest` h6, `verdict`, `recall`, `gate`, `move POSSIBLE`, `move CONFIRMED` | a finding whose `capabilities.granted = ["pause"]` reaches `CONFIRMED` |
| 54–59 | the same six commands for h7 (`capabilities.required = ["pause"]`) | a second CONFIRMED finding that REQUIRES what h6 GRANTS — the capability graph's raw material |
| 60–65 | v2's `invariant-verify` … `answered-lens` (unchanged, shifted) | no regression |
| 66 | `exec --dry-run …` | the sandbox preview line: profile, network, tmpfs workdir, the exact `docker run` argv and the entrypoint pin note; mints nothing |
| 67–68 | `exec` (host-readonly, exit 0) and `exec` (host-readonly, exit 7) | the real exec ledger: two `EXEC-` dirs with `exec_record.json` + stdout/stderr logs; a failing command is recorded, not raised |
| 69–71 | `execs`, `execs --json`, `execs --id` | the ledger projections (plain, JSON, single record) |
| 72 | `classify <exec>` | the failure classifier over the exit-7 record |
| 73 | `seed-exec` (harness) | an externally-reported `docker-networkless` E4 record, minted identically in both trees |
| 74 | `mint <finding> --exec …` | E4 evidence from the seeded record (the `EV-` family) |
| 75–88 | `ladder start/show/add/explore ×4/repro/set-maximal/complete/report` + both `disprove` GUARD branches | the full variant ladder lifecycle on the CONFIRMED h5: rung creation, four exploration axes, a reproduction bound to a seeded exec (mints onto the finding), the maximal-rung pin, completion and the report |
| 89–91 | `chains`, `terminals`, `privileged` | the capability graph over h6→h7 (1 link, 1 proposal, 0 materialized chains), the terminal-state enumeration and the bounded privileged-role track |
| 92 | `sequence verify` | the coverage read path on the golden state (vacuous: h5 declares no multi-step `exploit_sequence`); the real fork run needs docker+anvil and lives in `scripts/p2-docker-e2e.sh` |
| 93–96 | `impact` priced, `impact` priced+artifact (E7 mint), `impact --unpriceable` (named decision), `impact` incomplete (**exit 2**) | the impact/`ECO-` surface and its documented refusal |
| 97–101 | `status`, `audit`, `audit --json`, `log --tail 5`, `verify` | the closing integrity view over the P2 state |

Every command's stdout, stderr and exit code must match byte-for-byte.
Six steps are *declared* non-zero and asserted as such (v2's three plus
`ladder-disprove-short-reason`=2, `ladder-disprove-reproduced`=2,
`impact-unpriceable-incomplete`=2).

## 2. Pins and isolation (v3 additions in bold)

| pin | value | why |
|-----|-------|-----|
| `WEBV2_NOW` | `2026-09-08T12:00:00.000000+00:00` + 1 s per step | both twins return it verbatim from `now_iso` |
| `WEBV2_UUID` | **`golden-p2:<step>`** (one seed per command) | every CLI run is a fresh process whose `new_id` counter restarts at 0; a single global seed would make two `exec` commands mint the SAME `EXEC-` id |
| `WEBV2_FINDING_IDS` | `pin` | installs the deterministic finding-id minter in the Go twin |
| `WEBV2_FINDING_ID_SEQ` | running count of findings minted so far | the two twins must mint the same `F-` ids (golden-v2 §3.1) |
| `WEBV2_GLOBAL_MEMORY_DIR` | `<work>/shared-memory` (empty) | the operator's `~/.webv2/shared-memory` store must never leak into a deterministic comparison (D15) |
| run root | the SAME path for both twins, sequentially | every event hash covers absolute artifact paths |
| **seeded exec ids** | `sha256("<seed>:seed-exec:<n>")[:10]` with version/variant bits | the harness-seeded records are INPUT, not CLI output; their ids must never collide with the per-process CLI stream (a real `exec` can mint the same first id as another real `exec`, but never as a seed) |

The Python tree is archived to `.scratch/golden/tree-py` before the Go run
re-creates `.scratch/golden/root`, so `events.jsonl` (a chained hash log)
is comparable byte-for-byte rather than "comparable after normalization".

## 3. P2 parity defects found by this gate

### 3.1 `reproduction.RecordAttempt` inserted `tier_reached` before `attempts`

Python's `repro.setdefault("attempts", [])` inserts `attempts` *before*
the later `tier_reached` key; the Go port set `tier_reached` first. The
finding file's JSON key order therefore differed at line 110 of the h5
finding (py: `attempts` then `tier_reached`; go: the reverse). Fixed in
`internal/reproduction/reproduction.go` by inserting `attempts` before the
tier block. Byte-diff of the 7 finding files is now exact.

### 3.2 `sandbox.Execute` used the zero timeout (instant kill)

`Sandbox.run(timeout: int = 300)` in the reference defaults to 300 s. The
Go `RunOpts.Timeout` is an `int` whose zero value is `0`, and
`time.NewTimer(0)` fires immediately, so any caller that did not pass a
timeout killed the child instantly. `scripts/p2-docker-e2e.sh` caught this
on the first real `sequence run` (`exit=-1`, empty logs). Fixed in
`internal/sandbox/exec.go` (`defaultRunTimeout = 300`) and made explicit
in `internal/sequencepoc/run.go` (`sequenceRunOpts` passes 300, mirroring
`run_sequence`); `driver_test.go` now asserts the forwarded timeout.

### 3.3 `chains` comment vs behaviour (documentation defect)

The recipe comment claimed `chains` materializes a `CHAIN-<8>`. It does
not: `chains` reports capability links and proposals, and neither twin has
a CLI verb for `materialize_chain`, so **no `CHAIN-` file exists in either
tree**. The `CHAIN-` id family is pinned by construction (`new_id`) and
covered by the `internal/chainengine` unit tests; the comment was
corrected rather than the comparison.

## 4. Fixtures added by v3 (`scripts/golden/`)

| file | role |
|------|------|
| `h6-grants-pause.json` | `logic-error` with `capabilities.granted = ["pause"]`, `required = []` → CONFIRMED, becomes the chain link's source |
| `h7-requires-pause.json` | `logic-error` with `capabilities.granted = []`, `required = ["pause"]` → CONFIRMED, becomes the chain link's target |

v2's fixtures (`model.json`, `h1`–`h5`, `policy.json`, `artifact.md`,
`sitecustomize.py`) are unchanged and still drive steps 00–59.

## 5. What is compared, and the normalizations

Compared byte-for-byte:

* every file under `campaigns/<cid>/` — **34 files**: `campaign_state.json`,
  `events.jsonl` (same seqs, same hash chain, same pinned timestamps), the
  pinned snapshot tree incl. `snapshot.json`, 7 finding files, the protocol
  model + plan + superseded plan + `invariant_links.json`, the 4 exec
  directories (`exec_record.json` + `stdout.log` + `stderr.log`), the
  ladder file `ladders/F-93976b475d79.json`, `bounty_policy.json`,
  `planner_hints.jsonl`, `waivers.jsonl`;
* every command's stdout, stderr and exit code (102 × 2);
* both `audit --json` reports: **all 14 sections** (D2 closed),
  `ok`, `campaign_id` — py-only sections are now a hard failure.

Normalized (each backed by a `KNOWN_DIVERGENCES.md` row):

1. the run root path and the target path → `<ROOT>` / `<TGT>` (D4);
2. `environment_hash` and the derived `manifest_hash` → `<ENVHASH>` (D3)
   — a runtime fingerprint can never match across implementations, and it
   appears in no event payload, so the hash chain stays comparable.

Nothing else is normalized. In particular **the exec record's
`environment` block is NOT normalized** — see §6.

## 6. The exec record environment block

The exec records carry an `environment` object
(`tool_versions`, `env_keys`, `network_access`, `filesystem`). The task
asked whether it needs normalization. Empirically it does **not**:

* the two CLI-side records (steps 67–68) run the SAME host commands
  through the same sandbox profile, so `tool_versions`, `env_keys`,
  `network_access` and `filesystem` are byte-identical;
* the two harness-seeded records (steps 73, 82) are written by the
  harness with a fixed `environment` (`tool_versions: {}`,
  `network_access: "none"`, `filesystem: "sandbox-tmp"`), so both trees
  carry the same bytes;
* the only environment-derived field that can never match is
  `environment_hash` in `snapshot.json` (D3), which lives outside the exec
  records.

The docker e2e reaches the same conclusion for REAL container runs: the
`docker-networkless` records it produces differ only in the fields the
harness normalizes there (`root` paths, `environment_hash`/`manifest_hash`
by value, `generated_at`) — `environment.tool_versions` is identical
because both twins probe the same host.

## 7. Unresolved / out of scope

1. **`ladder disprove` happy path** — the reference queues negative
   memory (`memory/MEM-*.json` + a `memory.queued` event); the Go
   `learning` seam is a no-op (D18), so the happy path would fork the
   event chain. The golden exercises both GUARD branches (short reason,
   reproduced rung), which abort before any write.
2. **`snap --deployment/--chain`** — parsed and dropped by the Go CLI
   (D19), so no fork pin is attachable through the Go CLI; consequently
   `sequence verify` is exercised only on the vacuous verdict. The docker
   e2e asserts the same vacuous verdict in both twins.
3. **`sequence run`** needs docker + anvil; it is not in the golden. It is
   covered end-to-end by `scripts/p2-docker-e2e.sh`.
4. **`CHAIN-` materialization** has no CLI verb in either twin (§3.3);
   link/proposal/report are covered, the id family by unit tests.
5. **`WEBV2_GLOBAL_MEMORY_DIR`** is honoured by Python only (D15), as in
   v2.

## 8. Reproduce

```bash
cd /home/xand/Projects/dsh-plugins/websec2/web3sec-go
export GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gopath \
       GOMODCACHE=$PWD/.scratch/gomodcache GOFLAGS=-mod=mod
./scripts/golden.sh          # exit 0 = GOLDEN GREEN
```

On-disk evidence: `.scratch/golden/spec.json` (recipe + expected exits),
`.scratch/golden/captures/{py,go}/` (stdout/stderr/exit per step),
`.scratch/golden/tree-{py,go}/` (the archived campaign trees).

Determinism was verified by running the suite twice and comparing every
capture and tree file after path normalization: run 1 == run 2.

