# P3 Gate — Knowledge & Memory (Python → Go)

**Verdict: ALL FIVE DELIVERABLES PASS — the P3 gate is OPEN (2026-09-09).**

Spec gate (GO_REWRITE_SPEC.md §14), quoted verbatim:

> - **P3 — Knowledge and memory.** structural index (+queries/value flow), **probes
>   (candidate surface: trust join, sibling collapse, quota, four-state closure,
>   emit/disposition, row ids/shape_sha)**, corpus surface, archetypes, playbooks,
>   history mining, relations, learning, shared memory, briefing, report, doctor, env,
>   costs. CLI: index/sinks/**probes**/prescreen/forkdiff/recency/baseline/relations/
>   resemble/publish/globalize/shared/memory/report/brief/doctor/env doctor/cost/yields/
>   price/price-basis. **Gate**: index + derived reports + probe surface byte-identical
>   on a fixture tree (row ids included); report.md diff = timestamp lines only.

Reference state: web3sec-final HEAD `2e41cd2` (1378 test functions).
Port state: web3sec-go HEAD `8240e3c` + the working-tree changes in §9
(not committed — this session was scoped to verification, not commits).

| # | deliverable | verdict |
|---|-------------|---------|
| 1 | testmap finish: P3 rows real or documented | **PASS** — 155 flipped, 45 documented |
| 2 | D19 close: `snap --deployment/--chain` | **PASS** — does not reproduce; probe + CLI test + golden |
| 3 | Golden v4: P3 recipe byte-identical across twins | **PASS** — 166 steps × 2, 66 files, 2 campaigns |
| 4 | verify-full P3: cross-audit + CLI smoke | **PASS** — 13 steps, 80 P3 invocations |
| 5 | P3 gate report (this document) | **PASS** |

---

## 1. The spec's gate sentence — PASS

**"index + derived reports + probe surface byte-identical on a
fixture tree (row ids included)"** — golden v4 (§4) runs `index`,
`sinks`, `prescreen`, `probes run/list/--all/--axis/blank/--emit`,
`relations`, `resemble`, `corpus-surface`, `brief`/`--json`/`--deep`,
`report`, `recency`, `forkdiff` and `baseline` over a pinned fixture tree
in both twins under a pinned clock and id stream; the checker byte-diffs
**every artifact, every capture and the whole campaign tree** (66 files
across 2 campaigns). Probe **row ids and `shape_sha` match** because both
twins hash the same canonical JSON.

**"report.md diff = timestamp lines only"** — exceeded: `WEBV2_NOW` is
pinned, so `report.md` is byte-identical with **no** timestamp
normalization. The checker normalizes exactly two classes, neither of
which is a timestamp: `<ROOT>`/`<TGT>` (absolute paths in artifacts) and
`<ENVHASH>` (environment/manifest hashes, D3/D16).

## 2. Modules ported 1:1 — PASS

20 P3 packages, 44,826 non-test lines, 54 packages total (51 internal)
green:

| package | lines | spec P3 item |
|---------|------:|--------------|
| `internal/structidx` | 4365 | structural index (+queries/value flow) |
| `internal/probes` | 8421 | probes (trust join, sibling collapse, quota, four-state closure, emit/disposition, row ids/shape_sha) |
| `internal/corpus` | 3195 | corpus surface |
| `internal/archetypes` | 1490 | archetypes |
| `internal/playbooks` | 788 | playbooks |
| `internal/histmining` | 984 | history mining |
| `internal/relations` | 2204 | relations |
| `internal/learning` | 1503 | learning (negative memory) |
| `internal/sharedmem` | 2901 | shared memory (root + global tiers) |
| `internal/briefing` | 3964 | briefing |
| `internal/report` | 2425 | report |
| `internal/doctor` | 577 | doctor |
| `internal/envgo` | 1574 | env (closes D17) |
| `internal/costs` | 696 | costs |
| `internal/forkdiff` | 1041 | forkdiff/baseline |
| `internal/adapter` | 1026 | prompts/stage adapter |
| `internal/roles` | 2365 | role bundle builders |
| `internal/boundary` | 1892 | model boundary |
| `internal/routing` | 1710 | routing table |
| `internal/trajectory` | 1705 | trajectories |

**CLI verbs byte-exact:** the Go binary registers **65 commands** (the
reference has 66; the only unported verb is `sft`, P4). Every P3 verb in
the spec's list exists — `index/sinks/probes/prescreen/forkdiff/recency/
baseline/relations/resemble/publish/globalize/shared/memory/report/brief/
doctor/env doctor/cost/yields/price/price-basis` — plus `corpus-surface`,
`shield`, `precondition` and the rest. Argparse-level help and refusals
are pinned by `internal/cli/cmd_t31_test.go`.

## 3. D19 close — `snap --deployment/--chain` — PASS

`KNOWN_DIVERGENCES.md` D19 is **CLOSED (2026-09-09) — the divergence
does not reproduce.** The Go CLI has attached both pins since the P0
commit (`internal/cli/cmd_snap.go`: `attachDeployment`/`attachChain` →
`snapshot.AttachDeploymentPin`/`AttachChainPin`, then the two summary
lines); the row's "parsed and dropped" description was stale. No
production code change was needed — T32 supplied the missing evidence,
test and golden coverage:

- **Evidence 1 — cross-twin probe** `.scratch/t32/d19_probe.py`: six
  `snap` invocations (plain, `--deployment`, `--chain`, both, twice)
  through both twins under a pinned clock/id; every stdout/stderr/exit
  and the full campaign tree (`snapshot.json` incl. both manifest roots +
  `events.jsonl`) byte-identical after `<ROOT>`/`<TGT>` normalization
  (sample pin: `deployment_merkle_root=706dc6aa…`,
  `chain_fingerprint=c5a6e5bf…`).
- **Evidence 2 — CLI test** `internal/cli/cmd_snap_test.go` (new): pins
  the on-disk `deployment`/`chain` members, the 64-hex manifest roots,
  the active snapshot id, the event order and the two summary lines, plus
  the missing-file refusal.
- **Evidence 3 — golden v4** steps 161–165: a SECOND campaign
  `init → snap --deployment scripts/golden/deployment.json --chain
  scripts/golden/chain.json → status/audit/verify`; the checker
  byte-diffs every campaign tree (66 files across 2 campaigns).

## 4. Golden v4 — PASS

```
$ bash scripts/golden.sh
golden run complete: campaign C-34c0ce6f4b (166 steps x 2 twins)
tree: 66 files byte-MATCH across 2 campaign(s) (normalized)
steps: 166 commands x 2 twins (declared nonzero: gate-h1=1, gate-h3=1,
       prove-learning=1, ladder-disprove-short-reason=2,
       ladder-disprove-reproduced=2, impact-unpriceable-incomplete=2,
       env-doctor=1, run=3, complete-short-reason=2)
step 07 audit-json: 14 audit section(s) + ok MATCH (py-only: none)
step 158 audit-json-final: 14 audit section(s) + ok MATCH (py-only: none)

GOLDEN GREEN: all artifacts and command outputs byte-match (normalized per KNOWN_DIVERGENCES)
```

P3 steps are **97–155 (59 steps)** plus the D19 campaign **161–165**.
New recipe surface: `index`/`sinks`/`prescreen`, the probe surface
(`run`, `list`, `--all`, `--axis`, `blank`, `--emit` twice for
idempotence), `relations --rebuild`, `resemble`, `corpus-surface`, the
memory lifecycle (`ladder disprove` happy path → `memory --approve` →
`publish` → `globalize` → `shared`/`--verify`), `brief`/`--json`/
`--deep`, `report`, `recency`, the baseline lifecycle
(`list`/`add`/`forkdiff`/`--json`/`remove`), `cost`×2, `yields`,
`price set/table/basis`, `env doctor`, `doctor`, the `run` halt and
`complete`.

### 4.1 New pins and seams (full table in `docs/gates/golden-v4.md`)

| pin / seam | without it | with it |
|-----|-----------|---------|
| `WEBV2_COST_IDS=pin` + `WEBV2_COST_ID_SEQ` | `COST-` ids are a raw uuid4 in the reference → differ per twin | identical cost ledger |
| `WEBV2_EVAL_DIR` / `WEBV2_POC_ROOT` (absent) | the reference reads 135 eval cases + 287 PoCs + 930 explorer records, Go reads none (D26) | both read an absent store — the module's own documented empty input |
| `WEBV2_BASELINES_DIR` (scratch, reset per twin) | `baseline add/remove` cannot be compared (the reference writes its read-only package root, D24) | the full lifecycle compares without touching either repo |
| `WEBV2_PROMPTS_BASE` (Go embed mirror) | the `run` prompt path differs (`assets/` segment, D25) and lands in the run event hash | both twins print and hash the SAME path — no normalizer |

Normalizations remain exactly two: `<ROOT>`/`<TGT>` and `<ENVHASH>`.
Everything else — every event hash, every `MEM-`/`PUB-`/`SCP-`/`PRC-`/
`COST-` id, both prompt paths — is byte-identical.

## 5. verify-full P3 — PASS

The transcript below is from the 15-step revision at the gate date; at head
the cross-audit is step 9 and the smoke runs as step 12 (the step-12 bullet
below counts it at head).

```
$ bash scripts/verify-full.sh
=== step 11/15: cross-audit: a Python-written campaign audits clean in Go ===
ok: Python built C-45488bdaf5 (init/model/plan/ingest x2/verdict/dedup/answered/gate/artifact/invariant)
ok: Go audit/verify accept the Python-written campaign (ok: true)
  ok Go audit of Python campaign: 14 audit sections incl sequence_coverage
  ok Go reading Python P2 state: 3 exec records readable
  ok Go reading Python P2 state: ladder report reads the other twin's completed ladder
  ok Go reading Python P2 state: memory view reads the other twin's queued negative row
  ok Go reading Python P2 state: 6 probe axes (1 blind) readable
=== step 12/15: cross-audit: a Go-written campaign passes the LIVE Python audit ===
ok: Go built the same campaign id (C-45488bdaf5) under the pinned stream
ok: Python audit/verify accept the Go-written campaign (ok: true)
...
=== step 15/15: P3 CLI smoke: index/probes/memory/publish/baselines/costs/run ===
ok: P3 commands exercised, exit codes as documented

VERIFY-FULL GREEN: all 15 steps pass
```

Wall clock: **50 s** with warm Go build/test caches (golden alone 25 s);
well under the 5-minute budget. `scripts/golden.sh` measured separately at
25 s.

- **transcript steps 11/12 (cross-audit, both directions)** built P3 state in
  the campaign: `snap` the reference blind fixture → `index` →
  `sinks`/`prescreen` → `probes run` → `probes run --emit` →
  `relations --rebuild`, a **disproved rung's queued memory row** (D18
  happy path) and **`report.md`**. So the OTHER twin's audit must
  validate a real `probe_surface` section — including the "surface has
  rows but no emitted priority" refusal, which is why `--emit` is in the
  build. `p2_cross_read` additionally reads the other twin's exec
  ledger, completed ladder, **queued memory row**, probe axes/blind keys
  and report.
- **step 12 (P3 CLI smoke)**: **80 P3 invocations** against scratch Go
  campaigns — the repo-wide one for the structural/probe/memory/publish/
  baseline/cost legs, plus a second root whose index is built straight from
  the assertion-strength fixture — each asserting the reference's documented
  exit code — the structural surface, the probe surface incl. the named
  `blank` attestation (recorded against the fixture-only campaign, whose
  enforcement-timing axis is `blind`: sites 4, rows 0, 5 near-keys),
  `relations`/`resemble`/`corpus-surface`, the D18 memory
  happy path, `publish`/`globalize`/`shared`, `shield`/`precondition`,
  `brief`/`report`/`recency`, the baseline lifecycle, `cost`/`yields`/
  `price`, `env doctor`/`doctor`, `run` (exit 3), `complete` (guard 2 /
  success 0), and the closing `audit`/`--json`/`verify` (14 sections).
  Declared refusals: `precondition` unknown description = 1,
  `complete` short reason = 2, `run` needs-model = 3.

The smoke is Go-only by design (cross-twin byte-identity is the golden's
job); it is the fast "each verb works in a valid shape with the
documented exit code" check.

## 6. testmap finish — PASS

```
$ python3 scripts/check-testmap.py
testmap.json reconciled OK
  rows total           : 1378 (matches count-python-tests.py grand total 1378)
  real rows (P0 slice) : 987  [1:1=973, merged=14]
  deferred stubs       : 391  deferred-P1=227  deferred-P2=7  deferred-P3=45  deferred-P4=112
  distinct py funcs    : 1378
  P0 10-file slice     : fully real (no deferred stubs)
  go_file/go_func refs  : all exist in the Go test tree
```

`deferred-P3` went **200 → 45**; **155 rows flipped** to real, each
naming the Go test that absorbs it:

| kind | count | example |
|------|-------|---------|
| exact CamelCase match (`test_probes_x` → `TestProbesX`) | 134 | `test_probes_run_emits_rows` → `internal/cli/cmd_probes_test.go::TestProbesRunEmitsRows` |
| semantic match (renamed/merged Go test) | 21 | `test_bad_file_rebuild_creates_no_archive` → `internal/structidx/indexsha_test.go::TestBadRebuildCreatesNoArchive` |

**45 rows stay `deferred-P3`, each with a `notes` string naming the
missing piece** (the checker enforces a note or a real Go home):

| rows | python file | missing piece (representative) |
|------|-------------|-------------------------------|
| 9 | `test_probes_cli.py` | CLI-level probe rendering branches (e.g. `--emit` on an empty plan) |
| 5 | `test_recall_relevance.py` | relevance-ranking integration (ranker core pinned by `internal/learning`) |
| 5 | `test_work_order.py` | work-order ordering view |
| 4 | `test_plan_lenses.py` | lens-divergence line in `brief`/`plan` |
| 4 | `test_plan_rebuild.py` | plan-rebuild integration paths |
| 3 | `test_lens_exhaustive.py` | exhaustive lens sweep |
| 3 | `test_reachability.py` | reachability notes in `plan` |
| 2 | `test_criticality.py` | `brief` critical-hunt ranking integration |
| 2 | `test_partition_guards.py` | partition guard refusals |
| 2 | `test_tier1_minor_sweep.py` | minor-sweep aggregation |
| 2 | `test_unpriceable_impact.py` | unpriceable-impact CLI rendering |
| 1 each | `test_answered.py`, `test_bundle_corpus_keys.py`, `test_history_learning.py`, `test_playbooks.py` | answer-quality section, bundle corpus keys, history learning, playbook tool ids |

Residual `deferred-P1` (227) and `deferred-P2` (7) are the pre-existing,
documented backlog from those phases (role/model-boundary bundles,
routing/adapter integration); the P3 flips did not regress them.
`deferred-P4` (112) is the unported SFT/eval/dataset surface.

## 7. Ported suite and speed — PASS

```
$ go vet ./...                                   # clean
$ go build ./cmd/webv2                           # clean
$ go test ./...                                  # PASS, warm 3 s
$ go test -race ./...                            # PASS, 19 s
$ go test -count=1 ./... (twice, durations stripped)  # byte-identical
```

- **51 internal packages / 54 total** green; ~3.1 s warm full suite.
- **Determinism:** two fresh `-count=1` runs compare byte-identical
  after stripping durations (Go==Go), on top of the golden's Py==Go.
- **New regression test** `internal/cli/cmd_brief_test.go`:
  `TestBriefPrescreenEmptyMatchRendersNone` pins a P3 finding — `brief`
  renders an empty prescreen match list as the literal
  `prescreen: matched none` (Python: `', '.join(...) or 'none'`), not a
  bare empty tail. The fix is `internal/cli/cmd_brief.go:174`.
- `scripts/check-testmap.py` and `scripts/sync-testmap.py --check` OK;
  `scripts/sync-assets.sh` + schema diff OK (28/28 schemas).

## 8. Cross-twin docker e2e — still green

```
$ bash scripts/p2-docker-e2e.sh
[p2-docker] comparing the two twin trees
P2 DOCKER E2E GREEN: 11 commands x 2 twins, 21 tree files, real docker exec +
real anvil sequence, byte-identical
```

Re-run once for this gate (2026-09-09): real `forge test` in the foundry
image, real anvil sequence execution, byte-identical exec record and
minted evidence in both twins.

## Known divergences added or closed by this phase

`KNOWN_DIVERGENCES.md`:

- **D2 — CLOSED** (P2): 14 audit sections in both twins.
- **D17 — CLOSED** (T26): `internal/envgo` ports `webv2.env`; the
  `internal/sandbox` seam now installs the real implementation.
- **D18 — CLOSED (2026-09-09).** `learning.queue_memory` is ported and
  wired, so the `ladder disprove` happy path writes the negative-memory
  row + `memory.queued` event; golden steps 118–124 exercise it.
- **D19 — CLOSED (2026-09-09).** See §3.
- **D23 — OPEN, and it is a PYTHON bug.** The reference's bare
  `webv2 env` prints the wrong parser's help (a late-bound closure in
  `build_parser()` rebinds `s` to the last subparser, today `sft`); the
  Go twin prints the correct `env` help. Per spec §1.4 the fix belongs in
  the Python twin — **flagging for the user**: either fix `cli.py` or
  accept the Go behavior as the correct one. No golden step runs bare
  `webv2 env`.
- **D24 — OPEN (inherent).** The reference's `baselines` dir hangs off
  the binary cwd (RUNBOOK runs from the repo root); Go hangs it off the
  package root and honours `WEBV2_BASELINES_DIR`. Golden pins the seam;
  no behavior difference in the documented run mode.
- **D25 — OPEN (packaging).** `prompt_path` carries the embed mirror's
  `assets/` segment in Go. The golden aligns the reference to the Go
  mirror via `WEBV2_PROMPTS_BASE`, so `run` compares byte-for-byte with
  no normalizer; the row stays open as a packaging fact.
- **D26 — ADDED.** The eval store and the DeFiHackLabs corpus are
  unported (P4). The golden pins both ABSENT for both twins and compares
  the ported layers (`class_inventory`, probe classes, exposure ordering,
  `poc_missing: 0`, `shape_matches: []`).
- **D15 — unchanged** (shared-memory dir default, reference-only seam).

## Residuals (out of P3 scope)

- **45 deferred-P3 testmap rows** (§6) — rendering/ordering integrations,
  each with a note; not unported verbs.
- **227 deferred-P1 + 7 deferred-P2 rows** — pre-existing documented
  backlog (`internal/roles` / model-boundary bundle builders).
- **112 deferred-P4 rows + the datasets** — SFT, eval store, metrics,
  DeFiHackLabs ingestion (D26). `WEBV2_EVAL_DIR`/`WEBV2_POC_ROOT` are the
  seams the P4 port will wire; `sft` is the one unported CLI verb.
- **Real fork/anvil `sequence run`** lives in `scripts/p2-docker-e2e.sh`,
  not the golden.
- **D23's Python help bug** needs a Python-side fix (see above).

## 9. Working-tree changes (uncommitted by design)

```
 M KNOWN_DIVERGENCES.md          D18/D19 closed, D24/D25/D26 updated
 M cmd/webv2/main.go             WEBV2_BASELINES_DIR -> forkdiff.SetBaselinesDir
 M internal/cli/cmd_brief.go     prescreen empty-match "none" fix
 M scripts/check-golden.py       multi-campaign diff + env/manifest normalization
 M scripts/golden-run.py         P3 recipe, D19 campaign, new pins
 M scripts/golden.sh             v4 header
 M scripts/golden/sitecustomize.py  eval-store/baselines/poc/prompt seams
 M scripts/verify-full.sh        P3 cross-audit + step 15 P3 CLI smoke
 M testmap.json                  155 P3 rows flipped, 45 documented
?? docs/gates/golden-v4.md
?? docs/gates/P3-gate.md
?? internal/cli/cmd_snap_test.go
?? internal/cli/cmd_brief_test.go
?? scripts/golden/deployment.json
?? scripts/golden/chain.json
```

## Reproduce

```bash
cd web3sec-go
export GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gopath \
       GOMODCACHE=$PWD/.scratch/gomodcache GOFLAGS=-mod=mod
go test ./... -count=1 && go test -race ./... -count=1
bash scripts/golden.sh                 # 166 steps x 2 twins, ~25 s
bash scripts/p2-docker-e2e.sh          # real docker + anvil, ~25 s
bash scripts/verify-full.sh            # 15 steps, 50 s warm (all caches hot)
python3 scripts/check-testmap.py
python3 .scratch/t32/d19_probe.py      # D19 cross-twin probe
```

Artifacts: `.scratch/golden/` (tree-py, tree-go, captures),
`.scratch/verify-p1/`, `.scratch/p2-docker/`, `.scratch/t32/` (probes,
logs: `verify-full-p3.log`, `docker-e2e.log`).
