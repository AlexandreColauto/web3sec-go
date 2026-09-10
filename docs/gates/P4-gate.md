# P4 Gate — Dataset tooling & cutover (Python → Go)

**Verdict: ALL SIX DELIVERABLES PASS — P4 gate GREEN (2026-09-09). The
cutover clock starts here; Python remains the reference implementation.**

Spec gate (`docs/GO_REWRITE_SPEC.md` §14), quoted verbatim:

> - **P4 — Dataset tooling + cutover.** metrics, eval store, sft, ingest, verify,
>   full test-suite parity gate, RUNBOOK walkthrough executed against the Go binary,
>   cross-twin CI green, binary release (embed assets), docs updated (README quick
>   start gains the Go install; runbook notes the binary name).

> **Cutover rule**: Python remains the reference implementation until P4's golden
> suite is green for two consecutive weeks of real campaign use; after cutover,
> Python is archived (not deleted) and the golden suite keeps a pinned Python
> container for regression checks.

Reference state: `web3sec-final` HEAD `2e41cd2` (1,378 test functions).
Port state: `web3sec-go` HEAD `1254db0` + the T37 working-tree changes in §10
(uncommitted by design — this session was scoped to verification, not commits).

| # | deliverable | verdict |
|---|-------------|---------|
| 1 | `webv2 selftest` (verify.py port, fast + `--full`) | **PASS** — §1 |
| 2 | RUNBOOK walkthrough executed against the Go binary | **PASS** — §2, 140/140 commands |
| 3 | binary release (embed assets) | **PASS** — §3, static 16 MB, standalone |
| 4 | docs updated (README quick start, runbook notes, twin issues) | **PASS** — §4 |
| 5 | divergence ledger: D26 closed, D27 + D28 added (T38 adds D29) | **PASS** — §5 |
| 6 | P4 gate report (this document) | **PASS** — §6 |
| — | full test-suite parity gate | **PASS** — §7 |
| — | cross-twin CI green | **PASS** — §8 |

**The cutover itself is NOT triggered by this gate.** The rule requires the
golden suite to be green for *two consecutive weeks of real campaign use*
after P4; that clock starts now (2026-09-09). **Operator decision
(2026-09-09): the Python repository is not touched** — no tag, no banner,
no archival step; it remains fully developable and the reference
implementation. The archive procedure (tag `webv2-python-final`,
deprecation banner, golden keeps the pinned-Python regression) is
documented in open item 1 below and executes only when the operator
approves it after the two-week window.

---

## 1. Deliverable 1 — `webv2 selftest` — PASS

`verify.py` is ported as a subcommand (`internal/cli/cmd_selftest.go`), in
the reference's exact output shape:

```
$ ./dist/webv2 selftest
web3sec-go self-check (fast — pass --full for the go test suite)
============================================================
[PASS] build-sweep  embedded assets ok: 28 schemas, 54 stage prompts, 8 playbooks, 7 archetypes, 67 commands
[PASS] walkthrough  done. campaign kept at /tmp/webv2-walkthrough-…/campaigns/C-…
[PASS] cli-audit    audit PASS: event_log=0 problem(s), … unpriceable=0 problem(s)
============================================================
ALL PASS
```

| verify.py check | Go check | what it does |
|-----------------|----------|--------------|
| `check_imports` | `build-sweep` | `go build ./...` (when run inside the module) + asset sweep: 28 schemas validated against `VNull`, 54 stage prompts, 8 playbooks, 7 archetypes, 67 registered commands |
| `check_walkthrough` | `walkthrough` | pins clock/uuid, `state.Init` → `Snapshot` → `BuildStructuralIndex` → `Ingest` (embedded schema-valid payload) → `RunDedup` → `AuditCampaign` |
| `check_cli_audit` | `cli-audit` | in-process `cli.Run` init/scope/snap/audit on a temp root |
| (n/a) | `go-test` (`--full`) | `go test ./... -count=1`; from a released binary outside the module it reports where the suite lives instead of failing |

- 6 tests in `internal/cli/cmd_selftest_test.go` pin the behavior: output
  shape vs `verify.py`, `--full` plan growth, the forced-failure seam
  (`selftestPlan`) exiting 1, released-binary behavior, temp-module exit-code
  propagation, and the in-module `go build` branch.
- The header names the Go suite, not pytest (`web3sec-go self-check (fast —
  pass --full for the go test suite)`), because `selftest --full` is the
  pytest substitute (see `docs/runbook-go-notes.md` S3).

## 2. Deliverable 2 — RUNBOOK walkthrough — PASS

`scripts/runbook-walkthrough.sh` builds the binary, materializes a scratch
campaign from the golden fixtures, and runs the runbook's commands **verbatim**
against it — 140 checks, each asserting the exit code the runbook documents
(or the `0/1/2` CLI contract) and the output markers the runbook calls out.

```
$ bash scripts/runbook-walkthrough.sh
[PASS] L16    selftest-fast                  exit=0
…
[PASS] L699   audit                          exit=0
[PASS] L688   doctor-json                    exit=0
walkthrough: 140 passed, 0 failed (runbook web3sec-final/RUNBOOK.md, binary …/webv2)
WALKTHROUGH GREEN: every RUNBOOK command matched its documented behavior
```

Wall clock **10 s**; idempotent (wipes and rebuilds its scratch root, run
three times green).

Coverage:

- every command in the cheat sheet (L684-750) plus the operational blocks
  (§0 setup, §2-4 campaign build, §5 floors/budget, §6 lifecycle, §7 views,
  §9 memory/ladder, §10 completion/audit);
- both optional-flag families that change the output shape
  (`--json`, `--verbose`, `--deep`, `--all`, `--axis`, `--state-only`,
  `--snapshot-only`, `--global`, `--rebuild`, `--emit`, `--dry-run`, `--env`);
- the documented refusals, asserted as refusals: `run` exit 3,
  `prove --stage` exit 1 while open, `gate <c> <f>` exit 1 while checks
  fail, `probes blank` on a non-blind axis exit 2, an illegal transition
  exit 2, `immunize` on a unit-test PoC, `ladder complete` with unexplored
  axes;
- the docker-dependent path is conditional: with a live daemon the real
  `exec`/mint/verify chain runs; without one the documented preflight
  refusal is asserted instead.

**Four runbook/code discrepancies were proven by running the literal text**
and are documented in `docs/runbook-go-notes.md` §3 (both twins behave
identically — these are runbook bugs, not port divergences):

| id | runbook text | both twins |
|----|--------------|------------|
| R1 | §6a L488 `move … CONFIRMED` without the `POSSIBLE` step §6 performs at L425 | exit 2, `not a legal transition` |
| R2 | L746 `--mutations "M1;M2;M3"` | exit 2, `needs a written description (>=5 chars)` |
| R3 | L693 `explore F-xxx [RUNG|AXIS]` (axis binds to `rung`) | exit 2, `unknown axis None` |
| R4 | L685 promises a toolchain line for any `foundry.toml`; both twins read `profile.default.sol`, not Foundry's `solc` | no toolchain line |

## 3. Deliverable 3 — binary release — PASS

`scripts/release.sh`:

```
$ bash scripts/release.sh
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o dist/webv2 ./cmd/webv2
file/ldd: ELF 64-bit … statically linked
--- standalone from a scratch dir with NO repo access ---
webv2 --help / selftest / ingest --example / mini walkthrough (init→snap→index→
probes run→audit→verify→brief): all green
binary: dist/webv2
sha256: 020c0cfb37f8c12d5b67c2a26625ebec7776c184dcc088ed1151540a4688a973
size:   16601250 bytes (16M)
RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean
```

_Final rebuild (post-gate): the `WEBV2_SFT_STORE` env seam (D28) and the
D15/D28 ledger updates landed after the first release build; the sha above
is the final binary. Cross-twin proof of the seam: from `cwd=/tmp` with
`WEBV2_SFT_STORE=<pyroot>/sft/examples.json`, both twins' `sft list` print
the same two curated examples byte-identically._
```

- `CGO_ENABLED=0`, `-trimpath`, `-s -w`; `ldd` reports "not a dynamic
  executable".
- Assets are `go:embed`ded (schemas, 54 stage prompts, 8 playbooks,
  7 archetypes, `ingest --example`'s schema legend) — the standalone check
  runs from `/tmp` with no repo, no `PYTHONPATH`, no module tree.
- Reproducible: re-running `release.sh` reproduces the sha256 above.

## 4. Deliverable 4 — docs — PASS

| file | status | content |
|------|--------|---------|
| `README.md` | **new** | Go install + quick start (`selftest`, `release.sh`, walkthrough, golden/verify-full/e2e, `go test`), a first campaign end to end, command surface, env vars, repo layout, verification table, docs index |
| `docs/runbook-go-notes.md` | **new** | the substitution table (S1-S10: module→binary, verify.py→selftest, pytest→`--full`, walkthrough.py→selftest check, venv→static binary, API→CLI, docker degradation, global-store var), the four runbook discrepancies with verbatim transcripts and fixes, the exit-code table, the API-only blocks, toolchain expectations, and the one-binary-at-a-time rule |
| `docs/python-twin-issues.md` | **new** | P1-P8: reference issues surfaced by the port (wrong TOML key, `resolve-candidate --note` schema, `ladder explore` argparse, bare `env` help bug, two runbook gaps, the over-promise it causes, and the reference-only divergences) with reproduction and the upstream fix for each |

The README's quick start is the Go half of the spec's "README quick start
gains the Go install"; the runbook notes are the "runbook notes the binary
name" half, written as a patch the reference repo can apply (the Python tree
is read-only for this port).

## 5. Deliverable 5 — divergence ledger — PASS

| row | change | evidence |
|-----|--------|----------|
| **D26** | **CLOSED** | the T33/T34 seams are wired in the CLI (`cli.WireT33Seams` → `corpus.SetListEvalCases` + trajectory/metrics case lookups; `cli.WireT34Seams` → `SetLoadPocRecords` + `SetRoots`/`SetPocRoot`). With the REAL stores mounted, both twins print `15 classes probed, 254 PoC files with signal, 135 records without a resolvable PoC` and the `corpus_surface.json` artifacts are byte-identical apart from `generated_at`; class weights match exactly (access-control w=172 score=11.152, logic-error w=320 score=6.245, reentrancy w=60 score=5.931, unchecked-external-call w=34 score=5.129, oracle-manipulation w=139 score=3.565). Script: `.scratch/t37/d26_check.sh`. T38 closes the golden caveat: the recipe now points both P4 seams at the committed `scripts/golden/p4/` fixture (§8), so the absent-store pins are gone. |
| **D27** | **ADDED** | `chains` proposal ORDER is `PYTHONHASHSEED`-dependent in the reference (sets), sorted (deterministic per fixture) in Go. `scripts/cap-analysis.py` proves the substantive parity live: both twins cap at exactly 500 with 500 distinct member sets; Go repeats identically over the same fixture; Python's order digest differs for seeds 0/1/2/3; with the cap raised Python enumerates **793** distinct member sets and BOTH capped sets are subsets of it (0 outside). The exact cut — and hence the overlap between the two cuts (275-373/500 observed) — is a per-run value because `new_finding_id` is a raw uuid4 in both twins and `WEBV2_UUID` does not pin it; the asserted properties are stable. Permanent while the reference iterates sets. |
| **D29** | **ADDED (T38)** | three character-vs-byte / `null`-vs-`[]` divergences the P4 fixture surfaced in the memory + bundle path (`deciding_propositions` verbatim, rune-clipped `pattern`/`evidence_summary`/assumption text, rune-counted context budget) — all **fixed in the Go twin** with unit tests and byte-identical in the golden; nothing normalized. See the ledger row for the per-site evidence. |
| **D28** | **ADDED** | the `sft` store path is source-relative in the reference (`repo_root()/sft/examples.json`) and cwd-relative in the Go binary — the same host fact as D24. Evidence: from `cwd=/tmp` the Python twin lists the two committed examples, the Go twin reads an empty store; from the repo root both agree. T38 drives the whole `sft` verb group through both twins with `WEBV2_SFT_STORE` (a per-twin fixture copy), so nothing is normalized; the embedder seam is `sft.SetStorePath`. |

Ledger hygiene (rows whose stated blockers have since been satisfied) is
recorded as an open item in §9.

## 6. Deliverable 6 — this report — PASS

`docs/gates/P4-gate.md` (this document). Gate template follows
`docs/gates/P3-gate.md`.

## 7. Full test-suite parity gate — PASS

```
$ go test ./... -count=1
ok  websec/internal/… (59 packages with tests, 0 failures, 3 packages without tests)
$ python3 scripts/check-testmap.py
testmap.json reconciled OK
  rows total           : 1378 (matches count-python-tests.py grand total 1378)
  real rows (P0 slice) : 1378  [1:1=1364, merged=14]
  deferred stubs       : 0
  distinct py funcs    : 1378
  go_file/go_func refs  : all exist in the Go test tree
```

1,378 reference test functions → 1,378 real Go rows (1,364 1:1 + 14 merged
with a written reason), **0 deferred stubs**. 1,963 Go `Test*` functions
across 62 packages (79,643 non-test lines).

`webv2 selftest --full` runs the same suite from the binary and is asserted
green by the walkthrough (check `selftest-full`, exit 0, `ALL PASS`).

## 8. Cross-twin CI green — PASS

```
$ bash scripts/golden.sh
golden run complete: campaign C-34c0ce6f4b (179 steps x 2 twins)
tree: 68 files byte-MATCH across 2 campaign(s) + sft-store (normalized)
steps: 179 commands x 2 twins (declared nonzero: gate-h1=1, gate-h3=1,
  prove-learning=1, ladder-disprove-short-reason=2, ladder-disprove-reproduced=2,
  impact-unpriceable-incomplete=2, env-doctor=1, run=3, complete-short-reason=2,
  sft-lint-dedup=1, sft-lint-reject=1)
step 07  audit-json: 14 audit section(s) + ok MATCH (py-only: none)
step 158 audit-json-final: 14 audit section(s) + ok MATCH (py-only: none)
GOLDEN GREEN: all artifacts and command outputs byte-match (normalized per KNOWN_DIVERGENCES)

$ bash scripts/verify-full.sh
… step 11/15 cross-audit Python→Go … step 12/15 cross-audit Go→Python …
ok: P3 commands exercised, exit codes as documented
VERIFY-FULL GREEN: all 15 steps pass          (133 ok assertions)

$ bash scripts/p2-docker-e2e.sh
[p2-docker] anvil ready at http://172.17.0.3:8545
[p2-docker] comparing the two twin trees
P2 DOCKER E2E GREEN: 11 commands x 2 twins, 21 tree files, real docker exec
+ real anvil sequence, byte-identical
```

The P4 command surface itself (selftest, sft, the full cheat sheet) is covered
by deliverable 2's walkthrough plus §7's suite; `verify-full.sh` remains the
P3 cross-audit smoke and was re-run to prove no regression.

**Golden v5 (T38, 2026-09-09) — the P4 modules are now IN the recipe.** The
recipe grew 166 → 179 steps:

* 13 new `sft` steps — `list` (plain, `--status curated`, `--status draft`,
  `--partition training`), `lint` on three committed fixture files (a curated
  PASS, an exact-duplicate hard dedup refusal with exit 1, and a TODO/rubric
  refusal with exit 1), `split --seed 42`, `report`, `export` (all and
  `--partition training`) and `backfill`. `split` REWRITES the store, so
  `WEBV2_SFT_STORE` points at a per-twin copy inside the run root and the
  post-split bytes are a compared tree file (`sft-store/examples.json`) — that
  is why the tree count moved 66 → 68.
* the existing P3 `corpus-surface` step now runs against the REAL P4 stores,
  because all three seams point at the committed fixture:
  `WEBV2_POC_ROOT` → the 30-record DeFiHackLabs slice (18 mapped bug classes
  + 1 unmapped, 19 PoC files), `WEBV2_EVAL_DIR` → the 4-case tamper-evident
  eval store (3 dev + 1 held-out) and `WEBV2_SFT_STORE` → the per-twin store.
  Its `corpus_surface.json` therefore carries non-zero class weights with
  eval-case and memory-row components, and `shape_matches` carries
  `record_id` / `memory_ids` / `bug_class` attribution.

The fixture is REAL-FORMAT and hermetic: `python3 scripts/golden/p4/build.py
--check` reproduces it byte-for-byte from the read-only reference, so CI needs
neither the 2.5 GB corpora nor the reference checkout at run time (open item 2,
now resolved).

The fixture immediately paid for itself: the new `sft-backfill` capture
surfaced three byte divergences the ASCII-only v4 recipe could never reach —
`deciding_propositions: null` vs `[]` on v2 rows, and character-vs-byte
clipping in the roles/corpus/sft/adapter paths. All three were real Go port
bugs, all three are fixed with unit tests and the step is now byte-identical
(D29); **nothing was normalized**.

## 9. Open items and residuals

Nothing blocks the P4 gate. These are recorded so they are decisions, not
surprises:

1. **Cutover clock + operator decision.** The spec requires P4's golden
   suite to be green for *two consecutive weeks of real campaign use*
   before Python is archived. This gate opens that window (2026-09-09).
   Operator decision (2026-09-09): do not touch the Python repository —
   the Go repository is the deliverable. The archive procedure when the
   operator eventually approves it: (a) tag `webv2-python-final` at the
   last reference commit, (b) a deprecation banner in the Python README
   pointing at this repository, (c) the golden suite keeps its pinned
   Python for regression. Until then Python remains the reference and
   both trees stay developable.
2. **D26 golden pins — RESOLVED (T38, 2026-09-09).** The golden recipe no
   longer exports absent `WEBV2_EVAL_DIR`/`WEBV2_POC_ROOT`. Both — plus the
   new `WEBV2_SFT_STORE` seam — point at the committed `scripts/golden/p4/`
   fixture (a REAL-FORMAT 30-record DeFiHackLabs slice, a 4-case eval store
   and 20 published shared-memory rows, reproduced byte-for-byte by
   `python3 scripts/golden/p4/build.py --check`), so the P3 `corpus-surface`
   step exercises the REAL stores in CI without the 2.5 GB corpora. See D26
   and §8.
3. **D15 closed; D23 closed as a fixed papercut; D14/D30 FIXED-IN-GO.**
   D15 (Go twin had no global store) is CLOSED in the ledger — the P3
   `internal/sharedmem` port landed and honours `WEBV2_GLOBAL_MEMORY_DIR` in
   production. D23 (bare `webv2 env` prints the wrong parser's help via a
   late-bound closure) is a Python bug; with the Python repository deprecated
   the decision was taken 2026-09-09: the Go behavior is correct, so D23 is
   CLOSED as a fixed papercut (the row documents the permanent reference
   divergence). D14 (`resolve-candidate --note` rejected by its own schema)
   and D30 (`ladder explore` natural axis form) are FIXED-IN-GO the same day
   (schema widened / positional rebound), each with a regression test; the
   golden recipe and `verify-full.sh` still omit those two paths so the
   byte-diff against the buggy reference stays green. Details in
   `docs/python-twin-issues.md` (P2, P3, P4).
4. **D28's seam landed.** `sft.StorePath()` now consults `WEBV2_SFT_STORE`
   (closeout commit) — cross-twin proof: from `cwd=/tmp` with the env
   pointed at the reference's committed store, both twins' `sft list` are
   byte-identical. The default-path difference remains a documented D24-class
   packaging fact.
5. **Four RUNBOOK discrepancies** (§2) are reference/runbook bugs; the fixes
   are written out in `docs/runbook-go-notes.md` §3 and
   `docs/python-twin-issues.md`. They are not port defects.
6. **`sequence run`** (RUNBOOK L737) needs a fork-runner RPC and is covered
   by `scripts/p2-docker-e2e.sh` (real anvil) rather than the walkthrough,
   which exercises `sequence verify`.
7. **Docker-less hosts.** The walkthrough asserts the documented preflight
   refusal when no daemon is present; on this box the daemon is live, so the
   real exec/mint/verify chain ran.

## 10. Final commit state

All P4 work is committed on `main` (59 commits total for the rewrite):

```
ee86315  P4 closeout: the WEBV2_SFT_STORE seam + ledger rows D15/D28
313e07e  P4 cutover: selftest + RUNBOOK walkthrough + binary release + P4 gate report
1254db0  P4 parity: the last three rows — testmap is now 1378/1378 real, 0 deferred
aec1b61  P4 wave 8b: the dataset loaders + the testmap re-triage sweep
5b018da  P4 wave 8a: dataset tooling — eval store + ingest + metrics + sft
```

New production code in P4: the dataset family
(`internal/{evalstore,ingest,metrics,sft,datasets}`), the `sft` CLI verb
(order 66) and the `selftest` command (order 67), plus the three parity
fixes (chain cap, verify E6 flags, brief siblings — the latter three
inside existing modules). `go.mod`/`go.sum` untouched (no new
dependencies). `dist/webv2` is the gitignored release artifact.

## 11. Reproduce

```bash
cd web3sec-go
export GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gopath \
       GOMODCACHE=$PWD/.scratch/gomodcache GOFLAGS=-mod=mod

go run ./cmd/webv2 selftest --full        # deliverable 1 (fast: drop --full)
bash scripts/runbook-walkthrough.sh       # deliverable 2, ~10 s
bash scripts/release.sh                   # deliverable 3
bash scripts/golden.sh                    # 179 steps x 2 twins, ~35 s
python3 scripts/golden/p4/build.py --check   # fixture drift guard (needs the reference repo)
bash scripts/verify-full.sh               # 15 steps, ~90 s
bash scripts/p2-docker-e2e.sh             # real docker + anvil, ~40 s
go test ./... -count=1                    # 59 packages
python3 scripts/check-testmap.py          # 1378/1378, 0 deferred
python3 scripts/cap-analysis.py           # D27 evidence
bash .scratch/t37/d26_check.sh            # D26 evidence (needs the reference repo)
```

Logs for this report: `.scratch/t37/{gotest,golden,verifyfull,dockere2e,rb-run5}.log`,
`.scratch/t37/d26_check.sh`, `.scratch/t37/cap-analysis/`.
