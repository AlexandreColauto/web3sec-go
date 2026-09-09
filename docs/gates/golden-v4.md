# Golden Gate v4 — the ported P3 surface (knowledge, memory, ops, env)

**Verdict: GOLDEN GREEN — 166 commands × 2 twins byte-identical, 66
artifact files across 2 campaigns byte-identical, 14/14 audit sections
matched in both directions, deterministic across runs (2026-09-09).**

`scripts/golden.sh` (= `golden-run.py` + `check-golden.py`) drives the
SAME scripted op-sequence through both twins — the Python reference
(`python3 -m webv2.cli`) and the Go port (`webv2`) — and byte-diffs every
artifact and every captured stdout/stderr/exit. Exit 0 = GREEN.

v4 keeps v3's 97 steps **verbatim** as steps 00–96 (nothing regresses; see
`docs/gates/golden-v3.md`), inserts the ported P3 surface as steps 97–155,
shifts v3's closing P0 verbs to 156–160, and appends a five-step second
campaign for the D19 deployment/chain pin (161–165).

```
$ ./scripts/golden.sh
tree: 66 files byte-MATCH across 2 campaign(s) (normalized)
steps: 166 commands x 2 twins (declared nonzero: gate-h1=1, gate-h3=1,
       prove-learning=1, ladder-disprove-short-reason=2,
       ladder-disprove-reproduced=2, impact-unpriceable-incomplete=2,
       env-doctor=1, run=3, complete-short-reason=2)
step 07 audit-json: 14 audit section(s) + ok MATCH (py-only: none)
step 158 audit-json-final: 14 audit section(s) + ok MATCH (py-only: none)

GOLDEN GREEN: all artifacts and command outputs byte-match (normalized per KNOWN_DIVERGENCES)
```

## 0. What changed from v3

| change | why |
|--------|-----|
| **Target enriched** with five of the reference probes package's own Solidity fixture trees (`probes/accumulator/blind`, `cursor/buggy`, `assertion_strength/clean`, `custody/buggy`, `short_circuit/buggy`) | v3's target was one trivial contract: `index`/`sinks`/`prescreen`/`probes` had no real surface (0 sites, 0 sinks, no BLIND keys). The fixtures are single-sourced from `internal/probes/testdata/probes/`, so they cannot drift from the ported probe code |
| **`WEBV2_COST_IDS=pin` + `WEBV2_COST_ID_SEQ`** | the reference mints `COST-` ids from a RAW `uuid4()` that the `WEBV2_UUID` pin never reached; the Go hook already existed, the harness now sets it |
| **`WEBV2_EVAL_DIR` / `WEBV2_POC_ROOT`** (absent paths) | the eval store and the DeFiHackLabs corpus are unported (D26); an absent corpus root is the module's own documented input state, so the *ported* layers compare |
| **`WEBV2_BASELINES_DIR`** (one scratch dir, reset per twin) | closes the "baseline add/remove can't be in the golden because the reference store lives in a read-only repo" gap (D24): the whole baseline lifecycle is now compared |
| **`WEBV2_PROMPTS_BASE`** | the reference is pointed at the Go twin's byte-identical embed mirror so `run`/`status` print and hash the SAME prompt path — D25 needs NO normalization in the golden checker |
| **`check-golden.py` diffs EVERY campaign** | the recipe now creates a second campaign (D19); the diff walks `campaigns/*` instead of one campaign id, and the env/manifest-hash normalizers are collected from every `snapshot.json` in both trees |
| **D18 closed** | `learning.queue_memory` is ported, so the `ladder disprove` happy path (memory row + `memory.queued` event) is now in the recipe |
| **D19 covered** | a second campaign snaps with `--deployment`/`--chain`; the pin members, both manifest roots, both `snapshot.*_attached` events and the two summary lines are byte-compared |

## 1. What the P3 recipe walks (steps 97–155)

| step(s) | command(s) | what it proves |
|---------|-----------|----------------|
| 97–98 | `index --src <snapshot>` / `--json` | the structural index over real Solidity; the entry count + `snapshot_id` view |
| 99–100 | `sinks --src <snapshot>` / `--json` | unguarded value paths (`custody` fixture) |
| 101–102 | `prescreen --src <snapshot>` / `--json` | archetype matches over the enriched tree (the pre-P3 target matched nothing) |
| 103–104 | `probes run`, `probes list --all` | 3 emitted rows + 2 BLIND axes + 1 `no-sites` axis over 5 fixture trees |
| 105 | `probes list --all --json` | the machine view the harness reads: it captures the FIRST `status=="blind"` axis and its first published key, and both twins must select the same one |
| 106–108 | `probes list`, `--axis <blind>`, `--axis <blind> --json` | the single-axis view |
| 109 | `probes blank --axis <blind> --anchor-blind <key> --reason … --actor golden` | the named blank attestation that closes a BLIND axis |
| 110 | `probes list --all` | the axis is now dispositioned; every other row is untouched |
| 111–112 | `probes run --emit` twice | plan obligations minted from the surface (Q-016…Q-019) and the **idempotent** second run |
| 113 | `plan` | the plan after emit, read-only view |
| 114–115 | `relations --rebuild`, `relations` | the typed research-memory graph and its derived delta |
| 116 | `resemble` | primitive-similarity search over the confirmed set |
| 117 | `corpus-surface` | class inventory, probe classes, exposure ordering, `poc_missing: 0`, `shape_matches: []` (absent corpus root, D26) |
| 118–120 | `ladder start` / `add` / `disprove` on h7 | the D18 happy path: a disproved rung queues a `MEM-` row + `memory.queued` event |
| 121–123 | `memory`, `memory --approve MEM-… --by golden`, `memory` | the queue → human-approved promotion |
| 124 | `publish --actor golden` | the approved memory row crosses to the root-tier shared store (`PUB-` id) |
| 125 | `globalize --actor golden --tier root` | re-scope to global (`SCP-` id) |
| 126–127 | `shared`, `shared --verify` | the merged both-tier view and the store verification |
| 128–130 | `brief`, `brief --json`, `brief --deep` | the operator cockpit, its machine view and the deep integrity fold |
| 131 | `report` | the campaign report artifact |
| 132–133 | `recency --target <tgt> --src <snapshot>` / `--json` | target-vs-pin freshness (the target is not a git repo: the "never" verdict) |
| 134–142 | `baseline list` (empty) → `forkdiff`/`--json` (none) → `baseline add` → `list` → `forkdiff`/`--json` (1.00) → `baseline remove` → `list` (empty) | the full baseline lifecycle against one pinned scratch store (D24) |
| 143–144 | `cost --kind model`, `cost --kind human-review --finding …` | operator cost ledger (`COST-` ids pinned) |
| 145 | `yields` | the derived yield view |
| 146–148 | `price set ETH 3000`, `price table`, `price-basis <F> <PRC>` | the price table (`PRC-` id) and the price-basis pin |
| 149–150 | `env doctor`, `env doctor --json` | the environment report (exit 1: no docker/forge in the golden) |
| 151–152 | `doctor`, `doctor --json` | the state-repair preflight + its machine view |
| 153 | `run` | the pipeline walk halting at the first model stage (exit 3, HALTED block) |
| 154–155 | `complete` guard (exit 2), `complete` | the completion gate and the successful completion |
| 156–160 | `status` / `audit` / `audit --json` / `log --tail 5` / `verify` | v3's closing P0 verbs, shifted, over the now-complete campaign |
| 161–165 | `init` (2nd campaign) → `snap --deployment … --chain …` → `status` / `audit` / `verify` | D19: both pin members, `deployment_merkle_root`, `chain_fingerprint`, the two `snapshot.*_attached` events and the two summary lines |

`doctor --json` (152) deliberately runs **before** `run` (153): it reports
`campaign_state.json`'s byte size, and the halting stage's note embeds the
prompt path. Since the harness aligns the prompt root (D25) the sizes
would match anyway, but the ordering keeps the numeric fields independent
of any future prompt-pack change.

<!-- section 2 appended below -->

## 2. The five new harness pins

All five are **harness-only** seams: unset, the Go binary and the
reference behave exactly as before (no behavior change, no new
dependency). Each has a `KNOWN_DIVERGENCES.md` row where it exists
because of a permanent host/packaging fact.

| env var | reference side (`sitecustomize.py`) | Go side (`cmd/webv2/main.go`) | row |
|---------|-----------------------------------|-------------------------------|-----|
| `WEBV2_COST_IDS=pin` + `WEBV2_COST_ID_SEQ` | patches `uuid.uuid4` (already in place for `F-` ids) | `costs.SetCostIDSource` (already in place) | — |
| `WEBV2_EVAL_DIR` | rebases `webv2.eval_store.EVAL_DIR` | not wired (store unported) | D26 |
| `WEBV2_POC_ROOT` | rebases `defihacklabs` `POC_ROOT` + `EXPLORER_DIR`/`INCIDENTS_FILE`/`ROOTCAUSE_FILE` | not wired (corpus unported) | D26 |
| `WEBV2_BASELINES_DIR` | rebases `webv2.forkdiff.BASELINES_DIR` | `forkdiff.SetBaselinesDir` | D24 |
| `WEBV2_PROMPTS_BASE` | rebases `webv2.adapter.resolve_prompt` + `PROMPTS_DIR`/`LEGACY_PROMPTS_DIR` onto the Go embed mirror | reads `assets/prompts*` natively | D25 |

The patch mechanism is the same meta-path finder as v3: it patches each
module **after its own import** (no `webv2` import at interpreter
startup), and only when `WEBV2_UUID` is set, so an ordinary CLI run is
untouched.

## 3. Target enrichment

`make_target()` writes `src/Vault.sol`, `src/Other.sol`, `docs/INVARIANTS.md`,
`data/f000*.dat` and `foundry.toml` exactly as v3 did, then copies five
fixture trees verbatim from `internal/probes/testdata/probes/`:

| fixture | contributes |
|---------|-------------|
| `accumulator/blind` | the BLIND `accumulator-skew` axis + its published key (the `probes blank` target) |
| `assertion_strength/clean` | the BLIND `enforcement-timing` axis (7 keys) |
| `cursor/buggy` | the emitted `liveness` row |
| `custody/buggy` | the emitted `primitive-symmetry` row + the unguarded transfer `sinks` reports |
| `short_circuit/buggy` | the emitted `guard-short-circuit` row |

Each fixture lands in its own `probes/<subdir>/` because `cursor` and
`assertion_strength` both ship a `Rollup.sol` and the probe ordering is
path-based. The snapshot id is content-addressed, so the enriched target
is still deterministic and identical in both twins.

## 4. Divergence ledger movement

| row | before v4 | after v4 |
|-----|-----------|----------|
| D18 — `ladder disprove` happy path writes no memory row | open, happy path excluded from the golden | **CLOSED**: `learning.queue_memory` is ported and wired; steps 118–124 exercise it |
| D19 — `snap --deployment/--chain` "dropped" | did not reproduce (the CLI has attached both pins since the P0 commit); verified by a dedicated cross-twin probe + CLI test | **also golden-pinned** (steps 161–165) |
| D24 — baseline store hangs off cwd vs package root | add/remove excluded from the golden | **golden-covered** via `WEBV2_BASELINES_DIR` (steps 134–142) |
| D25 — prompt path carries `assets/` | `run` excluded from the golden | **aligned** via `WEBV2_PROMPTS_BASE`; `run` is step 153 with NO normalization |
| D26 — eval store + DeFiHackLabs corpus unported | not recorded | **new row**: both stores pinned ABSENT; `corpus-surface` is step 117 |

`check-golden.py` normalizes exactly two classes: `<ROOT>`/`<TGT>` and
`<ENVHASH>` (environment + manifest hashes, which hash the runtime
version). Everything else — including every event hash, every `MEM-`/
`PUB-`/`SCP-`/`PRC-`/`COST-` id and both prompt paths — must be
byte-identical.

## 5. Running it

```
cd <repo> && export GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gopath \
  GOMODCACHE=$PWD/.scratch/gomodcache GOFLAGS=-mod=mod
./scripts/golden.sh
```

`golden.sh` rebuilds the binary, re-materializes the target in a fresh
temp dir, runs both twins sequentially under one root path, archives the
two trees to `.scratch/golden/tree-{py,go}` and byte-diffs them. The
baseline store is reset before each twin so neither inherits the other's
state.

Determinism sources: pinned clock (`WEBV2_NOW`, +1 s per step), pinned id
stream (`WEBV2_UUID=<seed>:<step>` plus the running `WEBV2_FINDING_ID_SEQ`
/ `WEBV2_COST_ID_SEQ`), the two absent-store pins and the aligned prompt
root. Two consecutive runs produce identical captures.

## 6. What is deliberately NOT in the golden

- **`sequence run` / `exec` against a real fork** — needs docker/anvil;
  covered by `scripts/p2-docker-e2e.sh`.
- **`sft`** — not ported (P4); D23's `env`-help quirk stays out of the
  recipe.
- **A real eval store / DeFiHackLabs corpus** — unported (D26); the golden
  pins both absent and compares the ported layers.
- **`baseline add` writing into either repo** — the store is pinned to a
  scratch dir (D24), so neither repo is mutated by a golden run.

