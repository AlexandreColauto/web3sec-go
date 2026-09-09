# Golden v5 P4 fixture (T38)

The small, **real-format** corpus the golden suite drives the P4 surface
with. Every byte is produced by the read-only Python reference
(`web3sec-final`) — see `build.py`, which is the only way this directory is
written:

```bash
python3 scripts/golden/p4/build.py          # regenerate in place
python3 scripts/golden/p4/build.py --check  # rebuild + byte-compare
```

`--check` is the drift guard: it rebuilds into a temp dir and byte-compares
the generated files against the committed ones. It is not part of
`golden.sh` (the golden must not depend on the reference checkout at run
time), but it is the one-command proof that the fixture is still exactly
what the reference emits.

## Layout

| path | what | built by |
|------|------|----------|
| `datasets/explorer/incidents.json` | 30-incident slice of the real DeFiHackLabs incident explorer, corpus order | `defihacklabs.load_records` selection |
| `datasets/explorer/rootcause_data.json` | the RCA records joined to that slice (name-normalized join) | same |
| `datasets/DeFiHackLabs/src/test/<YYYY-MM>/*_exp.sol` | the 18 resolved PoC files (flat Foundry layout the adapter expects) | copied from the read-only corpus |
| `eval/cases.json` + `cases.sha256` | 4 gold cases (3 dev + 1 held-out; 3 mapped classes + 1 `unmapped`) | `ingest.ingest_record` + `eval_store.add_case` |
| `shared-memory/{memory.json,signatures.json,manifest.json}` | 20 dev-partition prior rows published under `ingest:defihacklabs:<record_id>` | `ingest.publish_ingested` (the reference's real publish path) |
| `sft/examples.json` | the 2 committed curated examples + 2 constructed drafts | copy + derivation |
| `sft/lint-pass.json` | a curated example with a distinct claim the lint ACCEPTS | derivation |
| `sft/lint-dedup.json` | the SAME curated example: hard `dedup:` refusal | derivation |
| `sft/lint-reject.json` | a TODO skeleton the lint REFUSES (arc + TODO + reason) | derivation |

Selection rule (deterministic, no wall clock): for every canonical
`bug_class` the reference maps out of the corpus, the first record (corpus
order) with a resolvable PoC **and** the first without one, plus the first
`unmapped` record with a PoC — 30 records over 18 classes. The slice keeps
the real incident/RCA/PoC bytes; the PoC-present/PoC-missing mix is what
makes `poc_missing` and the attribution non-trivial.

## How the golden uses it

`scripts/golden-run.py` pins all three env seams at this directory for both
twins:

| env var | points at | consumed by |
|---------|-----------|-------------|
| `WEBV2_POC_ROOT` | `scripts/golden/p4/datasets` (`<base>/explorer`, `<base>/DeFiHackLabs`) | the Python sitecustomize root patch and the Go `datasets/defihacklabs.SetRoots` seam |
| `WEBV2_EVAL_DIR` | `scripts/golden/p4/eval` | `eval_store.EVAL_DIR` (Python) / `evalstore.EvalDir` (Go) |
| `WEBV2_SFT_STORE` | `<run root>/sft-store/examples.json` (a per-twin copy of `sft/examples.json`) | `sft_dataset.store_path` (Python, via the sitecustomize patch) / `sft.StorePath` (Go) |

The `shared-memory/` store is copied to the harness's global-memory dir
before each twin runs, so the reference's `publish`/`globalize`/`shared`
steps start from the same 20 prior rows in both twins.

`datasets/DeFiHackLabs/` is inside the Go repository, so the PoC-shape
cache's `git rev-parse HEAD` pin resolves to the Go repo's HEAD — the same
value for both twins in one golden run (the cache key is compared
cross-twin, not across commits).
