# P0 Gate — cross-twin golden suite v1 (Task 17)

Status: **GOLDEN GREEN** (2026-09-08). Full gate evidence (items 1-7)
is filled in by Task 19 below this recipe.

## The golden recipe (P0 command surface)

Run through BOTH twins — the Python CLI (`python -m webv2.cli`) and the
Go binary (`webv2`) — into two fresh roots, with:

- **Pinned clock**: `WEBV2_NOW` = `2026-09-08T12:00:00.000000+00:00`
  + 1s per step (monotonic). Both twins return it verbatim from their
  `now_iso`; unset = real clock (no behavior change).
- **Pinned id stream**: `WEBV2_UUID` = `golden-p0`. Both twins derive
  each "uuid4" as `sha256("<seed>:<counter>")[:16]` with the version/
  variant bits forced — identical bytes, so campaign/artifact ids match
  across implementations.
- **Fixed source tree**: tiny foundry target — `foundry.toml`
  (`sol = "0.8.24"`), `src/Vault.sol`, `src/Other.sol`, `data/f0000..0002.dat`
  (the `data/` dir exercises the bulk-default prune).

| step | command |
|------|--------------------------------------|
| 01 | `init --program Golden` |
| 02 | `status <cid>` |
| 03 | `snap <cid> <target>` |
| 04 | `log <cid>` |
| 05 | `verify <cid>` |
| 06 | `audit <cid>` |
| 07 | `status <cid>` |
| 08 | `audit <cid> --json` |

## What is compared (byte-level)

- `campaign_state.json`, `events.jsonl` (same seq, same hash chain).
- The pinned snapshot tree incl. `snapshot.json` (same snapshot_id,
  content_hash; environment_hash/manifest_hash normalized — see
  KNOWN_DIVERGENCES).
- Every command's stdout, stderr, and exit code.
- `audit --json`: the six P0 sections + `ok` + `campaign_id`
  (Python's extra P1+ sections are an expected, recorded difference).

## Normalizations (each backed by a KNOWN_DIVERGENCES row)

1. Twin root path + target path → `<ROOT>` / `<TGT>`.
2. `environment_hash` + derived `manifest_hash` → `<ENVHASH>` (the
   fingerprint hashes the runtime: `python 3.x` vs `go1.26` can never
   match across implementations; the logic is identical).
3. Plain `audit` summary line: the six P0 section tokens are compared
   in order; Python's P1+ section tokens are dropped (they land with
   P1+).

## Reproduce

```
./scripts/golden.sh        # build + run + check; exit 0 = GREEN
```
