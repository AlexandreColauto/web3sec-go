# P0 Gate — Trust Core (Python → Go)

**Verdict: ALL SEVEN ITEMS PASS — the P0 gate is OPEN (2026-09-08).**

Design-8 checklist; each item: PASS/FAIL, the command whose output is
the evidence, and the on-disk evidence path.

| # | item | verdict |
|---|------|---------|
| 1 | Python campaign audits clean (reference suite green) | **PASS** |
| 2 | events.jsonl byte-identical (golden) | **PASS** |
| 3 | verify fast green (Go tests under budget) | **PASS** |
| 4 | golden suite v1 green | **PASS** |
| 5 | testmap.json function-level accounting reconciles | **PASS** |
| 6 | OQ3 checkpoint: Go jsonschema/v6 ≡ Python jsonschema on 27 schemas | **PASS** |
| 7 | Python coverage floor measured and recorded | **PASS** |

---

## 1. Python campaign audits clean — PASS

Command: `scripts/verify-full.sh` step 7
(`cd web3sec-final && PYTHONPATH=src python3 -m pytest tests -q`).

Evidence (2026-09-08 run): `1146 passed, 1 skipped, 1 warning in
172.10s`. The reference baseline — including every audit and
integrity test — is green; the Go port did not regress it.
On-disk: `.scratch/pytest.log` (verify-full step 7), full transcript in
`.scratch/verify-full-last.log`.

## 2. events.jsonl byte-identical — PASS

Command: `scripts/golden.sh` (Task 17 recipe, pinned clock + pinned id
stream — see appendix).

Evidence: the golden tree diff is byte-MATCH on all six files,
including `events.jsonl` (same seqs, same hash chain, same pinned
timestamps) and `campaign_state.json` (whose events mirror must match
event-for-event):

```
C-f249c45687/campaign_state.json
C-f249c45687/events.jsonl
C-f249c45687/snapshots/src-afb393bd-f1225bb346d5/foundry.toml
C-f249c45687/snapshots/src-afb393bd-f1225bb346d5/snapshot.json
C-f249c45687/snapshots/src-afb393bd-f1225bb346d5/src/Other.sol
C-f249c45687/snapshots/src-afb393bd-f1225bb346d5/src/Vault.sol
```

The identical `snapshot_id` on both twins (`src-afb393bd-f1225bb346d5`)
proves git-dirty snapshot_id derivation agrees too.
On-disk: `.scratch/golden/{py,go}/campaigns/C-f249c45687/`.

## 3. verify fast green (under budget) — PASS

Commands: `go test ./... -count=1`; `go test -race ./... -count=1`.

Evidence (2026-09-08): full suite **0.25s** (wall), `-race` **1.45s**
(wall) — both under the 2s budget set from the user directive
("I don't wanna super slow tests"). No flood loops >50 events anywhere
(the original 1002-event flood was replaced by `tailEvents()` pure
function tests). On-disk: `.scratch/gotest-run1.txt` / `run2.txt`
(verify-full step 5, the two determinism runs).

## 4. Golden suite v1 green — PASS

Command: `scripts/golden.sh` = `scripts/golden-run.py` +
`scripts/check-golden.py`.

Evidence: `GOLDEN GREEN` — 6 tree files byte-MATCH (normalized per
KNOWN_DIVERGENCES D3/D4/D2), 8 recipe commands × 2 twins with byte-
identical stdout/stderr/exit, deterministic across runs (same pinned
campaign id `C-f249c45687` every run). On-disk:
`.scratch/golden/spec.json`, `.scratch/golden/captures/{py,go}/`.

## 5. testmap.json reconciles — PASS

Commands: `python3 scripts/check-testmap.py`;
`python3 scripts/count-python-tests.py`.

Evidence (2026-09-08):

```
rows total           : 1096 (matches count-python-tests.py grand total 1096)
real rows (P0 slice) : 56  [1:1=53, merged=3]
deferred stubs       : 1040
P0 9-file slice       : fully real (no deferred stubs)
go_file/go_func refs  : all exist in internal/{state,snapshot,audit,cli}
```

The 3 merged rows are legitimate (the two root-default hint branches,
the legacy-log split), each noted in the row. The 2 rows that started
as flagged GAPs are now real 1:1 Go tests
(`TestPruneMakesPinEquivalentToCleanTree`, `TestSnapExcludeFlag`).
On-disk: `testmap.json`.

## 6. OQ3 checkpoint — PASS

Commands: `python3 scripts/oq3-check.py` (drives
`cmd/oq3check` — the production parse+validate path — against
`webv2.validation.validate`/jsonschema on the identical 27 embedded
schemas).

Evidence (2026-09-08): **972 (doc, schema) pairs, 0 mismatches.**
Corpus: the golden run's real documents (campaign_state, both event
lines, snapshot.json) × 27 schemas, plus per-doc mutations (drop each
top-level key, flip the first leaf to a wrong type, empty object),
plus 27 schema-driven type-flip documents (each schema's own top-level
properties set to the wrong type).

```
schema                  pairs  py-valid  go-valid  mism
finding                    36         0         0     0
snapshot                   36         2         2     0
campaign_state             36         2         2     0
model_response             36        36        36     0
trajectory                 36        36        36     0
…(27 rows, every mism = 0)…
```

Note: `model_response` and `trajectory` are container schemas
(per-role definitions selected at the model boundary), so every corpus
document validates against their loose roots — zero-discriminating, but
the two validators still agree on all 36 pairs each. The discriminating
pairs come from the mutations and type-flips across the other 25
schemas.
On-disk: `.scratch/oq3check` (binary), output pasted above.

## 7. Python coverage floor — PASS (floor recorded: 44%)

Command: `cd web3sec-final && COVERAGE_FILE=… .venv/bin/python -m
coverage run --source=src/webv2 -m pytest <the 9 P0-slice files> -q`,
then `coverage report`.

Evidence (2026-09-08): 56 passed in 32.4s. Coverage of the P0-slice
modules (the subset the Go port is accountable for):

```
src/webv2/audit.py          237    114    52%
src/webv2/cli.py           1722   1186    31%
src/webv2/snapshot.py       226     18    92%
src/webv2/state.py          323    109    66%
src/webv2/validation.py      48      9    81%
TOTAL                      2556   1436    44%
```

**Recorded floor: the P0 slice (9 test files) must keep
state/snapshot/audit/validation/cli coverage ≥ 44% (1,436 of 2,556
statements).** Whole-package coverage is 21% (12,418 statements) — the
P0-slice modules are the accountable subset; the rest belongs to later
phases' slices.

---

## Appendix A — the golden recipe (Task 17)

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

## Appendix B — what is compared (byte-level)

- `campaign_state.json`, `events.jsonl` (same seq, same hash chain).
- The pinned snapshot tree incl. `snapshot.json` (same snapshot_id,
  content_hash; environment_hash/manifest_hash normalized — KNOWN_D3).
- Every command's stdout, stderr, and exit code.
- `audit --json`: the six P0 sections + `ok` + `campaign_id`
  (Python's extra P1+ sections are KNOWN_D2).

## Appendix C — normalizations (each backed by a KNOWN_DIVERGENCES row)

1. Twin root path + target path → `<ROOT>` / `<TGT>` (KNOWN_D4).
2. `environment_hash` + derived `manifest_hash` → `<ENVHASH>`
   (KNOWN_D3).
3. Plain `audit` summary line: the six P0 section tokens are compared
   in order; Python's P1+ section tokens are dropped (KNOWN_D2).

Nothing else is normalized. Reproduce: `./scripts/golden.sh`
(exit 0 = GREEN).
