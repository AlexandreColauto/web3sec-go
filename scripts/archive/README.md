# scripts/archive — retired tooling

One-off or twin-era tooling, kept for provenance but wired to nothing.
Nothing in the live gates references these files.

| file | retired | why |
|---|---|---|
| `sync-assets.sh` | 2026-09-10 | byte-synced `assets/schema/` from the Python twin; superseded by `scripts/sync-asset-manifest.py` + `assets.TestAssetPackManifest` |
| `sync-testmap.py`, `check-testmap.py`, `count-python-tests.py` | 2026-09-10 | the Python↔Go test accounting machinery; the twin was retired 2026-09-09, so the 1:1 map stopped earning its keep. The map itself lives at `docs/archive/testmap-2026-09.json` |
| `invariants-vectors.py` | 2026-09-10 | regenerated differential vectors by executing the twin. The committed vectors stay as plain Go regression goldens (`internal/invariants` tests) — they pin "stable with itself", no Python needed. (`canon-oracle.py` did NOT retire: it imports only stdlib `json`/`sys`, so it stays a live differential oracle for `internal/validation/fuzz` — restored to `scripts/`.) |
| `oq3-check.py`, `oq3check-main.go.txt` | 2026-09-10 | the P0 differential validator probe (`cmd/oq3check`) that compared Go schema verdicts against Python `jsonschema`. The schema suite itself (28 embedded schemas + `internal/validation` tests) carries on |
| `cap-analysis.py` | 2026-09-10 | produced the D27 chain-cap parity evidence for the P4 gate report; the conclusion is recorded in the archived ledger |
