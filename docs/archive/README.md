# docs/archive — frozen history

Records that describe the port era (the Python twin `web3sec-final`, retired
2026-09-09 at the P4 cutover). They are kept read-only for provenance: every
claim in them is about bytes and behavior of a tree that no longer moves.

| file | what it is |
|---|---|
| `KNOWN_DIVERGENCES.md` | the permanent ledger of every place the Go port diverged from the Python reference, and why. Rows are historical; no code reads it at runtime (comments referencing `D<n>` ids refer to row numbers here) |
| `python-twin-issues.md` | bugs the port surfaced in the reference (each marked FIXED-IN-GO or reproduced); the Go-side fixes carry their own regression tests |
| `testmap-2026-09.json` | the final 1,378-row Python-test → Go-test accounting from 2026-09-10, right before the map was retired (post-retirement rows would lie: Go tests now move independently). The `internal/routing` + `internal/datasets/{forge,scabench}` rows point at code deleted in the same wave |
