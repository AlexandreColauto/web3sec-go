# KNOWN_DIVERGENCES

The permanent ledger of places where the Go port is *not* byte-identical
to the Python reference, why, and what unblocks it. Every row must be
concrete: the exact bytes/field/line that differ, the reason, and the
milestone that closes it (or `permanent` with justification). The
cross-twin golden suite (`scripts/golden.sh`) normalizes exactly the
rows marked as golden-normalized — nothing else.

## P0 (this phase)

### D1 — Canonical float formatting (Task 2)
- **What:** a Go `float64` rendered via `strconv.FormatFloat(x, 'g', -1, 64)`
  and the same value rendered by CPython `repr()` diverge on *integral*
  floats: CPython emits `1.0` (always a decimal point), Go emits `1`.
- **Rule:** the canonical float rule appends `.0` when the `g`-format
  output has no `.`, `e`, or `-inf`/`+inf` marker, so both twins emit
  `1.0`. Implemented in `internal/validation/canon.go` (`PythonFloat`).
- **Oracle:** differential test suite in `internal/validation/` runs the
  rule against CPython-generated repr vectors (the vectors are committed
  next to the tests; they were produced by the Python reference, not by
  hand).
- **Status:** closed by design — the Go twin deliberately matches
  CPython, so this row documents the *mechanism*, not a live divergence.

### D2 — Audit section set: 6 (Go) vs 12 (Python) (Task 13)
- **What:** `audit` (plain and `--json`) reports every section the
  implementation has. The Go audit registry (P0) registers six sections —
  `event_log`, `artifacts`, `execs`, `findings`, `projection`,
  `snapshots` — while the Python reference has twelve (the extra six are
  P1+ territory: `relations`, `floor_policy`, …).
- **Surface:** the plain `audit` summary line lists all sections
  (`audit PASS: event_log=0 problem(s), …`); `audit --json` carries a
  `sections` object with the same set.
- **Why:** the P1+ sections need P1+ state that does not exist in the Go
  port yet; stubbing them would be dishonest (they would report
  "0 problems" over data the implementation does not model).
- **Golden:** the golden checker compares the six P0 section tokens in
  order and drops the Python-only P1+ tokens (plain line) / compares
  `ok` + the six P0 sections only (`--json`).
- **Unblocks:** P1 (audit registry grows section by section as each P1
  module lands; the golden comparison then widens automatically).

### D3 — `environment_hash` / derived `manifest_hash` (Task 11)
- **What:** `snapshot.json` carries `manifest.environment_hash` (a
  fingerprint of the build/runtime environment) and a `manifest_hash`
  anchored to it. The environment fingerprint hashes the *runtime*:
  `python 3.14.x` on one twin, `go1.26.2` on the other — the digests can
  never match across implementations.
- **Why:** the fingerprint exists to make a snapshot's provenance
  reproducible *within* an implementation line; cross-implementation
  equality of a runtime fingerprint is not a property the schema
  promises.
- **Golden:** normalized to `<ENVHASH>` (both fields) before the byte
  diff; everything around them (every other manifest field, the whole
  snapshot) is compared byte-for-byte.
- **Unblocks:** permanent. The *logic* (what goes into the fingerprint,
  the hashing order, the self-anchor) is identical and unit-tested
  against shared vectors on both sides; only the runtime string differs.

### D4 — Twin root and target paths inside artifacts (Task 14+)
- **What:** `campaign_state.json`, `snapshot.json` (`source.root`), and
  CLI output embed absolute filesystem paths that necessarily differ
  between the two twin roots (and between machines).
- **Why:** location, not behavior — the path *derivation* (which
  directory, which name, which nesting) is identical and compared
  structurally by the golden suite after normalization.
- **Golden:** normalized to `<ROOT>` / `<TGT>` before the byte diff.
- **Unblocks:** permanent (a property of running two instances).

### D5 — Corrupted-log `verify` problem text embeds the parser's wording (Task 17 finding)
- **What:** when `events.jsonl` is truncated mid-line, `verify` reports
  `line N: not valid JSON (<parser message>) — integrity past this point
  is unverifiable`. The `<parser message>` is the local JSON parser's
  wording: Go `encoding/json` says `unexpected EOF`; Python `json` says
  `Unterminated string starting at: line 1 column 152 (char 151)`.
- **Why:** the contract for corrupted input (verified by the verify-full
  crash smoke) is *a verdict, not a panic*: exit 1, well-formed JSON
  verdict, `ok: false`, `malformed_lines` counted. The embedded parser
  wording is diagnostic, not part of the state contract — the golden
  suite exercises only well-formed logs, where both twins are
  byte-identical.
- **Unblocks:** none planned (surface-level); may be aligned to a
  fixed wording in a future polish pass.

## Conventions for future rows

- One row per divergence; keep the **What / Why / Golden / Unblocks**
  shape.
- A row may be added by any phase, but a row may only be *removed* when
  the golden suite proves the bytes now match (delete the normalization,
  re-run `scripts/golden.sh` green).
- Nothing may be normalized by the golden checker without a row here.
