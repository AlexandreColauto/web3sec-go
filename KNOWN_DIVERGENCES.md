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

### D2 — Audit section set: 13 (Go) vs 14 (Python) (Task 13, t15)
- **What:** `audit` (plain and `--json`) reports every section the
  implementation has. The Go registry now carries thirteen sections in
  the Python `audit.py` code order — `event_log`, `artifacts`, `execs`,
  `findings`, `projection`, `snapshots`, `relations`, `floor_policy`,
  `stage_completions`, `baselines`, `invariant_verification`,
  `probe_surface`, `unpriceable` — while the Python reference has
  fourteen. The missing one is `sequence_coverage` (Python's section
  12), which the P0 plan reserves for a later phase.
- **Surface:** the plain `audit` summary line lists all sections
  (`audit PASS: event_log=0 problem(s), …`); `audit --json` carries a
  `sections` object with the same set.
- **Why:** `sequence_coverage` reads coverage state (P2) that the Go
  port does not model yet; stubbing it would be dishonest (it would
  report "0 problems" over data the implementation does not have).
- **Parity:** `internal/audit/testdata/p1_audit_vectors.json` holds 21
  scenarios whose expected bytes were produced by the LIVE Python twin
  (`.scratch/t15/gen_vectors.py`), and `.scratch/t15/parity_check.py`
  builds the same P1 campaign independently in both twins, audits it in
  both, and diffs the full report after id/hash normalization. The only
  delta is the `sequence_coverage` token/section.
- **Golden:** the golden checker compares the six P0 section tokens in
  order and drops the Python-only tokens (plain line) / compares `ok` +
  the six P0 sections only (`--json`); unchanged by this row.
- **Unblocks:** the phase that ports `sequence_coverage`; D2 then closes.

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

## P1 (risk / pricing)

### D6 — Unicode `\b` word boundary in regexes (risk, findings, sandbox)
- **What:** `webv2.risk._INSOLVENCY_RE` contains `\bpools?\b`. Python's
  `\b` is Unicode-aware (a word char is `str.isalnum()` or `_`); RE2 has
  no Unicode word boundary, so the Go twin spells it as
  `(?:^|[^\p{L}\p{N}\p{Pc}])pools?(?:$|[^\p{L}\p{N}\p{Pc}])` — the
  convention already used by `internal/findings` (`claimHalfRe`),
  `internal/sandbox` and `internal/validation/atomicio`.
- **Exact divergence:** under `(?i)` RE2 expands a negated class to the
  case-fold closure of `\p{L}\p{N}\p{Pc}`, which is a strict superset of
  Python's word set, so Go can only *miss* a boundary Python sees, never
  invent one. Concrete bytes (`impact_vector({"title": …})
  ["insolvency_risk"]`): `"pool\u0345"` → Python `"high"`, Go `"low"`
  (U+0345 COMBINING GREEK YPOGEGRAMMENI folds with U+03B9, so `(?i)`
  pulls it into `\p{L}`); `"pool\u203F"` and `"pool\u2054"` (connector
  punctuation other than `_`) → Python `"high"`, Go `"low"`. All other
  probed boundary characters agree (`poolſ`, `pool\u0301`, `pool\u212A`,
  `pool\u00B2`, `pool\u00AA`, `pool_`, `pool-`, `épool`, …), and the
  410-vector differential run against the Python twin is 410/410.
- **Why:** RE2 exposes no Unicode word-boundary primitive; a hand-rolled
  boundary scan would fork the `pool` alternation from the other four
  and from the three other modules using the same convention.
- **Golden:** not exercised — the golden corpus is ASCII free text, and
  nothing is normalized for this row.
- **Unblocks:** permanent (justified above); closable by a per-rune
  Python-`isalnum` boundary scan if a real campaign ever puts U+0345 /
  U+203F / U+2054 next to "pool"/"pools".

### D7 — Numeric argument typing in risk / pricing
- **What:** Python's duck-typed publics accept ints where floats are
  expected, keep the caller's int/float identity in the output, and raise
  `TypeError`/`ValueError` on non-numbers. Go has no int/float union, so
  the port narrows at the API boundary: `risk.EconomicRisk` and
  `risk.RecordEconomicImpact` take `validation.Value` (int/float identity
  preserved — differential-verified), `risk.EconomicRiskFloat` takes
  `*float64`, and `pricing.SetPrice` takes `float64`.
- **Exact divergence:** `pricing.SetPrice(c, "ETH", 0, …)` with a Python
  *int* raises `usd must be a positive number, got 0`; Go's `float64`
  parameter renders `got 0.0` (byte-identical to Python when the caller
  passes `0.0`, and the CLI's argparse always yields a float).
  `risk.BountyScore` / the `insolvency_risk` ratio return `0` instead of
  raising on a schema-invalid non-numeric field (Python `TypeError`);
  unreachable for schema-valid findings.
- **Why:** the alternative is a `validation.Value` parameter on every
  numeric entry point, which would make the CLI-facing API unusable.
- **Golden:** not exercised (both twins' CLIs pass floats).
- **Unblocks:** permanent.

### D8 — Malformed invariant registry: Python raises, Go fails safe
- **What:** `webv2.invariants.load_links` / `seed_from_model` / `coverage`
  read `links.get("invariants", {})` and then call `.items()` / index it.
  A registry whose `invariants` value is not an object (a list, a string,
  `null`) raises `AttributeError: 'list' object has no attribute 'items'`
  (or `TypeError`) out of `load_links`. `internal/invariants` instead
  treats a non-object registry as the empty registry (`regOf`,
  `internal/invariants/invariants.go`) and returns empty-registry results.
- **Exact divergence:** `invariant_links.json` containing
  `{"invariants": []}` → Python `load_links(camp)` raises `AttributeError`;
  Go `LoadLinks(camp)` returns the document unchanged. Unreachable for
  schema-valid campaign state: every writer in both twins emits an object
  (`{}` or a dict of entries), so this only fires on hand-corrupted
  registries.
- **Why:** a corrupted registry is exactly when an operator wants the rest
  of the run to keep working; crashing on a hand-edit is the wrong failure
  mode, and the fail-safe keeps the guardrail's "unknown id" remediation
  (not a panic) in charge.
- **Golden:** not exercised — the golden corpus only writes registries the
  twins themselves produced.
- **Unblocks:** permanent (deliberate fail-safe; revisit if Python adopts
  the same guard).

### D9 — `baselines` problem text embeds the parser's wording (t15)
- **What:** when a baseline's JSON is unreadable, the audit reports
  `baseline '<name>': unreadable (<decoder message>)` (and
  `baseline manifest unreadable (manifest.json): <decoder message>`).
  The ported prefix is byte-identical; the embedded `<decoder message>`
  is the host parser's: CPython `json` says `Expecting property name
  enclosed in double quotes: line 1 column 2 (char 1)`, Go
  `encoding/json` says `invalid character 'b' looking for beginning of
  object key string`.
- **Why:** same shape as D5 — the contract for corrupted input is a
  verdict, not a panic, and the diagnostic wording is not part of the
  state contract. Everything else about the row (checked count, `ok`,
  the prefix) is compared byte-for-byte by
  `TestBaselinesUnreadableJSONTextIsHostSpecific`.
- **Golden:** not exercised — the golden corpus writes only
  well-formed baselines.
- **Unblocks:** none planned (surface-level diagnostic).

### D10 — P1 audit seams: relations / probe_surface / forkdiff (t15)
- **What:** `relations` and `probe_surface` are P3 modules (not ported)
  and the forkdiff T0 fingerprint parser is a separate port, so the
  three audit sections reach them through seams
  (`sections.SetRelations`, `sections.SetProbeSurfaceAudit`,
  `sections.SetForkdiff`) whose defaults are "absent":
  `relations` → `{"checked":0,"problems":[],"ok":true}`; `probe_surface`
  → the exact no-artifact dict Python emits, including the note text
  ``no probe surface artifact (campaign predates or has not run `webv2
  probes`)``; forkdiff → no baselines directory.
- **Why:** rule 5 (an unported module becomes an interface seam with a
  safe "absent" default). These are not stubs over modelled data: each
  default is exactly what the Python twin reports when the artifact or
  directory is missing, and the oracle suite pins that byte-for-byte
  (`TestRelationsSeam`, `TestProbeSurfaceSeam`,
  `TestP1EmptyCampaignSectionsMatchPython`).
- **Golden:** not exercised for relations/probe_surface (the golden
  recipe creates neither artifact); baselines fixtures are exercised by
  the vector suite with fingerprints recorded from the LIVE Python
  parser, and the live driver shares one fixture with both twins.
- **Unblocks:** the P3 port wires the real implementations behind the
  same seams.

## Conventions for future rows
- One row per divergence; keep the **What / Why / Golden / Unblocks**
  shape.
- A row may be added by any phase, but a row may only be *removed* when
  the golden suite proves the bytes now match (delete the normalization,
  re-run `scripts/golden.sh` green).
- Nothing may be normalized by the golden checker without a row here.
