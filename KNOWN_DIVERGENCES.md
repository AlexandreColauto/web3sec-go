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

### D2 — Audit section set: 13 (Go) vs 14 (Python) — CLOSED 2026-09-09
- **What (was):** `audit` reported thirteen sections while the Python
  reference reported fourteen; the missing one was `sequence_coverage`
  (Python's section 12), reserved for P2.
- **Closed by:** `internal/audit` now registers all fourteen sections in
  the reference's `audit.py` order — `event_log`, `artifacts`, `execs`,
  `findings`, `projection`, `snapshots`, `relations`, `floor_policy`,
  `stage_completions`, `baselines`, `invariant_verification`,
  `sequence_coverage`, `probe_surface`, `unpriceable`.
- **Golden:** `scripts/check-golden.py` carries `PY_ONLY_SECTIONS = set()`
  (kept as an empty set so a re-introduction is a hard failure, not a
  silent pass); the plain `audit` summary line and every `audit --json`
  section are now compared byte-for-byte in BOTH directions. Both
  `audit-json` steps report `14 audit section(s) + ok MATCH (py-only:
  none)`.
- **Status:** closed.

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

## P1 (CLI wave, wave 3)

### D11 — Usage block lists implemented commands only
- **What:** `webv2` with no command (or an unknown one) prints the usage
  block. Python's argparse usage lists *all* 66 registered subcommands;
  the Go twin lists the 28 implemented ones (P0 7 + P1 21) in the same
  registration order, with the same two-line wrap style for long entries.
- **Why:** listing unimplemented commands would be a lie; the block is a
  menu of what the binary can do. Per-command argparse errors (missing
  required args, invalid choices, unrecognized arguments on the
  subcommand) are byte-exact to Python — only the root-level
  all-commands menu differs.
- **Golden:** not exercised (the golden recipe never triggers root
  usage).
- **Unblocks:** permanent until the final wave implements all 66; the
  block re-pads dynamically as commands register.

### D12 — Non-object ingest payload: Python's `dict(payload)` crash vs Go's schema error
- **What:** `ingest --json-file` with a JSON payload that is not an
  object (e.g. `"a"`). Python's `findings.ingest` does
  `payload = dict(payload)`, which raises
  `ingest failed: dictionary update sequence element #0 has length 1;
  2 is required` (exit 1). Go's `findings.IngestHypothesis` treats the
  non-object as an empty object and the schema validator reports the
  missing required fields (exit 1, `ingest failed: ...` with the schema
  error list).
- **Why:** the exit code and the `ingest failed:` framing match; only the
  inner wording differs, and Python's is an interpreter artifact of
  `dict()` on a string, not a designed message. No reference test
  exercises this payload.
- **Unblocks:** none planned (pathological payload; both twins reject).

### D13 — `Infinity` / `NaN` JSON literals
- **What:** CPython's `json.loads` accepts the non-standard literals
  `Infinity`, `-Infinity`, `NaN`; on a hypothesis payload the reference
  then dies with an *uncaught traceback* (exit 1). Go's
  `encoding/json` rejects the literal:
  `error: json: invalid character 'I' looking for beginning of value`
  (exit 1).
- **Why:** exit code matches; the text cannot match a traceback by
  design (D5 convention: a verdict, not a stack dump). No reference test
  exercises these literals.
- **Unblocks:** none planned (pathological payload).

### D14 — `resolve-candidate --note`: the reference bug, faithfully reproduced
- **What:** `resolve-candidate … --verdict same|distinct --note N` fails
  in *both* twins with the identical byte-exact error
  `finding validation failed at dedup_meta/candidate_notes:
  {'F-…': '…'} is not of type 'string'` (exit 2). The reference's
  `dedup.py` writes `dedup_meta.candidate_notes` as a dict
  `{other_finding_id: note}` while `finding.schema.json` declares
  `dedup_meta.additionalProperties: {"type": "string"}` — the reference
  validates its own write and rejects it.
- **Why:** PYTHON WINS includes reproducing reference bugs; "fixing" only
  the Go side would create a divergence. The golden recipe and the
  verify-full P1 smoke deliberately omit `--note` (documented in
  `scripts/golden-run.py` and `scripts/verify-full.sh` step 13).
- **Unblocks:** an upstream Python fix to the schema or the writer; then
  the `--note` path is ported back and this row is deleted.

### D15 — `WEBV2_GLOBAL_MEMORY_DIR` is honoured by the Python twin only
- **What:** the Python reference's `recall` consults the user-global
  shared-memory store (`~/.webv2/...`), overridable via
  `WEBV2_GLOBAL_MEMORY_DIR`. The Go twin's `recall` reads only the
  campaign tier — the shared/published tiers live in the unported P3
  `shared_memory` module.
- **Why:** without the P3 port the Go twin has no global store to read;
  reading an empty one would be honest but is indistinguishable from
  having none, so the seam is simply absent. The golden suite and
  verify-full pin `WEBV2_GLOBAL_MEMORY_DIR` to an empty directory for
  *both* twins so the operator's real store can never mask a divergence.
- **Unblocks:** the P3 shared-memory port wires the real store behind a
  seam and this row closes.

### D16 — Finding-id pin is a harness mechanism, not a live difference
- **What:** under the golden pins (`WEBV2_UUID` seed), the Python
  reference's `new_finding_id` still uses raw `uuid.uuid4()` (it does
  not consult the pin), while the Go twin's minter does. Left alone,
  every run would mint different `F-…` ids in the Python twin and every
  event hash would diverge.
- **Rule:** the harness reroutes *both* twins to the same derivation
  (sha256 of seed + counter, first 16 hex): Python via
  `scripts/golden/sitecustomize.py` (installed by `golden-run.py`), Go
  via the `WEBV2_FINDING_IDS=pin` switch in `cmd/webv2/main.go` (off by
  default). Outside the harness both twins mint random uuid4 ids — no
  live divergence exists.
- **Unblocks:** permanent (documenting the mechanism, like D1).

## P2 (evidence execution, T20)

### D17 — `webv2.env` is transcribed into `internal/sandbox` (T20 seam)
- **What:** `exec` and `classify` read three functions from `webv2/env.py`
  — `classify_failure`, `sandbox_preflight`, `docker_image_probe` — plus
  the `docker_daemon_ok` probe. `env.py` is P3 scope, so until it is
  ported `internal/sandbox/envseam.go` carries a faithful transcription
  as the *seam default*: `SetClassifyFailure` / `SetSandboxPreflight` /
  `SetDockerImageProbe` / `SetDockerDaemonOK` install a replacement and
  `nil` restores the transcribed default.
- **Why:** the alternative — a keyless/no-op seam — would make the two
  verbs diverge from the reference the moment an exec fails, which is
  exactly when an operator reads them. The transcription is verified
  byte-for-byte against the live Python by `.scratch/t20/parity.py`
  (45/45 cases: the four verbs, the solc-cache preflight refusal, every
  `classify` verdict, `exec --help` for all four commands).
- **Unblocks:** the P3 env port installs its own implementation over the
  seam and deletes this row; the defaults are already equivalent, so no
  behavior changes when it does.

## P2 (maximization / chains / sequences, T21–T23)

### D18 — `ladder disprove` happy path: the negative-memory row is not written
- **What:** the reference's `maximization.disprove_rung` finishes by
  calling `learning.queue_memory(kind="disproved", …)`, which writes
  `campaigns/<cid>/memory/MEM-<8>.json` **and** appends a `memory.queued`
  event to `events.jsonl`. The Go twin has no `learning` port: the
  `maximization.queueMemory` seam (`SetQueueMemory`) is a documented
  no-op, so Go records the rung's `status="disproved"`, its `reason` and
  the `ladder.rung_disproved` event, but neither the memory row nor the
  `memory.queued` event.
- **Why:** `learning.py` is P3 scope (memory lifecycle, promotion,
  rejection classes, deciding propositions). Stubbing it would write a
  schema-invalid or half-populated row; skipping the *event* while writing
  the row is impossible without forking the hash-chained log.
- **Golden:** `ladder disprove` is exercised on its two GUARD branches
  only — a <10-character reason and a reproduced rung — which abort before
  any write and therefore compare byte-for-byte (both exit 2, both print
  the reference text). The happy path is deliberately NOT in the recipe:
  one extra `memory.queued` event would shift every later `seq` and hash
  in `events.jsonl`, so it cannot be normalized away. The verb's happy
  path is covered by `internal/maximization` unit tests with the seam
  installed.
- **Unblocks:** the P3 `learning.queue_memory` port installs a real
  writer behind `SetQueueMemory`; the golden then gains a
  `ladder-disprove` step and this row closes.

### D19 — `snap --deployment/--chain`: parsed by the Go CLI, dropped
- **What:** `webv2 snap <campaign> <target> --deployment d.json
  --chain c.json` attaches a deployment/chain pin in the reference
  (`snapshot.attach_deployment_pin` / `attach_chain_pin`) and prints the
  pin summary. The Go CLI parses both flags (so they are not rejected)
  and then calls `PinSourceSnapshot` without them — the pin file gets no
  `deployment`/`chain` member and the summary line is not printed.
- **Why:** the CLI wiring was deferred with the rest of the P1 `snap`
  flags; the library functions themselves ARE ported and tested
  (`internal/snapshot/compat.go`, `TestAttachDeploymentAndChainPins`).
- **Surface:** `snapshot.json`, and every P2 consumer of
  `sequencepoc.SnapshotHasForkTarget` — a campaign cannot become
  "fork-pinned" through the Go CLI, so `sequence_coverage` rows are
  vacuous (`required=0`) in both twins. The docker e2e therefore compares
  the `sequence_coverage` section and asserts the *vacuous* verdict
  (`required=0, covered=0`) in both twins.
- **Golden:** no `--deployment`/`--chain` in the recipe (it would make
  `snapshot.json` py-only-membered); the flag shape is covered by the
  Python-side CLI tests, which the testmap marks deferred.
- **Unblocks:** wiring the two flags into `runSnap` (≈20 lines, mirroring
  `cmd_snap`'s tail); the docker e2e then gains a chain pin and the
  coverage check flips to `required>=1, covered>=1`.

## Conventions for future rows
- One row per divergence; keep the **What / Why / Golden / Unblocks**
  shape.
- A row may be added by any phase, but a row may only be *removed* when
  the golden suite proves the bytes now match (delete the normalization,
  re-run `scripts/golden.sh` green).
- Nothing may be normalized by the golden checker without a row here.
