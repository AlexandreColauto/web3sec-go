# KNOWN_DIVERGENCES

The permanent ledger of places where the Go port is *not* byte-identical
to the Python reference, why, and what unblocks it. Every row must be
concrete: the exact bytes/field/line that differ, the reason, and the
milestone that closes it (or `permanent` with justification). The
cross-twin golden suite (`scripts/golden.sh`) normalizes exactly the
rows marked as golden-normalized — nothing else.

> **Source-of-truth change (2026-09-09).** The Python twin is **retired**
> (operator decision; `docs/gates/P4-gate.md` §9.1): the Go port is now the
> source of truth and is no longer tracked for byte-compatibility with
> Python. `scripts/golden.sh` is **Go-only** — it validates the single Go run
> (exit codes, tree + event chain, the 14-section audit surface) and no
> longer byte-diffs against the Python twin. The rows below are kept as a
> historical record of *where and why* the twins diverged; their
> golden-normalization hooks are dormant. New Go-only bug-fixes and
> intentional improvements (the 2026-09-09 full review: Tier A/B fixes and
> the C1–C13 bug-hunt sweep, `docs/feedback-triage.md`) change no golden
> bytes and therefore carry **no row here** — see
> [Go improvements over the reference](#go-improvements-over-the-reference-2026-09-09-review).

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

### D14 — `resolve-candidate --note`: reference bug — FIXED-IN-GO, 2026-09-09
- **What (was):** `resolve-candidate … --verdict same|distinct --note N`
  failed in *both* twins with the identical byte-exact error
  `finding validation failed at dedup_meta/candidate_notes:
  {'F-…': '…'} is not of type 'string'` (exit 2). The reference's
  `dedup.py` writes `dedup_meta.candidate_notes` as a dict
  `{other_finding_id: note}` while `finding.schema.json` declared
  `dedup_meta.additionalProperties: {"type": "string"}` — the reference
  validated its own write and rejected it.
- **Fix (Go only):** the reference is deprecated and will not be patched,
  so the Go twin deliberately diverges. `assets/schema/finding.schema.json`
  now declares `dedup_meta.properties.candidate_notes` as
  `{"type": "object", "additionalProperties": {"type": "string"}}`, which
  JSON-Schema precedence lets the writer's dict pass. A valid `--note`
  now records cleanly on BOTH sides.
- **Golden:** the recipe and the verify-full P1 smoke STILL omit `--note`
  (the deprecated Python twin rejects it, so a byte-diff of the `--note`
  path would go red). The fixed path is pinned instead by
  `TestResolveCandidateNoteRecordsOnBothSides`
  (`internal/cli/cmd_resolve_candidate_test.go`).
- **Status:** closed for the Go twin; the row documents the permanent
  reference divergence. See `docs/python-twin-issues.md` P2.

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
- **Unblocks:** CLOSED 2026-09-09 by T28 — `internal/sharedmem` (the P3
  shared-memory port) reads the user-global store, and
  `WEBV2_GLOBAL_MEMORY_DIR` is honoured in production
  (`internal/sharedmem/sharedmem.go:56`); the recall tiers and the
  publish/globalize verbs are wired through `cli.ensureSeams()`. The
  golden/verify-full pins of the env to an empty directory for both
  twins stay (they guard the operator's real store, not a divergence).

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
- **Unblocks:** CLOSED by T26 — `internal/envgo` (the `webv2.env` port)
  is now installed over `SetClassifyFailure` / `SetSandboxPreflight` /
  `SetDockerImageProbe` by `cli.ensureSeams()` and `cmd/webv2`'s
  `init()`. The transcription stays as the seam default and is
  byte-identical to the port (`.scratch/t26/parity.py`: 127/127
  cross-twin checks byte-exact, including `env doctor` text/`--json` and
  the `doctor` preflight section).

## P2 (maximization / chains / sequences, T21–T23)

### D18 — `ladder disprove` happy path: the negative-memory row is not written — CLOSED 2026-09-09
- **What (was):** the reference's `maximization.disprove_rung` finishes by
  calling `learning.queue_memory(kind="disproved", …)`, which writes
  `campaigns/<cid>/memory/MEM-<8>.json` **and** appends a `memory.queued`
  event to `events.jsonl`. The Go twin had no `learning` port: the
  `maximization.queueMemory` seam (`SetQueueMemory`) was a documented
  no-op, so Go recorded the rung's `status="disproved"`, its `reason` and
  the `ladder.rung_disproved` event, but neither the memory row nor the
  `memory.queued` event.
- **Fix (T32, 2026-09-09):** `learning.queue_memory` is ported and the
  seam is installed at CLI boot (`internal/learning`, wired from
  `ensureSeams`); the row + `memory.queued` event are written by both
  twins.
- **Golden:** golden v4 exercises the HAPPY path — `ladder-disprove-h7`
  (exit 0) queues the MEM- row, `memory --approve` promotes it and
  `publish` carries `memory_added 1` to the shared store; the memory row,
  the `memory.queued` event and every later `seq`/hash compare
  byte-for-byte. The two GUARD branches (<10-char reason, reproduced rung)
  remain in the recipe.
- **Evidence:** `scripts/golden.sh` GREEN (166 steps x 2 twins, 66 tree
  files across 2 campaigns); `internal/learning` unit tests.


### D19 — `snap --deployment/--chain`: parsed by the Go CLI, dropped — CLOSED 2026-09-09
- **What (was):** `webv2 snap <campaign> <target> --deployment d.json
  --chain c.json` attaches a deployment/chain pin in the reference
  (`snapshot.attach_deployment_pin` / `attach_chain_pin`) and prints the
  pin summary. The Go CLI parsed both flags and then called
  `PinSourceSnapshot` without them — the pin file got no
  `deployment`/`chain` member and the summary line was not printed.
- **Resolution (T32, 2026-09-09): CLOSED — the divergence does not
  reproduce.** The Go CLI has attached both pins since the P0 commit
  (`internal/cli/cmd_snap.go`: `attachDeployment`/`attachChain` →
  `snapshot.AttachDeploymentPin`/`snapshot.AttachChainPin`, then the two
  summary lines), so the "parsed and dropped" description above was
  stale. T32 proved the behavior end-to-end (probe), added the missing
  CLI-level test and a golden campaign, and closed the row. No
  production code change was needed.
- **Evidence:**
  - cross-twin probe `.scratch/t32/d19_probe.py`: 6 `snap` invocations
    (plain, `--deployment`, `--chain`, both, twice) through the Python
    reference and the Go binary under pinned `WEBV2_NOW`/`WEBV2_UUID` —
    every stdout/stderr/exit and the full campaign tree
    (`snapshot.json` incl. both manifest roots + `events.jsonl`) is
    byte-identical after `<ROOT>`/`<TGT>` normalization. Sample pin:
    `deployment_merkle_root=706dc6aa…`, `chain_fingerprint=c5a6e5bf…`.
  - `internal/cli/cmd_snap_test.go` (new): pins the on-disk
    `deployment`/`chain` members, the 64-hex manifest roots, the active
    snapshot id, the event order and the two summary lines; plus the
    missing-file refusal.
  - library halves already pinned 1:1 by
    `tests/test_snapshot.py::test_deployment_and_chain_pins` →
    `internal/snapshot/compat_test.go::TestAttachDeploymentAndChainPins`
    and `tests/test_design_upgrades.py::test_manifest_refreshes_when_pins_attach`
    → `internal/snapshot/manifest_test.go::TestManifestAttachRefreshesRoots`.
- **Surface (was):** `snapshot.json`, and every P2 consumer of
  `sequencepoc.SnapshotHasForkTarget` — a campaign could not become
  "fork-pinned" through the Go CLI, so `sequence_coverage` rows were
  vacuous (`required=0`) in both twins.
- **Golden:** golden v4 adds a SECOND campaign whose only steps are
  `init` → `snap --deployment scripts/golden/deployment.json --chain
  scripts/golden/chain.json` → `status` / `audit` / `verify`, and
  check-golden.py now byte-diffs EVERY campaign tree (66 files across 2
  campaigns), so `snapshot.json` (both manifest roots + the pin members),
  `events.jsonl` (both `snapshot.*_attached` events) and the two summary
  lines are pinned. It is kept last on purpose: a fork-pinned snapshot
  changes the plan's reachability lines and the `sequence_coverage`
  verdict, which would rewrite campaign 1's already-compared P1/P2
  outputs.

## P3 (env / costs / history-mining, T26)

### D23 — bare `webv2 env` prints the wrong help in the reference — CLOSED 2026-09-09 (fixed papercut)
- **What:** `build_parser()` gives the `env` parser a
  `set_defaults(func=lambda a: (s.print_help() ...))` closure whose `s`
  is late-bound; by the time the lambda runs `s` has been rebound to the
  LAST subparser built (today `sft`). The reference therefore prints the
  `sft` usage block (exit 0) for bare `webv2 env`; the Go twin prints the
  `env` usage block.
- **Decision:** the stated unblocker (porting `sft`) landed and the row
  stayed open "awaiting a decision". Decision taken 2026-09-09 with the
  reference deprecated: the Go behavior is the CORRECT one — a bare
  `webv2 env` must print the `env` usage block. The reference bug is
  permanent (the Python twin is no longer maintained), so this row
  documents a fixed papercut, not a live divergence to close.
- **Golden:** no recipe runs bare `webv2 env`; `env doctor` (both
  surfaces) and `env <bad-action>` compare byte-for-byte.
- **Status:** closed. See `docs/python-twin-issues.md` P4.

## P3 (knowledge & memory: structural index / forkdiff, T25)

### D24 — `baselines` hangs off the binary's cwd, not the package root
- **What:** Python's `forkdiff.REPO_ROOT` is `Path(__file__).resolve()
  .parent.parent.parent` and `BASELINES_DIR = REPO_ROOT / "baselines"`, so
  the store lives beside the *source package* (an absolute path). A Go
  binary has no source-relative root, so `forkdiff.RepoRoot` defaults to
  the ABSOLUTE working directory (`SetRepoRoot` / `SetBaselinesDir` let an
  embedder or CLI repoint it). Both are absolute, but the prefix differs
  unless the two twins run with the same cwd — which every parity harness
  in this repo does (`scripts/golden.sh` runs both with `cwd=GO_ROOT`;
  `.scratch/t25/cross_twin.py` and `argfuzz.py` run both from one temp
  cwd).
- **Why:** there is no portable way to recover "the directory the Python
  package was installed from" from a compiled binary; pinning a path
  constant would be worse (it would break every relocation). The
  *contract* — one manifest + one directory per baseline, relative
  `src/` trees, byte-identical `baseline.json` — is unaffected, and
  `baseline.json` records no path.
- **Golden:** golden v4 pins ONE scratch store for both twins
  (`WEBV2_BASELINES_DIR` → `scripts/golden/sitecustomize.py` patches
  `webv2.forkdiff.BASELINES_DIR`; `cmd/webv2/main.go` calls
  `forkdiff.SetBaselinesDir`) and resets it per twin, then runs the whole
  lifecycle: `baseline list` (empty) → `forkdiff`/`--json` (no baselines)
  → `baseline add` → `list` → `forkdiff`/`--json` (score 1.00 against
  itself) → `baseline remove` → `list` (empty). No repo is written, and
  every output compares byte-for-byte. The one diagnostic that embeds the
  destination (`baseline source X overlaps the destination Y`) is compared
  by `.scratch/t25/argfuzz.py` with both twins in one cwd.
- **Unblocks:** nothing (host fact, permanent). `WEBV2_BASELINES_DIR` is
  the operator-facing version of the "future `--baselines-dir` flag" this
  row used to ask for.

### D25 — `prompt_path` carries the embed mirror's `assets/` segment (T30)
- **What:** `webv2 run` prints `prompt_path` for the halting model
  stage. Python resolves `REPO_ROOT / <rel>` where `rel` is
  `prompts_legacy/02_protocol_model.md` and the pack sits at its repo
  root: `<pyroot>/prompts_legacy/02_protocol_model.md`. The Go repo
  keeps the pack at `assets/prompts_legacy/` (a `go:embed` directive can
  only reach files under the embedding package's own directory), so the
  twin prints `<goroot>/assets/prompts_legacy/02_protocol_model.md` —
  same relative tail after the root, one extra `assets/` segment.
- **Why:** the alternative is a repo-root copy of the prompt pack that
  would silently drift from the embedded bytes; naming a path that does
  not exist (the old relative `prompts_legacy/...` fallback) is worse
  for the operator than naming the real file.
- **Golden:** golden v4 DOES invoke `run` (exit 3, the halting model
  stage). The harness points the reference at the Go twin's byte-identical
  embed mirror (`WEBV2_PROMPTS_BASE` → `sitecustomize.py` rebases
  `webv2.adapter.resolve_prompt` + `PROMPTS_DIR`/`LEGACY_PROMPTS_DIR`), so
  both twins print and hash the SAME prompt path; the HALTED block, the
  `status` note and the run event hash compare byte-for-byte with NO
  normalization (check-golden.py normalizes only <ROOT>/<TGT>/<ENVHASH>).
  The in-process twin test (`internal/cli/cmd_run_test.go`) still pins the
  HALTED block with `prompt_path` derived from `adapter.PromptPath`.
- **Unblocks:** permanent (a `go:embed` constraint, not behavior). A
  future build step that copies the pack to the repo root could close it.

### D26 — the eval store and the DeFiHackLabs corpus are unported (P4) — CLOSED 2026-09-09
- **What (was):** `corpus-surface` reads two datasets beside the reference
  package: the eval store (`webv2.eval_store.EVAL_DIR` →
  `<pyroot>/eval/cases.json`) and the DeFiHackLabs corpus
  (`webv2.datasets.defihacklabs` `POC_ROOT` + incident explorer). The Go
  twin had neither: `corpus.SetListEvalCases` / `corpus.SetLoadPocRecords`
  stayed on their absent-store defaults in the CLI, so both stores were
  empty and `poc_missing` was 0.
- **Closed by:** T33/T34. `internal/evalstore` and
  `internal/datasets/defihacklabs` are ported, and `cmd/webv2` installs both
  seams at init (`cli.WireT33Seams()` → `SetListEvalCases` +
  `trajectory`/`metrics` case lookups; `cli.WireT34Seams()` →
  `SetLoadPocRecords` + `SetRoots`/`SetPocRoot` from `WEBV2_POC_ROOT`).
- **Evidence (2026-09-09):** with the REAL stores mounted
  (`WEBV2_EVAL_DIR=<pyroot>/eval`, `WEBV2_POC_ROOT` → a base holding
  `DeFiHackLabs/` + `explorer/{incidents,rootcause_data}.json`) both twins
  print the identical surface line — `15 classes probed, 254 PoC files with
  signal, 135 records without a resolvable PoC` — and the
  `corpus_surface.json` artifacts are byte-identical apart from
  `generated_at` (class weights match exactly: access-control w=172
  score=11.152, logic-error w=320 score=6.245, reentrancy w=60
  score=5.931, unchecked-external-call w=34 score=5.129,
  oracle-manipulation w=139 score=3.565). The reproduction script is
  `.scratch/t37/d26_check.sh`.
- **Golden:** golden v5 (T38, 2026-09-09) closes the hermeticity gap that
  golden v4 left open. `scripts/golden/p4/` commits a REAL-FORMAT fixture —
  a 30-record DeFiHackLabs slice (18 mapped bug classes + 1 unmapped, PoC
  and no-PoC mix) with 19 PoC `.sol` files, a 4-case tamper-evident eval
  store (3 dev + 1 held-out) and 20 published shared-memory rows, all
  reproduced byte-for-byte from the read-only reference by
  `python3 scripts/golden/p4/build.py --check`. The recipe now exports
  `WEBV2_EVAL_DIR` / `WEBV2_POC_ROOT` at that fixture for BOTH twins, so
  the existing P3 `corpus-surface` step runs against the REAL stores and its
  `corpus_surface.json` (class weights incl. eval-case + memory-row
  components, shape_matches carrying record_id / memory_ids / bug_class
  attribution, `poc_missing`) is compared byte-for-byte. The ABSENT pins
  are gone: a bigger corpus is now an operator choice, not a CI requirement.
- **Unblocks:** closed, and the hermetic recipe no longer needs the 2.5 GB
  corpora on every box.

### D27 — `chains` proposal ORDER is PYTHONHASHSEED-dependent (T36)
- **What:** `chainengine.FindChains` enumerates simple capability chains up
  to depth 5 and caps the result at `MAX_PROPOSALS = 500`. The Python
  reference iterates `caps_held` and `needs[cap]` as **sets**, so the order
  in which candidates enter the cap is a function of the interpreter's hash
  seed: on the 13-finding capability-sharing fixture the capped proposal
  order digests into 4 distinct values across `PYTHONHASHSEED=0..3` (fixed
  fixture). The Go twin sorts both neighbour sets, so given the same finding
  ids its cut is stable across repeated runs.
- **Why:** there is no canonical Python byte order to match. Every seed
  produces a *different* legitimate 500-set; matching one seed would make
  the Go twin reproducible only against that seed and would break on the
  next Python run. The cap SEMANTICS are what the contract promises, and
  those are identical (500 proposals, 500 distinct member sets, the same
  793-member space). This is the port's only declared `chains` deviation;
  `internal/chainengine/chainengine.go` documents it at the function.
- **Evidence (2026-09-09, `scripts/cap-analysis.py`, run live):** both
  twins cap at exactly 500 with 500 distinct member sets; Go is
  deterministic across repeated runs **over the same fixture**; Python's
  digests differ for seeds 0/1/2/3; with the cap raised Python enumerates
  **793** distinct member sets (stable — a function of the fixture graph
  alone) and BOTH capped sets are subsets of it, with 0 outside. The
  overlap between the two cuts is substantial but **a per-run value**
  (275-373/500 observed over 6 runs), because `new_finding_id` is a raw
  uuid4 in both twins and is NOT pinned by `WEBV2_UUID` — every invocation
  renames the findings, which permutes Go's sort order and Python's set
  iteration. Script exit 0 = analysis green.
- **Golden:** golden v4 never drives `chains` into the cap, so no recipe
  normalization is needed. The T36 cross-twin harness captured 15 cap steps
  and 14 are byte-identical — the exception is exactly this enumeration
  order. `scripts/cap-analysis.py` is the standing proof.
- **Unblocks:** permanent while the reference iterates sets. If the Python
  side switches to sorted iteration, the Go twin already matches and this
  row is deleted.

### D28 — the `sft` store path is cwd-relative in the Go binary (P4)
- **What:** the reference's `sft_dataset.store_path()` is
  `repo_root()/sft/examples.json`, where `repo_root()` is
  `Path(__file__).resolve().parents[2]` — the *source tree*, so `sft` reads
  and writes the committed dataset from any working directory. The Go twin's
  `sft.StorePath()` is `<process cwd>/sft/examples.json` (`sft.RepoRoot`), so
  the two twins read different stores unless both run from their repo roots.
- **Evidence (2026-09-09):** from `cwd=/tmp`,
  `PYTHONPATH=<pyroot>/src python3 -m webv2.cli sft list` prints the two
  committed examples (`SFT-0001 curated confirmed-critical …`,
  `SFT-0002 curated real-weakness-non-exploitable …`); `webv2 sft list` from
  the same cwd prints nothing (empty store). From the repo root both agree.
- **Why:** the same host fact as D24 — a compiled binary cannot recover the
  directory the source package was installed from, and pinning an absolute
  path would break every relocation. The reference's store is committed to
  git, so a wrong path silently reads an EMPTY dataset instead of failing
  loudly; the port keeps the reference's documented empty-store behavior.
- **Golden:** golden v5 (T38, 2026-09-09) now drives the `sft` verb group —
  `list` (plain / `--status` / `--partition`), `lint` on three committed
  fixture files (PASS, hard dedup refusal, rubric refusal), `split --seed
  42`, `report`, `export` (all / `--partition training`) and `backfill` —
  through both twins with `WEBV2_SFT_STORE` pointing at a PER-TWIN copy of
  the fixture store inside the run root. Because `split` rewrites the store,
  the post-split bytes are a compared tree file
  (`root/sft-store/examples.json`), so the store schema, the cluster-hash
  partitioning and the id minting are all byte-diffed.
- **Unblocks:** the `WEBV2_SFT_STORE` env seam is implemented (2026-09-09):
  `sft.StorePath()` consults it after the explicit `SetStorePath` seam and
  before the cwd default (`internal/sft/sft.go`, test
  `TestSFTStorePathEnvOverride`) — point both twins at one store with
  `WEBV2_SFT_STORE=<pyroot>/sft/examples.json` from any working directory.
  The default-path difference itself is the D24 packaging fact and stays
  documented; golden v5 closes the "no recipe drives sft" caveat.

### D29 — character-vs-byte clipping and `null`-vs-`[]` in the memory/bundle path — CLOSED 2026-09-09 (T38)
- **What (was):** golden v5's P4 fixture was the first run to put REAL
  multi-byte and v2-shaped rows through the shared-memory / proposer-bundle
  path, and it exposed three Go-vs-Python byte divergences that the
  ASCII-only v4 recipe could not reach:
  1. `roles.summarizeNonIssue` emitted `deciding_propositions: []` for a
     schema_version-2 row whose field is ABSENT; the reference passes
     `row.get(...)` through verbatim, so Python emitted `null`. Every
     campaign negative-memory row in the backfilled proposer bundle
     diverged.
  2. `roles.summarizeNonIssue` and `corpus.SharedMemoryBlock` clipped
     `pattern`/`evidence_summary` by BYTES; the reference slices CHARACTERS
     (`[:300]`/`[:200]`), so a multi-byte rune straddling the budget
     shortened the row (the P4 ingest rows' descriptions carry em/en
     dashes).
  3. `sft.backfillTrace` (`a['text'][:60]`) and `adapter.blockBuilder`
     (`text[:budget]`, `budget -= len(text)`) had the same byte/character
     mismatch; the adapter's byte budget also mis-charged the remaining
     budget.
- **Fix:** `internal/roles/context.go` passes the v2 field through
  verbatim (`validation.VArr()` only for v1) and clips by runes;
  `internal/corpus/report.go` (`clipRunes`), `internal/sft/backfill.go`
  (`clipRunes`) and `internal/adapter/adapter.go` (`add`/`truncate`) now
  count characters, matching Python's `s[:n]`.
- **Evidence:** `scripts/golden.sh` GREEN (179 steps × 2 twins, 68 tree
  files across 2 campaigns + `sft-store/`) — the `sft-backfill` capture was
  the failing step before the fix and is byte-identical after it. Unit
  tests: `internal/roles/t38_context_test.go`,
  `internal/corpus/corpus_test.go::TestSharedMemoryBlockClipsSummaryByRunes`,
  `internal/sft/sft_backfill_test.go::TestBackfillTraceClipsAssumptionTextByRunes`,
  `internal/adapter/adapter_test.go::TestBlockBuilderBudgetCountsRunes`.
- **Unblocks:** closed; ASCII-only behavior is unchanged, so no golden
  normalization was needed.

### D30 — `ladder explore` natural form: the reference bug, FIXED-IN-GO (2026-09-09)
- **What (was):** the reference binds `ladder` positionals as
  `finding, rung, axis` for every action, so the documented natural call
  `webv2 ladder C explore F-xxx capital-minimization --note "…"` bound the
  axis to the RUNG slot and failed with `unknown axis None; the axes are
  (…)`. The only working form was the undocumented dummy-rung
  `explore F-xxx R-any capital-minimization --note "…"` (python-twin-issues
  P3).
- **Fix (Go only):** `parseLadder` (`internal/cli/cmd_ladder.go`) treats a
  trailing positional as the axis when the action is `explore` and no axis
  positional follows: the natural form now works, and the legacy
  dummy-rung form is unchanged (when an axis positional follows, nothing
  moves). No usage/help text changed, so no golden normalization is needed.
- **Golden:** the recipe drives the legacy form (`explore F - <axis>`),
  which behaves identically in both twins; the natural form is pinned by
  `TestLadderExploreNaturalAxisForm`
  (`internal/cli/cmd_ladder_test.go`), including the legacy form.
- **Status:** closed for the Go twin; the row documents the permanent
  reference divergence (the Python twin is deprecated and unfixed).

## Go improvements over the reference (2026-09-09 review)

Since the Python twin is retired, these are **intentional Go improvements**
over the reference (bug-fixes and hardening), not divergences to reconcile.
None changes a golden byte (the golden fixtures do not exercise these paths,
and the golden is Go-only), so none carries a normalization row. Full detail,
file:line, and regression tests: `docs/feedback-triage.md` (Tier A/B + the
Bug-hunt sweep).

- **Tier A (A1–A10)** — `not-applicable` closes a priority; mint idempotency
  keyed on `(exec, type)`; `FOUNDRY_LINT_ON_BUILD` defaulted; adapter prompt
  repointed; `stages 19/17` counted distinct; silent empty `verify`/raw `prove`
  humanized; `env doctor` pre-runs floor checks; report-freshness is a pure
  rule (log head is `report.generated`); nested `foundry.toml` walked; `snap`
  scope fix.
- **Tier B (B1–B5)** — immunization gate gains a waiver branch; `ladder
  reopen` implemented (`ReopenLadder`); the invariant gate accepts
  `CONTRADICTED` as confirming; scope matches a contract name against the name
  *and* the path it resolves to; probe anchors validated against the index
  (`resolveAnchorToken`).
- **Bug-hunt sweep (C1–C13)** — short-hash panic guard (`trunc12`); report
  evidence-level validated for all slice sizes; empty-string `closed_ref`
  flagged; `pyEqual` compares key sets; `autoMergePair` checks both sides for
  cross-snapshot; `RunDedup` excludes all non-duplicatable states;
  `Complete` replaces rather than duplicates keys; `collectFiles` skips
  non-regular entries; `criticality` tokenizes state ids; `surfaceAxis`
  index fix; `ListCampaigns` follows symlinks; `AllExecs` avoids glob
  metacharacters; `BlankReasonMin` counts characters not bytes.
- **IMPROVEMENTS waves (2026-09-10+, `docs/IMPROVEMENTS.md`)** — new
  capabilities that did not exist in the reference: **E5** `risk.reversibility`
  (victim-perspective recoverability adds a validated_risk weight; `impact
  --reversibility`); **A1** `accepted_risks[]` policy channel + gate check13
  `accepted-risk` (recorded on the finding, blocks submission, same-pattern
  exclusion suppressed, waivable per-finding, `min_severity` caps the
  acceptance); **A2** `ackscan` in-code acknowledgement matcher
  (`finding.dedup_meta.in_code_ack`, demotes acceptance likelihood, gate
  advisory `bounty.advisories`); **A3** deterministic acceptance score
  (`risk.acceptance_score`, stored on the finding at gate time, clamped at
  0; the report's Results precision block — dual critic/evidence counts,
  false-positive ratio, top-K table, presence-gated so pre-A3 reports are
  byte-identical; `webv2 rank <campaign>`; policy
  `submission_budget {max_findings, rank_by}`); **A4** paid-exploitability
  answer (`finding.exploitability`, gate check14 `paid-exploitability`,
  `webv2 exploit` verb); **B4** disposition linter
  (Go-only — the Python twin is retired): the dismissal vocabulary
  (`internal/planner/disposition.go`: 9 phrases, case-insensitive), the
  high-risk rule (tier 0 or gap ≥ 3, missing tier reads as 0), the v2 hard
  gate in `MarkAnswered` (a dispositioned closure of a high-risk probe row
  with dismissal vocabulary needs a refutation-backed ref — an
  `EXEC-` ref with an on-disk exec record or an `INV-` ref in
  `invariant_links.json` — or `--override-dismissal
  --override-reason R`, which logs `probe.dismissal_overridden`); the
  A4 anchor rule now accepts a refutation-backed ref on probe rows
  (`closed_ref` = the refutation, `probe.anchor.ref` keeps the rendered
  anchor); v1 surfaces are the presence-gated report "Disposition review"
  section and the presence-gated brief `disposition_review` key; the
  finding-side twin is an advisory-only warning on `webv2 verdict`.
  `webv2 answered` gained `--override-dismissal` / `--override-reason`
  (usage + help strings changed — no scenario step captures them, golden
  stays byte-identical). **B1** liveness terminal (Go-only — the Python
  twin is retired): `liveness_loss` is a new capability (kind `liveness`,
  starter vocab in `internal/capabilities/capabilities.go`) and a member of
  `TERMINAL_KINDS`, so every `IsTerminal` consumer (terminal-chain search,
  relations drift diagnostics, sharedmem signatures) now treats it as a
  terminal; `FindTerminalChainsMode` adds the `includeHypothesis` node mode
  (B3's `chain --unproven` seam — default `FindTerminalChains` is
  unchanged); `MaterializeChain` prices a chain whose verified terminal
  annotation names a liveness capability: `economic_impact.kind =
  "liveness"` (new additive schema property, enum `["liveness"]`),
  blast_radius floored at `protocol-solvency` (bridge-canonical preserved),
  `priceable: false` + non-USD `ceiling` — no USD figure is defensible for a
  freeze; `TerminalReport`'s note gains a liveness sentence only when a
  liveness terminal surfaced (presence-gated); the ingest legend gained
  `economic_impact/kind: liveness` (pinned in `t14FindingLegend`). **B2**
  adversarial-game clause (Go-only — the Python twin is retired): a liveness
  finding (`internal/findings/adversarial.go`: liveness class, or
  `economic_impact.kind == "liveness"`, or a granted liveness terminal
  capability) must carry `adversarial_game` — three strings
  (`who_profits`, `profit_mechanism`, `challenge_interplay`), each ≥ 20
  **runes** — recorded by `SetAdversarialGame` (validates before writing,
  logs `finding.adversarial_game_set` with per-field char counts) and
  re-validated by the new gate check15 `adversarial-game`
  (`internal/bounty/bounty.go`), which is waivable on stage
  `adversarial-game` and whose remediation text is reachable through
  `gate explain`; the schema property is finding-level **optional** (the
  schema cannot say "required only for liveness findings", so check15
  enforces presence); the CLI verb is `webv2 adversarial-game <campaign>
  <finding> --who-profit X --mechanism Y --interplay Z`
  (`internal/cli/cmd_adversarial.go`, ord 71; three required flags,
  argparse-shaped exit 2 on a missing flag); the adapter's
  `structuredOutputs` and the planner's liveness lens hint surface the verb
  at ingest; and the report gains two presence-gated blocks — the three
  clause lines in the finding section, and a "### LIVENESS FINDINGS — who
  profits from the freeze" subsection listing every liveness finding at any
  status (`who_profits` or `UNANSWERED (gate check15)`). **B3** chain
  materialization at HYPOTHESIS (Go-only — the Python twin is retired):
  `MaterializeChainOpts(..., MaterializeOpts{Unproven: true})` opened the
  chain engine's materializer to its first non-test caller path
  (`MaterializeChain` now delegates with `Unproven: false`; the proven path's
  bytes and behavior are unchanged). `--unproven` loads members at **any**
  status, relaxes `checkPinsMode` to "every member carries a source pin"
  (mixed pins are legal — a lead may span the snapshots its members were
  filed against, and ingest's `unpinned` placeholder counts; a null pin is
  still refused), stamps `provenance: "unproven"` on the chain doc, adds
  `link_evidence` (E0–E7, the strongest level on the link's `from_finding`)
  to each `capability_links` entry, and derives the terminal from
  `FindTerminalChainsMode(..., includeHypothesis=true)` when the caller
  passes none; it logs `chain.materialized_unproven` (data: members,
  evidence_floor, provenance) and creates **no** super-finding, so nothing
  downstream can count a hypothesis-level chain as evidence-confirmed (the
  deliberate tightening: a CHAIN-status super-finding would leak the lead
  into the confirmed count and the bounty-gate re-run). The CLI verb is
  `webv2 chain <campaign> <finding> <finding> [...] [--unproven] [--note N]
  [--title T]` (`internal/cli/cmd_chain.go`, ord 72; a proven refusal on
  hypothesis members exits 2 with the `--unproven` hint); `chains` appends a
  provenance marker to a materialized row and splits its headline count
  (`materialized chains: N (M unproven — hypothesis-level leads, not
  evidence)`) only when an unproven chain exists, `terminals` appends the same
  marker to a row only when the doc says `unproven`; the report gains a presence-gated "## Unproven chains
  (hypothesis-level)" section (its own UNPROVEN CHAIN heading, per-link
  evidence levels, and the derived terminal carrying an explicit "no price is
  asserted" note — an unproven chain has no super-finding, hence no
  `economic_impact`), the `- chains materialized: **N**` summary line counts
  **proven** chains only, and a presence-gated `- unproven chains
  (hypothesis-level): N — leads only, never counted as confirmed` line sits
  beside it; the adapter's `structuredOutputs` gains the `chain` key. Golden
  stays green
  without normalization: no golden campaign declares a liveness finding or
  the clause, so every change is presence-gated behind a capability or field
  no existing finding carries. Intentional oracle updates that
  accompanied these: the `gates` scenario `bounty_gate_all` oracle in
  `internal/orchestrator/testdata/oracles.json` gained the 14th
  `accepted-risk`, the 15th `paid-exploitability` and the 16th
  `adversarial-game` check rows, and its
  `calibrate_all` oracle's risk objects gained the `acceptance_score` key
  (A3 — the gate stores the score before calibrate runs; regenerated from
  the Go replay — the unit oracles pin Go behavior; the retired Python
  twin is not re-run), the planner lens text changed (hence the pinned plan
  sha256s and the scenario/probe lens strings in
  `internal/planner/testdata/*.json`), and the bounty unit goldens in
  `internal/bounty/bounty_test.go` (16-row `policy_checks`, 21 gate
  vectors, catalog + unknown-check lists). `scripts/golden.sh` stays green
  without normalization — its recipe policy carries no `accepted_risks` and
  its gate steps predate any CONFIRMED finding.
  **B3** adds no oracle updates for
  the same reason: no golden fixture calls `chain --unproven` (the flag is
  new, `MaterializeChain` remains the default path), the `chain.schema.json`
  additions (`provenance`, `link_evidence`) are optional additive properties,
  and the new `chain` verb's `--help` text — like B2's `adversarial-game`
  help, added in the same wave — is not captured by any scenario step.
  **C1** (the enforcement-timing stage table) adds no oracle updates either,
  and for a sharper reason: its probe-surface half is opt-in. `ProbeOpts`
  (`internal/probes/surface.go`) defaults to the reference behaviour, so
  `BuildSurface` — the entry point every parity test and golden call site uses
  — still reproduces the retired module's surface byte-for-byte, while
  `RunProbes` and `audit.go`'s surface re-derivation pass `ProdProbeOpts()`
  and attach `stages_unguarded`/`stages_unguarded_total` to
  assertion-strength rows that have an uncovered write. The new keys are
  optional properties in `assets/schema/probe_surface.schema.json` (plus a
  shared `definitions.stage_site`), so a reference-shaped surface still
  validates. `scripts/golden.sh` stays green unnormalized: the golden
  campaign's probe surface carries **0** assertion-strength rows (its 4 rows
  come from `custody-primitive`, `sequential-cursor`,
  `short-circuitable-guard` and `trust-assumption`), and the stage keys are
  absent from any row they do not apply to. The row shape hash also cannot
  see them — `RowShapeSha` covers anchors, classes, siblings and the stranded
  set only — so `audit`'s re-derivation comparison is unaffected by a surface
  that carries the enrichment. The Go-only verb `webv2 enforce` (ord 73,
  `internal/cli/cmd_enforce.go`) has no reference counterpart, so no reference
  behavior is claimed for it; its `--help` text, like the other new verbs', is
  not captured by any scenario step.
  **C0** (storage-list fidelity) is a divergence the Go build *adds* rather
  than removes, and deliberately so. The parser's `writes_storage` — ported
  from the reference's `stateWriteRe` regex verbatim — only records a write
  when the assignment operator follows the variable name directly, so an
  indexed or member lvalue (`balances[who] = v`, `prevStateRoot[i+1] = root`)
  never lands in the list even though the statement-level `uses` record it.
  Measured over the 18 fixture indexes: 52 of 144 statement-proven
  (state-variable, kind) pairs are missing, all of them writes. The reference
  behaves the same way, so this is a reference bug the port inherited, and the
  fix is read-side: `internal/structidx/writers.go` reconciles the list with
  the statement proofs (`WritersOf`, `ReadsWritesOf`, `EffectiveWriters`) and
  the four corpus prescreen predicates, the archetype
  `unguarded_entry_writes` check and recency's asset-writer-file scan consume
  the reconciled list. `StorageWriters` — the `storage_writers` query, no live
  callers — keeps the reference semantics so a future parity check of that
  query still matches. No index bytes move, so the index fixtures and their
  goldens are untouched, and `scripts/golden.sh` is green without
  normalization: the prescreen/recency artifacts the enriched lists feed are
  validated for well-formedness and declared exit codes, never byte-compared,
  and no step's exit code moved (verified 2026-09-10). Artifact *content* in a
  real campaign can legitimately change, because a function whose only write is
  an indexed lvalue now counts as a writer — that is the point of the fix, and
  the example above (an indexed-only `setBalance` firing the access-control
  prescreen) is pinned as a Go test. The parser-level
  fix (an optional postfix chain in `stateWriteRe`, then regenerate the index
  fixtures) would be an intentional oracle update and is left to a future item
  with its own row.
  **D2** (the pipeline's report seam) adds no oracle updates either, and the
  reason is a gap worth naming: `pipeline.SetReport` was never installed, so
  `webv2 run` failed its LAST deterministic stage with "report module not
  wired: cannot run stage 'report'" on any campaign whose model stages were
  already complete. The seam is now installed in `ensureSeams()`
  (`internal/cli/cmd_dedup.go`); `cmd_report` still calls `report.Generate`
  directly, so the report BYTES are produced by the same module either way and
  no artifact format changed. `scripts/golden.sh` cannot see the difference: the
  recipe's single `run` step halts at a model stage (`mainnet-fork-poc`) that
  comes before `report` in the DAG, so it never reaches the stage — identical
  tree (165 events, 75 files) and identical exit codes before and after. The
  new coverage lives in `cmd_run_test.go::TestRunReachesTheReportStage`, which
  seeds the upstream stages done and asserts the stage runs; the golden recipe
  is deliberately left as-is (seeding it would widen the golden surface).
  **C2** (the family primitive matrix) and **D6** (the unscoped-campaign
  notice) are likewise golden-invisible, for two different reasons. C2's
  divergence rows ride the custody-primitive axis but only when
  `ProbeOpts.Symmetry` is set, and the golden fixture has no family that mixes a
  mint/burn forward path with a transfer-out recovery path, so no new row is
  produced there; the opt-in path is pinned by parity + schema tests instead.
  D6 changes the report BYTES for a policy-less campaign, which the golden never
  is: its recipe runs `scope --policy` before the bounty gate, so the unscored
  notice is suppressed (presence-gated) and the archived tree is unchanged
  (165 events, 75 files, same exit codes). One intentional oracle update did
  land with D6: `webv2 rank` now prints the unscoped warning above its table,
  and `TestRankTable` was updated to pin those bytes — an unscoped ranking is a
  severity order, not a submission order, and saying so is the point.

**D3** (artifact supersession) carries the largest declared deviation of this
batch: `RegisterOrRefresh` no longer mints a row when the requested kind differs
from the row at the same resolved path — it MIGRATES that row's kind, refreshes
it, and prunes every other row at that path. The ported Python test
`test_different_kind_same_path_registers_new` is therefore replaced by
`TestLivingDifferentKindSamePathMigratesRow` (same file, renamed and re-asserted:
one row, kind rewritten, hash current). The reason is not preference: the
reference behaviour made `report.md` accumulate a row per regeneration
(`artifact-register` defaults to kind `other`; `report.generate` registers kind
`report`), only the newest row was ever re-hashed, and the audit's
re-hash-every-row check could never be cleared — refreshing or pruning instead
logged events, which the report-freshness proof reads as "something happened
after report.generated". One row per path, re-hashed at refresh, is the state
that satisfies both checks at once. Ghosts are pruned (with the retired id, kind
and path in the `artifact.pruned` event) rather than copied to
`artifacts/superseded/`: every ghost resolves to the same file as its
replacement, so a copy would be an unverifiable duplicate. Two new verbs landed
with it: `artifact-reconcile` (Go-only, the rewrite escape hatch) and
`dedup-signature` (Go-only). **D4** adds no bytes to the dedup report — the
tier-2 pass now flags code-protected same-root-cause pairs on both sides
(`finding.possible_duplicate` events), which is new Go-only behaviour on the
reference's own lineage rule, and the model-facing `structured_outputs.
dedup_signatures` string now names the callable CLI verb instead of the Python
function names the adapter never dispatched.

**D1** (the "All findings" table) and **D5** (`memory --reflect` /
`memory --reject`) are Go-only additions with no reference counterpart, because
the reference had neither path. D1 changes `report.md` bytes for every campaign
that has findings — the golden's checker pins exits, tree shape and the audit
summary, not report bytes, and no test byte-compares a whole report, so nothing
in the reference contract moves; the table is the operator's inventory and its
gate is "there are findings", deliberately ungated on policy. D5 extends the
`memory` verb's usage and help text past `cli.py cmd_memory` (the Python twin was
retired, so there is no byte-parity obligation left to break, but the divergence
is recorded here as the docs claimed verbatim parity) and adds two behaviours the
reference has no equivalent of: a reflection entry written to `learnings.jsonl`,
and a rejection whose REASON lives in the `memory.rejected` event rather than the
row — the memory schema is `additionalProperties:false` and has no reason field,
and a rejected row is refused outright once it is `human-approved`/`promoted`.

## Conventions for future rows
- One row per divergence; keep the **What / Why / Golden / Unblocks**
  shape.
- A row may be added by any phase, but a row may only be *removed* when
  the golden suite proves the bytes now match (delete the normalization,
  re-run `scripts/golden.sh` green).
- Nothing may be normalized by the golden checker without a row here.
