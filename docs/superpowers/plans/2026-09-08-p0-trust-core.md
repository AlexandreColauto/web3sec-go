# P0 — Trust Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Go trust-core foundation of webv2 — `internal/validation`, `internal/state`, `internal/snapshot`, `internal/audit`, and the P0 CLI (`init/status/log/snap/audit/verify`) — byte-exact with the Python `webv2` reference, verified by a differential fuzz oracle, a Go-native hardening suite, and a cross-twin golden suite against the Python implementation.

**Architecture:** Approach A — phase-serial, module-level TDD. Each task writes the ported invariant tests first as Go table tests, then implements the minimal Go package until green. The P0 gate (design §7) is reached when a Python-written campaign audits clean from Go, `events.jsonl` is byte-identical for the scripted op-sequence, `verify` fast is green, the golden suite v1 passes, and `testmap.json` accounts for every Python trust-core test function.

**Tech Stack:** Go 1.26, stdlib-only CLI dispatch + UUID (`crypto/rand`), `santhosh-tekuri/jsonschema/v6` (draft-07 validation), `pelletier/go-toml/v2` (foundry.toml), `testing.B` benchmarks. No other dependencies at P0.

---

## Global Constraints

Copied from design §4–§8 and `web3sec-final/docs/GO_REWRITE_SPEC.md`. Every task inherits these.

- **Python wins:** Where the spec and the Go port disagree on behavior, the Python code in `web3sec-final/src/webv2/` wins. Port the behavior; do not "improve" it.
- **Repo:** `web3sec-go/` is the git repo (already initialized, `main` branch). Go module path is **`websec`**. Binary name stays **`webv2`**.
- **Layout:** `cmd/webv2/main.go`; `internal/<one-package-per-Python-module>/`; `assets/` for `go:embed`. One Python module may map to a small package directory (splitting a 561-line module into focused files is fine and preferred; see repo layout).
- **Assets:** `schema/` (27 draft-07 schemas) copied into `assets/schema/` and embedded. `scripts/sync-assets.sh` syncs from `web3sec-final`; every gate asserts embedded == source.
- **Dependencies (P0): exactly two** — `santhosh-tekuri/jsonschema/v6` and `pelletier/go-toml/v2`. No dependency outside the design table without a design addendum. No unused deps at any gate.
- **CLI:** stdlib subcommand dispatcher (no cobra). `--root` global flag defaults to `.`. Exit codes: 0 ok · 1 check/prove/audit/gate failure · 2 usage/validation/failed stage · 3 needs-model.
- **Error message text is part of the contract** — ported verbatim, including remediation snippets. `KNOWN_DIVERGENCES.md` at the repo root from day one (create it in the first commit; every conscious divergence recorded there).
- **Canonical JSON:** byte-exact CPython escaping (see Task 1). Two flavors: spaced (event/context/row hashes) and compact (snapshot manifests, spec_hash, fingerprint). Recursive key sort by byte order; floats via `strconv.FormatFloat('g',-1,64)`; NaN/Inf handled exactly as CPython (Task 1).
- **pythonRound:** round-half-to-even (banker's rounding); every `round(x,n)` call site audited, ties-possible sites use the helper, ties-impossible sites carry a comment proving impossibility.
- **Time & ids:** `nowIso()` = UTC, 6-digit microsecond fraction, `+00:00` (never `Z`); nanoseconds truncated. `newId(prefix, n=12)` via `crypto/rand`. Clock injected via `Clock` interface; `WEBV2_TEST_CLOCK` honored **only** in `testclock`-tagged builds (production build refuses it at startup).
- **Atomic IO:** same-directory tmp + rename, `mkdir -p` parents. `events.jsonl` and `costs.jsonl` written ASCII; all other JSONL and pretty JSON raw UTF-8.
- **Test discipline:** ported tests first, implementation second. A module is done only when its own ported tests pass. `testmap.json` maps every Python test function → Go table case or explicit disposition. Go-native hardening suite beyond the ported suite.
- **Hard gates (every gate):** `go vet ./...`; `go build ./...`; `go test ./...`; **`go test -race ./...`**; `scripts/golden.sh` (cross-twin byte diffs) **plus** a Go==Go self-consistency determinism run; CLI golden tables; benchmarks with regression thresholds; `testmap.json` accounting; embedded assets == source; regex-hazard grep; schema compile + KNOWN_SCHEMAS=27 test.
- **Coverage floor:** `internal/validation`, `internal/state` must hold ≥ the recorded Python-suite coverage of the same modules (measured at P0 via pytest-cov, recorded in the gate report).
- **No external CI today:** `scripts/verify-full.sh` is the mandatory local gate, written to map 1:1 onto GitHub Actions jobs.

### Repo layout (P0 result)

```
web3sec-go/
  cmd/webv2/main.go              # entrypoint; calls internal/cli
  internal/
    validation/                  # canonical JSON, schema wrapper, atomic IO, SchemaError, pythonRound
      canon.go  canon_test.go
      schema.go schema_test.go
      atomicio.go atomicio_test.go
      pyround.go pyround_test.go
      fuzz/canon_oracle_test.go  # feeds the Python differential oracle
    state/                       # Campaign, event log, chain, phases, artifacts, budget, ids
      campaign.go campaign_test.go
      eventlog.go eventlog_test.go
      chain.go chain_test.go
      phases.go id.go note.go
    snapshot/                    # ladder, pins, hashing, manifest, toolchain, compat
      hashing.go hashing_test.go  # content_hash, merkle, canonical
      ladder.go ladder_test.go
      toolchain.go toolchain_test.go
      pin.go pin_test.go
      manifest.go manifest_test.go
      compat.go compat_test.go
    audit/                       # section-registry
      audit.go audit_test.go
      sections/ events.go artifacts.go execs.go findings.go projection.go snapshots.go
    cli/                         # stdlib dispatch + P0 commands
      dispatch.go cli_test.go
      cmd_init.go cmd_status.go cmd_log.go cmd_snap.go cmd_audit.go cmd_verify.go
  assets/schema/*.schema.json    # 27 files, embedded
  scripts/
    sync-assets.sh
    canon-oracle.py              # canonical-JSON differential fuzz oracle
    golden.sh                    # cross-twin byte-diff runner
    verify-full.sh               # the mandatory gate
  testdata/                      # fixture trees (CampaignStore nesting, exclude sets, zoo)
  docs/gates/  docs/plans/  KNOWN_DIVERGENCES.md  testmap.json
```

**Interfaces core vocabulary** (used throughout the plan — memorize, referenced by later tasks):
- `CanonJSON.stringify(v: JsonValue, compact: bool) -> string` — canonical encoder (Task 1).
- `SchemaError : error` — typed error; `toString()` = the exact Python `SchemaError` message (Task 3/4).
- `validate(data: JsonValue, schemaName: string, maxErrors?: int) throws SchemaError` (Task 3/4).
- `nowIso() -> string`, `newId(prefix: string, n?: int) -> string`, `sha256Hex(b: []byte) -> string`, `sha256File(path) -> string`.
- `type Campaign` with the Python `Campaign` method surface (Task 5+): class `init/open`, instance `log/events/verifyLog/setPhase/halt/complete/stageStatus/setStage/registerArtifact/artifact/pruneArtifact/refreshArtifact/registerOrRefresh/pinSnapshot/activeSnapshot/budget/consumeDiscoverySlot/setCostCeiling/setDiscoveryBudget/state`; plus `listCampaigns(root)`.
- `pinSourceSnapshot(campaign, target, config?, extraExcludes?) -> snapshot dict`, `attachDeploymentPin`, `attachChainPin`, `assertSnapshotCompatible`, `reverifyRequired`, `SnapshotMismatch` (Task 10+).
- `auditCampaign(campaign) -> report dict`, `auditSummaryLine(report) -> string` (Task 13+).

---

### Task 1: Canonical JSON encoder (byte-exact CPython)

**Files:**
- Create: \`internal/validation/canon.go\`
- Test: \`internal/validation/canon_test.go\`
- Create: \`scripts/canon-oracle.py\`
- Test: \`internal/validation/fuzz/canon_oracle_test.go\`

**Interfaces:**
- Consumes: nothing.
- Produces: \`CanonJSON.stringify(v: JsonValue, compact: bool) -> string\` reproducing CPython \`json.dumps\` byte-for-byte given matching settings. Shared \`JsonValue\` tree type:

\`\`\`go
type JsonValue =
  | nil
  | { tag: "b", b: bool }
  | { tag: "i", i: int64 }
  | { tag: "f", f: f64 }
  | { tag: "s", s: string }
  | { tag: "a", a: []JsonValue }
  | { tag: "o", o: [(string, JsonValue)] }  // sorted at encode time
\`\`\`

**CPython escaping contract** (encode to these exact bytes):
Two flavors: spaced = \`json.dumps(v, sort_keys=True, ensure_ascii=True, separators=None)\` (separators \`", "\`, \`": "\`), used for event/context/row hashes. Compact = \`json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(",", ":"))\`, used for snapshot manifests, spec_hash, fingerprint. Escaping identical; only inter-token whitespace differs.

1. **Strings** quoted with \`"\`; inside: \`"\` (0x22) -> \`\\"\`; \`\\\` (0x5C) -> \`\\\\\`; \`\\b\`->\`\\\\b\`, \`\\f\`->\`\\\\f\`, \`\\n\`->\`\\\\n\`, \`\\r\`->\`\\\\r\`, \`\\t\`->\`\\\\t\`; every other code point < 0x20 -> \`\\\\u00XX\` (2 lowercase hex); every code point >= 0x7f -> \`\\\\uXXXX\` (4 lowercase hex), above U+FFFF a UTF-16 surrogate pair. **No HTML escaping** (\`<\`,\`>\`,\`&\` raw); **\`/\` raw**.
2. **Integers** decimal, no leading zero.
3. **Floats** shortest round-trip (\`strconv.FormatFloat(f,'g',-1,64)\` used as base); \`1.0\`->\`1.0\`, \`-0.0\`->\`-0.0\`, \`Infinity\`, \`-Infinity\`, \`NaN\` bare IEEE names. A float that round-trips to an integer still prints with \`.0\`; exponents (\`1e16\`->\`1e+16\`) stay as-is. The differential oracle is the final authority.

**Read the reference first:** \`web3sec-final/src/webv2/state.py\` ~69-79 (\`_event_hash\`, spaced) and \`web3sec-final/src/webv2/snapshot.py\` ~118-126 (\`_canonical\`, compact). Pretty JSON (\`validation.py\` \`indent=2, ensure_ascii=False\`) is Task 4.

- [ ] **Step 1: Write the failing table test** \`internal/validation/canon_test.go\` — rows \`(input, compact, expected)\`. Verify each expectation against CPython 3.14:

\`\`\`go
table := [][3]string{ // {json, compact, expected}
  {"{}", "false", "{}"},
  {"{}", "true", "{}"},
  {"{\\"a\\":1}", "false", "{\\"a\\": 1}"},
  {"{\\"a\\":1}", "true", "{\\"a\\":1}"},
  {"\\"<>&/\\"", "false", "\\"<>&/\\""},
  {"{\\"b\\":1,\\"a\\":2}", "true", "{\\"a\\":2,\\"b\\":1}"},
  {"[1,2,3]", "true", "[1,2,3]"},
  {"1.0", "true", "1.0"},
  {"1e16", "true", "1e+16"},
  {"-0.0", "true", "-0.0"},
  {"Infinity", "true", "Infinity"},
  {"NaN", "true", "NaN"},
  {"{\\"k\\":{\\"z\\":1,\\"a\\":[true,null,2.5]}}", "true", "{\\"k\\":{\\"a\\":[true,null,2.5],\\"z\\":1}}"},
};
\`\`\`

- [ ] **Step 2: Run to verify it fails** — \`go test ./internal/validation -run CanonJSON\` -> FAIL (canon.go absent).
- [ ] **Step 3: Implement \`canon.go\`** — \`JsonValue\` + \`CanonJSON.stringify\`; byte-order key sort; surrogate pairs; FormatFloat + integer-suffix normalization; two separator modes. Add \`// ponytail:\` notes where Go floats diverge from CPython.
- [ ] **Step 4: Run to verify it passes** — \`go test ./internal/validation\` -> PASS.
- [ ] **Step 5: Differential fuzz oracle** — \`scripts/canon-oracle.py\` reads JSON on stdin, emits CPython spaced+compact outputs; Go \`canon_oracle_test.go\` generates seeded random JSON, invokes oracle, byte-diffs. Checks in golden vectors.
- [ ] **Step 6: Commit** — \`git add internal/validation/ scripts/canon-oracle.py && git commit -m "P0: canonical JSON encoder byte-exact with CPython (Task 1)"\`

---
### Task 2: pythonRound (banker's rounding) + rounding audit

**Files:**
- Create: \`internal/validation/pyround.go\`
- Test: \`internal/validation/pyround_test.go\`

**Interfaces:**
- Consumes: nothing (pure function).
- Produces: \`pythonRound(x: f64, ndigits: int) -> f64\` — Python \`round(x, n)\` semantics (round-half-to-even). Also a tiny focused helper used only for money to allow callers to name the tie rule:
  - \`pythonRound\` for ties-possible sites.
  - ties-impossible sites carry a comment proving impossibility (no callsite left unaudited).

**Design note (risk R3):** Python's \`round()\` is banker's rounding (round-half-to-even), NOT round-half-away-from-zero. This differs from Go's \`math\` and IEEE \`round\` default. Implement mypy-style:
- \`pythonRound(x, n)\`: scale by \`10^n\`, then apply round-half-to-even on the scaled value, then unscale. Because \`n\` in webv2 is small (0..3, risk/score/similarity fractions), the double scaling error is negligible for the actual domain; add a comment. For integer precision where \`n <= 0\` and \`f64\` cannot represent the needed integer exactly, note the limitation (schema bounds that domain; recorded).

CPython reference: \`pyobject_round\` uses round-half-to-even. Verify against: \`python3 -c "print(round(2.5)); print(round(-2.5)); print(round(0.5)); print(round(1.5)); print(round(2.675, 2))"\` → \`2 -2 0 2 2.67\`.

- [ ] **Step 1: Write the failing table test** in \`internal/validation/pyround_test.go\`:

\`\`\`go
table := [][2]f64{ // {x, expected}
  {2.5, 2},    {-2.5, -2},   {0.5, 0},   {1.5, 2},  {-1.5, -2},
  {2.4, 2},    {3.5, 4},     {4.5, 4},   {0.05, 0.0}, {-0.05, -0.0},
};
// borderline: pythonRound(2.675, 2) == 2.67  (float 2.675 is 2.6749...)
\`\`\`

- [ ] **Step 2: Run to verify it fails** — \`go test ./internal/validation -run PyRound\` -> FAIL (pyround.go absent).
- [ ] **Step 3: Implement \`pyround.go\`** — \`pythonRound(x,n)\` with round-half-to-even.
- [ ] **Step 4: Run to verify it passes** — \`go test ./internal/validation\` -> PASS.
- [ ] **Step 5: Rounding audit** — write \`docs/RoundingAudit.md\` (or a section in the P0 gate report): grep the Python tree for every \`round(\` call, classify each port-eligible site as ties-possible (needs pythonRound) or ties-impossible (comment proof). At P0 only validation/state/snapshot/audit sites matter; the rest is expanded each phase.
- [ ] **Step 6: Commit**
\`\`\`bash
git add internal/validation/pyround.go docs/RoundingAudit.md
git commit -m "P0: pythonRound round-half-to-even + callsite audit (Task 2)"
\`\`\`

---

### Task 3: Schema loader + validator wrapper (jsonschema draft-07)

**Files:**
- Create: \`internal/validation/schema.go\`
- Test: \`internal/validation/schema_test.go\`
- Create: \`internal/validation/schema_assets_test.go\` (build-time: all 27 compile, all draft-07)

**Interfaces:**
- Consumes: the 27 embedded \`assets/schema/*.schema.json\` files (synced in Task 0); \`santhosh-tekuri/jsonschema/v6\`.
- Produces: \`KNOWN_SCHEMAS: []string\` (the 27 names, order-insensitive set); \`loadSchema(name) -> compiled schema\` (throws on unknown name with the Python KeyError message); \`validate(data: JsonValue, schemaName: string, maxErrors?: int) -> void\` throwing \`SchemaError\` with the exact Python message shape; the internal-definitions wrapper builder.

**Python reference** (\`web3sec-final/src/webv2/validation.py\`, read it fully before coding):
- \`KNOWNS_SCHEMAS\` exact list (27 names).
- \`load_schema(name)\`: unknown → \`KeyError(f"unknown schema {name!r}; known: {KNOWN_SCHEMAS}")\`; missing file → \`FileNotFoundError\`; else \`json.load\`.
- \`validate(data, schema_name, max_errors=1)\`: \`validator_cls = jsonschema.validators.validator_for(schema)\`; \`validator_cls.check_schema(schema)\`; \`validator = validator_cls(schema)\`; \`errors = sorted(validator.iter_errors(data), key=abs_path)\`; if none, return. Build the error message:
  - \`where = "/".join(str(p) for p in first.absolute_path) or "<root>"\`
  - \`max_errors <= 1\`: \`"{schema} validation failed at {where}: {first.message} (+{len(errors)-1} more errors)"\`
  - \`max_errors > 1\`: header line + continuation lines \`"\n  also at {ew}: {err.message}"\` for errors 1..max_errors, plus \`"\n  (+{len(errors)-max_errors} more errors)"\` if truncated.

**OQ3 checkpoint (P0 gate item 6):** This task is the checkpoint. Build a prototype validating all 27 schemas with \`santhosh-tekuri/jsonschema/v6\` against Python \`jsonschema\` on adversarial accept/reject fixtures for the pattern-heavy schemas (\`finding\`, \`campaign_state\`, \`snapshot\`, \`sandbox_execution\`, \`dedup\`-style id patterns). Record the verdict in the P0 gate report. Any divergence unmappable into the \`SchemaError\` shape escalates to \`qri-io/jsonschema\` BEFORE P1.

- [ ] **Step 1: Write the failing test** — \`schema_test.go\`. Cases (table-driven):
  - \`loadSchema\` returns a compile for each KNOWN_SCHEMAS name.
  - unknown name → error message matches \`unknown schema 'bogus' known: (...27 names in order...)\`. Python uses \`!r\` repr → single-quoted. Verify against the exact Python message.
  - \`validate\` on a valid \`campaign_state\` (a Campaign init state) passes.
  - \`validate\` on an invalid campaign_state (e.g. \`phase: "BOGUS"\`) → SchemaError whose string equals the Python output for the same input (run the Python to capture the exact message; the \`v6\` \`first.message\` for an enum violation must match jsonschema's wording — this is the OQ3 divergence point).
  - \`validate\` with a schema-minLength violation shows \`<root>\` when the error is at root.
  - \`max_errors>1\` produces the \`also at\` continuation lines in abs-path order.
  - A valid single-event mirror (the \`events\` array item shape) validates.
- [ ] **Step 2: Run to verify it fails** — \`go test ./internal/validation -run Schema\` -> FAIL.
- [ ] **Step 3: Implement \`schema.go\`** — embed the 27 schemas (go:embed), compile once with v6, cache; wrap errors into \`SchemaError\` per the message contract, sorting by absolute path. Add the \`internalDefinitions\` wrapper builder (evidence_item over the finding schema; the 4 model_response kind defs; trajectory defs) ported from the Python usage sites when those land — at P0 implement the structural wrapper builder shell.
- [ ] **Step 4: Run to verify it passes** — \`go test ./internal/validation\` -> PASS.
- [ ] **Step 5: Build-time schema test** — \`schema_assets_test.go\`: every file in \`assets/schema/\` compiles; \`len(KNOWN_SCHEMAS)==27\`; every file \`$schema\` is draft-07 (a future draft bump is loud). Tie into the gate's "schema compile + count" check.
- [ ] **Step 6: OQ3 prototype checkpoint** — build the adversarial fixture set (accept/reject) for the pattern-heavy schemas; run both v6 (Go) and Python jsonschema; diff verdicts + error messages; record in gate report.
- [ ] **Step 7: Commit**
\`\`\`bash
git add internal/validation/
git commit -m "P0: schema loader + v6 validator wrapper, OQ3 checkpoint (Task 3)"
\`\`\`

---

### Task 4: Atomic IO (read/write JSON, tmp+rename, JSONL split policy)

**Files:**
- Create: \`internal/validation/atomicio.go\`
- Test: \`internal/validation/atomicio_test.go\`

**Interfaces:**
- Consumes: \`JsonValue\`, a JSON parser (Go stdlib \`json\` — use the native \`json\` package; verify its float formatting only for *reading* — reading must not round-trip through the canonical encoder).
- Produces: \`readJson(path) -> JsonValue\`; \`writeJson(path, data, schemaName?: string)\` — validates (when schema), mkdir parents, writes tmp + \`replace\` (atomic rename), pretty \`indent=2, ensure_ascii=False\` (raw UTF-8) with a trailing newline; \`writeJsonlAscii(path, line: string)\` / the event-log writer (ASCII-safe, Task 6); \`sha256Hex\`/\`sha256File\` helper.\`

**Python reference** (\`validation.py\` \`read_json\`/\`write_json\`):
- \`read_json(path)\`: \`json.load\` from utf-8.
- \`write_json(path, data, schema_name=None)\`: validate when schema_name set; \`mkdir(parents=True, exist_ok=True)\`; tmp = \`path.with_suffix(path.suffix+".tmp")\`; \`json.dump(data, fh, indent=2, ensure_ascii=False)\` + \`fh.write("\\n")\`; \`tmp.replace(path)\`. **Note the tmp suffix is appended to the FULL suffix** — \`foo.json\` → tmp is \`foo.json.tmp\`.

**JSONL split policy:** \`events.jsonl\` and \`costs.jsonl\` are written ASCII (the lines are \`ensure_ascii=True\`). All OTHER JSONL and all pretty JSON are raw UTF-8. This matters because a non-ASCII char in an ASCII-required file would break its framing/hash determinism.

- [ ] **Step 1: Write the failing test** — \`atomicio_test.go\`:
  - \`readJson\` round-trips a dict.
  - \`writeJson\` creates parent dirs, writes a file ending in exactly one trailing newline, with \`indent=2\` and \`ensure_ascii=False\` (a non-ASCII char stays raw UTF-8).
  - \`writeJson\` with a schema_name validation failure throws SchemaError and writes NOTHING (the file must not be left half-written).
  - \`writeJson\` tmp file is \`path+".tmp"\` and is removed/renamed correctly (no \`.tmp\` residue after success).
  - \`sha256File\` matches \`sha256sum\` on a sample.
  - Read-only: \`readJson\` of a file with a non-ASCII string returns the correct \`JsonValue\`.
- [ ] **Step 2: Run to verify it fails** — \`go test ./internal/validation -run AtomicIO\` -> FAIL.
- [ ] **Step 3: Implement \`atomicio.go\`** — the above; stdlib \`json\` parse; tmp+rename; validation hook into Task 3's \`validate\`.
- [ ] **Step 4: Run to verify it passes** — \`go test ./internal/validation\` -> PASS.
- [ ] **Step 5: Commit**
\`\`\`bash
git add internal/validation/atomicio.go
git commit -m "P0: atomic JSON IO + JSONL split policy (Task 4)"
\`\`\`

---

### Task 5: Campaign skeleton + init/open + ids/notes/list

**Files:**
- Create: \`internal/state/campaign.go\` (type + paths + init/open/state/save)
- Test: \`internal/state/campaign_test.go\`
- Create: \`internal/state/id.go\` (\`nowIso\`, \`newId\`), \`internal/state/note.go\` (\`NOTE_CAP\`, \`capNote\`)
- Test: \`internal/state/id_note_test.go\`

**Interfaces:**
- Consumes: Task 3 \`validate\`, Task 4 \`readJson\`/\`writeJson\`, \`sha256File\`.
- Produces: the \`Campaign\` type and lifecycle:
  - \`Campaign.init(root, program, opts?) -> Campaign\` (opts: \`campaignId?\`, \`budget?\`).
  - \`Campaign.open(root, campaignId) -> Campaign\` (throws when state file absent).
  - fields: \`root\`, \`campaignId\`, \`dir\`, \`statePath\`, \`findingsDir\`, \`artifactsDir\`, \`eventsPath\`, \`memoryDir\`, \`chainsDir\`, \`execsDir\`.
  - \`state() -> dict\`, private \`save(st)\`.
  - \`listCampaigns(root) -> []string\`.
  - \`nowIso() -> string\`, \`newId(prefix, n?) -> string\`, \`capNote(note) -> string\`, \`sha256Hex\`, \`sha256File\`.

**Python reference** (\`state.py\`, read fully): ctor validates \`^C-[0-9a-z]{8,16}$\` -> \`ValueError(f"malformed campaign id: {campaign_id!r}")\`; sets 8 paths. \`init\` rejects existing -> \`FileExistsError(f"campaign already exists: {c.dir}")\`; mkdirs 6 subdirs; builds initial state (campaign_id, program, created_at, updated_at, phase=SCOPE, phase_history=[], halt_reason=None, budget=DEFAULT_BUDGET|budget, snapshots=[], active_snapshot_id=None, artifacts=[], stages={}, events=[], policy_path, floor_policy=[]); \`write_json(path, state, "campaign_state")\`; log \`campaign.created\`. \`open\` throws FileNotFoundError when state missing.

**Time/ids:** \`nowIso\` = UTC + 6-digit microseconds + \`+00:00\` (never \`Z\`), nanoseconds truncated. \`newId(prefix,n=12)\` = \`prefix + "-" + uuid4().hex[:n]\`. \`capNote\`: None->""; non-str -> \`json.dumps(note, sort_keys=True, default=str)\` (on TypeError/ValueError -> \`str(note)\`); if len <= 4096 return; else \`note[:4096] + " …[truncated {len-4096} chars — full content must live in an artifact, not a stage note]"\` (space + ellipsis U+2026).

- [x] **Step 1: Write the failing tests** — \`campaign_test.go\` (port \`test_state.py\` init/layout/ids):
  - init creates 6 dirs, campaign_state.json, events.jsonl; listCampaigns == [id].
  - init duplicate id -> FileExistsError with exact message.
  - bad id -> message \`malformed campaign id: 'INVALID ID'\`.
  - open nonexistent -> FileNotFoundError.
  - nowIso matches \`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}\\+00:00$\`.
  - newId("C",10) matches \`^C-[0-9a-f]{10}$\`.
  - capNote: None->""; str 5->same; dict->sorted serialized; long->truncated \`…[truncated N chars\` suffix; exact 4096 ok.
  - sha256File == known hash.
- [x] **Step 2: Run to verify they fail** — \`go test ./internal/state -run Campaign\` -> FAIL.
- [x] **Step 3: Implement** \`campaign.go\`, \`id.go\`, \`note.go\`.
- [x] **Step 4: Run to verify pass** — \`go test ./internal/state\` -> PASS.
- [x] **Step 5: Commit**
\`\`\`bash
git add internal/state/
git commit -m "P0: Campaign skeleton init/open + ids/notes (Task 5)"
\`\`\`

---
### Task 6: Event log (log / next_seq / events) + hash-chain core

**Files:**
- Create: \`internal/state/eventlog.go\` (append path) + \`internal/state/eventlog_test.go\`
- Create: \`internal/state/chain.go\` (\`_eventHash\`, \`_legacyAnchor\`, \`GENESIS_HASH\`) + \`internal/state/chain_test.go\`

**Interfaces:**
- Consumes: Task 1 \`CanonJSON.stringify\` (spaced), Task 3 \`validate\`, Task 4 atomic IO, Task 5 \`Campaign\`, \`nowIso\`, \`sha256Hex\`.
- Produces:
  - \`GENESIS_HASH\` = 64 zeros.
  - \`eventHash(event) -> string\` — canonical sha256 over \`{seq,at,type,ref,data,prev_hash}\`, spaced flavor (NOT event_hash).
  - \`legacyAnchor(event) -> string\` = \`"legacy-seq-{seq}"\`.
  - \`Campaign.log(eventType, ref?, data?) -> event\`, \`Campaign.nextSeq() -> int\`, \`Campaign.events() -> []dict\`, private \`logLines()\`, \`lastEvent()\`.

**Python \`log\` algorithm** (\`state.py\` ~150-175, port exactly):
1. \`lines = logLines()\` (raw non-empty; single read).
2. \`prev_hash\`: none -> GENESIS_HASH; last has event_hash -> that value; else -> \`legacyAnchor(last)\`.
3. Event \`{seq: len(lines), at: nowIso(), type, ref, data: data or {}, prev_hash}\`.
4. \`event_hash = eventHash(event)\`; add.
5. Append \`CanonJSON.stringify(event, spaced) + "\\n"\` to events.jsonl in **ASCII**.
6. Mirror: \`st=state()\`; \`st["events"] = (tail 999) + [event]\`; \`save(st)\`. State tail holds **last 1000**.

**ASCII (spec §5.4):** events.jsonl lines must be ASCII-clean. Non-ASCII (U+2028 etc.) escaped on disk as \`\\u2028\` so JSONL stays one-event-per-line and hash is independent of line separators. \`test_non_ascii_payload_cannot_break_framing_or_alias\` encodes this.

- [x] **Step 1: Write the failing tests** — port \`test_state_log.py\`, \`test_state_log_chain.py\` (non-verify_log parts):
  - first event prev_hash == GENESIS_HASH; event_hash == eventHash(first).
  - 4 appends chain (each prev_hash == prior event_hash).
  - seq contiguity from 0; jsonl replay strictly increasing.
  - events() full log; state()["events"] mirrors last 1000.
  - data with \`\\u2028\` writes \`\\\\u2028\` on disk; identical payload different seq/time -> distinct hashes.
  - None ref/data -> ref:null, data:{}.
  - legacy: pre-chain first event no event_hash -> next prev_hash == "legacy-seq-0".
- [x] **Step 2: Run to verify they fail** — \`go test ./internal/state -run EventLog\` -> FAIL.
- [x] **Step 3: Implement** \`eventlog.go\` (\`log/nextSeq/events/logLines/lastEvent\`) + \`chain.go\` (eventHash/legacyAnchor). Single-writer P0 CLI; still make \`log\` re-entrant-safe under one mutex now (\`go test -race\` is a hard gate from day one).
- [x] **Step 4: Run to verify pass** — \`go test ./internal/state\` -> PASS.
- [x] **Step 5: Commit**
\`\`\`bash
git add internal/state/
git commit -m "P0: hash-chained event log append (Task 6)"
\`\`\`

---
### Task 7: verify_log (chain/seq/tail integrity check)

**Files:**
- Create: \`internal/state/verifylog.go\` + \`internal/state/verifylog_test.go\`

**Interfaces:**
- Consumes: Task 6 \`eventHash\`, \`legacyAnchor\`, \`GENESIS_HASH\`, \`Campaign.state()\`.
- Produces: \`Campaign.verifyLog() -> {events, ok, problems:[]string, chained, legacy_unchained, malformed_lines}\`.

**Python \`verify_log\` algorithm** (\`state.py\` ~120-214, port exactly — audit trust claim #1):
1. Read every log line (1-based). Empty lines skipped. JSON parse failure -> \`malformed+=1\`, problem \`"line {n}: not valid JSON ({msg}) — integrity past this point is unverifiable"\`. Non-dict -> \`"line {n}: event is not a JSON object — integrity past this point is unverifiable"\`. Successes collected.
2. If malformed > 0: return \`{events: valid+malformed counts, ok: false, problems: problems[:10], chained: 0, legacy_unchained: 0, malformed_lines: malformed}\` (chain skipped past torn line).
3. Seq contiguity: first where seq != index -> problem \`"event {i} has seq={e.seq}"\`, break. (Broken contiguity does NOT stop chain checks.)
4. Chain: \`expected_prev = GENESIS_HASH\`, \`chained=0\`. No event_hash -> \`expected_prev = legacyAnchor(e)\`, continue. Else if prev_hash != expected_prev -> \`"event {i}: prev_hash breaks the chain"\`; if \`eventHash(e) != e.event_hash\` -> \`"event {i}: event_hash does not recompute (content edited?)"\`; expected_prev = event_hash; chained+=1.
5. State tail: \`st_tail = state()["events"]\`; if non-empty and \`st_tail != events[-len(st_tail):]\` -> \`"state event tail does not match the log suffix"\`.
6. Return \`{events, ok: problems empty, problems: problems[:10], chained, legacy_unchained: events.size - chained, malformed_lines: 0}\`.

Must **never crash** on a torn log — a verdict is always produced.

- [x] **Step 1: Write the failing tests** — \`verifylog_test.go\` (port \`test_state_log_chain.py\` + \`test_state_log.py::test_verify_log_detects_*\`):
  - clean -> ok, events==1 (campaign.created), chained==1, legacy_unchained==0; after 5 more -> events==6, chained==6.
  - reordered (swap seq of first two on disk) -> not ok, "seq" problem.
  - state tail mismatch (tamper state["events"]) -> not ok, "tail" problem.
  - edit OLD event in place (state tail fixed to match) -> not ok, "event 2" + "event_hash" problem.
  - insert forged event (seq 99, hashed) -> not ok; "seq" + "prev_hash"/"event_hash" problems.
  - delete event (drop index 2, renumber) -> not ok; "prev_hash breaks the chain".
  - legacy-only log -> ok, chained==0, legacy_unchained==1; after append prev_hash=="legacy-seq-0", ok, chained==1, legacy_unchained==1.
  - **Go-native hardening:** malformed (non-JSON) middle line -> ok:false, malformed_lines==1, "not valid JSON" problem, no crash.
- [x] **Step 2: Run to verify they fail** — \`go test ./internal/state -run VerifyLog\` -> FAIL.
- [x] **Step 3: Implement** \`verifylog.go\`.
- [x] **Step 4: Run to verify pass** — \`go test ./internal/state\` + \`go test -race ./internal/state\` -> PASS.
- [x] **Step 5: Commit**
\`\`\`bash
git add internal/state/
git commit -m "P0: verify_log chain/seq/tail integrity (Task 7)"
\`\`\`

---
### Task 8: Phase machine + budget + complete

**Files:**
- Create: \`internal/state/phases.go\` (\`PHASES\`, \`DEFAULT_BUDGET\`, \`setPhase\`, \`halt\`, \`complete\`)
- Test: \`internal/state/phases_test.go\`

**Interfaces:**
- Consumes: Task 5 \`nowIso\`, \`Campaign.save\`, Task 6 \`log\`.
- Produces: \`PHASES: []string\` (19 names, exact order), \`DEFAULT_BUDGET: dict\`, instance \`setPhase(phase, reason?) -> void\`, \`halt(reason)\`, \`complete(actor, reason) -> dict\`, \`budget()\`, \`consumeDiscoverySlot()\`, \`setCostCeiling(ceil?, actor) -> dict\`, \`setDiscoveryBudget(maxFindings, actor) -> dict\`.

**Python reference** (\`state.py\` ~216-310, port exactly):
- \`set_phase\`: unknown phase -> \`ValueError(f"unknown phase {phase!r}")\`; same as current -> no-op return; else set \`st["phase"]\`, append \`{at: nowIso(), from: prev, to: phase, reason}\` to phase_history, save, log \`phase.transition ref=phase data={from: prev, reason}\`.
- \`halt(reason)\`: \`st["halt_reason"]=reason\`, save, \`set_phase("HALTED", reason)\`.
- \`complete(actor, reason)\`: trim both; empty actor -> \`ValueError("complete requires a named actor")\`; reason < 10 chars -> \`ValueError("complete requires a written reason (>= 10 chars): what was closed and why the pass is done")\`; set completed_by/completed_reason, save, log \`campaign.completed ref=campaignId data={actor, reason}\`, \`set_phase("COMPLETE", f"{actor}: {reason}")\`, return \`state()\`.
- \`budget\` returns \`state()["budget"]\`.
- \`consumeDiscoverySlot\`: budget.discovery_findings_so_far += 1, save.
- \`setCostCeiling(ceil, actor)\`: old = budget.max_total_cost_usd; budget.max_total_cost_usd = ceil; save; log \`budget.limit_set data={old, new: ceil, actor}\`; return budget.
- \`setDiscoveryBudget(maxFindings, actor)\`: bool is not an int; \`maxFindings < 1\` (incl bool) -> \`ValueError("max_discovery_findings must be a positive integer")\`; set, save, log \`budget.discovery_set data={old,new,actor}\`.

**Note:** \`setStage\` is Task 9. \`complete\`'s COMPLETE-phase story and "closure stays on log" are contract — port verbatim.

- [x] **Step 1: Write the failing tests** (port \`test_state.py::test_phase_transitions_recorded\`, \`test_budget_consumption\`):
  - init phase SCOPE; setPhase SNAPSHOT then STRUCTURAL_INDEX -> history "to" == [SNAPSHOT, STRUCTURAL_INDEX]; unknown -> ValueError.
  - setPhase same -> no-op (no extra history entry).
  - consumeDiscoverySlot increments.
  - setDiscoveryBudget(400, "op"); setDiscoveryBudget(0, "op") -> ValueError; negative -> ValueError; log records budget.discovery_set with old/new/actor.
  - setCostCeiling(100.0,"op") -> budget.max_total_cost_usd==100; setCostCeiling(None,"op") clears; log records budget.limit_set.
  - halt("x") -> halt_reason set + phase HALTED with history entry.
  - complete: empty actor -> ValueError; short reason -> ValueError; valid -> completed_by/reason set, phase COMPLETE, history entry "op: reason", campaign.completed event with data.actor.
- [x] **Step 2: Run to verify they fail** — \`go test ./internal/state -run Phases\` -> FAIL.
- [x] **Step 3: Implement** \`phases.go\`.
- [x] **Step 4: Run to verify pass** — \`go test ./internal/state\` -> PASS.
- [x] **Step 5: Commit**
\`\`\`bash
git add internal/state/phases.go
git commit -m "P0: phase machine + budget + complete (Task 8)"
\`\`\`

---
### Task 9: Stage ledger + artifacts (register/prune/refresh/register_or_refresh)

**Files:**
- Create: \`internal/state/artifacts.go\` (stages + artifacts)
- Test: \`internal/state/artifacts_test.go\`

**Interfaces:**
- Consumes: Task 5 \`nowIso\`, \`newId\`, \`capNote\`, \`sha256File\`, \`Campaign.save\`, Task 6 \`log\`.
- Produces: instance \`stageStatus(stage) -> dict\`, \`setStage(stage, status, note?, executor?) -> void\`, \`registerArtifact(kind, path, note?, snapshotId?) -> id\`, \`artifact(id) -> dict\`, \`pruneArtifact(id, reason?) -> dict\`, \`refreshArtifact(id, reason, actor?) -> dict\`, \`registerOrRefresh(kind, path, note?, snapshotId?, reason?) -> id\`, private \`resolveArtifactPath(a)\`.

**Python reference** (\`state.py\` ~276-440, port exactly):
- \`stage_status(stage)\`: \`state()["stages"].get(stage, {"status":"pending"})\`.
- \`set_stage(stage, status, note="", executor=None)\`: entry defaults \`{status:"pending", attempts:0, last_run_at:None, note:"", executor:None}\`; \`entry["status"]=status\`; \`entry["attempts"] += 1 if status in ("needs-model","done","failed") else 0\`; \`entry["last_run_at"]=nowIso()\`; \`entry["note"] = capNote(note) if note else entry["note"]\` (overwrite only when note non-empty); \`entry["executor"] = executor or entry["executor"]\`; set, save.
- \`register_artifact(kind, path, note="", snapshot_id=None)\`: path must exist else FileNotFoundError; \`artifact_id = newId("ART",8).replace("ART-", kind[:3].upper()+"-")\`; append \`{artifact_id, kind, path: resolved (relative-to-root when inside root else absolute), registered_at: nowIso(), sha256, snapshot_id, note}\`; save; log \`artifact.registered ref=id data={kind, path: str(path)}\` (log uses ORIGINAL str(path), not resolved).
- \`artifact(id)\`: find in state; miss -> \`KeyError(f"unknown artifact {id!r}")\`.
- \`prune_artifact(id, reason="")\`: find index (miss->KeyError); pop; save; log \`artifact.pruned ref=id data={kind, path, reason}\`; return record.
- \`refresh_artifact(id, reason, actor="operator")\`: find (miss->KeyError); resolve path; missing file -> \`FileNotFoundError(f"artifact file missing, cannot refresh: {p}")\`; empty reason -> \`ValueError("refresh_artifact requires a written reason")\`; old=a.sha256; a.sha256=sha256File; a.refreshed_at=nowIso(); a.refresh_reason=str(reason); a.refresh_count=int(a.refresh_count or 0)+1; save; log \`artifact.refreshed ref=id data={kind, actor, reason, old_sha256, new_sha256, refresh_count}\`.
- \`register_or_refresh(kind, path, note="", snapshot_id=None, reason="re-registered (content may have changed)")\`: resolved path; find existing artifacts with same resolved path; none -> register; found and kind set and differs -> register (new row); else refresh(latest, reason) and return its id. "latest" = max by registered_at.

- [x] **Step 1: Write the failing tests** (port \`test_state.py::test_artifact_registration_hashes_content\`, \`test_stage_ledger_attempts\` + new):
  - register -> sha256 len 64; artifact(id) returns it; path stored resolved; event logged.
  - register missing file -> FileNotFoundError.
  - setStage "done" twice -> attempts 2; note capped; executor set.
  - setStage note only set when non-empty; non-done status no attempt increment.
  - artifact unknown -> KeyError.
  - prune -> removed, event logged, returns record.
  - refresh: content changed -> new sha256, refresh_count 1, old/new in log; missing file -> FileNotFoundError; empty reason -> ValueError.
  - registerOrRefresh: same-path re-register -> refresh (single row, refresh_count 1); different path -> new row; different kind same path -> new row.
- [x] **Step 2: Run to verify they fail** — \`go test ./internal/state -run Artifacts\` -> FAIL.
- [x] **Step 3: Implement** \`artifacts.go\` (setStage/stages live here per layout).
- [x] **Step 4: Run to verify pass** — \`go test ./internal/state\` -> PASS. \`go test -race ./internal/state\` -> PASS.
- [x] **Step 5: Commit**
\`\`\`bash
git add internal/state/
git commit -m "P0: stage ledger + artifact register/prune/refresh (Task 9)"
\`\`\`

---
### Task 10: Snapshot hashing (content_hash, merkle, file leaf, canonical)

**Files:**
- Create: \`internal/snapshot/hashing.go\`
- Test: \`internal/snapshot/hashing_test.go\`

**Interfaces:**
- Consumes: Task 1 \`CanonJSON\` (compact), \`sha256Hex\`, SOURCE_EXCLUDES, \`Path\` walk.
- Produces:
  - \`SOURCE_EXCLUDES: set\` = {".git",".hg",".slps","node_modules","cache","out",".venv","__pycache__",".mantis_snapshots"}.
  - \`contentHash(root, skipRootFiles?) -> (hash, count)\` — length-prefixed, path-sorted (per \`_content_hash\`, snapshot.py ~57-95).
  - \`canonical(obj) -> string\` (compact flavor, \`_canonical\`).
  - \`merkleRoot(leaves) -> string\` (odd duplicate; empty -> sha256("")).
  - \`fileLeaf(p, root) -> bytes\` (length-prefixed rel path + content).
  - \`pinnedFiles(snapDir) -> []Path\` (SOURCE_EXCLUDES + skip root snapshot.json).
  - \`sourceMerkleRoot(snapDir) -> string\`.
  - \`lockfileLeafNames\`.

**Python reference** (\`snapshot.py\` ~57-137):
- \`_content_hash(root, skip_root_files={\\"snapshot.json\\"})\`: files = sorted over \`root.rglob("*")\` where is_file AND no part in SOURCE_EXCLUDES AND not (parent==root AND name in skip_root_files). For each: \`rel=as_posix().encode()\`; \`h.update(len(rel).to_bytes(8,"big"))\`; \`h.update(rel)\`; \`size=stat().st_size\`; \`h.update(size.to_bytes(8,"big"))\`; stream content in 1<<16 chunks (exact remaining size). Return hexdigest + count.
- \`_canonical\`: \`json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)\` = compact.
- \`_merkle_root(leaves)\`: empty -> sha256(b""); else pairwise; append last if odd; next level = sha256(left+right) digest bytes; until one; hex.
- \`_file_leaf(p, root)\`: \`rel=as_posix().encode()\`; sha256(8be len(rel) + rel + 8be len(data) + data).
- \`_pinned_files(snap_dir)\`: SOURCE_EXCLUDES on parts + skip root snapshot.json.
- \`source_merkle_root(snap_dir)\`: merkle over [fileLeaf(p) for p in pinnedFiles].

- [ ] **Step 1: Write the failing tests** (port \`test_snapshot_integrity.py::test_content_hash_is_length_prefixed_and_order_invariant\`, hashing parts):
  - contentHash small tree == known, count correct.
  - rename a->b same content -> hash changes (length-prefix), count stable.
  - new file -> new hash.
  - merkleRoot empty == sha256(""); odd duplication; known vectors vs reference impl.
  - fileLeaf length-prefixes path and data.
  - contentHash skips root snapshot.json but includes nested ones.
  - SOURCE_EXCLUDES honored at any depth.
  - canonical matches Task 1 compact.
- [ ] **Step 2: Run to verify they fail** — \`go test ./internal/snapshot -run Hashing\` -> FAIL.
- [ ] **Step 3: Implement** \`hashing.go\`.
- [ ] **Step 4: Run to verify pass** — \`go test ./internal/snapshot\` -> PASS.
- [ ] **Step 5: Commit**
\`\`\`bash
git add internal/snapshot/
git commit -m "P0: snapshot content_hash + merkle + canonical (Task 10)"
\`\`\`

---
### Task 11: Snapshot ladder detection + pin_source_snapshot

**Files:**
- Create: \`internal/snapshot/ladder.go\` (\`detectLadder\`, \`_git\`, SOURCE_EXCLUDES use) + \`ladder_test.go\`
- Create: \`internal/snapshot/pin.go\` (\`pinSourceSnapshot\`, prune helpers) + \`pin_test.go\`

**Interfaces:**
- Consumes: Task 5 \`Campaign\`, Task 10 hashing (contentHash, canonical), Task 3 \`validate\`, Task 4 \`writeJson\`, \`newId\`, \`nowIso\`.
- Produces:
  - \`detectLadder(target) -> (ladder: "git-clean"|"git-dirty"|"no-vcs", commit: ?string, dirty: ?bool)\` (per \`_detect_ladder\`, snapshot.py ~256-264).
  - \`git(path, args...) -> string\` (returns "" on any SubprocessError/FileNotFound, per \`_git\`).
  - \`pinSourceSnapshot(campaign, target, config?, extraExcludes?) -> snapshot dict\`.
  - \`SourceSpec\` shorthand used by snap command: ladder, contentHash, fileCount, excluded, root, commit.

**Python reference** (snapshot.py \`pin_source_snapshot\` ~176-260, port exactly):
- \`_detect_ladder\`: \`git rev-parse HEAD\`; if commit: \`dirty = bool(git status --porcelain)\`; return "git-dirty"/"git-clean" accordingly; else "no-vcs".
- Prune/exclude setup: \`excludes = SOURCE_EXCLUDES | BULK_SOURCE_EXCLUDES | extra\`; if \`snap_root.relative_to(target)\` succeeds, add the top part (never copy the store into itself). \`pruned_top = _excluded_names_in(target, excludes - SOURCE_EXCLUDES)\` (computed from target).
- Staging dir = \`snap_root / "staging-{nowIso sans ':'}-{pid}"\`. Clean git -> \`git worktree add --detach staging commit\` (fall back to copytree if worktree_added false). Else copytree with ignore_patterns(*excludes), symlinks=True, dirs_exist_ok=True, PLUS a post-copy physical prune (\`_prune_excludes\`) because git worktree materializes the WHOLE tree and ignore_patterns only prunes on the copytree path.
- Build the snapshot dict per schema \`snapshot.schema.json\`: snapshot_id (ladder-dependent: "src-content-"+content_hash for no-vcs and git-clean; "src-"+commit[:7]+"-content-"+content_hash for git-dirty), layers, campaign_id, source, config, manifest. Requires the exact field names/schema — read the full schema file first.
- Write snapshot.json via writeJson(snap, "snapshot"); register artifact (snapshot.json) + merkle artifact (lockfileLeaves); set active snapshot; return snap dict.

**BULK_SOURCE_EXCLUDES** = {"data","datasets","data-raw",".scratch","webv2-workspace",".pytest_cache",".mypy_cache",".ruff_cache",".tox","build","dist"}.

- [ ] **Step 1: Write the failing tests** (port \`test_snapshot.py\` non-hash parts, \`test_snapshot_integrity.py\` integrity, \`test_snap_exclude.py\`):
  - no-vcs ladder; pinned root has src/Vault.sol and snapshot.json.
  - re-pin identical -> same snapshot_id + content_hash; changed content -> different id, old dir immutable.
  - git-dirty ladder (init+commit+dirty) -> "git-dirty", content_hash 64, id form "src-<7>-content-...".
  - target containing the campaign store never nests (both branches).
  - bulk default prunes data/ -> source.excluded contains "data", file_count==2, no data dir in final.
  - tampered immutable copy -> RuntimeError "no longer matches", file NOT repaired.
  - repin identical content -> noop (same id).
  - toolchain detection test data (Task 12) not here.
- [ ] **Step 2: Run to verify they fail** — \`go test ./internal/snapshot -run Pin\` -> FAIL.
- [ ] **Step 3: Implement** \`ladder.go\` + \`pin.go\`. **git is a runtime dependency** (like Python subprocess) — probe-guard it; missing git degrades git-clean/git-dirty to no-vcs fallback exactly like Python (\`_git\` returns "" and worktree_added stays false).
- [ ] **Step 4: Run to verify pass** — \`go test ./internal/snapshot\` -> PASS.
- [ ] **Step 5: Commit** — \`git add internal/snapshot/ && git commit -m "P0: snapshot ladder + pin_source_snapshot (Task 11)"\`

---

### Task 12: Snapshot manifest, toolchain, deployment/chain pins, active snapshot + compat

**Files:**
- Create: \`internal/snapshot/manifest.go\` (buildManifest, manifestHash, lockfile) + \`manifest_test.go\`
- Create: \`internal/snapshot/toolchain.go\` (foundry.toml via go-toml) + \`toolchain_test.go\`
- Create: \`internal/snapshot/compat.go\` (activeSnapshot, assertSnapshotCompatible, reverifyRequired) + \`compat_test.go\`
- Extend: \`internal/state/campaign.go\` (pinSnapshot, activeSnapshot fields)

**Interfaces:**
- Consumes: Task 10 hashing (merkleRoot, canonical, sourceMerkleRoot, lockfileLeafNames), Task 11 detectLadder.
- Produces:
  - \`lockfileLeafNames\` = {"package-lock.json","Cargo.lock","poetry.lock","yarn.lock","pnpm-lock.yaml","Gemfile.lock","go.sum","composer.lock","npm-shrinkwrap.json"}.
  - \`moduleFingerprintLeaf(relPath, dataSha256) -> bytes\` (length-prefixed "module:meta:" + relPath + sha256 hex of data, from \`_module_leaf\`).
  - \`buildManifest(snap, target) -> manifest dict\` (per schema manifest fields + \`manifest_hash\` self-anchor).
  - \`manifestHash(manifest) -> string\`.
  - \`merkleRootOfVisibleLockfiles(snapDir) -> string\`.
  - \`snapRootFingerprint(snap) -> (sha256, canonical form)\`.
  - \`detectToolchain(staging) -> ?dict\` (foundry: {compiler, build_system:"foundry"}; else None).
  - \`pinSnapshot(campaign, snapshotId) -> void\`, \`activeSnapshot(campaign) -> ?dict\`, \`activeSnapshotIdOrNone\`.
  - \`attachDeploymentPin(campaign, snapshotId, deployment) -> snap\`.
  - \`attachChainPin(campaign, snapshotId, chain) -> snap\`.
  - \`SnapshotMismatch : error\`; \`assertSnapshotCompatible(finding, active) -> bool | raise\`; \`reverifyRequired(finding, activeSnapshotId) -> bool\`.

**Python reference** (snapshot.py ~110-176, 266-494 — read fully; many exact formulas). Key exact behaviors:
- \`attachDeploymentPin\`: reads a JSON deployment doc with network/chain_id/contracts/addresses; records contract address set (lowercased), root_addresses, and a \`deployment: {network, contract_set_root, root_addresses}\`; logs events \`snapshot.deployment_pinned\` and \`snapshot.deployment_repo_pinned\`.
- \`attachChainPin\`: \`chain: {network, chain_id, fork_block, fork_block_hash}\`; writes \`chain: {network, chain_id, fork_block, fork_block_hash, fork_block_hash<0x20>}\`; logs \`snapshot.chain_pinned\`.
- \`active_snapshot\` / \`active_snapshot_id_or_none\` read \`state()["active_snapshot_id"]\`; \`pin_snapshot\` sets it.
- \`assert_snapshot_compatible(finding, active)\`: no active -> True; \`pins = finding.snapshot_ids\`; if \`pins.source != active.snapshot_id\` and strict -> raise SnapshotMismatch with the exact message \`"finding {finding_id} was discovered against {pins.source!r} but campaign is pinned to {active.snapshot_id!r}; re-verify instead of trusting"\`; non-strict -> False; else True.
- \`reverify_required(finding, activeId)\`: \`activeId is None -> False\`; else \`pins.source != activeId\`.
- \`detectToolchain\`: foundry.toml [profile.default].sol -> {compiler (str or ",".join(list)), build_system:"foundry"}; any parse error or no profile.sol -> None (deterministic, total).

**Ponytail note:** foundry.toml parse uses \`pelletier/go-toml/v2\` (native TOML, deterministic); but Python \`tomllib\` is a TOML 1.0 parser — verify go-toml accepts the same grammar for the foundry subset. Any divergence from tomllib on the foundry files is a KNOWN_DIVERGENCES entry.

- [ ] **Step 1: Write the failing tests** (port \`test_snap_toolchain.py\` + manifest/compat portions of \`test_snapshot_integrity.py\`):
  - detectToolchain on a tree with foundry.toml sol="0.8.24" -> {compiler:"0.8.24", build_system:"foundry"}; sol list -> comma-joined; no foundry.toml -> None; bad TOML -> None (no crash).
  - CLI snap on a foundry target prints \`toolchain: foundry — solc 0.8.24\` (after Task 17 wires cli).
  - activeSnapshot None then set; pinSnapshot sets id.
  - assertSnapshotCompatible: no active -> True; matching -> True; mismatch strict -> SnapshotMismatch with exact message; mismatch non-strict -> False.
  - reverifyRequired: None active -> False; matching -> False; mismatch -> True.
  - attachDeploymentPin: builds deployment set; logs snapshot.deployment_pinned.
  - attachChainPin: writes chain record + log.
  - manifestHash self-anchors; merkleRootOfVisibleLockfiles matches a known vector.
- [ ] **Step 2: Run to verify they fail** — \`go test ./internal/snapshot -run Toolchain\` and \`-run Compat\`, \`-run Manifest\` -> FAIL.
- [ ] **Step 3: Implement** \`manifest.go\`, \`toolchain.go\`, \`compat.go\` + extend campaign pins.
- [ ] **Step 4: Run to verify pass** — full \`go test ./internal/snapshot ./internal/state\` -> PASS.
- [ ] **Step 5: Commit** — \`git add internal/snapshot/ internal/state/ && git commit -m "P0: snapshot manifest/toolchain/pins/compat (Task 12)"\`

---

### Task 13: Audit — section registry + P0 sections (1-6)

**Files:**
- Create: \`internal/audit/audit.go\` (\`auditCampaign\`, \`auditSummaryLine\`, section registry) + \`audit_test.go\`
- Create: \`internal/audit/sections/events.go\` (section 1), \`artifacts.go\` (2), \`execs.go\` (3), \`findings.go\` (4), \`projection.go\` (5), \`snapshots.go\` (6)
- Create: \`internal/state/execs.go\` (\`allExecs\`) — minimal EXEC record glob for audit section 3 (full sandbox module is a later phase; this reader only)

**Interfaces:**
- Consumes: Task 7 \`Campaign.verifyLog\`, Task 3 \`validate\`, Task 4 \`readJson\`, Task 10 \`contentHash\`, Task 12 \`sourceMerkleRoot\`/\`manifestHash\`.
- Produces:
  - \`allExecs(campaign) -> []dict\` = sorted \`exec_dir/EXEC-*/exec_record.json\` reads (mirrors \`sandbox.all_execs\`; [] if dir absent).
  - \`auditCampaign(campaign) -> report dict\` — \`{campaign_id, sections: {name: section}, ok}\`; section = \`{checked?, problems, ok, ...}\`.
  - \`auditSummaryLine(report) -> string\` = \`"audit {PASS|FAIL}: {name}={n} problem(s), ..."\`.
  - Section registry: \`registerAuditSection(name, fn(campaign) -> section)\`; \`auditCampaign\` runs all registered sections in deterministic name order; overall ok = all.

**P0 section ownership (refactor of Python audit.py sections 1-6; port message-for-message):**
1. **event_log** = \`campaign.verifyLog()\` (Task 7).
2. **artifacts**: for each \`state()["artifacts"]\`: resolve path (\`p\` absolute? else \`campaign.root / p\`); missing file -> \`"{artifact_id}: missing file {a.path}"\`; else if \`sha256\` stored then re-hash; mismatch -> \`"{artifact_id}: content hash mismatch (stored {stored[:12]}..., actual {actual[:12]}...)"\`. Section = \`{checked, problems, ok}\`.
3. **execs**: validate each \`allExecs(campaign)\` rec against "sandbox_execution" -> \`"{eid}: {SchemaError msg}"\`; for each \`(name,stored)\` in \`rec.artifact_hashes\`: file \`execs_dir/{exec_id}/{name}\`; missing -> \`"{eid}: missing output file {name}"\`; hash mismatch -> \`"{eid}: {name} hash mismatch after execution"\`. Section = \`{checked, problems, ok}\`.
4. **findings**: for each sorted \`findings_dir/F-*.json\`: \`validate(readJson(p), "finding")\` -> \`"{p.name}: {SchemaError msg}"\`. Section = \`{checked, problems, ok}\`.
5. **projection**: for each log-event kind (read audit.py section 5 fully): an event kind the projection holds that the log never recorded is flagged; reverse (log events with no state entry = legacy) NOT flagged; runs only when the log records >= 1 event of that kind. \`{checked?, problems, ok}\`.
6. **snapshots**: for each \`state()["snapshots"]\` pointing at a real pin dir: \`contentHash(snapDir)\` (excluding snapshot.json) vs recorded \`content_hash\` -> mismatch problem; and the self-describing manifest: \`sourceMerkleRoot(snapDir)\` vs manifest, \`manifestHash\` recompute (port exact messages from audit.py lines 133-181).

**Later phases** register sections 7-12 (relations, floor_policy, stage_completions, baselines, invariant_verification, sequence_coverage) by extending the registry — do NOT stub them always-pass in P0; a missing section is simply absent until its phase. Record the "audit backward-compat" note in \`KNOWN_DIVERGENCES.md\`: the P0 gate's golden campaign recipe must not depend on P1+ sections being green.

- [ ] **Step 1: Write the failing tests** — \`audit_test.go\` (port \`test_audit.py\` P0-reachable cases; P1+ rows explicitly deferred):
  - fresh campaign audit -> ok true, present sections ok.
  - tamper an artifact file on disk -> artifacts problem, ok false.
  - tamper the event log (Task 7 style) -> event_log problem, ok false.
  - malformed F-*.json -> findings problem.
  - projection drift (state tail mismatch) -> projection/event_log problem.
  - register exec record + artifact_hash, then mutate the file -> execs problem.
  - snapshot pin then mutate pinned tree -> snapshots problem.
  - auditSummaryLine exact: \`audit FAIL: artifacts=1 problem(s), ...\`.
  - registry lists exactly the six names in deterministic order.
- [ ] **Step 2: Run to verify they fail** — \`go test ./internal/audit\` -> FAIL.
- [ ] **Step 3: Implement** registry + six sections + \`state/execs.go :: allExecs\`.
- [ ] **Step 4: Run to verify pass** — \`go test ./internal/audit ./internal/state\` -> PASS; \`go test -race ./internal/audit\` -> PASS.
- [ ] **Step 5: Commit** — \`git add internal/audit/ internal/state/execs.go && git commit -m "P0: audit section registry + sections 1-6 + allExecs (Task 13)"\`

---
### Task 14: CLI — init / status / snap / log / audit / verify + --root

**Files:**
- Create: \`cmd/webv2/main.go\` (entry + dispatch) + \`internal/cli/cli.go\` (run, dispatch, help) + \`internal/cli/cli_test.go\`
- Create: \`internal/cli/cmd_init.go\`, \`cmd_status.go\`, \`cmd_snap.go\`, \`cmd_log.go\`, \`cmd_audit.go\`, \`cmd_verify.go\`

**Interfaces:**
- Consumes: Task 5 Campaign init/open, Task 6 log, Task 8 complete (COMPLETE-phase story), Task 11-12 snap/pins, Task 13 audit; Task 1 CanonJSON.
- Produces: the six P0 subcommands, each returning exit 0 or 1, printing to a captured writer (testable). Global flags: \`--root <dir>\` (campaign root) for all commands; \`--json\` where Python emits JSON.

**CLI parity — port \`cli.py\` exactly** (read cli.py fully for the P0 commands; messages/adverbs/exit codes must match):
- **init** \`webv2 init <program> [campaignId] [--budget JSON] [--root dir]\`: creates campaign, prints \`campaign {id} initialized in {root}\`. Duplicate -> the FileExistsError message + exit 1.
- **status** \`webv2 status [--root dir] [--json]\`: prints phase, campaign_id, budget, active snapshot, artifact/item counts, staged structure. \`--json\` prints canonical JSON (Task 1). EXACT keys/order from cli.py primitives (\`print_status\`).
- **snap** \`webv2 snap [--target DIR] [--name NAME] [--extra-exclude GLOB...] [--foundry-on-disk] [--deployment FILE] [--chain KEY] [--no-pin] [--root dir] [--json]\`: ladder detection, pin, manifest, toolchain line \`toolchain: foundry — solc 0.8.24\` when detected, artifact registration, active pin. Port cli.py \`snap\` flags/prints exactly.
- **log** \`webv2 log [--tail N] [--root dir] [--json]\`: prints event log lines (seq/at/type/ref), tail filter, canonical JSON when \`--json\`. Port \`print_log\`.
- **audit** \`webv2 audit [--root dir] [--json]\`: runs auditCampaign, prints auditSummaryLine to stderr, full JSON to stdout when \`--json\`; exit 1 if ok false. Port cli.py \`audit\` exactly.
- **verify** \`webv2 verify [--root dir] [--exit-code]\`: runs verifyLog, prints \`log OK: {events} events, {chained} chained, {legacy} legacy\` (EXACT cli message) or problems; exit per \`--exit-code\`.
- **help** \`webv2 help\`/no-arg: usage listing all subcommands in fixed order.

**Ponytail CLI note:** stdlib \`flag\` only (no cobra). \`--root\` is a persistent flag every subcommand parses first. All printing goes through a [bytes buffer]/\`io.Writer\` on the run struct so tests capture output without exec'ing the binary.

- [ ] **Step 1: Write the failing tests** — \`cli_test.go\` (port \`test_root_default.py\` + cli golden):
  - init then status: status output contains campaign id and SCOPE.
  - status --json parses as canonical JSON with expected fields.
  - log --tail 2 after 4 events prints last 2.
  - audit on clean campaign exit 0; auditSummaryLine on stderr.
  - init duplicate -> exit 1 + FileExistsError text.
  - bad campaignId via init -> exit 1 + malformed msg.
  - verify clean -> \`log OK: ...\` + exit 0; tampered -> exit 1 with problem lines.
  - snap on a tiny foundry target -> prints \`toolchain: foundry — solc 0.8.24\`; snap --json valid.
  - --root honored: init --root tmp, then status --root tmp reads it.
  - help lists six subcommands.
- [ ] **Step 2: Run to verify they fail** — \`go test ./internal/cli\` -> FAIL.
- [ ] **Step 3: Implement** \`cmd/webv2/main.go\` + \`internal/cli\` dispatch + six commands. Wire \`internal/snapshot\` pin path into snap cmd per Task 12. **Do not** wire P1+ flags yet.
- [ ] **Step 4: Run to verify pass** — \`go test ./...\` -> PASS; \`go test -race ./...\` -> PASS; \`go build ./cmd/webv2\` -> binary builds.
- [ ] **Step 5: Commit** — \`git add cmd/ internal/cli/ && git commit -m "P0: CLI init/status/snap/log/audit/verify + --root (Task 14)"\`

---

### Task 15: Schema assets sync (assets/schema) + embedded schemas

**Files:**
- Create: \`scripts/sync-assets.sh\` (+ \`scripts/sync-assets.sh\` executable)
- Create: \`assets/schema/\` (27 draft-07 schemas, byte-identical to \`web3sec-final/schema/\`)
- Create: \`internal/validation/schemas.go\` (embed) + \`assets_test.go\`

**Interfaces:**
- Consumes: Task 3 validator.
- Produces:
  - \`//go:embed\` of \`assets/schema\` into the binary via \`embed.FS\` (\`internal/validation/schemas.go\`).
  - \`syncAssets()\` script copies \`web3sec-final/schema/*.json\` -> \`assets/schema/\` and fails unless every file matches byte-for-byte.
  - \`schemaNames() -> []string\` sorted.

**Contract:** the 27 embedded schemas must be **byte-identical** to the Python repo's \`schema/\` directory (spec §data). \`internal/validation\` loads schemas from the embedded FS (same set/names as Task 3; Task 3 may have read from a temp dir — this task finalizes the embedded source). Nothing else in the binary reads schema files from disk at runtime.

- [ ] **Step 1: Write a failing test** — \`assets_test.go\`: embedded FS exposes all 27 schema names; each is valid JSON; \`campaign_state\`, \`snapshot\`, \`finding\`, \`sandbox_execution\` present.
- [ ] **Step 2: Run to verify it fails** — \`go test ./internal/validation -run Assets\` -> FAIL (embedded FS empty until sync).
- [ ] **Step 3: Write** \`scripts/sync-assets.sh\`: \`cp web3sec-final/schema/*.json assets/schema/\` then verify byte equality; run it.
- [ ] **Step 4: Run to verify pass** — \`go test ./internal/validation\` -> PASS; \`diff -r web3sec-final/schema assets/schema\` clean.
- [ ] **Step 5: Commit** — \`git add assets/ scripts/sync-assets.sh internal/validation/schemas.go && git commit -m "P0: sync 27 embedded schemas + sync-assets.sh (Task 15)"\`

---

### Task 16: testmap.json — function-level test accounting across Python reference

**Files:**
- Create: \`testmap.json\` (project root) + \`scripts/count-python-tests.py\` (generator)

**Interfaces:**
- Produces: \`testmap.json\` mapping every Python test function in \`web3sec-final/tests\` to its Go home.
- \`scripts/count-python-tests.py\`: walks \`web3sec-final/tests\` (+ package tests), collects every \`def test_...\` / \`async def test_...\` function name, counts by file/package, and reports the grand total.

**Purpose (spec §testmap / design §7.3):** prove no silent losses. Every Python test function (baseline ~1,052) is either mapped to a Go test (\`testmap.json\` row \`{"python_file","python_func","go_file","go_func","merged_into","notes"}\`) or explicitly merged (\`merged_into\` set, so a Go suite of far fewer functions is justified row-by-row). The P0 slice ~56 functions are mapped in this task; later phases extend the file.

**P0 coverage to map (56 funcs across 9 files):**
- \`test_state.py\` (8), \`test_state_log.py\` (4), \`test_state_log_chain.py\` (7), \`test_snapshot.py\` (10), \`test_snapshot_integrity.py\` (4), \`test_snap_exclude.py\` (7), \`test_snap_toolchain.py\` (6), \`test_audit.py\` (6), \`test_root_default.py\` (4).

**Mapping rule:** list the exact \`python_func\` name and where it lands:\n- same-name Go test in \`internal/state\`, \`internal/snapshot\`, \`internal/audit\`, or \`internal/cli\`;\n- or \`merged_into\` naming the Go test that absorbs it (aggressive merge per design §7.3), plus a \`notes\` line saying what merged and why.

- [ ] **Step 1: Generate** the Python totals — run \`scripts/count-python-tests.py\` (write it first) against \`web3sec-final\`; capture the full per-file function list for the 9 P0 files.
- [ ] **Step 2: Write \`testmap.json\`** for the P0 slice: every one of the 56 P0 funcs has a row; remaining ~996 funcs get a stub row \`{"status":"deferred-P{n}"}\` grouped by phase so the total = 1,052 and no function is ever silently dropped. (Fill real rows as each phase lands.)
- [ ] **Step 3: Validate** — \`scripts/count-python-tests.py\` totals == sum of testmap rows; a small \`scripts/check-testmap.py\` verifies no row duplicates a \`python_func\` and counts reconcile.
- [ ] **Step 4: Run to verify** — both scripts pass; \`git add testmap.json scripts/ && git commit -m "P0: testmap.json function-level accounting (Task 16)"\`

---

### Task 17: Cross-twin golden suite v1 (scripted op-seq, pinned clocks)

**Files:**
- Create: \`scripts/golden.sh\` + \`scripts/golden-run.py\` (orchestrator) + \`golden/\` fixtures
- Create: \`scripts/check-golden.py\` (byte-diff Go vs Python)

**Interfaces:**
- Produces: the cross-twin golden harness — runs the SAME scripted operation sequence through the Python \`webv2\` AND the Go \`webv2\` binary, both with pinned clocks, and byte-diffs every emitted artifact.
- Consumes: \`cmd/webv2\` binary (Task 14), Python \`src/webv2\` in the \`.venv\`, and the init / snap / log / audit / verify commands.

**What it pins (spec section golden / design 4.1, 10):**
- Monotonic fake clock: now injected via an env var the Go binary and the Python CLI both honor for \`nowIso\` (design: \`WEBV2_NOW\`; Python side wraps \`state.now\` — pin the exact mechanism in the plan before starting).
- Deterministic ids: \`WEBV2_UUID\` seed so \`newId\`/artifact ids match across impls (design: fake \`uuid4\`).
- A fixed op-sequence recipe: init, status, snap, record, audit, verify, repeat for N steps.
- Fixed source tree: tiny foundry target with \`foundry.toml\` solc 0.8.24, a couple Solidity files, and a data/ dir being pruned.

**Assertions (byte-level):**
- events.jsonl identical (same seq, same hash chain) after every step.
- campaign_state.json identical.
- snapshot.json + pinned tree identical (same snapshot_id, content_hash, manifest_hash).
- audit report JSON identical (same section names + problems + ok).
- CLI stdout/stderr identical (same messages, same exit codes) for every command.
- The canonical-JSON paths (status --json, snap --json, audit --json) identical byte-for-byte.

**Determinism trap the harness is built to catch:** any divergence (a different hash, an extra field, a reordered key, a non-ASCII line in events.jsonl) fails the diff and names the phase/step — expect the first full golden run to expose a handful; each is triaged into a Go fix or a KNOWN_DIVERGENCES.md row.

- [ ] **Step 1: Write scripts/golden-run.py** — orchestrate: build Go binary (go build -o /tmp/webv2 ./cmd/webv2), set pinned NOW/UUID for both, run the recipe against two fresh roots, emit both artifact trees.
- [ ] **Step 2: Write scripts/check-golden.py** — recursive byte-diff of the two trees; green iff identical; else report per-file diffs + which phase introduced the divergence.
- [ ] **Step 3: Run scripts/golden.sh** against the P0 command surface. Iterate: every divergence is either fixed in Go (parity bug) or documented in KNOWN_DIVERGENCES.md (true behavioral difference with rationale + a blocking milestone).
- [ ] **Step 4: Gate criterion** — the P0 golden run is fully green for the recipe covering the six P0 commands (document the recipe in docs/gates/P0-gate.md).
- [ ] **Step 5: Commit** — git add scripts/ golden/ && git commit -m "P0: cross-twin golden suite v1 (Task 17)"

---

### Task 18: verify-full.sh — one-shot local parity harness + Go==Go determinism

**Files:**
- Create: \`scripts/verify-full.sh\` (+ executable) — the single entry point the P0 gate runs.

**Interfaces:**
- Produces: a green/red verdict across the whole P0 surface with per-step output.
- Runs, in order (fail-fast with named step):
  1. \`go vet ./...\` clean.
  2. \`go build ./cmd/webv2\` -> /tmp/webv2.
  3. \`go test ./...\` PASS.
  4. \`go test -race ./...\` PASS (hard gate from day one — design 7.1).
  5. \`go test -count=1 ./...\` twice; assert identical output (Go==Go determinism run — design 7.1).
  6. \`scripts/sync-assets.sh\` then \`diff -r web3sec-final/schema assets/schema\` clean.
  7. \`python -m pytest web3sec-final/tests -q\` against the Python reference (baseline still green — must not regress while we port).
  8. \`scripts/check-testmap.py\` totals reconcile with \`scripts/count-python-tests.py\`.
  9. \`scripts/golden.sh\` green (Task 17).
  10. Crash/robustness smoke: run audit/verify against a deliberately truncated events.jsonl in a copy; gate expects a verdict, not a panic (Task 7 + hardening 7.2).
- Exits non-zero at the first failing step with its name in the message.

**Design intent:** one command a human (or CI) runs to know whether P0 is clean. Every P0 task ends green under this script before the gate is opened.

- [ ] **Step 1: Write** \`scripts/verify-full.sh\` with the ten ordered steps; make it executable.
- [ ] **Step 2: Make it green** — iterate against the P0 tasks above until it exits 0 end-to-end.
- [ ] **Step 3: Commit** — git add scripts/verify-full.sh && git commit -m "P0: verify-full.sh parity harness (Task 18)"

---

### Task 19: Dependencies, KNOWN_DIVERGENCES.md, and the P0 gate report

**Files:**
- Create: \`KNOWN_DIVERGENCES.md\` (root, first entry now; grows every phase)
- Create: \`docs/gates/P0-gate.md\` (the gate report)
- Modify: \`go.mod\` (add the P0 deps)

**Interfaces:**
- Produces the gate evidence and the permanent divergence ledger.
- Deps to add in this task (ponytail P0 pass): \`santhosh-tekuri/jsonschema/v6\`, \`pelletier/go-toml/v2\` (the only two the P0 packages import). \`dlclark/regexp2\` (P2) and \`gopkg.in/yaml.v3\` (P3) are NOT yet added — YAGNI until the phase that needs them (module path \`websec\`, binary \`webv2\`).

**KNOWN_DIVERGENCES.md — first P0 entries (port the exact wording, keep every row concrete):**
- Canonical float formatting: Go FormatFloat('g',-1,64) vs CPython repr divergence on integral floats; the .0-suffix rule and its differential oracle (Task 2).
- The audit backward-compat note (Task 13): audit section 1-6 only until P1+; the golden recipe must not depend on P1+ sections.
- Any golden suite row that could not be closed with byte parity in Task 17, with rationale and the milestone that unblocks it.

**Gate report structure (design 8):** every P0 gate checklist item (7 items, design gate section) with evidence:
1. Python campaign audits clean (step 7 of verify-full).
2. events.jsonl byte-identical (golden).
3. verify fast green (Go test under budget).
4. golden suite v1 green.
5. testmap.json function-level accounting reconciles.
6. OQ3 checkpoint: santhosh-tekuri/jsv v6 validator agrees with Python jsonschema on the 27 schemas over a corpus (a table listing schema -> verdict).
7. Python coverage floor measured (a line reading: the P0 slice of Python tests, run with coverage, must be >= the recorded floor %; the subset the Go port is accountable for).
Each item: PASS/FAIL + the command whose output is the evidence. The gate opens only when all seven PASS.

- [ ] **Step 1: Add P0 deps** to go.mod; \`go mod tidy\`; commit go.mod + go.sum.
- [ ] **Step 2: Create KNOWN_DIVERGENCES.md** with the first entries above; commit.
- [ ] **Step 3: Run verify-full.sh** and confirm it exits 0.
- [ ] **Step 4: Fill docs/gates/P0-gate.md** — run each checklist command, paste the on-disk evidence paths, mark PASS/FAIL. Commit.
- [ ] **Step 5: Commit** — git add go.mod go.sum KNOWN_DIVERGENCES.md docs/gates/P0-gate.md && git commit -m "P0: deps, KNOWN_DIVERGENCES, P0 gate report (Task 19)"

---