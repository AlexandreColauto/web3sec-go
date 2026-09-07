# Go Rewrite of webv2 — Implementation Design

> **Status:** approved design (brainstormed 2026-09-07; revised same day with the
> test-porting + Go-native hardening revision, §11).
> **Companion contract:** `web3sec-final/docs/GO_REWRITE_SPEC.md` (DRAFT v1) — the behavioral
> contract. This document decides **how** we build; the spec decides **what** must be true.
> Where prose and code disagree, the **Python code wins** (spec's own rule).
> **Skills:** brainstorming (this process) → writing-plans (per-phase plans) → ponytail
> (implementation minimalism, enforced per module).

## 1. Objective

Byte-exact port of the `webv2` deterministic control plane (52 Python modules, ~23.4k LOC)
to Go. Definition of done = spec §1.5, all four items:

1. `verify`-equivalent fast self-check passes; `--full` runs the ported suite (~1,100 tests) green.
2. Cross-golden suite: Python and Go produce byte-identical outputs (event log lines, JSON
   artifacts, report.md modulo `generated_at`, completion proofs, fingerprints, corpus reports).
3. `audit` cross-checks both directions: Python-written campaigns audit clean from Go and
   vice versa.
4. RUNBOOK.md commands run verbatim against the Go binary with documented exit codes.

Doctrine (unchanged): the framework decides, models propose. No LLM integration in the
binary. No redesign — every gate, floor, ladder, hash format, and refusal message is
load-bearing. The spec's tables are **transcribed, not re-derived**.

## 2. Delivery model (decisions recorded 2026-09-07)

- **Autonomy:** fully autonomous P0→P4. The phase gates (spec §14) are the checkpoints;
  no per-phase user pause is scheduled. A tracked session goal enforces continuation.
- **Approach A — phase-serial, module-level TDD.** Inside each phase, per module:
  (1) triage the module's Python tests, then port the **invariant tests** as Go table
  tests first (dispositions recorded in `testmap.json`); (2) implement the Go package
  until those tests are green; (3) keep `webv2 verify` (fast) green at all times;
  (4) at the phase boundary extend the cross-twin golden suite to the phase's modules
  and run it green — that is the gate.
- **Test-porting philosophy (revision 2026-09-07):** port invariants, not Python
  implementation details — and **merge aggressively**: the Go suite is expected to be
  substantially smaller than the Python suite's ~1,052 test functions; a near-1:1
  function count would be a smell, not an achievement. Before porting, triage:
  (a) **invariant test** (verifies system behavior) → a case in a Go table test;
  (b) **implementation-detail test** (pins a Python footgun: local-import cycles,
  jsonschema's particular error strings, monkeypatch quirks) → adapt to the Go
  equivalent or drop, reason recorded; (c) **similar tests** (same invariant, different
  data/setup) → merged into one table test. Accounting unit = the Python test
  function: every one lands as a Go table case or an explicit disposition
  (ported / merged-into / adapted / dropped-with-reason) in `testmap.json` — nothing
  is silently lost, and the manifest gate (§8) remains the floor. **Test count is a
  floor, not the goal**: Go-specific failure modes (races, map iteration order,
  goroutine scheduling) get their own coverage in the Go-native hardening suite (§8).
- **Ponytail discipline** on every implementation choice: YAGNI → stdlib → native platform
  → existing reliable dependency → the one-liner → minimum viable implementation.
  Readability and maintainability win over cleverness. Every deliberate shortcut carries
  `// ponytail: [upgrade path]` so the scaling path is documented at the shortcut.

## 3. Decomposition (spec §14 phases, verbatim gates)

| Phase | Contents | Exit gate |
|---|---|---|
| **P0 — trust core** | repo skeleton, canonical JSON encoder (+fuzz oracle), schema loader (27 embedded, compile test), validation, `state` (events/chain/projection/budget/artifacts/ids), `snapshot` (pins/manifest/hashing/compat), `audit`, `verify`; CLI: init/status/log/snap/audit/verify | Python-written campaign audits clean from Go; event bytes identical; `verify` fast green |
| **P1 — findings & gates** | findings (IR/transitions/gates/evidence/assumptions/memory checks), floors, taxonomy, capabilities, dedup, risk, pricing, bounty_policy, invariants, protograph, economics, planner, coverage, orchestrator, pipeline, completion; CLI: ingest/model/plan/answered/floors/budget/dedup/resolve-candidate/prioritize/repro-queue/verdict/recall/gate/gate-explain/prove/waive/invariant-*/artifact-*/hint/scope | Ported deterministic walkthrough reproduces Python artifact bytes; gate dry-run outputs identical |
| **P2 — evidence execution** | sandbox (argv+policy+ledger), reproduction (attempts/mints/guidance), fork_poc, sequence_poc (POSIX-sh driver generation), maximization, immunize, chain engine, privileged; CLI: exec/execs/mint/sequence/classify/impact/ladder/immunize/chains/terminals/privileged | Docker-based e2e: exec record + minted evidence byte-identical; sequence coverage verdicts identical |
| **P3 — knowledge & memory** | structural index (+queries/value flow), corpus surface, archetypes, playbooks, history mining, relations, learning, shared memory, briefing, report, doctor, env, costs; CLI: index/sinks/prescreen/forkdiff/recency/baseline/relations/resemble/publish/globalize/shared/memory/report/brief/doctor/env doctor/cost/yields/price/price-basis | Index + derived reports byte-identical on fixture tree; report.md diff = timestamp lines only |
| **P4 — dataset tooling & cutover** | metrics, eval store, sft, ingest, `verify` full parity gate, RUNBOOK walkthrough vs Go binary, cross-twin green, single-binary release (embedded assets), docs updated | DoD §1.5 all four items; Python archived (not deleted) with a pinned Python env kept for golden regression |

P1–P4 each get their own implementation plan (writing-plans skill) written after the prior
phase's gate passes, executed autonomously, and gated the same way.

## 4. Repository, naming, assets (resolves OQ1, OQ2)

- **Repo:** `web3sec-go/` becomes a git repository. Go module path **`websec`** (plain
  local module — no remote exists, no vanity path needed). **Binary name stays `webv2`**
  (RUNBOOK/docs compatibility).
- **Layout:** spec §4.2 verbatim: `cmd/webv2/main.go`, `internal/<one-package-per-Python-
  module>` per Appendix A, `assets/` for `go:embed`. One Python module → one Go
  package; **no merging "for convenience"**. The three Python import cycles
  (findings↔floors, sandbox↔env, invariants↔playbooks) are broken at the same seams with
  small interface packages or function parameters.
- **Assets:** `schema/`, `prompts/`, `prompts_legacy/`, `playbooks/`, `archetypes/`,
  `config/` are copied into `assets/` and embedded. `scripts/sync-assets.sh` copies
  from `web3sec-final` (the single source of truth until P4 cutover); every gate asserts
  embedded == source (risk R10). **Not embedded** (disk-resolved, env-overridable):
  `data/datasets`, `baselines/`, campaign stores, `~/.webv2`.
- **CLI engine:** stdlib subcommand dispatcher — **no cobra** (ponytail pass). A
  `Command` table with per-command flag specs ported 1:1 from `cli.py build_parser`;
  argparse edge semantics (unknown flag, `--flag=v` vs space form, repeatable `K=V`,
  `--`) are pinned by the ported CLI tests, not assumed. Exit codes per spec I2:
  0 ok · 1 check/prove/audit/gate failure · 2 usage/validation/failed stage · 3 needs-model.
  `--root` global flag (default `.`), help exits 0.

## 5. Dependencies — ponytail pass (4 total; user decision 2026-09-07)

| Dependency | Lands with | Justification (spec §12 need) |
|---|---|---|
| `santhosh-tekuri/jsonschema/v6` | P0 | draft-07 semantics (`oneOf/anyOf/additionalProperties/$ref` across all 27 schemas) are a hand-rolling trap (risk R4); wrap its errors into the spec's `SchemaError` shape |
| `pelletier/go-toml/v2` | P0 | `foundry.toml` `profile.default.sol` (string **or** list — `tomllib` behavior); hand-rolled TOML rejected |
| `dlclark/regexp2` | P2 | the 6 lookahead/lookbehind patterns (sandbox deny-list, env failure classifier, structural-index call regexes) — impossible in RE2 |
| `gopkg.in/yaml.v3` | P3 | playbooks/archetypes/taxonomy maps; closest to `yaml.safe_load` semantics; duplicate-key and block-scalar behavior verified byte-for-byte against PyYAML on the real corpus files (risk R12) |

**Stdlib instead of deps:** uuid4 = `crypto/rand` + hex formatting (5 lines — no
`google/uuid`); CLI dispatch = stdlib subcommand table (no cobra).
**Rule:** no dependency outside this table without a design addendum; a dependency is
added only when the first module that needs it lands (no unused deps at any gate).
**OQ3 checkpoint (P0):** prototype v6 against Python `jsonschema` on all 27 schemas plus
adversarial accept/reject fixtures for the pattern-heavy schemas (`finding.dedup`, ids).
Any divergence that cannot be mapped into the `SchemaError` shape escalates to
`qri-io/jsonschema` **before P1**, with the decision recorded in the P0 gate report.

## 6. Cross-cutting trust primitives (built once in P0, shared by all phases)

1. **Canonical JSON encoder** — `internal/validation/canon.go` (spec §5.1). One encoder,
   `compact` flag selects the two flavors (spaced for event/context/row hashes; compact
   for snapshot manifests, spec_hash, forkdiff fingerprints). Exact CPython escaping:
   named escapes for quote/backslash and the five whitespace control chars; other control
   chars below 0x20 as lowercase 4-hex unicode escapes; non-ASCII as lowercase unicode
   escapes with UTF-16 surrogate pairs; **no** HTML escaping; forward-slash raw;
   recursive key sort (byte order). Floats via `strconv.FormatFloat(f, 'g', -1, 64)`.
   Big integers pass through as `json.Number` (Python emits arbitrary precision;
   schemas constrain the domain — documented).
   Verified by: a differential fuzz oracle (`scripts/canon-oracle.py` + Go test feeding
   the same random JSON values to both and diffing bytes), checked-in golden vectors, and
   a lint test asserting hashed payloads stay ASCII-keyed.
2. **pythonRound** — round-half-to-even to n decimals (risk R3). Every Python
   round(x, n) call site is audited at port time; ties-possible sites use the helper,
   ties-impossible sites carry a comment proving impossibility.
3. **Time & ids** — now_iso(): UTC, 6-digit microsecond fraction, +00:00 (never Z);
   nanoseconds truncated. new_id(prefix, n=12) via crypto/rand.
4. **Atomic IO + JSONL split policy** — same-directory tmp + rename, mkdir parents;
   events.jsonl and costs.jsonl written ASCII, all other JSONL and pretty JSON
   raw UTF-8 (spec §5.4).
5. **Schema wrapper** (internal/validation) — compile the 27 embedded draft-07 schemas
   once, cache validators; unknown schema name → error listing all 27; error paths mapped
   to the exact message shape "{schema} validation failed at {where}: {msg} (+N more
   errors)" sorted by absolute JSON path, with max_errors and "  also at {path}: {msg}"
   continuation lines; the internal-definitions wrapper builder (evidence_item over the
   finding schema, the 4 model_response kind definitions, trajectory definitions) ported
   once and shared. Build-time test: all 27 compile; all are draft-07 (a future draft
   bump is loud).
6. **Typed errors** — sentinel/typed errors 1:1 with Python exception types
   (SchemaError, IllegalTransition, SnapshotMismatch, OrchestrationError,
   ModelBoundaryError, + later phases add theirs), checked with errors.As where
   the CLI branches. **Error message text is part of the contract** — ported verbatim,
   including the remediation-command snippets embedded in messages.
7. **Clock** — Clock interface injected into Campaign (default: real UTC).
   WEBV2_TEST_CLOCK (fixed timestamp) is honored **only** in builds tagged
   testclock; the default production build refuses the env var at startup (resolves
   OQ4: both routes, production-safe).
8. **Test infrastructure** — golden-file helper (-update flag to regenerate);
   **testmap.json** mapping all 106 Python test files → Go package + port status
   (a completeness check in every gate — kills risk R8); **cross-twin runner**
   scripts/golden.sh: the scripted op-sequence runs through the Python venv and the
   Go binary from the same seed state with pinned clocks, then byte-diffs
   events.jsonl, campaign_state.json, every artifact JSON, exec record shapes,
   fingerprints, and report.md (modulo generated_at and environment_hash);
   Docker-dependent tests skip honestly when no daemon is present (matching Python's
   environment-failure classification — never faked).
9. **Go-native hardening suite** (beyond the ported suite — revision 2026-09-07):
   self-consistency determinism runs, crash-consistency fault injection, adversarial
   argv/shell fixtures, CLI golden tables, and benchmarks with regression thresholds
   (§8); the race detector is a hard gate.

## 7. P0 — trust core (the first sub-project, in detail)

- **Packages (1:1 with Python):**
  - internal/validation — schema loader/wrapper + canonical encoder + atomic IO +
    SchemaError (owns validation.py's whole surface).
  - internal/state — Campaign (paths per state.py __init__), hash-chained event log
    (append under one mutex-protected writer; read-modify-append atomic per event),
    projection (last-1000 mirror, full-file atomic rewrite — never tail-append),
    phases + phase_history, budget (ceiling-crossing halts with the exact raising
    command named), artifacts (register/refresh/prune with hash attribution), ids,
    note caps (4096 + truncation suffix; 200 display cap).
  - internal/snapshot — ladder detection (git-clean/dirty/no-vcs ids), pruned copies
    with frozen SOURCE_EXCLUDES + BULK_SOURCE_EXCLUDES, content hash + Merkle root +
    lockfile/deployment/chain fingerprints (spec §5.3 exactly), manifest (manifest_hash
    self-anchoring), re-pin idempotence (hash-verified, not re-copied) and mutated-pin
    refusal, toolchain detection via foundry.toml, compatibility (MODE-OFF, strict
    mismatch, reverify_required).
  - internal/audit — **section-registry design**: each of the 12 audit sections is a
    registered function. P0 implements the sections whose inputs exist in P0 (1
    event_log, 2 artifacts re-hash, 3 exec records, 4 findings schema conformance,
    5 projection cross-check, 6 pinned snapshot trees re-hash). Sections 7-12
    (relations, floor policy, stage completions, forkdiff, invariant re-check, sequence
    coverage) register with their owning phase and are added there — the package never
    needs restructuring, and a P0 audit of a P0-surface campaign is complete.
- **CLI (thin wrappers only, I3):** init, status, log, snap (pin + attach
  deployment/chain), audit, verify [--full]; global --root.
- **verify fast in P0:** build/vet sweep → P0-surface walkthrough (scratch campaign
  init→snap→audit) → cross-audit of a Python-written fixture. The full model-less
  walkthrough port lands with P1 (its gate).
- **P0 fixtures:** a small pinned snapshot tree (a handful of .sol files with
  contract/function/interface variety + a lockfile) and scratch campaigns. The seeded
  fixture campaigns under web3sec-final/campaigns/ (C-seed*) become cross-audit inputs
  as their owning phases land.
- **P0 gate (all evidenced in the gate report):**
  1. A Python-written campaign directory audits clean from Go (ok: true, all P0 sections).
  2. events.jsonl **bytes identical** for the scripted op-sequence (pinned clock):
     init, snap (source+deployment), artifact register + refresh, phase transition,
     budget limit set, note-cap truncation.
  3. webv2 verify (fast) green.
  4. Golden suite v1 green (cross-twin over the P0 surface).
  5. testmap.json: every Python test function covering validation/state/snapshot/audit
     is a Go table case or carries an explicit disposition; its invariant surface green.
  6. OQ3 checkpoint result recorded (v6 accepted, or qri-io decision with evidence).
  7. Python line coverage of validation/state/snapshot/audit measured (pytest-cov) and
     recorded as the Go coverage floor for those packages.
- **go.mod at P0:** only santhosh-tekuri/jsonschema/v6 + pelletier/go-toml/v2.

## 8. Testing & verification (all phases)

- **Module TDD loop** per Approach A: ported tests first, implementation second; a module
  is done only when its own ported tests pass (parity bugs surface immediately, and the
  Python-wins rule is enforced by the tests themselves).
- **The gate** = scripts/verify-full.sh, run before every phase closes (and before
  any commit that claims a gate):
  1. go vet ./... + go build ./...
  2. go test ./... (ported suite + Go-native hardening unit tests)
  3. **go test -race ./... (hard gate, not optional)** — concurrency is a rewrite
     justification (spec §1.2) and the Python suite cannot catch races
  4. scripts/golden.sh (cross-twin byte diffs) **plus a Go==Go self-consistency
     determinism run**: the same seeded op-sequence executed twice by the Go binary
     alone must be byte-identical (map iteration order, goroutine scheduling, and sync
     primitives can poison event-log hashes and artifact bytes in ways single-threaded
     Python never could)
  5. CLI golden tables: table-driven {command, args, fixture campaign} →
     {stdout, stderr, exit code} goldens covering every CLI command — the ~70-command
     parity surface (spec §1.3.3) gets its own harness, not just unit tests underneath
  6. benchmarks with regression thresholds (testing.B: bulk tree hashing, merkle,
     snapshot copy, index parse; baselines recorded when first landing, gate fails
     beyond threshold — "bulk hashing" is a stated reason for Go, so it is measured)
  7. testmap.json accounting: every Python test function is a Go table case or an
     explicit disposition (ported / merged-into / adapted / dropped-with-reason) —
     a floor against silent omissions, not the goal (R8); the Go suite is deliberately
     much smaller than ~1,052 functions
  8. embedded assets == web3sec-final sources (R10)
  9. regex-hazard grep: any lookahead/lookbehind outside the regexp2 allowlist file
     (which carries a comment per entry) fails the gate
  10. schema compile + KNOWN_SCHEMAS count (27) test
- **Crash-consistency fault injection (P0 — the actual disaster scenario):** the store
  is a hash-chained single-writer ledger. Every write site (event-log append, projection
  save, artifact write, JSONL appends, snapshot copy) gets a kill-mid-write test: the
  next audit either repairs cleanly (doctor's sanctioned note-rewrite is the only
  repair) or fails loudly; a torn write must never silently corrupt the chain.
- **Argv/shell injection fixtures (P2 — novel, prioritized):** sandbox, sequence_poc,
  and the docker argv builder construct shell programs and command lines from data that
  traces back to model output (finding titles, protocol names, PoC parameters). An
  adversarial fixture set — $(), backticks, quotes, newlines, semicolons, &&, crafted
  identifiers — feeds through build_container_argv / build_command / the generated sh
  driver in **both** implementations; byte-parity alone would not catch this, and a
  security tool skipping it would be an own goal.
- **Edge-case campaign zoo (testdata):** beyond the MiniVault-style walkthrough fixture,
  deliberately messy campaign directories checked in as inputs: partial pipeline state,
  a corrupted event mid-chain, campaigns frozen at each phase, orphan artifacts —
  regression coverage for audit's detection/repair logic specifically.
- **Coverage floor:** the trust-core packages (validation, state, plus findings from P1)
  must hold ≥ the recorded Python-suite coverage of the same modules (mechanism measured
  in P0, enforced in every gate thereafter).
- **No external CI today** (no remote): verify-full is the mandatory local gate and is
  written to map 1:1 onto GitHub Actions jobs (spec §13.4: unit job, golden matrix job,
  lint job, schema job, coverage job) the moment a remote exists.

## 9. Risks and mitigations

| Risk | Blast radius | Mitigation (enforced where) |
|---|---|---|
| R1 canonical-JSON drift | every hash, chain, fingerprint | one encoder; differential fuzz oracle vs CPython + checked-in vectors (P0, spec §5.1) |
| R2 float formatting in hashed payloads | event/manifest bytes | FormatFloat 'g' -1 64; differential fuzz over the schema-allowed float domain (P0) |
| R3 banker's rounding | risk scores, thoroughness, similarity, yield | pythonRound helper; per-call-site audit at port time, comment where ties impossible (every phase) |
| R4 jsonschema semantic gaps | validation verdicts | v6 wrapper; P0 prototype checkpoint vs Python jsonschema incl. adversarial accept/reject fixtures; unmappable divergence → qri-io before P1 |
| R5 sequence driver byte-parity | T4 coverage proofs | Go template reproducing build_command exactly + golden test on 3 fixture specs (P2) |
| R6 docker argv drift | exec records | build_container_argv ported exactly, argv order preserved (P2) |
| R7 scope creep / entropy | the whole port | 1:1 mapping rule (Appendix A), Python-wins rule, no behavioral changes inside port PRs (changes go through Python first, then port) |
| R8 silent test-suite shrinkage | parity confidence | testmap.json function-level accounting in every gate (ported/merged/adapted/dropped-with-reason) — floor, not goal |
| R13 Go-native nondeterminism (new) | event hashes, artifact bytes | -race hard gate + Go==Go self-consistency determinism runs in every gate |
| R14 shell/argv injection from model-influenced data (new) | exec records, sequence driver, sandbox | adversarial fixture set through build_container_argv/build_command/sh driver in both implementations (P2) |
| R9 no external CI (new) | gate enforcement is local | verify-full.sh is the mandatory phase-close gate; script maps 1:1 to GitHub Actions jobs if a remote appears |
| R10 asset drift vs Python tree | embedded prompts/schemas diverge | scripts/sync-assets.sh + embedded==source assertion in every gate |
| R11 argparse↔stdlib-CLI divergence | CLI contracts, exit codes | CLI tests ported 1:1; argparse edge semantics pinned by tests, not assumed |
| R12 YAML library semantics | playbook/archetype/taxonomy loads | goldens byte-compare PyYAML vs yaml.v3 on the real corpus files (P3) |

## 10. Phase workflow (autonomous execution)

1. P0 gate passes → write the P1 implementation plan (writing-plans skill) → execute P1
   module-by-module (tests first) → P1 gate → … → P4.
2. Each gate report lands at `docs/gates/P{n}-gate.md` in this repo: evidence for every
   gate item (commands run, outputs, coverage numbers, OQ3 decision where applicable).
3. `KNOWN_DIVERGENCES.md` at the repo root from day one: every deferred Python papercut
   (OQ6) and every conscious Go-side divergence (test triage drops/merges, validator
   error-string mapping) is recorded with the Python behavior it departs from — a
   deferred papercut must never quietly become an undocumented spec by P4. Reviewed at
   every gate.
4. At P4: DoD §1.5 all four items evidenced; Python repo archived (not deleted); the
   cross-twin golden suite keeps a pinned Python venv for regression checks; RUNBOOK
   notes the "one binary at a time" rule; README gains the Go install.
5. A failure at any gate stops the phase; the failure is fixed in Go (Python changes
   only for confirmed Python bugs, filed and fixed in **both** implementations per the
   spec's non-goals).

## 11. Decisions log

| Decision | Choice | Source |
|---|---|---|
| Delivery model | fully autonomous P0→P4, phase gates only | user, 2026-09-07 |
| Dependencies | ponytail pass — 4 deps (jsonschema/v6, go-toml/v2, regexp2, yaml.v3); stdlib uuid4 + stdlib CLI dispatch | user, 2026-09-07 |
| Execution approach | A — phase-serial, module-level TDD | user, 2026-09-07 |
| OQ1 naming | CLI `webv2`, Go module `websec` | spec recommendation |
| OQ2 repo layout | fresh repo + go:embed + sync-assertion vs Python tree | spec recommendation |
| OQ3 validator | santhosh-tekuri/jsonschema/v6 with P0 prototype checkpoint; qri-io fallback before P1 | spec + ponytail (hand-rolled draft-07 rejected) |
| OQ4 clock | injected Clock + WEBV2_TEST_CLOCK (testclock tag only; production build refuses) | spec lean |
| OQ5 Windows | non-goal, documented | spec |
| OQ6 Python papercuts | no fixes during P0–P3 (parity); post-cutover queue, tests on both sides, tracked in KNOWN_DIVERGENCES.md | spec recommendation |
| Test-porting + hardening revision | invariants over 1:1 count; **aggressive merging** of similar tests into table tests (Go suite much smaller than ~1,052 functions, function-level accounting so nothing is silently lost); Go-native suite: -race hard gate, Go==Go determinism runs, crash-consistency fault injection, argv/shell injection fixtures, benchmark thresholds, CLI golden tables, edge-case campaign zoo; KNOWN_DIVERGENCES.md from day one | user, 2026-09-07 |

---

*End of design. Behavioral contract: GO_REWRITE_SPEC.md. Per-phase plans: docs/plans/.
Gate reports: docs/gates/.*
