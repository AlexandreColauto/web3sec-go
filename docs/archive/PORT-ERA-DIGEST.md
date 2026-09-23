# Port-era digest (frozen)

**What this is.** A single-file digest of the process archaeology that accumulated while
`web3sec-go` was ported from the retired Python twin and then hardened wave by wave. It
replaces **96 files / 2.17 MB** of task reports, review reports, plan trails and
re-runnable command logs with one browsable document, so that a new reader (human or
model) is not buried by history while the *claims* that history produced stay citable.

**What it is not.** It is not a summary of the code, and it is not the project's current
state. For those, read `README.md`, `docs/INDEX.md`, `docs/REVIEW-BRIEF.md`,
`docs/gates/v16-prompt.md` (the current phase) and `framework-plan-v1.6.md` (the spec).

**Provenance.** Written 2026-09-23 from the originals at commit `2771d466`, immediately
before they were removed from the working tree. Every digest section was produced by
reading every source file; measured numbers, commit shas, operator rulings, refusals and
laws were preserved rather than paraphrased. Contradictions between sources are flagged
where they were found, not resolved.

**How to recover an original.** The full text of every removed file is in git history:

```bash
git show <removal-commit>^:<path>        # e.g.
git show <removal-commit>^:docs/sdd/task-13-report.md
git log --diff-filter=D --name-only <removal-commit>   # the full removed-path list
```

Frozen gate reports and plan references written *before* the removal still cite the old
paths; those citations are historical and were deliberately not rewritten. Live code
comments that cited a removed path were re-pointed here (see the table below).

---

## Contents

| section | digest file | covers |
|---|---|---|
| **§I** | `go-rewrite-design-2026-09-07.md` | the Go rewrite design: the architecture, the byte-exactness contract, the conventions it fixed, and 17 measured divergences between what it predicted and the tree today |
| **§II** | `trust-boundary-hardening-trail.md` | the 2026-09-17/18 trust-boundary-hardening trail: the operator rulings ledger, 16 tasks plus 3 fix waves and 2 critic rounds, the F1 race-lock ×10 derivation, the step-12 section-count ruling, every review defect and its disposition |
| **§III** | `gold-findings-closure-trail.md` | the 2026-09-18 gold-findings closure trail: the plan's tasks and acceptance criteria, the per-task record, the final review's must-fixes, every measured number |
| **§IV** | `closed-wave-plan-trails.md` | the 21 closed wave plans (2026-09-08 … 2026-09-20): per-plan goals, tasks, acceptance criteria and commit shas; the cross-plan laws; an 8-item contradiction register; a 34-item deferral/refusal register |

---

## Removed paths → where their content went

### §I — `docs/superpowers/specs/` (1 file)

| removed path | what it was |
|---|---|
| `docs/superpowers/specs/2026-09-07-go-rewrite-design.md` | the design that drove the Python→Go port |

### §II — `docs/sdd/` top level (48 files)

**Task reports** (implementer records: commit shas, diffstats, re-pin inventories,
disclosed deviations): `task-1-report.md`, `task-2-report.md`, `task-3-report.md`,
`task-4-report.md`, `task-4a-report.md`, `task-4a-fix1-report.md`, `task-5-report.md`,
`task-6-report.md`, `task-7-report.md`, `task-7-fix1-report.md`, `task-8-report.md`,
`task-9-report.md`, `task-9-fix1-report.md`, `task-10-report.md`, `task-11-report.md`,
`task-12-report.md`, `task-13-report.md`, `task-14-report.md`, `task-15-report.md`,
`task-16-report.md`.

**Review reports** (adversarial review of the above, including the refuted claims):
`task-1-review.md`, `task-2-3-review.md`, `task-4-review.md`, `task-4a-fix1-review.md`,
`task-5-review.md`, `task-6-review.md`, `task-7-review.md`, `task-7-fix1-review.md`,
`task-8-review.md`, `task-9-review.md`, `task-9-fix1-review.md`, `task-10-12-review.md`,
`task-14-15-review.md`, `task-16-review.md`.

**Ledger and verdicts:** `progress.md` (the operator/controller rulings), `critic-round-1.md`
(the whole-branch judgement, 7/10), `critic-round1-fixes.md` (the closure record that
corrects the ledger).

**Logs** (re-runnable command output, kept only for the bytes a re-run cannot reproduce):
`f1-race-diagnosis.txt`, `f1-red-race.log`, `f1-mutation-race.log`,
`f1-mutation-nolock-race.log`, `f1-green-race.txt`, `f5-red.txt`, `f5-golden.txt`,
`final-gates.log`, `verify-full-final.log`, `verify-full-final-head.log`, `release-final.log`.

### §III — `docs/sdd/gold-plan/` (26 files)

The task brief/report/review/review-package set for tasks 1–5 plus
`final-fixes.md`, `final-fix-review.md`, `final-fix-review-package.md`, `final-review.md`
and `progress.md`.

### §IV — `docs/superpowers/plans/` (21 closed trails; the three `2026-09-21-v16-*` plans stay)

`2026-09-08-p0-trust-core.md`, `2026-09-09-p1-findings-gates.md`,
`2026-09-10-emit-quota-repair.md`, `2026-09-10-p0-review-consumption.md`,
`2026-09-10-wave-g-tranche-1.md`, `2026-09-11-recall-wave.md`,
`2026-09-11-wave-g-tranche-2.md`, `2026-09-11-wave-g-tranche-3.md`,
`2026-09-11-wave-i.md`, `2026-09-11-wave-j.md`,
`2026-09-12-minicertora-harness-backend.md`, `2026-09-12-wave-l-advice-dispositions.md`,
`2026-09-12-wave-l-defer-validation-completion.md`,
`2026-09-12-wave-l-system-sweep-calibration.md`,
`2026-09-12-wave-m-fork-consumption-run2.md`, `2026-09-13-wave-n-operator-friction.md`,
`2026-09-16-morph-c12-feedback-wave.md`, `2026-09-17-trust-boundary-hardening.md`,
`2026-09-18-gold-findings-closure.md`, `2026-09-19-morph-r3-fork-ladder-and-record-trust.md`,
`2026-09-20-morph-pass2-framework-fixes.md`.

### Live code comments re-pointed to this digest

| file | was | now cites |
|---|---|---|
| `internal/probes/campaign.go:59` | `docs/sdd/task-10-12-review.md` | §II |
| `internal/planner/task12_coverage_parity_test.go:2` | `docs/sdd/task-10-12-review.md` | §II |
| `internal/briefing/task10_open_question_brief_test.go:2` | `docs/sdd/task-10-12-review.md` | §II |
| `internal/briefing/briefing_nextactions_probe.go:238` | `docs/sdd/task-10-12-review.md` | §II |
| `internal/report/report_finding_section.go` | `docs/sdd/task-15-report.md` | §II |
| `internal/orchestrator/task13_lifecycle_surfaces_test.go:2` | `docs/superpowers/plans/2026-09-18-gold-findings-closure.md` | §III |
| `internal/envgo/classifier_toolabsent_test.go:4` | `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` | §II |
| `internal/cli/supersede_discovery.go:30` | `docs/superpowers/plans/2026-09-13-wave-n-operator-friction.md` | §IV |
| `scripts/archive/sync-assets.sh:6` | `docs/superpowers/plans/2026-09-08-p0-trust-core.md` | §IV |

---

# Digest §I — the Go rewrite design

# The Go rewrite design (2026-09-07)

**Digest of `docs/superpowers/specs/2026-09-07-go-rewrite-design.md`** (317 lines, ~25 KB) — the
file is scheduled for deletion; this section is its browsable replacement.

**Measurement provenance.** Every "tree today" claim below was checked in the working tree at
`HEAD 2771d4661985f18c45b8f1702275023673ae1cc1` (2026-09-23 11:32:56 +0100, branch `main`,
5 modified + 10 untracked files present). Source-document facts come from the file itself; gate
numbers come from `docs/gates/P0-gate.md`, `P2-gate.md`, `P4-gate.md` and `docs/archive/KNOWN_DIVERGENCES.md`.

## 1. What the document is and when it was written

| Fact | Value |
|---|---|
| Title | `# Go Rewrite of webv2 — Implementation Design` |
| Status (verbatim) | "**Status:** approved design (brainstormed 2026-09-07; revised same day with the test-porting + Go-native hardening revision, §11)." |
| Companion contract | `web3sec-final/docs/GO_REWRITE_SPEC.md` (DRAFT v1) — "the behavioral contract. This document decides **how** we build; the spec decides **what** must be true." |
| Precedence rule (quote) | "Where prose and code disagree, the **Python code wins** (spec's own rule)." |
| Skill chain | "brainstorming (this process) → writing-plans (per-phase plans) → ponytail (implementation minimalism, enforced per module)" |
| Git: original | `ee9b895e` — `docs: Go rewrite implementation design (brainstormed 2026-09-07)` |
| Git: revision | `2cbcc6cab69834a6c8dfa969fc6788d5c87523b5` — `docs: revise design - aggressive test merging, Go-native hardening suite, KNOWN_DIVERGENCES` (2026-09-08 00:47:37 +0100) — the last commit touching the file |
| Location note | the only file in `docs/superpowers/specs/`; its per-phase plans live in `docs/superpowers/plans/` (25 files today, starting `2026-09-08-p0-trust-core.md`) |
| Section map | §1 Objective · §2 Delivery model · §3 Decomposition · §4 Repository/naming/assets · §5 Dependencies · §6 Cross-cutting trust primitives · §7 P0 in detail · §8 Testing & verification · §9 Risks · §10 Phase workflow · §11 Decisions log |

**Baseline numbers the design asserted for the Python twin** (all of them already stale by the P4
gate — see §4.2 #8 and §5.3): "52 Python modules, ~23.4k LOC"; "~1,100 tests"; "~1,052 test functions"; "27
embedded" schemas; "106 Python test files"; CLI "~70-command parity surface".

## 2. The architecture it proposed

### 2.1 Objective and definition of done

"Byte-exact port of the `webv2` deterministic control plane (52 Python modules, ~23.4k LOC) to Go.
Definition of done = spec §1.5, all four items:"

1. `verify`-equivalent fast self-check passes; `--full` runs the ported suite (~1,100 tests) green.
2. Cross-golden suite: Python and Go produce byte-identical outputs (event log lines, JSON artifacts, `report.md` modulo `generated_at`, completion proofs, fingerprints, corpus reports).
3. `audit` cross-checks both directions: Python-written campaigns audit clean from Go and vice versa.
4. `RUNBOOK.md` commands run verbatim against the Go binary with documented exit codes.

Doctrine, quoted in full:

> "Doctrine (unchanged): the framework decides, models propose. No LLM integration in the binary.
> No redesign — every gate, floor, ladder, hash format, and refusal message is load-bearing. The
> spec's tables are **transcribed, not re-derived**."

### 2.2 Delivery model (§2)

- **Autonomy:** "fully autonomous P0→P4. The phase gates (spec §14) are the checkpoints; no per-phase user pause is scheduled. A tracked session goal enforces continuation."
- **Approach A — phase-serial, module-level TDD:** per module (1) triage the Python tests and port invariant tests as Go table tests first (dispositions in `testmap.json`); (2) implement until green; (3) keep `webv2 verify` fast green at all times; (4) at the phase boundary extend the cross-twin golden suite and run it green — "that is the gate".
- **Test-porting philosophy (revision 2026-09-07):** port invariants, not Python implementation details, and "**merge aggressively**"; triage classes (a) invariant → table case, (b) implementation-detail (local-import cycles, jsonschema error strings, monkeypatch quirks) → adapt or drop with recorded reason, (c) similar tests → merged into one table test.
- **Ponytail discipline:** "YAGNI → stdlib → native platform → existing reliable dependency → the one-liner → minimum viable implementation." Quote: "Every deliberate shortcut carries `// ponytail: [upgrade path]` so the scaling path is documented at the shortcut."

### 2.3 Phases and exit gates (§3)

| Phase | Contents (condensed) | Exit gate (as written) |
|---|---|---|
| **P0 — trust core** | repo skeleton, canonical JSON encoder (+fuzz oracle), schema loader (27 embedded, compile test), validation, `state` (events/chain/projection/budget/artifacts/ids), `snapshot` (pins/manifest/hashing/compat), `audit`, `verify`; CLI init/status/log/snap/audit/verify | Python-written campaign audits clean from Go; event bytes identical; `verify` fast green |
| **P1 — findings & gates** | findings (IR/transitions/gates/evidence/assumptions/memory checks), floors, taxonomy, capabilities, dedup, risk, pricing, bounty_policy, invariants, protograph, economics, planner, coverage, orchestrator, pipeline, completion; 21 CLI verbs | Ported deterministic walkthrough reproduces Python artifact bytes; gate dry-run outputs identical |
| **P2 — evidence execution** | sandbox (argv+policy+ledger), reproduction (attempts/mints/guidance), fork_poc, sequence_poc (POSIX-sh driver generation), maximization, immunize, chain engine, privileged | Docker-based e2e: exec record + minted evidence byte-identical; sequence coverage verdicts identical |
| **P3 — knowledge & memory** | structural index (+queries/value flow), corpus surface, archetypes, playbooks, history mining, relations, learning, shared memory, briefing, report, doctor, env, costs | Index + derived reports byte-identical on fixture tree; `report.md` diff = timestamp lines only |
| **P4 — dataset tooling & cutover** | metrics, eval store, sft, ingest, `verify` full parity gate, RUNBOOK walkthrough vs Go binary, cross-twin green, single-binary release (embedded assets), docs updated | DoD §1.5 all four items; "Python archived (not deleted) with a pinned Python env kept for golden regression" |

### 2.4 Repository, naming, assets, CLI, dependencies (§4–§5)

- **Naming:** `web3sec-go/` becomes a git repo; Go module path **`websec`** ("plain local module — no remote exists, no vanity path needed"); "**Binary name stays `webv2`** (RUNBOOK/docs compatibility)".
- **Layout:** "spec §4.2 verbatim: `cmd/webv2/main.go`, `internal/<one-package-per-Python-module>` per Appendix A, `assets/` for `go:embed`. One Python module → one Go package; **no merging "for convenience"**." The three Python import cycles (`findings↔floors`, `sandbox↔env`, `invariants↔playbooks`) "are broken at the same seams with small interface packages or function parameters."
- **Assets:** `schema/`, `prompts/`, `prompts_legacy/`, `playbooks/`, `archetypes/`, `config/` copied to `assets/` and embedded; `scripts/sync-assets.sh` copies from `web3sec-final` ("the single source of truth until P4 cutover"); every gate asserts embedded == source (risk R10). **Not embedded:** `data/datasets`, `baselines/`, campaign stores, `~/.webv2`.
- **CLI engine:** stdlib subcommand dispatcher, "**no cobra** (ponytail pass)"; `Command` table with per-command flag specs "ported 1:1 from `cli.py build_parser`"; argparse edge semantics (unknown flag, `--flag=v` vs space form, repeatable `K=V`, `--`) "are pinned by the ported CLI tests, not assumed". Exit codes per spec I2: "0 ok · 1 check/prove/audit/gate failure · 2 usage/validation/failed stage · 3 needs-model." Global `--root` (default `.`), help exits 0.
- **Dependencies (4 total; user decision 2026-09-07):**

| Dependency | Lands with | Justification (as written) |
|---|---|---|
| `santhosh-tekuri/jsonschema/v6` | P0 | draft-07 semantics (`oneOf/anyOf/additionalProperties/$ref` across all 27 schemas) "are a hand-rolling trap (risk R4)"; wrap errors into the spec's `SchemaError` shape |
| `pelletier/go-toml/v2` | P0 | `foundry.toml` `profile.default.sol` (string **or** list — `tomllib` behavior); hand-rolled TOML rejected |
| `dlclark/regexp2` | P2 | "the 6 lookahead/lookbehind patterns (sandbox deny-list, env failure classifier, structural-index call regexes) — impossible in RE2" |
| `gopkg.in/yaml.v3` | P3 | playbooks/archetypes/taxonomy maps; closest to `yaml.safe_load`; duplicate-key and block-scalar behavior "verified byte-for-byte against PyYAML on the real corpus files (risk R12)" |

  Plus: uuid4 = `crypto/rand` + hex formatting ("5 lines — no `google/uuid`"); CLI dispatch = stdlib
  table. **Rule (quote):** "no dependency outside this table without a design addendum; a dependency
  is added only when the first module that needs it lands (no unused deps at any gate)."
- **OQ3 checkpoint (P0):** prototype v6 against Python `jsonschema` on all 27 schemas plus adversarial accept/reject fixtures for pattern-heavy schemas (`finding.dedup`, ids). "Any divergence that cannot be mapped into the `SchemaError` shape escalates to `qri-io/jsonschema` **before P1**, with the decision recorded in the P0 gate report."
- **go.mod at P0:** "only santhosh-tekuri/jsonschema/v6 + pelletier/go-toml/v2."

### 2.5 Cross-cutting trust primitives built once in P0 (§6)

| # | Primitive | Contract as written |
|---|---|---|
| 1 | Canonical JSON encoder — `internal/validation/canon.go` | one encoder, `compact` flag selects two flavors (spaced for event/context/row hashes; compact for snapshot manifests, `spec_hash`, forkdiff fingerprints). "Exact CPython escaping: named escapes for quote/backslash and the five whitespace control chars; other control chars below 0x20 as lowercase 4-hex unicode escapes; non-ASCII as lowercase unicode escapes with UTF-16 surrogate pairs; **no** HTML escaping; forward-slash raw; recursive key sort (byte order). Floats via `strconv.FormatFloat(f, 'g', -1, 64)`. Big integers pass through as `json.Number`". Verified by differential fuzz oracle (`scripts/canon-oracle.py` + Go test), checked-in golden vectors, and a lint test asserting hashed payloads stay ASCII-keyed |
| 2 | `pythonRound` | round-half-to-even to n decimals (risk R3); every Python `round(x, n)` call site audited at port time; ties-possible sites use the helper, ties-impossible sites "carry a comment proving impossibility" |
| 3 | Time & ids | `now_iso()`: UTC, 6-digit microsecond fraction, `+00:00` "(never Z); nanoseconds truncated". `new_id(prefix, n=12)` via crypto/rand |
| 4 | Atomic IO + JSONL split policy | same-directory tmp + rename, mkdir parents; `events.jsonl` and `costs.jsonl` written ASCII, "all other JSONL and pretty JSON raw UTF-8 (spec §5.4)" |
| 5 | Schema wrapper (`internal/validation`) | compile the 27 embedded draft-07 schemas once, cache validators; unknown schema name → error listing all 27; error paths mapped to the exact shape `"{schema} validation failed at {where}: {msg} (+N more errors)"` sorted by absolute JSON path, with `max_errors` and `"  also at {path}: {msg}"` continuation lines; the internal-definitions wrapper builder (evidence_item over the finding schema, the 4 model_response kind definitions, trajectory definitions) "ported once and shared". Build-time test: all 27 compile and are draft-07 |
| 6 | Typed errors | sentinel/typed errors 1:1 with Python exception types (`SchemaError`, `IllegalTransition`, `SnapshotMismatch`, `OrchestrationError`, `ModelBoundaryError`, + later phases add theirs), checked with `errors.As` where the CLI branches |
| 7 | Clock | `Clock` interface injected into `Campaign` (default real UTC); `WEBV2_TEST_CLOCK` (fixed timestamp) "is honored **only** in builds tagged testclock; the default production build refuses the env var at startup (resolves OQ4: both routes, production-safe)" |
| 8 | Test infrastructure | golden-file helper (`-update` flag); **`testmap.json`** mapping all 106 Python test files → Go package + port status ("a completeness check in every gate — kills risk R8"); cross-twin runner `scripts/golden.sh` — "the scripted op-sequence runs through the Python venv and the Go binary from the same seed state with pinned clocks, then byte-diffs `events.jsonl`, `campaign_state.json`, every artifact JSON, exec record shapes, fingerprints, and `report.md` (modulo `generated_at` and `environment_hash`)"; Docker-dependent tests "skip honestly when no daemon is present (matching Python's environment-failure classification — never faked)" |
| 9 | Go-native hardening suite (revision) | self-consistency determinism runs, crash-consistency fault injection, adversarial argv/shell fixtures, CLI golden tables, benchmarks with regression thresholds; "the race detector is a hard gate" |

### 2.6 P0 in detail (§7) and the byte-exactness contract

- **P0 packages (1:1 with Python):** `internal/validation` (schema loader/wrapper + canonical encoder + atomic IO + `SchemaError`, "owns validation.py's whole surface"); `internal/state` (`Campaign` paths per `state.py __init__`, hash-chained event log "append under one mutex-protected writer; read-modify-append atomic per event", projection "last-1000 mirror, full-file atomic rewrite — never tail-append", phases + `phase_history`, budget "ceiling-crossing halts with the exact raising command named", artifacts register/refresh/prune with hash attribution, ids, note caps "4096 + truncation suffix; 200 display cap"); `internal/snapshot` (ladder detection git-clean/dirty/no-vcs ids, pruned copies with frozen `SOURCE_EXCLUDES` + `BULK_SOURCE_EXCLUDES`, content hash + Merkle root + lockfile/deployment/chain fingerprints, manifest self-anchoring, re-pin idempotence "hash-verified, not re-copied" and mutated-pin refusal, toolchain detection via `foundry.toml`, compatibility MODE-OFF/strict-mismatch/reverify_required); `internal/audit` — "**section-registry design**: each of the 12 audit sections is a registered function", P0 implementing sections 1–6 (`event_log`, `artifacts` re-hash, `exec` records, `findings` schema conformance, `projection` cross-check, pinned `snapshots` re-hash) and sections 7–12 "register with their owning phase".
- **P0 gate (7 items, all evidenced in the gate report):** (1) Python-written campaign audits clean from Go; (2) `events.jsonl` bytes identical for the scripted op-sequence (init, snap source+deployment, artifact register + refresh, phase transition, budget limit set, note-cap truncation); (3) `webv2 verify` fast green; (4) golden suite v1 green; (5) `testmap.json` accounting for every Python test function over validation/state/snapshot/audit; (6) OQ3 result recorded; (7) Python line coverage of those four packages measured with pytest-cov and recorded as the Go coverage floor.
- **Byte-exactness contract (the deliverable to be diffed):** event log lines, JSON artifacts, `report.md` modulo `generated_at`, completion proofs, fingerprints, corpus reports; `audit` clean both directions; RUNBOOK commands verbatim with documented exit codes.

## 3. The conventions it fixed (binding statements quoted)

### 3.1 Naming and structure

> "One Python module → one Go package; **no merging "for convenience"**." (§4)

> "**Binary name stays `webv2`** (RUNBOOK/docs compatibility)." Go module `websec`; `cmd/webv2/main.go`.

OQ1/OQ2 rulings (source column: "spec recommendation"): CLI `webv2` + Go module `websec`; "fresh
repo + go:embed + sync-assertion vs Python tree".

### 3.2 Error text is contract

> "**Error message text is part of the contract** — ported verbatim, including the
> remediation-command snippets embedded in messages." (§6.6)

> error paths mapped to the exact message shape `"{schema} validation failed at {where}: {msg}
> (+N more errors)"` sorted by absolute JSON path, with `max_errors` and `"  also at {path}: {msg}"`
> continuation lines. (§6.5)

Related gate item: "schema compile + `KNOWN_SCHEMAS` count (27) test" (§8.10).

### 3.3 Determinism pins (a future reader can cite these as the design's laws)

| Pin | Exact rule |
|---|---|
| Canonical JSON escaping | named escapes for quote/backslash + the five whitespace control chars; other control chars below 0x20 as lowercase 4-hex unicode escapes; non-ASCII as lowercase unicode escapes with UTF-16 surrogate pairs; **no** HTML escaping; forward-slash raw; recursive key sort in byte order |
| Floats | `strconv.FormatFloat(f, 'g', -1, 64)`; big integers pass through as `json.Number` ("Python emits arbitrary precision; schemas constrain the domain — documented") |
| Rounding | `pythonRound` = round-half-to-even; per-call-site audit, comment where ties are impossible (risk R3) |
| Timestamps | `now_iso()` UTC, 6-digit microsecond fraction, `+00:00` "(never Z)"; nanoseconds truncated |
| Ids | `new_id(prefix, n=12)` via `crypto/rand` |
| File bytes | atomic same-dir tmp + rename, mkdir parents; `events.jsonl` + `costs.jsonl` ASCII; all other JSONL and pretty JSON raw UTF-8 |
| Race freedom | "**go test -race ./... (hard gate, not optional)** — concurrency is a rewrite justification (spec §1.2) and the Python suite cannot catch races" |
| Go==Go determinism | "the same seeded op-sequence executed twice by the Go binary alone must be byte-identical (map iteration order, goroutine scheduling, and sync primitives can poison event-log hashes and artifact bytes in ways single-threaded Python never could)" |

### 3.4 Test strategy and the gate (§8)

- Module TDD loop: "ported tests first, implementation second; a module is done only when its own ported tests pass".
- Anti-shrinkage law, quoted: "**Test count is a floor, not the goal**"; and "a near-1:1 function count would be a smell, not an achievement". Accounting unit = the Python test function, with dispositions "ported / merged-into / adapted / dropped-with-reason" in `testmap.json` — "nothing is silently lost".
- **The gate = `scripts/verify-full.sh`, run before every phase closes** (and before any commit that claims a gate), 10 items as written:
  1. `go vet ./...` + `go build ./...`
  2. `go test ./...`
  3. `go test -race ./...` (hard gate)
  4. `scripts/golden.sh` cross-twin byte diffs **plus a Go==Go self-consistency determinism run**
  5. CLI golden tables `{command, args, fixture campaign} → {stdout, stderr, exit code}` "covering every CLI command — the ~70-command parity surface (spec §1.3.3) gets its own harness"
  6. benchmarks with regression thresholds (`testing.B`: bulk tree hashing, merkle, snapshot copy, index parse; "gate fails beyond threshold — "bulk hashing" is a stated reason for Go, so it is measured")
  7. `testmap.json` accounting (floor, not goal)
  8. embedded assets == `web3sec-final` sources (R10)
  9. regex-hazard grep: "any lookahead/lookbehind outside the regexp2 allowlist file (which carries a comment per entry) fails the gate"
  10. schema compile + `KNOWN_SCHEMAS` count (27) test
- Crash-consistency fault injection (P0): "Every write site (event-log append, projection save, artifact write, JSONL appends, snapshot copy) gets a kill-mid-write test: the next audit either repairs cleanly (doctor's sanctioned note-rewrite is the only repair) or fails loudly; a torn write must never silently corrupt the chain."
- Argv/shell injection fixtures (P2, "novel, prioritized"): adversarial fixture set — `$()`, backticks, quotes, newlines, semicolons, `&&`, crafted identifiers — "feeds through build_container_argv / build_command / the generated sh driver in **both** implementations; byte-parity alone would not catch this, and a security tool skipping it would be an own goal."
- Edge-case campaign zoo: "partial pipeline state, a corrupted event mid-chain, campaigns frozen at each phase, orphan artifacts — regression coverage for audit's detection/repair logic specifically."
- Coverage floor: "the trust-core packages (validation, state, plus findings from P1) must hold ≥ the recorded Python-suite coverage of the same modules (mechanism measured in P0, enforced in every gate thereafter)."
- CI: "**No external CI today** (no remote): verify-full is the mandatory local gate and is written to map 1:1 onto GitHub Actions jobs (spec §13.4: unit job, golden matrix job, lint job, schema job, coverage job) the moment a remote exists."

### 3.5 Process laws (§10)

- Gate reports land at `docs/gates/P{n}-gate.md` in this repo, with evidence for every gate item.
- `KNOWN_DIVERGENCES.md` at the repo root from day one: "every deferred Python papercut (OQ6) and every conscious Go-side divergence (test triage drops/merges, validator error-string mapping) is recorded with the Python behavior it departs from — a deferred papercut must never quietly become an undocumented spec by P4. Reviewed at every gate."
- "A failure at any gate stops the phase; the failure is fixed in Go (Python changes only for confirmed Python bugs, filed and fixed in **both** implementations per the spec's non-goals)."
- Risk R7: "no behavioral changes inside port PRs (changes go through Python first, then port)".

### 3.6 Risk register as written (§9)

| Risk | Blast radius | Mitigation (enforced where) |
|---|---|---|
| R1 canonical-JSON drift | every hash, chain, fingerprint | one encoder; differential fuzz oracle vs CPython + checked-in vectors (P0) |
| R2 float formatting in hashed payloads | event/manifest bytes | `FormatFloat 'g' -1 64`; differential fuzz over the schema-allowed float domain (P0) |
| R3 banker's rounding | risk scores, thoroughness, similarity, yield | `pythonRound` helper; per-call-site audit (every phase) |
| R4 jsonschema semantic gaps | validation verdicts | v6 wrapper; P0 prototype checkpoint incl. adversarial fixtures; unmappable divergence → qri-io before P1 |
| R5 sequence driver byte-parity | T4 coverage proofs | Go template reproducing `build_command` exactly + golden test on 3 fixture specs (P2) |
| R6 docker argv drift | exec records | `build_container_argv` ported exactly, argv order preserved (P2) |
| R7 scope creep / entropy | the whole port | 1:1 mapping rule (Appendix A), Python-wins rule, no behavioral changes inside port PRs |
| R8 silent test-suite shrinkage | parity confidence | `testmap.json` function-level accounting in every gate — floor, not goal |
| R13 Go-native nondeterminism (new) | event hashes, artifact bytes | `-race` hard gate + Go==Go determinism runs in every gate |
| R14 shell/argv injection from model-influenced data (new) | exec records, sequence driver, sandbox | adversarial fixture set in both implementations (P2) |
| R9 no external CI (new) | gate enforcement is local | `verify-full.sh` mandatory phase-close gate; maps 1:1 to GitHub Actions jobs |
| R10 asset drift vs Python tree | embedded prompts/schemas diverge | `scripts/sync-assets.sh` + embedded==source assertion in every gate |
| R11 argparse↔stdlib-CLI divergence | CLI contracts, exit codes | CLI tests ported 1:1; edge semantics "pinned by tests, not assumed" |
| R12 YAML library semantics | playbook/archetype/taxonomy loads | goldens byte-compare PyYAML vs yaml.v3 on the real corpus files (P3) |

### 3.7 Decisions log (§11) — the operator rulings of 2026-09-07

| Decision | Choice | Source |
|---|---|---|
| Delivery model | fully autonomous P0→P4, phase gates only | user, 2026-09-07 |
| Dependencies | ponytail pass — 4 deps (jsonschema/v6, go-toml/v2, regexp2, yaml.v3); stdlib uuid4 + stdlib CLI dispatch | user, 2026-09-07 |
| Execution approach | A — phase-serial, module-level TDD | user, 2026-09-07 |
| OQ1 naming | CLI `webv2`, Go module `websec` | spec recommendation |
| OQ2 repo layout | fresh repo + go:embed + sync-assertion vs Python tree | spec recommendation |
| OQ3 validator | `santhosh-tekuri/jsonschema/v6` with P0 prototype checkpoint; qri-io fallback before P1 | spec + ponytail ("hand-rolled draft-07 rejected") |
| OQ4 clock | injected `Clock` + `WEBV2_TEST_CLOCK` (testclock tag only; production build refuses) | spec lean |
| OQ5 Windows | non-goal, documented | spec |
| OQ6 Python papercuts | no fixes during P0–P3 (parity); post-cutover queue, tests on both sides, tracked in `KNOWN_DIVERGENCES.md` | spec recommendation |
| Test-porting + hardening revision | invariants over 1:1 count; **aggressive merging**; Go-native suite (`-race` hard gate, Go==Go determinism, crash-consistency fault injection, argv/shell injection fixtures, benchmark thresholds, CLI golden tables, edge-case campaign zoo); `KNOWN_DIVERGENCES.md` from day one | user, 2026-09-07 |

## 4. Predicted vs. the tree (checked at HEAD `2771d466`, 2026-09-23)

### 4.1 Held as designed

| Prediction | Tree evidence |
|---|---|
| Go module `websec`, binary `webv2`, layout `cmd/webv2/main.go` | `go.mod`: `module websec`, `go 1.26.2`, `toolchain go1.26.6`; `cmd/webv2/main.go` exists |
| `assets/` + `go:embed` | `assets/schemas.go` (`//go:embed schema/*.schema.json`), `assets/{archetypes,playbooks,prompts,prompts_legacy,protocol,runbook,schema,taxonomy,evalsuite,testdata}` |
| No cobra, no `google/uuid` | no `spf13/cobra` and no `google/uuid` anywhere in `go.mod`/`go.sum`/tree |
| P0 packages `internal/{validation,state,snapshot,audit}` exist with the designed surfaces | `internal/validation/{schema.go,atomicio.go,pyrepr.go,sortedkeys.go}`; `internal/state/{campaign.go,eventlog.go,phases.go,artifacts*.go,id.go,note.go,processlock.go}`; `internal/snapshot/{pin.go,hashing.go,manifest.go,compat.go,ladder.go,toolchain.go}`; `internal/audit/{audit.go,sections/}` |
| Audit section-registry design | `internal/audit/audit.go` — "section registry runs in registration order = Python's code order"; `RegisterAuditSection` rejects duplicates; comment: "the Audited registry lists exactly the six P0 names" |
| Gate reports at `docs/gates/P{n}-gate.md` | `docs/gates/P0-gate.md` … `P4-gate.md` (+ `golden-v2..v4`, `v16-*`) |
| Exit code 3 = needs-model | `internal/cli/cmd_run_test.go` asserts `"status": "needs-model"` and exit 3 (`cmd_sequence_test.go`: "no attempts yet -> FAIL, exit 3") |
| OQ3 resolved with jsonschema/v6, no qri-io fallback | P0-gate §6: `972 (doc, schema) pairs, 0 mismatches` on the 27 schemas, 2026-09-08 |
| P0 gate 7/7 PASS | P0-gate verdict: "ALL SEVEN ITEMS PASS — the P0 gate is OPEN (2026-09-08)". Key numbers: pytest `1146 passed, 1 skipped … in 172.10s`; golden 6 tree files byte-MATCH incl. `events.jsonl`, shared `snapshot_id` `src-afb393bd-f1225bb346d5`; `go test ./...` 0.25s, `-race` 1.45s; testmap 1096 rows (56 real P0-slice: 1:1=53, merged=3); coverage floor **44%** (1,436/2,556 stmts; audit 52%, cli 31%, snapshot 92%, state 66%, validation 81%) |
| `-race` as a hard gate + Go==Go determinism | `scripts/verify-full.sh` steps 4 and 5 |

### 4.2 Contradicted, superseded, or never landed

| # | Design said | Tree today |
|---|---|---|
| 1 | **Cross-twin byte-exactness** is DoD items 2–3; `scripts/golden.sh` diffs Python vs Go; P4 keeps "a pinned Python env for golden regression" | The Python twin was **retired 2026-09-09** (the day P4 closed) and `golden.sh` is Go-only. `docs/archive/KNOWN_DIVERGENCES.md` banner (quote): "**Source-of-truth change (2026-09-09).** The Python twin is **retired** (operator decision; `docs/gates/P4-gate.md` §9.1): the Go port is now the source of truth and is no longer tracked for byte-compatibility with Python." `verify-full.sh` header: "The twin was retired 2026-09-09 … step 9's committed fixture carries the reader-compatibility half of that coverage with zero external dependencies." The Python tree still exists at `../web3sec-final` (58 `.py` files, 30,570 lines) but is not exercised by any gate |
| 2 | Clock seam: `WEBV2_TEST_CLOCK` honored **only** in `testclock`-tagged builds; "the default production build refuses the env var at startup" (OQ4) | Implemented instead as `WEBV2_NOW` (+ `WEBV2_UUID` pinned id stream) with **no build tag**: `testclock` appears nowhere in any `.go` file (only in this design and `docs/superpowers/plans/2026-09-08-p0-trust-core.md`). The analogous production-refusal guard exists only for build identity — `internal/version/version.go`: "A stamped production binary ignores it — the environment must never be able to fake a release build" (`WEBV2_BUILD`) |
| 3 | uuid4 = `crypto/rand` only ("no `google/uuid`") | True for the default, but a golden hook was added: `internal/state/id.go` — when `WEBV2_UUID` is set, `newId` derives `sha256("<seed>:<counter>")[:16]` with version/variant bits forced ("the exact same derivation the Python twin performs"), plus `ResetIDStream()`; unset falls back to `crypto/rand` |
| 4 | `dlclark/regexp2` lands with P2 for "the 6 lookahead/lookbehind patterns … impossible in RE2" | **Never in `go.mod`** and no Go file imports it (`go.sum` retains stale `regexp2 v1.11.0` lines, added at P0 commit `4bd064b0`). Instead `internal/structidx/pyre.go` is a hand-written backtracking engine with Python `re` semantics ("a backtracking engine over a parsed AST with Python's preference order … only the incompatible ones compile here"), and the other sites restructure the patterns (`internal/sandbox/envseam_classify.go`, `internal/envgo/classifier.go`, `internal/sandbox/profiles.go` `ruleViolated`, `internal/findings/ingest.go`). Gate item 9 (regex-hazard grep against a regexp2 allowlist) does not exist in `verify-full.sh` |
| 5 | "go.mod at P0: only jsonschema/v6 + go-toml/v2"; yaml.v3 lands with **P3**; "no dependency outside this table without a design addendum" | `go.mod` today requires 4 modules: `pelletier/go-toml/v2 v2.4.3`, `santhosh-tekuri/jsonschema/v6 v6.0.3`, `golang.org/x/text v0.39.0`, `gopkg.in/yaml.v3 v3.0.1`. yaml.v3 actually landed at **P1** (commit `357edf24`, "P1 Task 3: taxonomy + capabilities + floors packages"). `x/text` is a **fifth direct dependency** absent from the design's table — present as an indirect requirement from the P0 schema-validation commit `b0918907`, promoted to direct at `aa98a216` (P1 Task 1) for Python-faithful `str.lower()` in the findings-signature path. No design addendum for either was found in the tree. `x/text` was bumped to v0.39.0 with toolchain go1.26.6 by advisory commit `ac11de2c` (govulncheck) |
| 6 | "27 embedded" schemas; gate item "schema compile + `KNOWN_SCHEMAS` count (27) test" | `assets/schema/*.schema.json` = **35** today. `assets/schemas.go` records why: "taxonomy_aliases (Task 24, G12) and operator_facts (Wave I Task 8, I4) are Go-native — no Python twin defines them" |
| 7 | "the Go suite is expected to be **substantially smaller** than the Python suite's ~1,052 test functions; a near-1:1 function count would be a smell" | Inverted. P4-gate §7 (2026-09-09): 1,378 reference functions → 1,378 real Go rows (1,364 1:1 + 14 merged), **1,963 Go `Test*` functions across 62 packages** (79,643 non-test lines). Today: **4,203 `func Test`** in **661** test files, 137,011 non-test lines across `internal/` + `cmd/` |
| 8 | Python baseline: 52 modules, ~23.4k LOC, ~1,100 tests, ~1,052 functions, 106 test files | Stale even at P4: P4-gate cites reference `web3sec-final` HEAD `2e41cd2` with **1,378 test functions**. Today `web3sec-final/src/webv2` has 58 `.py` files (54 top-level), 30,570 lines |
| 9 | `testmap.json` at repo root; `KNOWN_DIVERGENCES.md` at repo root; `scripts/sync-assets.sh`; per-phase plans in `docs/plans/` | All moved/renamed: `docs/archive/testmap-2026-09.json`; `docs/archive/KNOWN_DIVERGENCES.md` (947 lines, D-rows D1…D30+); `scripts/archive/sync-assets.sh` (replaced in the gate by the committed `assets/testdata/asset_manifest.json`, asserted by `verify-full.sh` step 6); plans live in `docs/superpowers/plans/` (25 files) |
| 10 | Gate items 5, 6, 7, 9 (CLI golden tables, benchmark thresholds, testmap accounting, regex-hazard grep) | Only partly survived. `verify-full.sh` today is **14 steps**: 1 vet · 2 build · 3 test · 4 `-race` · 5 Go==Go determinism · 6 asset-pack manifest · 7 `golden.sh` · 8 crash smoke (truncated `events.jsonl` must "produce a verdict, not a panic") · 9 legacy cross-audit of a committed reference-written fixture · 10 P1 CLI smoke (21 commands, documented exit codes) · 11 P2 CLI smoke · 12 P3 CLI smoke · 13 runbook walkthrough · 14 entropy ratchet. There is **no benchmark step and no `func Benchmark` in the tree** (the two files named `*_benchmark.go` define business functions `BenchmarkReport`/`BenchmarkCase`, not Go benchmarks), **no coverage-floor step**, and **no testmap reconciliation step** |
| 11 | `scripts/golden.sh` = the P0 8-step recipe, cross-twin | `golden.sh` is now **v5, Go-only**: a **179-step** sequence of fresh processes with pinned clock/id stream, an isolated global memory store, committed P4 fixtures behind `WEBV2_POC_ROOT`/`WEBV2_EVAL_DIR`/`WEBV2_SFT_STORE`, a `gofmt -l` pre-gate, and `check-golden.py` validating declared exit codes, the event chain and the rendered audit sections |
| 12 | `internal/audit` "each of the 12 audit sections is a registered function"; 6 live in P0 | Reference had 14 (D2 row: `event_log`, `artifacts`, `execs`, `findings`, `projection`, `snapshots`, `relations`, `floor_policy`, `stage_completions`, `baselines`, `invariant_verification`, `sequence_coverage`, `probe_surface`, `unpriceable`). Today `verify-full.sh` counts **19 registered**, 16 rendered by a plain campaign, with 3 presence-gated (`eval`, `price_table`, `exec_record_anchor`) and `v16_coverage` unconditional |
| 13 | CLI "~70-command parity surface"; exit codes 0/1/2/3 | Grew: 90 `ord:` registrations across `internal/cli/*.go` (125 non-test `cmd_*.go` files) today; P4-gate places `sft` at order 66 and `selftest` at order 67. Exit codes held, though the P0 provenance block in `internal/cli/cli.go` records "exit codes are 0 ok / 1 handled error / 2 usage error" and adds `help` as additive |
| 14 | `internal/validation/canon.go` is the canonical encoder; import cycles broken "with small interface packages or function parameters" | No `canon.go`. The encoder is `internal/jval` (a new **leaf** package: `value.go`, `parse.go`, `accessors.go`) with `validation` re-exporting type aliases/forwarders in `jval_alias.go` "because package assets must build ordered values without importing validation (validation reads its schemas from assets — the edge would cycle)". `PythonFloat` lives at `internal/jval/value.go:427`; `validation` adds `pyrepr.go`, `pyrepr_table.go`, `sortedkeys.go`, `pyround.go`, `pystr.go`, `pytruthy.go`, `atomicio.go`. Python's import-time wiring became `initWire*()` functions in `cmd/webv2/main.go` ("the cross-module seams (Python's import-time connections, in one place)") |
| 15 | "No external CI today (no remote)"; verify-full maps 1:1 onto 5 GitHub Actions jobs when a remote appears | A remote now exists (`origin git@github.com:AlexandreColauto/web3sec-go.git`) and so does CI — but **not** the designed 5-job matrix: `.github/workflows/ci.yml` (51 lines, commit `c4fc2147` "ci(J): minimal green gate — build, vet, tests, golden") is one job "build, vet, tests, golden" running `go build`, `go vet`, `go test ./... -count=1`, `bash scripts/golden.sh`; no `-race`, no lint/schema/coverage jobs (Python is set up for the golden harness, not for a twin) |
| 16 | Embedded asset set: `schema/`, `prompts/`, `prompts_legacy/`, `playbooks/`, `archetypes/`, `config/` | `assets/config/` does not exist; the tree carries `assets/{archetypes,evalsuite,playbooks,prompts,prompts_legacy,protocol,runbook,schema,taxonomy,testdata}` — `protocol/`, `taxonomy/`, `runbook/`, `evalsuite/`, `testdata/` are additions the design did not list |
| 17 | Package names per Appendix A (`protograph`, `fork_poc`, `sequence_poc`, `env`, `bounty_policy`, "structural index", "shared memory", "history mining") | Renamed in Go: `protocolgraph`, `forkpoc`, `sequencepoc`, `envgo`, `bounty`, `structidx`, `sharedmem`, `histmining`. `internal/` holds **67** packages today — more than the design's ~52 modules, including Go-native ones (`jval`, `regression`, `backtest`, `feed`, `reviewsession`, `probes`, `solscope`, `srcclass`, `textsim`, `wilson`, `roles`, `adapter`, `anchorlink`, `classweights`, `harness`, `boundary`) |

### 4.3 Contradiction inside the tree's own record (flagged, not resolved)

`docs/gates/P4-gate.md` (2026-09-09) says the cutover is **not** triggered — "**The cutover itself is
NOT triggered by this gate.** The rule requires the golden suite to be green for *two consecutive
weeks of real campaign use* after P4; that clock starts now" — and records the operator ruling
"**Operator decision (2026-09-09): the Python repository is not touched** — no tag, no banner, no
archival step; it remains fully developable and the reference implementation."

`docs/archive/KNOWN_DIVERGENCES.md`, same date, says the opposite: the twin is retired and Go is the
source of truth. A future reader should treat **the divergence banner + `golden.sh` (Go-only) as the
operative state** and `P4-gate.md` §9.1 as the decision it cites, but note that the two documents
describe incompatible worlds on the same day. Neither the design's DoD items 2–3 (cross-twin byte
identity, bidirectional audit) nor its P4 archival procedure (tag `webv2-python-final`, deprecation
banner, pinned-Python regression) was executed as written.

### 4.4 One more law the tree broke

Design risk R7 required "no behavioral changes inside port PRs (changes go through Python first,
then port)". P4-gate §9 item 3 records the opposite disposition for four rows: D23 "CLOSED as a fixed
papercut (the row documents the permanent reference divergence)" and "D14 … and D30 … are
FIXED-IN-GO the same day (schema widened / positional rebound), each with a regression test; the
golden recipe and `verify-full.sh` still omit those two paths so the byte-diff against the buggy
reference stays green." So Go-side behavior changes were made while the twin was still nominally the
reference, and the gate was kept green by omitting the paths — a deliberate, documented departure
from the design's R7.

## 5. What a future reader needs if the Go port is ever revisited

### 5.1 Authority: which document governs what

| Document | Where it lives now | Standing |
|---|---|---|
| `GO_REWRITE_SPEC.md` (the *what* / behavioral contract, DRAFT v1) | `../web3sec-final/docs/GO_REWRITE_SPEC.md` (162.9 KB) — **outside this repo**, in the retired twin | Still the only statement of the behavioral contract; the design's precedence rule ("the **Python code wins**") is now moot because the twin is retired and Go is the source of truth |
| This design (the *how*) | `docs/superpowers/specs/2026-09-07-go-rewrite-design.md` → this digest | Approved 2026-09-07, revised `2cbcc6ca`; its phase plan is superseded by the actual tree |
| Per-phase plans | `docs/superpowers/plans/2026-09-08-p0-trust-core.md` … | 25 files; the P0 plan still repeats the `WEBV2_TEST_CLOCK` rule (line 26) and records the switch to a `WEBV2_NOW` pin (line 727) |
| Gate evidence | `docs/gates/P0-gate.md` … `P4-gate.md`, `golden-v2..v4`, `v16-*` | The authoritative numbers (pytest counts, coverage %, byte-match lists, commit shas) |
| Divergence ledger | `docs/archive/KNOWN_DIVERGENCES.md` (947 lines) | D-rows are the live/historical record; "New Go-only bug-fixes … carry **no row here**" since 2026-09-09 |
| Test accounting | `docs/archive/testmap-2026-09.json` | Last reconciled at P4: 1,378 rows, 1,364 1:1 + 14 merged, 0 deferred stubs |

### 5.2 Design commitments that never landed (candidate work if revisited)

1. **Benchmarks with regression thresholds** (gate item 6; bulk tree hashing, merkle, snapshot copy, index parse). Zero Go benchmark functions exist today, and `verify-full.sh` has no benchmark step — despite the design calling bulk hashing "a stated reason for Go, so it is measured".
2. **Coverage floor enforcement.** Measured once at P0 (44% floor for the P0 slice) and never re-asserted: no coverage step in `verify-full.sh`.
3. **`testmap.json` accounting in every gate** (risk R8). Reconciled at P4; no longer part of `verify-full.sh`, and the file now sits under `docs/archive/`.
4. **Regex-hazard lint** (gate item 9, regexp2 allowlist with a comment per entry). Not in `verify-full.sh`; regexp2 itself never landed (see §4.2 #4) — the lookaround semantics live in the hand-written engine `internal/structidx/pyre.go`.
5. **`WEBV2_TEST_CLOCK` production refusal** (OQ4). `WEBV2_NOW`/`WEBV2_UUID` are honored unconditionally; no `testclock` build tag exists.
6. **CLI golden tables** as designed (item 5). Replaced by three per-phase smoke steps with documented exit codes.
7. **Crash-consistency fault injection** across every write site. Narrowed to `verify-full.sh` step 8 (audit/verify on a truncated `events.jsonl` must not panic).
8. **Adversarial argv/shell fixtures in *both* implementations** (R14). Adversarial coverage exists in Go tests (e.g. `internal/sequencepoc/driver_test.go`, `internal/findings/*`, `internal/harness/*`), but the design's both-implementations comparison is impossible now and no gate step asserts the fixture set — flagged as partially verified.
9. **The 1:1 dependency table's own rule** ("no dependency outside this table without a design addendum"): `golang.org/x/text` (direct since P1) has no addendum in the tree; yaml.v3 landed a phase early.

### 5.3 Numbers that must be re-measured before anyone cites them

The design's baseline figures are stale (see §4.2 #7/#8): "52 modules / ~23.4k LOC / ~1,100 tests /
~1,052 functions / 106 test files / 27 schemas / ~70 commands" versus, today: 35 embedded
`*.schema.json`, 67 `internal/` packages, 4,203 Go test functions in 661 test files, 137,011
non-test Go lines, 90 CLI `ord:` registrations, and a Python twin frozen at
`web3sec-final` HEAD `2e41cd2a457dbf72e691f7f5c4cc8402dc59c86f` (2026-09-09 00:18:53 +0100; the last
commit the twin received — consistent with the retirement the same day).

### 5.4 Reference shas and dates for citation

| Event | Ref |
|---|---|
| Design written | `ee9b895e` (2026-09-07) |
| Design revised (test merging + hardening + KNOWN_DIVERGENCES) | `2cbcc6cab69834a6c8dfa969fc6788d5c87523b5` (2026-09-08 00:47:37 +0100) |
| P0 gate open, 7/7 PASS | `docs/gates/P0-gate.md` (2026-09-08) |
| P4 gate green, 6/6 deliverables | `docs/gates/P4-gate.md` (2026-09-09); port HEAD `1254db0` + T37 working-tree changes; reference HEAD `2e41cd2` |
| Twin retired (Go = source of truth) | `docs/archive/KNOWN_DIVERGENCES.md` banner, 2026-09-09 |
| Dependency commits | `b0918907` (P0 jsonschema + x/text indirect), `4bd064b0` (P0 baseline; regexp2 lines appear in go.sum), `aa98a216` (P1 Task 1: x/text direct for `str.lower()`), `357edf24` (P1 Task 3, yaml.v3), `ac11de2c` (x/text v0.39.0 + go1.26.6) |
| CI added | `c4fc2147` — one job: build, vet, tests, golden |
| Digest measurement point | `2771d4661985f18c45b8f1702275023673ae1cc1` (2026-09-23) |

### 5.5 Reproduce the state a revisit would inherit

```bash
cd web3sec-go
bash scripts/verify-full.sh      # 14 steps, fail-fast, names the failing step
bash scripts/golden.sh           # Go-only v5: 179-step recipe + gofmt pre-gate
go test -race ./...              # design's hard gate (not in CI today)
python3 scripts/check-golden.py  # golden validator (rendered audit sections, event chain)
```

Fixtures/inputs the design's contract depends on and that still exist: `assets/testdata/asset_manifest.json`
(embedded-asset pin, gate step 6), `scripts/legacy/campaigns/` (reference-written campaign for step 9),
`scripts/golden/{fixtures-surface,p4,scorecard-fixture}/`, and `docs/archive/testmap-2026-09.json`.
If byte-parity against Python is ever wanted again, the last known-green cross-twin run is recorded in
`docs/gates/P4-gate.md` §8: 179 commands × 2 twins, 68 tree files byte-MATCH, `14 audit section(s) + ok
MATCH (py-only: none)`, plus the Docker e2e (`scripts/p2-docker-e2e.sh`: "11 commands x 2 twins, 21 tree
files, real docker exec + real anvil sequence, byte-identical") — and the twin it compared against is
`web3sec-final` HEAD `2e41cd2`.


---

# Digest §II — the trust-boundary-hardening trail

# Digest — The trust-boundary-hardening trail (2026-09-17/18)

Sources digested: **all 48 top-level files in `docs/sdd/`** (the 34 `task-*` report/review files,
the 3 ledger/verdict files `progress.md` / `critic-round-1.md` / `critic-round1-fixes.md`, and the
11 logs `f1-race-diagnosis.txt`, `f1-red-race.log`, `f1-mutation-race.log`,
`f1-mutation-nolock-race.log`, `f1-green-race.txt`, `f5-red.txt`, `f5-golden.txt`,
`final-gates.log`, `verify-full-final.log`, `verify-full-final-head.log`, `release-final.log`).
The subdirectories `v16-recon/`, `v16-p0/`, `v16-p1/`, `gold-plan/` are out of this section's scope.

Conventions: **quoted text is verbatim from a source** (blockquote or backticks). Commit shas appear
as the sources print them (mostly 8-char); full shas were resolved with `git rev-parse` where the
sources gave them. Every number is labelled with what it measures. All these files were about to be
deleted from the working tree, so this digest is the browsable copy; the underlying files remain in
git history (`docs/sdd/` is tracked — 96 tracked paths at the time of writing, `git ls-files docs/sdd`).

---

## 1. What this trail was (the plan it executed, its base/head commits, its size)

### 1.1 The plan

- **Plan:** `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` — referenced by every
  task as "v3" / "plan (2026-09-17-trust-boundary-hardening.md, v3)", read with its header, its
  **Global Constraints** (v3) and, from Task 5 on, a "Phase B preamble".
- The plan document was **untracked in the main checkout** when Task 1 ran (`task-1-report.md`
  concern 1: "The plan document is not present in this worktree … the file is **untracked in the
  main checkout** (`?? docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md`)"); it was
  committed afterwards as **`e4a3dc01`** — `docs: add production-readiness implementation plan
  (approved v2)`. `task-1-review.md` therefore corrects the dispatch range: "the plan doc itself
  landed afterwards in `e4a3dc01`", and future Task-N dispatches should use plan-commit-relative
  ranges (`e4a3dc01..`).
- The plan was **revised once under operator ruling**: `progress.md:30` — "Operator approved the
  three corrections (\"yep\"); plan revision committed as `913b089e`" (`docs(plan): correct evidence
  legacy and release acceptance`). A second plan edit, **`78f755bb`** (`docs(plan): add Task 16 from
  Task 1 review (yaml duplicate-key law)`), added Task 16 to the plan.

### 1.2 Base, head, branch, size

| Fact | Value | Source / verification |
|---|---|---|
| Base (merge base) | `b0006c4abb0735cf4e93789b3b59cc6a91d48d81` (`b0006c4a`) | `task-1-report.md`, `critic-round-1.md`; `git rev-parse` confirmed |
| Branch / worktree | `production-readiness` @ `.worktrees/production-readiness` | every task report; main checkout untouched |
| End of the 16 plan tasks | `16b3bc3a` | `progress.md:63`; `critic-round-1.md` range `b0006c4a..16b3bc3a` |
| Critic-round-1 range size | **30 commits** | `critic-round-1.md`; independently re-counted: `git rev-list --count b0006c4a..16b3bc3a` = 30 ✓ |
| Final HEAD of the trail | `10182b5c90ca09e4620072e8af4c8841a8c23916` (`10182b5c`) | `progress.md:73`; `git rev-parse` confirmed |
| Commits since base | `progress.md:73` says **44**; `git rev-list --count b0006c4a..10182b5c` = **39** | **CONTRADICTION — see §1.3** |
| Push/merge state at the time | "NOT pushed/merged (operator approval pending by design)" | `progress.md:73` |
| Push/merge state now | `10182b5c` is an ancestor of `main` (the `production-readiness` branch no longer exists in this checkout) | `git branch -a --contains 10182b5c` → `* main`, `remotes/origin/main` |
| Size of the durable trail | `docs/sdd/` = 47 files when committed (`progress.md:70`); the copies are 20 `task-*-report.md`, 14 `task-*-review.md`/`-fix1-review.md`, 2 critic files, `progress.md`, 2 `verify-full` logs, `final-gates.log`, 7 per-fix evidence files | `critic-round1-fixes.md` F4 list; matches this section's 48-file source set |

**Full ordered commit list** (`git log --oneline --reverse b0006c4a..10182b5c`, 39 commits — the
authoritative spine of this trail; every task sha below appears in it):

```
115ba97f fix(jval): reject duplicate JSON object keys
e4a3dc01 docs: add production-readiness implementation plan (approved v2)
b47d893e fix(sandbox): honest network labels for host profiles
bbe5a030 fix(invariants): per-machine liveness coverage gate
78f755bb docs(plan): add Task 16 from Task 1 review (yaml duplicate-key law)
37511ec8 fix(invariants): evidence relevance binding on invariant-verify
1e6412e5 fix(state): artifact-register deduplicates by resolved path
913b089e docs(plan): correct evidence legacy and release acceptance
32ce5578 fix(release): require successful dependency scan for release
b00532ca fix(validation): reject duplicate YAML mapping keys
521eecfd fix(invariants): disclose operator attestation provenance
f13ae1df test(invariants): re-pin twin fixtures for attestation field (additive)
f837a26a fix(cli): index emits registry refresh events for rewritten artifacts
dae1c42f fix(orchestrator): brief next-actions are copyable webv2 commands
bd14d44b fix(snapshot): summarize re-pin exclusions with exact count
fc9241d4 fix(release): security-check uses repo Go cache convention
ac11de2c fix(deps): advisory-driven bump x/text v0.39.0 + toolchain go1.26.6 (govulncheck)
b77eb7fa fix(orchestrator): next-actions close their proofs (review round 1)
eb44603a fix(envgo): missing toolchain classifies ENVIRONMENT per runbook
cbdd93d5 feat(orchestrator): open questions rank into the work queue
c15a1291 feat(briefing): cold probe surface warning during discovery
1a03c8ca feat(orchestrator): additive risk-weighted queue ordering
6fdec840 fix(envgo): tighten tool-absence matching boundaries and precedence
e303fbd3 fix(release): security-check forces repo Go cache like verify-full
7287e5bb docs: add SECURITY.md release assurance summary
a79c3fb6 docs: reconcile README and runbook with hardened behavior
fabc7d18 feat(briefing): surface open-question rows in brief
4fa0aef0 test(planner): pin coverage-swept parity
0f881e55 fix(release): force repo Go cache in release and walkthrough scripts
16b3bc3a docs: record production-readiness wave in IMPROVEMENTS
1130e324 fix(state): race-detector-aware lock budget in concurrent test
91437a44 test(planner): pin open-question row counting
4382e586 docs(sdd): record SDD ledger and review trail
2e9ff576 fix(release): verify-full step 12 accepts presence-gated sections.
656d2e4b docs: correct fork RPC env var and vm-snapshot availability note.
64b6eefa docs: correct fork RPC env var in runbook and notes.
df9ae26b docs(sdd): refresh critic fix trail with verify-full green state.
8fabb878 docs(sdd): refresh ledger copy to current state.
10182b5c docs(sdd): archive green release run at final HEAD.
```

### 1.3 Contradictions and gaps in the record (stated, not resolved)

1. **Commit count.** `progress.md:73` says "44 commits since `b0006c4a`"; git says **39**. The
   ledger's own critic-round-1 count (30 for `b0006c4a..16b3bc3a`) is correct. No other source
   gives a count, so the 44 is unexplained (it is not 39 + the 4 post-`16b3bc3a` commits either:
   39 + 4 = 43, and `16b3bc3a` is commit #30).
2. **`critic-round-2.md` is not in this durable set.** `progress.md:72` records "Critic round 2 =
   9/10 (`.scratch/sdd/critic-round-2.md`)" but that file was never copied to `docs/sdd/`; only the
   ledger's summary survives. The ledger lines it closes are N1 (stale ledger copy → `8fabb878`) and
   N2 (missing RELEASE OK log → `10182b5c`, archived as `docs/sdd/release-final.log`).
3. **`task-6-review.md` accepted green evidence from logs it did not re-run**, and `task-10-12-review.md`
   could not re-run `go test` at all ("read-only module cache") — both say so explicitly. Those gate
   results are attested, not independently reproduced, in exactly those two reviews.
4. **`f1-green-race.txt` is a single line** (`ok websec/internal/state 195.626s`) with no header, no
   HEAD, no command; the `-count=3` claim comes from `critic-round1-fixes.md`, not from the file.

---

## 2. The ledger: operator rulings and the controller's verdicts

Three files carry the rulings: `progress.md` (the append-only ledger, 73 lines, ends at the final
state), `critic-round-1.md` (the independent critic's report, verdict 7/10) and
`critic-round1-fixes.md` (the fix wave's closure record + Wave 2 + Wave 2 addendum).

### 2.1 Operator rulings (quoted)

| # | Ruling | Where |
|---|---|---|
| R1 | "Task 3: plan-internal conflict ruled by orchestrator: the Law section (refusal names UNCOVERED machines) governs over the skeleton test comment naming the covered machine; implementer asserted the law (names relay, staking; not vault-lifecycle). Reviewer to verify." | `progress.md:7` |
| R2 | "Task 3: orchestrator ruling recorded — law section governs over skeleton comment (uncovered names); concern 4 semantics ruled correct by reviewer (zero coverage across modeled machines = synthesis)." | `progress.md:10` |
| R3 | "Operator approved the three corrections (\"yep\"); plan revision committed as `913b089e`. Historical fixtures immutable, attribution not semantic proof, unavailable release scan cannot pass." | `progress.md:30` |
| R4 | "Task 4A: next correction is explicit operator-attestation provenance and disclosure; it must not produce or upgrade a mechanical harness outcome. Historical missing method is legacy-unspecified, never inferred as mechanically verified." | `progress.md:36` |
| R5 | "Task 4A: open ruling from implementer concern 1 RESOLVED by orchestrator under the plan's deliberate-pin-update Global Constraint — testdata files are pinned expectations, not scripts/legacy compatibility fixtures; re-pin + rename documented in commit body" | `progress.md:39` |
| R6 | "Routing update (operator): reviewers now b-ai/glm-5.3-flash" | `progress.md:43` (earlier: "re-dispatching on b-ai-plain/qwen3.8-flash (operator-directed fallback)", `progress.md:3`; `task-7-report.md` records 3 deepseek null returns before the glm-5.3-flash swap) |
| R7 | "Critic round 1 F3 RULING (operator-scoped fix wave): the critic loop IS the plan-mandated final whole-branch review — `.scratch/sdd/critic-round-1.md` is the independent, read-only MERGE_BASE..HEAD sweep (`b0006c4a..16b3bc3a`) the plan's execution order promises, and the F1/F5 fix wave below is its one scoped re-review; no separate artifact is owed, and none is claimed." | `progress.md:64` |
| R8 | Step-12 ruling request → decision: "operator ruling requested: teach `p2_sections_ok` the presence-gated tail, or rule `price_table` a product bug" (`progress.md:68`); then "ruling: implement option (a) with audit-code verification" (`progress.md:70`). Option (a) = teach the helper the presence-gated tail (see §5). | `progress.md:68,70` |

### 2.2 The controller's three production-acceptance corrections (quoted, and the reason each exists)

`progress.md:24-30` records a "Controller checkpoint: production acceptance conflicts":

> "Task 4: reviewer returned spec YES / quality APPROVED, but controller found a plan-level acceptance gap: textual mention of an invariant/contract establishes attribution, not that the property was checked. Do not describe this as semantic evidence verification. Resolve the acceptance contract with the operator before further reliance on this status."

> "Task 5: implementation commit `1e6412e5` is test-only; deduplication already existed. Independent task review remains pending. Do not claim a production bug was fixed."

> "Legacy instructions to sanitize historical fixtures conflict with immutable compatibility evidence. Preserve original fixtures; any migration must be explicit and tested separately."

> "Task 13's network-error exit 0 conflicts with release assurance. An unavailable scan must remain visibly incomplete, not satisfy production acceptance."

> "Controller verification: focused `go test ./internal/jval -run '^TestParseOrdered' -count=1 -v` passed (2 tests), clean worktree at `1e6412e5`. This does not establish full production readiness."

The critic independently credited these as the branch's best honesty signals: "the three
operator-corrected acceptance rules are genuinely delivered and independently re-verifiable"
(`critic-round-1.md` SCORE), and singled out Task 5: "Task 5's premise-fabrication trap was
**avoided**: the implementation was already correct, the commit (`1e6412e5`) says so explicitly, the
ledger says 'test-only pin … Do not claim a production bug was fixed', and the counterfactual (route
the verb through `RegisterArtifact`) is pinned red. This is the single best honesty signal in the
wave." (`critic-round-1.md`, honest-limits section).

### 2.3 The critic's verdicts

**Critic round 1 = 7/10** (`critic-round-1.md`, range `b0006c4a..16b3bc3a`, 30 commits; critic ran
every gate itself):

> "**7/10** — the engineering substance, honesty discipline, and the three operator-corrected acceptance rules are genuinely delivered and independently re-verifiable, but the plan's own Definition-of-Done gate `verify-full.sh green at final HEAD` is **false on this machine** (deterministic `-race` failure in `internal/state`), and independent-review evidence is not persisted for roughly a third of the tasks."

Its findings (severity as filed): **F1 CRITICAL** (verify-full red at step 4; ledger's "all final
gates green" overstates), **F2 IMPORTANT** (no persisted review artifacts for Tasks 1/2/3/4/8/14/15),
**F3 IMPORTANT** (plan-mandated whole-branch review never produced an artifact), **F4 MINOR**
(`.scratch/sdd/` untracked), **F5 MINOR** (Task 12 double-counts an open question naming two
components of one row), **F6 MINOR** (parked residuals: unbounded YAML alias traversal,
`shellAbsentRe` colon-widening, govulncheck PASS semantics).

**Critic round 2 = 9/10** (`progress.md:72`): "F1-F5 all ruled genuinely closed (verify-full re-run
GREEN all 13 steps at final HEAD by the critic itself); N1 stale ledger copy + N2 missing RELEASE OK
log closed (`8fabb878`, `10182b5c`; release.sh exit 0, strict scan PASS, RELEASE OK archived in
`docs/sdd/release-final.log`)". The round-2 report itself is not in this durable set (§1.3.2).

### 2.4 The fix wave's own closure rulings (quoted)

The wave opens with the ledger's plan-completion line (`progress.md:63`):

> "ALL PLAN TASKS (1-16) IMPLEMENTED, REVIEWED, FIXES VERIFIED. Critic loop begins."

- **F3 closure** (`critic-round1-fixes.md`): "**Ruling (recorded in the ledger as well): the critic loop IS that review.** … No separate artifact is needed, and none is claimed: the plan text now has its artifact, `critic-round-1.md`, plus this closure record."
- **F1's fail-loud constraint** (`critic-round-1.md` fix text): "deflake the r13 harness for `-race` … do not skip under `-race` — that would be gate-weakening".
- **F5's conservative-direction law** (`critic-round1-fixes.md`): "the count-once rule can only LOWER a weight relative to the per-component sum — **no row is ever promoted by it**".
- **The step-12 refusal to self-fix a gate** (`critic-round1-fixes.md`): "**Not fixed here, deliberately.** The instruction for this wave was to run verify-full to completion, report a failure exactly and stop — and a DoD gate must not be edited green as part of the wave it judges."
- **Wave-2's anti-relaxation rule** (`critic-round1-fixes.md`): "It is deliberately NOT relaxed to a count of 15: a bare 15 would let a never-priced campaign that silently grew a fake row pass."
- **F2's disposition, twice** — first not taken, then closed: "**F2 was not addressed.** … it is a routing/delegation task, not a code fix, and this wave was scoped to F1/F5/F4+F3 by the operator" (`critic-round1-fixes.md`), with the note that `.scratch/sdd/` "**does** contain `task-1-review.md`, `task-2-3-review.md`, `task-4-review.md`, `task-8-review.md` and `task-14-15-review.md`, so part of F2's 'no review recorded' claim looks like a search gap rather than a missing review". Then `progress.md:70`: "F2 closed (all 5 missing reviews run: T1/T2/T3/T4/T8/T14-15 spec YES quality APPROVED; 2 minors: FORK_RPC_URL env var nonexistent [code reads FORK_RPC_URL], vm-snapshot ProfileAvailable-false honesty note)".
- **Superseded-claim discipline** (`critic-round1-fixes.md`, Wave 2 addendum): "**Superseded claim, called out so no reader is misled:** the Wave-1 bullet above that says 'verify-full is still RED at step 12 … the DoD checkbox cannot be checked' is HISTORICAL — true of the tree before `2e9ff576`."
- **FINAL STATE** (`progress.md:73`, the ledger's last line): "branch production-readiness @ `10182b5c`, 44 commits since `b0006c4a`; all 16 plan tasks + Task 16 landed, reviewed (spec YES/quality APPROVED across the board), fix waves verified; every gate green: suite, `-race`, vet, golden, runbook 150/0, security-check-test 56/0, verify-full 13/13, real govulncheck PASS, release.sh RELEASE OK. NOT pushed/merged (operator approval pending by design). Residuals honestly parked: 0/2 gold discovery out of scope; YAML alias traversal cap optional; Windows/macOS unbuildable (documented); operator adjudications pending: bare-metal `-race` sensitivity, advisory-DB freshness ruling on release host, push/merge approval."

---

## 3. Task-by-task record

One row per task/fix round, in commit order. "Gate result" is what the task's own report and/or its
review recorded; where a review re-ran gates, that is said. Deviations are the *disclosed* ones —
undisclosed ones surfaced later are in §7.

| Task | What it built | Commit(s) | Gate result | Disclosed deviations |
|---|---|---|---|---|
| **1** jval | Reject ambiguous duplicate JSON object keys: one `seen` map per object in `parseValue` `case '{'`; error text `json: duplicate object key %q`; `ParseOrdered` signature unchanged | `115ba97f` (2 files, +39/−0) | RED exit 1 (4 dup cases returned `<nil>`, separate-objects case already passed) → GREEN exit 0; `jval`+`validation`+`harness`+`state` ok; full suite exit 0; vet clean; `-run Legacy` ok; **337 committed JSON fixtures scanned, 0 with duplicate keys**; verify-full step 9 replicated PASS (14 sections, `ok:true`) | Plan doc untracked in the worktree (read from main checkout, read-only); full `verify-full.sh` not run end-to-end (only step 9 replicated); `seen` allocates one map per object level (accepted, brief-prescribed); duplicate keys are refused, not canonicalized (behaviour change for previously ambiguous input) |
| **2** sandbox | Honest network labels for host profiles: `networkLabel(profile)`; `Preview` `network` + `environmentValue` `network_access` routed through it; schema enum widened; manifest resynced | `b47d893e` (5 files, +78/−11) | RED #1 compile (`undefined: networkLabel`), RED #2 behavioural (2 tests: Preview/record still `"none"`), RED #3 **13 tests** — every host-profile record write refused by `WriteJson` validation; GREEN `sandbox` 49.2s + `envgo` ok, 71 pkgs ok, vet 0, gofmt 0, golden GOLDEN GREEN, runbook 150/0 | **The brief's file list was incomplete**: `assets/schema/sandbox_execution.schema.json` enum widening + `asset_manifest.json` resync were *required*, not optional (r36 F5 precedent `9641c681`, whose body says "Schema change required an asset manifest resync."); plan self-contradiction on helper placement (Files list says `profiles.go`, Step 3 says next to `profileFilesystemLabel` in `exec.go`) — landed in `profiles.go`; stale host-profile "network none" prose left in `assets/runbook/RUNBOOK.md:67`, `docs/MINICERTORA_INTEGRATION.md:18`, `docs/MINICERTORA_ARCHITECTURE.md:79` → routed to Task 15; 52-char CLI label unpinned by any test/golden; `vm-snapshot`/`docker-gvisor` labels unverified (no VM runtime) |
| **3** invariants | Per-machine liveness coverage gate (the G-01 hole): coverage built from `kind=="liveness"` entries' `applies_to` vs `state_machines[].name`; partial ⇒ refusal naming uncovered machines; zero ⇒ synthesis unchanged; full ⇒ silence | `bbe5a030` (2 files, +172/−5) | RED exit 1 (`expected error containing "…relay, staking…", got nil`) → GREEN; `1182 passed in 3 packages`; `-run Legacy` `23 passed in 73 packages`; full `5017 passed in 73 packages`; vet clean; gofmt clean; E2E partial `PARTIAL_EXIT=2`, zero `ZERO_EXIT=0` | The brief's **skeleton test contradicted the brief's law** (skeleton asserted the error names the *covered* machine `vault-lifecycle`); implementer asserted the law and the orchestrator ruled the law governs (R1/R2); a third test (`TestFullLivenessCoverageNeedsNoTemplate`) was added *after* the implementation, so it has no red run of its own; the shared `modelWithInvariants()` fixture has no `state_machines`, so a local `livenessMachinesModel()` literal was used; semantics change — a liveness entry with empty/non-model `applies_to` now *synthesizes* where the old global presence check stayed silent (ruled correct) |
| **4** invariants | Evidence relevance binding on invariant-verify: refusal unless the cited artifact's bytes name the invariant id (raw + `NormalizeInvID`) or an `applies_to` target, `(?i)\b<escaped>\b`; exported `ResolveArtifactPath` wrapper; 11 call-site fixtures made honest; 2 script fixtures re-registered with necessity proof | `37511ec8` (12 files, +470/−14) | RED: 5 invariants tests + 1 CLI test + `internal/state` build failure; GREEN 4 pkgs ok, `./...` 60 pkgs ok exit 0, vet 0, gofmt empty, golden GOLDEN GREEN (196 steps), runbook 150/0; **verify-full RED at step 4 and step 12 — both proved pre-existing on clean HEAD** | Brief premise corrected: the `--exec` registry *note* (`"invariant %s checked against code (exec %s)"`) is written to the registry row, **not** the artifact file, so counting it would make the gate vacuous — the gate reads the captured stdout/stderr instead; token set is a **superset** of the plan's "normalized inv id" (raw + canonical, else honest `INV-002` artifacts would be falsely refused); plan-internal conflict "case-insensitive substring" (L184) vs word boundaries (L222) resolved to the stricter word-boundary reading; unreadable bytes ⇒ the same relevance refusal (fail closed); gate is prospective, not retroactive; bytes read whole; gate judges current bytes, not the registered sha256 |
| **4A** invariants/CLI | Operator-attestation provenance: `verification_method: "operator-attestation"` on the registry entry *and* the `invariant.verified` event; exported `VerificationMethod(entry)` → `operator-attestation`/`legacy-unspecified`/`unrecognized`; CLI stderr disclosure on success only | `521eecfd` (4 files, +342/−10) | Focused `go test ./internal/invariants ./internal/cli` **exit 1** and full `go test ./...` **exit 1** — the *only* failures in the whole tree are the two Python-twin parity tests; vet 0; gofmt 0; the 6 new tests all PASS; red re-derived by stash cycle with md5-pinned restore | **BLOCKING (filed, not fixed here):** byte-parity with the frozen Python-twin fixtures (`scenario_links.json`, `scenario_events.jsonl`, `guard_links.json`, `guard_events.jsonl`, untouched since port commit `32641d7f`) is impossible with the mandated new key — deliberately **not** re-pinned, because re-pinning would make `TestLinkScenarioMatchesPythonTwin` compare against bytes this build produced ("exactly the weakening the brief forbids"); tree therefore **not green** and "must not be reported as passing its gates"; digest/source binding still open; `cmd_invariant_verify.go:239` help line still said "mark an invariant verified" (parked) |
| **4A fix1** | Additive re-pin of the twin fixtures for the one key + rename to Go-pin semantics + help-line disclosure | `f13ae1df` (8 files, +86/−27) | All gates exit 0: focused, full `71 ok, no FAIL/panic`, vet, gofmt, both renamed tests PASS, `-run Legacy` PASS, verify-full step 9 standalone replay PASS; tree hash `f62c95c0a947f94e15328ee0d08fc1b70ab31ec6` unchanged | **Fifth file `scenario_steps.json`** (brief named four) carried the identical sanctioned add (14 adds, 0 other) and was required for exit 0 — disclosed, then **APPROVED** by re-review; `compareTwinFile` identifier kept (2 call sites, out of brief scope); deferred minors: doc-comment name typo (`Matches` vs `Match`), guard comment understates `source`, verified-then-contradicted entries keep `verification_method`, sibling `…PythonTwin` test names |
| **5** state/CLI | Regression pin that `artifact-register` deduplicates by resolved path (5 spellings of one file → one row, one id, 4 refreshes; distinct file still mints) | `1e6412e5` (**1 file, test-only, +130**) | Focused `-run TestArtifactRegister` 6/6 PASS exit 0; `state`+`cli` ok; `-run Legacy` ok; full `57 packages ok` exit 0; vet 0; gofmt clean | **Premise correction: no production change was required** — `resolvePath` (Abs + `EvalSymlinks`) has compared both sides since the P0 port `d07ef68d`, and the verb has routed through the seam since r34 F3 (`af3be559`, 2026-09-15); red was proved by two counterfactuals instead (append primitive → 4 ids; `Abs`-only compare → symlinked spelling mints a new id); Low-1: CF1's transcript shows a 4-element id list against a 5-spelling test (captured on an earlier draft); Low-2: no Task 5 gate logs captured (gate table prose-only); Info-3: the symlink-to-file and hard-link arms live only in a deleted scratch probe |
| **6** CLI/state/structidx | `index` rewrite + registry row + `artifact.refreshed` in **one lock window**: `SaveIndexIfChanged`, `RegisterOrRefreshIfChanged`, `runIndex` holds the campaign lock | `f837a26a` (5 files, +694/−7) | RED: unchanged rebuilds appended **2** events (want 0); ten concurrent rebuilds of one changed tree emitted **10** `artifact.refreshed` (want 1); GREEN: `-race` 1.42s, `-race -count=3`, focused, full exit 0, vet 0, golden 196 steps/179 events/chain intact, runbook 150/0 | `orchestrator.BuildStructuralIndex` keeps the old write-then-lock shape (out of file scope; **follow-up required**); Minor 4: `EnsureFreshIndex` shares that shape and *is* CLI-reachable (`cmd_dedup.go:334`, `archetypes/prescreen.go:41`, `corpus/report.go:37`, `histmining/recency.go:101`, `structidx/queries.go:396`); `created_at` is now "last semantic rebuild"; the lock window excludes the index build (pre-existing pin-move race); kept-ghost rows not re-hashed (pre-existing r35 F1); Minor 1: the saved red log is truncated (1528 B, ends mid-JSON, spurious `exit=0`) so the headline 10-event line is absent — defect proved by construction instead; Minor 2: Global Constraints' `-race` on `./internal/state` not recorded; Minor 3: "tampered files always differ" overstated |
| **7** orchestrator | `brief` next-actions become copyable `webv2 …` commands: `phaseActions` catalog rewritten, proof "teeth", 2 latent shape bugs fixed (`webv2 gate --explain`; ladder slash-joined pseudo-usage), 27 oracles re-recorded | `dae1c42f` (6 files, +517/−83) | RED: **131 failure lines across the 19 phases** (pseudo-API, parentheses, uncovered metavariable) → GREEN focused + full 71 ok + vet + gofmt + golden GOLDEN GREEN + runbook 150/0; E2E on a real campaign: both emitted commands exit 0, `prove --stage protocol-model` exit 1 with the missing item preserved | Scope dispute: the implementer applied the law only at the orchestrator mint; the reviewer **ruled the law covers `briefing.go`'s own mint too** ("The implementer's narrower reading is not supported by the plan text") → Spec **NO (qualified)**, remedy Task 7b; `oracles.json` is now partly Go-authored (27 `next_actions` snapshots; a Python-twin regeneration would revert them); per-item proof prose no longer inlined (moved to `webv2 prove --stage`); two adjacent pseudo-API strings left (`orchestrator/triage.go:220`, `sharedmem/sharedmem.go:385`); metavariables are runnable shapes, not filled values |
| **7 fix1** | C-1/I-1/I-2 + M-1/M-2/M-3 closed at the mint: RISK_CALIBRATION leads `webv2 run`; INDEPENDENT_VERIFICATION leads `webv2 verify --finding --exec --verifier --description` (mint demoted); every `briefing.NextActions` block converted to `webv2 …  # reason`; 9 oracles re-recorded | `b77eb7fa` (15 files) | RED inherited 12 failing tests + new law reds; GREEN focused ok×3, full exit 0 zero FAIL, vet 0, golden GOLDEN GREEN, runbook 150/0 (repo-cache convention) | REPRODUCTION reorder (mint before repro-queue) went beyond the review's letter, justified by generalizing the proof-closing property (upheld); T35 parity assertions re-pinned deliberately in 10 files; `TestNextActionsLeadWithTheProofClosingCommand` covers all 13 proof-bearing phases; deferred minors D-1 (duplicate bare `run` line for IV/RISK_CALIBRATION), D-2 (`--finding ?` fallback), D-3 (ledger commands carry literal `--reason R --actor A`); attention lines minted as bare ledger commands (upheld) |
| **8** CLI/snapshot | Snapshot re-pin exclusion summary: `N paths excluded (first 10): … (+M more — the full list is in the record's source.excluded)`, cap `excludedInlineCap = 10` | `bd14d44b` (2 files; `cmd_snap.go` +27/−2 is the interrupted implementer's hunk, **byte-identical, md5 `541b9f04667873e2de12d1c2f48bec8d`**) | RED (re-derived on the current revision: whole 25-path list on one line) → GREEN 3/3; focused + full `71 ok, 0 FAIL` + vet + golden + runbook 150/0; boundary mutant `>` → `>=` caught; `-run Legacy` tree hash `f62c95c0…` | Two caps for one concept (10 for the pin line vs 40 for the dry-run preview) flagged, not unified; the cap is not documented in the RUNBOOK (routed to Task 15); the inherited red log cited test line 92 while the handed-over test fails at line 93 → red re-derived rather than trusted; inherited `vet.txt` was 0 bytes with no exit code; event assertion could go vacuous (reads the last `snapshot.excluded`); **no `-race` run** (pure string formatting) |
| **9** envgo/sandbox | Missing toolchain/dependency classifies **ENVIRONMENT** per the runbook: `toolAbsentNote` (solc/forge/cast/anvil/docker + shell's own "command not found"), absence precedence over the setup heuristic, fix-naming notes; the identical hunks mirrored into `sandbox/envseam.go`'s `defaultClassifyFailure` (r38 rail) | `eb44603a` (5 files: +108/−1, new 208-line and 68-line tests, +110 mirror, +22 rows) | RED law table 13 FAILs (setup/unknown where environment wanted) + mutation run 20 FAILs + sandbox mirror 5 FAILs; GREEN focused, full exit 0, vet 0, golden GOLDEN GREEN, runbook 150/0 incl. `§6a classify` | `internal/sandbox/envseam.go` changed although the plan's Files line named only `internal/envgo` (unavoidable — leaving the seam fallback stale is the r36 defect class in reverse); `shellAbsentRe` is **wider than the plan's parenthetical** (any `command not found` routes ENVIRONMENT); `docker image … not found` changed class SETUP → ENVIRONMENT with a hedged note; the CLI test's red is mutation-based (authored after the fix); report §3b's quoted `sha256 fd9bf0a11d0e16d7` / 3214 B is not reproducible (cosmetic, flagged by review) |
| **9 fix1** | F1 (leading `\b` in `toolAbsentRe` `tok`) + F2 (precedence: `solcFailed → dockerHit → logicHit → toolAbsent → setupHit → unknown`) in both copies | `6fdec840` (5 files, +141/−18) | RED on all three surfaces → GREEN focused (envgo 0.685s / sandbox 50.039s / cli 32.710s), full exit 0 `71 ok, 0 FAIL`, vet 0, gofmt empty; probe 16 rows + mirror equality PASS | Chose review option (b) over (a) — anchoring `shellAbsentRe` would drop a real bare `jq: command not found` out of the law; **side effect not in the original report: `logicHit` also moved above `setupHit`**, so setup+logic co-occurrence now routes LOGIC (law-consistent, no pinned row exercises it, caught by the re-review); colon-delimited `broadcast: not found` still routes ENVIRONMENT via the unchanged `shellAbsentRe` (pre-existing, byte-identical to base); missing *repository script* not-found unchanged; report's non-reproducible digest left as-is |
| **10** planner | `open_questions` entries naming a contract reference mint a work-queue row `resolve open question <id>: <text>`, ranked in the top 3 when they name consensus-critical/untouched contracts; empty list is a no-op; supplied plans never rewritten | `cbdd93d5` (1 file, +61) | RED witness (no `resolve open question` row) → GREEN focused + full + vet + golden (no pin change) + runbook 150/0 | Spec **PARTIAL**: the law's clause "brief shows it" is **not met** — the brief renders only `attention` + `next_actions`, and the printable attention line names only the oldest untouched priority, so the question's own text is visible only via `webv2 plan --json` and the debt counts; top-3 is *emergent* from slot class + score, not enforced; the report first said the minted row is `risk 0.8`/`budget_class standard`, the code mints **`risk 0.9`/`cheap`** (report correction appended 2026-09-17); fixture placed in a new `task10_open_questions_test.go` instead of the plan's suggested file; closed by `fabc7d18` |
| **11** briefing | Standing cold-probe-surface warning while a campaign is in `DISCOVERY` with no `probes run --emit` on record: `probes.Emitted` scans the ledger for `probes.emit`; the line names the exact command | `c15a1291` (`probes/campaign.go` +19, `briefing/briefing.go` +15) | RED witness (action list missing the line) → GREEN briefing ok; focused + full + vet + golden + runbook 150/0 | Comment-vs-caller mismatch: `campaign.go` says an unreadable ledger is "an error, never a silent 'no': the caller renders it as unknown" while the caller silently **omits** the line on error (behaviour defensible for a non-gate line); the line requires `campaign != nil`, so a hand-built brief with a DISCOVERY phase gets nothing; advisory only — verified no proof/floor/phase transition reads `next_actions` |
| **12** planner/orchestrator | Additive risk-weighted queue ordering: `untouched*1.0 + severity*2.0 + openQ*1.5` (bands critical=3/high=2/medium=1/low=0), slot class primary, ties alphabetical, deterministic; `planQueueModel()` makes the read-back path score the same model as the write path; coverage ledger read **by path** to dodge the test-binary import cycle | `1a03c8ca` (`planner/queue.go` +225, `orchestrator/plan.go` +36) | RED 3 tests (`queue order = [Q-001 Q-002]`) → GREEN planner 0.458s + orchestrator 1.186s; focused + full + vet + golden + runbook 150/0; 25-run determinism | 3 `planned`-scenario plan snapshots re-pinned (order only: `Q-001 Q-002 Q-013 | Q-003 Q-009 Q-010 Q-004 Q-005 Q-006 Q-007 Q-008 Q-011 Q-012`); `coverageSwept` duplicates the ledger's "worked" predicate instead of sharing it — two edge divergences vs `coverage.RefreshGaps`, both conservative → parity pin recommended (closed by `4fa0aef0`); `scoreRow` adds `openQ[ref]` per component → one question naming two components of a row counts twice (**= critic F5**); `touched[path]` last-row-wins; sort lives in `internal/planner` not the plan's `internal/orchestrator` hint |
| **13** deps | Advisory-driven bump: `golang.org/x/text v0.14.0 → v0.39.0` + `toolchain go1.26.6` + one README verification-table row | `ac11de2c` (`go.mod`, `go.sum`, `README.md`) | **Before: `GATE_EXIT=3`** — 10 CALLED (9 stdlib fixed in go1.26.3–1.26.6 + `GO-2026-5970` x/text) plus 5 import-level + 7 require-level uncalled; **After: `GATE_EXIT=0` — "No vulnerabilities found." / `security-check: PASS`**; clean-tree battery: build 0, test 0 (71 ok), vet 0, golden GOLDEN GREEN, runbook 150/0, gate repeat 0 | The brief's advisory ID was wrong: `GO-2026-4970` is a stdlib `os.Root` issue; the real x/text advisory is **`GO-2026-5970`** (ledger corrected); the *literal* briefed command returned `GATE_EXIT=1` post-bump because an inherited `GOPATH=/home/xand/go` defeats the script's `${VAR:-…}` defaults → read-only module cache (both runs kept verbatim, neither presented as the other); the worktree was dirty from the interrupted Task 7 fix1 (status.go + next_actions_cli_test.go, +286/−15) so the battery was run twice; `go.sum` keeps stale v0.14.0 lines (no `go mod tidy`); uncalled findings remain — "PASS" means nothing CALLED is known-vulnerable; `GOTOOLCHAIN=local` on go1.26.2 would fall below the security floor; no verify-full step 14 (gate wired into `release.sh:158` instead) |
| **13A** release | Strict release-scan gate `scripts/security-check.sh` + hermetic tests (missing scanner ⇒ exit 2; PASS only on scan exit 0) | `32ce5578` | Controller ran `bash scripts/security-check-test.sh`: **43 passed / 0 failed**; `bash -n` clean; **actual govulncheck unavailable at that time — no live scan claimed**; release acceptance **INCOMPLETE** at that point | Nit: the test's install-guidance assertion too broad (final fix wave); scanner absent from the box until `.scratch/gomod/bin` was populated |
| **14** docs | `SECURITY.md` (121 lines) — supported platforms/toolchain, scan instructions, advisory-driven dependency policy, attestation-is-not-proof, no offensive-automation claims, trust core, sandbox IS/IS NOT, E-caps and floors, reporting | `7287e5bb` | Cross-build proof: `GOOS=linux` exit 0; `GOOS=darwin` exit 1 (`undefined: setProcGroup`/`killGroup`); `GOOS=windows` exit 1 (`syscall.Flock`/`LOCK_EX`/`Pwrite`); vet 0; full 71 ok, 0 FAIL | 121 lines vs the plan's "~80" (estimate, not a cap; no padding); no security contact exists in the repo, so the section names the mechanism, not an address; Linux statement scoped to `linux/amd64` only; `audit` not documented; review minors: phantom `WEBV2_FORK_RPC_URL` and the `vm-snapshot` "executes a real `docker run`" precision |
| **15** docs | README + RUNBOOK reconcile with hardened behaviour (7 rows) + asset-manifest resync; IMPROVEMENTS wave section | `a79c3fb6` (+ `16b3bc3a`) | doc contract `go test ./internal/cli ./assets/...` 0; runbook 150/0; golden GOLDEN GREEN; vet 0; full 71 ok, 0 FAIL; manifest `--check` current | `docs/IMPROVEMENTS.md` was **not** touched by `a79c3fb6` (dispatch scope said README + RUNBOOK only) and landed later in `16b3bc3a` (process note, append-only +140/−0); `${VAR:-…}` cache defect still in `runbook-walkthrough.sh` + `release.sh` (flagged here, fixed by `0f881e55`); `verify-full.sh` runs no dependency scan — the docs now describe the shipped wiring |
| **16** validation | Reject duplicate YAML mapping keys: per-mapping `seen` map, error `yaml: duplicate mapping key %q`, `VNull()` on refusal; `ParseYaml` signature unchanged | `b00532ca` (`yaml.go` +11/−1, new 115-line test) | RED `EXIT=1` (5 reject subtests) → GREEN `EXIT=0` (10 subtests); 4-pkg focused 0; full `71 ok, 0 FAIL`; vet 0 (empty); gofmt clean | Rendered-key strictness is stricter than PyYAML (`1: x` + `"1": y` refused; null key vs `"None"` refused) — required by the brief, half-pinned (review Low); `<<` merge not expanded (pre-existing); **adjacent unbounded `AliasNode` recursion left unaddressed** ("do not claim general YAML safety"); plain `fmt.Errorf`, no sentinel/`%w`; multi-document input: only the first document is decoded |
| **fix wave** (Phase C + docs residuals) | `fabc7d18` brief surfaces open-question rows; `4fa0aef0` coverage-swept parity pin; `0f881e55` forced repo cache in `release.sh` + `runbook-walkthrough.sh`; `16b3bc3a` IMPROVEMENTS wave section | `fabc7d18`, `4fa0aef0`, `0f881e55`, `16b3bc3a` | "all final gates green incl real gate PASS" (`progress.md:62`) | The ledger's fix-wave *scope* list has **6 items** but only **4 named commits**: "campaign.go comment" (Task 11 minor) and "Task 9 undocumented setup/logic precedence note" have no commit in `b0006c4a..10182b5c` matching them — the precedence note exists only as prose in `task-9-fix1-report.md` §"Not changed / residual" |
| **docs batch** | `e303fbd3` forced repo cache in `security-check.sh` (56/0 tests, mutation-checked, real gate PASS exit 0); `7287e5bb` SECURITY.md; `a79c3fb6` README+RUNBOOK reconcile (7 rows, manifest resynced) | `e303fbd3` (+ `fc9241d4`) | `security-check-test.sh` 56/0; real gate PASS exit 0; `progress.md:60` | "release.sh + runbook-walkthrough.sh share the `${VAR:-}` cache defect; `docs/IMPROVEMENTS.md` wave section not added (plan-mandated)" — both listed as residuals and both closed in the fix wave |
| **critic wave 1** | F1 fix (`1130e324`), F5 fix (`91437a44`), F4 durability (`4382e586`, 47 files to `docs/sdd/`) | `1130e324`, `91437a44`, `4382e586` | F1: `-race -count=3` green (195.626s) + mutation-proven still red; F5: red then green + golden exit 0; F4: manifest check "`rg docs/ assets/testdata/asset_manifest.json` returns no matches"; verify-full run to completion at `1130e324` (6m13.9s) = steps 1–11 GREEN, **step 12 RED** | F2 not taken in this wave (routing task); F6 parked; verify-full still red at step 12; second run at `91437a44` (5m35.7s) same verdict |
| **critic wave 2** | Step-12 gate fix (`2e9ff576`) + SECURITY.md minors (`656d2e4b`); then `64b6eefa` (runbook/notes fork-var), `df9ae26b` (trail refresh), `8fabb878` (ledger copy), `10182b5c` (release log) | `2e9ff576`, `656d2e4b`, `64b6eefa`, `df9ae26b`, `8fabb878`, `10182b5c` | "`VERIFY-FULL GREEN: all 13 steps pass`"; gates after both commits: full 0, vet 0, golden 196 steps, security-check-test 56/0; addendum at `64b6eefa`: full **71 `ok` + 2 `[no test files]`**, golden GOLDEN GREEN, runbook 150/0, 56/0 | Wave-2's "127 packages `ok`" line was a **counting artifact** (ok-prefixed lines across concatenated logs), corrected in the addendum to 73 packages / 71 ok; `scripts/p2-docker-e2e.sh` still says "15 registered" (comment :321, assertion :330) and is left as found; verify-full not re-run in the addendum (its committed green log is the evidence) |

---

## 4. The F1 race finding (the lock-budget ×10 decision)

### 4.1 Where it came from, and the first honest disclosure

The failure was **first disclosed, not caused, by Task 4** (`task-4-report.md` §8, "Pre-existing
failure found (NOT caused by this task): `-race` lock test"): `scripts/verify-full.sh` step 4 was red
on the box at HEAD, and the report proved it was not Task 4 by reverting its two `internal/state`
files and reproducing the identical failure on a clean tree:

```
$ go test -race ./internal/state -run TestConcurrentLoadModifyWritesLoseNothing -count=1
--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (5.08s)
    processlock_r13_test.go:156: worker 2: exit status 1
        campaign C-lmwrace001 is locked by another process (waited 5s; holder: 2468111 …)
FAIL	websec/internal/state	5.098s
CLEAN-EXIT=1
```

Task 4's own reading: "The 5s lock-wait timeout in the test is simply too tight for six concurrent
race-instrumented worker processes on this machine; the non-race run of the same test passes".
Because `verify-full.sh` is fail-fast, steps 5–13 never ran in that run; a scratch copy with only
step 4 replaced by a recorded note then exposed the **second** pre-existing red, step 12 (see §5).

The critic then filed it as **F1 — CRITICAL**: `verify-full.sh` RED at final HEAD, DoD gate unmet,
ledger's final claim overstating — "I ran `bash scripts/verify-full.sh` to completion: `FAIL [step 4:
go test -race]` … Reproduced **deterministically, twice, including in full isolation**". The critic's
mitigation language is itself a durable ruling:

> "this failure was honestly *disclosed* earlier — the Task 4 report proved the same step-4 lock-timeout (and a step-12 p2_sections 14-vs-15 mismatch) pre-existing on clean BASE — so it is not a regression of this branch. But 'disclosed, then silently dropped from the DoD accounting' is exactly the pattern the plan's honesty rules exist to prevent."

### 4.2 The derivation (measured, not assumed) — the ×10 decision's evidence base

`f1-race-diagnosis.txt` records a temporary, test-only instrumentation (stage timestamps written by
the worker processes themselves; the instrumented test file was reverted with
`git checkout -- internal/state/processlock_r13_test.go`, so "nothing in the committed tree carries
the instrumentation"). Run A used a **scaled 50s budget** so all six workers could finish
("with the production 5s budget the sixth fails"):

| worker | `locked` at | `logged-then-exit` at | next worker acquires |
|---|---|---|---|
| 2 | +249.748µs | +7.192576ms | +1.0043s later |
| 4 | +1.010165608s | +1.019493891s | +1.0029s later |
| 3 | +2.023665014s | +2.033411625s | +1.0064s later |
| 1 | +3.039737175s | +3.04795234s | +1.0051s later |
| 5 | +4.048340881s | +4.056741721s | +1.0092s later |
| 0 | +5.065779506s | +5.075356091s | — |

(The report's own summary table rounds these to +0.25ms/+7.2ms, +1.010s/+1.019s, +2.024s/+2.033s,
+3.040s/+3.048s, +4.048s/+4.057s, +5.066s/+5.075s — the two presentations agree.)

> "Reading: every critical section is 7.2ms of real work (lock -> State -> edit -> SaveState -> Log). The lock is then held for ~1.004s MORE by each worker, and the next worker acquires it exactly one teardown later"

> "lmwWorker ends in os.Exit(0), so its `defer c.UnlockProcess()` never runs and the kernel releases the flock only when the process dies. The ~1.004s between 'last write' and 'next lock' is therefore process teardown under -race."

Run B is the control, "because this worker does NOT hold the lock past its write (Log's own deferred
unlock releases it)":

```
worker-start       pid=956376 07:25:32.772157
worker-before-exit pid=956376 07:25:32.778994   (7ms of work)
DIAG logger worker 4 pid=956376 started=07:25:32.756607 returned=07:25:33.780988
elapsed=1.024382728s
```

> "Conclusion: the r13/r14/r15 fail-loud law was never violated. The 5s wall-clock budget was being spent on race-detector teardown, so the fix scales the budget in -race test builds only (commit 1130e324) and pins the production value with TestLockBudgetMatchesBuild."

The wave report states the same conclusion in the shape a reader should cite:

> "**The budget, not the lock hold, is the contended resource — the r13/r14/r15 law was never violated, and no update was lost for a concurrency reason.** This is exactly the 'test-infrastructure fragility, not demonstrated production data loss' the critic described; the fix is to stop the harness from spending a production budget on detector overhead."

### 4.3 The decision and its mechanics (commit `1130e324`, "fix(state): race-detector-aware lock budget in concurrent test")

| Element | Decision |
|---|---|
| Mechanism | the standard library's `internal/race` pattern, inside `internal/state` |
| Build tags | `raceenabled_race.go` (`//go:build race`) → `const raceEnabled = true`; `raceenabled_norace.go` (`//go:build !race`) → `const raceEnabled = false`. "A compile-time constant: the false branch costs nothing and cannot be observed by a shipped binary." |
| Budget | `lockBudget` becomes a documented `var` holding the same `5 * time.Second`; "nothing outside test code ever assigns it" |
| The ×10 | `processlock_racebudget_test.go` (**test code only**) scales it by `raceLockBudgetFactor = 10` when `raceEnabled`, in `init()` "so it applies to the worker subprocesses too, which are the same test binary re-executed" → 50s under `-race` |
| The pin | `TestLockBudgetMatchesBuild` pins **both** directions: exactly 5s in a normal build, exactly 50s under `-race`. "Production behavior is byte-identical" is therefore a checked claim, not a comment |
| What was *not* done | no test skipped under `-race` (the critic's own constraint: "do not skip under `-race` — that would be gate-weakening"); production budget unchanged; the ~1s race-teardown cost untouched (it is the detector's) |
| Fail-loud law | "the timeout error still names the budget actually waited, a real stuck holder still fails after five seconds" |

### 4.4 The red run, verbatim (`f1-red-race.log`, reproduced 3× on the pristine tree)

```
--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (5.09s)
    processlock_r13_test.go:156: worker 1: exit status 1
        campaign C-lmwrace001 is locked by another process (waited 5s; holder: 954077 /tmp/go-build351526845/b001/state.test -test.run=TestConcurrentLoadModifyWritesLoseNothing) — let the running webv2 finish and retry; do NOT edit the ledger or state by hand
    processlock_r13_test.go:185: ledger lost a class: 5 of 6
FAIL
FAIL	websec/internal/state	5.109s
FAIL
```

Same failure non-race: **passes in 0.114s**. (Task 4's variant of the same lines: `worker 2`,
`holder: <pid>`, `FAIL websec/internal/state 66.342s` inside verify-full and `5.098s` standalone —
the pid and worker index vary, the message and the two line numbers do not.)

### 4.5 The mutation proof (the test still catches a real lost update)

Both mutations were reverted with `git checkout -- internal/state/processlock_r13_test.go`; "the
committed test file is byte-identical to its pre-wave content."

| mutation | expected | observed (verbatim) | file |
|---|---|---|---|
| drop one worker's `SaveState` write | FAIL | `--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (6.10s)` / `processlock_r13_test.go:189: state lost an update: 5 rows, want 6` / `FAIL websec/internal/state 6.118s` | `f1-mutation-race.log` |
| remove `LockProcess` from the worker (r14's original P0 shape) | FAIL | `--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (1.09s)` / `processlock_r13_test.go:189: state lost an update: 1 rows, want 6` / `FAIL websec/internal/state 1.114s` | `f1-mutation-nolock-race.log` |

### 4.6 Green evidence

```
f1-green-race.txt:            ok  	websec/internal/state	195.626s
critic-round1-fixes.md:       go test -race ./internal/state -count=3   →  ok  websec/internal/state  195.626s   (exit 0)
                              go test ./internal/state -count=2         →  ok  (non-race path unchanged)
```

`verify-full.sh` step 4 is green in **both** post-fix runs: `verify-full-final.log` (`ok: race clean`)
and `verify-full-final-head.log` (`ok: race clean` at `91437a44`). The fix is closed in the ledger as
"F1 complete (`1130e324` race-detector-aware test-only budget x10, mutation-proven fail-loud
retained, `-race` x3 green)" (`progress.md:70`).

### 4.7 What remains open about F1

- `critic-round-1.md` what-would-make-it-ten item (ii).2: "Adjudicate the r13 race-test environment
  sensitivity on a non-sandboxed machine (if it passes there, the finding downgrades to 'gate is
  machine-fragile' with a CI requirement rather than 'gate red')" — **still pending** at the final
  ledger line ("operator adjudications pending: bare-metal `-race` sensitivity").
- `task-6-review.md` independently flagged the same machine-dependence from the other side: "`-race`
  timing margin: 10 serialized runs finished in 1.42 s under race vs the 5 s per-acquisition
  `lockBudget` (`processlock.go:38`) — ample on the recording machine, but a pathologically loaded box
  could turn a legit wait into a `locked by another process` exit; machine-dependent, no action."
- The fix scales only the *test* budget; a genuinely stuck holder still fails after 5s in production.

---

## 5. The F5 / step-12 section-count ruling (step 164 = 15 / step 194 = 14)

Two separate defects were fixed in the critic wave, and they are easy to confuse because both live in
"counting" logic: **F5** (planner open-question double-count) and the **verify-full step-12
`p2_sections_ok` assertion** (audit section count). The second one is the one that required an
operator ruling.

### 5.1 F5 — one open question naming two components of one row (critic MINOR)

**Finding (critic):** "`internal/planner/queue.go` `scoreRow` adds `openQ[ref]` per component, so one
question naming two components of the same row contributes W3 twice (noted by the Phase C review,
accepted without a pin). Direction is conservative (ranks higher, never lower)." Fix offered:
"count distinct questions per row, or pin the current semantics with a named test."

**Red first, verbatim (`f5-red.txt`):**

```
--- FAIL: TestQueueOpenQuestionCountedOncePerRow (0.00s)
    task12_queue_scoring_test.go:172: one question naming TWO components of one row scored openQ=2, want 1 (counted once per row)
--- FAIL: TestQueueMultiComponentQuestionDoesNotInflateRank (0.00s)
    task12_queue_scoring_test.go:211: queue order = [Q-002 Q-001] — a row whose single open question names two components must not outrank the one-component spelling of the same question (counted once per row)
FAIL
FAIL	websec/internal/planner	0.011s
FAIL
```

**Fix (commit `91437a44`, `test(planner): pin open-question row counting`):**

- `queueSignals.openQ` becomes `map[string][]int` — contract reference → the **ordinals** of the
  unresolved questions naming it, in model declaration order. "Identity, not a tally, is what makes a
  once-per-row count possible."
- `scoreRow` unions those ordinals across the row's components and takes `len()`: "one model entry is
  one question however many components it names; two questions naming the same row still count twice."
- No map is ranged (the union set is only measured; per-reference slices are ordered), so the
  module's determinism guarantee is unchanged.
- Direction documented at the law comment: "the count-once rule can only LOWER a weight relative to
  the per-component sum — **no row is ever promoted by it** — which is the conservative direction for
  a cockpit that must not rank work on a duplicated signal."
- Tests: fixture `task12OpenQModel` (one question naming Rollup **and** Zeta, both in scope; the
  coverage ledger marks Zeta swept and Rollup untouched); `TestQueueOpenQuestionCountedOncePerRow`
  (two-component spelling scores `openQ=1`, weighs the same as the one-component spelling, leaves
  `untouched=1`/`severity=3` alone) and `TestQueueMultiComponentQuestionDoesNotInflateRank` (through
  the real `WorkQueue`: the two rows tie and fall back to alphabetical, stable across **25 runs**).
- **No pin churn (checked):** "Only one committed fixture anywhere in the repo has a multi-reference
  open question (`internal/coverage/testdata/golden_replay.json`: `blocks: ["INV-3","ORC-1"]` —
  invariant ids, not in-scope contracts, so it contributes nothing to `openQ` either way). Every other
  fixture names at most one contract per question, so no row's `openQ` changes and no oracle needed
  re-pinning." `scripts/golden.sh` re-run after the fix: exit 0.

### 5.2 Step 12 — the ruling (the `p2_sections_ok` `len(secs) == 14` assertion)

**Symptom.** `verify-full.sh` step 12 failed fail-fast, before step 13 could run. In
`verify-full-final-head.log` (run at `91437a44`, `real 5m35.732s`, `VERIFY_EXIT=1`), verbatim:

```
Traceback (most recent call last):
  File "<string>", line 12, in <module>
    assert len(secs) == 14, f"{label}: {len(secs)} sections, want 14"
           ^^^^^^^^^^^^^^^
AssertionError: P3 smoke audit: 15 sections, want 14

FAIL [step 12: smoke audit --json sections]
```

The earlier post-F1 run (`verify-full-final.log` at `1130e324`) recorded the same assertion. Steps 9
and 11 were GREEN at 14 in the same run.

**Evidence that decided it (all from the fixes record):**

| claim | evidence |
|---|---|
| the extra section is `price_table` | hand re-derivation: `count: 15`, `extra: ['price_table']`, and "every one of the 14 reference sections is present, in order" — order: `[event_log, artifacts, execs, findings, projection, snapshots, relations, floor_policy, stage_completions, baselines, invariant_verification, sequence_coverage, probe_surface, unpriceable, price_table]` |
| the registry is 16 names, not 14 | `internal/audit/audit_test.go:85` pins `len(SectionNames()) == 16` with `price_table` last |
| `eval` and `price_table` are presence-gated, appended past the 14 | `internal/audit/sections/register.go:43` (also `:26-39` registers the 14 in reference order; registration order **is** report order via `RegisterAuditSection` → `SectionNames`); `p1_sections_test.go:236` pins the registry tail |
| `price_table` is genuinely presence-gated | `pricetable.go:40` — `return validation.Value{}, ErrSkip // never priced anything`; pinned by `pricetable_test.go:27` |
| `eval` is gated the same way | `eval.go:140` — `return validation.Value{}, ErrSkip` |
| a skipped section is omitted from the report | `audit.go:88` — `if errors.Is(err, sections.ErrSkip) { continue }` |
| step 12 is what makes the price registry non-empty | its own body runs `price <C> set ETH 3000 …` before `audit --json`; step 11's P2 smoke never prices anything |

**Measured on the live surface** (the binary verify-full built, against the three campaigns it leaves
behind):

| report | sections | `price_table` | `eval` |
|---|---|---|---|
| step 12 `C-10ab2d8738` (priced) | **15** | yes | no |
| step 11 `C-50abeacbb3` (never priced) | **14** | no | no |
| step 9 legacy `C-45488bdaf5` (never priced) | **14** | no | no |

**The precedent that made the ruling near-mechanical.** `scripts/check-golden.py` — the independent
golden checker, green in the same wave — already allows exactly this shape for the same section:

> "The registry carries 16 … price_table (r4) DOES render here, because the P4 recipe sets a price … this list is not a copy of the registry and must not be 'completed' to 16"

> "The rendered surface is EXPECTED_SECTIONS, optionally TRUNCATED after its 14 unconditional members: presence-gated sections … render exactly when their precondition holds — the s2 campaign prices nothing and must not fake the row. What stays hard-failed: any unexpected name, and the ORDER of what does render."

**The step 164 = 15 / step 194 = 14 evidence** is one green golden run printing both shapes in the
same pass (`f5-golden.txt`, and identically in `final-gates.log:99-102`):

```
step 07 audit-json: 14 audit sections + ok (ok=True) present
step 105 probes-list-all-json: 6 probe axes alive, states as declared (…; rows=5)
step 164 audit-json-final: 15 audit sections + ok (ok=True) present
step 194 audit-json-s2: 14 audit sections + ok (ok=True) present
GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)
GOLDEN_EXIT=0
```

The fixes record draws the conclusion the ruling rests on: "precedent check-golden.py already allows
the presence-gated tail … so `p2_sections_ok`'s `len(secs) == 14` is the only place that cannot
express both shapes" — i.e. "**the gate's assertion is stale for step 12, not the audit**".

**The ruling** (ledger `progress.md:70`): "ruling: implement option (a) with audit-code verification",
where option (a) = "teach `p2_sections_ok` to assert the 14 reference sections in order and allow the
presence-gated tail" (option (b) would have been "rule the step-12 assertion correct and treat
`price_table`'s rendering as a product bug"). The wave that requested it deliberately did **not** fix
it: "a DoD gate must not be edited green as part of the wave it judges" (`critic-round1-fixes.md`).

**The fix (commit `2e9ff576`, `fix(release): verify-full step 12 accepts presence-gated sections.`):**

- `p2_sections_ok` (shared by steps 9/11/12) now asserts the **14 unconditional sections, in
  registration order, plus any of the documented presence-gated extras** (`eval`, `price_table`) that
  render — and nothing else. "It is deliberately NOT relaxed to a count of 15: a bare 15 would let a
  never-priced campaign that silently grew a fake row pass." Hard failures stay hard: missing base row,
  unknown name, and the order of whatever renders.
- **10/10 mutation cases** (python body extracted verbatim from the script): PASS as required — 14
  base; base+`price_table` (the real step-12 capture); base+`eval`; base+`eval`+`price_table`. FAIL as
  required — missing base row; **unknown 15th name at `count==15`**; base reorder; gated tail out of
  order; gated row spliced into the base run; empty report.
- **verify-full to completion:** "`VERIFY-FULL GREEN: all 13 steps pass`" — step 12 reports
  `ok P3 smoke audit: 15 audit sections = 14 base + presence-gated ['price_table'], incl
  sequence_coverage`, step 11 reports `14 audit sections = 14 base (no presence-gated section
  rendered)`, step 13 walkthrough green.
- **Same-pass honesty fix:** the four stale "(15 registered; `eval` is presence-gated)" comments in
  `verify-full.sh` (the registry carries **16**: 14 base + `eval` + `price_table`) and the step-12 row
  claiming "all 14 rendered sections" were corrected in the same commit.
- **Residual, left as found:** `scripts/p2-docker-e2e.sh` still says "15 registered" (comment `:321`,
  assertion `:330`; the earlier Wave-2 text's ":319" was the block start). Its 14-section assertion
  remains **correct** because that campaign never prices, and the script is not part of the 13-step
  gate.
- Scope honesty: "The step-12 change is a **gate** fix, not a product change: no section, no registry
  entry, no audit output changed." `p2_sections_ok` remains a surface-shape check — "It does not
  re-derive WHY `price_table` rendered — the Go tests own that".

---

## 6. The logs — what each proves, its HEAD sha, exit codes, and the only non-reproducible bytes

Rule applied here: a re-runnable log's *reproducible* content (package lists, step banners, "ok"
lines) is not transcribed; only what a re-run would not reproduce is — the HEAD/date stamp, exit
codes, wall times, failure lines, and generated ids/digests.

| Log (lines) | What it proves | HEAD recorded | Exit codes | Only non-reproducible bytes |
|---|---|---|---|---|
| `final-gates.log` (420) | the five gates at the **final code HEAD of the critic wave**, including the F1 step-4 fix in a non-race form | **yes** — line 1: `HEAD=91437a44 date=2026-09-18T07:42:09+01:00` | `GOTEST_EXIT=0`, `RACE_EXIT=0`, `VET_EXIT=0`, `GOLDEN_EXIT=0`, `RUNBOOK_EXIT=0` | the HEAD/date stamp; wall times `0m53.855s` (full suite), `2m58.751s` (`-race` state 67.804s + cli 172.856s), `0m8.704s` (golden), `1m3.400s` (runbook); golden run ids: campaign `C-34c0ce6f4b`, **179 events**, 99 files archived, `step 105 probes-list-all-json: … rows=5`; the runbook `150 passed, 0 failed` |
| `verify-full-final.log` (358) | **the GREEN 13/13 run** whose step-12 assertion the ruling repaired | **no** — the file has no HEAD line and no `real`/duration line | implicit green (`VERIFY-FULL GREEN: all 13 steps pass`, line 358) | the step-12 line `ok P3 smoke audit: 15 audit sections = 14 base + presence-gated ['price_table'], incl sequence_coverage`; step 11 `ok 14 audit sections = 14 base (no presence-gated section rendered)`; step 13 `ok runbook-walkthrough (134+ rows green)`; step 10 `21 P1 commands`; campaign id `C-10ab2d8738` and report id `F-99db0a513cea`. Provenance from prose, not from the file: the fixes record says a 6m13.9s run at `1130e324` was RED at step 12, and that `2e9ff576` replaced the committed copy with the green run (byte-identical to `.scratch/sdd/verify-full-final.log`) |
| `verify-full-final-head.log` (359) | the **RED run at the final code HEAD** — steps 1–11 green, step 12 red, step 13 never reached; same verdict as the post-F1 run, so the F1+F5 fixes cost nothing | **no** in-file HEAD; named by the fixes record as `91437a44` ("Second run at the final code HEAD (`91437a44`)") | `VERIFY_EXIT=1`; `real 5m35.732s` | the verbatim failure block (below); step 4 `ok: race clean` (the F1 fix holding under the whole repo); the step-12 command list; the random report id in that run is `F-fd2321e373c0` (the green run has `F-99db0a513cea`) |
| `release-final.log` (36) | the release artifact + the strict scan at the archived final HEAD (`10182b5c`, per the ledger's N2 closure) | **no** | implicit success — `security-check: PASS`, `RELEASE OK: …` | `sha256: f8d75ad544409dc4a2bac93d155abd7227e45f5924005403b759aede5eec6db2`; `size: 20017314 bytes (20M)`; ELF/Go `BuildID`s (`BuildID[sha1]=44c28fb610641939c956298c48bf423eab355583`, Go BuildID `0NllhuJ6GnD5K6qfE81D/…`); embedded-asset census `32 schemas, 54 stage prompts, 10 playbooks, 13 archetypes, 83 commands`; temp paths `/tmp/webv2-walkthrough-2089167790`, `/tmp/tmp.SBNGmyEJO8`; campaigns `C-1a8038422a`, `C-34dc291381` |
| `f1-race-diagnosis.txt` (82) | **the F1 mechanism measurement** — the whole basis of the ×10 decision (§4.2) | **no** (run pre-`1130e324`) | none recorded | pids `956109`–`956114`, `956376`; wall-clock stamps `07:25:01.6…`, `07:25:32.7…`, `07:25:33.780988`; the derived spacings (+1.0043s, +1.0029s, +1.0064s, +1.0051s, +1.0092s) are the finding, not noise |
| `f1-red-race.log` (7) | the deterministic red the F1 fix removes, on the pristine tree | **no** | FAIL / exit 1 | holder pid `954077` and build dir `/tmp/go-build351526845/b001/state.test`; duration `5.09s` / `5.109s`; the failure lines themselves (below) |
| `f1-mutation-race.log` (5) | mutation 1 — the test still catches a dropped write after the fix | **no** | FAIL / exit 1 | `6.10s` / `6.118s`; `state lost an update: 5 rows, want 6` |
| `f1-mutation-nolock-race.log` (5) | mutation 2 — the test still catches the r14 no-lock shape after the fix | **no** | FAIL / exit 1 | `1.09s` / `1.114s`; `state lost an update: 1 rows, want 6` |
| `f1-green-race.txt` (1) | the F1 fix's green `-race` run | **no** | none in-file | the single line `ok  	websec/internal/state	195.626s`. The `-count=3` and `exit 0` claims come from `critic-round1-fixes.md`, not from this file |
| `f5-red.txt` (7) | the F5 double-count red (§5.1) | **no** | FAIL / exit 1 | test line numbers `172` / `211`; `queue order = [Q-002 Q-001]`; `0.011s` |
| `f5-golden.txt` (14) | F5's no-pin-churn proof: golden stays green with **both** section shapes | **no** | `GOLDEN_EXIT=0` | campaign `C-34c0ce6f4b`; `196 steps … 179 events, chain intact; 99 files archived`; the four audit-surface lines `step 07 = 14`, `step 164 = 15`, `step 194 = 14` (and `step 105 probes-list-all-json … rows=5`); the absolute worktree prefix `.worktrees/production-readiness` |

**The red run's failure lines, verbatim (kept because the fix's whole justification is that these are
lock-*budget* failures, not data-loss failures).**

`f1-red-race.log` (complete file — 7 lines):

```
--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (5.09s)
    processlock_r13_test.go:156: worker 1: exit status 1
        campaign C-lmwrace001 is locked by another process (waited 5s; holder: 954077 /tmp/go-build351526845/b001/state.test -test.run=TestConcurrentLoadModifyWritesLoseNothing) — let the running webv2 finish and retry; do NOT edit the ledger or state by hand
    processlock_r13_test.go:185: ledger lost a class: 5 of 6
FAIL
FAIL	websec/internal/state	5.109s
FAIL
```

`verify-full-final-head.log` step-12 failure (complete block, lines 350-359):

```
Traceback (most recent call last):
  File "<string>", line 12, in <module>
    assert len(secs) == 14, f"{label}: {len(secs)} sections, want 14"
           ^^^^^^^^^^^^^^^
AssertionError: P3 smoke audit: 15 sections, want 14

FAIL [step 12: smoke audit --json sections]

real	5m35.732s
user	9m19.080s
sys	0m53.861s
VERIFY_EXIT=1
```

**Cross-log observations a future reader needs:**

1. **Only one log in the set names its HEAD** (`final-gates.log`). Every other gate log is
   HEAD-anonymous; the HEAD of the verify-full runs comes from prose (`1130e324`, `91437a44`), and the
   HEAD of the release log comes from the ledger's N2 line (`10182b5c`).
2. **Two files named "verify-full-final" carry opposite verdicts** — `verify-full-final.log` is
   GREEN (post-`2e9ff576`, HEAD unrecorded) and `verify-full-final-head.log` is RED at `91437a44`.
   The Wave-2 addendum warns about exactly this trap: the tracked copy "was a byte-prefix of it (first
   329 lines, 17195 bytes — `cmp` confirmed the prefix before the refresh)" and was refreshed so the
   durable trail carries the closure.
3. **`f1-green-race.txt` is a one-line file with no provenance** (§1.3.4) — its `-count=3` claim is
   attested in prose only.
4. **No log in this set records the worktree's `git status` or tree hash**, so "clean tree" claims
   rest on the task reports; the one tree hash that is cross-checked by two independent sources is
   `scripts/legacy` = `f62c95c0a947f94e15328ee0d08fc1b70ab31ec6` (`task-8-report.md` and
   `task-4a-fix1-review.md`).

---

## 7. Defects found by review and their dispositions (all of them, with severity)

### 7.1 The critic's findings (round 1) and the round-2 items

| ID | Severity | Defect | Disposition |
|---|---|---|---|
| F1 | **CRITICAL** | `verify-full.sh` RED at final HEAD (`-race` lock budget, step 4); DoD gate unmet; ledger's "all final gates green" overstated | **CLOSED** — `1130e324` (test-only ×10 budget, mutation-proven, `-race -count=3` green, step 4 green in both later runs). See §4. Operator adjudication on bare-metal `-race` sensitivity still pending |
| F2 | **IMPORTANT** | Independent-review evidence not persisted for Tasks 1, 2, 3, 4, 8, 14, 15; Task 8 "appears to have skipped the plan-mandated independent review entirely" | **NOT taken in the fix wave** (routing/delegation, out of the operator's scope for that wave), with the note that 5 of the 5 reviews actually exist — "part of F2's 'no review recorded' claim looks like a search gap rather than a missing review". **CLOSED later** (`progress.md:70`): all 5 reviews run, T1/T2/T3/T4/T8/T14-15 spec YES / quality APPROVED; 2 minors parked (phantom `FORK_RPC_URL`; `vm-snapshot` `ProfileAvailable`-false honesty note) |
| F3 | **IMPORTANT** | The plan-mandated final whole-branch review never produced an artifact | **CLOSED by ruling** (R7): the critic loop *is* that review; `critic-round-1.md` + the closure record are the artifact. "no separate artifact is owed, and none is claimed" |
| F4 | **MINOR** | Durable SDD ledger and review evidence untracked (`.scratch/` is gitignored, `.gitignore:3`) | **CLOSED** — `4382e586`, 47 files committed under `docs/sdd/`; manifest check "`rg docs/ assets/testdata/asset_manifest.json` returns no matches, so no asset pin names a `docs/` path and no resync was owed or performed"; verified no gate walks `docs/` |
| F5 | **MINOR** | Task 12 `scoreRow` double-counts an open question naming two components of one row (W3 twice) | **CLOSED** — `91437a44` (distinct-question counting; no oracle re-pin needed). See §5.1 |
| F6 | **MINOR** | Parked residuals: unbounded YAML alias traversal; `shellAbsentRe` colon-widening contradicts the runbook's tool-absent law; govulncheck PASS semantics | **PARKED, disclosed, listed for the record** — "keep the wording in release notes"; alias cap suggested as follow-up |
| N1 (round 2) | — | Stale ledger copy | **CLOSED** — `8fabb878` |
| N2 (round 2) | — | Missing RELEASE OK log | **CLOSED** — `10182b5c`; `release.sh` exit 0, strict scan PASS, `RELEASE OK` archived as `docs/sdd/release-final.log` |

### 7.2 Per-task review findings

| Task | Finding (severity as filed) | Disposition |
|---|---|---|
| 1 | Info: dispatch range predated the plan (`115ba97f` is the real Task 1 commit); Info: YAML duplicate-key law correctly split out | No action; the YAML half became **Task 16** (`78f755bb`, implemented `b00532ca`) |
| 2 | Non-blocking: helper placement (plan self-contradiction); `profileNetwork` still carries `"none"` for host profiles (now documented as the container label) | Accepted; "Cosmetic only" |
| 3 | Non-blocking: empty `applies_to` liveness entry no longer suppresses synthesis (specified behaviour); `covered[pyStr(a)]` lacks the `Kind == Str` check Task 4's `referenceTokens` has | Accepted as specified / cosmetic ("the two sites now disagree stylistically") |
| 4 | Observation 1: **digest not checked at the gate** — the gate reads current bytes, never compares the row's registered `sha256` (stored at `artifacts.go:139-152`); content swapped between registration and verify is judged on its new bytes | **Open, owned by the v3 correction** — "4A added provenance labeling but the digest binding itself remains open work — tracked here so it is not lost. Not a Task 4 defect: the plan's own consumes line specifies plain `os.ReadFile`" |
| 4 | Observation 2: plan-internal wording conflict (`L184` "case-insensitive substring" vs `L222` word boundaries) resolved to the stricter reading | Correct call, noted for the record |
| 4 | Observation 3 (Minor): per-call regex compilation (≤4 tokens/verify) | Negligible at CLI cadence |
| 4A | **BLOCKING** (implementer-filed): Python-twin byte parity impossible with the mandated `verification_method` key | **ADDRESSED** by `f13ae1df` (additive re-pin + rename to Go-pin semantics); re-review: "re-pin JUSTIFIED, proof CREDIBLE → ADDRESSED" |
| 4A fix1 | Finding 2: CLI help line still said "mark an invariant verified" | **ADDRESSED** — now "record an operator attestation (attribution, not mechanical proof)" |
| 4A fix1 | Sanctioned deviation: fifth pinned file `scenario_steps.json` | **APPROVED** (necessity proven from `scenarioChecker.step`; same sanctioned add) |
| 4A fix1 | Deferred minors: doc-comment name typo; guard comment understates `source`; verified-then-contradicted entries keep `verification_method`; sibling `…PythonTwin` test names | Deferred, out of scope, no loop extension |
| 5 | **Low-1**: CF1's transcript shows a 4-element id list against the committed 5-spelling test (captured on an earlier draft) | Correct the evidence record; "No product impact; the pin is real either way" |
| 5 | **Low-2**: no Task 5 gate logs captured — the gate table is "prose-only and unverifiable after the fact" | Process fix for later tasks ("capture the run to `.scratch/sdd/task-N-*.txt`") |
| 5 | **Info-3**: symlink-to-file and hard-link arms live only in a deleted scratch probe → "a future 'optimisation' that dedups by inode would pass the tree" | Substantive coverage suggestion for a follow-up line; not fixed |
| 5 | Info-4/5/6/7: event assertions count types only; stored-path assertion is order-coupled; `os.Chdir` in a process-wide test binary; `fix(state):` label on a test-only change | Accepted as-is (each with its safety argument) |
| 5 | Adjacent flag (report §9.4): `audit/sections/artifacts.go:31-39` + `state.resolveArtifactPath` join without `EvalSymlinks` while the dedup key expands symlinks | "carry it to final triage, don't widen Task 5" |
| 6 | **Minor 1**: saved red log truncated (1528 B, ends mid-JSON, spurious `exit=0`); the headline 10-event line absent | Red confirmed by construction; fix = re-record the base red run. **Not fixed** |
| 6 | **Minor 2**: the letter of the Global-Constraints race gate not recorded (`-race` only on `./internal/cli`, not `./internal/state`) | Fix = append `go test -race ./internal/state -count=1`. **Not fixed** |
| 6 | **Minor 3**: "tampered files always differ" is overstated — a tamper preserving canonical content modulo `created_at`/key order compares equal, so `index` no longer heals that shape | Tighten the doc sentence; detection unaffected (audit re-hash / `artifact-reconcile`). **Not fixed** |
| 6 | **Minor 4**: the follow-up list was incomplete — `EnsureFreshIndex` shares the old write-then-lock shape and **is CLI-reachable** (`cmd_dedup.go:334`, `archetypes/prescreen.go:41`, `corpus/report.go:37`, `histmining/recency.go:101`, `structidx/queries.go:396`) | Recorded together with concern 1 (orchestrator seam); both are the same mechanical fix. **Not fixed** |
| 6 | Concern 6 adjudication: `seamsInstalled` is an unsynchronized check-then-set global (`cmd_dedup.go:259-264`) — the concurrent test dodged a `-race` violation with a single-threaded warm-up | Real but pre-existing; `sync.Once` conversion only if in-process concurrent `Run` is formalized. **Not fixed** |
| 6 | Note: when the latest row is current, the early return also skips the opportunistic uncited-ghost prune the base performed | "noted for the ledger, not a finding" |
| 7 | **C-1 CRITICAL**: RISK_CALIBRATION guidance dead-ends — its only minted line `webv2 rank <C>` is read-only by contract (`cmd_rank.go:8-9`), so an operator following the brief can never close the phase proof (`risk.validated.band`, `completion/proofs2.go:108-131`) | **ADDRESSED** — `b77eb7fa`: RISK_CALIBRATION now leads `webv2 run <C>`, `rank` retained as informational; pinned 3 ways (concrete fixture, the 13-phase property, a non-vacuous pin guard) |
| 7 | **I-1 IMPORTANT**: INDEPENDENT_VERIFICATION minted `webv2 mint`, which cannot close the phase's proof (`verification.independent_reproduction.status == "matches"` is set only by `reproduction.MintIndependentEvidence`, reachable only via `verify --exec` → `orchestrator.VerifyIndependently`) | **ADDRESSED** — leads `webv2 verify --finding --exec --verifier --description` (flags verified against `cmd_verify.go:194-196`); `mint` demoted, not deleted |
| 7 | **I-2 IMPORTANT**: the scope gap — `briefing.go`'s own mint still emitted prose-first lines that fail the law and the plan's `\(` test for populated campaigns | **ADDRESSED** — every block converted to `webv2 …  # reason` via `webv2Action` + `noParens`; new law test `brief_next_actions_law_test.go`; T35 parity pins re-pinned deliberately with inline reasons. (Also fixed a latent nil-campaign panic at the old emit-probe-row branch, `briefing.go:2147` pre-fix) |
| 7 | **M-1..M-5** minors: DISCOVERY omits `run`; MAINNET_FORK_POC line names only `exec`; `<same|distinct>` is a shell hazard; residual pseudo-API in error strings; `# n missing` suffix / phase staleness | M-1/M-2/M-3 **ADDRESSED**; M-4/M-5 correctly untouched (M-4 tracked as follow-up, triage one is oracle-pinned) |
| 7 fix1 | Deferred minors D-1/D-2/D-3 (duplicate bare `run` line for IV/RISK_CALIBRATION; `--finding ?` fallback; ledger commands carry literal `--reason R --actor A`) | Deferred, out of scope |
| 8 | No findings; 2 informational notes (summary pointer names `source.excluded` but not the `snapshot.excluded` event; `/build` counting safe because rows==1) | None |
| 9 | **F1 Medium**: `toolAbsentRe` lacked a leading `\b`, so `broadcast`/`forecast`/`recast` classified as a missing foundry tool ("the r36 bug's mirror image, introduced by Task 9") | **ADDRESSED** — `6fdec840` (`\b(?:…)[\s:,;)"'\]}]` in both copies; pinned at 3 surfaces) |
| 9 | **F2 Medium** (low likelihood, law clause broken): the `shellAbsentRe` widening outranked `logicHit`, so a capture merely *echoing* a subprocess not-found while an assertion failed routed ENVIRONMENT and denied the retry | **ADDRESSED** (review option b) — `logicHit` moved above the tool-absent arm in both copies |
| 9 | Cosmetic: report §3b's `sha256 fd9bf0a11d0e16d7` / 3214 B not reproducible with the stated label (identity itself verified) | No action beyond re-deriving or dropping the hash; left as-is |
| 9 fix1 | Residuals disclosed, not fixed: colon-delimited `broadcast: not found` still reaches ENVIRONMENT via the unchanged `shellAbsentRe`; a missing repository *script* not-found stays ENVIRONMENT; the precedence swap also moved `logicHit` above `setupHit` | Documented residuals; re-review: "not a regression… recorded here so the next reviewer does not mistake it for an F1 escape" |
| 10 | Finding 1: "**'brief shows it' is not met — ruled a genuine spec gap, not a reading quibble**"; Finding 2: top-3 is "emergent, not enforced"; Minor 3: report says risk 0.8, code mints 0.9; Minor 4: fixture file differs from the plan's hint | Spec **PARTIAL**; residual tracked to closure → **closed by `fabc7d18`**; report correction appended 2026-09-17; top-3 accepted as qualitative |
| 11 | Minor 1: `probes/campaign.go` comment says an unreadable ledger is rendered "as unknown", but the caller silently omits the line; Nit 2: the warning requires `campaign != nil` | Comment-only fix suggested (behaviour defensible); **no commit for it in this range** (see §3 fix-wave row) |
| 12 | Minor 1: `scoreRow` counts one question naming two components twice (**= critic F5**); Minor 2: `touched[path]` last-row-wins on duplicate paths; Nit 3: sort lives in `planner`, not the plan's `orchestrator` hint; drift risk: `coverageSwept` duplicates `RefreshGaps`' predicate with two conservative edge divergences | F5 closed by `91437a44`; parity pin recommended → **`4fa0aef0`**; last-row-wins accepted (writer never produces duplicates) |
| 13 | Concerns: `${VAR:-}` cache defect (script inherits foreign `GOPATH`); dirty worktree from Task 7; stale `go.sum` lines; wrong advisory ID in the brief; uncalled findings remain; toolchain-floor coupling under `GOTOOLCHAIN=local` | Cache defect fixed for `security-check.sh` (`e303fbd3`, `fc9241d4`) and for `release.sh`+`runbook-walkthrough.sh` (`0f881e55`); the rest disclosed/accepted |
| 13A | Nit: the test's install-guidance assertion is too broad | Routed to the final fix wave |
| 13 (correction) | Wave-2 gate table's "127 packages `ok`" was a counting artifact (ok-prefixed lines across concatenated logs; security-check alone contributes 56) | Corrected in the addendum: the repo has **73** Go packages; real `go test ./... -count=1` = **71 ok + 2 `[no test files]`, 0 FAIL**, exit 0 |
| 14 | Minor 1: untraceable env var name `WEBV2_FORK_RPC_URL` (code reads only `FORK_RPC_URL`: `envgo/env.go:266`, `sandbox/profiles.go:341`, `findings/gate.go:408`; the `WEBV2_` prefix is real only for `WEBV2_SOLC_DIR`); Minor 2: `vm-snapshot` listed among profiles that "execute a real `docker run`" although `ProfileAvailable` returns false unconditionally (`profiles.go:282`) and `BuildContainerArgv` has no branch for it | Both **fixed** — `656d2e4b` (SECURITY.md) and `64b6eefa` (RUNBOOK.md:44, RUNBOOK.md:1692, docs/runbook-go-notes.md:257, with the manifest resync sha256 `f1843f46…943b807` → `41e40478…52de53`, size 110383 → 110337) |
| 14/15 | Process note: `docs/IMPROVEMENTS.md` was in Task 15's file list but landed in the follow-up commit `16b3bc3a` | Acceptable sequencing; all 30 referenced hashes verified in-range |
| 16 | **Low**: rendered-identity strictness beyond PyYAML is intended but only half-pinned (null vs `"None"` rests on report prose); **Low**: double merge key `<<` edge wording; **Low**: `strings.Contains` vs equality; **Info**: no sentinel/`%w` | Non-blocking polish; suggested follow-up task |
| 16 | Adjacent, pre-existing, NOT introduced: `yamlNodeValue`'s `AliasNode` recursion has no visited/depth bound → a self-referential anchor "could crash the process"; multi-document input: only the first document is decoded | Correctly out of scope, correctly not exercised (brief forbade resource-exhaustion payloads); recommend a follow-up task (visited set or depth cap) |
| 2–9 (docs wave) | Parked Task-2/3 minors routed to Task 15: stale prose RUNBOOK:67 / MINICERTORA docs; `invariants.go:369/461` doc comments; refusal exactness pinned only by substring; silent `applies_to` typo; coverage-is-registry-truth comment | Routed to the Task 15 docs wave; the docs wave fixed the rows it could verify (7 rows) |
| all | Final parked residuals (`progress.md:73`): "0/2 gold discovery out of scope; YAML alias traversal cap optional; Windows/macOS unbuildable (documented)" | Honest limits, not defects |

---

## 8. Laws and conventions this trail established

### 8.1 The plan's Global Constraints (as the task reports quote them)

| Constraint | Quoted form | Where it bit |
|---|---|---|
| Deliberate pin updates | "**Pins:** update golden/runbook expectations deliberately." / "minimal fix → full gates → deliberate golden/runbook pin updates → commit" (Phase B preamble) | every oracle/golden re-pin (Tasks 2, 4, 7, 7fix1, 12, 15, 16) |
| Pinned expectations are not legacy fixtures | orchestrator ruling R5: "testdata files are pinned expectations, not `scripts/legacy` compatibility fixtures; re-pin + rename documented in commit body" | unblocked the Task 4A fix1 re-pin |
| Legacy artifacts re-registered honestly | Global Constraints: "a legacy artifact that no longer satisfies the relevance gate is re-registered with an honest artifact in the same commit" | `scripts/golden/artifact.md`, `scripts/verify-full.sh` `note.md` (Task 4) |
| Historical fixtures immutable | operator ruling R3: "Historical fixtures immutable" / `progress.md:27`: "Preserve original fixtures; any migration must be explicit and tested separately." | `scripts/legacy/**` — `git diff b0006c4a..HEAD -- scripts/legacy` and `16b3bc3a..HEAD` both empty; tree hash `f62c95c0a947f94e15328ee0d08fc1b70ab31ec6` |
| No new mechanism | "no new dependencies, no new status enum, no new scheduler (Global Constraints 15)" | Tasks 4A, 9, 9fix1, 16 |
| Gate set for CLI-output changes | "Global Constraints require `scripts/golden.sh`, `scripts/runbook-walkthrough.sh` and `python3 scripts/check-golden.py` for any task that CHANGES CLI OUTPUT" | every CLI-facing task |
| Attribution is not proof | `progress.md:25` + R3 "attribution not semantic proof"; `progress.md:36` "it must not produce or upgrade a mechanical harness outcome. Historical missing method is legacy-unspecified, never inferred as mechanically verified." | Task 4 acceptance, Task 4A provenance |
| Unavailable scan cannot pass | `progress.md:28` "An unavailable scan must remain visibly incomplete, not satisfy production acceptance." | Task 13/13A |
| Review integrity | Task 14's plan line: "Reviewer checks every claim against the cited file/line" | Task 14/15 review |
| No score claimed, no marketing | `task-14-15-review.md`: "Global Constraints respected: no score claimed, no marketing." | SECURITY.md, IMPROVEMENTS |
| No push / no merge / no delegation | repeated verbatim in every report and review | whole trail |

### 8.2 The task laws (verbatim, as quoted in the reports)

- **Task 1:** error text law — `json: duplicate object key %q`; `ParseOrdered`'s signature is unchanged and the guard is per-object ("`seen` is allocated inside the `case '{'` branch, so the guard is per-object and the same key in sibling/nested/array-element objects stays valid").
- **Task 2:** host-profile label is byte-exact — `host (unconfined — nothing enforces network-off)`; container profiles return `profileNetwork[profile]` verbatim. `profileNetwork` "documents the **container** label and must not be read directly for host profiles".
- **Task 3:** refusal text, byte-exact: `protocol model: state machine(s) relay, staking have no liveness invariant (one per machine — stage 37)` — plus the law table: no machines → early `return nil`; zero coverage → synthesis unchanged; **partial → refusal naming the uncovered machines**; full → no synthesis, no error.
- **Task 4:** refusal text, byte-exact: `artifact <id> does not reference <inv> (nor its applies_to) — cite a check that names what it verifies (invariant-verify with --exec <id> re-registers stdout as the artifact)`. Matching rule: token set = invariant id (registry **and** `NormalizeInvID` spelling) ∪ every `applies_to` string (raw and canonical), each `regexp.QuoteMeta`-escaped and matched `(?i)\b<token>\b`.
- **Task 4A:** "The label is a statement about the record, not about the check. It means the record does not say how it was established — never that it was established weakly." CLI stderr on success, exact text: `invariant-verify: operator attestation recorded; artifact attribution is not mechanical proof`. Help line: `record an operator attestation (attribution, not mechanical proof)`.
- **Task 5 (plan law):** "registering the same file twice (relative then absolute, or any path spelling) yields the SAME artifact id and an `artifact.refreshed` event — never a second row. Use the existing `RegisterOrRefresh` … one fix in the shared function, not per-CLI."
- **Task 6 (plan law):** "any artifact whose bytes the command changed gets a registry row update + `artifact.refreshed` event in the same lock window (rawState/unwind law applies). Audit section for artifacts must render the refreshed rows without a new section."
- **Task 7 (plan law):** "every next-action line is a runnable `webv2 …` command; no `orchestrator.scope(policy_path=…)` pseudo-API. The plan/replan code that MINTS those strings is the fix site, not the renderer." Test: "fixture campaign → `brief` output next-actions all match `^webv2 ` and none match `\(`."
- **Task 8 (plan law):** "exclusion lists render as `N paths excluded (first 10): …` with N exact; full list available in the record object, not stdout." Extended directive: ≤10 paths inline unchanged.
- **Task 9 (plan law):** "missing toolchain/dependency (solc, forge, docker binary) → ENVIRONMENT per the runbook's own vocabulary; only hypothesis-space failures stay SETUP. **Read the runbook row FIRST and make the code match the documented law.**" Runbook law it matched (`assets/runbook/RUNBOOK.md:46-53`): "a missing solc binary is an **environment failure, not a harness bug**"; `:942-945`: "**ENVIRONMENT** (daemon down, image missing, solc download cut — fix the environment, do NOT spend a fresh-context retry), **SETUP** (retry in a fresh context with the failure record), **LOGIC** (the only class that argues the hypothesis)".
- **Task 10:** "Every `open_questions` entry that names a contract reference produces a work-queue entry `resolve open question <id>: <text>`, ranked in the top 3 when it names consensus-critical or untouched contracts; an empty `open_questions` list leaves the queue unchanged."
- **Task 11:** "While a campaign is in phase `DISCOVERY` and the ledger records no `probes run --emit` execution, `brief` prints a standing warning that names the exact command. **It is advisory, never a gate.**"
- **Task 12:** "Ordering weight is `(untouchedCount * W1) + (severityScore * W2) + (openQuestionCount * W3)`; severity `critical=3 / high=2 / medium=1 / low=0`; named constants with a `ponytail:` comment; **never** multiplicative; ties alphabetical; fully deterministic."
- **Task 13 policy:** advisory-driven — `scripts/security-check.sh` header: "no `go get`, no tool install, no latest-bumps"; PASS only on scan exit 0.
- **Task 16:** error text law — `yaml: duplicate mapping key %q`, `VNull()` on refusal, `ParseYaml` signature unchanged.

### 8.3 The numbered repo rails this trail relied on (each cited by a task)

| Rail | Content as used | Where |
|---|---|---|
| r12 | a hash-equal refresh still logs an event | Task 6 (must not be broken) |
| r13/r14/r15 | fail-loud lock: the r13/r14/r15 law was never violated; a real stuck holder fails after the budget | §4 |
| r15 | load → edit → write is one unit (lock window) | Task 6, Task 5 |
| r16 | a refused ledger event unwinds the state write (`rawState` → `save` → `Log` → `unwindState`) | Tasks 4, 6, 8, 9 |
| r34 F3 | the `artifact-register` verb routes through the shared seam (`af3be559`, 2026-09-15) | Task 5 |
| r35 F1 | kept-ghost rows are not re-hashed by refresh | Task 6 |
| r36 F5 | a schema enum change for an honest label **requires** an asset-manifest resync (`9641c681`: "Schema change required an asset manifest resync.") | Task 2 |
| r38 | the sandbox seam's default classifier must mirror `internal/envgo` byte-for-byte | Task 9 |
| r39 | refused-log unwinding for exec/register-exec/policy refusals | Task 2's red list |
| r40d | the verify refusal path's unwind pin | Task 4 |

### 8.4 Repo-wide conventions the trail fixed in place

- **Trust-core laws** (restated in `SECURITY.md` and re-verified line-by-line by the Task 14/15 review): hash over `seq/at/type/ref/data/prev_hash`, anchored at 64 zero bytes (`state/chain.go:7,37`); atomic tmp-in-dir + `os.Rename` (`validation/atomicio.go:48,72`); `flock(LOCK_EX|LOCK_NB)` with a 5s budget, depth-counted re-entry, fails loudly (`state/processlock.go:38,50-68`); **one-writer law**; host profiles can never back E4+ (`e4_capable`); floor overrides E4–E7 only, hash-chained `floor_policy.set`/`cleared`.
- **Audit-section convention** (the §5 ruling): the registry carries **16** names = 14 unconditional, order-pinned, + `eval` and `price_table` **presence-gated** (registered past the 14 in `sections/register.go`); a skipped section is omitted (`audit.go:88`); any consumer must allow "14 unconditional in order + documented gated extras", and must not be "completed" to 16. `scripts/check-golden.py`'s `EXPECTED_SECTIONS` is the reference implementation; `p2_sections_ok` now matches it.
- **Gate layout:** `scripts/verify-full.sh` = **13 steps** (vet, build, `go test`, `go test -race`, determinism ×2, asset-pack manifest, golden, crash smoke, legacy cross-audit, P1/P2/P3 CLI smokes, runbook walkthrough); the real dependency scan is **not** one of them — it lives in `scripts/release.sh:158` and is enforced strictly (`security-check.sh`, missing scanner ⇒ exit 2); the docker e2e tiers in `scripts/p2-docker-e2e.sh` are **not** part of the gate.
- **Cache convention** (and its defect class): every Go command must run with `GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod` (or `.scratch/gomodcache` in Task 4's variant), because the harness `$HOME` caches are read-only; scripts that use `${VAR:-…}` defaults silently inherit a foreign `GOPATH=/home/xand/go` and die on a mechanical build failure — fixed for `security-check.sh` (`e303fbd3`, `fc9241d4`) and for `release.sh` + `runbook-walkthrough.sh` (`0f881e55`).
- **Manifest law:** any `assets/` byte change requires `python3 scripts/sync-asset-manifest.py` (verify-full step 6's `go test ./assets -run TestAssetPackManifest -count=1`); `docs/` paths are not manifest-covered.
- **TDD/report conventions every task followed:** BASE/HEAD/COMMIT/STATUS header; exact file list with deltas and `git add`-by-exact-path (never `-A`); a red run before the implementation; a gate table with exit codes and log paths; a "Concerns"/"Deviations" section; "no push, no merge, no delegation"; scratch probes written/run/deleted, tree left clean. Reviews: independent, read-only, "verified by running, not reading", with the reviewer's own mutation/counterfactual runs, and a "cannot verify" list kept separate from findings.
- **Honesty rules established by the critic and the controller** (quoted): "disclosed, then silently dropped from the DoD accounting … is exactly the pattern the plan's honesty rules exist to prevent" (critic F1); "a DoD gate must not be edited green as part of the wave it judges" (fix wave); "This does not establish full production readiness" (controller); "do not claim general YAML safety" (Task 16 review, quoted into the ledger); "PASS means nothing CALLED is known-vulnerable, not a clean graph"; "the count-once rule can only LOWER a weight … no row is ever promoted by it".

### 8.5 Durable numbers and identifiers worth citing (collected)

| Thing | Value |
|---|---|
| Plan file | `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` (v3; Tasks 1–16; plan commit `e4a3dc01`, correction `913b089e`, Task 16 added by `78f755bb`) |
| Base / final HEAD | `b0006c4abb0735cf4e93789b3b59cc6a91d48d81` / `10182b5c90ca09e4620072e8af4c8841a8c23916` |
| Commit counts | 30 to `16b3bc3a` (critic range), **39** to `10182b5c` (git; ledger says 44 — see §1.3.1) |
| Repo size at final HEAD | **73** Go packages; `go test ./...` = 71 `ok` + 2 `[no test files]`, 0 FAIL |
| Gate figures | golden 196 steps / 179 events / 99 files; runbook 150 passed / 0 failed; security-check-test 56 passed / 0 failed (43/0 at Task 13A time); verify-full 13/13 |
| Release artifact | `sha256 f8d75ad544409dc4a2bac93d155abd7227e45f5924005403b759aede5eec6db2`, 20017314 bytes (20M), static ELF, embedded assets 32 schemas / 54 stage prompts / 10 playbooks / 13 archetypes / 83 commands |
| Asset-manifest deltas named in this trail | `sandbox_execution.schema.json` sha256 `00ecd581…` 5171 B → `0a22d3ee…` 5225 B (Task 2); `RUNBOOK.md` sha256 `f1843f46…943b807` 110383 B → `41e40478…52de53` 110337 B (Wave 2 addendum) |
| Legacy tree hash | `f62c95c0a947f94e15328ee0d08fc1b70ab31ec6` (cross-checked by two reviews) |
| Task 8 production hunk digest | md5 `541b9f04667873e2de12d1c2f48bec8d` (hand-off == commit == post-mutation restore) |
| Lock budget | production exactly `5 * time.Second`; `-race` test builds exactly 50s (`raceLockBudgetFactor = 10`), both pinned by `TestLockBudgetMatchesBuild` |
| F1 green | `ok websec/internal/state 195.626s` (`-race`, `-count=3`) |
| Advisory IDs | stdlib `GO-2026-6218` (net/url), `GO-2026-6090` (crypto/tls), `GO-2026-5972` (encoding/asn1) + 6 more stdlib, all fixed in go1.26.3–1.26.6; `golang.org/x/text` **`GO-2026-5970`** (fixed v0.39.0). The brief's `GO-2026-4970` was wrong (ledger corrected) |
| Task 4 refusal ids (example run) | `REP-05ba614a` old bytes → exit 2; `REP-91182d3d` new bytes → exit 0 (golden); `REP-70a9cd95` old `note.md` → exit 2; `REP-d8a1a7ac` new → exit 0 |
| Step-12 campaigns | priced `C-10ab2d8738` (15, `price_table`), never-priced `C-50abeacbb3` (14), legacy `C-45488bdaf5` (14) |

### 8.6 Pending at the close of this trail (all recorded, none hidden)

1. Push/merge approval — the branch was never pushed by this trail (it is now an ancestor of `main`).
2. Bare-metal `-race` sensitivity adjudication for the r13 harness (critic §what-would-make-it-ten (ii).2).
3. Advisory-DB freshness ruling for release-host scans (critic (ii).3).
4. Artifact **digest binding** at the relevance gate (Task 4 review observation 1) — explicitly assigned to the follow-up work, never landed here.
5. Task 10's "brief shows it" clause — closed by `fabc7d18` per the ledger; the Phase C review's alternative ("get an operator ruling that plan-JSON + debt counts satisfy the clause") was not taken.
6. YAML alias/recursion cap; `scripts/p2-docker-e2e.sh`'s stale "15 registered" wording; `verify-full.sh` running no dependency scan (Task 15 concern 3); 0/2 gold discovery (out of scope by design).


---

# Digest §III — the gold-findings closure trail

# Digest — The gold-findings closure trail (2026-09-18)

Sources digested (all 26 files in `docs/sdd/gold-plan/` + the executing plan):
`final-fixes.md`, `final-fix-review.md`, `final-fix-review-package.md`, `final-review.md`,
`progress.md`, and for each of Tasks 1–5 the `*-brief.md` / `*-report.md` / `*-review.md` /
`*-review-package.md` set (Task 4 and Task 5 also have `*-fix1-review.md`); plus
`docs/superpowers/plans/2026-09-18-gold-findings-closure.md` (the plan this trail executed, 475 lines).

Conventions in this digest: **quoted text is verbatim from a source**, in blockquotes or backticks.
Commit shas printed in full were either stated in the sources or resolved with `git rev-parse`
(short forms are what most sources carry). Numbers are always labelled with what they measure.

---

## 1. What this trail was — the goal (closing the G-01/G-02 gold findings), base/head commits, size

### 1.1 The goal, verbatim from the plan

> **Goal:** Close the discovery-axis gaps that produced 0/2 on `web3sec-final/targets/gold-findings.json`
> (Morph L2 @ `22ca805e`) — enforce evidence relevance, rank adversarial lifecycle surfaces, make
> evidence reachability visible, and make the benchmark score measurable and repeatable.

> **Architecture:** Four framework changes (invariants gate, orchestrator queue minting, briefing
> reachability line, gold scorer script) plus an operator-run re-evaluation protocol. The campaign
> re-run itself is operator-driven work — no task automates exploit reasoning.

The plan also fixes what success means, explicitly to stop tasks being judged on score movement:

> this plan's deliverables are measured by **framework quality and measurement repeatability** — the
> exec-relevance gate refusing theater evidence, the cockpit ranking the adversarial game,
> reachability visible at planning time, the score reproducible by one command. **The re-run score is
> NOT a deliverable of this plan.** Only Task 2 plus the operator's own campaign session can plausibly
> move 0/2; Tasks 1/3/4 raise the honesty and measurement bar and must not be judged against score
> movement they were never designed to produce.

### 1.2 The defect/wish mapping the plan retired (single table, defect numbers only)

`morph/FRAMEWORK_EVALUATION.md` numbers its failure list as defects 1–7 and its wishes 1–6; the
schemes are offset (wish 4 = defect 6, wish 5 = defect 5). The plan uses **defect numbers only**:

| Defect | Closed by |
|---|---|
| 1. Liveness doctrine unenforced | hardening Task 3 (done) |
| 2. Cockpit ranks comfort, not risk | hardening Tasks 10/12 + **this plan Task 2** |
| 3. Cold probe surface silent | hardening Task 11 (done) |
| 4. Amplifier signal misweighted (no adversarial-game surface) | **this plan Task 2** |
| 5. Evidence ceiling invisible at planning time | **this plan Task 3** |
| 6. `invariant-verify` accepts execs that never exercised the invariant | **this plan Task 1** |
| 7. Bookkeeping friction | hardening Tasks 4A/5/6/7/8/16 (done) |
| Measurement loop | **this plan Tasks 4-5** |

### 1.3 Base, head, commits, size

- Branch/worktree: `production-readiness` in `.worktrees/production-readiness`.
- **BASE `d9da34285b644e320e206694c18c546d6e664021`** — `progress.md`: "Plan v2 committed at d9da3428
  (union of three external reviews); executing Tasks 1-5."
- **HEAD `64d7b11ba3673a01db2f3858d55129bdec1e2343`** — "PLAN COMPLETE (d9da3428..64d7b11b)."
- Range size: **9 commits, 20 files changed, 2386 insertions(+), 40 deletions(-)** (`git diff --stat d9da3428 64d7b11b`).
- Routing (operator): implementer `b-ai/deepseek-v4.1-flash`, reviewer `b-ai/glm-5.3-flash`.
- Tech stack: "Go 1.26.2 (toolchain `go1.26.6`), stdlib only; Python 3 stdlib for the offline scorer;
  existing SDD flow".
- The plan file itself is 475 lines; its closing "Self-Review Record" states three independent
  external reviews were applied, resolving the matching-semantics contradiction all three found.

| # | Commit | Subject | Diffstat |
|---|---|---|---|
| base | `d9da34285b644e320e206694c18c546d6e664021` | plan v2 (union of three external reviews) | — |
| T1 | `55be2c2e9ab279b13d57926502e00fd7e75d2094` | `fix(invariants): exec-relevance gate for invariant-verify (defect 6)` | 7 files, +455/−33 |
| T2 | `3c095827ddb967bf08fcf676bc64a4950a2f1f3f` | `feat(orchestrator): adversarial lifecycle machines mint into the work queue (defect 4)` | 5 files, +592/−5 |
| T3 | `280e348d965c9904177854d35389f772438b9de7` | `feat(briefing): evidence reachability line (class confirm floor vs box cap) (defect 5)` | 4 files, +267/−0 |
| T4 | `8b2886ec059444e614efd5e87f219f8a8f2cdc4c` | `feat(eval): offline gold scorer honoring benchmark match criteria` | 3 files, +724/−2 |
| T5 | `99e7e906f4c7ed75357280e1d5792174b0a3daae` | `docs(eval): Morph gold re-run protocol (operator-driven measurement loop)` | 1 file, +240 |
| T4 fix 1 | `e28efeedb4c1d61ff41cf70e5de3a0fad967aaac` | `test(eval): pin FP-budget boundary and bonus short-circuit (review round 1)` | 2 files, +28/−2 |
| T5 fix 1 | `bc80d1513b513e8c26a87c70da9553cead9ddd26` | `docs(eval): schema-valid model skeleton and partial-coverage clarification in re-run protocol (review round 1)` | 1 file, +73/−12 |
| F-B | `50d6da9c6015657afdb69a227f5739385f788303` | `fix(cli): refused invariant-verify citations mint no artifact row (defect 6 residue)` | 2 files, +25/−10 |
| F-A | `64d7b11ba3673a01db2f3858d55129bdec1e2343` | `docs(eval): fresh-campaign requirement for the partial-coverage refusal example` | 1 file, +7/−1 |

`final-review.md` states the seven-commit shape of the task range: "`55be2c2e` (T1) → `3c095827` (T2)
→ `280e348d` (T3) → `8b2886ec` (T4) → `99e7e906` (T5) → `e28efeed` (T4 fix 1) → `bc80d151` (T5 fix 1)",
all "clean, exactly-staged, and in plan order", with historical fixtures untouched across the range.
`final-fixes.md` adds the wave: "Range after this wave: `bc80d151` → `50d6da9c` (F-B) → `64d7b11b` (F-A)."

### 1.4 The 0/2 baseline being closed, and what G-01/G-02 are

The baseline was produced by hand; Task 4 turned it into one command. `task-4-report.md` real run:

```
$ python3 scripts/eval-gold.py --gold .../web3sec-final/targets/gold-findings.json \
      --campaign .../morph/campaigns/C-7f1005ecd5
{"found": [], "missed": ["G-01", "G-02"], "false_positives": 0, "pass": false,
 "bonus": false, "verdict": "FAIL", "verdict_note": "", "operator_confirmed": {}}
exit=0
```

The benchmark itself (`web3sec-final/targets/gold-findings.json`, read-only evidence, outside the
repo — quoted here for framing, it is not one of the 26 assigned sources):

| Gold | `bug_class_accept` | Severity | Match criteria (abridged) | `primary_functions` |
|---|---|---|---|---|
| G-01 | `dos-griefing`, `logic-error`, `economic-invariant` | critical | `prevStateRoot` (previous state root / prevStateHash) not verified when a batch is COMMITTED — only checked in `finalizeBatch`; consequence: sequencer commits a batch with a fake root that passes challenge but can never be finalized → whole chain frozen (liveness loss); optionally the stolen-challenger-deposit variant | `commitBatch`, `finalizeBatch`, `challengeState` |
| G-02 | `logic-error`, `token-integration` | high | `onDropMessage` (drop/refund path for failed deposits) calls `safeTransfer` from the gateway on the custom gateway's L1 token, which was BURNED at deposit so the gateway holds no balance — it must MINT (as `finalizeWithdrawERC20` does) | `onDropMessage`, `finalizeWithdrawERC20`, `_deposit` |

Benchmark pinned target: Morph L2 @ `22ca805e2d09c9d0bddb3e8a52ddd7d3435ce769` (repo
`https://github.com/morph-l2/morph`); eval name `fireproofing-hardest-critical-001`, created 2026-09-07.
Benchmark `scoring` strings (quoted verbatim in `task-5-review.md` V-8 and in the plan):

- `pass`: "G-01 found at CONFIRMED with E4+ evidence (or HYPOTHESIS/INVESTIGATING with the correct root cause named and a working PoC draft)"
- `bonus`: "G-02 also found"
- `false_positive_budget`: "count all other CONFIRMED findings; a submission-ready report that includes G-01 but buries it under 10+ FPs is a partial result"

`contamination_check`: `checked: 2026-09-07`; global store `~/.webv2/shared-memory` (766 rows:
defihacklabs + forge-curated ingests); result CLEAN; strict A/B arm = set `WEBV2_GLOBAL_MEMORY_DIR`
to an empty dir.

---

## 2. The plan's tasks and acceptance criteria (from the plan file)

Global constraints that bound every task (plan §Global Constraints):

- Every go command uses `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`.
- "Toolchain `go1.26.6` resolves via GOTOOLCHAIN auto-download — expected behavior; do NOT vendor or pin a local toolchain."
- "No new Go module dependencies (stdlib only). The scorer is Python 3 stdlib only (no pip installs)."
- "Historical fixtures (`scripts/legacy/`, `web3sec-final/`, `morph/`) are immutable; the scorer reads them, never writes them."
- Evidence honesty: "`CHECKED_AGAINST_CODE` remains an operator-attestation provenance … the new exec-relevance gate strengthens admission, it does not claim mechanical proof of the invariant."
- "No automated exploit development: no task synthesizes exploits, no CI step runs attacks. The re-run protocol is an operator session using the framework normally."
- TDD: "red test first for every code task; deliberate pin updates carry the reason in the commit body; **golden re-pins are tagged in the commit subject** (`(golden: <file>)`) so a later bisect can attribute which task moved which pin."
- "Exact-path staging only; never `git add -A`; work happens in the `production-readiness` worktree unless the operator moves it."
- "Scoring numbers from external datasets entering framework DATA need a `provenance` row per `docs/eval-methodology.md` (claim-intake rubric). The scorer consumes the benchmark file read-only and its output is an eval artifact, not framework DATA."

### Task 1 — `invariant-verify` refuses execs that did not target an `applies_to` contract (defect 6)

Defect quote (plan): "I closed INV-003 (staking liveness) citing a generic full-suite exec
(EXEC-5ca6c7aac3). The framework recorded `CHECKED_AGAINST_CODE` without checking any relation
between the cited exec and the invariant's `applies_to`". Because a foundry full-suite run names every
contract in its output, "the gate must inspect what the exec *ran*, not what it printed."

Produces: `invariants.ExecTouchesInvariant(c *state.Campaign, invID string, execID string) (bool, string)`
— `(true, "")` or `(false, reason)` with `reason` ∈ {`"no-exec-record"`, `"no-command-record"`, `"no-target-match"`}.

Binding matcher semantics (quoted):

> **Matcher semantics (binding, decided after three independent plan reviews):** case-insensitive
> **left-boundary token match** — the lowered command contains the lowered token at a position whose
> preceding character is NOT `[0-9a-z_]` (start-of-string counts as a boundary); there is **no trailing
> boundary**. Explicitly rejected alternatives: (a) regex `\b` on both sides — `\bStaking\b` fails on
> `StakingTest` (no boundary between `g` and `T`), under-accepting exactly the commands the gate must
> accept, since Foundry's `--match-contract` is a regex/prefix filter; (b) plain case-insensitive
> substring — over-accepts (`Staking` would match `Unstaking`).

Ruling on empty `applies_to`: "empty means **unbound → unverifiable**, never wildcard."

Acceptance criteria: Step 0 pre-flight tripwire (`rg -n "forge test\b" … | wc -l`; "if the count
exceeds ~20, STOP and report before proceeding"); red test first; CLI refusal = exit 2 + exact refusal
text + status stays `UNVERIFIED` + **zero new `invariant.verified` events** + no attestation label +
"leaves the registry untouched"; `go test ./... -count=1`, `go vet ./...`, `scripts/golden.sh` all
exit 0; golden pins must not move on the happy path.

### Task 2 — adversarial-lifecycle surfaces mint into the work queue (defect 4)

Defect quote: "The amplifier signal was misweighted for this target — nothing pointed at the
adversarial commit→challenge→finalize game" (structural diagnosis: "nothing enforces that the
highest-risk unmodeled surface becomes the next action"). Existing planner `scoreRow` constants are
reused, not replaced: `untouched*1.0 + severity*2.0 + openQ*1.5`, slot class primary.

Produces: `orchestrator.AdversarialLifecycleMachines(model validation.Value) []string` (sorted
machine names).

Binding cardinality rule (quoted):

> a machine qualifies only when **≥ 2 distinct** adversarial-vocabulary tokens occur (left-boundary,
> case-insensitive) across its name and transition action names combined. The vocabulary is
> `commit, challenge, finalize, settle, claim, withdraw, dispute, prove, refund, liquidate, redeem`.
> Rationale: a true adversarial game is a commit→challenge→finalize *chain*; a lone `withdraw` (every
> vault), lone `claim` (airdrops), lone `redeem` (receipt tokens), lone `settle` (oracle fulfillment)
> is benign happy-path surface, and single-verb matching would mint spurious rows — the exact noise
> this task exists to remove.

Binding id-scheme law (quoted): "rows get positional ids `LC-001…` assigned over sorted machine names
at mint time … **The stable handle is the machine NAME, never the id** … Any golden pin that
references an LC-id by value is a review-blocking finding." Asset-flow verbs
(deposit/transfer/relay/swap/mint/burn) are "deliberately NOT in the vocabulary".

Acceptance criteria: Step 0 oracle blast radius recorded; dedup scope = "the ENTIRE existing work
queue … not just `bootstrapOpenQuestions`' output"; row text names machine + verb chain and is
command-first per the Task 7 law; four named tests (mint, negative cases, queue row with `slot == now`,
dedup + coverage); package + full + vet + golden gates; oracle re-record only if a fixture machine
qualifies.

### Task 3 — brief renders evidence-reachability per bug class (class floor vs box ceiling) (defect 5)

Re-derivation (plan): the eval claimed "G-01's accepted classes floor at E6 (economic-invariant)" —
but `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR` pins `dos-griefing: E4` and `logic-error: E4`,
and the eval box reached E4. "So CONFIRMED for G-01's accepted classes was **locally reachable**; the
cockpit simply never said so." A new status was explicitly rejected ("a cross-gate state-machine change
for no scoring gain").

Produces three contract symbols: `findings.ClassConfirmFloor(class) string` (map value, else `"E5"` =
`STATUS_FLOOR["CONFIRMED"]`), `findings.ReachableLocally(class, cap) bool`, and
`briefing.ReachabilityLine(classes []string, cap string) string`.

Binding rendering rule (quoted): "reachable classes first, fork-required classes second, each group
alphabetized; reachable clause `evidence reachability: CONFIRMED locally reachable for <c1> (floor
<F1>); fork required for <c2> (floor <F2> > <cap>)` — **one class per clause with its own floor
value** (this exact form is what the test pins; the earlier prose with comma-joined classes and
`floor ≤ E4` was inconsistent and is superseded)." Edge cases: all reachable → omit the fork clause;
all fork-required → omit the reachable clause and start with `evidence reachability: fork required
for ...`; empty class list → `""`.

Acceptance criteria: Step 0 reads the REAL floor map and never pins an assumed key; the line is
rendered "immediately after the cold-probe warning line (Task 11)" with "the reachability line's index
exactly one greater than the cold-probe warning's index"; advisory only ("no gate, proof, or phase
transition reads it"); gates include `scripts/runbook-walkthrough.sh`.

### Task 4 — offline gold scorer (`scripts/eval-gold.py`) (the measurement loop, half 1)

"The 0/2 score was produced by hand. This task makes it a repeatable command with hermetic tests,
honoring the benchmark's own `match_criteria`, `pass`, `bonus`, and `false_positive_budget` strings
verbatim (read from `web3sec-final/targets/gold-findings.json`, never re-typed). The scorer is offline
analysis of a finished campaign record — it never runs tooling against a target."

Pinned stdout schema (decision table): `found`, `missed`, `false_positives` (int), `pass`, `bonus`,
`verdict`, `verdict_note`, `operator_confirmed`. Binding rules: "`pass` | bool | true iff G-01 is in
`found`. **Independent of FP count and of operator confirmation.**"; `PASS` if pass AND
`false_positives < 10`; `PARTIAL_RESULT` if pass AND `false_positives >= 10` ("the budget is
verdict-affecting at that boundary, read from `scoring.false_positive_budget` at runtime, not
hardcoded"); `operator_confirmed` is "Advisory only — it never changes `pass`/`bonus`/`verdict`; it
exists so a human semantic judgment is not silently laundered into the machine verdict."

Acceptance criteria: exit 0 on any well-formed scoring run ("scoring is not a gate"); exit 2 with a
clean stderr message and no raw traceback for every malformed input; `events.jsonl` parsed
line-by-line; schema-drift guard; keyword matching over prose uses `(?i)\b<tok>\b` ("this deliberately
differs from Task 1's command matcher, which operates on shell commands"); the scorer never mutates
the campaign or the benchmark. **Not** wired into `verify-full.sh`: "the 13-step pin is deliberate; a
python step would add an interpreter dependency to the release gate — YAGNI."

### Task 5 — re-run protocol document (the measurement loop, half 2)

"The score only moves when a fresh operator campaign runs against the pinned target on the hardened
binary. This task ships the protocol; executing it is the operator's session (explicitly out of CI and
out of this plan's automation)."

Six mandatory sections, no placeholders: (1) pinned target `22ca805e` with a **fresh**
`bash scripts/release.sh` that must print `RELEASE OK` — the archived log
`docs/sdd/release-final.log` @ `10182b5c` "proves a different checkout was clean and is cited only as
evidence the script itself works, never as a substitute for the fresh run"; (2) contamination re-check
FIRST, machine-global `~/.webv2/shared-memory`, CI persistent-home note ("that is the check working,
not a bug"); (3) campaign protocol, including the three **expected** gate firings; (4) scoring with
the pinned `eval-gold.py` invocation and `--confirm G-01`; (5) honesty rules ("no score pressure on
the record; a miss is recorded as a miss with the failure analysis … numbers learned during the re-run
enter framework DATA only through the `docs/eval-methodology.md` provenance rubric"); (6) out of
scope: "no exploit development automation, no CI execution of the protocol, no benchmark edits (the
benchmark file is read-only evidence; changing it invalidates the comparison to 0/2)."

Acceptance criteria: every command the protocol names must resolve (verified against `--help` or a
scratch campaign, never against the pinned target); drift fixed in the doc before commit.

---

## 3. Task-by-task record

### 3.1 Summary table

| Task | What it built | Commit sha(s) | Gate result | Deviations disclosed |
|---|---|---|---|---|
| T1 exec-relevance gate (defect 6) | `invariants.ExecTouchesInvariant` + `tokenOccursLeftBound` / `isLowerWordByte` / `stripShellQuotes` / `appliesToTokens`; CLI refusal before `VerifyInvariantStatement`; 2 new test files; 3 fixture helpers made variadic | `55be2c2e9ab279b13d57926502e00fd7e75d2094` (BASE `d9da3428`) | `go test ./...` exit 0; `go vet` 0; `golden.sh` 0 — "GOLDEN GREEN: Go run validates" (196 steps); `gofmt -l internal cmd` empty; red-first confirmed | 2 deliberate law changes (empty `applies_to` refuses; `TestInvariantVerifyExecRelevanceGate` part (a) re-pinned to the new text, Task 4 byte-gate pin retained as case (b)); helper-variadic fixture strategy; `tokenOccursLeftBound` new helper because reuse was impossible |
| T2 lifecycle surfaces mint into the queue (defect 4) | matcher + `AdversarialLifecycleMachines` + `bootstrapLifecycleSurfaces` in `internal/planner/plan.go`; orchestrator re-export; schema id pattern widened; manifest resynced | `3c095827ddb967bf08fcf676bc64a4950a2f1f3f` (BASE `55be2c2e`) | focused 8/8 PASS; `go test ./...` **71 packages ok, 0 FAIL**; vet clean; `GOLDEN GREEN` (196 steps, campaign `C-34c0ce6f4b`, 179 events); gofmt clean | 3: mint-site file path (`planner/plan.go`, brief's path wrong), schema widening + manifest resync (mandated by the plan's own id law), matcher located in `planner` (brief allowed `orchestrator`) — plus one **undeclared** deviation the reviewer caught (machine name used as component; machines have no `applies_to` field) |
| T3 reachability line (defect 5) | `ClassConfirmFloor`, `ReachableLocally` (`internal/findings/levels.go`); `ReachabilityLine`, `boxLocalCap`, `openFindingClasses`, one `NextActions` mint (`internal/briefing/briefing.go`) | `280e348d965c9904177854d35389f772438b9de7` (BASE `3c095827`) | findings+briefing ok; `./...` 71 ok; vet clean; `GOLDEN GREEN`; `runbook-walkthrough.sh` **150 passed, 0 failed — WALKTHROUGH GREEN**; no golden re-pin needed | 1: `boxLocalCap = "E4"` is a documented constant, not an envgo read (plan premise false — see §4.4) |
| T4 offline gold scorer | `scripts/eval-gold.py` (344 lines) + `scripts/eval_gold_test.py` (377 lines); plan doc corrected in-commit | `8b2886ec059444e614efd5e87f219f8a8f2cdc4c` (BASE `280e348d`) | 25/25 tests OK (both invocations), red-first 25 failures; `go test ./...` 71 ok / 0 FAIL; vet clean; real benchmark × real Morph campaign reproduces 0/2, exit 0 | 9 concerns; the campaign-dir contract was **wrong in the brief** and corrected to the real record (`findings/F-<id>.json`, real field spellings) with the plan doc fixed in the same commit |
| T4 fix round 1 | boundary + bonus pins | `e28efeedb4c1d61ff41cf70e5de3a0fad967aaac` (BASE `99e7e906`) | 26/26 OK; boundary mutant (`<` → `<=`) fails exactly 2 tests; `go vet` exit 0 (no Go change) | `scripts/eval-gold.py` diff is comments/docstring only — zero behavior change |
| T5 re-run protocol doc | `docs/eval/morph-rerun-protocol.md` (240 lines, six sections, no placeholders) | `99e7e906f4c7ed75357280e1d5792174b0a3daae` (BASE `8b2886ec`) | every named command resolved; no command ever run against the pinned target | 4 drifts fixed in-doc (see §3.6) + 7 concerns |
| T5 fix round 1 | schema-valid skeleton, zero-vs-partial coverage, test count | `bc80d1513b513e8c26a87c70da9553cead9ddd26` (BASE `e28efeed`) | mechanical verification: doc JSON blocks extracted, `json.loads`-parsed, fed to a binary built from HEAD — block 0 exit 0, block 1 exit 2; quoted outputs byte-equal to captured stdout+stderr | 4 deliberate decisions; introduced N-1 (new Important finding) |
| Final fix wave | F-B Go + F-A doc | `50d6da9c6015657afdb69a227f5739385f788303`, `64d7b11ba3673a01db2f3858d55129bdec1e2343` | at `64d7b11b`: `./...` exit 0; vet clean; scorer 26/26; `golden.sh` GREEN re-run live (196 steps, `C-34c0ce6f4b`) | F-B deliberately not expanded (Task 4 byte-gate residual stays parked); D2/D4 optional fold-ins left parked |

### 3.2 The ledger's own task trace (`progress.md`, in order)

`progress.md` is the running SDD ledger; its lines are the authoritative in-trail record:

| Ledger entry | Content |
|---|---|
| T1 implementer | "COMPLETE pending review (55be2c2e; blast radius confirmed empirically = 5 CLI tests; tokenOccursLeftBound new helper, Task 4 matcher byte-identical; INV-3 bypass closed; variadic helpers preserve Task 4 pins; red-first confirmed; gates green)" |
| T2 implementer | "COMPLETE pending review (3c09582; pre-flight blast radius 0 qualifying machines, oracles.json untouched; mint site = planner/plan.go (brief path was wrong), orchestrator re-export; LC- id scheme required widening campaign_plan id pattern `^(Q\|LC)-[0-9]{3}$` + manifest re-sync; 8/8 focused green, ./... 71 ok, vet clean, GOLDEN GREEN)" |
| T1 review | "Spec YES / APPROVED with findings … F1 Important PARKED with ruling: refusal fires after resolveExecArtifact's RegisterOrRefresh so a refused citation still mints an artifact row … candidate for final fix wave (move gate before resolveExecArtifact). F2 minor: appliesToTokens adds NormalizeInvID variants (inert). F3 minor: pre-flight probe drift 210 vs 212." |
| T2 review | "Spec YES / APPROVED … 2 minors report-only: applies_to-components unimplementable -> machine-name-as-component is the correct undeclared deviation [add report bullet], skipped machines consume LC position. Concern 4 ruled COMPLIANT (queue row meets defect-4 law; no brief-line requirement in Task 2)." |
| T3 implementer | "COMPLETE (280e348d; REAL floor map pinned from levels.go: dos-griefing E4, share-price-inflation E6; line renders after cold-probe warning with index pin; deviation: boxLocalCap documented constant E4 instead of envgo read … — reviewer to adjudicate)." |
| T3 review | "Spec YES / APPROVED … boxLocalCap constant ruled COMPLIANT — plan premise false, envgo exports no accessor; cleaner follow-up = pure map-read over profileMaxLevel. Minor deferred: task14_reachability_test.go:245-247 comment claims an unexercised terminal-finding pin." |
| T4 implementer | "COMPLETE (8b2886ec; real store = findings/F-*.json + events.jsonl + artifacts/invariant_links.json, plan doc corrected in-commit; 25/25 unittest; real benchmark x real Morph campaign reproduces 0/2 exit 0 in one command). Review pending; rulings requested: accepted-state breadth (HYPOTHESIS+attempt vs CONFIRMED-only), MIN_KEYWORD_HITS=3 quorum." |
| T4 review | "Spec YES / APPROVED with findings … MEDIUM-1: FP-budget boundary unpinned (9/11 pass under both >= and >) — fix round 1: add 10-FP fixture asserting PARTIAL_RESULT; LOW-2 dead INVESTIGATING branch comment; LOW-3 bonus-short-circuit untested. Concern rulings: accepted-state breadth faithful, quorum synthetic-only disclosed, missing-dir exit 2 right, confirmed-missed-key superset OK." |
| T5 implementer | "COMPLETE (99e7e906; 240-line protocol; 4 drifts fixed in-doc incl. $WEB3SEC2 path base, index-before-probes, real CLI signatures, memory.json contamination grep; fixture checkout at 8e8b6c5 != pinned 22ca805e until operator takes scratch worktree — documented)." |
| T4 fix 1 | "fix round 1/5 complete (e28efeed; all 3 findings ADDRESSED per … task-4-fix1-review.md; boundary mutant-proven; 26/26 both invocations) — Task 4 COMPLETE" |
| T5 fix 1 | "fix round 1/5 complete (bc80d151; F-1 schema-valid skeleton + F-2 partial-coverage clarification + F-3 26-tests; every quoted output byte-verified against real scratch runs incl. the stage-37 refusal firing) — scoped re-review pending" |
| T5 re-review | "fix round 1 re-review all ADDRESSED (N-1 caught in-sequence vs fresh-campaign nuance) — Task 5 COMPLETE" |
| Final review | "all five tasks implemented as specified; two must-fix residues (F-B refused-citation artifact row; F-A protocol refusal reachability) -> ONE fix wave (50d6da9c Go + 64d7b11b doc) -> scoped re-review both ADDRESSED, no new breakage, gates re-verified live at 64d7b11b (suite exit 0, vet clean, scorer 26/26, GOLDEN GREEN)" |
| Close | "PLAN COMPLETE (d9da3428..64d7b11b). Parked with rulings: D1 … D6 …; I1 scorer quorum synthetic-only disclosed (first real re-run finding is the datum). P1 superseded by F-B fix." |

Ledger nit: `progress.md` writes the Task 2 sha as both `3c09582` (line 5) and `3c095827` (line 7);
the full sha is `3c095827ddb967bf08fcf676bc64a4950a2f1f3f`.

### 3.3 Task 1 detail — the tripwire, the provenance finding, the blast radius

- **Step 0 tripped the tripwire.** The brief's literal probe returned **210** (> the ~20 tripwire), so
  the first report was filed **STATUS: BLOCKED** ("at Step 0, per the brief's own tripwire — no code
  written, no commit"; `git rev-parse HEAD` still `d9da3428…`). Composition: "Of the 210 matching
  lines, only **6** mention an invariant at all"; top offenders `internal/harness/zz_r32_test.go` (30),
  `internal/cli/cmd_verify_harness_test.go` (24), `internal/sandbox/envseam_test.go` (21).
- **Static blast radius** was then enumerated: 5 CLI tests asserting exit 0 on the `--exec` path
  (`TestInvariantVerifyExecHappyPath` `:107`, `…ExecRerunRefreshesTheSameArtifact` `:136`,
  `…ExecFallsBackToTheStderrLog` `:182`, `…ExecRelevanceGate` part b `:320`, `TestInvariantVerifyExec`
  `cmd_invariant_verify_test.go:150`), plus a colliding pinned assertion
  (`TestInvariantVerifyExecRelevanceGate` part (a) pinned the Task 4 text `does not reference INV-008`).
  The report also self-corrected one wrong entry in that list (§15: `TestInvariantVerifyUnknownIDExits2OneLine`
  uses `t15Register`, not the seeder).
- **The controller ruling lifted the tripwire** ("the literal 210 is a probe artifact; the true radius
  is the pre-flight number") and fixed four decisions; part 2 of the report supersedes BLOCKED.
- **Blast radius then confirmed empirically**: with the fixture migration temporarily reverted, the
  suite fails **exactly 5** tests and no more, each `exit 2, no-target-match`.
- **Matcher provenance finding** (required by the brief): `referenceTokens` (`invariants.go:913`)
  builds only the token list; matching lives in `artifactReferencesInvariant` (`invariants.go:888`,
  compile at `:898`) as `regexp.Compile("(?i)\\b" + regexp.QuoteMeta(tok) + "\\b")` — a full `\b…\b`
  match, i.e. rejected-alternative (a). "Verdict: NOT left-boundary ⇒ reuse is impossible." Second
  finding: `referenceTokens` **prepends the invariant id**, so reusing it would let
  `forge test --match-contract INV-3` satisfy the gate — "an unreviewed hole the brief's test table
  does not cover"; the implementation builds tokens from `applies_to` alone and pins the closure with
  `TestExecTouchesInvariantIgnoresInvariantID`.
- Refusal text implemented byte-for-byte as the brief binds it (deliberately **not** `PyReprStr`-wrapped,
  so the pinned substring survives): `invariant verify failed: cited exec <ID> does not target any
  applies_to contract of <invID> (<reason>)`.
- Files in the commit (7): `invariants.go` +121; `invariants_exec_relevance_test.go` +140 (new);
  `invariants_test.go` 12±; `cmd_invariant_verify.go` +10; `cmd_invariant_verify_exec_relevance_test.go`
  +100 (new); `cmd_invariant_verify_exec_test.go` 71±; `cmd_invariant_verify_test.go` 34±.
- Task 1 concerns left standing: the gate reads the **recorded command string**, so "a forged or
  `sh -c`-wrapped record is out of scope"; `ExecTouchesInvariant` has no error return, so an unreadable
  store folds into `no-target-match` / `no-exec-record` ("fail closed, but the caller cannot
  distinguish 'store broken' from 'nothing matched'"); `tokenOccursLeftBound` is byte-wise over
  `[0-9a-z_]`, so a non-ASCII byte before a token counts as a boundary ("not pinned and not reachable
  with Foundry-style ASCII contract names").

### 3.4 Task 2 detail — the mint, the schema widening, the operator path

- **Step 0**: `rg -n -i "commit|challenge|…|redeem" internal/orchestrator/testdata/` → "53 raw text
  hits, but **0 machines meet the cardinality rule**". The only pinned machine is `vault-lifecycle`
  with trigger `pause()` → 0 vocabulary tokens, so the `planned`/`queues` oracle rows cannot move;
  `oracles.json` and `internal/planner/testdata/oracles.json` untouched. Repo-wide cross-check: the
  only ≥2-hit machines are *loose* fixtures (bare-string transitions, or `id` instead of `name`) that
  do not mint because the matcher reads the schema shape.
- Row shape: `risk 0.9`, `budget_class cheap` → `DecisionRule(0.9,"cheap") = "now"`,
  `components = [machine name]`, `trajectories = ["lifecycle"]`, id `LC-%03d` positional over the
  sorted machine list; `bootstrapLifecycleSurfaces` is called LAST in `DefaultPlanFromModel` so every
  pre-existing Q-number stays byte-for-byte.
- Skip predicate `lifecycleSurfaceCovered`: (a) any already-minted queue row carries the machine name
  as a **component** (exact equality, not substring), (b) any live finding's
  `affected[].contract`/`.path` equals the name, (c) the coverage ledger marks the machine's in-scope
  contract **swept** (the same "untouched" predicate queue scoring uses).
- **Real CLI evidence** (scratch campaign `C-8b8fdab6d5`): `work_queue[0]` is
  `{"priority_id":"LC-001","question":"review adversarial lifecycle rollup_finalization (commit → challenge → finalize) — no covering finding","risk":0.9,"cost":"cheap","slot":"now","trajectories":["code"],"components":["rollup_finalization"],"invariant_ids":[],"required_context":["structural_index","protocol_model"]}`;
  all queue rows `['LC-001','Q-001','Q-002','Q-003','Q-004']`; `token_vault minted? False`.
  Answering closes it with no new code (`LC-001: status -> answered …`, exit 0).
- **Schema widening was mandatory, proven by temporary revert**: `task13_lifecycle_surfaces_test.go:252:
  plan: campaign_plan validation failed at priorities/4/id: 'LC-001' does not match '^Q-[0-9]{3}$'`.
  Fix `^(Q|LC)-[0-9]{3}$` + `python3 scripts/sync-asset-manifest.py`; only the `campaign_plan` manifest
  entry moved (`eaadacff…` → `3a021cb7…`, 10631 → 10636 bytes); `"X-001"`-style ids still fail.
- Id-scheme audit: nothing pins an LC id by value (`rg '"LC-'` finds only the definition at
  `plan.go:750`, one comment, and the test's `strings.HasPrefix(row.ID, "LC-")` at test:345); other id
  consumers skip non-`Q-` ids explicitly (`planner/answered.go:nextPriorityID`,
  `probes/emit.go:nextPrioritySeq`, `findings/transitions.go:nextPriorityNumber`).
- **Brief path drift**: `rg -n "bootstrapOpenQuestions" internal/orchestrator` finds **nothing** —
  both symbols live in `internal/planner/plan.go` (Task 10's commit `cbdd93d5` did the same thing, and
  the hardening plan's Task 10/12 "Files: internal/orchestrator" line has the same drift).
- Reviewer verdict on the undeclared deviation: the protocol-model schema gives machines only
  `name`/`states`/`transitions`/`suspect_properties` (no `applies_to` — that field is on *invariants*),
  so "the brief's instruction was unimplementable as written"; machine-name-as-component is "the
  coherent choice". Ruling on the operator surface: "**RULED: COMPLIANT; no briefing line is required
  by this task**" — the row reaches the operator via `plan --json` / attention, and defect 4's law is
  satisfied by `work_queue[0]`, asserted by `TestLifecycleSurfaceRanksFirst`.

### 3.5 Task 3 detail — the real floor map and the exact rendered line

- **Step 0 read of `internal/findings/levels.go:52-78` `CLASS_CONFIRM_FLOOR`, 16 keys**:
  E4 (9) `access-control`, `signature-replay`, `upgrade-initializer`, `authorization`, `reentrancy`,
  `logic-error`, `dos-griefing`, `token-integration`, `share-price-accounting`; E5 (3)
  `oracle-manipulation`, `flash-loan`, `liquidation-logic`; E6 (6) `share-price-inflation`,
  `economic-invariant`, `bridge-message`, `cross-chain-replay`, `frontend-injection`, `infra-boundary`.
  "**An E6 key exists, so the plan's placeholder is the real value**" — the committed test pins
  `ClassConfirmFloor("share-price-inflation") == "E6"` and `"nonexistent-class"` → `"E5"`.
- **No envgo cap accessor exists**: `e4_capable` is a key of `envgo.Doctor`'s result (`env.go:407`);
  per-profile ceilings live in the **unexported** `profileMaxLevel` (`env.go:456`: isolated container
  profiles E4, `fork-runner` E5); `Doctor` shells `docker info` (20s timeout) + a 5s fork-RPC probe.
  Resolution: `boxLocalCap = "E4"` at `internal/briefing/briefing.go:2081`.
- Mint position: `briefing.go:2216-2229`, immediately after the Task 11 cold-probe block
  (`briefing.go:2201-2214`) and before the probe-surface block. Classes come from
  `openFindingClasses` (`briefing.go:2088`): non-`findings.IsTerminal` findings with a non-empty
  `root_cause.class`, deduped.
- **Exact rendered line** (`task-3-logs/reachability-verbose.log`):
  `task14_reachability_test.go:92: cold-probe warning index 0, reachability line index 1:`
  → `evidence reachability: CONFIRMED locally reachable for dos-griefing (floor E4)`.
- No golden re-pin was needed: `check-golden.py` does not byte-compare `brief` stdout, and every
  fixture that pins next-actions exactly (the fresh `"Acme"` campaign, the Task 7 `lawBrief` with a nil
  campaign, and the closed-pass campaign) renders no line.
- Task 3 concerns accepted by the reviewer: the "fork required" wording also covers E4 classes on a
  container-less box (plan pins the exact bytes); an unknown cap makes every class fork-required
  (matches `LevelIndex`'s refusal, unreachable from `NextActions`); dedupe lives in the collector, not
  the renderer.

### 3.6 Task 4 / Task 5 detail — the real campaign contract and the protocol's drifts

**Task 4 Step 0 replaced the brief's campaign-dir contract with the real record** (corrected in the
same commit, plan doc included):

| Brief said | The real record says | Pinned in Go by |
|---|---|---|
| `findings.json` (one JSON array) | `findings/F-<id>.json`, one finding object per file | `internal/state/campaign.go` (`Campaign.FindingsDir`), `internal/findings/storage.go` (`FindingPath`, `LoadAllFindings` → `validation.ListPrefixedOptional(dir, "F-", ".json")`) |
| `id` | `finding_id` | `findings.SaveFinding` → `validation.Validate(_, "finding", 1)` vs `assets/schema/finding.schema.json` |
| `bug_class` | `root_cause.class` | same schema |
| `text` | `title` + `root_cause.description` (+ optional `root_cause.mechanism`) | same schema |
| `primary_functions` | `affected[].function` (optional per item; `path` required) | same schema |
| `artifacts` | `evidence[].artifact_id` | same schema |
| `links.json` (Step 0 grep) | `artifacts/invariant_links.json` — not part of this scoring contract | `internal/invariants.SaveLinks` (`internal/state/artifacts.go:824`) |
| `events.jsonl` | `events.jsonl` — **correct as briefed** | `internal/state/campaign.go` (`Campaign.EventsPath`) |

Real records inspected: `scripts/legacy/campaigns/C-45488bdaf5/findings/F-*.json` (2 findings, all 14
schema-`required` keys present) and the real Morph campaign
`/home/xand/Projects/dsh-plugins/websec2/morph/campaigns/C-7f1005ecd5` (empty `findings/` + a 62-line
`events.jsonl`).

Scorer implementation facts: accepted evidence state = `CONFIRMED` with highest `evidence[].level` ≥ E4
(ladder of `internal/findings.EVIDENCE_ORDER`), **or** `HYPOTHESIS`/`INVESTIGATING` with
`verification.reproduction.attempts[].outcome == "reproduced"`; matching = ≥ `MIN_KEYWORD_HITS` (3)
distinct `match_criteria` content tokens **and** one `primary_function`; the budget is parsed at
runtime from the prose (`(\d+)\s*\+?\s*FPs?` → 10 in the real file) and a budget prose with no number is
**refused (exit 2), never defaulted**; `events.jsonl` is read line-by-line and validated only; a test
hashes the campaign tree and the benchmark before/after a run to prove non-mutation.

**Task 5's four in-doc drifts** (found by actually resolving every command):

1. The plan's pinned `--gold web3sec-final/targets/gold-findings.json` does **not** resolve from the
   repo root (as `../web3sec-final/…` the scorer exits 2: `eval-gold: ../web3sec-final/targets/gold-findings.json not found`).
   Fix: the doc defines `WEB3SEC2` and uses `$WEB3SEC2/web3sec-final/targets/gold-findings.json`.
2. `probes run --emit` needs an index first — the doc orders `webv2 index <C-id> --src <target>` before the emit.
3. Real CLI signatures: the campaign is positional *before* the subcommand (`webv2 probes <C-id> run --emit`).
4. The contamination check must grep `memory.json`, not the store directory — a directory-wide search
   hits `manifest.json`, whose provenance note literally contains "ScaBench" (a migration note, not a corpus row).

Step 2 resolution evidence (`task-5-logs/command-resolution.log`): fixture checkout `8e8b6c5…` is
**not** on `22ca805e` (the commit object exists, `git cat-file -t 22ca805e` → `commit`);
`webv2 shared --verify` → exit 0, `integrity: PASS — 0 problem(s)`, **766 approved rows**;
contamination `rg` → exit 1, no matching row → **CLEAN today**; `webv2 init --program "Morph L2"` →
`C-386d8b3bf7`; `probes … run --emit` → exit 2, `probes: no structural index for C-386d8b3bf7 — run
'webv2 index …' first`; `bash scripts/release.sh` is `-rwxr-xr-x`, `bash -n` clean, prints
`RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean`
(`release.sh:164`); archived `docs/sdd/release-final.log` last touched at `10182b5c`, line 36 carries
the same `RELEASE OK`.

---

## 4. The final review and the final fixes

### 4.1 `final-review.md` — the whole-plan gate at `bc80d151`

Scope: "**Role:** last gate before the plan is declared complete. Independent read-only review of the
whole plan execution (Tasks 1-5 + two fix rounds); no tracked changes."

| Gate re-run at `bc80d151` | Result |
|---|---|
| `go test ./... -count=1` (repo cache convention) | **exit 0** — all packages ok |
| `go vet ./...` | clean (exit 0) |
| `python3 -m unittest scripts.eval_gold_test` | **26/26 OK** |
| `scripts/golden.sh` | **not re-run**; inherited GREEN from the Task 3 reviewer's reproduction at `280e348d` — "**no Go file changed after `280e348d`** (8b2886ec/e28efeed are scripts+tests-only, 99e7e906/bc80d151 docs-only), so golden coverage state is byte-identical at HEAD" |

Per-task verdicts: T1 "implemented as specified" (one open residue P1); T2 "implemented as specified";
T3 "implemented as specified"; T4 "implemented as specified (fix round closed all findings)"; T5
"implemented as specified (fix round closed F-1/F-2/F-3; one open residue: N-1)". Historical fixtures
untouched across the range; one schema file widened with the manifest hash resynced, "necessary for
Task 2's mandated `LC-%03d` ids, strictly additive".

**F-B — IMPORTANT — must fix before merge: refused citations still mint a "checked against code"
artifact row (P1).** `internal/cli/cmd_invariant_verify.go:97-107` (gate) vs `:175-183`
(`RegisterOrRefresh` inside `resolveExecArtifact`); "the mint precedes the gate on every `--exec` path,
including the relevance refusal." Why it crossed the must-fix bar (and why the Task 1 reviewer's "park
as follow-up" was upgraded):

1. The minted note — `invariant INV-3 checked against code (exec EXEC-…)` — "is a durable record
   asserting a verification the gate just refused. That is the exact defect-6 class ('records asserting
   verification that didn't happen') this plan exists to close".
2. "It contradicts the plan's own Step 1 contract ('leaves the registry untouched — assert ALL of …');
   the committed test drops that assertion, so the spec gap is silent."
3. "The fix is small, local, and provably pin-free: hoist the mint to the tail of
   `resolveExecArtifact` … **no existing or new test asserts registry state on any refusal path**, so
   nothing moves."

**F-A — IMPORTANT — must fix before merge: protocol §3.2-1's quoted refusal is unreachable in the
doc's own sequence.** `docs/eval/morph-rerun-protocol.md:167-199` (open at `bc80d151`, carried from
`task-5-fix1-review.md` as N-1). The §3.1 skeleton load takes the zero-coverage synthesis path and
mints a `liveness-template` invariant numbered `INV-1` covering `rollup_finalization`; loading the
§3.2-1 variant into the same campaign refreshes that row in place, `applies_to` never lands, so
coverage is `{rollup_finalization}`, the uncovered set is `{message_queue}`, and the refusal names
**`message_queue`** — not the doc's quoted `state machine(s) rollup_finalization have no liveness
invariant`. The G-01 payoff line then fails in the natural in-sequence flow, "even though the doc
labels its outputs 'verbatim from a scratch campaign'".

**Seam audit (T1 gate × T2 queue minting × T3 brief line) — no further defects found.** "The three
features operate on disjoint stores and axes … the only cross-task interaction found is F-B itself
(Task 1's mint ordering)." Operator-surface note (observation, already adjudicated COMPLIANT):
the LC row reaches the operator via `plan --json` / the attention queue, not as a first-class
next-actions line; "If the cockpit brief is ever extended to render unattempted queue rows directly,
that is the natural home for it."

Minor observations (no action required): **M-1** the in-range plan-doc edit (Task 4 §4, `99e7e906`)
still says "25 tests" while the protocol doc and the suite say 26; **M-2** `ReachabilityLine`'s `cap`
parameter shadows the builtin (plan-mandated signature, vet clean, "Leave it"); **M-3** `boxLocalCap`
is pinned only behaviorally.

### 4.2 The triage table (parked/deferred items and their rulings)

| Item | Ruling | Reasoning (abridged) |
|---|---|---|
| **P1** — refusal fires after `RegisterOrRefresh` (Task 1 F1 Important) | **FIX BEFORE MERGE** → F-B | "contradicts the plan's own Step 1 contract, mints the exact defect-6 dishonesty record, fix is ~10 lines + one test assertion and provably moves no pin" |
| **N-1** — protocol §3.2-1 in-sequence refusal mismatch (Task 5 fix-round Important) | **FIX BEFORE MERGE** → F-A | "One-line doc edit; the doc is a primary plan deliverable and labels the outputs 'verbatim'" |
| **D1** — `trajectories` enum quirk (`["lifecycle"]` renders `["code"]`) | **PARK** | "Pre-existing by construction (`TrajectoryToEnum` keyed on long spellings; `queue.go` untouched by this range; affects every short-named plan row equally). Fixing moves pinned oracle rendering repo-wide." |
| **D2** — `appliesToTokens` adds `NormalizeInvID` variants | **PARK** | "Inert for contract names … widens acceptance only when `applies_to` literally contains `INV-xxx` … Optional one-sentence doc-comment addition" |
| **D3** — Step 0 probe drift 210 vs 212 | **PARK** | "Report-annotation nit only; the count is mentions-not-fixtures noise, measured pre-migration vs committed tree; zero code impact." |
| **D4** — `task14_reachability_test.go:245-247` comment overclaims a terminal-finding pin | **PARK** (may fold into F-B's fix wave) | "LOW; the production behavior is real (`IsTerminal` filter in `openFindingClasses`) — only the documented pin is missing." |
| **D5** — LC-id schema description note | **PARK** | "Doc nit in the schema's `id` property description; no consumer reads it" |
| **D6** — `boxLocalCap` constant instead of envgo read | **PARK** | "Ruled COMPLIANT (plan premise false; live probe would violate the pure-view architecture). Cleaner follow-up = pure, non-probing accessor over `profileMaxLevel`; the `ponytail:` hook is in place." |
| **I1** — scorer `MIN_KEYWORD_HITS=3` quorum calibrated synthetic-only | **PARK** | "Disclosed at every layer … No real finding exists to calibrate against; the FP budget and `--confirm` are the human layer; the first fresh re-run finding is the calibration datum" |

"Net: **zero** of the parked items block merge on their own; the two must-fix items are P1 and N-1
(both already discovered by the per-task reviews — no new blocking seam defect was found)."

### 4.3 The final verdict of the review, verbatim

> **PLAN COMPLETE PENDING TWO SMALL FIXES — not yet declarable as-is.**

> After those two land (one Go commit + one doc commit, or one combined fix commit; focused tests +
> `go test ./... -count=1` + the 26-test scorer suite are sufficient re-verification — no golden
> coverage is touched by either fix), the plan should be declared complete and the operator's re-run
> session (Task 5's protocol) is the next and final actor.

### 4.4 The fix wave (`final-fixes.md`) — F-B then F-A

**Commit 1 — F-B: `50d6da9c6015657afdb69a227f5739385f788303`**
`fix(cli): refused invariant-verify citations mint no artifact row (defect 6 residue)`
Files (exact-path staging, 2 files, +25/−10): `internal/cli/cmd_invariant_verify.go`,
`internal/cli/cmd_invariant_verify_exec_relevance_test.go`.

Red, against unmodified code (test added first):

```
$ go test ./internal/cli -run TestInvariantVerifyRefusesUntargetedExec -count=1
--- FAIL: TestInvariantVerifyRefusesUntargetedExec (0.01s)
    cmd_invariant_verify_exec_relevance_test.go:91: refused citation minted artifact row OTH-06102e5c: note "invariant INV-3 checked against code (exec EXEC-0000000002)"
FAIL
FAIL	websec/internal/cli	0.019s
```

"The failing note is the defect verbatim: the row claims 'checked against code' for a citation the
gate refused one frame later."

Fix: hoist the gate into `resolveExecArtifact`, after the `isFile(outPath)` check and before
`RegisterOrRefresh`; delete the gate block from `runInvariantVerify`. "Refusal text byte-identical …
so no pin moved. Ordering of every earlier refusal is unchanged (unknown invariant → missing exec →
incomplete/refused exec → no captured output → exec-relevance → mint)". The new test walks
`c.State()["artifacts"]` and fails on any row whose `note` names `INV-3`.

Green at HEAD: 4 focused tests PASS (`…RefusesUntargetedExec`, `…AcceptsTargetedExec`,
`…ExecHappyPath`, `…ExecRelevanceGate`); `go test ./internal/cli ./internal/invariants` → `ok` 33.080s /
0.235s; `go test ./...` `TEST_EXIT=0`; `go vet` `VET_EXIT=0`; `gofmt -l internal cmd` no output;
`bash scripts/golden.sh` → `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit
surface)`, `GOLDEN_PIPE_EXIT=0`, run root `.scratch/golden/root`, archived tree
`.scratch/golden/tree-go`, **196 steps, campaign `C-34c0ce6f4b`, 179 events, chain intact, 99 files
archived**; `python3 -m unittest scripts.eval_gold_test` → "Ran 26 tests in 1.049s — OK".

"Deliberately not expanded": `TestInvariantVerifyExecRelevanceGate` case (b) (targeted command,
generic log) still mints before Task 4's byte gate refuses — "the final review's stated residual, which
predates this plan and stays parked with its own pins"; D2 and D4 left parked.

**Commit 2 — F-A: `64d7b11ba3673a01db2f3858d55129bdec1e2343`**
`docs(eval): fresh-campaign requirement for the partial-coverage refusal example`
File: `docs/eval/morph-rerun-protocol.md` §3.2-1 (1 file, +7/−1).

Scratch reproduction (2026-09-18, binary built from this tree; fixtures `.scratch/f-a/{skeleton,variant}.json`,
campaigns created with `webv2 init --program "Morph L2"` in an isolated `HOME` under `.scratch/f-a/ws`):

- Fresh campaign → §3.2-1 variant: exit 2,
  `model load failed: protocol model: state machine(s) rollup_finalization have no liveness invariant (one per machine — stage 37)`
- In-sequence §3.1 → §3.2-1, same campaign: skeleton load exit 0 (`model loaded: 0 actors, 0 assets, 0 invariants`,
  stderr `WARNING: the model declares no invariants — the invariant registry was seeded with NOTHING (invariants.seed_empty logged). …`),
  then the variant exits 2 naming `message_queue`.
- Mechanism read directly from `campaigns/C-36f576bbc2/artifacts/invariant_links.json`:
  `INV-1 | applies_to= ['rollup_finalization'] | source= model | statement= LIVENESS: every modeled state machine must be able to advanc…`
  ("unchanged after the refused variant load: the variant's `INV-1` refreshed that row in place,
  `applies_to: ["message_queue"]` never landed").

Doc fix (quoted in the report):

> Load this variant in a **fresh campaign**. In the §3.1 → §3.2-1 sequence the skeleton's synthesized
> `INV-1` liveness template already covers `rollup_finalization`; the variant's `INV-1` refreshes that
> row in place, its `applies_to` never lands, and the gate instead names the *other* machine —
> `state machine(s) message_queue have no liveness invariant` (reproduced 2026-09-18). Verbatim output
> from a fresh scratch campaign, 2026-09-18 (exit 2):

Status table: F-B DONE (`50d6da9c`, red→green, no pin moved); F-A DONE (`64d7b11b`, both flows
reproduced, quote now qualified). Constraints held: "stdlib only, no new module deps, historical
fixtures untouched, no golden re-pin, exact-path staging, refusal semantics never weakened, no
push/merge/delegate."

### 4.5 The scoped re-review (`final-fix-review.md`) — both ADDRESSED, PLAN COMPLETE

Gates re-run live at `64d7b11b`: `go test ./...` exit 0 (local GOCACHE/GOMODCACHE overlay; "workspace
cache is read-only"); `go vet ./...` clean; scorer **26/26 OK**; **`bash scripts/golden.sh` GREEN,
re-run live this session — 196 steps, campaign `C-34c0ce6f4b`, exit 0 (matches `final-fixes.md`
byte-for-byte), so "no pin moved" is confirmed first-hand, not inherited**; `git status` after review
shows only `.scratch/` + pre-existing untracked `.superpowers/`.

F-B ADDRESSED, check by check: gate now at `cmd_invariant_verify.go:169-180`, immediately after the
`isFile(outPath)` refusal and before the `note := fmt.Sprintf(…)` + `c.RegisterOrRefresh(...)` pair;
the moved block's format string is character-for-character the same; the registry-absence assertion
was **red-first independently reproduced by the reviewer** by re-applying `bc80d151`'s
`cmd_invariant_verify.go` against the HEAD test file in a scratch copy — it fails with
`refused citation minted artifact row OTH-657d765b: note "invariant INV-3 checked against code (exec EXEC-0000000002)"`,
and passes at HEAD; `resolveExecArtifact` has "exactly one caller (`runInvariantVerify`, line 94)";
the `--artifact` path never enters the function; breakage scan found none.

F-A ADDRESSED, check by check: the §3.2-1 lead-in now opens "Load this variant in a **fresh campaign**"
(doc lines 193-199); the in-sequence `message_queue` expectation is named; quotes verified against
on-disk scratch evidence, not just the fix doc's claims — `.scratch/f-a/ws/campaigns/C-36f576bbc2/artifacts/invariant_links.json`
has exactly one `INV-1` (`source: model`, `synthesized: liveness-template`, `applies_to:
["rollup_finalization"]`), `.scratch/f-a/ws/campaigns/C-b7adb30545/` has **no** `invariant_links.json`
(the fresh-campaign refusal fires "before any write"), and the quoted refusal matches the format string
at `internal/invariants/invariants.go:500` byte-for-byte.

Verdict table: F-B **ADDRESSED**; F-A **ADDRESSED**; new breakage in `bc80d151..64d7b11b` **None**.
"**PLAN COMPLETE.** Both must-fix items are closed with red→green and first-hand reproduction evidence;
every gate is green at HEAD in this session."

### 4.6 Contradictions and drift inside the trail (recorded, not resolved by picking a side)

| # | Where | The contradiction |
|---|---|---|
| C-1 | `final-fixes.md` vs `final-fix-review.md` vs git | `final-fixes.md` calls commit 1 "2 files, +25/−10"; `final-fix-review.md` says "**+22/−10 Go, +13 test**" (which would sum to +35/−10). Git says **25 insertions, 10 deletions** (12+13 ins / 10+0 del); the fix-package diffstat says "3 files changed, 32 insertions(+), 11 deletions(-)" (adding the doc's +7/−1). The review's "+22/−10 Go" counts *changed lines* in the Go file, not insertions. |
| C-2 | the plan itself, Task 1 | "The plan itself is internally contradictory here (Step 1 prose 'leaves the registry untouched' vs Step 3 'after artifact resolution, call the gate'); the implementer followed Step 3's letter, and the committed refusal test does not assert registry absence (so the prose assertion the plan demanded was silently dropped)." — flagged by `final-review.md`, fixed by F-B. |
| C-3 | test count | The plan's own in-range edit (Task 4 §4, `99e7e906`) says "25 tests"; the protocol doc and the suite say **26** after `e28efeed`. `final-review.md` M-1: "The plan doc is a historical artifact of its own execution; noted only so a future reader doesn't read drift into it." |
| C-4 | gate-run environments | `task-4-report.md` concern 6 reports the shared Go caches (`/home/xand/go/pkg/mod`, `/home/xand/go/pkg/sumdb`, `/home/xand/.cache/go-build`) are read-only under that session's `workspace-write` policy, so the brief's plain `go test ./...` failed with `[setup failed]` on every package — "that is environment, not regression" — and the green runs used workspace-local caches + `GOTOOLCHAIN=local`. The report adds: "If Task 3's `71 ok` run used the host caches, its sandbox was wider than this one." Task 3's reviewer independently used temp caches + `GOTOOLCHAIN=local`; Task 1/Task 2 used the repo cache convention. Same result (71 ok) reported under all three regimes. |
| C-5 | `task-1-report.md` | Part 1 is `STATUS: BLOCKED` (Step 0 tripwire, no commit); part 2 is `STATUS: COMPLETE` and explicitly supersedes the status. Not a contradiction, but a reader must not cite part 1's status. The report also self-corrects §2.2's blast-radius list (it wrongly included `TestInvariantVerifyUnknownIDExits2OneLine`). |
| C-6 | probe count | The Step 0 probe is `210` as recorded, but the reviewer measured **212** on the committed tree (D3: "+1 from the new `EXEC-0000000002` suite record line …, +1 from `execCamp`'s hoisted default command line"); both are "mentions-not-fixtures noise". |
| C-7 | golden at `bc80d151` | `final-review.md` did **not** re-run golden (inherited GREEN on the argument that no Go file changed after `280e348d`); `final-fix-review.md` **did** re-run it live at `64d7b11b` and got the same 196-step GREEN. The later run strengthens, not contradicts, the earlier claim. |
| C-8 | `task-5-review.md` F-3 vs `task-5-fix1-review.md` scope note | The fix re-review says "the refusal sentence in §3.2-1 remains verbatim against `internal/invariants/invariants.go:498-502`" while its own N-1 says that sentence is unreachable in-sequence. Both true: the text is verbatim; the *reachability* was the defect. |

---

## 5. Measured outcomes — every number, labelled

### 5.1 The benchmark score (what the trail was closing)

| Number | What it measures | Source |
|---|---|---|
| **0/2** | gold findings found, Morph L2 @ `22ca805e`, hand-produced baseline | plan Goal |
| `found: []`, `missed: ["G-01","G-02"]`, `false_positives: 0`, `pass: false`, `bonus: false`, `verdict: "FAIL"`, `exit 0` | the same baseline reproduced by the Task 4 scorer against the real benchmark × real Morph campaign `C-7f1005ecd5` | `task-4-report.md` real run |
| verdict unchanged, `operator_confirmed: {"G-01": true}`, exit 0 | `--confirm G-01` is advisory only | `task-4-report.md`, `task-4-review.md` (reproduced live) |
| **0/2 still** | the score at plan completion — **no task in this plan re-ran the campaign**; "the operator's re-run session (Task 5's protocol) is the next and final actor" | plan "What success means", `final-review.md` §4 |
| 0 qualifying lifecycle machines (from 53 raw vocabulary hits) | oracle blast radius pre-flight, `internal/orchestrator/testdata/` | `task-2-report.md` Step 0 |

### 5.2 Scorer behaviour and test counts

| Number | What it measures |
|---|---|
| 25 → **26** tests | `scripts/eval_gold_test.py` size before/after `e28efeed` (+1 test: `test_bonus_short_circuits_the_fp_budget`) |
| 25/25 failures → 25/25 OK | red-first for Task 4 (scorer did not exist), then green |
| **2** failures under the boundary mutant (`<` → `<=`) | exactly `test_fp_budget_is_verdict_affecting_at_boundary` and `test_fp_budget_boundary_comes_from_the_benchmark_string`; the bonus test does not fail (bonus branch precedes the budget compare) |
| budget = **10** | parsed at runtime from `scoring.false_positive_budget` prose (`(\d+)\s*\+?\s*FPs?`); budget-5 mirror case also pinned |
| `MIN_KEYWORD_HITS = 3` | distinct `match_criteria` content tokens required, plus 1 `primary_function` |
| `MIN_EVIDENCE_INDEX = 4` | E4 = the CONFIRMED evidence floor the benchmark's `pass` string requires |
| 14 | schema-`required` keys the scorer asserts (`FINDING_REQUIRED_KEYS`), matching `assets/schema/finding.schema.json` |
| 10 exit-2 paths | gold absent, campaign absent, `events.jsonl` absent, `findings/` absent, unparseable finding JSON, unparseable events line, findings drift, gold drift, unreadable budget, unknown `--confirm` — each asserted to have clean stderr (no `Traceback`) |
| 1.049s | `python3 -m unittest scripts.eval_gold_test` wall time at `50d6da9c` (26 tests) |
| 344 / 377 lines | `scripts/eval-gold.py` / `scripts/eval_gold_test.py` as committed in `8b2886ec` (later +350/+397 in the range diffstat after `e28efeed`) |
| 0 write paths | scorer non-mutation, proven by hashing the campaign tree + benchmark before/after |

### 5.3 Gate results per commit

| Gate | T1 `55be2c2e` | T2 `3c095827` | T3 `280e348d` | T4 `8b2886ec` | T5 `99e7e906` | fix 1s (`e28efeed`,`bc80d151`) | F-B/F-A `50d6da9c`/`64d7b11b` |
|---|---|---|---|---|---|---|---|
| `go test ./... -count=1` | exit 0 | **71 packages ok, 0 FAIL** | 71 ok | 71 ok / 0 FAIL | (docs only) | — | exit 0 |
| `go vet ./...` | 0 | clean | clean | clean | — | exit 0 (`e28efeed`) | clean |
| `scripts/golden.sh` | 0 — GOLDEN GREEN, **196 steps** | 0 — GOLDEN GREEN, 196 steps, campaign `C-34c0ce6f4b`, **179 events** chain intact | GOLDEN GREEN | — | — | — | **GREEN re-run live**, 196 steps, `C-34c0ce6f4b`, **99 files archived**, exit 0 |
| `scripts/runbook-walkthrough.sh` | — | — | **150 passed, 0 failed — WALKTHROUGH GREEN** | — | — | — | — |
| scorer suite | — | — | — | 25/25 OK | 25/25 OK (both invocations) | 26/26 OK | 26/26 OK |
| `gofmt -l internal cmd` | empty (one blank-line violation found and fixed pre-commit) | clean | clean (golden's own formatting gate) | — | — | — | — |
| focused tests | red: `undefined: ExecTouchesInvariant` ×6, CLI `exit = 0, want 2` → green | 8/8 lifecycle PASS | findings+briefing ok | red: 25 failures | — | — | 4 invariant-verify tests PASS; boundary mutant 2 failures |
| red-first | confirmed | confirmed (`undefined: AdversarialLifecycleMachines`, 5 sites, RED EXIT 1) | confirmed (undefined ×7 + ×9 sites, RED EXIT 1) | confirmed | n/a (doc) | mutant-proven | F-B red-first (independent repro) |
| package timings | `cli` 33.080s, `invariants` 0.235s (fix wave) | orchestrator 0.030s | findings 0.798s, briefing 0.845s | — | — | — | cli 0.044s (4 focused) |

### 5.4 Structural / size numbers

| Number | What it measures |
|---|---|
| **9 commits, 20 files, +2386/−40** | whole trail `d9da3428..64d7b11b` |
| 7 commits / 2 fix commits | task range (`d9da3428..bc80d151`) / fix wave (`bc80d151..64d7b11b`) |
| 475 lines | the plan file `docs/superpowers/plans/2026-09-18-gold-findings-closure.md` |
| 3 external reviews | merged into plan v2 at `d9da3428` |
| 7 defects, 5 tasks | defect mapping coverage (plan Self-Review Record) |
| 240 lines | `docs/eval/morph-rerun-protocol.md` as committed in `99e7e906` (+73/−12 in `bc80d151`; 307 lines total in the range) |
| 60 lines | `task-5-logs/command-resolution.log` (the Step 2 resolution run) |
| 16 keys: 9×E4, 3×E5, 6×E6 | `CLASS_CONFIRM_FLOOR` real map read (Step 0) |
| 5 CLI tests + 3 fixture helpers | Task 1's true blast radius (confirmed empirically; the literal Step 0 probe said 210/212 mentions, only 6 of which mention an invariant) |
| 30 / 24 / 21 | top `forge test` mention counts: `internal/harness/zz_r32_test.go` / `internal/cli/cmd_verify_harness_test.go` / `internal/sandbox/envseam_test.go` |
| 7 files / 5 files / 4 files / 3 files / 1 file | Task 1 / 2 / 3 / 4 / 5 commit diffstats |
| `eaadacff…` → `3a021cb7…`, 10631 → 10636 bytes | `assets/testdata/asset_manifest.json` `campaign_plan` entry hash+size after the schema widening |
| 2 new test files + 2 new scripts + 1 new doc | new artifacts: `invariants_exec_relevance_test.go` (140), `cmd_invariant_verify_exec_relevance_test.go` (100), `eval-gold.py` (344), `eval_gold_test.py` (377), `morph-rerun-protocol.md` (240) |

### 5.5 Environment and version facts worth re-citing

- Go toolchain `go1.26.6` linux/amd64 (identical to `go.mod`'s `toolchain go1.26.6`, so `GOTOOLCHAIN=local` runs the same compiler); `go.mod` Go directive 1.26.2.
- Module graph is "four modules, x/text v0.39.0 fetched from `proxy.golang.org`" (Task 5 fix-1 binary build).
- Shared Go caches were read-only under the Task 4 session's sandbox; green runs used workspace-local caches (`.scratch/gomodcache`, `.scratch/gocache`, `.scratch/gopath`, `GOSUMDB=off`, `GOTOOLCHAIN=local`).
- Task 5 scratch state: fixture checkout HEAD `8e8b6c5…` vs pinned `22ca805e` (object present); `webv2 shared --verify` → `integrity: PASS — 0 problem(s)`, **766 approved rows**; contamination grep exit **1** (CLEAN) on 2026-09-18; scratch campaign `C-386d8b3bf7`; Task 2 scratch campaign `C-8b8fdab6d5`; Task 5 fix scratch campaigns `C-36f576bbc2` (in-sequence) and `C-b7adb30545` (fresh).
- The archived release evidence is `docs/sdd/release-final.log` @ `10182b5c`, line 36 `RELEASE OK` — demoted to script-works evidence only.
- `release.sh` prints `RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean` (`scripts/release.sh:164`).

### 5.6 Numbers that are explicitly NOT measurements of this trail

- Any re-run gold score: not produced (Task 5 ships the protocol; the operator executes it).
- The keyword quorum's adequacy against real finding prose: "unverifiable until the first fresh re-run
  produces one" (`task-4-review.md` "Cannot verify") — the quorum is validated only by synthetic fixtures.
- `boxLocalCap = "E4"` is "pinned only behaviorally (rendered bytes imply E4)"; no direct
  `boxLocalCap != "E4"` assertion exists.
- The `210` probe count is a mentions count, not a fixture count (its own report says so).

---

## 6. Laws and conventions established (quoted)

### 6.1 Matching law — one spec, two intentional matchers

> **Matcher semantics (binding, decided after three independent plan reviews):** case-insensitive
> **left-boundary token match** — the lowered command contains the lowered token at a position whose
> preceding character is NOT `[0-9a-z_]` (start-of-string counts as a boundary); there is **no trailing
> boundary**. (plan, Task 1)

Rejected alternatives, with the reason each was rejected: "regex `\b` on both sides — `\bStaking\b`
fails on `StakingTest` … under-accepting exactly the commands the gate must accept"; "plain
case-insensitive substring — over-accepts (`Staking` would match `Unstaking`)". Accepted forms:
`--match-contract Staking`, `--match-contract StakingTest`, `--match-path src/Staking.t.sol`;
rejected: `Unstaking` ("both rejections are pinned as adversarial tests, not incidental"). "Strip
surrounding shell quotes from the recorded command before matching."

The divergence is itself a law, stated on both sides:

> finding TEXT is natural language prose, where `\b` IS correct; this deliberately differs from Task 1's
> command matcher, which operates on shell commands (plan, Task 4)

> do NOT change the Task 4 matcher's behavior (that would silently move Task 4's pinned refusal
> semantics), and document in the new helper's comment that the two intentionally differ and why
> (plan, Task 1)

### 6.2 Empty `applies_to` law

> Task 4's pinned rule is that an empty `applies_to` does NOT bypass the artifact-reference refusal —
> empty means **unbound → unverifiable**, never wildcard. This task is consistent with that: an
> invariant bound to nothing cannot be exec-verified. (plan, Task 1)

### 6.3 The defect-6 record class and the gate-ordering law

The class definition (why F-B was must-fix, not a nit):

> The minted note — `invariant INV-3 checked against code (exec EXEC-…)` — is a durable record
> asserting a verification the gate just refused. That is the exact defect-6 class ("records asserting
> verification that didn't happen") this plan exists to close; leaving it in at plan completion means
> the plan closes with a live instance of its own target defect. (`final-review.md` F-B)

The resulting law, as implemented and pinned: **a refused citation mints no artifact row.** The gate
runs after `isFile(outPath)` and before `RegisterOrRefresh`; the refusal text and exit 2 are
byte-identical to the pre-move block; the refusal test asserts registry absence ("no artifact row
naming the invariant after a refused citation").

> If existing fixtures close invariants with suite execs and now fail, that is the law working —
> update those fixtures to targeted execs … never weaken the gate. (plan, Task 1)

> Never a weakened gate. (plan, Task 1 Step 0 tripwire rule)

### 6.4 Lifecycle-mint laws (Task 2)

Cardinality rule (quoted in full in §2); asset-flow verbs are "deliberately NOT in the vocabulary".
Dedup scope: "the skip checks run against the ENTIRE existing work queue (open-question rows AND any
other already-minted rows), not just `bootstrapOpenQuestions`' output — the planner may run
iteratively, and a dedup check scoped to one minter would not survive replanning."

Id-scheme law, verbatim:

> **The stable handle is the machine NAME, never the id** — a later campaign adding a machine
> alphabetically earlier shifts every subsequent id. Pins and downstream consumers (including Task 5's
> protocol) must match on the machine name; the id is display-only. Any golden pin that references an
> LC-id by value is a review-blocking finding.

Reviewer's confirmation that the law held: "The strongest form of the law holds: **no pin exists to
violate.**" Two adjudications became precedent: **machine-name-as-component** (the schema gives state
machines no `applies_to`, so the brief's instruction was unimplementable) and **schema widening is
strictly additive** (`^(Q|LC)-[0-9]{3}$`; `"X-001"` and bare ids still fail).

### 6.5 Reachability-line laws (Task 3)

> Advisory only: no gate, proof, or phase transition reads it. (plan, Task 3)

> If any minted line embeds a command it must lead with `webv2 ` per the Task 7 law; this line is pure
> prose so no command is embedded. (plan, Task 3)

Position law: the line renders "immediately after the cold-probe warning line (Task 11) — pin that
ordering in the briefing test by asserting the reachability line's index is exactly one greater than
the cold-probe warning's index in a fixture that has both."

The cap-source ruling, which set the precedent that a false plan premise does not force a bad
implementation:

> the documented constant with a named upgrade path **satisfies the plan**. The plan's premise (an
> exported envgo cap accessor exists to consume) is factually false, so a literal implementation is
> impossible within the plan's own file list and its "pure view" architecture … A live probe would have
> been the actual spec violation (host-dependent pure view, 20s wedge). (`task-3-review.md`)

### 6.6 Measurement-honesty laws (Tasks 4–5)

> `pass` | bool | true iff G-01 is in `found`. **Independent of FP count and of operator
> confirmation.** (plan, Task 4)

> `operator_confirmed` … Advisory only — it never changes `pass`/`bonus`/`verdict`; it exists so a human
> semantic judgment is not silently laundered into the machine verdict. (plan, Task 4)

> exit 0 on any well-formed scoring run (scoring is not a gate); exit 2 with a clean stderr message
> (no raw traceback) when inputs are missing/malformed (plan, Task 4)

> no score pressure on the record; a miss is recorded as a miss with the failure analysis (the 0/2
> eval's diagnosis is the template); numbers learned during the re-run enter framework DATA only
> through the `docs/eval-methodology.md` provenance rubric. (plan, Task 5 §5)

> no exploit development automation, no CI execution of the protocol, no benchmark edits (the
> benchmark file is read-only evidence; changing it invalidates the comparison to 0/2). (plan, Task 5 §6)

> Do NOT add it to `verify-full.sh` (the 13-step pin is deliberate; a python step would add an
> interpreter dependency to the release gate — YAGNI). (plan, Task 4)

### 6.7 Process conventions (global constraints the whole range held)

- **Exact-path staging only; never `git add -A`.**
- **Golden re-pins are tagged in the commit subject** (`(golden: <file>)`) "so a later bisect can
  attribute which task moved which pin"; deliberate pin updates carry the reason in the commit body.
- **TDD: red test first for every code task.**
- **Historical fixtures (`scripts/legacy/`, `web3sec-final/`, `morph/`) are immutable; the scorer reads
  them, never writes them.** Task 1–4 reports each assert them untouched (Task 1: "`git diff --stat
  d9da3428..HEAD --` over all three is empty — untouched, never read or written"); Task 5's is
  docs-only and asserts "Nothing was ever run against the pinned target."
- **stdlib only** (no new Go module deps; the scorer is Python 3 stdlib only, no pip).
- **The scorer never mutates the campaign or the benchmark file.**
- Task 5's protocol law: "a fresh `bash scripts/release.sh` on THIS checkout is required before
  discovery starts and must print `RELEASE OK`" — an archived log "is cited only as evidence the script
  itself works, never as a substitute for the fresh run. Repeatability is the point of the measurement
  loop."
- Closing convention: "no push/merge/delegate" — carried by the Task 1–4 reports (Task 1: "No commit,
  no push, no merge, no delegation" / "Push / merge / delegation | none"; Task 2/3: "no
  push/merge/delegate performed"; Task 4: "No push, no merge, no delegation") and by the fix wave
  ("no push/merge/delegate"). **Task 5's report does not carry the line** (docs-only commit; it says
  "Committed by exact path; the commit contains that one file and nothing else").

---

## 7. Open items this trail left behind

### 7.1 The one item the trail deliberately did not do

- **The operator's re-run session.** "the plan should be declared complete and the operator's re-run
  session (Task 5's protocol) is the next and final actor." Protocol:
  `docs/eval/morph-rerun-protocol.md` (six sections). It requires a fresh `RELEASE OK` on the
  pinned-target checkout, a contamination re-check on a clean environment **first**, the three
  expected gate firings, then the pinned scorer invocation + `--confirm G-01`. The score remains **0/2**
  until then.

### 7.2 Parked items with rulings (from `final-review.md` §3 and `progress.md`)

| ID | Item | Ruling / named follow-up |
|---|---|---|
| D1 | `trajectories` enum quirk — `["lifecycle"]` renders `["code"]` in the work queue | PARK: pre-existing (`TrajectoryToEnum` keyed on long spellings; `queue.go` untouched by the range). Fixing "would move pinned oracle rendering repo-wide". "Future-task material." |
| D2 | `appliesToTokens` adds `NormalizeInvID` variants | PARK: inert for contract names; optional one-sentence doc comment; could fold into the F-B wave — **not folded** |
| D3 | Step 0 probe drift 210 vs 212 | PARK: report-annotation nit, zero code impact |
| D4 | `task14_reachability_test.go:245-247` comment overclaims a terminal-finding pin | PARK: production behavior real (`IsTerminal` in `openFindingClasses`); only the documented pin missing — **not folded** |
| D5 | LC-id schema description note | PARK: doc nit in the schema's `id` property description; no consumer reads it |
| D6 | `boxLocalCap = "E4"` constant instead of an envgo read | PARK, ruled COMPLIANT: "Cleaner follow-up = pure, non-probing accessor over `profileMaxLevel`; the `ponytail:` hook is in place. Not this plan." |
| I1 | scorer `MIN_KEYWORD_HITS=3` quorum calibrated synthetic-only | PARK: "the first fresh re-run finding is the calibration datum — that is Task 5's protocol doing its job, not a defect." |
| INFO-4 | `PASS_GOLD_ID`/`BONUS_GOLD_ID` hardcoded in the scorer | Residual carried with no action: "a future benchmark edit that renumbers golds would need a scorer edit" |

### 7.3 Residuals stated by the reviewers as still open at HEAD

- **Task 4 byte-gate residual on the `--exec` path.** `TestInvariantVerifyExecRelevanceGate` case (b)
  (targeted command, generic log) still mints the artifact row before Task 4's byte gate refuses.
  "That behavior predates this plan (Task 4) and its refusal pins live elsewhere; moving the mint
  behind `VerifyInvariantStatement` entirely is the fuller fix and belongs in the same follow-up that
  eventually re-homes it, not in this closure wave." (`final-review.md` F-B "Residual"; explicitly
  not expanded in `final-fixes.md`.)
- **Task 2 operator-surface gap.** The LC row reaches the operator via `plan --json` / the attention
  queue (and via promoted probe rows in next-actions), not as a first-class next-actions line.
  "If the cockpit brief is ever extended to render unattempted queue rows directly, that is the
  natural home for it." Ruled COMPLIANT for Task 2, deferred as a future task.
- **Task 3 cap accessor.** `boxLocalCap` is pinned only behaviorally (rendered bytes imply E4); the
  envgo accessor wiring "will touch it anyway (D6's follow-up)".
- **Task 4 positive control.** No campaign record containing a real matched finding exists, so "the
  keyword quorum's adequacy against real finding prose is unverifiable until the first fresh re-run
  produces one".
- **Task 1 honesty bounds.** The gate reads the recorded command string, so "a forged or `sh -c`-wrapped
  record is out of scope"; `ExecTouchesInvariant` has no error return (unreadable store folds into
  `no-target-match` / `no-exec-record` — fail closed, indistinguishable from "nothing matched" at the
  signature level); `tokenOccursLeftBound` treats a non-ASCII preceding byte as a boundary ("not pinned
  and not reachable with Foundry-style ASCII contract names").
- **Task 5 operator sanity checks.** `git worktree add "$SCRATCH/morph-22ca805e" 22ca805e` was never
  executed (it writes into the fixture repo's admin dir), and "the operator's first run should
  sanity-check the path it picks"; the "verify the checkout hash" step "will fail today by design"
  because the fixture checkout is at `8e8b6c5`, not `22ca805e`.
- **Plan-doc drift (M-1).** The in-range plan edit still says "25 tests" where HEAD has 26 — "noted
  only so a future reader doesn't read drift into it".

### 7.4 What a future reader must not mis-cite

- `final-review.md`'s verdict is **"PLAN COMPLETE PENDING TWO SMALL FIXES — not yet declarable as-is"**;
  the plan is only complete at `64d7b11b`, per `final-fix-review.md` ("**PLAN COMPLETE.**") and
  `progress.md` ("PLAN COMPLETE (d9da3428..64d7b11b)").
- `task-1-report.md` part 1's `STATUS: BLOCKED` was superseded by part 2's `STATUS: COMPLETE` in the
  same file — cite the commit, not the first status line.
- No golden pin moved anywhere in the range, and no LC-id is pinned by value; if a future change makes
  either false, the `(golden: <file>)` subject tag and the review-blocking LC-id rule are the
  conventions to follow.
- The re-run score is **not** a deliverable of this plan (plan header), so 0/2 at `64d7b11b` is the
  expected state, not a failed closure.


---

# Digest §IV — the closed wave plan trails

# Digest — Closed wave plan trails, 2026-09-08 … 2026-09-20

Sources digested: **all 21 assigned files in `docs/superpowers/plans/`** dated 2026-09-08 through
2026-09-20 (`2026-09-08-p0-trust-core.md`, `2026-09-09-p1-findings-gates.md`,
`2026-09-10-emit-quota-repair.md`, `2026-09-10-p0-review-consumption.md`,
`2026-09-10-wave-g-tranche-1.md`, `2026-09-11-recall-wave.md`, `2026-09-11-wave-g-tranche-2.md`,
`2026-09-11-wave-g-tranche-3.md`, `2026-09-11-wave-i.md`, `2026-09-11-wave-j.md`,
`2026-09-12-minicertora-harness-backend.md`, `2026-09-12-wave-l-advice-dispositions.md`,
`2026-09-12-wave-l-defer-validation-completion.md`, `2026-09-12-wave-l-system-sweep-calibration.md`,
`2026-09-12-wave-m-fork-consumption-run2.md`, `2026-09-13-wave-n-operator-friction.md`,
`2026-09-16-morph-c12-feedback-wave.md`, `2026-09-17-trust-boundary-hardening.md`,
`2026-09-18-gold-findings-closure.md`, `2026-09-19-morph-r3-fork-ladder-and-record-trust.md`,
`2026-09-20-morph-pass2-framework-fixes.md`).
The three `2026-09-21-v16-*.md` files are **live and out of this section's scope** (the v16 P0 plan
was the one file with uncommitted working-tree modifications when this digest was written).

Conventions used below: **quoted/blockquoted text is verbatim from a source**; every number is
labelled with what it measures; shas appear as the plans print them, with the repo they resolve in
noted once in §1.5. These files are tracked in git (`git ls-files docs/superpowers/plans/` lists all
21), so this digest is a browsable copy while git history is the fallback.

---

## 1. How to read a plan trail

### 1.1 What these files are

Every one of the 21 is a **superpowers implementation plan**: a `**Goal:**`, an `**Architecture:**`,
a `**Tech Stack:**`, a `## Global Constraints` block that every task inherits, then numbered
`### Task N:` sections. Each task carries `**Files:**` (exact paths to create/modify), `**Interfaces:**`
(`Consumes:` / `Produces:` with real signatures and JSON shapes), and `- [ ] Step K:` checkboxes that
are the execution spine (red test → run red → implement → run green → gate → commit). Plans written
before execution keep `- [ ]`; plans whose tasks landed show `- [x]` on the executed steps
(e.g. `2026-09-08-p0-trust-core.md` Tasks 5–19 are `[x]`).

Three structural markers carry the durable outcome, and they are the first thing to look for:

| marker | where it appears | what it means |
|---|---|---|
| a status banner under the title | `2026-09-10-wave-g-tranche-1.md:3` — "**Status: EXECUTED 2026-09-11.** All 8 tasks landed via subagent-driven development on branch `wave-g-tranche-1` and merged to `main`" | the plan ran to completion; the banner also names what was consciously deferred |
| `## Execution errata` | `2026-09-16-morph-c12-feedback-wave.md:1011` | post-implementation corrections: what the plan got wrong, what the reviewer/provider did, and the **final measured outcome** |
| `## Self-Review` / `## Self-Review Record` | most plans (e.g. `2026-09-11-wave-g-tranche-2.md:1322`, `2026-09-11-recall-wave.md:969`) | spec-coverage map, placeholder audit, type-consistency check, byte-risk register |

A plan is a *proposal and a record*, not the code. Where a plan's `Consumes:` names a `file:line`, the
line may have moved; the plan text is the historical claim.

### 1.2 The landing record lives in `docs/IMPROVEMENTS.md`

These plans deliberately do **not** maintain their own status. They instruct the closer to write into
`docs/IMPROVEMENTS.md` — the repo's changelog and the authoritative landing ledger (370.5 KB / 5 236
lines when this digest was written). Examples of the target form:

- `docs/IMPROVEMENTS.md:1153` — `## 2026-09-13 — wave N: operator friction (FRAMEWORK_EVAL) — LANDED (14e78426..2465c4ca, 6/6)`
- `docs/IMPROVEMENTS.md:1199-1214` — the header status line: "Wave G tranche 1 LANDED 2026-09-10 (G1, G6, G7 …) … **Wave G is COMPLETE (G1–G18 all LANDED).** Wave H backlog filed 2026-09-11 — **closed by Wave J 2026-09-11** (H1–H15 landed; H16 filed) — Wave I LANDED 2026-09-11 (I1–I6). **Wave J, the definitive close-out, LANDED 2026-09-11**"
- `docs/IMPROVEMENTS.md:2673` — `### D8. The patch clause should follow the target program, not the framework *(LANDED 2026-09-10)*`
- `docs/IMPROVEMENTS.md:2781/2796` — `**LANDED via G14** (`4edfd60`)` / `**LANDED via G14** (`b8ed2c6`)`

The plans name the exact ledger edits: "Update `docs/IMPROVEMENTS.md` — in the Wave G TOC table,
change G1, G6, G7 rows to `LANDED (tranche 1, 2026-09-10)`" (tranche-1 Task 8 Step 3); "IMPROVEMENTS
statuses — G2/G3/G4/G5/G8 → LANDED (this tranche)" (tranche-2 Task 27 Step 2); "Append a dated section
to `docs/IMPROVEMENTS.md` (house changelog)" (pass-2 Task 8 Step 4).

### 1.3 Companion artifacts a reader should reach for

| artifact | role | named by |
|---|---|---|
| `docs/IMPROVEMENTS.md` | landing ledger / changelog; the only place wave statuses are authoritative | every plan's close-out task |
| `docs/feedback-triage.md` (65.5 KB) | open/closed review-item ledger; "Still open" tables carry deferrals with reasons | p0-review-consumption Task 6, wave-j Task 7 |
| `docs/feedback-triage-morph-r3.md` | the R3 file:line evidence doc | R3 plan header |
| `docs/gates/P0-gate.md`, `P1-gate.md`, `P3-gate.md` | per-phase gate reports (PASS/FAIL + evidence command) | p0 Task 19, p1 Task 19, emit-quota Task 5 |
| `KNOWN_DIVERGENCES.md` (repo root) | permanent divergence ledger, created in P0's first commit | p0 Global Constraints, Task 19 |
| `testmap.json` + `scripts/check-testmap.py` | function-level Python-test accounting (no silent drops) | p0 Task 16, p1 Task 16 |
| `docs/eval-methodology.md` | the G7 claim-intake rubric referenced "verbatim" by later waves | tranche-1 Task 1 |
| `docs/MINICERTORA_ARCHITECTURE.md` | planes L0–L6; the minicertora plans cite its §L3/§6 | minicertora, wave-l-* |
| `scripts/verify-full.sh` | the mandatory local gate (13 steps by Wave I/J) | p0 Task 18 onward |
| `.superpowers/sdd/<wave>/progress.md` | per-wave SDD ledger (checked tasks, model lines) | wave-i Task 10, wave-j Task 9 |

### 1.4 The laws that make these plans readable as one trail

Across all 21 plans, four postures never change, and a reader who assumes them will read every plan
correctly:

1. **Byte discipline.** New renderings are presence-gated so untouched campaigns stay byte-identical;
   `scripts/golden.sh` must be green after *every* task; a golden fixture is **never** edited to make a
   red test pass ("a fixture move is BLOCKED-report, never self-fixed" — tranche-3 Global Constraints).
2. **Assets are pinned.** Any edit under `assets/` requires `python3 scripts/sync-asset-manifest.py`;
   `assets/testdata/asset_manifest.json` is never hand-edited.
3. **Determinism.** No wall clock, no map-iteration order in output; `WEBV2_NOW`/`WEBV2_UUID` are the
   pinned seams; floats print with explicit formats.
4. **Fail-open on judgment, fail-closed on money** (principle 2, stated in tranche-2). Advisories
   inform; they never promote or auto-dismiss.

### 1.5 Sha provenance (verified with `git rev-parse`)

Shas named by these plans resolve as follows; the two that do not resolve in this repo are commits in
sibling repos, which matters when citing them:

| sha (as printed) | resolves to | repo |
|---|---|---|
| `e6cbff6` | `e6cbff61526f` | **web3sec-final** (the Python reference), not web3sec-go — P1's live-reference baseline |
| `22ca805e` | `22ca805e2d09` | **morph** (the vulnerable L2 checkout), not web3sec-go |
| `10182b5c` | `10182b5c90ca` | web3sec-go (the trust-boundary trail's final HEAD) |
| `d87ff34`, `f4b6c66`, `4edfd60`, `b8ed2c6`, `7230c42`, `85b2e3d`, `60663100`, `c8e2a299`, `31e4bea1`, `17bf9c55`, `7baaa6a`, `8240e3c`, `9e9a671`, `2dbea50`, `10477d4`, `2737486` | 12-char forms all resolve | web3sec-go |

Two further shas are cited in `docs/IMPROVEMENTS.md` rather than in these plans and also resolve here:
`14e78426..2465c4ca` (the Wave N landing range) and `92104cf` (the E5 checkpoint).

Campaign ids that look like shas are **not** shas: `C-21dd6a7642`, `C-12f17fd555`, `C-7f1005ecd5`,
`C-16148b932c`, `C-45488bdaf5`. Likewise the hex strings in c12/pass-2 are **probe row ids**
(`34589e8588`, `4dc010af55`, `a047e6509f`, `3ec92e56da`, `b6c0484194`, …) or finding ids
(`F-6791c9aee0b5`, `F-f010ea83b6ba`, `F-94e10538419b`, `F-e9461aa406cd`).

---

## 2. One subsection per plan

### 2.1 `2026-09-08-p0-trust-core.md` — P0 Trust Core (810 lines)

**Goal (verbatim):** "Build the Go trust-core foundation of webv2 — `internal/validation`,
`internal/state`, `internal/snapshot`, `internal/audit`, and the P0 CLI (`init/status/log/snap/audit/verify`)
— byte-exact with the Python `webv2` reference, verified by a differential fuzz oracle, a Go-native
hardening suite, and a cross-twin golden suite against the Python implementation."

**Tech stack:** Go 1.26, stdlib CLI dispatch (no cobra), UUID via `crypto/rand`, and **exactly two
dependencies**: `santhosh-tekuri/jsonschema/v6` (draft-07) and `pelletier/go-toml/v2`.
Module path `websec`, binary `webv2`. `dlclark/regexp2` (P2) and `gopkg.in/yaml.v3` (P3) deliberately
**not** added yet ("YAGNI until the phase that needs them").

**Tasks (19):**

1. Canonical JSON encoder, byte-exact CPython (`internal/validation/canon.go` + `scripts/canon-oracle.py` differential fuzz oracle).
2. `pythonRound` (round-half-to-even) + a call-site rounding audit in `docs/RoundingAudit.md`.
3. Schema loader + validator wrapper for the **27** draft-07 schemas; this task is the **OQ3 checkpoint**.
4. Atomic IO (`readJson`/`writeJson`, same-dir tmp + rename, JSONL split policy: `events.jsonl` and `costs.jsonl` ASCII, all else raw UTF-8).
5. Campaign skeleton: `init`/`open`, ids, notes, `listCampaigns`.
6. Event log (`log`/`nextSeq`/`events`) + hash-chain core (`GENESIS_HASH`, `eventHash`, `legacyAnchor`).
7. `verifyLog` — chain/seq/tail integrity; must **never crash** on a torn log.
8. Phase machine (`PHASES`, 19 names) + budget + `complete`.
9. Stage ledger + artifacts (`register`/`prune`/`refresh`/`registerOrRefresh`).
10. Snapshot hashing (`content_hash`, merkle root, file leaf, canonical form).
11. Snapshot ladder detection + `pinSourceSnapshot`.
12. Snapshot manifest, toolchain, deployment/chain pins, active snapshot + compat.
13. Audit section registry + P0 sections 1–6 (`state/execs.go`, `audit/sections/*`).
14. CLI: `init` / `status` / `snap` / `log` / `audit` / `verify` + global `--root`.
15. Schema assets sync (`assets/schema`, embedded) + `KNOWN_SCHEMAS=27` test.
16. `testmap.json` function-level test accounting across the Python reference.
17. Cross-twin golden suite v1 (scripted op-seq, pinned clocks).
18. `scripts/verify-full.sh` — one-shot parity harness + Go==Go determinism run.
19. Dependencies, `KNOWN_DIVERGENCES.md`, and the **P0 gate report**.

**Acceptance criteria it set** — the P0 gate is 7 items, each `PASS/FAIL` + "the command whose output
is the evidence"; the gate opens only when all seven PASS:

1. Python campaign audits clean (step 7 of verify-full).
2. `events.jsonl` byte-identical (golden).
3. `verify` fast green (Go test under budget).
4. golden suite v1 green.
5. `testmap.json` function-level accounting reconciles.
6. **OQ3 checkpoint:** `santhosh-tekuri/jsv v6` agrees with Python `jsonschema` on the 27 schemas (table of schema → verdict). If a divergence cannot be mapped into the `SchemaError` shape it escalates to `qri-io/jsonschema` **before P1**.
7. Python coverage floor measured (the P0 slice, run with coverage, ≥ the recorded floor %).

`verify-full.sh` is fixed at **10 ordered steps** (vet; build; test; `-race`; two `-count=1` runs with
identical output; asset sync + diff; Python pytest baseline; testmap reconcile; golden; truncated-log
crash smoke), failing fast with the step name.

**Durable design decisions recorded:**

- **Canonical JSON** has two flavors: **spaced** (`json.dumps(sort_keys=True, ensure_ascii=True)`, separators `", "`/`": "`) used for event/context/row hashes, and **compact** (separators `(",", ":")`) used for snapshot manifests, `spec_hash`, fingerprint. Escaping: `"`→`\"`, `\`→`\\`, control chars → `\u00XX`, every code point ≥ 0x7f → `\uXXXX` (surrogate pair above U+FFFF), **no HTML escaping**, `/` raw. Floats: shortest round-trip; integral floats keep `.0`; `Infinity`/`-Infinity`/`NaN` bare.
- **`eventHash(event)`** = canonical sha256 over `{seq,at,type,ref,data,prev_hash}`, **spaced** flavor (NOT `event_hash`). `GENESIS_HASH` = 64 zeros. `legacyAnchor(event)` = `"legacy-seq-{seq}"`. State mirrors the **last 1000** events; the log line is appended in **ASCII** so a U+2028 payload cannot break JSONL framing.
- **Time & ids:** `nowIso()` = UTC, 6-digit microseconds, `+00:00` (never `Z`), nanoseconds truncated. `newId(prefix, n=12)` via `crypto/rand`. `WEBV2_TEST_CLOCK` honored **only** in `testclock`-tagged builds; production refuses it at startup.
- **Exit codes (contract):** 0 ok · 1 check/prove/audit/gate failure · 2 usage/validation/failed stage · 3 needs-model.
- **Error message text is part of the contract** — ported verbatim including remediation snippets.
- Artifact ids: `newId("ART",8).replace("ART-", kind[:3].upper()+"-")`; the register event logs the **original** `str(path)` while the row stores the resolved path. `refresh_artifact` refuses a missing file (`FileNotFoundError`) and an empty reason (`ValueError("refresh_artifact requires a written reason")`), and logs `old_sha256`/`new_sha256`/`refresh_count`.
- `complete` requires a named actor and a reason ≥ 10 chars; the COMPLETE-phase story and "closure stays on log" are contract.
- Merkle: empty → `sha256(b"")`; odd leaf duplicated; file leaf is `sha256(8-byte len(rel) + rel + 8-byte len(data) + data)`.
- **Testmap baseline:** every Python test function (~**1 052**) gets a row; the P0 slice is **56 functions across 9 files** (`test_state.py` 8, `test_state_log.py` 4, `test_state_log_chain.py` 7, `test_snapshot.py` 10, `test_snapshot_integrity.py` 4, `test_snap_exclude.py` 7, `test_snap_toolchain.py` 6, `test_audit.py` 6, `test_root_default.py` 4); the remaining ~996 get stub rows `{"status":"deferred-P{n}"}` so "no function is ever silently dropped".
- **Hard gates every time:** `go vet ./...`, `go build ./...`, `go test ./...`, **`go test -race ./...`**, golden + a Go==Go determinism run, CLI golden tables, benchmarks with regression thresholds, testmap accounting, embedded assets == source, regex-hazard grep, schema compile + `KNOWN_SCHEMAS=27`.

**Deferred:** P1+ audit rows ("audit section 1-6 only until P1+; the golden recipe must not depend on
P1+ sections" — recorded as a `KNOWN_DIVERGENCES.md` row); ~996 testmap rows to later phases; the two
later-phase dependencies.

### 2.2 `2026-09-09-p1-findings-gates.md` — P1 Findings and Gates (435 lines)

**Goal:** port the P1 module set (findings IR/transitions/gate bundle/evidence/assumptions/memory
checks, floors, taxonomy, capabilities, dedup, risk, pricing, bounty policy, invariants, protocol
graph, economics, planner, coverage, orchestrator, pipeline, completion) and the P1 CLI verbs
(`ingest, model, plan, answered, floors, budget, dedup, resolve-candidate, prioritize, repro-queue,
verdict, recall, gate (+--explain), prove, waive, invariant-verify, invariant-contradict,
artifact-register, artifact-list, hint, scope`).

**Testmap phase retag (done 2026-09-08):** all **1 096** rows re-tagged from a per-file import scan
against spec §14's module→phase map. **P1 slice: 473 functions in 41 files** (was 524 — the excess was
P2/P3/P4 module tests). P2: **182** · P3: **266** · P4: **112** · **P0 addendum: 7**
(`tests/test_living_artifacts.py`; `check-testmap` was RED on exactly those 7 until Task 0 landed).
Mixed-subject files keep their dominant-subject tag.

**Module inventory (measured, lines → Go package):** findings 1476 → `internal/findings`; planner 578 →
`internal/planner`; invariants 504; orchestrator 499; pipeline 472; completion 469; bounty_policy 405;
risk 318; dedup 271; taxonomy 243; coverage 231; floors 168; economics 141; protocol_graph 124;
capabilities 126; pricing 72; costs (P1 slice) → `internal/state`. **Total ≈ 5.9k lines Python → Go.**

**Tasks (20, numbered 0–19):** 0 P0 addendum living-artifacts tests (7); 1 findings core; 2 findings
transitions + gate bundle; 3 taxonomy + capabilities + floors; 4 dedup; 5 protocol graph + economics;
6 risk + pricing; 7 bounty policy; 8 invariants; 9 planner; 10 coverage; 11 pipeline; 12 completion;
13 orchestrator facade; 14 CLI P1a; 15 CLI P1b; 16 testmap P1 (473 rows → real); 17 golden suite v2;
18 verify-full P1 (cross-audit + renumbered steps); 19 P1 gate report + KNOWN_DIVERGENCES.

**Acceptance:** the golden recipe grows a P1 section (`scope → model → plan → answered (x2) →
ingest (x3) → dedup → floors set → gate dry-run → prove --stage → invariant-verify`) whose campaign
artifacts and outputs are byte-identical after KNOWN_DIVERGENCES normalizations; `docs/gates/P1-gate.md`
keeps P0's 7-item shape; **OQ3 unaffected (no new schemas in P1 — verify)**; coverage floor
unchanged-or-better.

**Durable decisions:**

- **New dependency (YAGNI-checked):** `gopkg.in/yaml.v3` for `taxonomy.load_maps`/`validate_map_file` (PyYAML error semantics). "No other new dependency: risk/bounty formatting is hand-rolled, no regexp2 — P1's regexes are ASCII-class compatible with RE2; verify per-pattern when porting, record any divergence in KNOWN_DIVERGENCES."
- **Rules inherited from P0, unchanged:** TigerStyle/Ponytail (YAGNI → stdlib → native → existing dep → one-liner → minimum viable; functions ≤70 lines, ~2+ assertions per test, 4-space indent, hard-wrap 100 cols); Approach A (phase-serial, module-level TDD); **PYTHON WINS**; **fast tests are a hard gate** (`go test ./...` < 2s, `-race` < 2s; no flood loops >50 items); every task ends with a parity probe; testmap discipline.
- **Byte-exact contracts in P1** (transcribe exactly, golden-vector each): `findings.technical_signature`, `findings.text_signature`, `findings._canonical_row_hash`/`compute_row_digest`, `dedup.lineage_id_for`, `invariants.normalize_inv_id`, planner Q/L id numbering (counter continuation), economics EQ/TR numbering. `STATUS_NOTE_CAP=200`.
- **Reference is live (user directive 2026-09-09):** web3sec-final is developed in parallel; baseline at P1 start **`e6cbff6`** (= `e6cbff61526f`, web3sec-final). Before each task, `git -C web3sec-final log e6cbff6..HEAD`; if new code touches the module being ported, fold it in (PYTHON WINS = the *current* Python) and bump the baseline. Before any gate: full `src/`+`tests/`+`schema/` diff since baseline, Python suite re-run (the **1146** baseline count moves when tests are added).
- **End state (user directive 2026-09-09):** the parity tooling (`scripts/*.py`, verify-full's Python steps) is provisional; at P4 cutover it moves to the Python repo; the shipped Go repo is pure Go (`cmd/ internal/ assets/ docs/`).
- **Delegation rule as written:** subagents only via `workflow` `agent()` with `provider:"openrouter", model:"meta/muse-spark-1.3-contributor"`; fallback `openrouter/deepseek/deepseek-v4-flash-0731`; **never the local model**. (Superseded in later waves — see §3.5.)

**Deferred:** P2/P3/P4 testmap slices; parity tooling move to the Python repo at P4 cutover.

### 2.3 `2026-09-10-emit-quota-repair.md` — "the audit's repair command must repair" (296 lines)

**Origin (verbatim):** "the final whole-branch review of the P0 batch
(`docs/superpowers/plans/2026-09-10-p0-review-consumption.md`), minor finding 2, and the D1 residual
recorded in `docs/feedback-triage.md`." Status line: `Status: ready to execute`; Date 2026-09-10.

**The defect, with the measured numbers:** the `[probe_surface]` drift section of `audit` told the
operator to run `webv2 probes <campaign> run --emit`. Two things were wrong:

1. "**It names a command that makes the artifact worse.** A bare `probes run` builds with the
   compiled-in defaults (`per_axis 12`, `total 40`, see `internal/cli/cmd_probes.go:121`), while `audit`
   re-derives the surface with the quotas the artifact itself records (`internal/probes/audit.go:133-135`).
   On the operator's campaign **C-21dd6a7642** the artifact records **`per_axis 30, total 70`** (70 rows);
   the bare re-run rebuilds 40 rows, drops 30 of them and leaves **34** `[probe_surface]` problems where
   the pre-emit artifact had **24** — following the tool's own advice costs the operator ten more
   problems and **34 orphaned plan priorities**. Run with the artifact's own quotas it leaves **8**."
2. "**One hint is not even copy-pasteable.**" The plan-priority-orphan hint (`internal/probes/audit.go:73-77`) prints the literal `<campaign>` where it means the campaign id.

**What "repair" must mean (the ruling):** a `probes run` without an explicit `--per-axis`/`--total`
rebuilds the surface the campaign already has, per flag, each falling back independently:
(1) flag passed explicitly → use it; (2) else the existing `artifacts/probe_surface.json` records the
value → use it; (3) else the compiled-in default (`--per-axis 12`, `--total 40`). The source of each
effective value is printed.

**Tasks (5; note the file's own numbering order is 1, 2, 4, 3, 5):**

1. `probes run` repairs the surface it already has.
2. The audit hints name the command that actually repairs.
3. (printed as "Task 4") The planner's disposition errors name the campaign too.
4. (printed as "Task 3") Record the change.
5. Give the P3 smoke the blind axis it asserts — *added after Task 3, when the batch's own acceptance run showed the gate is red for reasons older than this batch.*

**Acceptance (whole plan):**

1. `scripts/verify-full.sh` green, all **13 steps**.
2. On a fresh copy of C-21dd6a7642 with the binary built from this plan's head: bare
   `webv2 probes C-21dd6a7642 run --emit` prints the recorded quotas and **`orphaned 8`, not `orphaned 34`**;
   `webv2 audit C-21dd6a7642` reports **8 `[probe_surface]` problems, all plan-priority drift (Q-253…Q-260)**,
   and no problem string contains `<campaign>`; the planner's two disposition errors name the campaign id;
   an explicit `--per-axis 2 --total 40` still rebuilds exactly what it says.
3. No new flags or verbs; `assets/` untouched; the audit's problem set for a pinned fixture unchanged.

**Task 5's durable defect finding (worth citing on its own):** `scripts/verify-full.sh` step 12 selects
an axis whose `status` is exactly `blind` (`:685-699`) and uses it for `probes blank` (`:700-702`), but
**no axis in the smoked corpus is ever blind**: `snap` pins the whole repository, not the directory it
is handed — `webv2 snap <c> internal/probes/testdata/probes/cursor/clean` prints
`pinned src-… (git-clean, 1071 files)` — so the enforcement-timing probe sees **125 sites** and ranks
**12 rows** instead of the fixture-only `sites 4, rows 0, blind` that
`internal/probes/probes_test.go:780-799` exercises. The step "has therefore failed since the check was
written, at every commit tested (`7baaa6a`, `8240e3c`, `9e9a671~1`, `9e9a671`, `2dbea50`, `10477d4`,
`2737486`) — including the one whose report claimed 13/13." The reproduced corpus option:
`webv2 index <c> --src internal/probes/testdata/probes/assertion_strength/clean` reports
`index: 4 entries (snapshot unpinned)` and an enforcement-timing axis of
`status=blind sites=4 rows=0 blind=5`. The fix is to give the smoke a corpus with a genuinely blind
axis — **not** to relax the selector, delete an assertion, or relax an exit code.

**Global constraints it fixed for itself:** determinism (effective quotas are a pure function of
flags + recorded knobs + defaults; no clocks/RNG/map order); **no gate weakening** (same problems, same
order, same counts for the same inputs; nothing that fails may start passing); **frozen assets** (do not
edit anything under `assets/`; if `assets/runbook/RUNBOOK.md` documents the old default, record it as a
frozen-asset follow-up); no new flags/verbs; tests must fail on pre-fix code; **commits: prose subjects,
no `feat:`/`fix:` prefix**; stage files explicitly, never `--no-verify`; do not run `verify-full.sh`
mid-plan (the plan runs it once at the end).

### 2.4 `2026-09-10-p0-review-consumption.md` — P0 Review Consumption Fixes (D1, D8, D6, D4, D5) (356 lines)

**Source:** two external reviews triaged against HEAD on 2026-09-10 with live reproductions against a
copy of the operator's campaign **C-21dd6a7642** (root `.scratch/morph-eval`, binary
`.scratch/review/lead/webv3`): `../morph/webv2-workspace/reviews/webv2-framework-review.md` and
`../morph/webv2-workspace/reviews/eval-retro-gold-findings.md`. "Five defects that are still live at
HEAD, each with a one-command reproduction. No new subsystem is introduced and no gate is relaxed."

**Tasks (6):**

1. **D1** — the custody label must be schema-legal. Fixed in the **emitter**, *not* by widening `assets/schema/probe_surface.schema.json`.
2. **D8** — the gate blocker must carry the precise reason (the text must contain `sequence coverage`, not the bare `no proven mainnet fork PoC (the latest required step)`).
3. **D6** — the precision metric must not go negative.
4. **D4** — a command that queues the memory row a terminal finding needs: exactly **one new flag** in the plan, `memory <campaign> --queue-finding FINDING`, plus `--kind KIND` and `--pattern TEXT`.
5. **D5** — name the actors the sequence PoC is missing, and document the rule.
6. **Record** what landed and what is still open (docs only).

**Acceptance (whole plan):** `scripts/verify-full.sh` green (**13/13**); against the campaign copy with
a freshly built binary — `probes C-21dd6a7642 run --emit` succeeds instead of aborting on `custody`, and
`audit` then reports **zero** `[probe_surface]` problems; `gate` prints the precise fork blocker whose
text contains `sequence coverage`; `report` prints a non-negative precision ratio;
`memory C-21dd6a7642 --queue-finding F-6791c9aee0b5 --kind confirmed --pattern <text>` queues a row and
`prove` no longer lists that finding under `learning`.

**Durable facts recorded:** `proofLearning` (`internal/completion/proofs2.go:261`) counts a terminal
finding satisfied when some `MEM-*.json` carries its `finding_id`. `learning.MEMORY_STATUSES` =
`["CONFIRMED","DISPROVED","DUPLICATE","OUT_OF_SCOPE","INTENDED_BEHAVIOR","UNREACHABLE","NON-ECONOMIC","TEST-HARNESS-ONLY"]`;
`learning.MemoryKinds` = `["confirmed","disproved","detector","benchmark","reflection","drift","regression"]`.
Queueing twice queues two rows (append-only, no dedup). The human `--approve` step is untouched.
Sequence coverage compares `actorSet(declared)` vs `actorSet(executed)` (`internal/sequencepoc/run.go:395`);
the reason today reads `executed steps use %d distinct actor(s) but the declared exploit needs %d — a
single-account PoC cannot cover a multi-actor exploit`, and D5 appends `; missing: a, b` (sorted, joined
with `, `) while keeping the prefix byte-identical. Declared actors are compared **as written** — no
normalising, lowercasing, or stripping prose like `(or protocol)`. Task 6 must also state a correction:
the eval retro's premise that every authoritative stage was green does not match `prove` on
C-21dd6a7642, which prints `discovery open [authoritative]` naming **Q-001/Q-143/Q-144**; the real gap
is that the bounty gate never consumes coverage, that the `discovery` bar is all **261 priorities**, and
that `brief` renders the probe surface as a bare count.

**Explicitly deferred (verbatim "Still open, with the reason each is deferred"):**

- **D2** — the capability graph has no writer, so `grants`/`needs` can be read but never recorded.
- **D3** — the severity floor has no mutation surface; `blast_radius` and `require_invariant_violation` are read by the policy rules and written by nothing.
- **D7** — a tooling failure and a genuine coverage failure produce the same reason.
- **D9** — budget has no attempt classes, so an unreachable RPC burns a repro attempt.
- **The eval-retro consumption batch** — provenance (`probe_row_id` on findings), a scoped ranked-coverage gate consumed by the bounty gate, a per-row probe disposition verb, and consequence-shaped row rendering.
- The plan's own "Out of scope (the next plan, P1 — the recall/consumption batch)" list repeats these plus `link --grants/--needs`, a severity mutation surface, budget attempt classes, tooling-vs-coverage classification, and `sequence check`.

**Constraints it fixed:** determinism; no gate weakening (D1 fixed in the emitter, D8 wording only, D6
computation only, D4 adds a queueing command, D5 text only); frozen assets (digests pinned by
`assets/testdata/asset_manifest.json`); exactly one new flag; each fix's test must fail on pre-fix code;
**commits: prose subject, no `feat:`/`fix:` prefix**, stage explicitly, never `git commit -a`, never
`--no-verify`; `.scratch/` and `../morph/` untouchable.

### 2.5 `2026-09-10-wave-g-tranche-1.md` — Wave G Tranche 1: Hybrid Evidence & Critic Outlook (1 311 lines)

**Status banner (verbatim):** "**Status: EXECUTED 2026-09-11.** All 8 tasks landed via
subagent-driven development on branch `wave-g-tranche-1` and merged to `main`; review ledger, per-task
briefs/reports and the final whole-branch review live in git history and the SDD workspace until
cleanup. Follow-ups consciously deferred (recorded in `docs/IMPROVEMENTS.md` G1/G6 notes):
dataset-registry vocabulary + `--backtest` (G3 era), automatic policy injection for the outlook rubric
(G3 era), corroboration records only on operator-resolved tool-less survivors."

**Goal:** land **G7** (claim-intake methodology doc), **G1** (Slither detector evidence as campaign
findings + corroboration factor + tool-flags rendering), **G6** (critic triager-outlook recorded and
scored). Architecture: everything rides existing rails (hypothesis ingest, dedup `same` resolution,
verdict transition, deterministic A3 score, embedded asset packs); new fields are presence-gated so no
existing campaign's bytes move. Go 1.26.2, stdlib only; deps frozen in `go.mod`: go-toml,
jsonschema/v6, x/text, yaml.v3.

**Tasks (8):**

1. **G7** — the claim-intake checklist doc (`docs/eval-methodology.md`) + runbook pointer.
2. **G1** — Slither adapter package (`internal/datasets/slither`).
3. **G1** — `webv2 ingest --from slither` (campaign path).
4. **G1** — corroboration link on `same` resolution + acceptance factor.
5. **G6** — `verification.triager_outlook`: schema + transition + `verdict --outlook`.
6. **G6** — outlook factor in the acceptance score.
7. **G1** — tool-flags advisory block in `brief` (computed, never stored).
8. **G6** — critic prompt rubric (data-only) + full-gate close-out.

**Acceptance criteria it set:** byte discipline (principle 1) — "a new score factor contributes 0 when
its field is absent; `scripts/golden.sh` must stay green with zero fixture edits. **If a golden byte
moves, the task FAILS and is returned for redesign.**"; the close-out runs
`python3 scripts/sync-asset-manifest.py`, `go test ./assets/`, `go vet ./... && go test ./... -count=1`,
`scripts/golden.sh`, `scripts/runbook-walkthrough.sh`, `scripts/verify-full.sh` ("if the docker daemon
is unavailable, note it in the commit message; do NOT skip the rest"), and
`go run ./cmd/webv2 selftest --full`. "Expected: all green. Any golden byte move is a REGRESSION of this
tranche — stop and report, do not 'fix' the golden."

**Durable design decisions:**

- **The nine-check claim-intake rubric** (`docs/eval-methodology.md`, G7): every numeric external claim baked into an asset carries a `provenance` row `{claim, source_url, checked_date, verdict, tier}`; `verdict: uncorroborated` is legal but renders in reports; "The gate: numbers without a row enter only as `uncorroborated`."
  - **Hard kills (one is fatal):** (1) no leakage control — for LLM claims the split must respect the model's **PRETRAINING CUTOFF**, not just the study's own split; (2) synthetic labels counted as real (SmartBugs/SolidiFI-style injected-bug corpora are pattern labels, never mixed with real-incident scores); (3) contract-level F1 as the unit; (4) no baseline or a strawman baseline (the baseline is the best detector **for that class**, plus always-flag/never-flag floors); (5) no significance test.
  - **Soft failures:** (6) no run variance (require pass@k or multi-seed spread); (7) no cost accounting; (8) secondary-source numbers (re-verify against the primary page and cite THAT); (9) edition/version drift.
  - **Worked examples kept in the doc:** the **$953.2M** access-control figure belongs to the 2025-edition analysis window; the 2026 edition is **122 deduplicated 2025 incidents, ~$905M** (`https://scs.owasp.org/sctop10/`). GMX V1 (Jul 2025, **$42M**) is a refund-based cross-contract reentrancy inflating GLP pricing — **not** flash-loan-mediated.
- **G1 adapter:** `ToPayloads(doc)` yields one hypothesis-shaped payload per Slither check result, byte-deterministic order; every payload carries `provenance.sast_tools = ["slither:<check>"]` and `provenance.discovered_by = "sast/slither"`. CLI: `webv2 ingest <CID> --from slither --json-file out.json` runs N hypotheses through the SAME orchestrator ingest path.
- **G1 corroboration:** `dedup_meta.corroborated_by = "<tool finding id>"` (string, legal under `dedup_meta additionalProperties: string`) is recorded on the **non-tool side** of a `same` pair when **EXACTLY ONE** side carries non-empty `provenance.sast_tools`; event `dedup.corroborated {by, of}`. Tool-vs-tool is explicitly **not** independent corroboration. New constant **`acceptanceCorroborationBonus = 0.5`**, applied iff `corroborated_by` is a non-empty string. `AcceptanceEntry.Corroborated bool` is additive.
- **G6 outlook:** `SetTriagerOutlook(campaign, findingID, outcome, reason)` with enum `likely|uncertain|unlikely`, `reason >= 15 runes` post-strip (same law as shield adjudication); writes `verification.triager_outlook = {outcome, reason}`; event `finding.triager_outlook`. CLI `verdict ... [--outlook O --outlook-reason R]` (both-or-neither; never replaces the verdict call). Score nudge **`likely +0.5 / uncertain 0 / unlikely -0.5`**, presence-gated, never disqualifying ("outlook is a likelihood call, not a refutation").
- **Prompt rubric text (verbatim excerpt):** "After you record your verdict, you MAY also record whether a bounty triager would accept and PAY this finding under THIS campaign's policy. … the rubric is the program's own words, never your imagination"; "the outlook NEVER changes your verdict and is not a refutation — it is a prediction about a third party. Cite the policy line, not a vibe. If the campaign has no bounty policy recorded, do not speculate: skip the outlook."
- **`ChToolFlags`** mirrors `ChAmplifiers`, renders NOTHING (absent key, zero byte move) when no finding carries `provenance.sast_tools`; when present: `{total, by_verdict: {confirmed, disproved, pending, possible, duplicate, out_of_scope, informational}, corroborated: [finding ids sorted]}` — "the per-detector FP ledger computed at view time; no new store, sidecar law untouched."
- **One Go source for the enum:** `findings.TriagerOutlooks()`, consumed by CLI and mirrored in the score table, with `TestOutlookEnumSync` asserting the score keys and schema enum are set-equal to it — "no fourth hardcode allowed (review feedback item 1)."
- Pins to watch: `internal/cli/testdata/p3_args_golden.json` (usage-block pins for `ingest` and `verdict`); `assets/testdata/asset_manifest.json` (regenerated by Tasks 1, 5, 8 — never hand-edited).

**Deferred/refused:** dataset-registry vocabulary + `--backtest` — "tool flags have no ground-truth
`outcome`, so the eval-case lane stays empty until G3 exists"; automatic policy injection for the
outlook rubric (G3 era); "**Deferred by plan, not accident:** the policy-flag graduation from the Wave G
design survives to G3's backtest — presence-gated writes are this tranche's whole default story."

### 2.6 `2026-09-11-recall-wave.md` — Recall Wave (operator post-mortem) (974 lines)

**Goal:** "Close the four recall gaps and the hygiene batch from the operator post-mortem (**0/2 gold
miss**): sentinel-form probe rows, falsifiable 'covered' dispositions, discovery-slot reform,
payout-funding questions, planner bug_class fill, plan --json truth, and CLI hygiene — without bloating
the framework." Architecture principle: "make falsifiable statements cheap to file and expensive to
skip; the framework forces questions, it never pretends to answer them."

**Tasks (8):**

1. Sentinel-form probe rows (`own_form` + adversarial why).
2. Falsifiable "covered" — closing a sentinel row demands the passing value.
3. Discovery-slot reform — suspicion is free, confirmation is metered.
4. Payout-funding sub-question on funding-mismatch divergences.
5. Divergence diversity gate counts findings — planner stops blocking on its own output.
6. `plan --json` stops lying.
7. Hygiene batch — truncation, `WEBV2_ROOT`, targeted DUPLICATE, register notice.
8. Full gates, golden, release binary.

**Global constraints (all binding, and several are new law for later waves):** build/test env
`GOCACHE=$PWD/.scratch/gocache`; **"The Python twin is RETIRED. Never run pytest; there is no
cross-twin harness anymore."**; any `assets/` change re-syncs the manifest;
"`campaign_state.schema.json` top-level keys are FORBIDDEN in this wave"; new schema properties must be
**OPTIONAL** (absent = old behavior); byte-pinned probe goldens are **15 trees × 6 probes** and must
stay byte-identical; "Every new refusal branch needs BOTH a negative control (mutate the expectation
and watch the test go red) and an accepting closure path on the same fixture tier. Every new refusal
reuses the gate family's existing escape hatch (`--override-dismissal` + `--override-reason`) — **one
escape hatch per family, never a new one.**"; value-consuming CLI flags must guard option-looking
tokens (`TestNoUnguardedValueConsumption`); **"Never pin evolving counts (row totals, command counts,
schema counts) in gate/release scripts or test assertions — assert the line/format, not the number."**;
conventional commits on `main`; no cross-package test-helper imports.

**Durable interfaces recorded:**

- `structidx.GuardForm(text string) string` → `"sentinel"` or `"substantive"`; assertion-strength rows gain `own_form: "sentinel"` and `own_guard_text` **only** when the consumer's strongest guard is sentinel-form.
- **Task 2 refusal text (exact, used by tests):** `sentinel-guarded probe row <row_id>: a closing disposition must name the value that passes its check (--passes VALUE) — or override explicitly (--override-dismissal --override-reason R)`; `AnsweredOpts.PassesValue *string`; priority field `passes`.
- **Task 3:** `findings.ConsumeSlotOnce(campaign *state.Campaign, finding *validation.Value) error` — idempotent per finding via the finding's own `discovery_slot_consumed` flag. The slot is consumed once per finding at the moment it first rises above the E0 baseline (first above-E0 evidence or first status promotion above E0), **never at bare-hypothesis ingest**. Counter and ceiling key names unchanged: `budget.discovery_findings_so_far`, `budget.max_discovery_findings`. Budget-exhausted text is EXACTLY the current ingest text: `discovery budget exhausted — raise the ceiling (webv2 budget <campaign> --set-discovery N --actor NAME) or plan a new pass`.
- **Task 4 forced question (exact suffix):** ` Who funds the observed payout — name the primitive that credits the paying balance for this asset; if none exists, the payout draws from an unfunded balance.` — appended to funding-mismatch divergence `question` only; rows without a funding mismatch stay byte-identical. Deliberately a **forced question, not a computed verdict** ("a static 'unfunded' detector would be wrong for escrow deployments").
- **Task 5:** `DivergenceOpts.CampaignClasses []string`; `MinDistinctClasses = 4`; pure `DivergenceStatus` output unchanged when `CampaignClasses` is nil; with it, `named_classes` is the sorted union and the diversity `what` reads `"<n> distinct bug class(es) named (…); min 4 — set priorities[].bug_class or file findings naming them"`.
- **Task 6:** `plan --json` must contain at minimum, consistent with the text view: `work_queue`, `lenses`, `divergence`, and `priorities` (integer = `len(work_queue)`, the source of truth). "The keys already present stay; no key is removed."
- **Task 7:** (a) console tables > 40 rows print the first 40 then exactly one line `  … +<K> more rows — use --json for the full table` (constant `consoleRowCap = 40`, `--json` untouched); (b) root resolution order `--root` flag > `WEBV2_ROOT` env > walk-up (nearest ancestor of cwd containing a `campaigns/` directory, max 5 levels) > `.`; (c) `move <c> <f> DUPLICATE` without `--of <fid>` refuses with `move to DUPLICATE must name the duplicate of (--of <finding-id>)`, and `move <c> <f> HYPOTHESIS` from DUPLICATE is a legal reopen that clears the recorded duplicate target; (d) every successful `register` prints `note: registered artifacts are immutable — to revise, register a new artifact (the old one stays for provenance)`.
- **Task 8 release proof:** `dist/webv2` installed to `~/.local/bin/webv2`, `--version` equals `git rev-parse --short=12 HEAD`, no `+dirty` in the stamp; `sha256sum dist/webv2 ~/.local/bin/webv2` digests equal.

**Execution handoff (as written):** implementer `deepseek-official/deepseek-flash`, reviewer
`opencode-go-responses/muse-spark-1.3-contributor` via workflow `agent()` overrides — "NEVER omit
provider/model (silent local fallback)"; "Never dispatch two implementation subagents in parallel;
reviewers run only against completed diffs."

**Deferred/refused:** "wish 2 (adversarial-game artifact) → **deliberately NOT built as machinery
(anti-bloat)**"; "wish 4 (fork-lite) → **explicitly out of scope**"; the reference pytest step skips by
default — leave it skipped.

### 2.7 `2026-09-11-wave-g-tranche-2.md` — Measurement, Calibration, Defense Layers, Proof Rungs (1 328 lines)

**Goal:** land **G4** (gold-eval expansion — recall/precision measurable with Wilson CIs), **G2**
(per-class three-weight table as data), **G3** (acceptance priors from adjudicated outcomes +
`--backtest`), **G5** (two-layer defense matcher: soundness `mitigation_present` vs policy
`accepted_risk`), **G8** (invariants → Halmos/forge harnesses with a `PROVEN-BOUNDED` rung).
**Addendum (2026-09-11, user-updated spec):** tasks 19–26 land G16, G14, G13, G15, G12, G18, G17 in the
user's stated order; closeout renumbered to Task 27.

**Tasks (27):** 1 `internal/wilson` leaf package; 2 evalsuite pack (**16 gold cases, ≥8 classes**, clean
control + validator); 3 `internal/evalscore` join + CI renderer; 4 presence-gated `eval` audit section;
5 `class_weights.json` + schema + embed + drift & provenance validators; 6 corpus consumes `search`
column (byte-identical swap), floors/risk **refuse** `severity_default`; 7 `AcceptancePrior` + fallback;
8 c4audit loader; 9 sherlock loader; 10 immunefi-resolved loader + registry vocabulary; 11 `wPrior`
policy-gated OFF; 12 `corpus-surface --backtest`; 13 `mitigscan.go`; 14 mitigation demotion; 15
non-interference test + `reference_url`; 16 scaffold generator; 17 sandbox recipes + `verify --scaffold`;
18 outcome mapping → `verification.harness`; 19 G16 second golden recipe (≥1 row per probe axis, rot
gate); 20 G14a `amend` + `supersede` + SUPERSEDED status; 21 G14b batch `answered` all-or-nothing +
dismissed-with-reach subsection; 22 G13 cost-per-confirmed + per-lens yield; 23 G15 mint gate rerun
variance + fork freshness advisories; 24 G12 OWASP/SCVS aliases from a FETCHED primary page; 25 G18
`report --format immunefi`; 26 G17 tactic batting average + policy-gated planner demotion; 27 close-out.

**Global constraints (binding, quoted):**

- "No new dependencies; no new CLI verbs (flags on existing verbs only)." **Exception (human-sanctioned, 2026-09-11 IMPROVEMENTS G14):** "`amend` + `supersede` are the ONLY new verbs allowed in this plan; nothing else may add one."
- "Additive + presence-gated (principle 1): untouched campaigns render byte-identical; the ONLY sanctioned byte movers in this tranche are (a) G2's corpus weight-table swap, which ships with an equal-valued initial table so golden MUST NOT move, and (b) none other. If any golden fixture byte moves in any other task, that is a regression — stop and report BLOCKED; never edit a golden fixture to 'fix' a red golden."
- "Fail-open on judgment, fail-closed on money (principle 2): priors inform, never auto-dismiss; `wPrior` ships gated OFF by `bounty_policy.acceptance_priors` (default false); only a `--backtest` win on held-out data may flip the default (a later tranche decision, NOT this plan)."
- "**Soundness and policy never mix (G5 law):** `mitigscan` may write ONLY `dedup_meta.mitigation_present`; check13 may write ONLY `bounty.accepted_risk`; enforced by a non-interference test, and the report renders them under different bullets."
- "Every claim baked into this tranche's data files carries G7 provenance rows `{source_url, checked_date, primary}`; **secondary-source figures may seed NOTHING** (validator-enforced)."
- "Schema enum edits MUST be pinned in `t14FindingLegend` (walk order)."
- `GOCACHE=$PWD/.gocache`; "never `git add -A`; stage only task files"; gates per task: focused tests → package suite → `scripts/golden.sh` untouched-green → commit.

**Durable numbers and formulas:**

| fact | value |
|---|---|
| Wilson z (95%) | `z95 = 1.959963984540054`; `Interval(k,n)` returns `(0,0)` for `n<=0`, NaN-free |
| evalsuite size | **16 gold cases (≥8 classes) + a clean control** = **17 rows** (the close-out runbook text says "17 gold cases"; wave-i backfills `deployed_at` on "all 17 rows") |
| `class_weights.json` | three weights per class: `search`, `acceptance`, `severity_default`; schema `acceptance` min 0.25 / max 4.0; **all weights ship 1.0 neutral**; drift test pins all-1.0 for this tranche; "Do NOT seed non-neutral weights 'from the OWASP numbers'" |
| `severity_default` | DISPLAY-only; floors and risk **refuse** it (plus `class_weights`, plus a top-level `classes` map) at their boundaries |
| `AcceptancePrior` | Wilson CI over adjudicated eval cases; `AcceptancePriors(minN)` returns per-class + global; **`n < 10` global fallback that says so** (`DefaultMinN`) |
| `wPrior` formula (verbatim law) | `wPrior = clamp( 2*(rate - global.rate) * min(1, n/30), -0.5, +0.5 )` — applies only when policy `acceptance_priors: true` AND the class prior is known with `!Fallback AND n >= DefaultMinN` |
| `--backtest` verdict | one of `improves` / `regresses` / `indistinguishable`, "decided ONLY by interval overlap"; indistinguishable-by-default; empty store exits 2 with `eval store: no adjudicated rows — the backtest certifies nothing without ground truth` |
| G5 mitigation demotion | `acceptanceMitigationDemotion = 1.0`; test pins ack + mitigation ⇒ −2, plus accepted_risk ⇒ −4 clamps to 0 with all three Factors shown |
| G5 sidecar shape | `mitigation_present = {"pattern":"cei-order","file":"src/Escrow.sol","line":"23","evidence":"last write at L23 precedes call at L26"}` (JSON with string values); NEVER writes `bounty.*`, never changes status, never touches `in_code_ack` |
| G8 rungs | `PROVEN-BOUNDED (halmos, k=100, EXEC-7)` / `counterexample (EXEC-9)` / `inconclusive (EXEC-11)`; "PROVEN-BOUNDED = bounded, never unbounded proof" |
| G15 advisories | `rerunAttempts = 3` (`reruns:"3/3"` or `"flaky n/3"`, docker-absent `"not-applicable"`); `forkStaleDays = 7` |
| G17 auto-tune | policy `auto_tune` default **false**; demote only when `n_planned >= 10` AND Wilson-upper(precision, n) `< 0.10`; flag OFF ⇒ zero change |
| G13 cost | `cost_per_critic_confirmed_usd`, `cost_per_evidence_confirmed_usd`; `null` when denominator 0 ("never ÷0") |
| G11 scope cap (tranche 3) | `postPatchScopeCap = 50` |
| G4 erratum | Wilson 95% for **2/2 is 34.2–100.0**; **20–100 is the 2/3 interval** (20.8–93.9); "Plan renders EXACT Wilson and files the erratum in T27 — never tune math to a doc sentence (G7 discipline)" |

**Other durable decisions:** `Acceptance(f)` keeps its exact signature and behavior; a new exported
`AcceptanceWithPriors(...)` carries the prior term; `AcceptanceRanking` delegates with priors=nil so no
current caller changes; `risk.SetPriorsEnabled`-style package-global is rejected in favour of the caller
resolving policy. `amend` bumps `claim_version` (never status) and appends a history entry
`reason: "amend: <changed keys>"`, logging `finding.amended`; `supersede` transitions the old finding to
**SUPERSEDED** (a status that transitions nowhere), re-parents every old evidence item into the new
finding as `{evidence_id, re_parented_from}`, sets `dedup_meta.supersedes`, logs `finding.superseded`,
and refuses when the old is terminal-already or new == old. Batch `answered` is all-or-nothing:
"validate EVERY row's gates … BEFORE applying ANY; all-or-nothing, first failure names the row and
exits non-zero with zero mutations."

**Deferred/refused:** "G3 graduation of defaults (explicitly OUT of tranche scope — policy flip needs
real backtest data)"; G2 weights stay neutral by design and graduation requires Task 12's `improves`
verdict on real data.

### 2.8 `2026-09-11-wave-g-tranche-3.md` — Wave G Tranche 3 (G10, G9, G11) (327 lines)

**Goal:** land **G10** (cross-chain assumption table + two structidx archetypes), **G9** (beyond-contract
`components[]` + two new taxonomy classes + two data-only playbooks), **G11** (`verify --post-patch`
regression loop). Architecture: "No new verbs (one new flag `--post-patch` on `verify`); no scanners, no
consensus/p2p code, no homebrew DOM/DNS scanners (**user non-goals** — the playbooks are YAML data for
model consumption only)."

**Tasks (10):** 1 G10+G9 model schema (additive `components[]` + `chain_assumptions[]`); 2 G10
projection (`AssumptionTable` + ASSUMPTION GAP rows in protocolgraph); 3 G10 archetypes (two structidx
predicates + YAML + schema + fixtures); 4 G10 table rendering (`brief` + report, presence-gated); 5 G9
taxonomy (two new canonical classes); 6 G9 components flow (opaque-surface rendering + component finding
end-to-end); 7 G9 playbooks (YAML, data only); 8 G11 post-patch verdict; 9 G11 scope (changed-surface
diff + clean-control plant check); 10 tranche close-out.

**Durable interfaces:**

- `AssumptionTable(model) (rows, gaps)`; row shape `{chain, finality, confirmation_depth, messenger, validator_set, threshold, separator}` (missing optional ⇒ JSON null, never empty string); gap shape `{hop, chain, reason}` with `reason ∈ {"missing-assumptions", "finality-unspecified"}`.
- Archetype ids **`signature-no-separator`**, **`proof-accepted-without-depth-gate`** with `playbook_hint: bridge-message`; check-type names **`sig_verify_no_separator`** / **`merkle_verify_without_depth_gate`** (reused by Task 9's plant check).
- New canonical classes **`frontend-injection`** and **`infra-boundary`**, resolvable everywhere a class resolves (ingest intake, dedup, gates, weights reader).
- `verification.patch_regression` record `{verdict, exec, base_exec}`; verdicts **`still_reproducible` / `fixed` / `indeterminate`** (fail-open); scope cap constant `postPatchScopeCap = 50`.
- `paid_for` join rule: `paid_for: true` components' classes are eligible for G3 priors; `paid_for: false` ⇒ `Fallback` side — "the fallback behavior is the law; assert it, do not change it."

**Acceptance / close-out:** `scripts/golden.sh` must exit 0 after EVERY task; golden campaigns carry no
`components`/`chain_assumptions`/post-patch data so every render addition is presence-gated; full gates
run in order with **everything committed first** (double-run determinism: no edits between run1/run2):
`go vet ./...`, `go test ./... -count=1`, `scripts/golden.sh`, `scripts/runbook-walkthrough.sh`,
`scripts/verify-full.sh` (13 steps), `selftest --full`. The IMPROVEMENTS entry must include honest
caveats: "chains[] stays strings with sidecar `chain_assumptions`; new classes carry no OWASP aliases by
design; post-patch verdicts are advisory."

**Deferred/refused (from the byte-risk register and non-goal guard):** no scanner code (T7 YAML only;
T9 reuses the existing prescreen evaluator); no consensus/p2p code (finality is a stored string, never
evaluated against a chain); no benchmark/standard writing (OWASP untouched; no classes beyond the two
G9 families); G10's "gold fixtures ride G4's cross-chain replay scenario" is handled as an honest
conditional (assert ES14-shape trips ONLY if shapes match — "no fake fixture coupling").

**Worker model (as written):** implementers AND reviewers `provider:"opencode-go-responses",
model:"muse-spark-1.3-contributor"`; final whole-branch review uses the most capable available model.
Untracked user files at repo root (`LEARNINGS.md`, two research `.md`s) are NEVER staged or committed.

### 2.9 `2026-09-11-wave-i.md` — Wave I: external-feedback items I1–I6 (415 lines)

**Goal:** land **I1** (G7 self-apply: temporal + near-dup discipline on eval partitions), **I2**
(baseline runner: always/never floors + binary-gated slither/aderyn comparators + aderyn loader), **I3**
(score-band precision + fabrication ledger in `## eval`), **I4** (operator-supplied DNS/dependency facts
for `components[]`, adapter pattern, **never live queries**), **I5** (four bridge predicates: threshold,
relayer-key, Merkle-path, default-on verifier), **I6** (SWC aliases fetch-primary + embargoed disclosure
bundle on publish). Same posture as tranches 2/3: no new verbs; one new flag `--baseline` on
`corpus-surface`, one `--disclosure` on `publish`.

**Tasks (10):** 1 I1a `deployed_at` on eval cases; 2 I1b temporal gate + cross-partition near-dup scan;
3 I5a threshold + relayer-key bridge predicates; 4 I5b Merkle-path + default-on-verifier predicates;
5 I2a SAST loader correctness (Slither real-shape repair + Aderyn loader + `--from aderyn`); 6 I2b
baseline runner (`always`/`never` floors + binary-gated Slither/Aderyn comparators); 7 I3 score-band
precision + fabrication ledger in `## eval`; 8 I4 operator-supplied DNS/dependency facts; 9 I6 SWC
aliases + embargoed disclosure bundle on publish; 10 close-out (IMPROVEMENTS, runbook narrative, full
gates, merge).

**Durable rules and corrections:**

- **`deployed_at` semantics:** `created_at` = ingestion stamp written by `AddCase`; `deployed_at` = when the underlying bug lived on-chain / advisory publication date, operator-supplied, may be absent; free string, backfill uses `YYYY-MM-DD` uniformly; validation is presence+string only — "no date-parser gate — a parser is YAGNI until the temporal rule needs ordering".
- **Ordering rule (locked):** compare `deployed_at` when BOTH rows carry parseable `YYYY-MM-DD`, else fall back to `created_at` (always present). Unparseable `deployed_at` ⇒ row is EXCLUDED with problem `unparseable-deployed_at <case_id>` (fail-closed on the row, fail-open on the run). A held-out row is temporal-excluded iff its date is strictly older than the max dev date.
- **Near-dup rule (locked):** `DupKey` = lowercase tokens of `gold.bug_class + gold.root_cause + basenames(gold.locations[].file) + code.repo`; Jaccard via the EXISTING `archetypes.Jaccard` (do not reimplement), threshold **`0.8`** constant `nearDupThreshold`; any held-out row with Jaccard ≥ threshold against ANY dev/training row ⇒ excluded with problem `near-dup <held> ~ <other> <score>`. Same-partition pairs are NOT scanned (dev-dev duplication is the loader's problem, out of scope).
- **Refusal posture (locked, no new verbs):** "no stored row is mutated or deleted. Backtest excludes + prints; Eval section renders problems when non-empty. A fully-excluded held-out set hits the existing `EmptyMessage` exit-2 path (already exists — reuse, do not invent)."
- **Premise correction #1 (ECE refused):** "Acceptance scores are NOT probabilities — they are an additive evidence sum (severity band 0–3 + evidence level 0–3 + critic verdict ±−2/+1.5 − demotions + reversibility, clamped at 0; the schema description at `assets/schema/finding.schema.json:1248` is authoritative). ECE over a non-probability score is meaningless." The honest question is band precision against the suite anchors. Commit message: `feat(I3): acceptance score-band precision + fabrication ledger in ## eval — ECE refused as inapplicable`.
- **Premise correction #2:** "there is no 'B4v3' anywhere in this tree; there is no such gate or event. There is also no stored refusal EVENT — stale/superseded refusals surface as `BoundaryError` at `internal/findings/boundary.go:258-262` and are not logged."
- **I6 disclosure bundle validation (fail-closed, exit 1 with a `publish failed: …`-style message):** unknown finding id → `disclosure: unknown finding id %s`; a cited finding not CONFIRMED (or a terminal state reached from CONFIRMED/CHAIN) → `disclosure: finding %s is not confirmed (status %s)` ("A disclosure about an unconfirmed hypothesis is a public false claim; the framework refuses it."); a cited finding outside the publish set → `disclosure: finding %s is not part of this publish`; duplicate ids ⇒ error ("an ambiguous count is a data defect").
- **I6 safety property (state it in the package doc comment, verbatim):** "The bundle's CONTENTS never enter shared memory. The campaign-local artifact holds the prose; the publish RECORD carries only `disclosure_sha256` (hex) and `disclosure_embargo_until`. Shared memory is a cross-campaign surface; free-text impact narratives do not belong on it."
- **I6 embargo law (verbatim):** "`embargo_until` is recorded verbatim. The framework does NOT refuse, delay, or suppress a publish while an embargo is open — an embargo is an agreement between the researcher and the program, and a tool that silently blocks publishing is a tool that silently loses the researcher's leverage. The one thing the framework does is make the state legible, so nobody can mistake a recorded embargo for an enforced one." Output lines: `disclosure: bundle <sha256[0:12]> (<n> findings), embargo_until <date> — recorded, not enforced` / `… , no embargo`. Record additions are present-only, so every existing `publish` invocation is byte-identical; the disclosure hash is a third, separate field — never folded into an existing hash.
- **I6 leak test:** "the bundle's `summary`/`impact` prose does NOT appear anywhere under the store directory (grep the store tree for a unique sentinel string in the test's summary — this is the leak test, and it must be a real grep of the written files, not an assertion about the record struct)."
- **Toolchain actually present on this box (measured):** Slither **0.11.6**, aderyn **0.6.8**, forge **1.8.1**, halmos **0.3.3** — "binary-gated tests run REAL here, skip-gated elsewhere".
- **CI-correctness pass at close-out:** grep the whole wave diff for `(95% CI` and re-check each by hand against `wilson.Format` semantics — "the `2/2 → 34.2–100.0` erratum must not be repeated".
- **Merge protocol:** verify the wave branch's base == the local `main` HEAD recorded at branch creation; if main moved, rebase and RE-RUN the full gate before merging; `git merge --no-ff wave-i`; "the wave branch stays listed (do NOT delete it until the user confirms the merge)".

**Deferred:** the Wave H backlog is the single index of open follow-ups — "This task does not file new
H-items unless a full-gate run produces one; if a task reported a deviation implying future work, FILE
it here in the Wave H section, appended with the next free H-number."

### 2.10 `2026-09-11-wave-j.md` — Wave J: "definitive final round — production-ready" (252 lines)

**Goal (verbatim):** "Close every remaining useful item, correct all known doc drift, prove the full
13-step gate green (**including `-race` and the determinism double-run, neither of which any wave has run
since 2026-09-10**), add CI so the gate runs without this box, and merge. After this wave there is no
backlog: Wave H is empty, the methodology's self-application gaps are closed, and the doc headers tell
the truth."

**Tasks (9):** 1 J-docs stale-prose correction; 2 J-perclass per-class precision/recall in `## eval`;
3 J-diversity suite compiler-version diversity; 4 J-backlog the validated H items; 5 J-lies skip-gates,
walkthrough gaps, README drift; 6 J-ci continuous gate (GitHub Actions); 7 J-truthy `pyTruthy`
consolidation; 8 J-recovery torn-log hand-recovery + `probes --flag=value` parity; 9 J-closeout.

**Corrections locked (each "a statement of landed fact, not a judgment")** with their evidence shas:
G14 evidence **`4edfd60`** (amend/supersede + live `internal/cli/cmd_amend.go`), **`b8ed2c6`** (batch
dispose + `internal/planner/batch.go`), **`7230c42`** (shared runner); D8 evidence **`85b2e3d`**. Header
changes: `E1–E4 deferred by principle 6` → `E1/E2 LANDED via G14, E3/E4 deferred by principle 6`;
`D8 awaits a decision` → `D8 LANDED 2026-09-10`; append `Wave H backlog filed 2026-09-11 (15 items,
open) — Wave I LANDED 2026-09-11 (I1–I6)`. "Do NOT renumber anything, do NOT touch Wave H or Wave I
sections."

**Triage results (measured):** triage-validated 2026-09-11 at **main `f4b6c66`** — "**ALL 15 STILL-OPEN,
zero already-fixed**; TODO/FIXME/XXX/HACK inventory: **zero real items**, all hits are by-design
placeholder vocabulary or fixture content". H15 = `reentrancy → SWC-107`: one data line + four pinned
literals (all `"[OWASP SC05]"`) + manifest regen, no code change. H1 = the `internal/costs/costs.go:430`
emit gate `if unattributedRows > 0 || !planOK` needs `|| planned["unattributed"]>0`. H2/H3/H4 =
post-patch scope caps + a shared constant with `internal/structidx/parser.go:52-53`. H5 (dedicated
citation hash fields) is the LARGEST item and must stay additive. H13 is "a decision + comment, not a
migration". H14 is a conditional hold.

**J-lies (audit-validated):** LIE 1 `WEBV2_PARITY_PROBE` (`internal/orchestrator/parity_probe_test.go:19`)
verified SKIP — **DELETE** the test (F2b precedent for retired twin-parity harnesses; "No replacement —
the golden suite + legacy cross-audit cover the ground against committed fixtures"). LIE 2
`requireClones`/`WEBV2_POC_ROOT` (`internal/datasets/defihacklabs/defihacklabs_test.go:510`, 4 tests)
verified 4× SKIP — convert to committed fixtures **or** delete, criterion "after the fix the tests run
GREEN in the default gate. No new skip, no new env var." Wiring notes: verify-full never invokes
`p2-docker-e2e.sh` (daemon-free by design) — add an echo line stating the separation; ambient-only gates
(forge-libs `.scratch/t16-libs`, sibling `sharevault/` checkout) documented as fresh-clone prerequisites
("Do NOT vendor third-party libs; do NOT move the sibling checkout"). **Dead-code audit: zero dead
symbols — no deletions authorized; the two compat shims `PublishCampaign`→`With` and
`ApplyFacts`→`Counted` are test-only-called but KEPT as the exported compat surface.**

**README/count drift:** `README.md` "14-section" ×3 (L59, L117, L120) → **15**
(`internal/audit/sections/register.go` has 15; `eval` presence-gated since G4), same fix in
`verify-full.sh` comments (L21/41/493/614), `scripts/p2-docker-e2e.sh:321`,
`scripts/legacy/README.md:23`; **`scripts/check-golden.py` `EXPECTED_SECTIONS` stays 14** (golden
fixtures correctly carry no `eval`) — fix only its false parity comment. Twin-retirement citation: P4-gate
has no §9.1 and §9 says the opposite — re-cite to `docs/archive/README.md`. `assets/playbooks.go`
"8 per-bug-class playbook YAMLs" → **10**; `assets/archetypes.go` "7 critical-bug archetype YAMLs" →
**13**.

**J-ci (locked minimal):** `ubuntu-latest`, setup-go 1.26.x, setup-python, then `go build ./...`,
`go vet ./...`, `go test ./... -count=1`, `bash scripts/golden.sh`. **NOT in CI:** `-race` ("slow, flaky
on shared runners — stays in verify-full.sh"), docker e2e, binary-gated tool tests ("assert the skips,
do not install the tools").

**J-truthy (the deferred "own pass"):** triage says "21 definitions, 11 bodies, 4 divergent semantics —
'a wrong unification silently flips gates. Needs its own pass that pins each call site's intended
truthiness first.'" Controller count 2026-09-11: **20 `func pyTruthy` + 1 `func pyTruthyCLI` across 21
files**. Method is the task: survey → pin each call site's intended truthiness with tests that pass
BEFORE and AFTER → unify only byte-identical clones into a new export `validation.PyTruthy`
("canonical format v1"; "matches CPython" retitles are out of scope) → rename genuinely divergent
variants to say what they do. Out of scope (locked): `pyTruthyCLI` (survey and pin it, do not merge
unless its tests prove identity); **any behavior change at any call site — "a test that needs its
expectation changed is a STOP-and-report, not an edit."**

**J-recovery:** the `verify` log-repair verb "stays **DECLINED** (a repair path needs a spec for what a
repaired chain claims, and minting chain-rewriting semantics in the final round is exactly the wrong
risk)". Instead, a documented hand procedure: `verify` fails loud pointing at the byte offset; copy
`events.jsonl` aside as `events.jsonl.torn-<date>` (evidence, never deleted in the same step); truncate
after the last complete line (a prefix truncated at a record boundary re-verifies; events after the cut
are LOST and must be re-done, and the loss is recorded in the campaign notes); re-run `verify`. Every
step must be VERIFIED against a real torn-log reproduction in scratch. Half B: 23 verbs accept
`--flag=value`; `probes` did not — make it match via the shared `=`-splitting helper; "If `probes`'s
parser is structurally different such that the shared helper does not apply, STOP and report — do not
hand-roll a second `=` convention."

**The decline ledger (verbatim list the close-out must record):** "corpus score cap [operator's number],
structidx↔probes authz vocab [coverage-contract change], E6 queue tie-break [deliberate + pinned],
C1-as-amend [append-only store; supersede via G14 is the sanctioned spelling], C2 [low value],
C4 [recommended against — G-01-at-scale machine], C5/E3 [deferred, needs an 'explored' rule],
C7/E4 [do-not-build reporting knob], `verify` log-repair verb [declined — hand procedure ships in
J-recovery instead]".

**Full gate (in order, "a failure anywhere re-opens the owning task, no exceptions"):** `go build ./...`
→ `go vet ./...` → `go test ./... -count=1` → `bash scripts/verify-full.sh` (the 13-step gate incl.
`-race`, determinism double-run, golden, walkthrough — paste the step table + exit code). Merge
`--no-ff wave-j`; branch retained until the user confirms.

### 2.11 `2026-09-12-minicertora-harness-backend.md` — MiniCertora Harness Backend (G8 third kind) (433 lines)

**Base:** `main` at **`60663100`** (or its descendant); work directly on `main` (this repo's convention).
**Depends on** `docs/MINICERTORA_ARCHITECTURE.md` (planes L0–L2 only; L3–L6 are follow-on plans).

**Goal:** land MiniCertora (local bounded Solidity SMT verifier) as a third `verify --scaffold`/`--kind`
harness backend behind the existing G8 seam: `.mspec` scaffold → EXEC record → rung mapping
(`counterexample / proved-bounded / inconclusive`) plus a presence-gated `proof` sidecar carrying the
tool's own `confidence/reason/bounds/assumptions`. "Wrap, don't build (Wave K law)."

**Tasks (5):** 1 MiniCertora scaffold (pure render, BODY law verbatim); 2 `MapMinicertora` — JSONL to
rung + proof sidecar (pure); 3 sandbox profile `minicertora` + toolchain probe (host-side, E3-capped);
4 CLI wiring — choices, `INV.mspec` file, attribution, proof write; 5 doctor/env honesty + close-out pins.

**The MiniCertora CLI contract (ground truth from source; cite when in doubt):** positional
`<sol_file> <spec_file>`; `--loop-bound` (def **4**), `--timeout-ms` (def **30000**), `--path-cap`
(def **64**), `--external-calls no-reentry|havoc-storage`, `--format json|text`, `--solc-path`,
`--solver z3|cvc5|portfolio`; exit **0/1/2 = PROVEN/VIOLATED/UNKNOWN**, one JSON object per line.
Verdict-line keys: `contract rule verdict confidence reason details assumptions bounds params
initial_storage calls final_storage failed_assertion warnings ghosts` + version stamps (`tool_version
solc_version spec_version evm_version optimizer_enabled`); `bounds` = `{loop_bound,
loop_bound_exhaustive, path_cap, solver_timeout_ms}`; `confidence ∈ confirmed|unconfirmed|modeled`.
**"23 reason codes, closed set"** (the plan prints the list: `assertion-violated`, `vacuous-rule`,
`vacuous-block`, `loop-bound-may-be-exceeded`, `path-limit-reached`, `solver-timeout`,
`solver-disagreement`, `unsupported-feature`, `unsupported-opcode`, `unsupported-storage-layout`,
`rejected-feature`, `unrecognized-dispatcher`, `multi-call-inner-arg-unsupported`,
`multi-call-stmt-between-calls`, `multi-call-ambiguous-call-site`, `unresolved-phi-source`,
`unresolved-branch-cond`, `summary-unverified`, `external-call-abstraction`,
`invariant-uninitialized`, `invariant-unchecked-functions`, `modelling-inconsistency`, `tool-error`).
**"abort lines have no `rule` key — key on absence, never on exit code alone."** ⚠ **This "23" is
contradicted by the two Wave L plans — see §3.5.**

**Mapping law (fixture-pinned, no prose scraping):** blank lines skipped; unparseable JSON line →
`inconclusive ("inconclusive (output is not JSONL)")`; a line WITHOUT a `rule` key is an abort →
`inconclusive ("aborted: <reason>: <details≤120>")`; zero attributed lines → `inconclusive
("inconclusive (no verdict line for rule inv_1)")`; two attributed lines → `inconclusive
("inconclusive (duplicate verdict lines for rule)")`; verdict-vs-exit contradiction → `inconclusive
("inconclusive (report-contradiction: exit N with verdict V)")`. **Caller contract:** a timed-out/killed
run is mapped to `inconclusive` by the caller BEFORE `MapMinicertora` is invoked ("timeout always wins
over output"); `MapMinicertora` treats a negative exitStatus defensively so "a caller bug degrades to
inconclusive, never to a false proof". `PROVEN` → `RungProvedBounded`, summary `"proved bounded (k=%d)"`
from `bounds.loop_bound`; `VIOLATED` → `RungCounterexample`, summary `"counterexample:
<failed_assertion.expression≤120>"` with `" [unconfirmed: crosses a havoc'd call]"` or `" [modeled]"`
appended per `confidence`; `UNKNOWN` → `RungInconclusive`, summary `"inconclusive (<reason>:
<details≤120>)"`.

**Proof sidecar:** fixed key order `tool_version, solc_version, spec_version, evm_version, confidence,
reason, bounds, assumptions, warnings, ghosts`, values verbatim, null for absent scalars, `VArr()` for
absent arrays. "The full counterexample witness (params/calls/final_storage) deliberately does NOT ride
into the sidecar — it stays in the EXEC stdout artifact (L4 plane: repro reads it from there)." Every
schema key is NULLABLE so the builder emits the full fixed key-set ("determinism over omission … a
strict `additionalProperties:false` + typed-only schema plus an omit-missing builder is a
byte-instability trap").

**Other durable facts:** `verification.harness {kind, rung, exec, bounded_k, summary, proof}`; event
`harness_run`; `bounded_k` from `bounds.loop_bound`; rungs render and inform — **"no live gate weight"**;
**`PROVEN-UNBOUNDED` is absent** by design; profile is host-only and "can never back E4+"; argparse
choice error renders `(choose from 'halmos', 'forge-fuzz', 'minicertora')`. Tests are fast and in-process
(P0 PERF law): "never execute real `minicertora`/`solc`/docker in default tests"; "NEVER run the
`web3sec-final` Python suite (policy: orchestrator-only)".

**Out of scope (deliberate — the follow-on plans):** "L3 escalation dispositions
(`internal/harness/disposition.go` + re-run ladders), L5 sweep templates, L6 calibration fixtures, and
the `calls[] → sequence_poc` repro bridge are plans 2–4 of `docs/MINICERTORA_ARCHITECTURE.md`'s §6
(tasks L-e→L-h). This plan is the honest minimum that makes `PROVEN-BOUNDED (minicertora, k=4, EXEC-n)`
a real campaign byte."

### 2.12 `2026-09-12-wave-l-advice-dispositions.md` — Wave L-advice (227 lines)

**Goal:** "Make every minicertora UNKNOWN a *named next action* (L3 advisory form from
docs/MINICERTORA_ARCHITECTURE.md §L3), and close the model-facing profile-registry drift (schemas +
prompts still list **five** profiles; the registry has **eight**)."

**Tasks (4):** 1 disposition table — pure data (`internal/harness/disposition.go`); 2 audit rendering —
every inconclusive minicertora line names its next action; 3 registry parity — schemas + prompts +
sidecar polish; 4 close-out — battery + docs record.

**Durable decisions:**

- `Disposition(summary string) (class string, advice string, ok bool)` — takes the EXACT inconclusive summary string a run stored (shape `inconclusive (reason: details…)` or the fixed floor strings); `ok=false` only for non-inconclusive rungs' summaries and empty input. Unknown reason codes return `(dispositionUnknown, adviceGeneric, true)` where `dispositionUnknown = "unmapped"` and `adviceGeneric = "review the spec and the tool version; the refusal names no known disposition"`.
- **Eight classes (constants):** `EscalateBound = "escalate-bound"`, `EscalateFlag = "escalate-flag"`, `EscalateSolver = "escalate-solver"`, `SpecRewrite = "spec-rewrite"`, `HonestRefusal = "honest-refusal"`, `ToolError = "tool-error"`, `ModelBug = "model-bug"`, `WitnessTriage = "witness-triage"`.
- ⚠ **"The closed set is 25 codes"** — verbatim from `/home/xand/Projects/minicertora/minicertora/corpus/runner.py:43-68` REASON_CODES ("read it yourself to confirm before coding"), with the class mapping (malformed-spec → spec-rewrite; the nine honest-refusal codes; tool-error; the four model-bug codes; `assertion-violated`/`expect-revert-violated` → witness-triage). This plan's Task 1 explicitly changes `docs/MINICERTORA_ARCHITECTURE.md:40` and `:206` from "23 codes" to **25**. See §3.5 for the contradiction with the minicertora backend plan.
- **Host toolchain law (prompts 36/47/49):** "Host toolchain profiles (halmos, forge-fuzz, minicertora) execute on the host with read-only source access; like `host-readonly` they support evidence at or below E3." — and "do NOT touch the `E4+ MUST reference container/VM` law."
- Golden-green string to expect: `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)`; walkthrough: `WALKTHROUGH GREEN`; selftest: `ALL PASS`. "If a gate fails, do not weaken the gate: report BLOCKED with the exact failing line."
- Check `ps aux | grep '[g]olden-run'` before running golden (never two concurrent runs).

**Deferred:** "auto-spawn of escalation execs remains the operator/model's `exec`, per surface budget;
`model_gaps` tally NOT built — the audit line is the gap surface"; follow-up 2 (bounded_k stays null; the
`k` rides `proof.bounds` and audit's `harnessBoundK` fallback) is "logged in the close-out note as an
open polish".

### 2.13 `2026-09-12-wave-l-defer-validation-completion.md` — Wave L-defer (60 lines)

**Goal:** "Close the wave L-system deferrals: enforce the scaffold byte-law on the run path (Validate
wiring), complete the faithful template set, make bridged witnesses fork-faithful (msg.value +
final_assertions), and render per-campaign refusal histograms (L3 full form, derived)."

**Tasks (6):** 1 wire `harness.Validate` into the run path (deferral #1); 2 complete the faithful
template set (deferral #2); 3 witness fork-fidelity — msg.value rides (deferral #3a); 4 `final_assertions`
from witness storage (deferral #3b); 5 refusal histograms — L3 full form, derived (deferral #4); 6 close-out.

**Durable decisions:**

- **Task 1:** new refusal arm in the existing Decision-2b violation rail: `scaffold-degraded:
  <describeScaffoldLine reason>` → rung inconclusive, output NOT used, no proof (minicertora). Failure
  order: **hash-bind first, then Validate** — "hash proves WHICH bytes ran; Validate proves those bytes
  match the CURRENT claim — both are needed and they refuse differently". A deliberate TIGHTENING (the
  tamper path was latent/unenforced; golden campaign does not tamper).
- **Task 2:** three more corpus-faithful templates (`privilege-escalation` from
  `no_privilege_escalation.mspec`, `unchecked-callback` from `ledger.mspec`,
  `value-transfer-accounting` from `withdraw_keeps_accounting.mspec`), bodies adapted EXCLUSIVELY from
  the vendored corpus specs, "same knob discipline as the shipped four (name/Contract/Function only)".
  **Doc truth:** "donation-accounting and cap-respected from the architecture list have **NO corpus
  ground-truth spec** (cap-respected rides the `invariant:` form instead)" — the RUNBOOK names the seven
  shipped template names plus these two dispositions honestly.
- **Task 3:** `sequence_poc` step gains optional `"value": {"type":"string",
  "pattern":"^(0x[0-9a-fA-F]{1,64}|[0-9]+)$"}` (wei literal; absent = zero or unstated). Bridge maps
  `env["msg.value"]` → step `value` when present/concrete; absent/zero → omit; unparseable → refusal
  `unbridgable step: <n> value <raw> not a wei literal`. "translate ONLY exact parseable forms and REFUSE
  the line otherwise (never round silently)".
- **Task 4 (AMENDED by controller pre-dispatch):** sequencepoc REQUIRES storage assertions to carry
  `target(0x)` + `slot(NUMBER)` (`sequencepoc.go:253-255`, driver reads by slot at `driver.go:318`), but
  the tool's `final_storage` gives variable NAMES; name→slot needs a solc storage-layout map the harness
  does not own. Landing = pure translation with an explicit layout parameter; **absent name ⇒ assertion
  SKIPPED, never guessed**. `BridgeSequence` keeps BEHAVING EXACTLY AS TODAY (emits empty
  `final_assertions`); add `BridgeSequenceWithLayout(obj, specID, findingID, layout map[string]string)`
  delegating to a shared core; layout maps `"<Contract>.<var>"`→slot digits; ids `A1..An` in sorted-slot
  order; `op` is `==`; "if ANY skipped, keep the emitted subset honest: docstring line `n of m`".
- **Task 5:** one derived audit line: `prover refusals (minicertora): <total> — <class>:<count>[, ...]
  sorted by count then class, top reason codes (<=3): <code>×<n>`, computed by walking the campaign's
  stored `verification.harness` records; presence-gated (halmos-only or no-refusal minicertora campaigns
  emit nothing). Histograms are rendering, not state — zero new event types, verbs, or campaign state.
- **Model directive:** implementers `b-ai/deepseek-v4.1-flash`, reviewers `b-ai/glm-5.3-flash`; explicit
  `git add` paths only ("LEARNINGS.md holds a foreign writer's uncommitted lines").

**Deferred after this wave (verbatim from Self-Review):** "remaining known-deferred after this wave:
template runtime-state-identifier surfacing, scorecard tier-2 exercise, **operator-gate law remains (a
local data run ≠ gate move)**." The close-out keeps deferrals #5/#6 (tier-2 pin, runtime surfacing) open
with one-line reasons.

### 2.14 `2026-09-12-wave-l-system-sweep-calibration.md` — Wave L-system (113 lines)

**Goal:** "Land the system half of docs/MINICERTORA_ARCHITECTURE.md: the corpus becomes our fixtures
(L6a tripwires), rule templates sweep classes over indexed contracts (L5), counterexample witnesses
bridge to repro candidates (L4), `invariant:` statements get real induction scaffolds whose report
objects ride the proof (L1+L2), and a scorecard script grades the prover on our evalsuite (L6b)."

**Tasks (6):** 1 vendored corpus + data tripwires (L6a); 2 rule-template library + statement-syntax
rendering (L5); 3 witness → sequence-PoC bridge, derived rendering (L4); 4 `invariant:` scaffolds +
`proof.invariant` sidecar (L1 deferred + L2); 5 prover scorecard over the evalsuite (L6b); 6 close-out.

**Durable decisions and measured facts:**

- **Vendored corpus:** exactly **8 targets** — `wrap-unchecked, rounding-drain, reentrancy-double-payout,
  access-control-mint, privilege-escalation, tx-origin-auth, invariant-cap, packed-storage-rejected`
  (copy `*.sol`, `*.mspec`, `expected.json`, `meta.md` verbatim; skip `replay.sh`). `VENDOR.json` shape:
  `{"upstream": "/home/xand/Projects/minicertora", "upstream_sha": "<rev-parse HEAD>", "vendored":
  "2026-09-12", "targets": {"<name>": {"files": {"<rel>": "sha256:<hex>"}}}}`. "Tests validate
  SELF-CONSISTENCY only (recorded sha == actual bytes; schema/enum conformance), never tool behavior."
- **Corpus expectation facts:** `status ∈ {expected, unwritable}`; verdict `∈ {PROVEN,VIOLATED,UNKNOWN}`;
  `expected_reason_code` null or a member of the closed set (empty string rejected); **`solc == 0.8.36`
  pinned literal**; `tool_flags` contains `--loop-bound`; `invariant-cap` pins rule_id **`cap_respected`**
  with PROVEN literals (per_function deposit/setCap, init proved, `witness_function` null, **5
  assumptions** — commit **`31e4bea1`**).
- **Reason-code set exported as data:** replace the disposition `switch reason` with a package-level
  `var dispositionOf = map[string]string{…25 entries…}` + `func IsReasonCode(code string) bool`; the pin
  test is `TestDispositionCoversClosedSet`; `TestReasonCodeSetIsTwentyFive` asserts the 25-name hard slice
  all true, `nope-code` false, and `len(dispositionOf) == 25`.
- **Statement syntax (two disjoint prefixes):** `template:<name> of <Contract>.<Function>` matched by
  `^template:([a-z0-9-]+) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$`; unknown template ⇒ error
  `unknown template %q` (no silent empty body). `invariant:<slug> of <Contract>.<State> <op> <expr>`
  matched by `^invariant:([a-z][a-z0-9_]*) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+) (>=|<=|==|>|<)
  ([A-Za-z0-9_]+)$`, rendering the induction scaffold syntax copied exactly from
  `invariant-cap/cap.mspec`. Non-matching statements fall through to today's plain skeleton (pinned).
- **`proof.invariant`:** `mcProof` gains an ELEVENTH key `"invariant"` placed LAST via a new helper
  `mcObjOr(obj, "invariant")` (verbatim copy when Obj, null otherwise — NO inner key filtering); the
  schema's `required` array gains `"invariant"` so the key set stays fixed at **11**. `bounds.loop_bound_exhaustive = (verdict==PROVEN)`.
- **Bridge refusals (L4):** `"no calls to bridge"` when `calls` absent/empty; `"unbridgable step: <why>"`
  when a call lacks function/target/step or an arg entry is non-string;
  `"symbolic senders cannot be fork-repro'd"` when ANY `env.sender` is not 0x-hex-40. Actors alias each
  distinct sender to `actor-1`, `actor-2`… by first appearance; `mine_blocks` NEVER emitted; audit gains
  `" | poc: <n> calls bridged"` (length only — no `BridgeSequence` call from audit).
- **Scorecard (L6b):** `scripts/minicertora-scorecard.py --results DIR --cases FILE [--json]` → per-class
  TSV (`class, cases, detected, proven_silence, refused, refusal_reasons histogram`); exit 0; `--self-test`
  runs the fixture and exits nonzero if printed rows differ from the pinned expected constants. Fixture
  pins: class arithmetic-overflow → detected 1/1 via `assertion-violated`; class access-control → detected
  1/1 via `expect-revert-violated`; proven_silence 1 case; refusal histogram `packed-storage-rejected` 1.
- **⭐ Acceptance law (record in docs, enforce nowhere yet):** "**no minicertora rung moves any gate
  until a REAL scorecard run on production evalsuite exists** — that run is operator-side (needs the
  binary) and is explicitly NOT part of this wave's gates."
- **Prompt-47-class trap:** "never edit `assets/prompts/` this wave (corpus resync precedent in LEARNINGS
  [20260912-0h9q])".

**Deferred out of the wave (verbatim):** "model_gaps histograms (L3 full form), fork-wave consumption of
bridged specs, remaining archetype templates beyond 4, final_assertions translation."

### 2.15 `2026-09-12-wave-m-fork-consumption-run2.md` — Wave M (26 lines)

**Goal:** "(1) make bridged witnesses actually runnable end-to-end (actor keys legal; `verify` emits a
`poc-<INV>.json` artifact a real `webv2 sequence run` can execute, layout sidecar honored); (2) teach the
scorecard what the first run exposed (correctly-clean agreement metric; cross-file tie-collision
diagnostic); (3) correct my own wrong 'gold-label drift' note; (4) collect a SECOND real evalsuite run
with better claims." Constraints: the wave L-defer law set applies **verbatim**; commits tagged `(M, n/5)`.

**Tasks (5):**

1. Legal actor keys bridge-side — `internal/harness/witness.go` actor alias `actor-N` → `actor_N`, replacing `TestBridgedActorAliasesAreRefusedByTheRunPath` (**commit `c8e2a299`**) with the POSITIVE pin: a bridged doc now PASSES `LoadSequenceSpec` + `BuildCommand`-stage validation with its native aliases (no `withLoaderSafeActorKeys` rename in tests).
2. Scorecard fidelity — new column **`clean_agreed`**: gold rows `confirmed-not-exploitable` whose tied lines are ALL PROVEN (the specificity signal the first run showed ES17 deserved; JSON emits it too; TSV header updated). Plus a **tie-collision diagnostic**: "a rule-bearing line whose rule ties case X while its FILE STEM ties case Y -> line EXCLUDED with stderr naming both (prevents the donation_keeps_rate double-tie fabricating counts); tier order otherwise unchanged." Verify against committed first-run data `docs/minicertora-eval/2026-09-12` — expect **ES17 now clean_agreed=1 (access-control row 2/0/0/1/1)** with the ES06 line still excluded.
3. `verify` emits the runnable PoC artifact — `artifacts/harness/<INV>/poc-<INV>.json`, presence-gated (nothing written when calls null/unbridgable; refusal ⇒ file NOT written but the existing `poc:` audit line still renders from state); **OVERWRITE law:** re-verify replaces the file deterministically (byte-pin rerun idempotence). Layout sidecar `artifacts/harness/<INV>/layout.json` = operator-provided `{"<Contract>.<var>":"<slot>"}` object mapping to decimal slot strings; malformed → "ignore + stderr note" (summaries stay stable), falling back to the plain (layout-less) bridge.
4. **(CONTROLLER, operator run — no subagent)** second real evalsuite sweep using `.scratch/mcvenv`: fast donation twin (local-snapshot form — expect VIOLATED), ES04 credit-accounting PROVEN false-silence probe (gold bad, model blind = honest data), ES13 twin of ES04 (LegacySplitter balances sweep accounting), one reentrancy accounting attempt each for ES03/ES18 documenting out-of-scope honestly, ES11 via the MintFreeC-style donate twin. Fix the class-map, RESCORE with the M2 scorecard, write `docs/minicertora-eval/2026-09-12-run2/`, and **RETRACT the wrong "gold-label drift" paragraph in run-1 `claim-sources.md`** ("ES17 IS the clean control: confirmed-not-exploitable; my note inverted it").
5. Close-out: IMPROVEMENTS Wave M record, battery incl. golden lock-safe + walkthrough + selftest + scorecard `--self-test` + manifest, final whole-branch review over the wave range.

**What remains (verbatim):** "G3 backtest for gate moves, RPC-timeout handling in driver?, third run
with template-surfaced state."

### 2.16 `2026-09-13-wave-n-operator-friction.md` — Wave N — operator friction (96 lines)

**Source (verbatim):** "`../morph/campaigns/C-16148b932c/FRAMEWORK_EVAL.md` (full operator review,
post-G-01). Controller triage done against code; every claim verified. **Rulings here are final for the
wave; reviewers police implementation, not design.**" Shared laws: `GOCACHE=$PWD/.gocache`; no
`git add -A`; tests never exec child tools; presence-gated schema additions; one-writer per file;
**controller commits — agents leave the worktree dirty and report.**

**Tasks (6) with their rulings:**

| id | defect / ask | controller ruling (durable) |
|---|---|---|
| T1 | stale remediation hints: `internal/findings/gate.go:48` `GATE_REMEDIATION["critic-verdict"]` = `webv2 verdict <fid> confirmed '<reasoning>' --actor <you>`, but the real CLI is `webv2 verdict <C> F-xxx --verdict confirmed --reason "..."` (RUNBOOK:715); same stale shape in `internal/risk/acceptance.go`, `internal/findings/transitions_test.go`, `internal/bounty/bounty_test.go` (5 fixtures), `internal/orchestrator/testdata/oracles.json` (1) | the oracle fixture documents a command that CANNOT run — fixing it is an **authorized golden-fixture edit**; golden reruns this wave. Derive the hint from the flags the parser actually accepts; hint must match the accepted argv EXACTLY including the campaign argument. NEW guard test in `internal/findings` asserting every `GATE_REMEDIATION` entry that starts `webv2 <verb>` names a verb present in the CLI dispatch registry and contains `--verdict` where required (registry-read, no source-grepping) |
| T2 | PoC-bearing payloads must be split ("static items now, mint later"); when both exist the E4-gate error masks schema errors | an evidence item may carry `"exec_ref": "EXEC-…"` (schema optional, pattern-matched) ONLY when the campaign ledger already holds that EXEC with SUCCEEDED status; ingest attaches through the SAME validation function `mint` uses (single source of truth; never fork the meaningfulness/E4 logic). Refuse: unknown exec_ref (naming it), not SUCCEEDED, ref'd exec bound to another finding (exec-finding binding stays). **Error ORDER: full schema validation of the whole payload first, then ledger checks, then gate math** |
| T3 | cheap agents wrote `CONTRADICTED` into model.json while the gate reads the ledger (UNVERIFIED); reconciler hashes artifacts but never compares statuses | **detect-and-name ONLY** — the ledger is authoritative; reconcile NEVER writes model.json statuses (one-writer law). Report line `invariant INV-xxx: model.json says X, ledger says Y — ledger governs`. Clean model files print nothing new |
| T4 | `webv2 ingest --lint` | validate through the EXACT same pipeline T2 established (schema → ledger checks → gate math) and print what ingest would print, but **write nothing**: no state change, no events, no files. Exit 0 accepted / 2 refused, "like the dry-run preflight spirit". Strictly after T2, same chain |
| T5 | self-duplicate resolved only via FP adjudication (poisons precision); `supersede` existed but was never found | **"do NOT add adjudication basis `duplicate` — it would create a second path to hide double-booked rows from precision when the honest fix (removing a row from the live set via SUPERSEDED/DUPLICATE status) already exists; double exclusion paths would silently inflate scores."** Instead: (a) `dedup`'s report gains a discovery line when it touched nothing — `manual self-duplicates: webv2 supersede <C> F-new --of F-old retires a copy WITH evidence copied — adjudicating it false-positive costs you precision instead`; (b) RUNBOOK cross-references supersede from the adjudication and dedup sections; (c) FP-adjudication acceptance checks whether the target duplicates another LIVE finding (same class + same affected path) and prints a **stderr nudge** to consider supersede — "nudge only, never refuses" |
| T6 | known class silently sets the floor; G-02 sat E4-saturated at an E6 floor because of an ingest-time taxonomy choice | (a) the `ingested …` line ALWAYS names the resulting CONFIRMED floor (`class bridge-message — CONFIRMED floor E6`) — "pure information, zero false positives"; (b) `ClassAdvisory` for KNOWN classes warns when the chosen class's floor is STRICTER than the loosest known class: name the count + two examples (sorted deterministically by (floor, name)); (c) re-file = `amend --class` already exists — VERIFY (test) that changing class recomputes the floor for the next gate read (no retroactive promotion, no stale blessing) and that a floor-relaxing re-file still requires the evidence the NEW class demands at CONFIRMED; RUNBOOK sentence: re-file by true root cause, attest the match in `--note` |

**Order & grouping (locked):** WF1: T1 ∥ T2 (disjoint files). WF2: T4 → T3 (T4 must follow T2; T3
disjoint). WF3: T6 ∥ T5. Controller verifies + commits each task; wave ends with full battery. (The
landing line in `docs/IMPROVEMENTS.md:1153` records Wave N as `LANDED (14e78426..2465c4ca, 6/6)`.)

### 2.17 `2026-09-16-morph-c12-feedback-wave.md` — Morph C-12f17fd555 Feedback Wave (1 018 lines)

**Goal:** "Implement the feedback items from the Morph campaign review (C-12f17fd555) that measurably
change detection or scoring outcomes; **refuse the rest.**" Architecture: eight small fixes in the Go
framework plus one data fix in the held-out gold pack.

**The measured root cause (verbatim):** "the custody probe's true-positive row existed but was
quota-cut behind symmetry noise (verified by re-running the surface with `--total 200` — rows
`4dc010af55`, `a047e6509f`, `3ec92e56da` appear and name the exact bug), so **the fix is noise removal,
not extractor changes**." The review's three suggested custody fixes were replaced by the verified root
cause, "with the re-run as evidence."

**Tasks (9):**

1. Reconcile gate must accept cites for `members` it demands — `rowSymbolKeys` (`internal/planner/disposition.go:377-380`) now includes `"members"`, so a cite naming a family member the reconcile gate requires (`reconcile.go:338-354`) passes instead of being refused (`reconcile.go:352-353`). Evidence: "C-12f17fd555 §8a: row `b6c0484194` demanded 34 members and refused every one of them."
2. Class synonyms — canonicalize on BOTH sides of the eval join + say so at ingest ("The C-12f17fd555 miss: the finding's class is a synonym of the gold…"; the eval join's class leg is an exact string compare at `internal/evalscore/evalscore.go:122-166`).
3. Custody/symmetry probes must ignore test-double members — "family cells no longer include cells contributed by test-double contracts, so all-test-double divergences (**8 of the 12 quota-filling rows** in the measured campaign: `d030096914`, `dd688b424a`, `a283479dbb`, `6476df1a6d`, `5c2f2bd715`, `83797a7db6`, `d47a01a479`, `994b7e202f`) disappear from the surface."
4. Sibling disagreement must not pair across token standards — cells carry asset `erc1155`/`erc721` instead of `erc20` when the receiver names that standard, so `symmetryDivergencesOf` (grouping by `Direction+"\x00"+Asset`, `symmetry.go:277-279`) stops pairing ERC-20 gateways against ERC-1155/721 gateways (rows `b6c0484194`, `be5532323d`, `135acfc612`, `4badf2ba8a`, `a836f14fd6` — "the review's 'top-ranked noise'"). Expected: cross-standard rows 0; at default quota (`--per-axis 12 --total 40`) the `onDropMessage` rows are now **emitted**, not tail-cut.
5. FP budget — split the precision denominator by CONFIRMED status. Measured: "the scorer's FP denominator counted **6 live findings (5 CONFIRMED + 1 POSSIBLE)** while the eval spec says 'count all other CONFIRMED findings' (**4**). Under the raw rule, an honestly-labelled unproven hypothesis is priced exactly like a fabrication." Produces `Report.ConfirmedLive`, `Report.ConfirmedAnchored` (ints) and `Report.ConfirmedPrecisionLine` (string; `""` when no CONFIRMED live findings). **Raw `FP` semantics unchanged.**
6. Synthesized economic equations are templates, not operator gaps.
7. Two hygiene fixes — model error flood + build-output drag.
8. Make the disposition + grading contracts discoverable.
9. (data, outside this repo) G-02 accept list must cover the framework's own vocabulary — modify `../targets/morph-gold-cases.json`: `CASE-2024a0923002` `bug_class_accept`: `["logic-error","token-integration"]` → `["logic-error","token-integration","bridge-message"]`.

**Repro convention (binding):** build with `GOCACHE=/tmp/gocache-webv2 go build -o .scratch/bin/webv2
./cmd/webv2` (home cache is read-only); run against a **copy** of the campaign at
`.scratch/repro-c/campaigns/C-12f17fd555`, **never the original** — `probes run` and `report` write.
No new dependencies; no new asset files, no asset-manifest churn ("this wave touches zero embedded
assets"); Python twin deprecated — "fixes are intentional Go-side decisions, no divergence ledger row
needed (ledger is archived at `docs/archive/`)".

**Execution errata (2026-09-16, after implementation):**

- "**Task 4 needed a schema widening the plan missed:** `assets/schema/probe_surface.schema.json:203` pinned `rows[].asset` to `["native","erc20","share"]`, so emitted `erc1155`/`erc721` rows aborted `probes run` at emit. Enum widened + description updated in **commit `17bf9c55`** (the plan's 'zero asset churn' constraint was a cost guard, and this is the same exact-allowed-values gap class the review flagged elsewhere)."
- "**Task 9's snippet had the wrong JSON level:** the pack's top level is a list and the class fields live under `gold` (`gold.bug_class_accept`), not at the row top. Applied at the correct level."
- "**Task 2's plan Step 5 was skipped during the wave** (repro-c owned by another task) and run by the coordinator between waves: **recall 0/2 → 1/2 after Task 2, 2/2 after Task 9.**"
- "**Task 8's glm reviewer returned null twice** (likely context death on the 105KB RUNBOOK); the coordinator verified it with direct commands instead."
- "**Final measured outcome** (coordinator-run `scorecard --gold` at HEAD, campaign record untouched): **recall 2/2, raw FP 4, CONFIRMED-only FP 3, CONFIRMED-only precision 2/5** — the §10b counterfactual, realized through code + pack data."

**Cut list — refused, with the reason (11 items, verbatim gist):**

| ask | why not now |
|---|---|
| `model --scaffold` (80–120 LOC skeleton writer) | Task 7 removes 90% of the pain (25 exact paths in one round trip); build it when a second operator hits it |
| Per-row `answered --explain` | Task 8's help block carries the same table for zero flag parsing |
| `evidence_ceiling` scope field (25–40 LOC + schema) | Real, but it silences a cosmetic warning; `floors set` already caps the campaign. Batch with the next schema-touching wave |
| `examined-unproven` closure status | Honest-record nicety; the reason prose already carries it and Task 5 stops it being *priced* as a fabrication. Revisit with the statuses vocabulary decision (two terminal-status vocabularies already disagree) |
| Probe-row `--subsumed-by` bulk disposition | With Tasks 3+4 the custody surface shrinks from **39 open rows to ~5**; the noise that made bulk closure urgent is gone |
| `complete` scope-capped vs unfinished grouping | Cosmetic; `deferred` already lists flags with reasons |
| Full OWASP/SWC crosswalk file | `aliases.json` already cross-references for display; a second vocabulary axis is a standardization project, not a bug fix |
| `poc_requirements.require_control_arm` switch | Not machine-checkable cheaply; the runbook operator-contract block (Task 8) is where the convention belongs |
| Contamination-check extension (fixtures, `targets/`, pinned tree) | Eval-harness ops decision, spans outside this repo; worth its own plan |
| `grep` pipeline guard | Host-side (DSH), not this repo |
| Mechanism-phrase stemming / description matching | Inert for this pack (no `match_mechanisms` rows); revisit when a pack carries phrases |

### 2.18 `2026-09-17-trust-boundary-hardening.md` — Production Readiness, v3 (337 lines)

**Goal (verbatim):** "Close every verified integrity gap and the operator-friction and
discovery-doctrine gaps from the C-7f1005ecd5 evaluation, so the framework is production-ready by its own
gates — **not 'flawless' (unknowable), but fully enforced**: every status the record can carry is true,
every doctrine the prompts preach is a gate, and the cockpit surfaces risk instead of comfort."
Go 1.26.2, stdlib, existing four direct dependencies; no new dependencies in any phase.

**Phases and tasks (16):**

- **Phase A — verified integrity defects (production blockers):** 1 reject ambiguous duplicate JSON object keys; 2 honest network labels for host profiles; 3 per-machine liveness coverage gate (the G-01 gap); 4 artifact attribution on invariant-verify.
- **Phase B — bookkeeping friction that cost real rounds:** 5 artifact-register deduplicates by resolved path; 6 `index` emits a registry refresh event when it rewrites artifact bytes; 7 `brief` next-actions are copyable commands; 8 snapshot re-pin summarizes exclusions; 9 classify maps missing-compiler to ENVIRONMENT.
- **Phase C — the cockpit enforces coverage, not comfort:** 10 open questions compile into the work queue; 11 cold probe surface is a persistent brief warning; 12 cockpit priority is risk × untouched, not alphabetical.
- **Phase D — supply chain and threat model:** 13 dependency freshness + advisory scan as an honest gate; 14 `SECURITY.md` — the honest threat model; 15 docs and pins reconcile.
- **16 (added during execution, from the Task 1 review):** reject duplicate YAML mapping keys.

**Definition of done (the production bar — "all checked, no exceptions"):** every task has a red→green
regression + review clean or parked-with-ruling + complete ledger; `go vet` clean; `go test ./...` green;
`-race` green on state/sandbox/harness; determinism ×2; `scripts/golden.sh`,
`scripts/runbook-walkthrough.sh`, `scripts/verify-full.sh` green at final HEAD; **release dependency
scanning must also succeed** ("missing tooling, unavailable advisory data, or scan errors leave
production acceptance incomplete. A development skip never satisfies this checkbox"); `scripts/release.sh`
green; static binary serves embedded assets standalone; legacy fixture cross-audit green; no open
Critical/Important findings in the final independently routed critic review ("Fix substantive feedback
and request reassessment toward >=9/10; **never pressure the critic to change its score, conceal skipped
checks, or equate the score with a security guarantee**"); honest-limitations note recorded —
"**discovery performance (the 0/2 benchmark) is NOT claimed fixed by this plan; it requires held-out
measurement.**"

**Durable decisions:**

- **Task 1 law:** `ParseOrdered` refuses a JSON object carrying the same key twice, before any consumer's first-match reader can disagree with the schema walker. Error `json: duplicate object key %q`; guard is per-object. **Unicode note (verified 2026-09-17):** `encoding/json` fully decodes `\uXXXX` escapes BEFORE the token reaches the caller, so the `seen` map already operates on the semantic key — "do NOT add a custom unescape step (it would be dead code)". Test rows include `{"a":1,"\u0061":2}`.
- **Task 16 law:** `ParseYaml` refuses a mapping node carrying the same key twice ("PyYAML safe_load silently last-wins; our canonical writer then emits JSON the Task 1 guard refuses — the two parsers must not disagree"). Error `yaml: duplicate mapping key %q`; per-mapping scope; alias nodes resolve before the check.
- **Task 2:** `networkLabel(profile)` — host profiles return `"host (unconfined — nothing enforces network-off)"`; container profiles return `profileNetwork[profile]` verbatim (`"none"`, `"bridge-host-gateway"`). Rationale: "The record must not assert isolation it does not have."
- **Task 3 law:** "**zero** liveness invariants → synthesize the template (existing behavior, unchanged); **partial** coverage (some machines covered, some not) → refuse the model load, naming the uncovered machines" (error names the stage-37 rule).
- **Task 4 — operator-approved acceptance correction (supersedes the original rationale):** "the implemented word-boundary check proves only that text names an invariant or target. It cannot establish that the property was checked. Existing `CHECKED_AGAINST_CODE` records must be described as **operator attestations, not automatic proof**. Preserve historical records; absent method provenance means legacy/unspecified, never machine-verified. A follow-up must label new attestations explicitly, bind artifact digest and statement/source identity, and keep mechanically parsed harness outcomes separate with their existing bounds and assumptions. **A token match alone must never create a mechanically verified outcome.**" Word-boundary regex `\bINV-2\b` (case-insensitive) after `NormalizeInvID`, because "a plain substring match would let `INV-2` falsely satisfy against an artifact citing `INV-20` or `INV-22`".
- **Task 12 law:** ordering weight is **ADDITIVE** — `Score = (untouchedCount * W1) + (severityScore * W2) + (openQuestionCount * W3)`, named constants with a `ponytail:` comment, ties break alphabetically. "**NEVER multiplicative:** a product would zero-out a critical consensus contract that happens to have zero open questions and drop it below alphabetical entries — exactly the failure the review flagged." Severity maps critical=3/high=2/medium=1/low=0.
- **Task 13 law (operator-approved correction):** "release mode fails nonzero when govulncheck is missing, unavailable, or reports findings. Development mode may explicitly skip an unavailable scanner but must label the scan INCOMPLETE, never PASS; findings always fail. Successful scanner exit is required for a release PASS. … Never classify arbitrary nonzero output as network isolation. Do not run go get, install tools, or update dependencies inside verification."
- **Global constraint on history:** "Original historical fixtures under `scripts/legacy` are immutable compatibility evidence. **Never sanitize, re-register, regenerate hashes, or rewrite their assertions to obtain green.** … When old data cannot satisfy a new assurance rule, preserve readability and report legacy/unvalidated provenance explicitly. Any migration requires a separate copy, explicit operator action, and tests proving the original bytes remain unchanged."
- **Dispatch model (as written):** implementers `b-ai` / `deepseek-v4.1-flash`; reviewers and final critic `b-ai-plain` / `qwen3.8-flash` (operator-selected fallback); worktree consent is an OPERATOR decision made before the first dispatch (declined → feature branch in place; never on main); strictly sequential Task 1→16, review packages from BASE never HEAD~1.
- **Explicitly out of scope (unchanged by v2):** Morph repo modifications, exploit development, autonomous hunting; new evidence rungs or lowered floors; MiniProver/MiniCertora changes absent a verified defect; Docker/VM escape hardening beyond honest labeling ("the container is the boundary; its hardening is upstream's").

**Deferred:** the Task 4 follow-up (label new attestations, bind artifact digest + statement/source
identity, keep mechanical harness outcomes separate) is explicitly **pending**; the 0/2 discovery
benchmark is explicitly **not claimed fixed**.

### 2.19 `2026-09-18-gold-findings-closure.md` — Gold-Findings Closure (475 lines)

**Goal:** "Close the discovery-axis gaps that produced **0/2** on `web3sec-final/targets/gold-findings.json`
(Morph L2 @ `22ca805e`) — enforce evidence relevance, rank adversarial lifecycle surfaces, make evidence
reachability visible, and make the benchmark score measurable and repeatable."

**What success means (read before judging any task, verbatim):** "this plan's deliverables are measured
by **framework quality and measurement repeatability** — the exec-relevance gate refusing theater
evidence, the cockpit ranking the adversarial game, reachability visible at planning time, the score
reproducible by one command. **The re-run score is NOT a deliverable of this plan.** Only Task 2 plus the
operator's own campaign session can plausibly move 0/2; Tasks 1/3/4 raise the honesty and measurement bar
and must not be judged against score movement they were never designed to produce."

**Defect/wish mapping (single table, "no dual vocabulary below this line"):** the eval numbers defects
1–7 and wishes 1–6, and "**The two schemes are offset (wish 4 = defect 6, wish 5 = defect 5). This plan
uses defect numbers only.**"

| defect | closed by |
|---|---|
| 1. Liveness doctrine unenforced | hardening Task 3 (done) |
| 2. Cockpit ranks comfort, not risk | hardening Tasks 10/12 + this plan Task 2 |
| 3. Cold probe surface silent | hardening Task 11 (done) |
| 4. Amplifier signal misweighted (no adversarial-game surface) | this plan Task 2 |
| 5. Evidence ceiling invisible at planning time | this plan Task 3 |
| 6. `invariant-verify` accepts execs that never exercised the invariant | this plan Task 1 |
| 7. Bookkeeping friction | hardening Tasks 4A/5/6/7/8/16 (done) |
| Measurement loop | this plan Tasks 4–5 |

**Tasks (5):** 1 invariant-verify refuses execs that did not target an `applies_to` contract;
2 adversarial-lifecycle surfaces mint into the work queue; 3 `brief` renders evidence-reachability per
bug class (class floor vs box ceiling); 4 offline gold scorer (`scripts/eval-gold.py`); 5 re-run protocol
document (the measurement loop).

**Task 4 durable contract (the scorer):** invocation
`python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir> [--confirm G-ID ...]`;
**exit 0 on any well-formed scoring run (scoring is not a gate)**; exit 2 with a clean stderr message
(no raw traceback) for missing/malformed inputs or a `--confirm` id naming no gold finding. Stdout is one
JSON object with exactly: `found` (gold ids matching at an accepted evidence state), `missed` (the
complement), `false_positives` (int: campaign findings at `CONFIRMED` matching no gold's criteria),
`pass` (true iff **G-01 is in `found`** — "**Independent of FP count and of operator confirmation.**"),
`bonus` (true iff `pass` AND G-02 in `found`), `verdict`, `verdict_note`, `operator_confirmed`.
Verdict labels include `PASS_WITH_BONUS` / `PASS` / `PARTIAL_RESULT` (FP ≥ 10) / `FAIL`; the FP budget
comes from the benchmark's `scoring.false_positive_budget` read at runtime, never re-typed.

- **Campaign-dir contract (CORRECTED 2026-09-18 at Step 0 from the real record):** `findings/F-<id>.json`
  — ONE finding object per file, not a `findings.json` array (`internal/state.Campaign.FindingsDir` =
  `<root>/campaigns/<id>/findings`, listed as `F-*.json` by `internal/findings.LoadAllFindings` via
  `validation.ListPrefixedOptional(dir, "F-", ".json")`, e.g.
  `scripts/legacy/campaigns/C-45488bdaf5/findings/F-df01bb454ed5.json`); `events.jsonl` — one JSON object
  per line ("parse line-by-line; `json.load` on the whole file WILL fail"). **Field spellings are the
  finding schema's, not the plan's:** `finding_id` (not `id`), `status`, `root_cause.class` (not
  `bug_class`), `title` + `root_cause.description` (not `text`), `affected[].function` (not
  `primary_functions`), `evidence[].artifact_id` (not `artifacts`). The Step 0 grep's `links.json` is
  really `artifacts/invariant_links.json` (`internal/invariants.SaveLinks`) and is not part of the scoring
  contract.
- **Matching semantics (the resolved contradiction):** "Keyword matching over finding text uses
  `(?i)\b<tok>\b` (**correct here: natural-language prose**) … this deliberately differs from Task 1's
  command matcher, which operates on shell commands." Three independent external reviews raised the
  matching-semantics contradiction; it is "resolved by the binding left-boundary token rule with
  adversarial near-miss pins".
- **The scorer's own gate:** `python3 -m unittest scripts.eval_gold_test` (also runnable as
  `python3 scripts/eval_gold_test.py`) — "**both verified green 2026-09-18, 25 tests**".
- **Do NOT add the scorer to `verify-full.sh`** — "the 13-step pin is deliberate; a python step would add
  an interpreter dependency to the release gate — YAGNI".

**Task 5 protocol — durable facts a re-run must reproduce:** pinned target Morph L2 @ vulnerable commit
**`22ca805e`** (= `22ca805e2d09`, morph repo); "**A fresh `bash scripts/release.sh` on THIS checkout is
required before discovery starts and must print `RELEASE OK`** — an archived log from a different commit
(`docs/sdd/release-final.log` @ **`10182b5c`**) proves a different checkout was clean and is cited only as
evidence the script itself works, never as a substitute for the fresh run. Repeatability is the point of
the measurement loop." The contamination re-check reads `~/.webv2/shared-memory` (machine-global, not
repo-local) and must run FIRST on a clean environment; "runners with persistent home dirs will fail this
check by design — that is the check working, not a bug." The protocol must model `rollup_finalization` as
a state machine (the per-machine liveness gate refusing the model without it "is expected and is itself a
test of the hardening work"), run lifecycle probes with discovery open (the cold-probe warning nagging is
expected), and close invariants only with execs that target `applies_to` (the Task 1 gate refusing
suite-run citations is expected). Benchmark `contamination_check.checked: 2026-09-07`.

**Global constraints:** toolchain `go1.26.6` resolves via GOTOOLCHAIN auto-download — "expected behavior;
do NOT vendor or pin a local toolchain"; no new Go module deps (stdlib only), scorer is Python 3 stdlib
only; historical fixtures (`scripts/legacy/`, `web3sec-final/`, `morph/`) immutable — the scorer reads
them, never writes; **golden re-pins are tagged in the commit subject** (`(golden: <file>)`) "so a later
bisect can attribute which task moved which pin"; external scoring numbers entering framework DATA need a
`provenance` row per `docs/eval-methodology.md`, but the scorer's output is "an eval artifact, not
framework DATA".

**Out of scope (verbatim):** "no exploit development automation, no CI execution of the protocol, no
benchmark edits (the benchmark file is read-only evidence; changing it invalidates the comparison to
0/2)."

### 2.20 `2026-09-19-morph-r3-fork-ladder-and-record-trust.md` — Morph R3 fork-ladder & record-trust fixes (525 lines)

**Goal:** "Close the Morph round-3 defect list (FINAL_REPORT items 1–9) so the fork half of the evidence
ladder (E5/E6/T4 → CONFIRMED) is actually reachable, the campaign record treats its policy as first-class
evidence, and the status/floor/ledger interlocks are honest." Evidence doc:
`docs/feedback-triage-morph-r3.md` holds the file:line evidence. **"Implementers never run `git commit`** —
the orchestrator commits each task after its review gate passes, so bisect + manifest rules stay
enforceable."

**⭐ RESOURCE LAW (verbatim, and the reason it exists):** "**RESOURCE LAW (a full-suite subagent run
drowned this box once and was killed):** every `go test` invocation must be (a) `-run`-scoped to the tests
you just wrote/touched until they are green, then ONE final package-scoped check with
`go test -count=1 ./internal/<pkg>`, (b) wrapped in `timeout 300`, (c) run with `GOCACHE=/tmp/gocache
GOFLAGS=-p 1` to cap compiler parallelism, (d) **NEVER `-race`, NEVER `./...`, NEVER `scripts/golden.sh`,
NEVER docker, NEVER concurrent test binaries.**" Only ONE implementation agent runs at a time against this
tree. (Contrast with the other waves' mandatory `go test ./... -count=1` and `-race` — see §3.5.)

**Tasks (14) — defect → fix → durable shape:**

| task | defect (from the report) | durable decision |
|---|---|---|
| R3-1a | profile injects the operator's `FORK_RPC_URL` verbatim, so `http://127.0.0.1:18545` becomes the container's own loopback — "This is what made E5/E6/T4 unobtainable in the Morph campaign" | `containerForkURL(url)` exported as **`sandbox.ContainerForkURL`**; rewrites only the URL's host when it is a loopback literal; port/scheme/path/query survive untouched. One guard in `BuildContainerArgv` fixes both `exec --profile fork-runner` and `sequence run`. The profile runs on the bridge network with `--add-host host.docker.internal:host-gateway` |
| R3-1c | the fork-RPC reachability failure surfaced as `seq: empty address for anvil:0` with no cause because the `eth_accounts` probe pipes cast's stderr to `/dev/null` | driver-text change (two lines): stop discarding cast's stderr; `seq_err.txt` is written per cast call and read by `sanitize_reason` |
| R3-6 | `RecordAttempt` writes `verification.reproduction.status` unconditionally from the newest outcome, so a later diagnostic/failed run flips a `reproduced` finding back to `attempted` and un-qualifies the `reproduction-reproduced` CONFIRMED clause | reproduction status tracks the **BEST** attempt, not the latest; failures stay on the record in `repro.attempts[]` — only the projection changes |
| R3-2a | the policy file is the only campaign input with no integrity story: deleting exclusions from the on-disk copy survived `audit` and `brief --deep` | `scope --policy` registers the bounty policy: `kind "policy"` ALREADY exists in the campaign_state artifact enum, so `RegisterOrRefresh` mints a `POL-…` row, hashes it, logs `artifact.registered`; audit section 2 then catches tampering for free — "No new audit section" |
| R3-8 | `Scope()` calls `SetPhase("SCOPE")` unconditionally, silently dragging `DISCOVERY` back to `SCOPE` while the stage table stays 4/17 | guard the reload: a policy reload never rewinds the campaign phase. On a FRESH campaign phase is already SCOPE, where `SetPhase` is a same-phase no-op — "so the guard changes nothing for the oracles" |
| R3-3 | `STATUS_FLOOR` was advisory for everything but CONFIRMED: `webv2 move C F POSSIBLE` succeeded on zero evidence and printed `POSSIBLE (evidence level E0)` | the single shared writer `transition()` enforces the floor for `POSSIBLE=E2`, `PROVISIONALLY_VALID=E1`, `CHAIN=E4`, `CONFIRMED=class floor`. **CONFIRMED is deliberately excluded** — its `ConfirmationGateClauses` bundle already enforces the floor AND records `finding.gate_attempt`; "double-refusing would reorder failures pinned by `TestConfirmationGateFailuresAreEnumerated`" |
| R3-4 | the library mutates assumption status honestly but the OPERATOR had no verb | new verb **`webv2 assume`** — "a thin wrapper over the existing `findings.AssumptionTransition`", no library change; ships with RUNBOOK wiring |
| R3-5 | (i) a closure linking `--finding` never checks the finding describes THIS row; (ii) `refutationBacked` EXEC refs are bare existence checks doubling as `resolveAnchor`'s escape hatch | (i) **WARN (stderr)** when the linked finding's mechanism shares no row symbol; "we do NOT refuse (causal truth is not statically decidable — the repo's own doctrine, and refusal would fight the FP budget)"; (ii) that half gets a **real refusal** |
| R3-7 | priorities citing dead rows burn `audit` forever and no verb can discharge them | one status filter makes `webv2 answered C Q-207 blocked --reason '…'` the discharge verb; a CLOSED orphan priority discharges the audit row |
| R3-9c | every other write verb carries the actor; the critic verdict does not | `webv2 verdict` takes `--actor` and records it |
| R3-9e/9d | `webv2 audit --deep` is an exit-2 parse error; `webv2 schema` cannot reach the 23-class taxonomy | add a heal line; `schema` help points at the taxonomy. **"the `sequence_poc` half of the claim is refuted — `schema --list` prints it today; do NOT 'fix' that."** |
| R3-9a | amending bumps `claim_version`, silently stale-grading the recorded critic verdict | `amend` announces the verdict it just re-staled (twin of the class-floor note at `cmd_amend.go` ~203) |
| R3-9f | protocol-model boundaries carry the evidentiary standard in the prompt but the schema has nowhere to record the seeing | optional `evidence` string on `trust_boundaries`; **PARTIAL verdict: refuse nothing new, just give the citation a home** |
| R3-1b | the report asked to "stamp the pin with the answering provider" | only the machine-shaped half ships: `webv2 env`/doctor reports the CONTAINER-facing fork RPC (`container_url: http://host.docker.internal:18545`); "the pin itself is free-form JSON — no machine field to stamp; recording that as a limitation is honest" |

**Final gates (orchestrator):** `go test ./...`; `go test -race ./internal/sandbox ./internal/findings
./internal/planner`; `selftest --full`; `python3 scripts/check-golden.py`; smoke the fork ladder
end-to-end IF docker + anvil are up ("If docker is unavailable, record that in the triage status section
(**do not fake the proof**)"); update `docs/feedback-triage-morph-r3.md` with the shipped-status section
(per-task commit ids).

**Explicitly NOT doing (ponytail ledger, verbatim):** "No per-axis/quota 'fix' (**claim refuted**), no
class-weights data change (G3 backtest is the door), no new audit 'policy' section (the artifact registry
covers tamper-detection), no in-container preflight docker probe on every sequence run (the driver now
fails with the cause visible; the rewrite removes the main footgun), no SetPhase transition-legality table
(18 callers' blast radius for one misbehaving caller)." Plus: "`docs/IMPROVEMENTS.md` untouched per-wave;
triage doc carries the status."

### 2.21 `2026-09-20-morph-pass2-framework-fixes.md` — Morph Pass-2 Framework Fixes (804 lines)

**Goal:** "Close the six ranked gaps the Morph pass-1 framework review
(`../morph/FRAMEWORK_REVIEW.md` §6–§7) measured against the `webv2` control plane, in descending cost
order." Architecture: "Every fix is a deterministic gate/proof/schema change in the Go control plane
(`internal/…`) plus the matching agent-facing prompt/runbook lines (`assets/…`). **No model-in-the-loop
logic:** each rule forces a question onto the record and refuses silent passes, exactly like the existing
B4 dismissal gate and B2 adversarial-game clause."

**Tasks (8):**

1. Enforcement-timing rows lose the "asserted downstream → Safe" escape (review §6.1 / §7.1 — **the G-01 miss**).
2. The adversarial-game clause gains a mandatory strongest-attacker arm, cross-examined by the critic (§6.2 / §7.2).
3. Liveness classes confirm on a local lifecycle harness (E4), not on fork reality (§6.3 / §7.3).
4. Promote-before-close at the discovery exit (§6.4 / §7.4).
5. Content-hash idempotent ingest (§6.5 / §7.5 first half).
6. SUPERSEDED no longer owes a memory row (§6.6 / §7.6).
7. `--live-only` clutter filter on brief and memory list (§7.5 second half).
8. Full gate + runbook coherence.

**Durable decisions with the measured evidence:**

- **Task 1 (structural, not lexical):** "In morph pass 1, probe row **`34589e8588`** (axis `enforcement-timing`, lens L-03, tier 0, `assertion_gap` 4) was dispositioned **Safe** with the reason 'the truth of the prev state root is asserted downstream by finalizeBatch'." The existing deferred-consequence gate (FIX-5, `internal/planner/disposition_deferred.go`) triggers only on the `asserter` ANCHOR or on consequence WORDS in the reason (`DeferredConsequenceTokens`) — "a rephrased safety-mode answer passes both triggers untouched. The fix is structural, not lexical: **a high-risk row on the enforcement-timing axis always owes the liveness-mode pricing.**"
- **Task 2:** finding **F-e9461aa406cd** carried a **wrong** `challenge_interplay` ("the challenge path DOES undo it") straight through the gate into the report; "the clause is write-only: nothing checks the interplay claim against the strongest attacker variant (proof-**valid** bad state vs proof-invalid)". Fix: `findings.AdversarialGameFields = []string{"who_profits", "profit_mechanism", "challenge_interplay", "strongest_attacker"}`; `SetAdversarialGame(...)` gains one trailing `strongestAttacker` param (update every caller); the fourth field is forced in the same write, surfaced into the critic's bundle, and made the critic's named duty.
- **Task 3:** "G-01's PoC needed no fork: `Rollup.t.sol` + `MockZkEvmVerifier` reproduce commit→challenge→finalize in-sandbox. The framework's default CONFIRMED floor for `chain-freeze` / `sequencer-halt` / `liveness` is **E5** (the class-map default), which additionally arms `reproduction-tier` (T3 fork demand) in `gate_checks.go` — so 'no fork' became the evidence ceiling. A local harness proves sequential-finalization semantics entirely; **liveness is the *most* locally provable class.**" Produces `CLASS_CONFIRM_FLOOR["chain-freeze"|"sequencer-halt"|"liveness"] == "E4"`; ripples (auto): `floors.FloorTableReport` rows, gate `evidence-floor` (floor < E5 → no `reproduction-tier`, no unreachable diagnostic), report/briefing "reachable locally" wording.
- **Task 4:** "The pass closed with a critic-confirmed POSSIBLE at rank #8 while 90 queue rounds of mechanical work ran." The forcing function: the top-K critic-confirmed open findings must each have a recorded reproduction attempt (exec-backed) or an explicit written deprioritization (waiver) before `discovery` — the divergence-era exit the campaign already passes through — closes. A third `missing[]` arm inside the `discovery` proof, with waiver stage string **`"promote-before-close"`**.
- **Task 5:** "The same agent output re-submitted creates a new finding each time; the dedup stage then spends cycles marking them DUPLICATE — **258 duplicates of ingest clutter in morph pass 1**, and the learning stage demanded a memory row per terminal DUPLICATE. Idempotency belongs at the door: a payload whose content digest already exists IS the finding it would have created." Produces `finding.dedup.content_sha` (**16-hex**, same derivation as ingest's case ids via `validation.Sha12Hex`); re-ingest returns the EXISTING finding unchanged and logs `finding.ingest_idempotent {finding_id, content_sha, actor}`; the orchestrator's priority-closure/stage-note half still runs on the returned finding.
- **Task 6:** "The learning proof tracks SUPERSEDED as terminal and demands a memory row; `memory --queue-finding` (and `learning.MEMORY_STATUSES` / the memory schema enum) refuse the status — a catch-22 that forced per-finding waivers. **Supersession is a BOOKKEEPING redirect:** the successor finding carries the knowledge, the predecessor has nothing to remember. Fix on the demand side (**one deletion**), not by widening the memory vocabulary (three files + retrieval semantics for a status that encodes no judgment)." `completion.TerminalStatuses`' only non-test consumer is `proofLearning` (`proofs2.go:312` — verified).
- **Task 7:** `junkStatuses = {DUPLICATE, SUPERSEDED, INFORMATIONAL}`; summary line `live-only: N rows hidden`; "**OUT_OF_SCOPE stays visible: scope is a judgment the operator re-checks, not clutter.**"
- **Global constraints:** Go toolchain floor `go 1.26.2`; no new dependencies; tests never hit Docker, a network, or the model (gates are deterministic reads/writes over a `t.TempDir()` campaign); byte-pinned CLI/help strings get updated in the same commit with a note; **`validation.SetOrAppend` returns a NEW slice — always write it back: `v.O = validation.SetOrAppend(v.O, k, val)`** (the SetOrAppend write-back trap); every mutation path keeps "state file write + `campaign.Log` event are one unit" (existing `SaveThenLog`, `planThenLog`, `writeThenLog` — do not hand-roll a new pair).
- **Task 8:** `go build ./... && go vet ./... && go test ./... -count=1` green; fix every failure at its root ("a pin that encoded the OLD behavior gets the update + a comment naming the morph section; a genuine break gets fixed in code"); asset manifest + golden; `scripts/runbook-walkthrough.sh` green (runbook commands changed in Tasks 2/5/7); append a dated section to `docs/IMPROVEMENTS.md` — one bullet per review recommendation with its commit scope.

---

## 3. Cross-plan laws and conventions

### 3.1 The laws stated as binding, with their source wording

| law | verbatim statement (source) |
|---|---|
| **Python wins** (P0/P1 era) | "**Python wins:** Where the spec and the Go port disagree on behavior, the Python code in `web3sec-final/src/webv2/` wins. Port the behavior; do not 'improve' it." (P0 Global Constraints) · "**PYTHON WINS:** where the spec and the Python code disagree, the Python code is the source of truth." (P1 Rules) |
| **Go is the source of truth** (Wave K onward) | "**Go is the source of truth; changes are additive.**" (minicertora Global Constraints) · "**Go is the source of truth; golden is sacred.**" (wave-l-advice Global Constraints) |
| **The Python twin is retired** | "The Python twin is RETIRED. Never run pytest; there is no cross-twin harness anymore." (recall-wave) · "NEVER run the `web3sec-final` Python suite (policy: orchestrator-only)." (minicertora) · "Python twin (`web3sec-final`) is deprecated; fixes are intentional Go-side decisions, no divergence ledger row needed (ledger is archived at `docs/archive/`)." (c12 wave) |
| **Golden byte discipline** | "If a golden byte moves, the task FAILS and is returned for redesign." (tranche-1) · "never edit a golden fixture to 'fix' a red golden." (tranche-2) · "a fixture move is BLOCKED-report, never self-fixed." (tranche-3) · "Silent pin drift is a review-blocking finding." (trust-boundary) |
| **Assets are pinned** | "any edit under `assets/` requires `python3 scripts/sync-asset-manifest.py` before committing, or `go test ./assets` fails." (tranche-1) · "never hand-edit `assets/testdata/asset_manifest.json`." (tranche-2) |
| **Determinism** | "Deterministic: no wall clock, no map iteration order in outputs — sort explicitly (the repo pattern); `WEBV2_NOW`/`WEBV2_UUID` are the pinned seams." (tranche-1) · "**Determinism.** No new clocks, RNG, or map-iteration order in any output." (p0-review-consumption) |
| **Fail-open on judgment, fail-closed on money** | "Fail-open on judgment, fail-closed on money (principle 2): priors inform, never auto-dismiss; `wPrior` ships gated OFF … only a `--backtest` win on held-out data may flip the default." (tranche-2) |
| **Soundness and policy never mix (G5 law)** | "`mitigscan` may write ONLY `dedup_meta.mitigation_present`; check13 may write ONLY `bounty.accepted_risk`; enforced by a non-interference test, and the report renders them under different bullets." (tranche-2) |
| **One escape hatch per family** | "Every new refusal reuses the gate family's existing escape hatch (`--override-dismissal` + `--override-reason`) — one escape hatch per family, never a new one." (recall-wave) |
| **Never pin evolving counts** | "Never pin evolving counts (row totals, command counts, schema counts) in gate/release scripts or test assertions — assert the line/format, not the number." (recall-wave) |
| **Error text is contract** | "**Error message text is part of the contract** — ported verbatim, including remediation snippets." (P0) · "Error messages follow the house style: name the exact repairing command." (recall-wave) |
| **Surface budget / no new verbs** | "No new CLI verbs." (tranche-1) · "No new verbs, no new rungs, no live gate weight." (minicertora) · sanctioned exceptions, each recorded: `amend`+`supersede` ("human-sanctioned, 2026-09-11 IMPROVEMENTS G14 … the ONLY new verbs allowed in this plan"), `webv2 assume` (R3-4), `ingest --lint` (wave N T4, a flag not a verb) |
| **Evidence honesty** | "Existing `CHECKED_AGAINST_CODE` records must be described as **operator attestations, not automatic proof** … **A token match alone must never create a mechanically verified outcome.**" (trust-boundary Task 4) |
| **Operator-gate law** | "**no minicertora rung moves any gate until a REAL scorecard run on production evalsuite exists** — that run is operator-side (needs the binary) and is explicitly NOT part of this wave's gates." (wave-l-system) · "operator-gate law remains (a local data run ≠ gate move)." (wave-l-defer) |
| **History is immutable** | "Original historical fixtures under `scripts/legacy` are immutable compatibility evidence. **Never sanitize, re-register, regenerate hashes, or rewrite their assertions to obtain green.**" (trust-boundary) · "do not fake the proof" (R3 final gates) · "the benchmark file is read-only evidence; changing it invalidates the comparison to 0/2." (gold-findings) |
| **Resource law** | "every `go test` invocation must be (a) `-run`-scoped … (b) wrapped in `timeout 300`, (c) run with `GOCACHE=/tmp/gocache GOFLAGS=-p 1` … (d) **NEVER `-race`, NEVER `./...`, NEVER `scripts/golden.sh`, NEVER docker, NEVER concurrent test binaries.**" (R3) |
| **One writer / one-writer law** | "detect-and-name ONLY — the ledger is authoritative; reconcile NEVER writes model.json statuses (one-writer law)." (wave N T3) · "state file write + `campaign.Log` event are one unit (existing helpers `SaveThenLog`, `planThenLog`, `writeThenLog` already do this — do not hand-roll a new pair)." (pass-2) |
| **SetOrAppend write-back trap** | "`validation.SetOrAppend` returns a NEW slice — always write it back: `v.O = validation.SetOrAppend(v.O, k, val)`." (pass-2) |
| **Byte-law tests compare against literal pre-change fixtures** | tranche-3 / wave-i / wave-j Global Constraints (repeated in every wave plan) |
| **Falsifiable statements, forced questions** | "make falsifiable statements cheap to file and expensive to skip; the framework forces questions, it never pretends to answer them." (recall-wave Architecture) |

### 3.2 The G7 claim-intake rubric (the one cross-plan data law)

Introduced in tranche-1 Task 1 and referenced "verbatim" by tranche-2 (validator-enforced), tranche-3,
wave-i (Task 9), gold-findings, and c12: **every numeric external claim baked into an asset carries a
`provenance` row `{claim, source_url, checked_date, verdict, tier}`; `verdict: uncorroborated` is legal
but renders in reports; numbers without a row enter only as `uncorroborated`.** Five hard kills
(no leakage control — for LLM claims respect the **pretraining cutoff**; synthetic labels counted as
real; contract-level F1 as the unit; no baseline or a strawman baseline; no significance test) and four
soft failures (no run variance; no cost accounting; secondary-source numbers; edition/version drift).
Tranche-2 tightens it: "secondary-source figures may seed NOTHING (validator-enforced)". gold-findings
adds the boundary: the scorer's output is "an eval artifact, not framework DATA".

### 3.3 Working conventions (environment, commits, delegation, tests)

- **`GOCACHE` is not one value across the trail** (sandbox-specific): `$PWD/.scratch/gocache` (P0-era `go test` steps, recall-wave, gold-findings uses `.scratch/gocache` + `GOFLAGS=-mod=mod GOPATH/GOMODCACHE`), `$PWD/.gocache` (tranche-3, wave-i, wave-j, wave-l-advice), `/tmp/gocache` (R3, c12's `GOCACHE=/tmp/gocache-webv2`). c12 explains why: "home cache is read-only here".
- **`GOPATH`/`GOMODCACHE`**: gold-findings pins `GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`.
- **Staging**: "stage only the task's files", "never `git add -A`", "never `git commit -a`", "never `--no-verify`" — stated in p0-review-consumption, emit-quota, tranche-1/2/3, wave-i/j, R3, pass-2. (Two plans do show `git add -A` in their own commit snippets — tranche-1 Task 4/7 and minicertora Task 4, wave-l-advice Task 3 — a literal inconsistency inside those plans.)
- **Untracked user property**: "`LEARNINGS.md` … and the two research `.md` files at the repo root are untracked user property and never staged" (wave-i, wave-j, tranche-3, R3, wave-l-defer: "LEARNINGS.md holds a foreign writer's uncommitted lines").
- **Commit message style drifts chronologically** (see §3.5): P0-era plans require "prose subjects, no `feat:`/`fix:` prefix"; wave plans require conventional commits (`feat(G6): …`, `fix(jval): …`) and later tag the wave (`(L-system, n/6)`, `(M, n/5)`, `(R3-1a)`).
- **Delegation routing (the historical ladder, all superseded — see §3.5):** P1 `openrouter/meta/muse-spark-1.3-contributor` (fallback `openrouter/deepseek/deepseek-v4-flash-0731`, "Never the local model"); tranche-3 `opencode-go-responses/muse-spark-1.3-contributor`; recall-wave implementer `deepseek-official/deepseek-flash` + reviewer `opencode-go-responses/muse-spark-1.3-contributor`; wave-i/j implementer `deepseek-official/deepseek-flash` + reviewer `opencode-go-responses/muse-spark-1.3-contributor`; wave-l-defer/wave-m/R3/gold-findings/trust-boundary `b-ai/deepseek-v4.1-flash` (reviewers `b-ai/glm-5.3-flash`, or `b-ai-plain/qwen3.8-flash` in trust-boundary).
- **Reviewer schemas**: wave-j notes "reviewers `provider:"opencode-go-responses", model:"muse-spark-1.3-contributor"` in PLAIN TEXT (no `opts.schema` — schema-constrained calls return null on that provider; parse the `VERDICT:` first line yourself)". c12 confirms the failure mode in practice: "Task 8's glm reviewer returned null twice (likely context death on the 105KB RUNBOOK)".
- **Test discipline (repeated):** tests never exec real tools / docker / the model; no `t.Skip`, no sleeps, no child processes; table-driven with byte-pinned expectations; "no >1000-event log loops in the default suite" (recall-wave); "`go test ./...` < 2s, `-race` < 2s" (P1).
- **CLI house shapes:** stdlib `t14Dispatch` handlers, `t14ExitErr(2, "<verb> failed: %s\n", err)`, value flags guarded `case a == "--x" && i+1 < len(args) && !looksLikeOption(args[i+1]):` with the standing guard `TestNoUnguardedValueConsumption`; usage block constant pinned once; refusals print the legal set; **warnings/notes ride stderr, never stdout** (quota-notice precedent `cmd_probes_quota_stream_test.go`).
- **Schema/legend law:** any new enum inside `assets/schema/finding.schema.json` must be mirrored in `t14FindingLegend` (`internal/cli/cmd_ingest_test.go`) **in walk order**; non-enum properties (e.g. `dedup_meta.mitigation_present`) leave the legend untouched. Run the Legend test after any schema edit even when no enum changed.
- **Style:** TigerStyle/Ponytail — YAGNI → stdlib → native → existing dep → one-liner → minimum viable; functions ≤70 lines; ~2+ assertions per test function; 4-space indent; hard-wrap 100 cols; full-sentence comments referencing task/wave history; lowercase error strings without trailing punctuation.

### 3.4 Gate commands and the green strings to expect

| gate | command | expected output |
|---|---|---|
| golden | `bash scripts/golden.sh` | `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)` |
| golden (older wording) | `scripts/golden.sh` | `MATCH` / `GREEN` |
| runbook | `bash scripts/runbook-walkthrough.sh` | `WALKTHROUGH GREEN` |
| selftest | `go run ./cmd/webv2 selftest` / `selftest --full` | `ALL PASS` |
| full local gate | `bash scripts/verify-full.sh` | **13 steps** green (10 in P0; grows by phase); includes `-race`, determinism double-run, golden, walkthrough |
| release | `bash scripts/release.sh` | `RELEASE OK`; `--version` == `git rev-parse --short=12 HEAD`, no `+dirty` |
| assets | `python3 scripts/sync-asset-manifest.py` then `go test ./assets/` | manifest updated; asset test green |
| testmap | `scripts/check-testmap.py` | totals reconcile; no duplicate `python_func` |
| gold scorer (offline) | `python3 -m unittest scripts.eval_gold_test` | 25 tests green (verified 2026-09-18) |
| security (new) | `scripts/security-check.sh` | strict release default; `--development` may skip a missing binary but labels the scan INCOMPLETE |

### 3.5 ⚠ Contradictions between source files (stated, not resolved)

These are cases where two assigned plans disagree. The digest records both; neither is silently picked.

1. **The minicertora reason-code set is 23 or 25.** `2026-09-12-minicertora-harness-backend.md:24` states "**23 reason codes, closed set**" and prints a 23-name list. `2026-09-12-wave-l-advice-dispositions.md:30/35` states the docs' "23 codes" claims are wrong and must become **25**, and `:35` says "**The closed set is 25 codes**" read verbatim from `/home/xand/Projects/minicertora/minicertora/corpus/runner.py:43-68`, whose list adds `malformed-spec` and `expect-revert-violated` to the backend plan's 23. `2026-09-12-wave-l-system-sweep-calibration.md:18` reinforces 25: "if unchanged, touch nothing" plus `TestReasonCodeSetIsTwentyFive` and `len(dispositionOf) == 25`. **Read: the later Wave L plans supersede the earlier count; the backend plan's "23" is the stale number, and the two Wave L plans are mutually consistent.**
2. **"Python wins" vs "Go is the source of truth".** P0/P1 make the live Python tree authoritative and require folding in new Python commits; recall-wave (2026-09-11) retires the twin outright and minicertora says "Go is the source of truth; changes are additive". **The cutover is real and dated (recall-wave), not a typo.**
3. **Test-suite scope.** R3 (`2026-09-19`) makes `go test ./...` and `-race` forbidden for its agents, with `timeout 300`, `GOFLAGS=-p 1`, and `GOCACHE=/tmp/gocache`, because "a full-suite subagent run drowned this box once and was killed". Every other wave mandates `go test ./... -count=1` (and verify-full's `-race`). **Both are binding in their own context: R3's law is an agent-level resource guard, while the wave-end orchestrator gates still run the full suite.**
4. **Commit message style.** "Prose subject, no `feat:`/`fix:` prefix" (p0-review-consumption, emit-quota-repair) vs conventional commits with wave tags (tranche-1/2/3, recall-wave, wave-i/j, wave-l-*, c12, R3, pass-2). **Chronological drift: the P0-era rule was replaced by the conventional-commit convention.**
5. **`GOCACHE` path.** `$PWD/.scratch/gocache` vs `$PWD/.gocache` vs `/tmp/gocache` (see §3.3). **Environment-specific, not semantic — but a copied command from one plan will fail under another plan's assumption.**
6. **Delegation provider/model.** Six different routes are named across the trail (see §3.3). **Superseded repeatedly; the standing directive recorded in the session ledger is `b-ai` only (`deepseek-v4.1-flash`, reviewer `glm-5.3-flash`), so the P1/tranche-3/recall-wave/wave-i/j routes are historical.**
7. **Gold-case count.** tranche-2 Task 2 says "**16 gold cases** (≥8 classes) + clean control"; tranche-2 Task 27's runbook text and wave-i Task 1 say "**17 gold cases**"/"all 17 rows". **Not a real contradiction: 16 cases + 1 clean control = 17 rows.**
8. **Plan-vs-ledger dates.** The tranche-1 plan file is dated 2026-09-10 but its banner says "EXECUTED 2026-09-11", while `docs/IMPROVEMENTS.md:1201` says "Wave G tranche 1 LANDED 2026-09-10". Similarly the file `2026-09-12-wave-m-fork-consumption-run2.md` is dated 2026-09-12, and `docs/IMPROVEMENTS.md` records **two different Wave Ms**: the eval-notes slice (M1–M6) "**LANDED 2026-09-11**" and "A later, distinct **Wave M** — the SDD minicertora fork-consumption + run-2 plan — landed 2026-09-12". **Cite the plan path, not the wave letter alone.**

---

## 4. Tasks these plans deferred that may still be open

Consolidated from every "deferred / still open / out of scope / declined / cut / not doing" statement in
the 21 plans. Grouped by the plan that recorded them; a later plan sometimes closes an earlier deferral
(noted inline). Nothing here is verified against HEAD — this is the plans' own open list.

### 4.1 Deferrals recorded as explicit open work

| # | deferral | recorded by | reason / where it was parked |
|---|---|---|---|
| 1 | **D2** — the capability graph has no writer; `grants`/`needs` are readable but never recordable | p0-review-consumption Task 6 ("Still open") | deferred to the next (recall/consumption) plan |
| 2 | **D3** — severity floor has no mutation surface; `blast_radius` and `require_invariant_violation` are read by policy rules and written by nothing | p0-review-consumption Task 6 | same |
| 3 | **D7** — a tooling failure and a genuine coverage failure produce the same reason | p0-review-consumption Task 6 | same |
| 4 | **D9** — budget has no attempt classes, so an unreachable RPC burns a repro attempt | p0-review-consumption Task 6 | same |
| 5 | **Provenance (`probe_row_id`) on findings** | p0-review-consumption "Out of scope" + Task 6 | next plan |
| 6 | **A scoped ranked-coverage gate consumed by the bounty gate** | p0-review-consumption "Out of scope" + Task 6 | "the real gap is that the bounty gate never consumes coverage, that the `discovery` bar is all 261 priorities" |
| 7 | **A per-row probe disposition verb** | p0-review-consumption "Out of scope" + Task 6 | next plan |
| 8 | **Consequence-shaped row rendering** | p0-review-consumption "Out of scope" + Task 6 | next plan |
| 9 | **`link --grants/--needs`, a severity mutation surface, budget attempt classes, tooling-vs-coverage classification, `sequence check`** | p0-review-consumption "Out of scope" | listed as the next plan's batch |
| 10 | **`assets/runbook/RUNBOOK.md` frozen-asset follow-up** if it documents the old bare `probes run` default | emit-quota-repair Task 3/Global Constraints | `assets/` is manifest-pinned, so the doc task records it instead of editing |
| 11 | **The P3-gate report's false "13/13" claim** must stay annotated as not reproducing | emit-quota-repair Task 5 requirement 4 | the step failed at `7baaa6a`, `8240e3c`, `9e9a671~1`, `9e9a671`, `2dbea50`, `10477d4`, `2737486` |
| 12 | **Dataset-registry vocabulary + `--backtest`** | tranche-1 banner + Self-Review | G3 era: "tool flags have no ground-truth `outcome`, so the eval-case lane stays empty until G3 exists" |
| 13 | **Automatic policy injection for the outlook rubric** | tranche-1 banner | G3 era |
| 14 | **Corroboration beyond operator-resolved tool-less survivors** | tranche-1 banner | "corroboration records only on operator-resolved tool-less survivors" |
| 15 | **Policy-flag graduation from the Wave G design** | tranche-1 Self-Review | survives to G3's backtest — "presence-gated writes are this tranche's whole default story" |
| 16 | **The adversarial-game artifact machinery** (post-mortem wish 2) | recall-wave Self-Review | "deliberately NOT built as machinery (anti-bloat)" |
| 17 | **Fork-lite** (post-mortem wish 4) | recall-wave Self-Review | "explicitly out of scope" |
| 18 | **The reference pytest step** in verify-full | recall-wave Task 8 Step 3 | "skips by default — leave it skipped" |
| 19 | **G3 graduation of defaults off neutral 1.0** | tranche-2 Global Constraints + Self-Review | "explicitly OUT of tranche scope — policy flip needs real backtest data"; Task 12's `improves` verdict on held-out data is the only door |
| 20 | **L3 escalation dispositions, L5 sweep templates, L6 calibration fixtures, `calls[] → sequence_poc` repro bridge** | minicertora "Out of scope" | "plans 2–4 of `docs/MINICERTORA_ARCHITECTURE.md`'s §6 (tasks L-e→L-h)" — L5/L6/bridge then landed in wave-l-system; **L3 landed advisory-only in wave-l-advice** |
| 21 | **Auto-spawn of escalation execs** | wave-l-advice Task 4 | "remains the operator/model's `exec`, per surface budget" |
| 22 | **`model_gaps` tally** | wave-l-advice Task 4 | "NOT built — the audit line is the gap surface" |
| 23 | **`harnessBoundK` fallback to `proof.bounds`** (bounded_k stays null) | wave-l-advice Self-Review | "logged in the close-out note as an open polish" |
| 24 | **Template runtime-state-identifier surfacing** | wave-l-defer Self-Review | remains known-deferred after that wave |
| 25 | **Scorecard tier-2 exercise** | wave-l-defer Self-Review + Task 6 | deferrals #5/#6 kept open with one-line reasons |
| 26 | **A gate move from minicertora rungs** | wave-l-system Global Constraints | "no minicertora rung moves any gate until a REAL scorecard run on production evalsuite exists" |
| 27 | **A third real minicertora run with template-surfaced state** | wave-m Task 5 | "what remains" |
| 28 | **RPC-timeout handling in the sequence driver** | wave-m Task 5 | "what remains" (question mark in the source) |
| 29 | **Task 4's assurance correction on `CHECKED_AGAINST_CODE`** — label new attestations explicitly, bind artifact digest + statement/source identity, keep mechanically parsed harness outcomes separate | trust-boundary Task 4 | "A follow-up must …"; "assurance correction pending" |
| 30 | **The 0/2 discovery benchmark** | trust-boundary Definition of done | "**is NOT claimed fixed by this plan; it requires held-out measurement**" |
| 31 | **The Morph gold re-run itself** | gold-findings Task 5 + "What success means" | operator session, out of CI and out of the plan's automation |
| 32 | **The gold scorer in CI / verify-full** | gold-findings Task 4 Step 4 | "Do NOT add it to `verify-full.sh` (the 13-step pin is deliberate … YAGNI)" |
| 33 | **Stamping the fork pin with the answering provider** | R3 Task 14 | "the pin itself is free-form JSON — no machine field to stamp; recording that as a limitation is honest" |
| 34 | **E1/E2 (amend/supersede, batch dispose) — closed by G14; E3/E4** | wave-j Task 1 | "E1/E2 LANDED via G14, E3/E4 deferred by principle 6" (the ledger header keeps E3/E4 open) |

### 4.2 Refused / declined, with the reason (do not re-propose without new evidence)

- **Wave J decline ledger:** "corpus score cap [operator's number], structidx↔probes authz vocab [coverage-contract change], E6 queue tie-break [deliberate + pinned], C1-as-amend [append-only store; supersede via G14 is the sanctioned spelling], C2 [low value], C4 [recommended against — G-01-at-scale machine], C5/E3 [deferred, needs an 'explored' rule], C7/E4 [do-not-build reporting knob], `verify` log-repair verb [declined — hand procedure ships in J-recovery instead]".
- **c12 cut list (11 items, §2.17):** `model --scaffold`, per-row `answered --explain`, `evidence_ceiling` scope field, `examined-unproven` closure status, probe-row `--subsumed-by`, `complete` scope-capped grouping, full OWASP/SWC crosswalk file, `poc_requirements.require_control_arm`, contamination-check extension, `grep` pipeline guard, mechanism-phrase stemming — each with its stated reason.
- **R3 ponytail ledger:** no per-axis/quota "fix" (**claim refuted**), no class-weights data change (G3 backtest is the door), no new audit "policy" section, no in-container preflight docker probe on every sequence run, no SetPhase transition-legality table ("18 callers' blast radius for one misbehaving caller").
- **wave N T5 ruling:** "do NOT add adjudication basis `duplicate` — it would create a second path to hide double-booked rows from precision … double exclusion paths would silently inflate scores."
- **wave-i premise refusals:** ECE refused as inapplicable to a non-probability additive score; "B4v3" does not exist; there is no stored refusal EVENT.
- **minicertora non-goals:** no new verbs, no new rungs, no auto-attribution, gate weight untouched, **`PROVEN-UNBOUNDED` absent**.
- **trust-boundary out of scope:** Morph repo modifications, exploit development, autonomous hunting; new evidence rungs or lowered floors; MiniProver/MiniCertora changes absent a verified defect; Docker/VM escape hardening beyond honest labeling.
- **gold-findings out of scope:** no exploit-development automation, no CI execution of the protocol, no benchmark edits.
- **tranche-3 non-goals:** no scanners, no consensus/p2p code, no homebrew DOM/DNS scanners (user non-goals); no benchmark/standard writing (OWASP untouched).
- **P0/P1 YAGNI deferrals:** `dlclark/regexp2` (P2) and `gopkg.in/yaml.v3` (P3) not added before the phase that needs them.

### 4.3 Closed deferrals a reader might otherwise re-open

Recorded so the trail is not re-litigated: **L1/L2 invariant scaffolds, L4 witness bridge, L5 templates,
L6a tripwires, L6b scorecard** landed in `2026-09-12-wave-l-system-sweep-calibration.md`;
**deferrals #1–#4 of that wave** (Validate wiring, faithful templates, msg.value, final_assertions) landed
in `2026-09-12-wave-l-defer-validation-completion.md`; **L3 advisory dispositions + registry parity**
landed in `2026-09-12-wave-l-advice-dispositions.md`; **the H1–H15 backlog** was "closed by Wave J
2026-09-11 (H1–H15 landed; **H16 filed**)" per `docs/IMPROVEMENTS.md:1209`; **G14 (amend/supersede +
batch dispose)** closed E1/E2.
