# Wave L-system: corpus tripwires, sweep templates, witness bridge, invariant scaffolds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the system half of docs/MINICERTORA_ARCHITECTURE.md: the corpus becomes our fixtures (L6a tripwires), rule templates sweep classes over indexed contracts (L5), counterexample witnesses bridge to repro candidates (L4), `invariant:` statements get real induction scaffolds whose report objects ride the proof (L1+L2), and a scorecard script grades the prover on our evalsuite (L6b).

**Architecture:** Everything rides the landed seams: scaffolds stay `Scaffold`-rendered with BODY-marker law, mappers stay pure functions in `internal/harness`, rendering stays derived (audit/brief), state stays untouched — this wave adds ZERO new event types, ZERO new verbs, and at most one schema-nullable proof key. Corpus data is vendored read-only. No test ever execs the real minicertora binary (no child tools in tests; the live tripwire is an operator script).

**Tech Stack:** Go stdlib + `internal/validation` ordered-JSON; `embed` for templates; one Python script in `scripts/` (consistent with `sync-asset-manifest.py`).

## Global Constraints

- Golden sacred: campaign bytes for existing flows must not move. New proof key `invariant` is presence-only for invariant lines (rule lines never carry it — mapper emits null, and the schema makes the key REQUIRED like its ten siblings, so the key set stays fixed at 11 — decide per Task 4: null-riding, not conditional).
- Every Go command with `GOCACHE=$PWD/.gocache`; `gofmt -l` empty on touched files; `go vet ./...` clean before each commit.
- Embedded-asset edits ⇒ `python3 scripts/sync-asset-manifest.py` in the same commit; `go test ./assets/ -count=1` green.
- **Prompt-47-class trap:** never edit `assets/prompts/` this wave (corpus resync precedent in LEARNINGS [20260912-0h9q]).
- Surface budget: no new verbs; `verify` gains NO new flags this wave (template/invariant modes are statement syntax, not flags).
- Fail-open + derived-rendering laws as before; dispositions unchanged (Task 4 may add reason codes only if minicertora's REASON_CODES set moves — check `corpus/runner.py` again at Task 4 time; if unchanged, touch nothing).
- Vendored corpus: provenance pinned in a `VENDOR.json` (source repo path, upstream git sha via `git -C /home/xand/Projects/minicertora rev-parse HEAD` at vendoring time, file sha256s). Tests validate SELF-CONSISTENCY only (recorded sha == actual bytes; schema/enum conformance), never tool behavior.
- Tests: no `t.Skip`, no sleeps, no child processes, no real binaries; table-driven; byte-exact expectations.
- Commit style: `feat|test|docs(scope): … (L-system, n/6)` matching prior waves.

### Task source-of-truth pointers (read before coding each task)
- Corpus root: `/home/xand/Projects/minicertora/minicertora/corpus/targets/<name>/` (`*.sol`, `*.mspec`, `expected.json`, `meta.md`, sometimes `replay.sh`).
- expected.json shape (verbatim from wrap-unchecked): keys `target, bug_class, sol, spec, solc, tool_flags[], status, rules[]{rule_id, expected_verdict, expected_reason_code, expected_details_include, essential_witness{failed_assertion, final_storage}, expected_assumptions_include[], replay}`.
- Witness calls entries (minicertora cli.py `_extract`): `{step, function, target, args[], env{}, reverted, reentrant, overrides{}}`.
- sequence_poc steps schema: `{step:int>=1, actor:str, target:0xH40, function:str>=2, args[str[]], mine_blocks?, expect_revert?}`; actors map alias→(0xH40|anvil:N); required spec_id `^SEQ-[A-Z0-9]+-[A-Za-z0-9]+$`, finding_id, actors, steps; `additionalProperties:false` everywhere.
- Invariant report line: `rule` = invariant decl name; extra top-level `invariant` object `{name, per_function[{selector,function,kind,reason,details}], init|null{selector:function-less, function,kind,reason,details}, witness_function}`; `bounds.loop_bound_exhaustive = (verdict==PROVEN)`.
- structidx: `internal/structidx/parser.go` emits functions with `name`, `selector`, attributes incl. `payable`/`external`/`view`/`pure` (attrSet :39); `LoadIndex(c)` reads the campaign's stored index.

---

### Task 1: Vendored corpus + data tripwires (L6a)

**Files:**
- Create: `internal/harness/testdata/minicertora-corpus/<target>/` for EXACTLY these 8 targets: `wrap-unchecked, rounding-drain, reentrancy-double-payout, access-control-mint, privilege-escalation, tx-origin-auth, invariant-cap, packed-storage-rejected` (copy `*.sol`, `*.mspec`, `expected.json`, `meta.md` verbatim — no edits; skip `replay.sh`)
- Create: `internal/harness/testdata/minicertora-corpus/VENDOR.json`
- Create: `internal/harness/corpus_test.go`
- Modify: `internal/harness/disposition.go` — EXPORT the closed set as data: replace the disposition `switch reason` with a package-level `var dispositionOf = map[string]string{…25 entries…}` (same classes; behavior identical) + `func IsReasonCode(code string) bool`; keep every existing test green UNCHANGED (the sweep test TestDispositionCoversClosedSet is the pin).

**Interfaces:**
- Produces: `harness.IsReasonCode(string) bool` (closed-set membership, single source now in Go); `testdata/minicertora-corpus/` tree for Tasks 2 and 4 to reuse (template bodies adapt from these specs; invariant syntax from invariant-cap's .mspec).
- VENDOR.json shape: `{"upstream": "/home/xand/Projects/minicertora", "upstream_sha": "<rev-parse HEAD>", "vendored": "2026-09-12", "targets": {"<name>": {"files": {"<rel>": "sha256:<hex>"}}}}`.

- [ ] **Step 1:** `git -C /home/xand/Projects/minicertora rev-parse HEAD` → pin; copy the 8 target dirs (python script, verbatim bytes); generate VENDOR.json from actual sha256s.
- [ ] **Step 2: Failing test** `corpus_test.go`: (a) `TestCorpusVendoringSelfConsistent` — walk testdata dirs (embed via `os.ReadDir` relative to testdata — Go tests may read their package's testdata directly), every file's sha256 equals VENDOR.json's record, VENDOR lists exactly the 8 targets, no unlisted files; (b) `TestCorpusExpectationsConform` — per expected.json: `status=="expected"`; verdict ∈ {PROVEN,VIOLATED,UNKNOWN}; every `expected_reason_code` is "" or `harness.IsReasonCode` true; `solc=="0.8.36"` (the vendored pin — assert equality so future revendors update consciously); tool_flags contains `--loop-bound`; invariant-cap's rules all carry `invariant`-shaped rule_ids — assert its `expected_verdict`/reason values verbatim as pinned at vendoring (write the exact expectations INTO the test as literals: invariant-cap → PROVEN + loop_bound_exhaustive semantics documented); (c) `TestReasonCodeSetIsTwentyFive` — count distinct `IsReasonCode` true across a hard-listed 25-name slice (copied from runner.py), and false for `"nope-code"`.
- [ ] **Step 3: RED** (missing map export / files) then implement disposition refactor (exact same class mapping; `Disposition` consults the map, default branch unchanged) → GREEN whole-package + `-run Disposition` old tests untouched and passing.
- [ ] **Step 4:** battery: go test ./internal/harness/ ./assets/ -count=1 (testdata inside the package must NOT ride the asset manifest — testdata is git-tracked but unembedded; verify assets test still green). Commit: `test(harness): vendored minicertora corpus tripwires + exported reason-code set (L-system, 1/6)`

### Task 2: Rule-template library + statement-syntax rendering (L5)

**Files:**
- Create: `internal/harness/templates.go` (+ `internal/harness/templates/*.tmpl` embedded) — FOUR templates whose bodies are verbatim-adapted from the vendored specs: `wrap-unchecked` (from wrap-unchecked/wrap.mspec), `rounding-drain` (rounding-drain/*.mspec), `access-control-mint` (access-control-mint/*.mspec), `tx-origin-auth` (tx-origin-auth/*.mspec). Each .tmpl is a BODY-window text with placeholders `{{.Contract}}`, `{{.Function}}`, `{{.StateVars}}`-style minimal set — derive the actual placeholder set from the four source specs (keep it ≤6 knobs).
- Modify: `internal/harness/mspec.go` — `Scaffold`'s minicertora branch: when the INV statement matches `template:<name> of <Contract>.<Function>` (regexp `^template:([a-z0-9-]+) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$`), render the .mspec rule frame exactly as today but the BODY window contains the rendered template (deterministic; no facts lookup — the statement carries all knobs). Unknown template name ⇒ error `unknown template %q` returned like today's validate errors (no silent empty body).
- Test: `internal/harness/templates_test.go`, extend `mspec_test.go`.

**Interfaces:**
- Consumes: Task 1 corpus as the adaptation source. Produces: `renderTemplateBody(name, contract, function string) (string, error)` (package-private) + the statement syntax recognized by `scaffoldMspec` — Task 4 does NOT extend it (invariant uses its own `invariant:` prefix).

- [ ] **Step 1: Failing tests:** table per template: name + knobs → byte-pinned body (write expected bodies AFTER extracting from the real .tmpl — pin them in the test so a later edit that moves a body trips the byte test); unknown-name error; `template:wrap-unchecked of Counter.deposit` INV through `Scaffold` → stdout artifact text contains the template body INSIDE the marker window and `Validate` round-trips unchanged (reuse existing Validate tests' helper); `template:nope …` → error; malformed statement prefix (e.g. `template:x`) → today's plain-skeleton path UNCHANGED (the regexp simply doesn't match — pin that non-matching statements render exactly what they render today).
- [ ] **Step 2: RED** → implement .tmpl files (bodies adapted from corpus specs: strip the `rule` frame — the BODY window is ONLY the `require`/`assert` sequence between the rule braces) → GREEN.
- [ ] **Step 3:** `go test ./internal/harness/ -count=1`, vet, gofmt; commit `feat(harness): rule templates sweep four archetypes through the scaffold law (L-system, 2/6)`.
- **Docs note in same commit:** RUNBOOK §verify minicertora paragraph (+2 lines describing the `template:` statement form and the four names) — manifest resync (RUNBOOK is embedded).

### Task 3: Witness → sequence-PoC bridge, derived rendering (L4)

**Files:**
- Create: `internal/harness/witness.go`: `func BridgeSequence(obj validation.Value, specID, findingID string) (validation.Value, string)` — obj is the verdict-line object (proof sidecar shape). Returns (sequence_poc-shaped object, "") or (VNull(), refusal) with refusals: `"no calls to bridge"` when `calls` absent/empty; `"unbridgable step: <why>"` when a call lacks function/target/step or an arg entry is non-string. Mapping: actors = alias each distinct `env.sender` value (0x… or symbolic text) to `actor-1`, `actor-2`… by first appearance; `symbolic senders cannot be fork-repro'd` refusal when ANY sender is not 0x-hex-40 (honest: the prover's free symbols don't survive the chain — the refusal text IS the guidance); steps: `{step, actor, target, function, args}`, `expect_revert:true` iff `reverted` true; mine_blocks NEVER emitted; final_assertions emitted ONLY when `final_storage`/`initial_storage` objects give concrete `balance`-style readings — for this wave return empty array (schema allows) + comment noting storage-assert translation is the fork wave's.
- Test: `internal/harness/witness_test.go` + one audit rendering extension.
- Modify: `internal/audit/sections/invariantverification.go`: for minicertora + rung counterexample + `proof.calls` non-empty array → append `" | poc: <n> calls bridged"` (pure derivation: read proof.calls length; NO call to BridgeSequence from audit — length only, honest label is about the witness existing). Test row.

**Interfaces:** Consumes nothing new; produces the shape later fork waves consume. Proof-sidecar access pattern: the audit gets the harness map (already has `objAt`).

- [ ] **Step 1:** failing tests: happy path (two distinct senders, 2 calls, one reverted) → exact object bytes via `validation.CanonCompact` pinned; refusal rows (empty calls; symbolic sender; missing function); audit `| poc: 2 calls bridged` byte row + no-poc row (halmos, or minicertora without calls).
### Task 4: `invariant:` scaffolds + proof.invariant sidecar (L1 deferred + L2)

**Files:**
- Modify: `internal/harness/mspec.go` — second statement syntax: `invariant:<slug> of <Contract>.<State> <op> <expr>` matching regexp `^invariant:([a-z][a-z0-9_]*) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+) (>=|<=|==|>|<) ([A-Za-z0-9_]+)$`; renders an induction scaffold: the file frame as today (`contract`, `function` lines kept if the current renderer emits them — read `scaffoldMspec` first; whatever the rule-frame path renders OUTSIDE the BODY window is scaffold-owned and stays scaffold-owned here) PLUS, inside the BODY window, the invariant block syntax copied EXACTLY from the vendored `invariant-cap/cap.mspec` (generalize its assert expression from the statement knobs; keep `foralls`/`init` clauses verbatim as in cap.mspec unless the file shows them optional).
- Modify: `internal/harness/minicertora.go` — `mcProof` gains an ELEVENTH key `"invariant"` placed LAST: `mcObjOr(obj, "invariant")` — a new tiny helper: verbatim copy when the value is an Obj, null otherwise (rule lines: no invariant object → null; invariant lines: verbatim object incl. per_function/init/witness_function inner values verbatim — NO inner key filtering, verbatim law).
- Modify: `assets/schema/protocol_model.schema.json` — proof gains `"invariant": {"type": ["object","null"]}` (values verbatim-admitted like the array slots' law; description one-liner) and the `required` array gains `"invariant"` (11 keys).
- Test: extend `mspec_test.go` (scaffold bytes pinned from cap.mspec shape; unknown/invalid statements fall through to today's plain skeleton — pin), `minicertora_test.go` (invariant PROVEN line → proof.invariant rides verbatim incl. init:null; rule line → invariant:null), `schema_verification_harness_test.go` (11-key accept; missing-invariant reject row), `cmd_verify_minicertora_test.go` e2e (invariant verdict JSONL line through verify --harness-result: proved-bounded rung, sidecar has invariant object with per_function array verbatim, display line unchanged shape).

**Interfaces:** Consumes Task 1's vendored cap.mspec as the syntax source of truth; produces the 11-key `mcProof` contract (update the existing key-order test).

- [ ] **Step 1:** RED tests as above (read cap.mspec + current scaffoldMspec BEFORE writing expected bytes; the invariant body's rule/attribution name is `MspecRuleName(inv)` unchanged — the report's `rule` field carries the invariant decl name, so attribution needs NO mapper change: pin that with a line `{"rule":"inv_1","verdict":"PROVEN","invariant":{…}}`).
- [ ] **Step 2:** implement (helper `mcObjOr`, mcProof append, scaffold branch) → GREEN harness+validation+cli+assets (`python3 scripts/sync-asset-manifest.py` rides the commit).
- [ ] **Step 3:** `bash scripts/runbook-walkthrough.sh` — if RUNBOOK's minicertora paragraph needs the invariant form (+2 lines), edit, resync manifest, rerun to `WALKTHROUGH GREEN`; then `ps aux | grep '[g]olden-run'` + `bash scripts/golden.sh` → GOLDEN GREEN (proof key addition must not move any existing links bytes: halmos/forge entries have NO proof key at all — already presence-gated; pin by the golden verdict). Commit `feat(harness): invariant induction scaffolds + verbatim invariant proof sidecar (L-system, 4/6)`.

### Task 5: Prover scorecard over the evalsuite (L6b)

**Files:**
- Create: `scripts/minicertora-scorecard.py`
- Create: `scripts/golden/scorecard-fixture/` — 2 tiny hand-made fixture dirs: `results/` (JSONL report lines copied in the tool's exact shape from Task 1 corpus expectations where convenient — 4 rules across 2 bug_classes incl. one UNKNOWN packed-storage refusal) and `cases.json` (3-row evalsuite-shaped slice: read `assets/evalsuite/cases.json` first and mirror its actual per-case keys — bug_class/deployment/file references — verbatim shape, 3 hand rows referencing nothing external).
- Modify: `scripts/README.md` (or the scripts index that exists) — one entry documenting the operator flow: run the sweep + verify chain, collect the report lines into a results dir, score it; `--self-test` mode exists for CI-free smoke.

**Interfaces:** Consumes nothing Go-side (pure python stdlib). CLI: `minicertora-scorecard.py --results DIR --cases FILE [--json]` → per-class TSV: class, cases, detected, proven_silence, refused, refusal_reasons histogram; exit 0; `--self-test` runs the fixture and exits nonzero if the printed rows differ from the pinned expected constants inside the script.

- [ ] **Step 1:** read `assets/evalsuite/cases.json` shape; author the fixture FIRST (it is the spec: 3 cases, 2 classes; expected output pinned in the script: class arithmetic-overflow → detected 1/1 via assertion-violated; class access-control → detected 1/1 via expect-revert-violated; proven_silence 1 case counted; refusal histogram packed-storage-rejected 1). Join key between result line and case: result `contract`/`rule` naming vs case fields — pick the join the evalsuite rows actually support (read them; document the choice in the script docstring; if cases carry no contract name, join on `bug_class` embedded in rule naming `inv-<class>`… honest fallback: cases→class via a --class-map FILE argument the operator passes; keep --self-test covering whichever chosen mechanism).
- [ ] **Step 2:** implement; verify `python3 scripts/minicertora-scorecard.py --self-test` exits 0, and against a corrupted fixture copy exits nonzero (temp dir).
- [ ] **Step 3:** NOTE: scripts/ is NOT embedded — no manifest ride; confirm `python3 scripts/sync-asset-manifest.py --check` still says current (proof of non-embedding). Commit `feat(scripts): minicertora scorecard over the evalsuite, fixture self-test (L-system, 5/6)`.
- [ ] Acceptance law (record in Task 6 docs, enforce nowhere yet): "no minicertora rung moves any gate until a REAL scorecard run on production evalsuite exists" — that run is operator-side (needs the binary) and is explicitly NOT part of this wave's gates.

### Task 6: Close-out — battery + docs record

**Files:** Modify `docs/MINICERTORA_ARCHITECTURE.md` (landing notes on §L1 invariant form now shipped, §L4 poc rendering, §L5 four templates landed / rest deferred, §L6a vendored tripwires landed + §L6b script landed with the operator-run law quoted), `docs/IMPROVEMENTS.md` (Wave L-system LANDED record + remaining deferrals: model_gaps histograms, fork-wave bridge consumption, remaining archetypes' templates, sequence-assert translation).
- [ ] **Step 1:** full battery in order: gofmt/vet/`go test ./... -count=1`; `ps` check + `bash scripts/golden.sh` → GOLDEN GREEN; `bash scripts/runbook-walkthrough.sh` → WALKTHROUGH GREEN; `go run ./cmd/webv2 selftest` → ALL PASS; `python3 scripts/minicertora-scorecard.py --self-test`; `python3 scripts/sync-asset-manifest.py --check`.
- [ ] **Step 2:** docs edits; commit `docs: wave L-system close-out — L5/L6 partial landed, deferrals named (6/6)`.

## Self-Review (plan author)

- Coverage: L6a→T1, L5→T2, L4-witness→T3, L1-invariant+L2→T4, L6b→T5, close-out→T6. Deferred honestly OUT of wave: model_gaps histograms (L3 full form), fork-wave consumption of bridged specs, remaining archetype templates beyond 4, final_assertions translation.
- Placeholders: template bodies and invariant syntax are pinned to VENDORED SOURCE FILES (T1 corpus) — the implementer copies bytes from them; that is concrete, not a placeholder. Evalsuite join mechanism has an explicit fallback ladder (T5 Step 1).
- Type consistency: `IsReasonCode` (T1) used only by T1 tests; `mcObjOr`/11-key mcProof (T4); `BridgeSequence(obj, specID, findingID)` (T3) consumed only by T3 tests + doc; template regexp and invariant regexp disjoint prefixes (`template:` / `invariant:`), fall-through pinned in both tasks.
