# Wave G Tranche 3 Implementation Plan (G10, G9, G11)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the last three Wave G items — G10 (cross-chain assumption table + two structidx archetypes), G9 (beyond-contract `components[]` + two new taxonomy classes + two data-only playbooks), G11 (`verify --post-patch` regression loop) — then close out.

**Architecture:** All three items are data-shape + deterministic-projection work on rails laid by tranches 1–2. No new verbs (one new flag `--post-patch` on `verify`); no scanners, no consensus/p2p code, no homebrew DOM/DNS scanners (user non-goals — the playbooks are YAML data for model consumption only, and findings on components arrive as model findings or G1-style adapter imports).

**Tech Stack:** Go control plane (`webv2` binary), embedded JSON/YAML assets (`assets/`), `validation.Value` document model, `structidx` Solidity index, golden suite (`scripts/golden.sh`) must stay green throughout.

## Global Constraints

- Golden byte discipline: `scripts/golden.sh` must exit 0 after EVERY task. Golden campaigns carry no `components`/`chain_assumptions`/post-patch data, so every render addition is presence-gated (absent ⇒ zero bytes). Never edit golden fixtures; a fixture move is BLOCKED-report, never self-fixed.
- Env: `GOCACHE=$PWD/.gocache` for every go command; `rg` (never bare `grep`); never `git add -A` — stage only the task's files (`git add <paths>` + the regenerated manifest when schema/assets change).
- After ANY `assets/` edit: `python3 scripts/sync-asset-manifest.py` and stage `assets/testdata/asset_manifest.json`.
- Schema/legend law: these tasks touch `protocol_model.schema.json` (NOT `finding.schema.json`) ⇒ the `t14FindingLegend` pin (`internal/cli/cmd_ingest_test.go`) is unaffected — but new canonical classes (T5) DO touch the finding-schema class vocabulary, so the legend test must be run and the pin updated in walk order there.
- TDD: failing test first for every behavior; byte-law tests compare against literal pre-change fixtures.
- Determinism: sorted output everywhere a map is iterated; no wall-clock except the pre-existing `nowIso()` path on write events; no `os.Stat` mtimes in new read paths.
- Model for workers: `provider:"opencode-go-responses", model:"muse-spark-1.3-contributor"` for implementers AND reviewers; the final whole-branch review uses the most capable available model.
- Untracked user files at repo root (`LEARNINGS.md`, two research `.md`s) are NEVER staged or committed.

---

### Task 1: G10+G9 model schema — additive `components[]` + `chain_assumptions[]`

**Files:**
- Modify: `assets/schema/protocol_model.schema.json` (two additive optional array properties; `additionalProperties:false` already governs the top level — new keys must be added to `properties` explicitly)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)
- Create: `internal/protocolgraph/components_assumptions_test.go` (schema round-trip + legacy byte stability)
- Consumes: nothing new (schema-only task)
- Produces: the `components[]` item shape and `chain_assumptions[]` item shape that Tasks 2/4/6 rely on — quote exact JSON below; later tasks must not drift these field names.

**Rationale (locked):** `chains[]` is `array<string>` (schema :13). Turning entries into objects would break legacy models, so assumptions ride a SEPARATE optional list keyed by chain name. `components[]` follows the doc's shape verbatim.

- [ ] **Step 1: Write the failing test** (`internal/protocolgraph/components_assumptions_test.go`):

```go
func TestComponentsAndAssumptionsRoundTrip(t *testing.T) {
    raw := `{"protocol_id":"p","name":"nn","contracts":[],"actors":[],"assets":[],"relations":[],
      "components":[{"kind":"frontend","path":"app/","trust":"untrusted","in_scope":true,"paid_for":true}],
      "chain_assumptions":[{"chain":"mainnet","finality":"probabilistic","confirmation_depth":12,"messenger":"canonical","separator":"eip712-domain"}]}`
    v := mustParseJSON(t, raw) // same helper the package's other tests use; find its real name first
    if err := validation.Validate(v, "protocol_model", 1); err != nil {
        t.Fatalf("additive schema rejects new keys: %v", err)
    }
}
func TestLegacyModelWithoutNewKeysStillValid(t *testing.T) {
    // byte-exact legacy fixture from an existing protocolgraph test (reuse, do not invent):
    // validate + marshal + compare bytes to the input literal.
}
```

Run: `GOCACHE=$PWD/.gocache go test ./internal/protocolgraph/ -run 'TestComponents|TestLegacyModelWithout' -count=1`
Expected: FAIL (schema rejects unknown keys — prove it with the validator's unknown-key error text in your report).

- [ ] **Step 2: Add the schema properties** — inside top-level `properties` (after `"subsystems"`):

```json
"components": {
  "type": "array",
  "items": {
    "type": "object", "additionalProperties": false,
    "required": ["kind", "trust", "in_scope", "paid_for"],
    "properties": {
      "kind": { "enum": ["frontend", "relayer", "keeper-service", "domain", "offchain-service"] },
      "path": { "type": "string" },
      "url":  { "type": "string" },
      "trust": { "type": "string" },
      "in_scope": { "type": "boolean" },
      "paid_for": { "type": "boolean" }
    }
  }
},
"chain_assumptions": {
  "type": "array",
  "items": {
    "type": "object", "additionalProperties": false,
    "required": ["chain"],
    "properties": {
      "chain": { "type": "string" },
      "finality": { "type": "string" },
      "confirmation_depth": { "type": ["integer", "null"] },
      "messenger": { "type": "string" },
      "validator_set": { "type": "string" },
      "threshold": { "type": "string" },
      "separator": { "type": "string" }
    }
  }
}
```

All assumption detail fields are free strings except `confirmation_depth` (nullable int): prose-recon-in, structured-out — the model stores what the recon declares, never an enum the codebase would have to version. `trust` is a free string for the same reason.

- [ ] **Step 3: Run the test** — same command. Expected: PASS. Then `python3 scripts/sync-asset-manifest.py`, `GOCACHE=$PWD/.gocache go test ./assets/ ./internal/protocolgraph/ -count=1` (green), `scripts/golden.sh` untouched-green.
- [ ] **Step 4: Commit** — `git add assets/schema/protocol_model.schema.json assets/testdata/asset_manifest.json internal/protocolgraph/components_assumptions_test.go && git commit -m "feat(G10/G9): model schema gains components[] + chain_assumptions[] — additive, legacy bytes stable"`

---

### Task 2: G10 projection — `AssumptionTable` + ASSUMPTION GAP rows in protocolgraph

**Files:**
- Create: `internal/protocolgraph/assumptions.go` — `func AssumptionTable(model validation.Value) (rows []validation.Value, gaps []validation.Value)`
- Create: `internal/protocolgraph/assumptions_test.go`
- Consumes: Task 1 shapes (read `components`? NO — only `chains` + `chain_assumptions` + `relations`).
- Produces: `AssumptionTable(model) (rows, gaps)` consumed by Task 4's renderers. Row shape: `{chain, finality, confirmation_depth, messenger, validator_set, threshold, separator}` (missing optional ⇒ JSON null, never empty string). Gap shape: `{hop, chain, reason}` where reason ∈ `{"missing-assumptions", "finality-unspecified"}`.

**Semantics (exact, mechanical, no judgment):**
- One row per entry of `chains[]` (strings). Assumption lookup: first `chain_assumptions[]` item whose `chain` equals the name; absent ⇒ all detail fields null (the "declared: none" rule — the RENDERER prints that, the projection emits nulls).
- Relations with `rel == "BRIDGES"` define hops: endpoints are matched against chain names by substring (`from`/`to`/`via` containing the chain string — relations are actor/contract edges; a hop "touches" a chain when any of its three text fields contains the chain name).
- Gap rule (the ONLY two rules — do not invent more): (a) a BRIDGES hop touches a chain name with NO assumption entry ⇒ gap `{hop: "<from>-><to>", chain, reason: "missing-assumptions"}`; (b) a touched chain HAS an entry but both `finality` and `confirmation_depth` are absent/null ⇒ gap `{reason: "finality-unspecified"}`. One gap per (hop, chain, reason) triple, sorted by hop then chain then reason.
- Sorting: rows in `chains[]` order (stable, declared order — NOT alpha); gaps sorted as above.

- [ ] **Step 1: Failing tests** — table for a 2-chain model with one partial assumption entry (nulls pinned); gap (a) fires once for the undeclared chain; gap (b) fires for declared-but-empty finality; duplicate BRIDGES relations dedupe to one gap row; model with NO `chain_assumptions` key ⇒ rows all-null + one gap per touched chain; model with NO relations ⇒ zero gaps.
- [ ] **Step 2: Run** — `GOCACHE=$PWD/.gocache go test ./internal/protocolgraph/ -run TestAssumption -count=1`, expect FAIL (undefined function).
- [ ] **Step 3: Implement** — pure function, no IO, no campaign handle. Reuse the package's `validation.Value` helpers (`objAt`, `listAt`, `orStr`) — read their real names/signatures from `internal/protocolgraph/protocolgraph.go` before writing (they exist: `ActorByID` uses them).
- [ ] **Step 4: Run** — focused green + full `./internal/protocolgraph/` + `go test ./...` once + `scripts/golden.sh` untouched.
- [ ] **Step 5: Commit** — `git add internal/protocolgraph/assumptions.go internal/protocolgraph/assumptions_test.go && git commit -m "feat(G10): per-hop assumption projection — declared table + two mechanical gap rules, legacy renders nulls"`

---

### Task 3: G10 archetypes — two structidx predicates + YAML + schema + fixtures

**Files:**
- Modify: `internal/archetypes/evaluate.go` (two new check types in `checkTypes` + `checkKeys` + evaluator functions)
- Modify: `assets/schema/archetype.schema.json` (two new `oneOf` check variants mirroring the existing style)
- Create: `assets/archetypes/signature-no-separator.yaml`, `assets/archetypes/proof-accepted-without-depth-gate.yaml`
- Create: fixtures under `internal/archetypes/testdata/` following the EXISTING pair convention (read how current archetype tests lay out buggy/clean fixtures before inventing paths)
- Modify (task-scoped pins, allowed): none expected — visibility is dynamic glob (`AvailableArchetypes`), no registry list. If any test pins the archetype COUNT, update it surgically and say so in the report.
- Modify: `assets/testdata/asset_manifest.json` (regenerated — two new embedded YAMLs)
- Consumes: structidx function nodes carry `selector` (`name + "(" + paramTypes + ")"` for external/public, parser.go) — NO parser changes in this task.
- Produces: archetype ids `signature-no-separator`, `proof-accepted-without-depth-gate` with `playbook_hint: bridge-message`; check-type names locked below for Task 9's plant-check reuse.

**Check type 1 — `sig_verify_no_separator`** (evaluator reads structidx `function` nodes):
params: `name_pattern` (regex string, required), `separator_markers` (optional string list, default `["chainid", "chainId", "domainSeparator", "domain_separator", "DOMAIN_SEPARATOR"]`).
Match rule: node name matches `name_pattern` AND the lowercase `selector` contains NONE of the lowercase markers. (Case-insensitive compare is the whole trick — `ChainId` in code matches.)
YAML (`signature-no-separator.yaml`):
```yaml
id: signature-no-separator
name: Signature verified without chain or domain separator
criticality: high
description: >
  A signature-verification entry point whose parameter list carries no
  chain-id or domain-separator argument. Cross-chain, the same signature
  verifies on every chain — the Nomad/Harmony-shape replay assumption gap.
checks:
  - type: sig_verify_no_separator
    names: ["verify", "recover", "checkSign", "isValidSignature"]
    playbook_hint: bridge-message
```
Wait — discriminator keys: existing check objects use per-type keys (`names:` in `unguarded_function_exists`). New check objects must use THE SAME convention: `names` (list of substrings matched against function names — read how `unguarded_function_exists` consumes `names` in evaluate.go and mirror it exactly; `name_pattern` above is then implemented as any-of-substrings, NOT a regex — simpler and consistent). Separator markers: hardcode the default list in the evaluator (documented in the code comment); a check-level override key is YAGNI — do not add one.

**Check type 2 — `merkle_verify_without_depth_gate`**:
Match rule: function name contains any of `names` (default in YAML: `["verifyProof", "processProof", "relayRoot", "submitRoot", "proveWithdrawal"]`) AND `selector` has no depth marker (hardcoded list: `["confir", "final", "depth", "checkpoint", "epoch", "finalized"]`, lowercase-contains) AND `reads_storage` has no entry containing a depth marker. (A depth marker in either place = the code gates on finality somewhere = no hit.)
`criticality: high`, `playbook_hint: bridge-message`.

- [ ] **Step 1: Failing tests** — for EACH check type: buggy fixture hits (pin `finding` id/file/line), clean fixture misses. Fixture pairs: `testdata/sigverify/{buggy,clean}.sol` (buggy: `verify(bytes signature, address signer)` with ecrecover and no chainId; clean: same + `uint256 chainId` param + `require(chainId == block.chainid)`), `testdata/merkleproof/{buggy,clean}.sol` (buggy: `verifyProof(bytes32[] proof, bytes32 root)` setting `accepted[root]=true` with no depth state; clean: requires `confirmations[root] >= minConf`). Also: schema rejects a check object with an unknown `type` string (negative); `AvailableArchetypes()` includes both new ids (glob proof).
- [ ] **Step 2: Run** — `GOCACHE=$PWD/.gocache go test ./internal/archetypes/ -count=1`, expect FAIL (unknown check types).
- [ ] **Step 3: Implement** — evaluator functions beside the existing ones; `checkTypes` + `checkKeys` additions; schema `oneOf` variants (copy the `unguarded_function_exists` variant block shape); the two YAMLs verbatim above (with `names` lists as written); manifest sync.
- [ ] **Step 4: Run** — focused + `go test ./assets/ ./internal/archetypes/ -count=1` + full `./...` once + `scripts/golden.sh` untouched. Also `go run ./cmd/webv2 prescreen` smoke? Only if a prescreen CLI test pattern already exists for ad-hoc runs — do not invent new CLI surface (prescreen consumes the new YAMLs automatically via glob).
- [ ] **Step 5: Commit** — stage the six paths + manifest; message `feat(G10): signature-no-separator + proof-without-depth predicates — structidx selector evidence, no parser changes`

---

### Task 4: G10 table rendering — `brief` + report assumption tables (presence-gated)

**Files:**
- Modify: `internal/briefing/briefing.go` (assumption table block — find the economics/projection area; the brief reads `artifacts/protocol_model.json` via `validation.ReadJson` at ~:1674)
- Modify: `internal/report/report.go` (same table in the model/protocol area — reuse one builder: put the line-builder in `internal/protocolgraph` as `func RenderAssumptionLines(rows, gaps []validation.Value) []string` so brief AND report share bytes; Task 2's function feeds it)
- Create/extend: briefing + report tests pinning exact lines
- Consumes: `AssumptionTable` (Task 2).
- Produces: golden-visible rendering law (absent ⇒ zero bytes).

**Line format (exact):**
- Per row: `- <chain>: finality=<v|declared: none> confirmations=<n|declared: none> messenger=<v|declared: none> separator=<v|declared: none>` (only these four columns — validator_set/threshold stay in the projection for future use, not in the line; say so in the code comment).
- Per gap: `- ASSUMPTION GAP <hop> <chain>: <missing-assumptions|finality-unspecified>` (reason rendered verbatim).
- Presence gate: the whole block (header + lines) renders ONLY when the model carries a `chain_assumptions` key OR a `chains` list longer than... NO — simpler honest rule: render when `len(rows) > 0 AND (any row has a non-null detail OR len(gaps) > 0)`; a chains-only legacy model (`chains: ["mainnet"]`, no assumptions, no BRIDGES relations ⇒ zero gaps) renders NOTHING. Golden campaigns are chains-only ⇒ untouched bytes.

- [ ] **Step 1: Failing tests** — briefing: legacy chains-only model ⇒ block absent (byte walk); assumed model ⇒ exact lines pinned; gap line pinned. Report: same three via its renderer. Shared-builder test: null detail ⇒ `declared: none` in each column.
- [ ] **Step 2: Run** — expect FAIL (no builder).
- [ ] **Step 3: Implement** — `RenderAssumptionLines` in protocolgraph (string building only, no IO); wire into both renderers behind the gate.
- [ ] **Step 4: Run** — focused suites + full `./...` + `scripts/golden.sh` untouched-green (plus open the golden campaign's report/brief excerpts and confirm no assumption bytes — evidence in the task report).
- [ ] **Step 5: Commit** — `feat(G10): assumption tables in brief + report — chains-only legacy models render nothing`

---

### Task 5: G9 taxonomy — two new canonical classes (`frontend-injection`, `infra-boundary`)

**Files:**
- Modify: `internal/taxonomy/taxonomy.go` (`defaultCompatClasses` += both, in alpha position)
- Modify: `internal/findings/levels.go` (class→E-level map: both are offchain finding families — assign the floor the map uses for non-contract classes; read the map: if `bridge-message`-style scenario classes carry a specific floor, mirror THAT row's floor value, do not invent a new one. Also `CROSS_CHAIN_E6_CLASSES`-style sets are meaning-specific — do NOT add the new classes there.)
- Modify: `assets/taxonomy/class_weights.json` (+2 rows, all three weights neutral 1.0, `search: 1.0`; provenance rows honest: source = the research docs? NO — provenance must be a URL or the literal `"taxonomy: canonical class addition (G9)"`. Never cite the untracked root `.md` files — they are not committed and not fetchable. Use the canonical-addition literal.)
- Modify: `internal/cli/cmd_ingest_test.go` (`t14FindingLegend` walk-order pin += both classes in the class row's position)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)
- Consumes: nothing (independent of T1–T4 — may run parallel with them).
- Produces: classes `frontend-injection`, `infra-boundary` resolvable everywhere a class resolves (ingest intake, dedup, gates, weights reader); required by Tasks 6–7 (playbook `bug_class` linkage + fixture findings).

**Class semantics (one line each, also the report-facing gloss):**
- `frontend-injection`: attacker-controlled content or approval flow in the dapp frontend / pairing surface that moves user funds or signatures (DOM-XSS sinks, permit phishing, pairing-URI phishing, extension supply chain).
- `infra-boundary`: trust-boundary failure in the offchain estate the protocol depends on (DNSSEC/CAA, subdomain takeover, deploy-path/CI compromise, upgrade-multisig ops).

- [ ] **Step 1: Failing tests** — ingest accepts both classes (no taxonomy advisory); legend pin test green AFTER the pin edit (run pre-edit to prove it fails first); weights loader returns both rows (neutral); `Alias()` returns (nil,false) for both (no standard mapping invented — G12 honesty); drift test (`keys ⊆ CanonicalClasses ∪ {unmapped}` from the T5-era suite) stays green.
- [ ] **Step 2: Run** — `GOCACHE=$PWD/.gocache go test ./internal/cli/ -run Legend -count=1` expect FAIL pre-pin; implement; re-run green.
- [ ] **Step 3: Implement** — the five edits above; canonical-addition provenance literal; floor mirror (quote which row you mirrored in the task report).
- [ ] **Step 4: Run** — `go test ./internal/taxonomy/ ./internal/findings/ ./internal/classweights/ ./internal/cli/ ./assets/ -count=1` + full `./...` + `scripts/golden.sh` untouched.
- [ ] **Step 5: Commit** — stage all six paths; message `feat(G9): frontend-injection + infra-boundary join the canonical classes — floor mirrored, legend pinned, weights neutral`

---

### Task 6: G9 components flow — opaque-surface rendering + component finding end-to-end

**Files:**
- Modify: `internal/briefing/briefing.go` + `internal/report/report.go` (components block: `tracked-but-opaque surfaces` — per component line `- <kind> <path|url>: <in_scope|out-of-scope><, paid>`)
- Modify: `internal/planner` (plan render: components listed as tracked surfaces in the plan view — find the plan's surface/coverage section at edit time; presence-gated same as Task 4)
- Create: `internal/findings/components_e2e_test.go` (fixture campaign: model with one frontend component + one `frontend-injection` finding anchored `app/swap.html` with the pinned-tree hash — full ingest → gate dry-run → report excerpt assertions)
- Consumes: Task 1 shape, Task 5 classes.
- Produces: proof that component findings flow through dedup/gate/report like contract findings (the doc's test clause).

**Laws:**
- `structidx` NEVER indexes component paths (opaque to structidx — assert in a test: index builder skips non-`.sol`? NO — snapshot hashes everything (scout: no .sol filter) but the INDEX is the solidity parser; assert that prescreen over a component-only tree yields zero archetype hits, pinning "never pretended-over").
- Snapshot pins the frontend subtree (proof: pin a fixture `app/` tree, cite file+hash in the finding's affected anchor, assert the pinned content hash equals the cited hash).
- Paid-for join: `paid_for: true` components' classes are eligible for G3 priors; `paid_for: false` ⇒ `Fallback` side (read how `AcceptancePriorsFrom` treats unknown classes — the fallback behavior is the law; assert it, do not change it).

- [ ] **Step 1: Failing tests** — render lines pinned (scope/paid variants); e2e fixture (ingest ok, gate dry-run CONFIRMED-eligible, report excerpt contains the component line + finding); prescreen-over-components yields zero hits; paid/unpaid prior-path assertions.
- [ ] **Step 2: Run** — expect FAIL (no renderer).
- [ ] **Step 3: Implement** — renderers + presence gates (block renders iff `components` key present AND non-empty); no model writer changes (CLI `model` passes the doc through validation already — verify this claim in code: `orchestrator.LoadProtocolModel` → `SaveModel` validates? If it does NOT validate, add validation at that seam and say so).
- [ ] **Step 4: Run** — focused + full + golden untouched.
- [ ] **Step 5: Commit** — `feat(G9): components render as tracked-but-opaque — component findings flow end-to-end, structidx never pretends over them`

---

### Task 7: G9 playbooks — `frontend-injection` + `infra-boundary` YAML (data only)

**Files:**
- Create: `assets/playbooks/frontend-injection.yaml`, `assets/playbooks/infra-boundary.yaml`
- Modify (task-scoped pins): `internal/playbooks/playbooks_test.go:58` (`TestAvailablePlaybooksAreExactlyTheShippedEight` — eight → ten) + `internal/playbooks/sweep_t35_test.go:58` (`TestAllPlaybooksAreListed` — same count update IF it pins eight; read both before touching)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)
- Consumes: Task 5 (`bug_class` values must be canonical — the schema + `playbooks.go:153` filename-stem rule enforce it).
- Produces: two lint-clean playbooks loadable via `PlaybookForClass`.

**Schema (playbook.schema.json required: `bug_class,title,description,invariants,assumption_templates,hunt_order`; `bug_class` regex `^[a-z0-9-]{3,64}$`; filename stem MUST equal `bug_class`):**
- `frontend-injection.yaml`: `bug_class: frontend-injection`; invariants (3–5, e.g. "every external approval request names the exact spender + amount cap", "pairing URIs are origin-bound", "no inline third-party scripts on signing pages"); assumption_templates (untrusted DOM, malicious extension, lookalike domain); hunt_order (approve/permit flows → pairing → supply chain).
- `infra-boundary.yaml`: `bug_class: infra-boundary`; invariants (DNSSEC+CAA on the dapp domain, no dangling DNS on protocol subdomains, deploy pipeline requires multisig sign-off, upgrade keys in cold multisig); assumption_templates (registrar compromise, CI runner compromise); hunt_order (DNS → deploy path → key custody).
- Class links into the taxonomy = the `bug_class` field itself (that IS the link — findings on components with these classes hit `PlaybookForClass` like contract findings; assert exactly that in tests). NO scanners, NO check types, NO code — YAML data only.

- [ ] **Step 1: Failing tests** — `PlaybookForClass("frontend-injection")` found + validates; same for `infra-boundary`; count-pin tests updated eight→ten AND passing; every shipped playbook still validates (`TestShippedPlaybooksLoadAndValidate`).
- [ ] **Step 2: Run** — expect FAIL (files missing).
- [ ] **Step 3: Write the YAMLs** — follow an existing small playbook's shape field-for-field (read `assets/playbooks/precision-rounding.yaml` fully first — mirror its key order and list styles).
- [ ] **Step 4: Run** — focused + `go test ./internal/playbooks/ ./assets/ -count=1` + full + golden untouched + manifest sync.
- [ ] **Step 5: Commit** — `feat(G9): frontend-injection + infra-boundary playbooks — data only, zero surface cost`

---

### Task 8: G11 post-patch verdict — `verify --post-patch`, record, report side

**Files:**
- Modify: `internal/cli/cmd_verify.go` (new `--post-patch FINDING --exec EXEC [--snapshot SID]` flag trio on the EXISTING verb; dispatch branch beside `:367` harness branch)
- Create: `internal/reproduction/postpatch.go` — `func PostPatchVerdict(c *state.Campaign, findingID, newExecID string) (verdict string, detail string, err error)` returning verdict ∈ `{"still_reproducible", "fixed", "indeterminate"}`
- Create: `internal/reproduction/postpatch_test.go` + CLI tests in `internal/cli/`
- Modify: `internal/report/report.go` (regression line beside the immunize clause at :2124 — presence-gated on the record)
- Consumes: evidence items carry the original repro exec link (MintReproEvidence wrote it — follow the existing evidence path at edit time: the exec id + its recorded stdout hash live in the exec record / `artifact_hashes["stdout.log"]`, the same ledger hash G15's rerun comparison used).
- Produces: `verification.patch_regression` record `{verdict, exec, base_exec}` on the finding + report line; consumed by Task 9 (scope rows append to the detail).

**Verdict law (exact):**
- Load the NEW exec record (`execs/<id>/exec_record.json` via the sandbox reader the harness path uses) and the ORIGINAL repro exec (from the finding's minted evidence; if the finding has NO minted repro evidence ⇒ `indeterminate`, detail `"no baseline repro exec on the finding"`).
- `still_reproducible`: new exit == 0 AND original exit == 0 AND stdout hashes equal.
- `fixed`: original exit == 0 AND new exit != 0.
- `indeterminate`: everything else (new exit 0 with different stdout; original non-zero; timeout markers; missing stdout file).
- Missing `--exec` with `--post-patch` ⇒ exit 2 usage error naming the flag. Unknown finding/exec ids ⇒ exit 2 naming the id (same `PyReprStr` style the harness path uses). `--snapshot` is ACCEPTED but only recorded (stored on the record as `snapshot`, advisory scope note) — the tree comparison is Task 9; say so in `--help` text.
- Fail-open: the verdict NEVER changes finding status, NEVER blocks anything; it is metadata + a report line. (Promotion rides triage reading the record, same law as harness rungs.)

**Report line (beside :2124 immunize clause, presence-gated):**
`- patch regression: <**FIXED**|**STILL REPRODUCIBLE**|**INDETERMINATE**> (<base_exec> → <exec>)` + second line `- <detail>` when detail non-empty.

- [ ] **Step 1: Failing tests** — verdict table (all three verdicts + no-baseline case via real exec-record fixtures — read how `cmd_verify_harness` tests seed exec dirs and reuse the builder); CLI exit-2 matrix (missing --exec, unknown ids); report line pins (all three labels); status-untouched assertion (finding status byte-identical pre/post).
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** — `PostPatchVerdict` pure-ish (reads campaign store + exec dirs, writes nothing); CLI branch writes `verification.patch_regression` via the same finding-save path immunize uses (`findings.SaveFinding`); report line.
- [ ] **Step 4: Run** — focused (`./internal/reproduction/ ./internal/cli/ ./internal/report/`) + full + golden untouched.
- [ ] **Step 5: Commit** — `feat(G11): verify --post-patch verdict — the fix gets proven, not just recorded (fail-open, status never moves)`

---

### Task 9: G11 scope — changed-surface diff + clean-control plant check

**Files:**
- Modify: `internal/reproduction/postpatch.go` (extend: `ScopeDiff(oldSnapshotDir, newSnapshotDir string) ([]string, error)` + plant-check entry `PlantCheck(c, changedFiles []string) ([]string, error)` — or a second file `postpatch_scope.go` if the first grows past ~300 lines; implementer's call, reviewer checks cohesion)
- Extend: `internal/reproduction/postpatch_test.go`, CLI test (detail lines)
- Consumes: Task 8 record shape (scope rows append into `detail` / a `scope` key on the record — additive fields only).
- Produces: advisory scope output; nothing else consumes it.

**Scope diff (pure file-set math):**
- Read both snapshot trees' fingerprints via `forkdiff.FingerprintTree` (exists, :73) and extract the file→hash mapping from the returned Value (read its shape at edit time — it carries per-file hashes; if the shape does not expose a clean map, compare `FingerprintSha256` per... NO — do NOT hash per file yourself; read the fp Value's file list properly. If genuinely unextractable, report BLOCKED with the exact shape — do not invent a parallel hasher.)
- Rows: `~ <path>` modified, `+ <path>` added, `- <path>` removed, sorted; capped at 50 rows + `… and N more` (bounded output law — a vendored-deps patch must not flood the record).
- Record gains `scope_roots: ["<old-sid>", "<new-sid>"]`-ish keys? NO — keep the Task 8 record shape; scope rows ride the `detail` string (newline-joined, capped). Simpler, no schema drift.

**Plant check (hint-only):**
- Run the archetype evaluators over the CHANGED files only: build a structidx index over the NEW snapshot dir (reuse the campaign's index builder — read how prescreen builds `idx` from a snapshot root at `prescreen.go:56-63`), evaluate ALL available archetypes (Task 3's included), keep hits whose `path` is in the changed set.
- Any hit ⇒ detail row `patch plants risk: <archetype-id> <path>:<line> (hint-only — triage decides)`; zero hits ⇒ detail row `patch plants nothing new (N files checked)`.
- Deterministic: archetype order = `AvailableArchetypes()` order (already sorted? verify — if not, sort).

- [ ] **Step 1: Failing tests** — fixture snapshot pair (3-file buggy tree → patched tree with 1 modified + 1 added + 1 removed): exact `~/+/-` rows pinned + cap behavior (51-change fixture ⇒ 50 rows + overflow line); plant check: patched tree that introduces an unguarded `initialize` ⇒ `proof-accepted...`/unguarded-initialize hit row; clean patch ⇒ `plants nothing new (N files checked)`; fp-Value-shape-mismatch ⇒ BLOCKED honest path exists (test the error return with a garbage dir).
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** — per above; cap constant `postPatchScopeCap = 50`.
- [ ] **Step 4: Run** — focused + full + golden untouched. NOTE: prescreen over test trees must not require docker (structidx is pure — assert no exec mocking needed).
- [ ] **Step 5: Commit** — `feat(G11): post-patch scope diff + plant check — the patch must not plant anything (advisory rows, capped)`

---

### Task 10: tranche close-out — docs, statuses, full gates

**Files:** `assets/runbook/RUNBOOK.md` (modify), `docs/IMPROVEMENTS.md` (modify), full gates.

- [ ] **Step 1: Runbook** — legend rows: `webv2 verify` gains `--post-patch FINDING --exec E [--snapshot S]`; new block after the tranche-2 paragraph covering: assumption tables (declared-vs-gap, `declared: none` rule), `components[]` (tracked-but-opaque, structidx never indexes them), the two new classes + two playbooks (data-only, findings arrive as model findings), `--post-patch` verdicts (still_reproducible/fixed/indeterminate; fail-open; scope cap 50). Every command named must already exist (verify flag spellings against `cmd_verify.go` usage text). Manifest sync + `scripts/runbook-walkthrough.sh` green.
- [ ] **Step 2: IMPROVEMENTS statuses** — G9/G10/G11 → LANDED (tranche 3, date) in the table rows, same one-line style as tranche 2 (include the honest caveats: chains[] stays strings with sidecar `chain_assumptions`; new classes carry no OWASP aliases by design; post-patch verdicts are advisory). Header line (`Date:`) updated: tranches 1–3 LANDED, nothing remains PROPOSED except the G19+ backlog pointer if one exists.
- [ ] **Step 3: Full gates, in order** — commit EVERYTHING first (double-run determinism: no edits between run1/run2), then `GOCACHE=$PWD/.gocache go vet ./...`; `go test ./... -count=1`; `scripts/golden.sh`; `scripts/runbook-walkthrough.sh`; `scripts/verify-full.sh` (13 steps); `go run ./cmd/webv2 selftest --full`.
- [ ] **Step 4: Commit** — `git add assets/runbook docs/IMPROVEMENTS.md && git commit -m "docs(G): tranche 3 close-out — runbook blocks, G9/G10/G11 LANDED"` (manifest already staged in its task commits; if the sync in Step 1 dirties it, stage it here too).

---

## Plan Self-Review

1. **Spec coverage:** G10 schema→T1, projection→T2, predicates→T3, rendering→T4. G9 classes→T5, components flow→T6, playbooks→T7. G11 verdict→T8, scope→T9. Close-out→T10. Every design bullet in the three doc entries maps: G10's "gold fixtures ride G4's cross-chain replay scenario" is covered by T3's instruction to assert ES14-shape trips ONLY if shapes match (honest conditional — no fake fixture coupling); G9's snapshot/tree-hash promise is covered by T6's pin-proof test; G9's "per-component priors join G3's table only where paid" is covered by T6's paid/unpaid fallback assertions (read-only — no priors change); G11's (a)(b)(c) map to T8/T9/T9.
2. **No placeholders:** every task names exact files, exact function signatures, exact JSON shapes, exact commands with expected outputs, exact commit messages. The two SEARCH-AND-MIRROR points (package test-helper names, evidence-exec link path) name the sibling to copy — acceptable: the sibling file:line is given.
3. **Type consistency:** `AssumptionTable(model)(rows,gaps)` → `RenderAssumptionLines(rows,gaps)` (T2→T4) — names locked. Check-type names `sig_verify_no_separator` / `merkle_verify_without_depth_gate` with `names` list convention (T3→T9) — locked. Record `verification.patch_regression{verdict,exec,base_exec}` with detail-carried scope rows (T8→T9) — locked. `components[]`/`chain_assumptions[]` shapes (T1→T2/T4/T6) — locked verbatim. New classes `frontend-injection`/`infra-boundary` (T5→T6/T7) — locked.
4. **Byte-risk register:** T1 (schema-only, no campaign bytes); T4/T6 renderers (presence gates; golden campaigns are chains-only/components-free — T4's gate explicitly excludes zero-gap chains-only models); T5 (class vocabulary + legend pin — ingest legend test is the tripwire, pin updated in-task); T7 (count pins eight→ten — task-scoped test literals, allowed); T8/T9 (new flag + record on findings that golden never post-patches). Any other move ⇒ BLOCKED, report, never edit fixtures.
5. **Non-goal guard:** no scanner code (T7 YAML only; T9 reuses the existing prescreen evaluator — no new detection logic beyond T3's two structidx checks, which are hypothesis pre-screens, hint-only); no consensus/p2p code (finality is a stored string, never evaluated against a chain); no benchmark/standard writing (OWASP untouched; no new classes beyond the two G9 families).


