# Wave L-defer: Validate wiring, template completion, witness fidelity, refusal histograms Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the wave L-system deferrals: enforce the scaffold byte-law on the run path (Validate wiring), complete the faithful template set, make bridged witnesses fork-faithful (msg.value + final_assertions), and render per-campaign refusal histograms (L3 full form, derived).

**Architecture:** Every landing rides already-built seams: `harness.Validate(k, inv, filled)` exists and is wired INTO the existing Decision-2b violation rail in `verify --harness-result`; templates are data faithful to vendored corpus specs; witness fidelity extends `BridgeSequence` + the `sequence_poc` schema + the sequence-run executor; histograms are pure audit derivation from stored links records — zero new event types, zero new verbs, zero new campaign state.

**Tech Stack:** Go stdlib + internal/validation; embedded .tmpl assets; one operator-collected data artifact (scorecard run, done by the CONTROLLER outside tasks).

## Global Constraints

- Golden sacred: no existing campaign bytes move. T1 is a deliberate TIGHTENING (tamper path was latent/unenforced — no existing test or campaign exercises it; golden campaign does not tamper).
- `GOCACHE=$PWD/.gocache` everywhere; `go vet ./...` clean; gofmt touched-empty; embedded-asset edits ⇒ `python3 scripts/sync-asset-manifest.py` in-commit; prompts NEVER touched.
- No new CLI verbs/flags this wave (statement syntax + schema + derivation only).
- Schema law: sequence_poc step `value` key, if added, must be OPTIONAL (older specs stay valid) and `final_assertions` translation must never invent assertions from symbolic values — concrete-only, skip-with-none emitted otherwise.
- Fail-open + derived-rendering laws as ever; histograms are rendering, not state.
- Tests: table-driven, byte-pinned, no skips/sleeps/child-processes.
- Model directive: implementers `b-ai/deepseek-v4.1-flash`, reviewers `b-ai/glm-5.3-flash`; explicit `git add` paths only (LEARNINGS.md holds a foreign writer's uncommitted lines).
- Commits: `feat|fix|test(audit|harness|assets|cli): … (L-defer, n/5)`.

### Task 1: Wire `harness.Validate` into the run path (deferral #1)

**Files:** Modify `internal/cli/cmd_verify_harness.go` (the bound-violation rail region ~:395-430 — read it first), add rows to `internal/cli/cmd_verify_harness_test.go` (+ `cmd_verify_minicertora_test.go` one row); test helper bytes for a degraded artifact may reuse `harness.DescribeScaffoldLine` (exists).
**Interfaces:** Consumes `harness.Validate(k Kind, inv validation.Value, filled []byte) error` (harness.go:289) and the existing INV entry + on-disk harness-file bytes the hash-bind step already reads. Produces: a new refusal arm in the same Decision-2b rail: `scaffold-degraded: <describeScaffoldLine reason>` → rung inconclusive, output NOT used, no proof (minicertora) — mirror the hash-differs arm exactly.
- [ ] Step 1 RED: rows — (a) halmos rec with correct hashes but the CURRENT INV entry has drifted so re-render differs from the on-disk harness file (statement edit after exec: `verify --scaffold` untouched file) → inconclusive refusal text pinned, event recorded, exit 0; (b) same drift but only the BODY window moved (model tuning) → maps NORMALLY (Validate passes; pin that Validate does not fire on in-window edits); (c) minicertora `.mspec` out-of-window claim change → refusal; (d) untampered flows byte-unchanged (existing rows green).
- [ ] Step 2: implement at the single place where harness bytes are already loaded; failure order: hash-bind first, then Validate (document why: hash proves WHICH bytes ran; Validate proves those bytes match the CURRENT claim — both are needed and they refuse differently).
- [ ] Step 3 battery: cli+harness+audit tests; `go vet`; golden gate via the SAME lock-safe procedure (pgrep '[g]olden-run' first) must stay GOLDEN GREEN. Commit `feat(cli): scaffold Validate enforced on the harness-result path (L-defer, 1/5)`.

### Task 2: Complete the faithful template set (deferral #2)

**Files:** Create `internal/harness/templates/{privilege-escalation,unchecked-callback,value-transfer-accounting}.tmpl`; Modify `templates.go` names list, `templates_test.go` byte pins, `mspec_test.go` rows, RUNBOOK template-names sentence (resync manifest).
- [ ] Bodies EXCLUSIVELY adapted from the vendored corpus specs: `internal/harness/testdata/minicertora-corpus/` — privilege-escalation (`no_privilege_escalation.mspec`), unchecked-callback (`ledger.mspec`), and value-transfer-accounting from payable-check-missing (`withdraw_keeps_accounting.mspec`); same knob discipline as the shipped four (name/Contract/Function only), same disclosed adaptation class (baked state identifiers ride the archetype; seeds not evidence).
- [ ] Doc truth: donation-accounting and cap-respected from the architecture list have NO corpus ground-truth spec (cap-respected rides the `invariant:` form instead) — one sentence in the RUNBOOK names the seven shipped template names + these two dispositions honestly.
- [ ] RED/GREEN byte pins per new template + fall-through unchanged; commit `feat(harness): three more corpus-faithful sweep templates (L-defer, 2/5)`.

### Task 3: Witness fork-fidelity — msg.value rides (deferral #3a)

**Files:** Modify `assets/schema/sequence_poc.schema.json` (step gains optional `"value": {"type":"string","pattern":"^(0x[0-9a-fA-F]{1,64}|[0-9]+)$"}`, description: wei literal; absent = zero or unstated — READ what the tool's `_pretty` emits for env msg.value FIRST (minicertora cli.py, read-only) and pin the pattern to what can actually be parsed; if the tool emits pretty forms like `1 ether`, translate ONLY exact parseable forms and REFUSE the line otherwise (never round silently)); `internal/harness/witness.go` (bridge: `env["msg.value"]` → step `value` when present/concrete; absent/zero → omit; unparseable → refusal `unbridgable step: <n> value <raw> not a wei literal`); the sequence-run executor (find it: `rg -ln 'steps' internal/cli/cmd_sequence*.go internal/sequencepoc/`) — thread value into the call it issues (if the executor builds calldata/tx fields, value is the natural tx field — smallest diff); tests each side + schema accept/reject rows; manifest resync.
- [ ] RED first; battery cli+harness+validation+assets; commit `feat(assets): sequence_poc steps carry wei value; witness bridge and executor honor it (L-defer, 3/5)`.

### Task 4: final_assertions from witness storage (deferral #3b)

AMENDED by controller pre-dispatch (facts): sequencepoc REQUIRES kind storage assertions to carry target(0x)+slot(NUMBER) (sequencepoc.go:253-255) and the driver reads by slot (driver.go:318) — but the tool's final_storage gives variable NAMES; name→slot needs a solc storage-layout map that the harness does not own. Landing = pure translation with an explicit layout parameter (fork wave supplies the map; absent name => assertion SKIPPED, never guessed). Keep the existing BridgeSequence signature BEHAVING EXACTLY AS TODAY (emits empty final_assertions) and ADD `BridgeSequenceWithLayout(obj, specID, findingID, layout map[string]string) (validation.Value, string)` delegating to the shared core; layout maps "<Contract>.<var>"→slot digits; also target(0x...) needed per assertion — contract address comes from layout map's companion or the assertion is skipped when the bridged step for that contract has a known target address (reuse the step's target when the state variable's owning contract == that target's contract name; document the derivation precisely in the docstring).

**Files:** Modify `internal/harness/witness.go` (BridgeSequenceWithLayout: `{"id":"A1","kind":"storage","target":<contract addr or refusal>,"account"?...}` — READ the schema's storage assertion keys EXACTLY (assets/schema/sequence_poc.schema.json final_assertions items: id/kind/op/value + target/account/slot fields — copy the real required set); ids A1..An in sorted-slot order; symbolic/pretty values → that assertion SKIPPED (and if ANY skipped, keep the emitted subset honest: docstring line `n of m`); op is `==` (observed final value), values wei/hex-literal pattern per schema.
- [ ] RED/GREEN byte pins (happy: two concrete slots → two assertions; mixed: one symbolic → skipped; all symbolic → empty array + no refusal). Executor: does sequence run already evaluate final_assertions? (`rg final_assertions internal/` — if it validates them post-run, confirm storage kind support exists; if not supported, the emitted assertions still ride as spec — pin ONE executor test proving an unsupported kind is refused LOUDLY not silently ignored). Commit `feat(harness): bridged PoCs carry concrete final-storage assertions (L-defer, 4/5)`.

### Task 5: Refusal histograms — L3 full form, derived (deferral #4)

**Files:** Modify `internal/audit/sections/invariantverification.go` (or a new sections file if the existing one is crowded — judge) — after the harness lines section, ONE derived line: `prover refusals (minicertora): <total> — <class>:<count>[, ...] sorted by count then class, top reason codes (<=3): <code>×<n>` computed by walking the campaign's stored verification.harness records (kind minicertora, rung inconclusive, proof.reason or summary-parsed reason — proof.reason exists since L-core: USE it, fall back to Disposition(summary) mapping via harness.Disposition which sections already imports). Test byte rows: 2 packed-storage + 1 loop-bound campaign; halmos-only campaign emits NOTHING (presence-gated); no-refusal minicertora campaign emits nothing.
- [ ] Commit `feat(audit): per-campaign prover refusal histogram from proof reasons (L-defer, 5/5)`.

### Task 6: Close-out

Docs: IMPROVEMENTS Wave L-system deferrals queue — mark #1,#2,#3,#4 CLOSED with commits, keep #5/6 (tier-2 pin, runtime surfacing) with one-line reasons; MINICERTORA_ARCHITECTURE landing notes extended; RUNBOOK template sentence if T2 changed names list (already in T2). Full battery order incl golden (lock-safe) + walkthrough + selftest + scorecard self-test. Commit `docs: wave L-defer close-out`.

## Self-Review

Coverage: deferrals #1→T1, #2→T2, #3→T3+T4, #4→T5; the real scorecard run = controller background job feeding T6 evidence; remaining known-deferred after this wave: template runtime-state-identifier surfacing, scorecard tier-2 exercise, operator-gate law remains (a local data run ≠ gate move). Type consistency: `harness.Validate` fixed signature; BridgeSequence keeps its signature (returns richer docs); histograms read `proof.reason` string keys as stored.
