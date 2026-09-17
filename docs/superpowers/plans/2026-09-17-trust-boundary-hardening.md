# Production Readiness Implementation Plan (v2 — full scope)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every verified integrity gap and the operator-friction and discovery-doctrine gaps from the C-7f1005ecd5 evaluation, so the framework is production-ready by its own gates — not "flawless" (unknowable), but fully enforced: every status the record can carry is true, every doctrine the prompts preach is a gate, and the cockpit surfaces risk instead of comfort.

**Architecture:** Four phases. Phase A (Tasks 1-4) fixes verified trust-boundary defects at their shared root (parser, record labels, model gate, evidence relevance). Phase B (Tasks 5-9) removes the bookkeeping friction that cost the operator real rounds. Phase C (Tasks 10-12) makes the cockpit enforce coverage of what should be claimed, not just honesty of what was claimed. Phase D (Tasks 13-15) is supply-chain and threat-model hygiene. Every task is TDD with red-green evidence and an independent review.

**Tech Stack:** Go 1.26.2, stdlib, existing four direct dependencies; no new dependencies in any phase.

## Global Constraints

- Implementer subagents: `b-ai` provider, model `deepseek-v4.1-flash`, dispatched via workflow `agent()` overrides (plain subagent has no model param). Reviewer subagents: session default (`opencode-go-anthropic/union-alpha`), explicitly requested by the operator.
- Worktree consent is an OPERATOR decision made BEFORE the first dispatch — the orchestrator asks once and passes the answer to every subagent; implementer subagents never ask. Declined → feature branch in place. Never on main.
- No new dependencies, no new status enum, no new scheduler. Reuse `RegisterOrRefresh`, `profileFilesystemLabel`'s pattern, existing rungs and floors.
- No target-specific detection, no exploit reproduction, no autonomous hunting, no Morph-repo changes.
- MiniProver/MiniCertora stay untouched in v2: no verified defect was found in the mapper (fail-closed) or sandbox profiles. Re-open only with a reproducible defect.
- Evidence floors stay at E3/E4/E6 exactly as today; no "almost-confirmed" rung. Environment-blocked verification is an annotation, never a lower bar.
- Legacy campaigns (scripts/legacy fixture) must keep reading and auditing clean after every task; run the fixture check when state shapes change.
- Golden pins: any task that changes CLI output must run `scripts/golden.sh`, `scripts/runbook-walkthrough.sh`, and `python3 scripts/check-golden.py`; deliberately update pinned expectations in the same commit with the reason in the commit message. Silent pin drift is a review-blocking finding.
- `go vet ./...` and `go test ./... -count=1` green after every task; `go test -race ./internal/state ./internal/sandbox ./internal/harness` for tasks touching concurrency.
- Commit only task-owned files; your 7 pre-existing modified files (LEARNINGS.md, RUNBOOK, asset manifest, docs) are out of bounds for every task. Golden/runbook pin updates are staged by exact path (`git add <pin-file>`), never `git add -A`/`git add .`.
- No score is claimed or promised; the Definition of Done section is the acceptance bar.

---

## Phase A — verified integrity defects (production blockers)

### Task 1: Reject ambiguous duplicate JSON object keys

**Files:**
- Modify: `internal/jval/parse.go` (the `case '{'` branch of `parseValue`)
- Test: `internal/jval/parse_test.go` (create; the package has no test file today)

**Interfaces:**
- Consumes and preserves `ParseOrdered(data []byte) (Value, error)` unchanged in signature and behavior for all valid JSON.
- Produces: a new error path `json: duplicate object key %q`. No new public API.

- [ ] **Step 1: Write the failing tests**

```go
package jval

import (
	"strings"
	"testing"
)

// TestParseOrderedRejectsDuplicateKeys pins the shared-parser law: a JSON
// object carrying the same key twice is refused outright, before any
// consumer's first-match reader can disagree with the schema walker. The
// same key in SEPARATE objects stays valid — the guard is per-object.
func TestParseOrderedRejectsDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"a":1,"a":2}`,
		`{"outer":{"a":1,"a":2}}`,
		`{"a":1,"\u0061":2}`,
		`{"":1,"":2}`,
	} {
		_, err := ParseOrdered([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
			t.Errorf("ParseOrdered(%q): want duplicate-key error, got %v", raw, err)
		}
	}
}

func TestParseOrderedAllowsKeysInSeparateObjects(t *testing.T) {
	v, err := ParseOrdered([]byte(`[{"a":1},{"a":2}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.A) != 2 || v.A[0].O[0].V.I != 1 || v.A[1].O[0].V.I != 2 {
		t.Fatalf("separate objects changed: %#v", v)
	}
}
```

- [ ] **Step 2: Run red** — `go test ./internal/jval -run 'TestParseOrdered' -count=1`. Expected: RejectsDuplicateKeys FAILS (nil error today), AllowsKeysInSeparateObjects PASSES.
- [ ] **Step 3: Implement the guard** — inside `case '{'`, allocate `seen := make(map[string]struct{})` once per object; after the `key, ok := keyTok.(string)` check, before consuming the value:

```go
if _, dup := seen[key]; dup {
	return VNull(), fmt.Errorf("json: duplicate object key %q", key)
}
seen[key] = struct{}{}
```

**Unicode note (verified 2026-09-17):** `encoding/json` fully decodes `\uXXXX` escapes BEFORE the token is handed to the caller — `dec.Token()` for `"\u0061"` returns Go string `"a"` (len 1, `== "a"`), so the `seen` map lookup already operates on the semantic key and no separate `decodeString` helper is needed. The `\u0061` test case guards this exact property; do NOT add a custom unescape step (it would be dead code).

- [ ] **Step 4: Run green** — same command as Step 2, then `gofmt -l internal/jval/` prints nothing, then `go test ./internal/jval ./internal/validation ./internal/harness ./internal/state -count=1`. All pass. Do NOT canonicalize duplicates or weaken a fixture to get green. Then run the legacy fixture check (`go test ./internal/state -run Legacy -count=1` plus `scripts/verify-full.sh` step 9 at task end): if the new refusal breaks a legacy fixture, sanitize the FIXTURE in the same commit — never weaken the gate.
- [ ] **Step 5: Full gates** — `go test ./... -count=1` and `go vet ./...`; record exact outcomes.
- [ ] **Step 6: Commit** — `git add internal/jval/parse.go internal/jval/parse_test.go && git commit -m 'fix(jval): reject duplicate JSON object keys'`
- [ ] **Step 7: Independent review** (union-alpha) of BASE..HEAD: spec compliance, nested scope, escape-sequence aliasing, valid-input preservation.

### Task 2: Honest network labels for host profiles

The r36 F5 fix made the filesystem label honest ("host (unconfined…)") but the network label still claims `"none"` for every host profile while the process has the host's full network. The record must not assert isolation it does not have.

**Files:**
- Modify: `internal/sandbox/profiles.go` (add one helper near `profileFilesystemLabel`'s twin in exec.go — keep both label helpers adjacent)
- Modify: `internal/sandbox/exec.go:1282` (`environmentValue`) and `internal/sandbox/exec.go:1122` (`Preview`)
- Test: `internal/sandbox/exec_test.go` (append)

**Interfaces:**
- Consumes: `HostProfile(profile) bool`, `profileNetwork map[string]string` (unchanged).
- Produces: `networkLabel(profile string) string` — same package; host profiles return `"host (unconfined — nothing enforces network-off)"`; container profiles return `profileNetwork[profile]` verbatim (`"none"`, `"bridge-host-gateway"`).

- [ ] **Step 1: Write the failing tests**

```go
func TestNetworkLabelIsHonestForHostProfiles(t *testing.T) {
	for _, p := range []string{"host-readonly", "halmos", "forge-fuzz", "minicertora"} {
		got := networkLabel(p)
		if !strings.Contains(got, "unconfined") {
			t.Errorf("networkLabel(%q) = %q, want an unconfined-host disclosure", p, got)
		}
	}
	if got := networkLabel("docker-networkless"); got != "none" {
		t.Errorf("docker-networkless label = %q, want none", got)
	}
	if got := networkLabel("fork-runner"); got != "bridge-host-gateway" {
		t.Errorf("fork-runner label = %q, want bridge-host-gateway", got)
	}
}
```

Plus one preview-level assertion: `Preview("host-readonly", "true", nil, nil)` has `network` containing `unconfined`.

- [ ] **Step 2: Run red** — `go test ./internal/sandbox -run TestNetworkLabel -count=1` fails (label is "none" today).
- [ ] **Step 3: Implement** — add `networkLabel` next to `profileFilesystemLabel`; replace both call sites (`environmentValue`, `Preview`) with it.
- [ ] **Step 4: Run green + full sandbox suite** — `go test ./internal/sandbox -count=1` (50s suite; expect existing tests that pinned `"none"` for host profiles to need their expectation updated to the honest label — update them, and note every such update in the commit body).
- [ ] **Step 5: Golden + runbook** — if any golden/legacy pin asserts `network_access: "none"` on a host-profile record, update the pin deliberately (reason in commit message). Run `scripts/golden.sh`.
- [ ] **Step 6: Commit and review** as Task 1's pattern.

### Task 3: Per-machine liveness coverage gate (the G-01 gap)

Stage-37 prose demands a liveness invariant per state machine; today `seedLiveness` accepts a model whose two covered machines hide a third uncovered one. Law: **zero** liveness invariants → synthesize the template (existing behavior, unchanged); **partial** coverage (some machines covered, some not) → refuse the model load, naming the uncovered machines.

**Files:**
- Modify: `internal/invariants/invariants.go:461-514` (`seedLiveness`)
- Test: `internal/invariants/invariants_test.go` (append)

**Interfaces:**
- Consumes: `SeedFromModel(c, model)` (signature unchanged), model `state_machines[].name`, registry liveness entries' `applies_to`.
- Produces: new error path `protocol model: state machine(s) X, Y have no liveness invariant (one per machine — stage 37) …`. Registry/event shapes unchanged.

- [ ] **Step 1: Write the failing tests**

```go
func TestPartialLivenessCoverageRefused(t *testing.T) {
	c := invCamp(t)
	model := modelWithInvariants() // machines: vault-lifecycle, relay, staking
	// give exactly one machine a liveness invariant
	machineCovered := /* copy of modelWithInvariants with invariants[0].kind="liveness", applies_to=["vault-lifecycle"] */
	_, err := SeedFromModel(c, machineCovered)
	if err == nil || !strings.Contains(err.Error(), "vault-lifecycle") {
		t.Fatalf("want refusal naming uncovered machines, got %v", err)
	}
}

func TestZeroLivenessStillSynthesizes(t *testing.T) {
	c := invCamp(t)
	links, err := SeedFromModel(c, modelWithInvariants())
	if err != nil {
		t.Fatal(err)
	}
	if objStr(objAt(objAt(links, "invariants"), "INV-4"), "synthesized") != "liveness-template" {
		t.Fatalf("template synthesis regressed")
	}
}
```

(Expand the `/* … */` comment into the full literal when writing the test — no placeholders land in the test file.)

- [ ] **Step 2: Run red** — partial-coverage test fails (load succeeds today).
- [ ] **Step 3: Implement** — inside `seedLiveness`, after building `machines` and before the `kinds["liveness"]` early return: compute the set of machines covered by any registered liveness entry's `applies_to`; if at least one machine is covered AND at least one is not, return the refusal naming the uncovered ones (exact wording from the test). Zero coverage keeps the existing synthesis path unchanged.
- [ ] **Step 4: Run green** — `go test ./internal/invariants ./internal/orchestrator ./internal/cli -count=1` (orchestrator's port fixture relies on synthesis — it must stay green untouched; if it breaks, the implementation is wrong, not the test). Then the legacy fixture check: any fixture model tripping the new partial-coverage refusal is corrected in the same commit — never weaken the gate.
- [ ] **Step 5: Full gates + commit + review** as before.

### Task 4: Evidence relevance binding on invariant-verify

`VerifyInvariantStatement` flips any registered invariant to `CHECKED_AGAINST_CODE` from any registered artifact. Morph's INV-003 was closed with a generic full-suite exec. New law: the cited artifact's bytes (or, for `--exec`, the registered stdout artifact's bytes) must reference the invariant id OR one of the entry's `applies_to` strings (case-insensitive substring), else the verify is refused with guidance. Documented invariants keep their existing exemption in `AssertInvariantsVerified` (unchanged); this gate sits in the verify path itself.

**Files:**
- Modify: `internal/invariants/invariants.go:751-787` (`VerifyInvariantStatement`)
- Modify: `internal/state/artifacts.go` — export `ResolveArtifactPath(a Value) string` (one-line wrapper over the existing unexported `resolveArtifactPath`)
- Test: `internal/invariants/invariants_test.go` (append)

**Interfaces:**
- Consumes: `c.Artifact(id)`, registry entry `applies_to`, file read via `validation.Sha256File`-style streaming (reuse `os.ReadFile`; artifacts are size-bounded by registration).
- Produces: new refusal `artifact <id> does not reference <inv> (nor its applies_to) — cite a check that names what it verifies (invariant-verify with --exec <id> re-registers stdout as the artifact)`. Existing callers (`cmd_invariant_verify.go`) need no signature change.

- [ ] **Step 1: Write the failing tests**

```go
func TestVerifyRefusesIrrelevantArtifact(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	artID := registeredArtifact(t, c, "suite.log", "go test ./... -count=1 PASS\n")
	_, err := VerifyInvariantStatement(c, "INV-2", artID)
	wantErr(t, err, "does not reference")
}

func TestVerifyAcceptsRelevantArtifact(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	artID := registeredArtifact(t, c, "inv-check.md",
		"INV-2 checked against src/V.sol L40\n")
	if _, err := VerifyInvariantStatement(c, "INV-2", artID); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run red** — refusal test fails (verify succeeds today); the generic full-suite log now MUST be refused.
- [ ] **Step 3: Implement** — in `VerifyInvariantStatement`, after the artifact lookup: load entry from registry (already loaded below — hoist), build the token set {normalized inv id} ∪ {each `applies_to` string}, read the artifact file bytes (`os.ReadFile(ResolveArtifactPath(a))`), and match each token with a word-boundary regex (Go: `\b` over the escaped token, e.g. `\bINV-2\b`, compiled case-insensitively) — a plain substring match would let `INV-2` falsely satisfy against an artifact citing `INV-20` or `INV-22`. Normalize the token through the existing `NormalizeInvID` (invariants.go:831) before escaping so `inv_002`-style spellings match too. No token match → the refusal above. Keep the existing event/save/unwind flow untouched. Add one negative test row: artifact citing `INV-20` must NOT satisfy `INV-2`.
- [ ] **Step 4: Fix the legitimate call sites** — existing tests register artifacts like `"checked against src/V.sol L40"` without the id; update those fixtures to include the inv id (they model honest artifacts). Enumerate: `grep -rn "VerifyInvariantStatement" internal/ | grep _test.go`. Production callers: `cmd_invariant_verify` already names the invariant in its note — verify, don't assume.
- [ ] **Step 5: Green + full gates** — `go test ./internal/invariants ./internal/cli ./internal/roles ./internal/audit -count=1`, then `go test ./... -count=1`. Then the legacy fixture check: a legacy artifact that no longer satisfies the relevance gate is re-registered with an honest artifact in the same commit — never weaken the gate.
- [ ] **Step 6: Commit + review** as before. Reviewer explicitly checks: no bypass (empty applies_to must not pass), documented-invariant flow unchanged, `--exec` path still works (stdout artifact carries the command → contains the id only if the operator's command did — that is the law working).

---

## Phase B — bookkeeping friction that cost real rounds

*(Tasks 5-9 follow the identical TDD loop: failing test → minimal fix → full gates → deliberate golden/runbook pin updates → commit → union-alpha review. Exact specs below; step-by-step scaffolding identical to Task 1 and not repeated.)*

### Task 5: artifact-register deduplicates by resolved path
**Files:** the `artifact-register` CLI handler (locate via `grep -rn "artifact-register" internal/cli --include=*.go | grep -v _test`), test in the same file's `_test.go`.
**Law:** registering the same file twice (relative then absolute, or any path spelling) yields the SAME artifact id and an `artifact.refreshed` event — never a second row. Use the existing `RegisterOrRefresh` (state/artifacts.go:434); if its semantics differ (it matches on stored path string), extend IT to resolve first — one fix in the shared function, not per-CLI.
**Test:** register `target/a.sol`, then `./target/a` from inside the root → same id, one row, second event says refreshed.

### Task 6: `index` emits a registry refresh event when it rewrites artifact bytes
**Files:** the `index` command handler; `internal/state/artifacts.go` if a shared refresh helper is needed.
**Law:** any artifact whose bytes the command changed gets a registry row update + `artifact.refreshed` event in the same lock window (rawState/unwind law applies). Audit section for artifacts must render the refreshed rows without a new section.
**Test:** run `index` on a fixture whose index rewrite touches a registered file → event present, hash updated, audit clean; run on an unchanged tree → zero events. Plus one concurrency test: `TestIndexConcurrentRefresh` runs 10 goroutines driving `index` over overlapping trees — the lock window must hold (no duplicate `artifact.refreshed` events for one rewrite, no deadlocked ledger, `-race` clean).

### Task 7: `brief` next-actions are copyable commands
**Files:** `internal/briefing` (or wherever next-actions render — locate via `grep -rn "next_action" internal/briefing`).
**Law:** every next-action line is a runnable `webv2 …` command; no `orchestrator.scope(policy_path=…)` pseudo-API. The plan/replan code that MINTS those strings is the fix site, not the renderer.
**Test:** fixture campaign → `brief` output next-actions all match `^webv2 ` and none match `\(`.
**Pins:** update golden/runbook expectations deliberately.

### Task 8: snapshot re-pin summarizes exclusions
**Files:** the snapshot re-pin path (locate via `grep -rn "pruned" internal/snapshot internal/cli | head`).
**Law:** exclusion lists render as `N paths excluded (first 10): …` with N exact; full list available in the record object, not stdout.
**Test:** fixture with >20 pruned paths → output lines bounded, count exact.

### Task 9: classify maps missing-compiler to ENVIRONMENT
**Files:** `internal/envgo` failure classifier (locate the SETUP classification of tool-absent), its test table.
**Law:** missing toolchain/dependency (solc, forge, docker binary) → ENVIRONMENT per the runbook's own vocabulary; only hypothesis-space failures stay SETUP. Read the runbook row FIRST and make the code match the documented law.
**Test:** table row `missing solc` → class ENVIRONMENT; note text names the fix.

---

## Phase C — the cockpit enforces coverage, not comfort

*(Same TDD loop. These are the Morph wishes #2/#3/#10-12 — product changes the operator explicitly wants. Each task: fixture model + fixture campaign in test, deterministic output, no new deps.)*

### Task 10: Open questions compile into the work queue
**Files:** `internal/orchestrator` (Plan/work-queue assembly), fixture in `port_fixtures_test.go`.
**Law:** every `open_questions` entry with a `blocks`/`applies_to` contract reference produces a work-queue entry `resolve open question Q-…: <text>` ranked above generic index work when it names consensus-critical or untouched contracts; brief shows it.
**Test:** fixture model with one open question naming rollup → `Plan` output contains it ranked in the top 3; empty open_questions → queue unchanged (existing tests stay green).

### Task 11: Cold probe surface is a persistent brief warning
**Files:** `internal/briefing` + `internal/probes` read seam.
**Law:** while the campaign phase is DISCOVERY and no `probes run --emit` exec exists in the ledger, `brief` prints a standing warning line naming the exact command. Not a gate; a persistent, honest cockpit line.
**Test:** campaign without probe emits → warning present; after a recorded probe emit → gone.

### Task 12: Cockpit priority is risk × untouched, not alphabetical
**Files:** the work-queue ordering function in `internal/orchestrator` (locate `sort` in plan/queue assembly).
**Law:** ordering weight is ADDITIVE — `Score = (untouchedCount * W1) + (severityScore * W2) + (openQuestionCount * W3)`, named constants with a `ponytail:` comment, ties break alphabetically. NEVER multiplicative: a product would zero-out a critical consensus contract that happens to have zero open questions and drop it below alphabetical entries — exactly the failure the review flagged. Severity maps critical=3/high=2/medium=1/low=0. No new config.
**Test:** fixture where the alphabetically-first untouched file is low-risk and a consensus-critical contract is later in sort order → queue puts the critical one first; deterministic across runs.

---

## Phase D — supply chain and threat model

### Task 13: Dependency freshness + advisory scan as an honest gate
**Files:** `go.mod` (bump `golang.org/x/text` to latest; others confirmed current at execution time), `scripts/verify-full.sh` (new optional step 14: `govulncheck ./...` when the tool exists; prints SKIPPED-with-reason when absent — never silently), `README.md` verification table row.
**Law:** the step exits 0 on skip (with the reason on stdout), fails on findings. Network-isolation handling is explicit: if `go get` or `govulncheck` fails on network, verify-full prints `[SKIPPED: network isolated — operator must run govulncheck locally]` and exits 0 — a sandbox network timeout must never fail the CI gate. Never fake versions.
**Test:** `go build ./... && go test ./internal/protocolgraph ./internal/bounty ./internal/findings ./internal/pricing -count=1` (the x/text consumers) after the bump; verify-full runs green with the new step.

### Task 14: SECURITY.md — the honest threat model
**Files:** create `SECURITY.md` (~80 lines, facts only, all verified against code).
**Contents (each a section with file refs):** what the trust core protects (hash chain, atomic writes, process lock, one-writer law); what the sandbox IS (container profiles: network/fs via docker flags) and IS NOT (host profiles are unconfined tripwires — Task 2's labels; deny-rules are static regex, not a boundary); the E-cap evidence semantics and why floors don't lower; supported versions; how to report.
**Test:** none (docs); `scripts/verify-full.sh` unaffected. Reviewer checks every claim against the cited file/line.

### Task 15: Docs and pins reconcile
**Files:** `README.md` command table (if Phase B/C changed output shapes), `assets/runbook/RUNBOOK.md` rows for `brief`/`snapshot`/`classify` changed behavior, `docs/IMPROVEMENTS.md` — one "production-readiness wave" section appended listing what shipped. Asset manifest resync via `python3 scripts/sync-asset-manifest.py` if RUNBOOK changed.
**Test:** `scripts/runbook-walkthrough.sh` green; manifest test green.

---

## Execution order and dispatch

- Strictly sequential: Task 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15. Each: implementer (`b-ai/deepseek-v4.1-flash` via workflow) → review package → reviewer (union-alpha) → fix loop (≤5 rounds, resume implementer rounds 1-3) → ledger line → next.
- BASE recorded per task before dispatch; review packages from BASE, never HEAD~1.
- Tasks 2, 7, 8, 9 touch pinned output: run golden + runbook walkthrough in-task, pin updates deliberate and documented.
- Final whole-branch review: union-alpha over MERGE_BASE..HEAD, pointed at the ledger's deferred minors; ONE fix wave then one scoped re-review.

## Definition of done (the production bar — all checked, no exceptions)

- [ ] All 15 tasks: red→green regression exists, review clean or parked-with-ruling, ledger complete.
- [ ] `go vet ./...` clean; `go test ./... -count=1` green; `-race` green on state/sandbox/harness; determinism x2 green.
- [ ] `scripts/golden.sh`, `scripts/runbook-walkthrough.sh`, `scripts/verify-full.sh` (steps 1-13) green at final HEAD, with govulncheck step reported honestly (run or skipped-with-reason).
- [ ] `scripts/release.sh` green; static binary serves embedded assets standalone.
- [ ] Legacy fixture cross-audit green (no reader breakage from the new refuse paths — Tasks 1/3/4 each verify this explicitly).
- [ ] No open Critical/Important findings in the final union-alpha review.
- [ ] Honest-limitations note recorded: discovery performance (the 0/2 benchmark) is NOT claimed fixed by this plan; it requires held-out measurement.

## Explicitly out of scope (unchanged by v2)

- Morph repo modifications, exploit development, autonomous hunting.
- New evidence rungs or lowered floors.
- MiniProver/MiniCertora changes absent a verified defect.
- Docker/VM escape hardening beyond honest labeling (the container is the boundary; its hardening is upstream's).

---

### Task 16 (added during execution, from Task 1 review): Reject duplicate YAML mapping keys

**Files:** Modify internal/validation/yaml.go (yamlNodeValue MappingNode branch, lines 57-70); test internal/validation/yaml_test.go (create if absent, else append).

**Law:** ParseYaml must refuse a mapping node carrying the same key twice (PyYAML safe_load silently last-wins; our canonical writer then emits JSON the Task 1 guard refuses — the two parsers must not disagree). Error text: "yaml: duplicate mapping key %q". Per-mapping scope, exactly like Task 1: seen := map[string]bool{} keyed on yamlKeyText(k) output, checked before append. Alias nodes resolve before the check (the alias IS the mapping; its own entries are what get checked).

- [ ] Step 1: failing test — ParseOrdered-equivalent table: "a: 1\na: 2\n" refused; nested mapping duplicate refused; sequence of two mappings each with key "a" accepted; alias-to-distinct-mapping accepted.
- [ ] Step 2: red run (ParseYaml currently accepts duplicates).
- [ ] Step 3: implement the seen-guard in the MappingNode branch.
- [ ] Step 4: green + go test ./internal/validation ./internal/playbooks ./internal/archetypes ./internal/taxonomy -count=1, then go test ./... -count=1, go vet ./...
- [ ] Step 5: legacy check per Global Constraints (sanitize fixture in same commit if tripped — never weaken the gate).
- [ ] Step 6: commit only the task files, message: fix(validation): reject duplicate YAML mapping keys
