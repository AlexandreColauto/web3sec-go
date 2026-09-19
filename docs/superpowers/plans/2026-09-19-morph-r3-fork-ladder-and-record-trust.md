# Morph R3 fork-ladder & record-trust fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: dispatch one fresh implementer subagent per task (provider `b-ai`, model `deepseek-v4.1-flash`), reviewed by a `glm-5.3-flash` gate agent per task. Steps use checkbox (`- [ ]`) syntax for tracking. **Implementers never run `git commit`** — the orchestrator commits each task after its review gate passes, so bisect + manifest rules stay enforceable.

**Goal:** Close the Morph round-3 defect list (FINAL_REPORT items 1–9) so the fork half of the evidence ladder (E5/E6/T4 → CONFIRMED) is actually reachable, the campaign record treats its policy as first-class evidence, and the status/floor/ledger interlocks are honest.

**Architecture:** Every fix is one guard in the single shared seam the defect analysis named (triage doc `docs/feedback-triage-morph-r3.md` holds the file:line evidence). No new packages, no new abstraction: the policy rides the existing artifact registry, the `assume` verb is a thin wrapper over the existing `findings.AssumptionTransition`, the repro-status fix is a rank loop inside the one writer, and the CLI papercuts are flag-level edits.

**Tech Stack:** Go 1.26.2 module `websec` (stdlib only), embedded assets (`assets/`, byte-pinned by `assets/testdata/asset_manifest.json` + `scripts/sync-asset-manifest.py`), golden vectors (`scripts/golden-run.py`, `scripts/check-golden.py`), orchestrator oracles (`internal/orchestrator/testdata/oracles.json`).

## Global Constraints

- **RESOURCE LAW (a full-suite subagent run drowned this box once and was killed):** every `go test` invocation must be (a) `-run`-scoped to the tests you just wrote/touched until they are green, then ONE final package-scoped check with `go test -count=1 ./internal/<pkg>`, (b) wrapped in `timeout 300`, (c) run with `GOCACHE=/tmp/gocache GOFLAGS=-p 1` to cap compiler parallelism, (d) NEVER `-race`, NEVER `./...`, NEVER `scripts/golden.sh`, NEVER docker, NEVER concurrent test binaries. The sandbox/sequencepoc/zz_* suites are process-heavy — keep `-run` filters on the final package check too if a whole-package run risks the memory budget. Only ONE implementation agent runs at a time against this tree.
- Tests run with `GOCACHE=/tmp/gocache`; **every build/test command is scoped to your task's own packages** — never `go test ./...` (other agents' half-edited packages would poison the signal).
- **Do not run `git commit`, `git add`, or any git write.** Stage/commit is the orchestrator's job. Do not touch files outside your task's file list.
- No new third-party dependencies. No new packages.
- Any edit under `assets/` requires `python3 scripts/sync-asset-manifest.py` before the task is done, and the manifest regen must land in the same commit (bisect gate: `TestAssetPackManifest` must pass at every commit).
- New/changed CLI refusal or notice text: grep `scripts/golden-run.py` and the repo's pinned bytes first; a fresh-campaign byte-identical promise applies to `cmd_scope` stdout (`internal/cli/cmd_scope_test.go` pins `policy loaded from %s — %d scope entries, %d exclusions`).
- Event-payload or state-projection changes ripple into `internal/orchestrator/testdata/oracles.json` — re-record through the replay harness (see Task 3 Step 4), never hand-edit expected bytes (event hashes cover real ids).
- House CLI shapes: t14 handlers (`t14Dispatch`, `t14ExitErr(2, "<verb> failed: %s\n", err)`, `t14ArgparseErr`), value flags guarded as `case a == "--x" && i+1 < len(args) && !looksLikeOption(args[i+1])` (standing guard `TestNoUnguardedValueConsumption`), usage block constant pinned once, refusals print the legal set. Warnings/notes ride **stderr**, never stdout (quota-notice precedent `cmd_probes_quota_stream_test.go`).
- New enum inside `assets/schema/finding.schema.json` must be mirrored in `t14FindingLegend` (`internal/cli/cmd_ingest_test.go`) — no task here changes that schema, but keep the rule in mind.
- New verbs ship with their RUNBOOK wiring (`assets/runbook/RUNBOOK.md` verb list + the command table) and `docs/IMPROVEMENTS.md` is NOT edited per-task (the wave tail updates the triage doc status section instead).
- One commit per task by the orchestrator, message style: `fix(sandbox): fork-runner rewrites loopback RPC for containers (R3-1a)`.
- Every task ends with its package tests green + `gofmt -l` clean on touched files.

---

## File structure (what each task owns)

| Task | Files |
|---|---|
| R3-1a | `internal/sandbox/profiles.go`, `internal/sandbox/ext_test.go` |
| R3-1c | `internal/sequencepoc/driver.go`, `internal/sequencepoc/driver_test.go` |
| R3-6 | `internal/reproduction/reproduction_attempt.go`, `internal/reproduction/reproduction_test.go` |
| R3-2a | `internal/orchestrator/scope.go`, orchestrator tests, `internal/orchestrator/testdata/oracles.json` |
| R3-8 | `internal/orchestrator/scope.go`, `internal/cli/cmd_scope.go`, `internal/cli/cmd_scope_test.go` |
| R3-3 | `internal/findings/transitions.go`, `internal/findings/transitions_test.go`, fixture files in ~dozen packages (discovered by the red run) |
| R3-4 | `internal/cli/cmd_assume.go` (new), `internal/cli/cmd_assume_test.go` (new), `assets/runbook/RUNBOOK.md`, manifest |
| R3-5 | `internal/planner/disposition_deferred.go`, `internal/planner/answered.go`, planner/cli tests for answered |
| R3-7 | `internal/probes/audit.go`, probes audit tests |
| R3-9c | `internal/cli/cmd_verdict.go`, `internal/findings` (SetCriticVerdict), `internal/cli/cmd_verdict_test.go` |
| R3-9e/9d | `internal/cli/cmd_audit.go`, `internal/cli/cmd_schema.go`, their tests |
| R3-9a | `internal/cli/cmd_amend.go`, `internal/cli/cmd_amend_test.go` |
| R3-9f | `assets/schema/protocol_model.schema.json`, manifest, `internal/protocolgraph` (carry-through only if trivial) |
| R3-1b | `internal/envgo/env_doctor.go`, `internal/envgo/envgo_test.go` |

---

### Task 1: R3-1a — fork-runner rewrites the loopback RPC to `host.docker.internal`

**Why.** The profile runs on the bridge network with `--add-host host.docker.internal:host-gateway` (`internal/sandbox/profiles.go`, fork-runner arm), but injects the operator's `FORK_RPC_URL` **verbatim**: an operator fork at `http://127.0.0.1:18545` becomes the container's own loopback, which answers nothing. This is what made E5/E6/T4 unobtainable in the Morph campaign. One guard in `BuildContainerArgv` fixes both `webv2 exec --profile fork-runner` and `webv2 sequence run` (the latter forwards the host env verbatim into the same seam — `internal/sequencepoc/run.go` `sequenceRunOpts`).

**Files:**
- Modify: `internal/sandbox/profiles.go` (the `BuildContainerArgv` fork-runner env arm, ~line 340)
- Test: `internal/sandbox/ext_test.go` (extend the three fork-runner env cases)

**Interfaces:**
- Produces: `containerForkURL(url string) string` — package-level, **exported as `sandbox.ContainerForkURL`** (Task 14's doctor line reuses it). Rewrites only the URL's host when it is a loopback literal; port/scheme/path/query survive untouched.

- [ ] **Step 1: Write the failing tests** in `internal/sandbox/ext_test.go`, next to `TestForkRunnerInheritsOperatorForkRPCURL` (which passes a non-loopback hostname and must stay byte-identical):

```go
func TestForkRunnerRewritesLoopbackRPC(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://127.0.0.1:18545", "http://host.docker.internal:18545"},
		{"http://localhost:8545", "http://host.docker.internal:8545"},
		{"http://127.0.0.1:8545/path?x=1", "http://host.docker.internal:8545/path?x=1"},
		{"http://[::1]:8545", "http://host.docker.internal:8545"},
		{"https://127.0.0.1:8545", "https://host.docker.internal:8545"},
		// not loopback: untouched
		{"http://operator-fork:9545", "http://operator-fork:9545"},
		{"https://eth.drpc.org/xyz", "https://eth.drpc.org/xyz"},
		// unparseable: untouched (the RPC will fail loudly, not silently)
		{"not a url", "not a url"},
	} {
		if got := ContainerForkURL(tc.in); got != tc.want {
			t.Errorf("ContainerForkURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
```

Plus one end-to-end argv case in the same file, following the existing `forkRunnerRun` helper pattern: with `t.Setenv("FORK_RPC_URL", "http://127.0.0.1:18545")`, the built argv must contain `-e FORK_RPC_URL=http://host.docker.internal:18545` and must NOT contain `127.0.0.1`. Also one case for an **explicit caller env entry** (`RunOpts.Env` carrying `FORK_RPC_URL=http://localhost:1234` — that wins over operator env per the existing precedence, and still lands rewritten), and one case proving `docker-networkless` never rewrites (its `--network none` makes the value meaningless; pass-through bytes stay).

- [ ] **Step 2: Run them, verify FAIL** — `GOCACHE=/tmp/gocache go test ./internal/sandbox -run 'ForkRunner' -v`.

- [ ] **Step 3: Implement.** In `profiles.go`, add the exported helper (near `BuildContainerArgv`):

```go
// ContainerForkURL is the fork-runner rewrite: a loopback RPC URL points at
// the CONTAINER's own loopback once inside the bridge sandbox, so the
// operator's local fork (127.0.0.1:port) is unreachable verbatim. host-gateway
// is already added for exactly this hop (Morph r3 defect 1). Port/scheme/
// path/query survive; a non-parseable URL passes through untouched.
func ContainerForkURL(url string) string {
	u, err := urlpkg.Parse(url)
	if err != nil {
		return url
	}
	h := strings.ToLower(u.Hostname())
	if h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return url
	}
	return strings.Replace(url, u.Host, "host.docker.internal:"+u.Port(), 1)
}
```

(`import urlpkg "net/url"` — the package already imports `net/http` elsewhere in `profiles.go` if present; check the file's import block and use the plain `net/url` name unless it collides.)
`u.Host` keeps brackets for IPv6 (`[::1]:8545`), so `strings.Replace` on the full host is exact. Guard the empty-port case: `u.Port()==""` → replace with bare `host.docker.internal`.
In the `BuildContainerArgv` fork-runner arm, route BOTH the operator-env/default value and a caller-provided `FORK_RPC_URL` entry through the rewrite — the laziest true seam is to rewrite at the `-e` emission step for the fork-runner profile only: after `containerEnv` is assembled, `if profile == "fork-runner" { for i := range containerEnv { if containerEnv[i].Key == "FORK_RPC_URL" { containerEnv[i].Value = ContainerForkURL(containerEnv[i].Value) } } }`.
Keep the unset-default (`http://host.docker.internal:8545`) byte-identical (it rewrites to itself; the pin at `ext_test.go` `want := "FORK_RPC_URL=http://host.docker.internal:8545"` must not move).

- [ ] **Step 4: Run package tests** — `GOCACHE=/tmp/gocache go test ./internal/sandbox ./internal/cli -run 'Fork|Exec' -v`; also run the FULL `go test ./internal/sandbox` and `go test ./internal/cli` (cmd_exec_test.go pins a dry-run preview with the unset default — it must stay green).

- [ ] **Step 5: `gofmt -l internal/sandbox` must print nothing. Report the diff summary (files + what changed) back; do NOT commit.**

---

### Task 2: R3-1c — the sequence driver stops swallowing cast's stderr

**Why.** The fork-RPC reachability failure surfaced as `seq: empty address for anvil:0` with no cause, because the `eth_accounts` probe pipes cast's stderr into `/dev/null` (`internal/sequencepoc/driver.go`, `BuildCommand` preamble). The report's root complaint: "never discard cast's stderr". The driver already has the right seams: `seq_err.txt` (written per cast call, read by `sanitize_reason`) and it exists before any step runs.

**Files:**
- Modify: `internal/sequencepoc/driver.go` (`BuildCommand` UNLOCKED line; `actorFragments` empty-address echo)
- Test: `internal/sequencepoc/driver_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: driver-text change (two lines) — the generated script is what runs in the container; `TestDriverEmptyAccountsFailClosed` and any byte-pinned full-script expectations move with it.

- [ ] **Step 1: Write the failing test.** In `driver_test.go`, extend/clone `TestDriverEmptyAccountsFailClosed`: build the command for a spec with an `anvil:0` actor, run it in `sh` against a stub `cast` (the existing stub-cast pattern in this file) whose invocation writes `MPP HTTP request to http://127.0.0.1:18545 failed` to **stderr** and exits 1. Assert the script's combined output contains BOTH `empty address for anvil:0` AND `MPP HTTP request` — today only the first line appears. Also assert the PASS path stays byte-clean (the C1 note in `BuildCommand`: a passing run prints the `seq: PASS ...` line to stdout and nothing else new).

- [ ] **Step 2: Run, verify FAIL** (`GOCACHE=/tmp/gocache go test ./internal/sequencepoc -run EmptyAccounts -v`).

- [ ] **Step 3: Implement.** In `BuildCommand`, the `UNLOCKED=` line ends `eth_accounts 2>/dev/null | grep ...` → `eth_accounts 2>"$WD/seq_err.txt" | grep ...`. In `actorFragments`, the empty-address branch becomes:

```go
fmt.Sprintf(`[ -n "${%s}" ] || `+
	`{ echo "seq: empty address for anvil:%s (fork rpc: $(sanitize_reason))" >&2; exit 1; }`,
	v, n),
```

`sanitize_reason` is already in `shHelpers` (`head -n1 "$WD/seq_err.txt" | tr ...`) and `seq_err.txt` still holds the probe's stderr at that point (nothing has overwritten it yet — every overwrite happens in a later `cast send`). If `seq_err.txt` is absent/empty (fork up, zero unlocked accounts) the suffix renders `fork rpc: ` — acceptable and honest; do NOT add a conditional (ponytail: two extra sh branches for cosmetics).

- [ ] **Step 4: Update the pins.** grep `driver_test.go` for `eth_accounts` / `empty address` expectations and move them with the new bytes. Run the whole package: `GOCACHE=/tmp/gocache go test ./internal/sequencepoc`.

- [ ] **Step 5: gofmt + report. Do NOT commit.**

---

### Task 3: R3-6 — reproduction status tracks the BEST attempt, not the latest

**Why.** `RecordAttempt` writes `verification.reproduction.status` unconditionally from the newest outcome, so a later diagnostic/failed run flips a `reproduced` finding back to `attempted` and un-qualifies the `reproduction-reproduced` CONFIRMED clause (report defect 6). Each attempt already carries its own outcome in `repro.attempts[]` — the failures stay on the record; only the projection becomes best-outcome.

**Files:**
- Modify: `internal/reproduction/reproduction_attempt.go` (~line 117, the `setKey(repro, "status", …)` map)
- Test: `internal/reproduction/reproduction_test.go`

- [ ] **Step 1: Write the failing tests** (assert-based, follow the file's existing helper style):

```go
func TestRecordAttemptStatusIsBestOutcome(t *testing.T) {
	c := // the package's campaign-init helper, same as neighbors use
	f := // the package's finding-init helper
	must := func(outcome string) {
		if _, err := RecordAttempt(c, fid, outcome, RecordOpts{}); err != nil {
			t.Fatalf("RecordAttempt(%s): %v", outcome, err)
		}
	}
	must("reproduced")
	must("failed") // a diagnostic failure must NOT un-qualify the repro
	if got := reproStatus(t, c, fID); got != "reproduced" {
		t.Fatalf("status after reproduced+failed = %q, want reproduced", got)
	}
	// and the history stays honest:
	if n := attemptsCount(t, c, fID); n != 2 {
		t.Fatalf("attempts = %d, want 2", n)
	}
	must("falsified") // falsified outranks attempted, not reproduced
	if got := reproStatus(t, c, fID); got != "reproduced" {
		t.Fatalf("status = %q, want reproduced (rank stays)", got)
	}
}

func TestRecordAttemptFalsifiedBeatsAttempted(t *testing.T) {
	// failed then falsified => falsified; falsified then failed => falsified.
}
```

(`reproStatus`/`attemptsCount` are two-line LoadFinding + `ObjAt(...verification.reproduction.status)` helpers — write them locally in the test file; match the names/helpers the file already has and reuse rather than duplicate.)

- [ ] **Step 2: Run, verify FAIL** — today the first case ends `attempted`.

- [ ] **Step 3: Implement.** Replace the latest-wins write:

```go
repro = setKey(repro, "status", validation.VStr(bestReproStatus(outcomeToStatus[outcome])))
```

where a small package-level pair defines the rank once:

```go
// outcomeToStatus maps an attempt outcome onto the recorded status.
var outcomeToStatus = map[string]string{"reproduced": "reproduced",
	"failed": "attempted", "blocked": "blocked", "falsified": "falsified"}

// reproStatusRank is the best-outcome ladder: reproduced > falsified >
// blocked = attempted (Morph r3 defect 6: a later diagnostic failure must
// not launder a reproduced finding back to attempted — the attempts[]
// ledger keeps every failure honestly, the STATUS reports the best result).
var reproStatusRank = map[string]int{"attempted": 1, "blocked": 1,
	"falsified": 2, "reproduced": 3}

func bestReproStatus(candidate string) string {
	// reads nothing but its argument — the caller feeds it the CURRENT
	// recorded status and the new one; simplest: keep max over all attempts
}
```

Concretely, compute it where `attempts` is already in hand right after the append: fold `reproStatusRank` over `attempts[]`'s outcomes (via `outcomeToStatus`) and write that; when the attempts list is empty (impossible path) fall back to the mapped outcome. ~8 lines in ONE function. `undoAttempt` and every event payload stay untouched.

- [ ] **Step 4: Full package green** — `GOCACHE=/tmp/gocache go test ./internal/reproduction`; grep `reproduced` expectations in `internal/sequencepoc/*_test.go` and `internal/findings/*_test.go` that assume latest-wins (verifier found none pin it — confirm with a targeted run of those two packages too if they touch RecordAttempt).

- [ ] **Step 5: gofmt + report. Do NOT commit.**

---

### Task 4: R3-2a — `scope --policy` registers the bounty policy (hash + ledger event)

**Why.** The policy file decides what counts as in-scope, yet at HEAD it is the only campaign input with no integrity story: `Orchestrator.Scope` validates, saves `<campaign>/bounty_policy.json`, stamps `policy_path` — and registers nothing. Deleting exclusions from the on-disk copy survives `audit` and `brief --deep` (report defect 2). `kind "policy"` ALREADY exists in the campaign_state artifact enum (verified at HEAD), so `RegisterOrRefresh` mints a `POL-…` row, hashes it, and logs `artifact.registered` — one call buys row + hash + event, and audit section 2 (re-hash every registered row) then catches tampering for free. No new audit section.

**Files:**
- Modify: `internal/orchestrator/scope.go` (after `bounty.SavePolicy`, inside the `policyPath != ""` branch)
- Test: `internal/orchestrator/` (the scope tests file matching the package's existing table — grep `func TestScope` first and extend it)
- Re-record: `internal/orchestrator/testdata/oracles.json`

- [ ] **Step 1: Failing test** — in the existing scope test harness (campaign init + policy file, same fixture the current scope tests build), after `o.Scope(policyPath)`: open state, assert `artifacts` carries one row with `kind == "policy"` whose `path` resolves to the campaign `bounty_policy.json` and whose `sha256` equals `validation.Sha256Hex` of the file bytes; assert `events.jsonl` ends with an `artifact.registered` event referencing the `POL-` id. Repeat a second `Scope` call with a MUTATED policy file: assert the SAME artifact id refreshed (D3 one-row-per-path law) and a second event landed.

- [ ] **Step 2: Run, verify FAIL** (`GOCACHE=/tmp/gocache go test ./internal/orchestrator -run Scope`).

- [ ] **Step 3: Implement** — inside `Scope`, immediately after `saved, err := bounty.SavePolicy(...)` (use `saved`, the returned path, NOT `dest`, so refresh matches the stamped `policy_path`):

```go
if _, err := o.C.RegisterOrRefresh("policy", saved,
	"bounty policy (scope)", nil,
	"scope loaded the bounty policy"); err != nil {
	return validation.VNull(), err
}
```

The snapshot id is nil: the pin does not exist yet at SCOPE stage — pass nil and check `RegisterOrRefresh`'s snapshotID handling accepts it (it's a `*string`).

- [ ] **Step 4: Re-record the orchestrator oracles.** Every scope op in `internal/orchestrator/testdata/oracles.json` (step[0] of every scenario) now carries one more artifact row + event. Find the re-record harness: grep `oracles.json` under `scripts/` and `internal/orchestrator/` (a regen test or `scripts/canon-oracle.py` driver). Replay-regenerate, then DIFF the old vs new file and verify the ONLY changes are the expected artifact row / `artifact.registered` line / state projection (ids normalized to the fixture placeholders). Hand-patching the fixture is BANNED (event hashes).
- CLI byte promise: `webv2 scope` stdout must stay byte-identical (pin in `internal/cli/cmd_scope_test.go`); do NOT print the artifact id on stdout. Run `GOCACHE=/tmp/gocache go test ./internal/cli -run Scope`.
- Then `python3 scripts/check-golden.py` (no golden step captures scope output today — prove it).

- [ ] **Step 5: Package green** (`go test ./internal/orchestrator ./internal/cli -run 'Scope|Oracle|Golden'` then full `./internal/orchestrator`), gofmt + report. Do NOT commit.

---

### Task 5: R3-8 — a policy reload never rewinds the campaign phase

**Why.** `Scope()` calls `SetPhase("SCOPE")` unconditionally; mid-campaign that silently drags `DISCOVERY` back to `SCOPE` while the stage table stays 4/17 — the report's phase/stage disagreement (defect 8). On a FRESH campaign phase is already SCOPE, where `SetPhase` is a same-phase no-op — so the guard changes nothing for the oracles.

**Files:**
- Modify: `internal/orchestrator/scope.go` (the SetPhase call), `internal/cli/cmd_scope.go` (stderr notice)
- Test: `internal/cli/cmd_scope_test.go` (new mid-campaign case)

- [ ] **Step 1: Failing test** — build a campaign, run `scope --policy` (fresh path, asserts existing bytes), then drive it past SCOPE the way the existing tests advance state (or call `c.SetPhase("DISCOVERY", "test")` directly), then run `scope --policy` again through the CLI runner and assert: exit 0, stdout policy line byte-identical, **stderr contains** `campaign is in phase DISCOVERY — phase left unchanged (policy reloaded)`, and `state["phase"]` is still `DISCOVERY` with NO new `phase.transition` event.

- [ ] **Step 2: Run, verify FAIL** (today the phase rewinds).

- [ ] **Step 3: Implement.** In `Scope`, replace the unconditional call:

```go
st, err := o.C.State()
if err != nil {
	return validation.VNull(), err
}
if validation.ObjStr(st, "phase") == "SCOPE" {
	if err := o.C.SetPhase("SCOPE", "load bounty policy"); err != nil {
		return validation.VNull(), err
	}
}
```

(Equivalent-and-lazier: skip SetPhase whenever the phase is not SCOPE; the same-phase call was already a no-op, so fresh-campaign bytes/events are untouched.) In `runScope`/`scopeCmd` (wherever the policy line prints, `cmd_scope.go` ~line 341-353): BEFORE calling `orchestrator.Scope`, read the phase; after a successful call with `--policy` and a phase that was not SCOPE, `fmt.Fprintf(r.Err, "campaign is in phase %s — phase left unchanged (policy reloaded)\n", phase)`.

- [ ] **Step 4: Green:** `GOCACHE=/tmp/gocache go test ./internal/cli ./internal/orchestrator` (full for those two packages; no golden captures scope — Task 4 already proved the byte promise; re-prove nothing new moved).

- [ ] **Step 5: gofmt + report. Do NOT commit.**

---

### Task 6: R3-3 — the status transition enforces the evidence floor (move included)

**Why.** `STATUS_FLOOR` (POSSIBLE=E2, PROVISIONALLY_VALID=E1, CHAIN=E4, CONFIRMED=class floor) was advisory for everything but CONFIRMED: `webv2 move C F POSSIBLE` succeeded on zero evidence and printed `POSSIBLE (evidence level E0)` (report defect 3). The single shared writer is `transition()` in `internal/findings/transitions.go` — cmd_move and cmd_amend funnel through it, so one guard there is the root-cause fix. CONFIRMED is deliberately excluded (its `ConfirmationGateClauses` bundle already enforces the floor AND records `finding.gate_attempt` — double-refusing would reorder failures pinned by `TestConfirmationGateFailuresAreEnumerated`).

**Files:**
- Modify: `internal/findings/transitions.go` (the guard), `internal/findings/transitions_test.go`
- Fixture ripple: every package whose tests do a zero-evidence promotion (`go test ./...` red-list finds them; the verifier expects ~20 files: `pos()` helpers in transitions_test.go, internal/invariants/guard_test.go, internal/boundary, internal/sharedmem, internal/report, internal/briefing, internal/roles, …).

- [ ] **Step 1: Failing tests** in `transitions_test.go`:

```go
func TestMoveEnforcesStatusFloor(t *testing.T) {
	c := newTestCampaign(t)
	f := newHypothesis(t, c) // zero evidence
	if _, err := Transition(c, f.ID, "POSSIBLE", MoveOpts{}); err == nil {
		t.Fatal("zero-evidence HYPOTHESIS -> POSSIBLE succeeded; want the E2 floor refusal")
	} else if !strings.Contains(err.Error(), "evidence level E0 < required E2 for POSSIBLE") {
		t.Fatalf("error = %v, want the EvidenceDeficit text", err)
	}
	// with E2 evidence the move lands:
	attachEvidence(t, c, f.ID, "E2") // the file's existing evidence helper — grep first
	if _, err := Transition(c, f.ID, "POSSIBLE", MoveOpts{}); err != nil {
		t.Fatalf("E2-backed move refused: %v", err)
	}
	// downgrades stay free: POSSIBLE -> HYPOTHESIS needs no floor.
	if _, err := Transition(c, f.ID, "HYPOTHESIS", MoveOpts{Reason: "x"}); err != nil {
		t.Fatalf("downgrade refused: %v", err)
	}
}
```

Match the real names/shapes the file uses (read `transitions_test.go` and the `pos()` helper first; the point is the three assertions, not my spelling).

- [ ] **Step 2: Run, verify FAIL** (`-run TestMoveEnforcesStatusFloor`).

- [ ] **Step 3: Implement** the guard in `transition()` — after the DISPROVED-adjacent block, immediately BEFORE the slot charge (`statusBaselineIndex` section):

```go
// Morph r3 defect 3: STATUS_FLOOR was a table the move path never read.
// The CONFIRMED arm above owns its own gate bundle (and its refusal
// event), so only the floor-less-by-gate statuses are checked here;
// EvidenceDeficit is campaign-aware (effective-floor seam) and returns
// nil for floor-less statuses (DISPROVED/DUPLICATE/INFORMATIONAL/
// OUT_OF_SCOPE/SUPERSEDED/NEEDS_RESEARCH), making this a no-op for them.
if toStatus != "CONFIRMED" {
	if deficit := EvidenceDeficit(finding, toStatus, campaign); deficit != nil {
		return validation.VNull(), &IllegalTransition{Msg: *deficit}
	}
}
```

Refuse silently in the ledger — do NOT log a `gate_attempt` (that event is CONFIRMED-specific).

- [ ] **Step 4: Fix the fixture ripple honestly.** `GOCACHE=/tmp/gocache go test ./...` and read the red list. For each failing fixture: give the test finding the minimum evidence the target status demands using that package's existing evidence helper (E1 for PROVISIONALLY_VALID, E2 for POSSIBLE, E4 for CHAIN), or demote the fixture's target move to a floor-less status if the test isn't ABOUT the move. NEVER weaken the guard, never special-case tests in production code, and NEVER make a test assert on nothing. Where a test previously did `pos()` on zero evidence and is not about the promotion itself, change the shared helper ONCE in that package.

- [ ] **Step 5: CLI surfacing test** in `cmd_move_test.go`: a zero-evidence move exits 2 with `move failed: evidence level E0 < required E2 for POSSIBLE` on stderr (the IllegalTransition handler class already does this — pin it).

- [ ] **Step 6: Green bar:** full `go test ./internal/...` (this task by definition touches many packages — it is the ONLY task running in its wave, scoped-wide on purpose), then `go run ./cmd/webv2 selftest --full`. gofmt + report (list every fixture file touched). Do NOT commit.

---

### Task 7: R3-4 — `webv2 assume` (operator half of the assumption ladder)

**Why.** The library already mutates assumption status honestly — `findings.AssumptionTransition` enforces the legal-move table and hard-resolves every `--ref` against the store (`resolveEvidenceRef`); the model boundary uses it. The OPERATOR has no verb, so a refuted blocking assumption could only be narrated (report defect 4). This task ships the thin CLI: no library change.

**Files:**
- Create: `internal/cli/cmd_assume.go`, `internal/cli/cmd_assume_test.go`
- Modify: `assets/runbook/RUNBOOK.md` (verb list + command table), then `python3 scripts/sync-asset-manifest.py` (same commit as the assets edit)

- [ ] **Step 1: Study the house shape first.** Read `internal/cli/cmd_move.go` end to end (parse struct, usage const, t14 error mapping, `--actor` handling) and `internal/findings/assumptions.go` (`AssumptionTransition` signature: `(campaign, findingID, assumptionID, toStatus string, evidenceIDs []string, actor string)`; `checkAssumptionMove` errors and `IllegalTransition`).

- [ ] **Step 2: Write the failing CLI tests** (package `cli`, using the existing runner-capture pattern from `cmd_move_test.go`):
  1. happy: after ingesting a finding with assumptions (reuse the ingest test fixtures), `assume C F A1 --status REFUTED --ref EXEC-… --actor op` exits 0, the finding file shows the new status + contradiction recorded, and a `finding.assumption_transition` event lands with `actor: op`.
  2. no refs off UNKNOWN: exit 2, stderr starts `assume failed:` and carries the library's provenance text.
  3. illegal edge (`--status UNKNOWN` from UNKNOWN): exit 2 naming the legal set.
  4. ghost ref (`--ref ART-DEADBEEF` unregistered): exit 2, store-refusal text.
  5. unknown assumption id `A9` on a 3-assumption finding: map like move maps a missing finding (the `LoadFinding`/`assumptionByID` error path, exit per move's precedent).
  6. usage: `--status` missing → required error at exit 2; `--bogus` → unrecognized; `webv2 assume -h` prints the pinned usage block.

- [ ] **Step 3: Run, verify FAIL** (unknown verb), then implement `cmd_assume.go`:
  - pinned `const assumeUsage = ...`:

```
usage: webv2 assume [-h] --status STATUS [--ref REF] [--actor ACTOR]
                    campaign finding assumption_id
```

  - parse loop with the guarded-value law; `--ref` REPEATABLE (collect `[]string`); `--actor` optional defaulting to `"cli"`; uppercase `--status` once at parse time and validate against `{"UNKNOWN","SUPPORTED","REFUTED"}`, printing the legal set on refusal (copy `verdict`'s `invalid choice` rendering).
  - dispatch: `ensureSeams()`; `state.Open`; `findings.AssumptionTransition(c, fid, aid, status, refs, actor)`; map `*findings.IllegalTransition` and the `errValue`-shaped texts to `t14ExitErr(2, "assume failed: %s\n", err)` exactly like move's handler; success prints `assumption A1: UNKNOWN -> REFUTED (evidence: EXEC-…)` to stdout.
  - `register(command{ord: <max registered + 1>, name: "assume", line: "assume <campaign> <finding> <aid> --status S [--ref R]        set an assumption's status against the store", run: ...})` — check whether `p3_args_golden.json` demands a row for every command (`go test ./internal/cli -run P3` to discover) and add it if so.
  - RUNBOOK: add the verb in BOTH the walkthrough verb list and the command table; then `python3 scripts/sync-asset-manifest.py` — `TestAssetPackManifest` passes with the regen staged into the same change.

- [ ] **Step 4: Green:** `GOCACHE=/tmp/gocache go test ./internal/cli ./internal/findings`. gofmt + report. Do NOT commit.

---

### Task 8: R3-5 — answered closures cross-check the finding (WARN) and gate the EXEC escape hatch

**Why.** Two halves, one seam family. (i) A closure that links `--finding` today never checks the finding describes THIS row — the report's arm-1 loss (G-02's row closed with a causally wrong reason quoting the row's own identifiers). We WARN (stderr) when the linked finding's mechanism shares no row symbol; we do NOT refuse (causal truth is not statically decidable — the repo's own doctrine, and refusal would fight the FP budget). (ii) `refutationBacked` EXEC refs are bare existence checks doubling as `resolveAnchor`'s escape hatch: a ref pointing at ANY exec record closes a row whose anchor it never matched, without naming which finding that exec ran for. That half gets a real refusal.

**Files:**
- Modify: `internal/planner/disposition_deferred.go` (warn), `internal/planner/answered.go` (`resolveAnchor` escape, ~394-407)
- Test: `internal/planner/*_test.go` (answered/disposition suites) + `internal/cli/cmd_answered_test.go` for the stderr surfacing

- [ ] **Step 1: Read the seams.** `checkDeferredConsequenceRow` (row-resolution + `SkipNotice` pattern), `findRow`, `RowSymbols`/`namesSymbol` in `disposition_citations.go`, `AnsweredOpts` fields (Finding/Anchor/Ref/SkipNotice), `refutationBacked`, and the exec-record shape (`internal/sandbox/exec_record.go` — optional `finding_id`).

- [ ] **Step 2: Failing tests (planner level, then one CLI).**
  - WARN: closing a probe-row priority with `--finding F-x` where F-x's `root_cause.mechanism`+`description` share no `RowSymbols(row)` token → the out-notice is set to a line naming the row anchor and pointing at `webv2 anchors` (B8 verb checks overlap mechanically); matching mechanism → no notice; no `--finding` → no notice; finding with empty mechanism → treated as no-signal, no notice.
  - REFUSE: `--anchor <field> --ref EXEC-…` where the EXEC record exists but its `finding_id` is null and no `--finding` was given → refusal containing `must name the finding it ran for (--finding)`; with `--finding F-x` → lands; with the exec record's own matching `finding_id` → lands; `INV-…` refs unaffected.
  - CLI: refuse exits 2 (`answered failed:` + sentence); WARN exits 0, notice on stderr, stdout unchanged.

- [ ] **Step 3: Implement.**
  (a) In `checkDeferredConsequenceRow`, right after `findRow` succeeds and BEFORE the `HighRiskRow` early-return (so it covers every linked closure, not just deferred-consequence ones): if `opts.Finding != nil`, `findings.LoadFinding` (pattern in `checkConsequenceFlags`), gather `root_cause.mechanism` + `root_cause.description`, zero `namesSymbol` overlap with `RowSymbols(row)` → set the notice. ~10 lines; if `SkipNotice` can already carry another notice in the same run, append — never clobber.
  (b) In `answered.go`'s escape branch: keep `refutationBacked` as existence, but when the escaping ref is an EXEC-id and differs from the rendered anchor, require `opts.Finding != nil` OR the exec record's non-null `finding_id`; refuse with `errValue`, extending the existing "must be the anchor it claims" message with the reason sentence. Upgrade `refutationBacked` into a helper that returns the parsed record (one helper, both callers — root-cause fix), reading `execs/<EXEC-ID>/exec_record.json` exactly where it already `os.Stat`s.

- [ ] **Step 4: Prove the golden does not move:** grep `scripts/golden-run.py` for `answered` steps passing `--finding`/`--ref EXEC` in an escaping combination (verifier: none do) and run `python3 scripts/check-golden.py` once (this wave may run it alone — coordinate per orchestrator).

- [ ] **Step 5: Green:** `GOCACHE=/tmp/gocache go test ./internal/planner ./internal/cli`. gofmt + report. Do NOT commit.

---

### Task 9: R3-7 — a CLOSED orphan priority discharges the audit row

**Why.** After a mid-campaign surface rebuild, priorities citing dead rows burn `audit` forever: `auditSurface` flags plan priorities whose `probe.row_id` left the surface, and NO verb can discharge them (`answered` refuses orphans at `resolveAnchor`; even a landed `blocked` closure still flags, because the flag loop ignores status). One status filter makes today's `webv2 answered C Q-207 blocked --reason 'row dropped by the surface rebuild'` the discharge verb (report defect 7).

**Files:**
- Modify: `internal/probes/audit.go` (~54-83)
- Test: the probes test file housing the `does not carry` string (grep first)

- [ ] **Step 1: Failing test** — reuse the existing audit-surface fixture builder: a plan priority `Q-007` whose `probe.row_id` is NOT in the surface. (a) priority `status: "open"` → the problem string fires (today's behavior, keep). (b) `status: "blocked"` (and `"answered"` as a second case) → no problem fires. (c) the reverse direction stays honest: a surface row with no priority still produces `never emitted`, and a CLOSED priority covering a LIVE row keeps that row out of the never-emitted arm (the emit-check loop keeps seeing ALL priorities — only the orphan loop filters).

- [ ] **Step 2: Verify FAIL.**

- [ ] **Step 3: Implement** — while building `planRows`, also record the priority's status (a second map or a struct; the loop already reads `vStr(p, "status")`-shape fields — match the file's accessor style). In the ORPHAN loop only: skip when `closedPriority[status]` hits (`closedPriority` exists in this package, `internal/probes/emit.go` — reuse, no export, no new set). Problem text for open orphans stays byte-identical.

- [ ] **Step 4: Green:** `GOCACHE=/tmp/gocache go test ./internal/probes ./internal/audit`. In the report, note whether `answered ... blocked` on an orphan lands end-to-end at HEAD (the verifier says blocked is anchor-free and closes — if a CLI probe proves otherwise, REPORT it; do not expand scope).

- [ ] **Step 5: gofmt + report. Do NOT commit.**

---

### Task 10: R3-9c — `webv2 verdict` takes `--actor` and records it

**Why.** Every other write verb carries the actor; the critic verdict — the single record the CONFIRMED gate reads — does not (`SetCriticVerdict(c, fid, verdict, reason)`; `--actor` is refused with `unrecognized arguments`). Report defect 9, item "verdict takes no --actor".

**Files:**
- Modify: `internal/cli/cmd_verdict.go`, `internal/findings` (wherever `SetCriticVerdict` lives + its event data — grep `func SetCriticVerdict` and `finding.critic_verdict`), `internal/cli/cmd_verdict_test.go`

- [ ] **Step 1: Failing tests:** (a) `verdict C F --verdict confirmed --reason R --actor op` exits 0 and the verdict event data / history row carries `actor: "op"`; (b) without `--actor`, the record keeps the historic default (`"model"` — the convention the verifier found on amend/supersede); (c) existing verdict bytes/tests: the success print gains `  actor: <who>` — update pins deliberately in the same commit.

- [ ] **Step 2: Verify FAIL, then implement.** Add the `--actor` case to `verdictArgs.parseFlags` (guarded-value law; `--actor=` form too). Thread the actor into `SetCriticVerdict` — first grep ALL callers (boundary critic sweep, CLI, tests): give the function an `actor string` parameter and update every caller explicitly (default at the call site that is genuinely a model writer, `"cli"`… NO: default `"model"` for the boundary, explicit operator value from the CLI; a bare `""` maps to `"model"` inside the setter to preserve old bytes where the field is absent). If the event schema already carries `actor` on neighboring events, reuse that key name verbatim.

- [ ] **Step 3: Green:** `GOCACHE=/tmp/gocache go test ./internal/cli ./internal/findings ./internal/boundary`. Check-golden if any captured step runs `verdict` (grep golden-run for `verdict` — if a step exists, its stdout gains the actor line: re-capture per the harness, don't hand-edit). gofmt + report. Do NOT commit.

---

### Task 11: R3-9e + R3-9d — `audit --deep` gets a heal line; `schema` help points at the taxonomy

**Why.** `webv2 audit --deep` is an exit-2 parse error while the integrity deep-sweep rides `brief --deep` (defect 9's "audit --deep is a parse error"). And `webv2 schema` cannot reach the 23-class taxonomy — by design, since classes live in `assets/taxonomy/class_weights.json`, not a schema doc; the operator just has no pointer (the `sequence_poc` half of the claim is refuted — `schema --list` prints it today; do NOT "fix" that).

**Files:**
- Modify: `internal/cli/cmd_audit.go`, `internal/cli/cmd_schema.go`, their tests

- [ ] **Step 1: Failing tests:** (a) `audit c --deep` still exits 2 but its stderr contains `webv2 brief <campaign> --deep` (the refusal names the working command — house "every refusal points at the next command" law); (b) `schema -h` help text contains a line naming `assets/taxonomy/class_weights.json` (or the `webv2 classify` discovery path) for bug classes.

- [ ] **Step 2: Implement.** `cmd_audit.go`: in the `strings.HasPrefix(a, "-")` branch, before returning the generic `usageErrf`, special-case `a == "--deep"`: return `usageErrf("unrecognized arguments: --deep — the deep integrity sweep rides the brief: webv2 brief %s --deep", pos0)` — watch precedence: argparse reports the ROOT unrecognized line; keep the shape `webv2: error: ...` consistent with how this verb already refuses unknown flags (read the current test pins first; the ONLY change is the sentence inside the same error class). Update the audit usage const to show `[--json]` unchanged (no false flag). `cmd_schema.go`: extend `schemaHelp` with one options-section-adjacent line: `bug classes are taxonomy data (webv2 classify / assets/taxonomy), not schemas`.

- [ ] **Step 3: Green** `go test ./internal/cli`; gofmt + report. Do NOT commit.

---

### Task 12: R3-9a — `amend` announces the verdict it just re-staled

**Why.** Amending a claim bumps `claim_version`, which silently stale-grades the recorded critic verdict (the boundary critic refuses a verdict pinned to an older claim) — the report's "run recall" was wrong (recalls key on row digests), but the silent staleness is real for the verdict. The class-floor note precedent already lives at the foot of `amendApply` (cmd_amend.go ~203); add its verdict twin.

**Files:**
- Modify: `internal/cli/cmd_amend.go`, `internal/cli/cmd_amend_test.go`

- [ ] **Step 1: Failing test:** amend a CONFIRMED-path finding that carries a `dedup_meta.critic_verdict` (reuse the ingest+verdict test fixtures): stderr now contains `note: the critic verdict pinned claim version <old> — re-run webv2 verdict to re-attest` exactly once when the claim_version actually bumped, and NOT on a no-op amend (same bytes → check what `findings.Amend` reports for a no-change; if it still bumps, pin the observed behavior and note it).

- [ ] **Step 2: Implement** — in `amendApply`, after the class-floor note block: the pre-amend `LoadFinding` (`pre`, already loaded above for oldClass) also gives the old verdict + old claim_version; compare against the amended `f`. Print via `fmt.Fprintf(r.Err, ...)`. One condition, no new state.

- [ ] **Step 3: Green** `go test ./internal/cli`; gofmt + report. Do NOT commit.

---

### Task 13: R3-9f — `trust_boundaries` can cite its evidence

**Why.** Protocol-model boundaries carry the evidentiary standard in the prompt ("validated:false until you have seen the code validate it") but the schema has nowhere to record the seeing — an optional `evidence` string closes the gap (defect 9's trust_boundaries item; PARTIAL verdict: refuse nothing new, just give the citation a home).

**Files:**
- Modify: `assets/schema/protocol_model.schema.json` (trust_boundaries items: add `"evidence": { "type": "string", "description": "artifact/exec id or file#lines that validated this crossing" }` to `properties`), `assets/testdata/asset_manifest.json` (regen), `internal/protocolgraph/protocolgraph.go` ONLY if it strips unknown fields on re-emit (check whether boundary rows round-trip into re-validated docs; if they do, carry the key through the same way `validated` is carried)
- Test: the protocolgraph/model-load test that builds a trust boundary — extend one case with `evidence` and assert it survives a model save/load round trip.

- [ ] **Step 1: Failing test** (a model fragment whose trust_boundaries[0] carries `evidence: "EXEC-…"` validates and round-trips).

- [ ] **Step 2: Implement** the schema key + `python3 scripts/sync-asset-manifest.py` + any carry-through in the graph code.

- [ ] **Step 3: Green:** `GOCACHE=/tmp/gocache go test ./internal/protocolgraph ./internal/validation ./internal/assets 2>/dev/null || go test ./internal/protocolgraph ./internal/validation` (find the real manifest test package via grep TestAssetPackManifest). gofmt + report. Do NOT commit.

---

### Task 14: R3-1b (light) — `webv2 env`/doctor reports the CONTAINER-facing fork RPC

**Why.** The report's ask was "stamp the pin with the answering provider"; the machine-shaped half we ship is the honest, cheap one: after Task 1, the container receives a DIFFERENT URL than the host env when the operator pinned a loopback fork — the doctor should say so, so an operator never debugs the host URL against a container failure (defect 1's diagnosis half; the pin itself is free-form JSON — no machine field to stamp; recording that as a limitation is honest).

**Files:**
- Modify: `internal/envgo/env_doctor.go` (fork section rendering), `internal/envgo/envgo_test.go`

- [ ] **Step 1: Failing test:** with `FORK_RPC_URL=http://127.0.0.1:18545`, the doctor report's fork row gains a field/line `container_url: http://host.docker.internal:18545` (call `sandbox.ContainerForkURL` — envgo already imports sandbox; no cycle). Without the env or with a non-loopback URL, output unchanged (pin that).

- [ ] **Step 2: Implement** — extend the existing fork-probe value in `env_doctor.go` (~line 56/124 region) additively; keep the host-side `ForkRPCProbe` untouched.

- [ ] **Step 3: Green:** `GOCACHE=/tmp/gocache go test ./internal/envgo ./internal/cli -run 'Env|Doctor'`. gofmt + report. Do NOT commit.

---

## Final gates (orchestrator, after all tasks are committed)

- [ ] `GOCACHE=/tmp/gocache go test ./...`
- [ ] `GOCACHE=/tmp/gocache go test -race ./internal/sandbox ./internal/findings ./internal/planner`
- [ ] `go run ./cmd/webv2 selftest --full`
- [ ] `python3 scripts/check-golden.py`
- [ ] Smoke the fork ladder end-to-end IF docker + anvil are up on this box (the report's operational block): anvil fork on :18545, `FORK_RPC_URL=http://127.0.0.1:18545`, `webv2 exec <C> --profile fork-runner --command 'cast rpc --rpc-url "$FORK_RPC_URL" eth_chainId'` → answers via the rewritten URL; a dead-port run shows the cast cause in the exec output. If docker is unavailable, record that in the triage status section (do not fake the proof).
- [ ] Update `docs/feedback-triage-morph-r3.md` with the shipped-status section (per-task commit ids).

## Explicitly NOT doing (ponytail ledger)

- No per-axis/quota "fix" (claim refuted), no class-weights data change (G3 backtest is the door), no new audit "policy" section (the artifact registry covers tamper-detection), no in-container preflight docker probe on every sequence run (the driver now fails with the cause visible; the rewrite removes the main footgun), no SetPhase transition-legality table (18 callers' blast radius for one misbehaving caller).
- `docs/IMPROVEMENTS.md` untouched per-wave; triage doc carries the status.

