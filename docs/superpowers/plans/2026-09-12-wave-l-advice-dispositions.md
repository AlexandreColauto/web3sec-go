# Wave L-advice: escalation dispositions + model-facing registry sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every minicertora UNKNOWN a *named next action* (L3 advisory form from docs/MINICERTORA_ARCHITECTURE.md §L3), and close the model-facing profile-registry drift (schemas + prompts still list five profiles; the registry has eight).

**Architecture:** Dispositions are pure data in a new `internal/harness/disposition.go`, keyed off the `reason` string embedded by the mapper in inconclusive summaries. Rendering is derived (audit sections only) — no new campaign state, no CLI stdout change, no gate weight. The registry sync extends two static JSON enums and three prompt texts to match `sandbox.Profiles` (the runtime already iterates the registry; this is a docs/schema parity fix, per final-review follow-up 1).

**Tech Stack:** Go 1.2x, stdlib only. Assets are embedded JSON schemas + markdown prompts with a Python manifest sync.

## Global Constraints

- **Go is the source of truth; golden is sacred.** Any task that moves campaign bytes is wrong by construction — the CLI stdout for existing kinds AND for minicertora must stay byte-identical (advice rides audit rendering only). `bash scripts/golden.sh` must end `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)`; never edit golden fixtures; check `ps aux | grep '[g]olden-run'` before running.
- **Every Go command needs `GOCACHE=$PWD/.gocache`** (default cache is read-only in this sandbox).
- **Embedded assets change ⇒ re-sync the manifest:** `python3 scripts/sync-asset-manifest.py` and `go test ./assets/ -count=1` (the manifest test re-hashes; hash mismatch fails loudly).
- **Surface budget:** no new verbs, no new flags in this wave. Disposition text must fit `--json`-compatible string fields and one audit line extension.
- **Fail-open law:** an unknown/unmapped reason code gets a generic advice string, never a panic, never a withheld line.
- **Closed set:** exactly 23 reason codes (minicertora cli.py `REASON_CODES`, verbatim list in Task 1). A code not in the table is "unknown", not an error.
- **Test discipline:** table tests, byte-pinned expected strings, no `t.Skip` except the ambient-libraries pattern (none needed here), no sleeps, no real binaries, no child minicertora.
- Prompt/audit wording must stay truthful with the G3 law: proved-bounded renders and informs, moves no gate.
- Commit messages: conventional style, scope `(harness|assets|audit)` matching prior wave L commits.

---

### Task 1: Disposition table — pure data (`internal/harness/disposition.go`)

**Files:**
- Create: `internal/harness/disposition.go`
- Test: `internal/harness/disposition_test.go`
- Modify: `docs/MINICERTORA_ARCHITECTURE.md:40` and `:206` (the "23 codes" claims → 25; the §L3 table gains a row)

**Interfaces:**
- Produces: `func Disposition(summary string) (class string, advice string, ok bool)` — takes the EXACT inconclusive summary string a minicertora run stored (shape `inconclusive (reason: details…)` or the fixed floor strings), returns one of the eight classes from §L3 of docs/MINICERTORA_ARCHITECTURE.md. `ok=false` only for non-inconclusive rungs' summaries and for empty input. Unknown reason codes return `(dispositionUnknown, adviceGeneric, true)` where `dispositionUnknown = "unmapped"` and `adviceGeneric = "review the spec and the tool version; the refusal names no known disposition"`.
- Also produces: `const ( EscalateBound = "escalate-bound"; EscalateFlag = "escalate-flag"; EscalateSolver = "escalate-solver"; SpecRewrite = "spec-rewrite"; HonestRefusal = "honest-refusal"; ToolError = "tool-error"; ModelBug = "model-bug"; WitnessTriage = "witness-triage" )` for tests and Task 2 consumers.
- **The closed set is 25 codes** (verbatim from `/home/xand/Projects/minicertora/minicertora/corpus/runner.py:43-68` REASON_CODES — read it yourself to confirm before coding): loop-bound-may-be-exceeded; path-limit-reached; solver-timeout; vacuous-rule; vacuous-block; malformed-spec (→spec-rewrite); unsupported-feature, unsupported-opcode, unsupported-storage-layout, rejected-feature, unrecognized-dispatcher, external-call-abstraction, summary-unverified, multi-call-ambiguous-call-site, multi-call-inner-arg-unsupported, multi-call-stmt-between-calls, invariant-uninitialized, invariant-unchecked-functions (→honest-refusal); tool-error (→tool-error); unresolved-phi-source, unresolved-branch-cond, modelling-inconsistency, solver-disagreement (→model-bug); assertion-violated, expect-revert-violated (→witness-triage; these never reach `Disposition` via a summary — the counterexample summary is an excerpt form, `counterexample: <expr>` — but they ARE in the table because they are reason codes, and consumers of `proof.reason` need their class).

- [ ] **Step 1: Write the failing test** `internal/harness/disposition_test.go`

```go
package harness

import "testing"

func TestDispositionTable(t *testing.T) {
	tests := []struct {
		name    string
		summary string
		class   string
		advice  string // "" means: assert non-empty only
		ok      bool
	}{
		{"loop bound", "inconclusive (loop-bound-may-be-exceeded: loop 4 exceeded on path 11)", EscalateBound,
			"re-run the same scaffold at --loop-bound 8, then 16, ceiling 32", true},
		{"path cap", "inconclusive (path-limit-reached: 2000 paths)", EscalateFlag, "", true},
		{"solver timeout", "inconclusive (solver-timeout: VC 12 after 30000ms)", EscalateSolver, "", true},
		{"vacuous rule", "inconclusive (vacuous-rule: pre never satisfiable)", SpecRewrite, "", true},
		{"vacuous block", "inconclusive (vacuous-block: unreachable branch body)", SpecRewrite, "", true},
		{"malformed spec", "inconclusive (malformed-spec: expected ';')", SpecRewrite, "", true},
		{"unsupported feature", "inconclusive (unsupported-feature: CREATE2 at C.f)", HonestRefusal, "", true},
		{"multi-call class", "inconclusive (multi-call-ambiguous-call-site: two calls)", HonestRefusal, "", true},
		{"tool error", "inconclusive (tool-error: bundle path /tmp/x)", ToolError, "", true},
		{"model bug", "inconclusive (unresolved-phi-source: line 44)", ModelBug, "", true},
		{"solver disagreement", "inconclusive (solver-disagreement: z3 vs cvc5)", ModelBug, "", true},
		{"unknown code", "inconclusive (something-new: details)", "unmapped",
			"review the spec and the tool version; the refusal names no known disposition", true},
		{"floor no output", "inconclusive (exit output unmapped)", "", "", false},
		{"floor not jsonl", "inconclusive (output is not JSONL)", "", "", false},
		{"floor aborted", "aborted: disk full: detail", "", "", false},
		{"floor contradiction", "inconclusive (report-contradiction: exit 0 with verdict PROVEN)", "", "", false},
		{"floor no line", "inconclusive (no verdict line for rule inv_1)", "", "", false},
		{"floor duplicate", "inconclusive (duplicate verdict lines for rule)", "", "", false},
		{"not inconclusive", "proved bounded (k=4)", "", "", false},
		{"counterexample excerpt", "counterexample: total >= before [unconfirmed: crosses a havoc'd call]", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, advice, ok := Disposition(tc.summary)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (class %q)", ok, tc.ok, class)
			}
			if !tc.ok {
				return
			}
			if class != tc.class {
				t.Errorf("class = %q, want %q", class, tc.class)
			}
			if tc.advice != "" && advice != tc.advice {
				t.Errorf("advice = %q, want %q", advice, tc.advice)
			}
			if tc.advice == "" && advice == "" {
				t.Errorf("advice empty for class %q", class)
			}
		})
	}
}

func TestDispositionCoversClosedSet(t *testing.T) {
	// every one of the 25 codes must classify to its §L3 class; one row per code.
	codes := map[string]string{
		"loop-bound-may-be-exceeded": EscalateBound, "path-limit-reached": EscalateFlag,
		"solver-timeout": EscalateSolver, "vacuous-rule": SpecRewrite, "vacuous-block": SpecRewrite,
		"malformed-spec": SpecRewrite,
		"unsupported-feature": HonestRefusal, "unsupported-opcode": HonestRefusal,
		"unsupported-storage-layout": HonestRefusal, "rejected-feature": HonestRefusal,
		"unrecognized-dispatcher": HonestRefusal, "external-call-abstraction": HonestRefusal,
		"summary-unverified": HonestRefusal, "multi-call-ambiguous-call-site": HonestRefusal,
		"multi-call-inner-arg-unsupported": HonestRefusal, "multi-call-stmt-between-calls": HonestRefusal,
		"invariant-uninitialized": HonestRefusal, "invariant-unchecked-functions": HonestRefusal,
		"tool-error": ToolError, "unresolved-phi-source": ModelBug,
		"unresolved-branch-cond": ModelBug, "modelling-inconsistency": ModelBug,
		"solver-disagreement": ModelBug,
		"assertion-violated": WitnessTriage, "expect-revert-violated": WitnessTriage,
	}
	if len(codes) != 25 {
		t.Fatalf("table has %d codes, want 25", len(codes))
	}
	for code, want := range codes {
		class, _, ok := Disposition("inconclusive (" + code + ": x)")
		if !ok || class != want {
			t.Errorf("code %q -> class %q ok=%v, want %q", code, class, ok, want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails:** `GOCACHE=$PWD/.gocache go test ./internal/harness/ -run Disposition -count=1` → compile error (undefined).

- [ ] **Step 3: Implement.** Structure: `strings.Cut(summary, " (")` guard + prefix check `inconclusive (` + trailing `)`; inner `reason, _ , _ := strings.Cut(rest, ": ")`; `switch reason` with the 25 cases and a default `"unmapped"` arm. The fixed floor/aborted strings above are NOT reason codes — they are caller/mapper plumbing; those arms return ok=false with comment: "plumbing refusals are not spec dispositions; the run never produced a verdict line". Advice strings (verbatim, one per class):
  - EscalateBound: `re-run the same scaffold at --loop-bound 8, then 16, ceiling 32`
  - EscalateFlag: `re-run the same scaffold once with --path-cap 256; if still capped, --lowering splitting`
  - EscalateSolver: `re-run once with --timeout-ms quadrupled within the exec wall-clock`
  - SpecRewrite: `the rule body proves nothing about the contract — rewrite BODY within the same scaffold (infeasible or malformed spec)`
  - HonestRefusal: `feature unprovable by this tool on this shape — record the gap, downgrade prover legs for this program, do not retry blindly`
  - ToolError: `escalate to the operator; never retried automatically`
  - ModelBug: `upstream modelling bug — harvest the report for an issue, do not re-spec around it`
  - WitnessTriage: `machine-checkable witness rides the report — triage for promotion; fork-repro the call sequence, never gate credit on the prover's model`
  - `unmapped` default: the `adviceGeneric` constant above.
  Package doc comment: dispositions are ADVISORY (§L3: named next actions, rendered where verdicts are consumed; the CLI never auto-spawns escalation execs — that stays `exec`'s job and the model's decision, budgeted).
  Doc fix in the same commit: `docs/MINICERTORA_ARCHITECTURE.md:40` `closed 23-code` → `closed 25-code`; `:206` same; the §L3 table gains two rows (witness-triage class row and the malformed-spec addition to spec-rewrite's list), marked "corrected at landing — REASON_CODES is 25, not 23".

- [ ] **Step 4: Run to verify it passes:** `GOCACHE=$PWD/.gocache go test ./internal/harness/ -run Disposition -count=1` → PASS. Then `-count=1` on the whole package (no regressions), `go vet`, `gofmt -l` empty.

- [ ] **Step 5: Commit** `git add internal/harness/disposition.go internal/harness/disposition_test.go docs/MINICERTORA_ARCHITECTURE.md && git commit -m "feat(harness): L3 disposition table — 25 reason codes to named next actions (pure data)"`

### Task 2: Audit rendering — every inconclusive minicertora line names its next action

**Files:**
- Modify: `internal/audit/sections/invariantverification.go` (the `harnessRunLine` function, ~:81-104)
- Modify: `internal/audit/audit_test.go` (or the existing test file covering harness lines; find it with `rg -ln 'harness_runs|PROVEN-BOUNDED' internal/audit/*_test.go`)

**Interfaces:**
- Consumes: `harness.Disposition(summary string) (class, advice string, ok bool)` from Task 1; the existing `harnessRunLine(iid string, e validation.Value) (string, bool)`; `objAt(objAt(e,"verification"), "harness")` gives the stored map with `summary`, `kind`, `rung`.
- Produces: same function, richer output. For rungs other than `inconclusive`, and for kinds other than `minicertora`, the returned string is BYTE-IDENTICAL to today's. Only the minicertora-inconclusive line changes shape, becoming exactly `"%s: inconclusive (%s, %s) | next: %s (%s)"` = iid, kind, exec, advice, class.

- [ ] **Step 1: Write the failing test** — add rows to the existing harnessRunLine test table (match its exact style; if the existing tests construct entries via helpers, reuse the helpers). New rows (verify the exact helper names by reading the file first):
  - halmos inconclusive → `"INV-1: inconclusive (halmos, EXEC-3)"` unchanged (existing case, re-assert);
  - forge-fuzz inconclusive → unchanged;
  - minicertora counterexample → unchanged (not inconclusive);
  - minicertora inconclusive with summary `"inconclusive (loop-bound-may-be-exceeded: x)"` → `"INV-1: inconclusive (minicertora, EXEC-9) | next: re-run the same scaffold at --loop-bound 8, then 16, ceiling 32 (escalate-bound)"`;
  - minicertora inconclusive with an unmapped reason `"inconclusive (quark-tunneling: x)"` → the adviceGeneric text with class `"unmapped"`;
  - minicertora inconclusive with a plumbing summary (floor) → NO `| next:` segment, identical to today's plain line.

- [ ] **Step 2: RED:** the minicertora rows fail with the old plain output.
- [ ] **Step 3: Implement** — inside `harnessRunLine`, after computing kind/rung/exec and the proved-bounded branch, add: `if kind == string(harness.MiniCertora) && rung == harness.RungInconclusive {` pull summary via `objStr(h, "summary")`, call `harness.Disposition`, and format the ` | next: ` suffix when ok. Import cycle check first: does `internal/audit/sections` import `internal/harness` already? `rg -n 'internal/harness' internal/audit/` — if not (sections only uses validation/jval), the alternative is a LOCAL copy call via a tiny seam: the audit package may import internal/harness ONLY if that is cycle-free (harness imports validation+jval only). If a ban exists (check for an import-boundary test listing allowed edges — `rg -ln 'forbidden import|import graph' internal/`), STOP and report BLOCKED rather than copy-pasting the table.
- [ ] **Step 4: GREEN + full package:** `GOCACHE=$PWD/.gocache go test ./internal/audit/... ./internal/harness/ -count=1`, `go vet ./internal/audit/...`, `gofmt -l` on touched files empty.
- [ ] **Step 5: Commit** `"feat(audit): minicertora inconclusive lines carry their disposition's next action"`

---

### Task 3: Registry parity — schemas + prompts + sidecar polish

**Files:**
- Modify: `assets/schema/model_response.schema.json:232-233` and `assets/schema/trajectory.schema.json:142-144` (the `execution_profile` enums; description in trajectory says "one of the five sandbox profiles the harness executes under")
- Modify: `assets/prompts/36_sandbox_isolation.md` (Profiles section, lines ~20-24), `assets/prompts/47_proposer_system.md` (~163-164), `assets/prompts/49_reproducer_system.md` (~88-92 and the "five"-ish wording at :74 context if any)
- Modify: `assets/schema/protocol_model.schema.json` — add `"required": ["tool_version","solc_version","spec_version","evm_version","confidence","reason","bounds","assumptions","warnings","ghosts"]` inside `verification.harness.properties.proof`
- Modify: `internal/harness/minicertora.go` — TWO polish items: (a) the stale `mcArr` comment near :234 that claims schema-admission; reword to "the sidecar mirrors tool values verbatim; the schema pins the key set, not the value types (post-landing contract, see IMPROVEMENTS Wave L-core)". (b) killed/timeout summary: `verifyHarnessResult`… NO — see Step 0.
- Test: `internal/validation/schema_verification_harness_test.go` (proof required-array rows), an existing boundary/ingest test file for profile acceptance (find: `rg -ln 'execution_profile' internal/boundary/ internal/roles/`), and the CLI test pinning the timeout row (update expected text — see Step 0).
- Modify after: `assets/testdata/asset_manifest.json` via the sync script.

**Interfaces:**
- Consumes: nothing from Tasks 1-2.
- Produces: prompt/schema/CLI-text parity; no Go API changes.

- [ ] **Step 0 (controller ruling, settle before writing):** the minicertora killed/timed-out summary currently renders `timeout after %ds` where N is the loop bound — a wrong unit (it's k, not seconds). New rule: when the timedOut branch maps a MINICERTORA run, the summary is exactly `inconclusive (no clean completion; loop bound was 4)` when the bound parses (invocationBound gives k), or `inconclusive (no clean completion)` when no bound was found — produced in `harnessMappedKind` via a kind check BEFORE calling MapRun's timeout path, and stored as the summary verbatim (the rung stays inconclusive, bounded_k null, proof null). halmos/forge keep their byte-pinned `timeout after %ds` untouched. Update the pinned rows accordingly: cmd_verify_minicertora_test.go timeout/killed rows (+ the Decision-2b rail tests must stay green unchanged).
- [ ] **Step 1: Failing tests first.**
  1. Validation: add a reject row proving a `proof` object missing `"warnings"` now FAILS schema validation (required array live) and keep a row proving the full 10-key object validates.
  2. Boundary/roles: add (or extend) a test that a model_response/trajectory document with `execution_profile` `"minicertora"` (and `"halmos"`, `"forge-fuzz"`) PASSES static validation, and `"vm-snapshot"` still passes, `"bogus-profile"` still fails.
  3. CLI Step 0: new pinned row minicertora + `--loop-bound 4` + exit_status -1 → summary `inconclusive (no clean completion; loop bound was 4)`; and no-bound variant (`timeout 40s` command, exit -1) → `inconclusive (no clean completion)`.
- [ ] **Step 2: RED** for all three groups.
- [ ] **Step 3: Implement.**
  - Both enums become the eight names in EXACTLY this order (match `sandbox.Profiles` declaration order): `["host-readonly", "docker-networkless", "docker-gvisor", "vm-snapshot", "fork-runner", "halmos", "forge-fuzz", "minicertora"]`. Trajectory description: `"one of the eight sandbox profiles the harness executes under"` (adjust wording if the enum order differs — READ `internal/sandbox/profiles.go` first; the declaration order IS the source of truth; if `halmos`/`forge-fuzz` precede `minicertora` there, match).
  - Prompt 36 Profiles section gains three lines after `fork-runner`:
    ```
    - `halmos` — host toolchain (symbolic checks). Ceiling: **E3**.
    - `forge-fuzz` — host toolchain (fuzz runs). Ceiling: **E3**.
    - `minicertora` — host toolchain (bounded proofs). Ceiling: **E3**.
    ```
    and the sentence after the list gains: "Host toolchain profiles (halmos, forge-fuzz, minicertora) execute on the host with read-only source access; like `host-readonly` they support evidence at or below E3." — do NOT touch the `E4+ MUST reference container/VM` law.
  - Prompt 47 §7: the profile list line gains the three names and a clause: `host toolchains (halmos, forge-fuzz, minicertora) plan symbolic/fuzz/proof legs` before the reject sentence.
  - Prompt 49 §`execution_profile`: the permitted list gains the three names, and the sentence after it states host toolchains are E3-ceilinged like `host-readonly` and require the matching tool on PATH; the E4/E5 floor sentences stay verbatim.
  - CLI: implement the Step 0 summary rule in `internal/cli/cmd_verify_harness.go` (branch on `kind == harness.MiniCertora && timedOut` BEFORE the MapRun call, produce the exact strings above with k from `invocationBound` (the same int the halmos path reads; if absent → omit the clause)).
  - `mcArr` comment reword (comment-only change).
  - Run `python3 scripts/sync-asset-manifest.py`, then verify the schema/prompt hash entries in `assets/testdata/asset_manifest.json` moved (spot check via the script's `--check` if present: `python3 scripts/sync-asset-manifest.py --check`).
- [ ] **Step 4: GREEN:** `GOCACHE=$PWD/.gocache go test ./assets/ ./internal/validation/ ./internal/boundary/ ./internal/roles/ ./internal/cli/ -count=1` (+ any prompt-embedding tests surfaced by failure). `go vet ./...`, `gofmt -l` empty.
- [ ] **Step 5: Commit** `git add -A && git commit -m "fix(assets): profile registry parity — eight enum, prompts 36/47/49; honest loop-bound timeout wording; proof required; mcArr comment"`

---

### Task 4: Close-out — battery + docs record

**Files:**
- Modify: `docs/MINICERTORA_ARCHITECTURE.md` §L3 (append a landing-status note: advisory rendering LANDED at this wave's commits; auto-spawn of escalation execs remains the operator/model's `exec`, per surface budget; `model_gaps` tally NOT built — the audit line is the gap surface).
- Modify: `docs/IMPROVEMENTS.md` Wave K section (append `Wave L-advice — LANDED (2026-09-12, commits …)` with the task list).
- No code changes.

**Interfaces:** none.

- [ ] **Step 1: Full battery in order:** `gofmt -l` empty on all touched files; `GOCACHE=$PWD/.gocache go vet ./...`; `GOCACHE=$PWD/.gocache go test ./... -count=1`; `ps aux | grep '[g]olden-run'` (must be none) then `bash scripts/golden.sh` → `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)`; `bash scripts/runbook-walkthrough.sh` → `WALKTHROUGH GREEN`; `go run ./cmd/webv2 selftest` → `ALL PASS`. If a gate fails, do not weaken the gate: report BLOCKED with the exact failing line.
- [ ] **Step 2: Docs:** append the two notes; in IMPROVEMENTS.md, mark the 6-item follow-up queue's items 1–5 as shipped (leave item 6, deferred planes, intact but annotate the L3 row "advisory form landed; see L3 note in MINICERTORA_ARCHITECTURE.md").
- [ ] **Step 3: Commit** `git commit -am "docs: wave L-advice close-out — L3 advisory landed"`.

## Self-Review (plan author)

- Spec coverage: follow-ups 1 (Task 3), 2 (Task 3 Step 0 — bounded_k stays null; the k rides proof.bounds and audit's harnessBoundK falls back to proof? — NOT in this wave; logged in the close-out note as an open polish), 3 (Task 3 Step 0), 4 (Task 3), 5 (Task 3); L3-advisory (Tasks 1-2). L5/L6/bridge/invariant-block = the separate system-wave plan (deferred, honest).
- Placeholder scan: enum order requires the implementer to read profiles.go first (declaration order is the source) — intentional, flagged in Step 3 text.
- Type consistency: `Disposition(summary)` used identically in Tasks 1 and 2; constants referenced by name.
