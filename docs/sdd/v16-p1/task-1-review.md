# Task 1 review — policy-boolean ↔ gate consistency (v1.6 P1)

Reviewer: independent task reviewer (did not write this code).
Slice: `review-4addbc03..5bcc168a.diff` — commit `5bcc168a` (Task 1) plus `be2565a2` (Task 0/P0a, out of slice; see "Cannot verify from this diff" item 4).
Read: brief, implementer report, full diff. Verified against the code in the repo, not the report.

## VERDICTS

- **SPEC COMPLIANCE: ✅** — every Step and every Produces/Consumes interface in the brief is implemented and verified; the one extra file (`bounty_test.go`) is forced by the byte-pinned-surface constraint the brief's own Step 6 mispredicted (PLAN-OMISSION, resolved in the same commit).
- **TASK QUALITY: Approved** — clean, minimal, deterministic, correctly chained, no dead code, focused tests green. Findings below are all Minor.

Findings: **Critical 0 · Important 0 · Minor 4.**

---

## Spec compliance, requirement by requirement

| Brief requirement | Verdict | Evidence |
|---|---|---|
| Step 1 — create `policy_gate_bindings_test.go` with the three directions | ✅ | `internal/bounty/policy_gate_bindings_test.go:47` (test), `:21` (schema walker), `:88` (on/off directions). Same three assertions as the brief; body restructured into two `t.Helper()` helpers (`:70`, `:88`) — behaviour identical |
| Step 1 — "in document order" comment | ✅ (corrected) | Brief text was wrong (Go map iteration is unordered); the landed comment says so: `policy_gate_bindings_test.go:19-20`. No assertion depends on order (first loop is membership-only) |
| Step 2 — re-verify all three clauses open with the falsy early return | ✅ | `gate_evidence.go:65-67` (`check6Fork`), `:82-84` (`check6Economic`), `:108-110` (`check6ExploitContract`) — all three open `if !pyTruthyBigNonEmpty(...) { return nil }`, so no existing check set moves |
| Step 3 — binding table with the three bindings | ✅ | `policy_gate_bindings.go:8-11` (struct), `:13-17` (table), byte-identical to the brief |
| Step 4 — `check6ExploitContract` + chain from `check6` | ✅ | `gate_evidence.go:103-121`; chained at `:54-60` (fork → economic → exploit-contract) |
| Step 4 — `exploit-contract` remediation entry | ✅ | `remediation.go:27` |
| Step 5 — the test passes | ✅ | `go test ./internal/bounty -run 'TestPolicyBooleansAreReferencedByTheirGate' -count=1` → `ok websec/internal/bounty 0.074s` |
| Step 6 — nothing else moved | ✅ | `go test ./internal/bounty -count=1` → ok (0.369s); `go test ./internal/orchestrator ./internal/cli -count=1` → `ok …orchestrator 1.309s`, `ok …cli 34.385s`. `TestFullSubmissionReady` still asserts 16 rows (`bounty_test.go:489-491`) and passes |
| Step 7 — one commit | ✅ | `5bcc168a`, message `feat(bounty): bind every evidence-tier policy boolean to its gate (v1.6 P1)`, body documents the deliberate surface growth |
| Produces `PolicyGateBinding{Key,Check}`, `PolicyGateBindings`, check id `exploit-contract` | ✅ | `policy_gate_bindings.go:8-17`, `gate_evidence.go:114,119` |
| Consumes: `EvaluateBountyGate`, `(*gate).add`, `BountyRemediation`, `validation.ReadSchemaFile/ObjAt/SetOrAppend`, `pyTruthyBigNonEmpty`, `checkRow`, `testPolicy`, `bountyFixture` | ✅ | All exist and are used: `bounty.go:422`, `bounty.go:41`, `remediation.go:18`, `validation/schema_enum.go` (`ReadSchemaFile` → `assets.FS.ReadFile`), `jval_alias.go:58`, `bounty/pyvalue.go:48`, `accepted_risk_test.go:31`, `bounty_test.go:24,456` |

**Extra beyond the brief (all justified, none gratuitous):**

1. `internal/bounty/bounty_test.go` — 4 insertions + 2 deletions updating the two byte-pinned catalogs (`explainGolden:1705`, `bountyRemediationGolden:1740`, `bountyRemediationOrder:1753`, `wantUnknownCheck:1756`). **PLAN-OMISSION**: the brief's file list omits this file and its Step 6 predicted PASS; the Global Constraint "gate checks carry a `BountyRemediation` entry or `gate explain` regresses" makes the edit mandatory, and the catalog is exactly `GATE_REMEDIATION ∪ BountyRemediation` (`remediation.go:58-62`). Landed in the same commit, so the slice is self-consistent. No unrelated golden text was touched (the hunk is 6 changed lines total, matching the stat).
2. The two extracted test helpers — DRY, no assertion weakened.
3. Out of Task 1 scope but inside the diff slice: `be2565a2` (Task 0/P0a — `internal/audit/part4_guard_test.go`, `internal/backtest/backtest.go`, `internal/classweights/classweights.go`, `internal/wilson/wilson.go`). Per `progress.md` Task 0 was already controller-reviewed; not re-reviewed here (see "Cannot verify from this diff" item 4).

**Global constraints:** stdlib only ✅ (no `go.mod` in the diff); asset manifest ✅ (no `assets/` file touched — `git show --stat 5bcc168a`); schema discipline ✅ (the boolean already exists at `assets/schema/bounty_policy.schema.json:110`; nothing new is written to a policy document); ledger law ✅ (no new mutation — the gate's existing `bounty.gate` event is unchanged); determinism pins ✅ (no `time.Now()`/UUID in the new code); byte-pinned CLI surfaces ✅ (no new verb, no help text; `internal/cli` green); gate-check remediation ✅ (`remediation.go:27`, auto-attached to a fail row by `bounty.go:47-54`); audit sections / helper duplication / no-mainnet ✅ N/A.

---

## Findings

### Critical (Must Fix)

None.

### Important (Should Fix)

None.

### Minor (Nice to Have)

**M1 — the new clause's FAIL branch (the refusal the task exists to add) has no test (PLAN-MANDATED).**
The standard fixture always carries a runnable-contract item — `fixtureConfirmed` mints `foundry-test`/`E4` (`bounty_test.go:402-405`) and `fork-test`/`E5` (`:406-409`), and `findings.LoadFinding` is real, not a seam (`bounty.go:424`; no `LoadFinding` in `seams.go`) — so `check6ExploitContract` takes the pass branch (`gate_evidence.go:113-116`) on every call the binding test makes. No test anywhere sets `require_exploit_contract` on a finding that lacks such evidence (`rg -n "require_exploit_contract" .` → schema, `gate_evidence.go`, `policy_gate_bindings.go`, docs only), so the fail row (`gate_evidence.go:119`) and its blocker text (`:120-121`) are executed by nothing.
Why it matters: that refusal is the whole point of the Phase 1 exit criterion ("a policy can demand a runnable exploit contract today and the gate will pass a finding that has none"), and its blocker string is user-facing (it lands in `blocking_reasons`). A regression that made the clause fail-open, or that corrupted the blocker text, would keep the suite green.
Not a bug today: I traced the branch — with no `foundry-test`/`fork-test` item the loop completes and falls through to `:119-121`, so the refusal is reachable and correct.
Fix (cheap): one case with a policy that sets the boolean and a finding whose evidence is only `manual`/`reasoning`, asserting `result == "fail"` and the blocker text. Worth knowing while fixing it: the ON assertion is result-agnostic (`policy_gate_bindings_test.go:90` checks only `row.Kind != validation.Null`), so it would stay green even if the clause always failed — the binding is pinned, the verdict is not. The brief mandated the binding test verbatim, so this is a plan-level coverage gap, not implementer error.

**M2 — the clause matches the evidence TYPE string only; it does not require the item to trace to a SUCCEEDED exec (PLAN-MANDATED).**
`internal/bounty/gate_evidence.go:111-117` passes on any evidence item whose `type` is `foundry-test`/`fork-test`, where the sibling `mainnet-fork-poc` check requires a fork-test tracing to a PROVEN, SUCCEEDED fork-runner exec (`internal/orchestrator/status.go:276-283`, `internal/bounty/bounty_test.go:1745` — "unit tests prove semantics; only the fork proves mainnet"). `exec_ref` is OPTIONAL on an evidence item (`assets/schema/finding.schema.json:1210-1213`).
Why it matters: the clause is documented as "a RUNNABLE exploit contract a triager can execute"; a type-only match is a proxy for that.
Mitigation I verified (this is why it is Minor, not Important): the ingest write path refuses E4+ evidence that does not trace to a real, exit-0, output-carrying EXEC (`internal/findings/ingest_evidence_gate.go:92-140`), and the schema says so in the `exec_ref` description itself ("`ingest` attaches the item through the SAME gate and item shape `mint` uses — the ledger must hold the exec, it must have SUCCEEDED (exit 0 with captured output)"); `amend` only copies already-verified items into a successor (`internal/findings/amend.go:208-222`). The code is the brief's snippet verbatim.

**M3 — the schema walker is hard-scoped to `poc_requirements`.**
`internal/bounty/policy_gate_bindings_test.go:21-45` reads only `properties.poc_requirements.properties`, so a future evidence-tier boolean added anywhere else in `bounty_policy.schema.json` would not be caught by the criterion.
No hole today: I enumerated every `"type": "boolean"` in `assets/schema/bounty_policy.schema.json` — `exclusions[].case_sensitive`, `accepted_risks[].case_sensitive`, `acceptance_priors`, `auto_tune`, `severity_rules[].match.require_invariant_violation` (read at `internal/bounty/policy.go:165`), and the three under `poc_requirements` (`:108-110`). Only the last three name an evidence tier, and all three are bound. The scoping matches the plan's own wording; noting it so the constraint is a conscious choice.

**M4 — the brief's interface line misnames the 4th parameter, and the call site silently inherits it.**
Brief (`task-1-brief.md:12`) and plan (`docs/superpowers/plans/2026-09-21-v16-p1-p2-record-and-evidence.md:82`) write `EvaluateBountyGate(..., dryRun bool)`; the real parameter is `save bool` (`internal/bounty/bounty.go:422-423`). `policy_gate_bindings_test.go:78` therefore passes `true` = **save**, not dry-run (the implementer reported this as deviation 3 — verified). Harmless here (fresh `t.TempDir()` campaign per call, and the package's other tests do the same), but the call site carries no comment, so the next reader inherits the wrong name.
Fix: a one-line comment at `:78` (`// 4th arg is save, not dry-run`), or fix the plan text.

---

## Cannot verify from this diff

1. **The red phase (brief Step 2).** The report's "build fail → exactly two predicted errors → PASS" is a process claim with no artifact in the slice. Structurally certain for the first half (the test references `PolicyGateBindings` before Step 3 exists), but the intermediate failure text is not reproducible from the diff. Controller has the TDD evidence.
2. **Authorship inside commit `5bcc168a`.** The report says the controller, not the implementer, wrote the `bounty_test.go` golden update. One commit, one author line (`AlexandreColauto`) — the diff cannot distinguish the two hands. Process only; the content is correct and required.
3. **Whether every write path that can append an evidence item enforces the E4+ exec trace.** I checked the ingest gate (`ingest_evidence_gate.go:92-140`) and `amend` (`amend.go:208-222`); `internal/findings/ingest.go:292-305` and `ingest_evidence.go:66` were not traced to their guards (outside this task's diff). This only matters for M2's severity, which is Minor either way.
4. **Task 0 / P0a (`be2565a2`, 4 files, 163 lines).** Inside the review slice but outside Task 1's brief; `progress.md` records it as already controller-reviewed. Not assessed here — the controller should not read my ✅ as covering it.
5. **Whole-branch effects beyond `bounty`/`orchestrator`/`cli`.** I ran only those three packages plus the focused tests; the controller's full-suite green at this commit is taken as given per the review method.

---

## Strengths

- **The consistency test is a real gate, not a label.** The OFF direction (`policy_gate_bindings_test.go:95-97`) is the part that would catch "the check always runs" — exactly the failure mode the criterion exists for, and it is asserted rather than assumed.
- **The schema walker reads the EMBEDDED schema** (`validation.ReadSchemaFile` → `assets.FS.ReadFile`), so the test cannot drift from the shipped schema, and it `t.Fatal`s if the walk finds no `poc_requirements.properties` (`:34-36`) instead of silently passing on an empty set.
- **Zero blast radius, verified rather than asserted.** All three clauses open with the falsy early return (`gate_evidence.go:65-67`, `:82-84`, `:108-110`); the only non-doc files naming `require_exploit_contract` are the schema (`assets/schema/bounty_policy.schema.json:110`), `gate_evidence.go:103,108` and `policy_gate_bindings.go:16` — no fixture or testdata policy sets it (`rg -n "require_exploit_contract" . --glob '!.git' --glob '!node_modules'`); `TestFullSubmissionReady` still counts 16 rows and the orchestrator oracles are untouched.
- **The remediation is executable, not decorative.** Every flag it names exists: `exec --profile docker-networkless` (`internal/sandbox/profiles.go:35-36`, `internal/cli/cmd_exec.go:58-69`), `exec --finding` (`cmd_exec.go:163`), `mint --type foundry-test` (`cmd_mint.go:54`), and `<campaign>` is substituted by `findings.NameCampaign` (`bounty.go:49-53`).
- **Fail rows cannot be un-remediated.** The binding test asserts a `BountyRemediation` entry per binding (`:60-62`) and `(*gate).add` auto-attaches it on a non-pass row (`bounty.go:47-54`) — the two halves of the Global Constraint, both covered.
- **The four byte-pinned surfaces moved together and byte-exactly**: `TestBountyRemediationCatalogByteExact` and `TestGateExplainCatalogByteExact` pass, and the new id sits in correct sorted position in `wantUnknownCheck` (`bounty_test.go:1756`, `exploit-contract` after `evidence-sufficient`) and in source order in `bountyRemediationOrder` (`:1753`).
- **Hygiene**: `gofmt -l` on all five touched files → empty; `go vet ./internal/bounty` → clean; the new file is 17 lines, the test 98 — nothing large was created.
- The implementer stopped at the Step 6 false prediction instead of silently rewriting pinned goldens, and documented all three deviations in the report — the deviations are accurate (I re-verified each).
