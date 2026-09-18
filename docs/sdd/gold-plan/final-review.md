# Final whole-plan review — gold-findings closure (`d9da3428..bc80d151`)

**Role:** last gate before the plan is declared complete. Independent read-only review of
the whole plan execution (Tasks 1-5 + two fix rounds); no tracked changes.

**Inputs used:** plan v2 (`docs/superpowers/plans/2026-09-18-gold-findings-closure.md`),
`progress.md` ledger, all five per-task reviews + both fix-round re-reviews, the full
diff (`git log --oneline d9da3428..bc80d151`, diffstat, then file-level reads of
`internal/invariants/invariants.go`, `internal/cli/cmd_invariant_verify.go`,
`internal/planner/plan.go`, `internal/orchestrator/plan.go`, `internal/briefing/briefing.go`,
`internal/findings/levels.go`, `scripts/eval-gold.py`, `docs/eval/morph-rerun-protocol.md`,
`assets/schema/campaign_plan.schema.json`, and the in-range plan-doc edits).

## Gates re-run at HEAD (`bc80d151`), this session

| Gate | Result |
|---|---|
| `go test ./... -count=1` (repo cache convention) | **exit 0** — all packages ok |
| `go vet ./...` | clean (exit 0) |
| `python3 -m unittest scripts.eval_gold_test` | **26/26 OK** |
| `scripts/golden.sh` | not re-run; inherited GREEN from the Task 3 reviewer's reproduction at `280e348d` — **no Go file changed after `280e348d`** (8b2886ec/e28efeed are scripts+tests-only, 99e7e906/bc80d151 docs-only), so golden coverage state is byte-identical at HEAD |

The seven commits are clean, exactly-staged, and in plan order: `55be2c2e` (T1) →
`3c095827` (T2) → `280e348d` (T3) → `8b2886ec` (T4) → `99e7e906` (T5) → `e28efeed` (T4 fix 1)
→ `bc80d151` (T5 fix 1). Historical fixtures (`scripts/legacy/`, `web3sec-final/`, `morph/`)
untouched across the whole range. One schema file widened (`campaign_plan.schema.json`
id pattern `^(Q|LC)-[0-9]{3}$`) with the manifest hash resynced — necessary for Task 2's
mandated `LC-%03d` ids, strictly additive (Task 2 review verified `X-001`/bare ids still fail).

---

## 1. Verdict per plan task

### Task 1 — exec-relevance gate (defect 6) — **implemented as specified** (one open residue: P1)

Verified first-hand against the diff:

- `invariants.ExecTouchesInvariant(c, invID, execID) (bool, string)` exported, additive, three
  pinned reasons (`no-exec-record` / `no-command-record` / `no-target-match`); empty `applies_to`
  refuses (`no-target-match`), never wildcard; store-read failures fail closed.
- `tokenOccursLeftBound` implements the binding left-boundary spec exactly (case-insensitive,
  boundary = start or prev byte ∉ `[0-9a-z_]`, **no trailing boundary**, overlap-correct scan
  `from = at+1`); quote stripping is one layer, whole command. The Task 4 matcher
  (`artifactReferencesInvariant`) is byte-identical — the `invariants.go` diff is a **pure
  insertion**, zero deleted lines.
- The §6-flagged INV-3 bypass is closed: `appliesToTokens` uses `applies_to` **alone** (the
  invariant id is deliberately out of scope, adversarially pinned).
- CLI half: exit 2, exact refusal text, status `UNVERIFIED`, empty `verified_by` /
  `verification_method`, explicit `invariant.verified` event-absence loop — all pinned in
  `cmd_invariant_verify_exec_relevance_test.go`.

The **P1 residue** (gate runs after `resolveExecArtifact`'s `RegisterOrRefresh`) is real —
confirmed by direct read: `cmd_invariant_verify.go:97-107` places the gate after
`resolveExecArtifact` returns, and `resolveExecArtifact:175-183` mints the artifact row with
note `invariant INV-3 checked against code (exec EXEC-…)` before returning. The plan itself is
internally contradictory here (Step 1 prose "leaves the registry untouched" vs Step 3 "after
artifact resolution, call the gate"); the implementer followed Step 3's letter, and the
committed refusal test does not assert registry absence (so the prose assertion the plan
demanded was silently dropped). Triage in §3 — **fix before merge**.

### Task 2 — adversarial-lifecycle surfaces mint into the work queue (defect 4) — **implemented as specified**

- The mint correctly lives in `planner/plan.go` (`bootstrapLifecycleSurfaces`, called LAST in
  `DefaultPlanFromModel` so no pre-existing Q-number moves), with the
  `orchestrator.AdversarialLifecycleMachines` re-export satisfying the plan's documented
  interface despite the import cycle — the only shape that satisfies both.
- Cardinality rule (≥2 distinct vocabulary tokens across machine name + transition triggers),
  left-boundary matcher (duplicated with the same pinned spec, as the plan explicitly permits),
  sorted names, `LC-%03d` positional ids with name-as-handle documented everywhere.
- Dedup scope is the ENTIRE minted queue (`b.priorities` re-read per iteration) + live findings
  + the coverage ledger's swept test, with exact component matching (not substring) — matches
  the plan's binding dedup law.
- Schema widening + manifest resync: necessary (the plan's own id-scheme law made the old
  `^Q-…` pattern unimplementable), additive, `assets` tests green.
- No golden pin references an LC-id by value (repo grep: definition + one prefix assertion only).
- Two deviations, both adjudicated in the task-2 review: machine-name-as-component (the brief's
  `applies_to`-on-machines instruction was unimplementable — machines have no such field) and
  the schema widening. Both correct.

### Task 3 — evidence reachability line (defect 5) — **implemented as specified**

- All three contract symbols exist with exact signatures: `findings.ClassConfirmFloor`
  (real-map value, `E5` default), `findings.ReachableLocally` (ladder-index compare, unknown
  cap/class → false, matching `LevelIndex`'s refusal), `briefing.ReachabilityLine` (reachable
  first / fork second, each alphabetized, one class per clause with its own floor, exact
  byte-pinned clause text, empty-list → `""`, all-reachable and all-fork omission rules pinned).
- Rendering position pinned exactly: `reachIdx == coldIdx + 1` after the Task 11 cold-probe
  warning; mint is gated on `campaign != nil` + a non-empty open-class set (Task 7 law fixtures
  stay clean); advisory only — no gate/proof/phase transition reads it (repo-verified).
- Floor map read from the REAL `CLASS_CONFIRM_FLOOR` (Step 0 done properly: `dos-griefing: E4`,
  `share-price-inflation: E6`, unknown → `E5`); `levels.go` diff is additive, no map bytes moved.
- `boxLocalCap = "E4"` constant: ruled COMPLIANT (plan premise false — envgo exports no
  accessor; a live `docker info` probe would violate the pure-view architecture; the constant
  equals every isolated profile's recorded ceiling). Ponytail hook names the upgrade path.

### Task 4 — offline gold scorer — **implemented as specified** (fix round closed all findings)

- Decision table fully pinned: found/missed, FP count semantics, `pass`/`bonus` independence
  (from FPs and from `--confirm`), verdict chain incl. the FP-budget boundary, `verdict_note`
  rules, advisory-only `operator_confirmed`, all exit-2 paths with clean stderr, line-by-line
  JSONL, tree-hash non-mutation.
- The campaign-dir contract was corrected in-commit exactly as the plan's own correction clause
  directs (`findings/F-*.json`, real field spellings) — the plan doc edit is in the same commit.
- Fix round 1 (`e28efeed`) closed MEDIUM-1 (exact at-budget `10 → PARTIAL_RESULT` fixture,
  mutant-proven: `<=` mutation fails exactly the two boundary tests), LOW-2 (dead
  `INVESTIGATING` branch now honestly documented against the real schema enum), LOW-3 (bonus
  short-circuit pinned with 10 FPs → `PASS_WITH_BONUS`, empty note pinning the branch order).
  Real-benchmark × real-campaign reproduction (0/2, exit 0) was reviewer-reproduced live.

### Task 5 — re-run protocol — **implemented as specified** (fix round closed F-1/F-2/F-3; one open residue: N-1)

- All six mandatory sections, no placeholders; fresh-release requirement with the archived log
  demoted to script-works evidence; contamination-first with machine-global/CI caveats; three
  expected gate firings quoted verbatim from source; scoring invocation pinned with the
  documented `$WEB3SEC2` path-base deviation; honesty rules and out-of-scope complete.
- Fix round 1 (`bc80d151`) closed F-1 (schema-valid skeleton, byte-verified against a real run),
  F-2 (zero-coverage synthesis vs partial-coverage refusal, with a complete pasteable
  partial-coverage variant), F-3 (test count 26 — matches this session's run).
- **N-1 is still open at HEAD** (found by the task-5 fix review, not yet addressed): see
  finding F-A below — **fix before merge**.

---

## 2. Findings (whole-plan pass, ordered by severity)

### F-A — IMPORTANT — must fix before merge — protocol §3.2-1's quoted refusal is unreachable in the doc's own sequence

`docs/eval/morph-rerun-protocol.md:167-199` (open at `bc80d151`, carried from
`task-5-fix1-review.md` as N-1; confirmed present at HEAD by direct read — no
fresh-campaign qualifier exists anywhere in §3.1/§3.2-1).

The doc's §3.1 skeleton load takes the zero-coverage synthesis path and mints a
`liveness-template` invariant numbered `INV-1` covering `rollup_finalization`. An operator who
then loads §3.2-1's variant into the same campaign gets its `INV-1` (`applies_to:
["message_queue"]`) colliding with the template's `INV-1` — refreshed in place, `applies_to`
never lands — so coverage is `{rollup_finalization}`, the uncovered set is `{message_queue}`,
and the refusal names **`message_queue`**, not the doc's quoted
`state machine(s) rollup_finalization have no liveness invariant`. The G-01 payoff line
("If the uncovered machine is `rollup_finalization`, the gate has just named the G-01 gap")
then fails in the natural in-sequence flow, even though the doc labels its outputs
"verbatim from a scratch campaign". (The task-5 fix reviewer reproduced this twice; the gate
fires and exits 2 either way — no claim outside §3 is affected.)

**Fix (one line):** state in §3.2-1 that the variant must be loaded in a **fresh campaign**
(the §3.1 load's synthesized template covers `rollup_finalization` in the same campaign), or
show the in-sequence `message_queue` refusal as the expected output. Optionally add the same
qualifier to the §3.1 skeleton's "loads, exit 0" block.

### F-B — IMPORTANT — must fix before merge — refused citations still mint a "checked against code" artifact row (P1)

`internal/cli/cmd_invariant_verify.go:97-107` (gate) vs `:175-183` (`RegisterOrRefresh` inside
`resolveExecArtifact`); the mint precedes the gate on every `--exec` path, including the
relevance refusal.

Why this crosses the must-fix bar at the whole-plan gate (and why the Task 1 reviewer's
"park as follow-up" is upgraded here):

1. The minted note — `invariant INV-3 checked against code (exec EXEC-…)` — is a durable
   record asserting a verification the gate just refused. That is the exact defect-6 class
   ("records asserting verification that didn't happen") this plan exists to close; leaving it
   in at plan completion means the plan closes with a live instance of its own target defect.
2. It contradicts the plan's own Step 1 contract ("leaves the registry untouched — assert ALL
   of …"); the committed test drops that assertion, so the spec gap is silent.
3. The fix is small, local, and provably pin-free: hoist the mint to the tail of
   `resolveExecArtifact`, running `invariants.ExecTouchesInvariant(c, invID, execID)` just
   before it and refusing there. Every earlier refusal (unknown invariant, missing exec,
   incomplete/refused exec, no captured output) happens before the mint and is unaffected;
   **no existing or new test asserts registry state on any refusal path**, so nothing moves.
   Then add the assertion the plan's Step 1 prose already demands to
   `TestInvariantVerifyRefusesUntargetedExec`: no artifact row naming the invariant after a
   refused citation.

**Fix sketch:** in `resolveExecArtifact`, after the `isFile(outPath)` check and before the
`RegisterOrRefresh` call:

```go
if ok, reason := invariants.ExecTouchesInvariant(c, invID, execID); !ok {
    fmt.Fprintf(r.Err, "invariant verify failed: cited exec %s does not "+
        "target any applies_to contract of %s (%s)\n", execID, invID, reason)
    return "", 2
}
```

and delete the gate block from `runInvariantVerify` (the refusal text is identical, so no pin
moves; the check still runs before `VerifyInvariantStatement` writes anything). Add the
registry-absence loop to the refusal test.

**Residual (park, do not expand this task):** after this fix, a Task 4 byte-gate refusal on the
`--exec` path (targeted command, generic log) still mints — `VerifyInvariantStatement` runs
after the mint. That behavior predates this plan (Task 4) and its refusal pins live elsewhere;
moving the mint behind `VerifyInvariantStatement` entirely is the fuller fix and belongs in the
same follow-up that eventually re-homes it, not in this closure wave.

### Seam audit (Task 1 gate × Task 2 queue minting × Task 3 brief line) — no further defects found

- The three features operate on disjoint stores and axes (invariant-verify CLI refusal path /
  plan build at mint time / brief rendering at view time) and share no state; the only
  cross-task interaction found is F-B itself (Task 1's mint ordering).
- Task 2's minted row text (`review adversarial lifecycle … (commit → challenge → finalize) —
  no covering finding`) never passes through the Task 7 no-parens law: it is row `question`
  text, not a `webv2Action` reason; if it is ever wired into next-actions as a command line,
  `noParens` already handles the parentheses.
- Task 3's reachability line renders independently of Task 2's rows and never embeds a command
  (pure prose carve-out verified); its `openFindingClasses` terminal filter is real
  (`findings.IsTerminal` in `openFindingClasses`) — only the test comment overclaims it (D4).
- Task 2 × Task 4: the scorer reads findings/events only; plans are not an input — no
  interplay. Task 1 × Task 5: the protocol's quoted refusal text matches the implemented
  format string verbatim (fix reviewer verified byte-equal against a real run).
- Operator-surface note (observation, not a finding — already adjudicated COMPLIANT in the
  task-2 review): the minted LC row reaches the operator via `plan --json` / the attention
  queue (and via promoted probe rows in next-actions), not as a first-class next-actions line.
  Defect 4's law ("becomes the next action") is carried by `work_queue[0]` + score/slot. If the
  cockpit brief is ever extended to render unattempted queue rows directly, that is the natural
  home for it.

### Minor observations (no action required)

- **M-1:** the in-range plan-doc edit (Task 4 §4, `99e7e906`) still says "25 tests" while the
  protocol doc and the suite now say 26 (`e28efeed` added one). The plan doc is a historical
  artifact of its own execution; noted only so a future reader doesn't read drift into it.
- **M-2:** `ReachabilityLine`'s `cap` parameter shadows the builtin — plan-mandated signature,
  body never uses the builtin, vet clean. Leave it.
- **M-3:** `boxLocalCap` is pinned only behaviorally (rendered bytes imply E4); the envgo
  accessor wiring will touch it anyway (D6's follow-up).

---

## 3. Triage of parked/deferred items

| Item | Ruling | Reasoning |
|---|---|---|
| **P1** — refusal fires after `RegisterOrRefresh` (Task 1 F1 Important) | **FIX BEFORE MERGE** → F-B above | Upgraded from parked: contradicts the plan's own Step 1 contract, mints the exact defect-6 dishonesty record, fix is ~10 lines + one test assertion and provably moves no pin. |
| **N-1** — protocol §3.2-1 in-sequence refusal mismatch (Task 5 fix-round Important) | **FIX BEFORE MERGE** → F-A above | One-line doc edit; the doc is a primary plan deliverable and labels the outputs "verbatim" — an operator following §3.1→§3.2-1 in one campaign gets a different machine named and the G-01 payoff line fails. |
| **D1** — `trajectories` enum quirk (`["lifecycle"]` renders `["code"]`) | **PARK** | Pre-existing by construction (`TrajectoryToEnum` keyed on long spellings; `queue.go` untouched by this range; affects every short-named plan row equally). Fixing moves pinned oracle rendering repo-wide. Defect-4 substance rides score/slot, not the tag. Future-task material. |
| **D2** — `appliesToTokens` adds `NormalizeInvID` variants | **PARK** | Inert for contract names (`NormalizeInvID` is the identity without an `INV-` prefix); widens acceptance only when `applies_to` literally contains `INV-xxx` — mirrors Task 4's `referenceTokens` convention. Optional one-sentence doc-comment addition, fold into the F-B fix wave if touching the file anyway. |
| **D3** — Step 0 probe drift 210 vs 212 | **PARK** | Report-annotation nit only; the count is mentions-not-fixtures noise, measured pre-migration vs committed tree; zero code impact. One clause in the report if the ledger is ever amended. |
| **D4** — `task14_reachability_test.go:245-247` comment overclaims a terminal-finding pin | **PARK** (may fold into F-B's fix wave) | LOW; the production behavior is real (`IsTerminal` filter in `openFindingClasses`) — only the documented pin is missing. Cheap fix if the wave is open: append a terminal class-bearing finding case or drop the clause. |
| **D5** — LC-id schema description note | **PARK** | Doc nit in the schema's `id` property description; no consumer reads it; the name-as-handle law is documented at every code site that matters. |
| **D6** — `boxLocalCap` constant instead of envgo read | **PARK** | Ruled COMPLIANT (plan premise false; live probe would violate the pure-view architecture). Cleaner follow-up = pure, non-probing accessor over `profileMaxLevel`; the `ponytail:` hook is in place. Not this plan. |
| **I1** — scorer `MIN_KEYWORD_HITS=3` quorum calibrated synthetic-only | **PARK** | Disclosed at every layer (report concern 3 + `ponytail:` in code + task-4 review ruling). No real finding exists to calibrate against; the FP budget and `--confirm` are the human layer; the first fresh re-run finding is the calibration datum — that is Task 5's protocol doing its job, not a defect. |

Net: **zero** of the parked items block merge on their own; the two must-fix items are P1 and
N-1 (both already discovered by the per-task reviews — no new blocking seam defect was found).

---

## 4. Final plan-level verdict

**PLAN COMPLETE PENDING TWO SMALL FIXES — not yet declarable as-is.**

Every task was implemented as specified, with each deviation either directed by the plan's own
correction clauses (Task 4's store contract, Task 5's invocation path base) or adjudicated as
compliant against a factually false plan premise (Task 3's cap accessor, Task 2's mint
location and schema widening). Both fix rounds closed all their findings with mutant- or
byte-level evidence. The global constraints held across the whole range: stdlib only, no new
module deps, historical fixtures untouched, no golden pin moved (and no LC-id pinned by
value), exact-path staging, refusal semantics never weakened, golden re-pin tags unnecessary
because no pin moved.

What stands between the branch and "plan complete" is two must-fix items, both small and both
inherited from the per-task reviews rather than newly discovered here:

1. **F-B** (from Task 1's parked F1, now upgraded): hoist the mint behind the exec-relevance
   gate and pin registry absence on refusal — closes the plan's last internal contradiction
   and its last live instance of the defect-6 record class.
2. **F-A** (from Task 5's fix-review N-1): one clarifying line so §3.2-1's quoted refusal is
   reproducible in the sequence the doc itself prescribes.

After those two land (one Go commit + one doc commit, or one combined fix commit; focused
tests + `go test ./... -count=1` + the 26-test scorer suite are sufficient re-verification —
no golden coverage is touched by either fix), the plan should be declared complete and the
operator's re-run session (Task 5's protocol) is the next and final actor.

**Gates at HEAD this session:** `go test ./... -count=1` exit 0 · `go vet ./...` clean ·
`python3 -m unittest scripts.eval_gold_test` 26/26 OK · golden green inherited (no Go change
since the last GREEN reproduction).


