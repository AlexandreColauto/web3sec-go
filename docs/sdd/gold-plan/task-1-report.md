# Task 1 report — exec-relevance gate for `invariant-verify` (defect 6)

**STATUS: BLOCKED** (at Step 0, per the brief's own tripwire — no code written, no commit)

## 1. Identity

| | |
|---|---|
| Worktree | `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness` |
| Branch | `production-readiness` |
| BASE (HEAD, unchanged) | `d9da34285b644e320e206694c18c546d6e664021` |
| Brief | `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-1-brief.md` (read in full, first action) |
| Go | go1.26.6 linux/amd64 |
| Commit | **none** — Step 0 tripped before Step 1 |
| Repo state | HEAD still `d9da3428`; only untracked additions are this report + `task-1-logs/` |

## 2. Step 0 — pre-flight fixture blast radius (the blocker)

Command, verbatim from the brief:

```
rg -n "forge test\b" internal/ --glob '*_test.go' --glob '!*_exec_relevance_test.go' | rg -v "match-contract|match-path" | wc -l
```

Raw output: **`210`**

The brief's rule: *"if the count exceeds ~20, STOP and report before proceeding; the operator
decides whether to split the task."* 210 ≫ 20 → **STOP**, reported here. Full transcript with
per-file breakdown: `task-1-logs/step0-preflight.txt`.

### 2.1 Composition — the literal count is mostly noise

The pipeline counts *every* `forge test` mention in any test file, not "fixtures that close an
invariant with an untargeted suite exec". Of the 210 matching lines, only **6** mention an
invariant at all (`invariant|INV-`). The rest are unrelated uses:

- `internal/sandbox/envseam_test.go` (21 lines) — the failure-classifier table, all `"forge test"` command strings
- `internal/sandbox/sandbox_test.go` (9), `ext_test.go` (3), `solcdir_test.go` (1) — policy/preview/argv tests
- `internal/bounty/bounty_test.go` (4), `internal/validation/schema_profile_enum_test.go` (1) — remediation-text and schema-enum literals
- `internal/trajectory`, `internal/sharedmem`, `internal/sequencepoc`, `internal/boundary`, `internal/planner`, `internal/forkpoc`, `internal/immunize`, … — PoC/fork/repro fixtures that never touch `invariant-verify`

Top offenders: `internal/harness/zz_r32_test.go` (30), `internal/cli/cmd_verify_harness_test.go` (24),
`internal/sandbox/envseam_test.go` (21).

### 2.2 The real blast radius (static analysis, recorded so the operator can decide fast)

The gate lands in the **CLI only** (`cmd_invariant_verify.go`), so direct
`VerifyInvariantStatement` callers (`internal/invariants/*_test.go`, `internal/roles`,
`internal/state`, `internal/reproduction`, `internal/orchestrator`, `internal/audit`) are
**unaffected**. The affected set is small in files but is a genuine fixture migration, not a
5-minute fix:

**Tests that currently assert exit 0 on the `--exec` path and would be refused:**

1. `TestInvariantVerifyExecHappyPath` — `cmd_invariant_verify_exec_test.go:107`
2. `TestInvariantVerifyExecRerunRefreshesTheSameArtifact` — `:136`
3. `TestInvariantVerifyExecFallsBackToTheStderrLog` — `:182`
4. `TestInvariantVerifyExecRelevanceGate` (part b) — `:320`
5. `TestInvariantVerifyExec` — `cmd_invariant_verify_test.go:150`

Why they break — both halves of the binding rule fire at once:

- The fixtures seed invariants **without `applies_to`** (`t15SeedInvariant`,
  `cmd_invariant_verify_test.go:23`; `SeedFromModel` defaults it to `[]` at
  `internal/invariants/invariants.go:426,765`). The brief's ruling is explicit: empty
  `applies_to` is *unbound → unverifiable*, so every one of these returns
  `(false, "no-target-match")`.
- The recorded commands are untargeted even ignoring that: `invExecRecord` writes
  `forge test --match-test test_liveness` (`cmd_invariant_verify_exec_test.go:53`) and
  `t15ExecRecord` writes exactly **`forge test`** — the whole-suite run the gate exists to reject
  (`cmd_invariant_verify_test.go:57`).

**Fixture-helper migration is coupled beyond the exec tests.** `t15SeedInvariant` is shared by the
`--artifact`-path tests (`TestInvariantVerifyArtifact`,
`TestInvariantVerifyArtifactRelevanceGate`, `TestInvariantVerifyDisclosesOperatorAttestation`,
`TestInvariantVerifyUnknownIDExits2OneLine`). Adding `applies_to` there changes the token set the
**Task 4** artifact-bytes gate matches against, so the "just tweak `execCamp`" fix is not clean —
the migration should add a new applies_to-bearing seed helper for the exec tests rather than
mutate the shared one.

**One pinned assertion collides semantically.** `TestInvariantVerifyExecRelevanceGate` part (a)
(`:333`) pins the Task 4 refusal text `does not reference INV-008`. The brief puts the new gate
*before* `VerifyInvariantStatement`, so that run now exits 2 with the **new** text
(`does not target any applies_to contract of INV-008 (no-target-match)`). The test's stderr
assertion must move — a deliberate change to a pinned 1:1 Python-port test, i.e. exactly the
"operator decides" case.

Unaffected on that path: `TestInvariantVerifyExecUnknownExecExits2` (fails in
`resolveExecArtifact`, before the gate), `TestInvariantVerifyExecIncompleteExecExits2`,
`TestInvariantVerifyExecWithoutCapturedOutputExits2`, `TestInvariantVerifyRequiresOneOption`,
`TestInvariantVerifyRejectsBothOptions`, `TestInvariantVerifyExecUnknownInvariantExits2`, and
`zz_r44a_test.go:145,153` (expect exit 1 from an unreadable store, resolved earlier).

**Golden:** `scripts/golden.sh` never invokes `invariant-verify` (`rg` exit 1), so no golden pin
should move. `scripts/golden.sh` does run a `gofmt -l internal cmd` gate first.

## 3. Steps 1–5 — not performed

| Step | State | Reason |
|---|---|---|
| 0 pre-flight | **DONE** | count = 210 → tripwire → STOP |
| 1 failing tests | not started | blocked at Step 0 |
| 2 red run | not started | no test files written |
| 3 implement gate | not started | no production file touched |
| 4 green + package gates | not started | — |
| 5 full gates + commit | not started | no commit; HEAD still `d9da3428` |

Per the brief, this is a *stop before proceeding*, not a weakened gate: nothing was relaxed,
nothing was implemented half-way, and no fixture was silently migrated. The gate design in the
brief is untouched and remains implementable exactly as specified.

## 4. Red / green transcripts

**None exist, and that is the honest answer** — Step 0 tripped before TDD began, so no test file
was authored and no `go test` was run for this task. Rather than paste a fabricated transcript,
here is the verification that nothing changed:

- `git rev-parse HEAD` → `d9da34285b644e320e206694c18c546d6e664021` (BASE, unchanged)
- `git status --porcelain` → `?? .superpowers/` only — the plan directory (brief + this report +
  logs) is untracked in this worktree; no tracked file is dirty (`git diff --stat` empty)
- No file under `internal/` was created or modified; `internal/invariants/invariants_exec_relevance_test.go`
  and `internal/cli/cmd_invariant_verify_exec_relevance_test.go` **do not exist**.
- `scripts/legacy`, `web3sec-final`, `morph` — untouched (historical fixtures, no read, no write).

## 5. Gate exit codes

Step 5's gates (`go test ./... -count=1`, `go vet ./...`, `scripts/golden.sh`) were **not run** —
running them would only measure a tree that the task did not modify, and `golden.sh` is a long
179-step replay. Logged instead are the Step 0 evidence commands and their exit codes, in
`task-1-logs/`:

| Log | Content | Exit |
|---|---|---|
| `task-1-logs/step0-preflight.txt` | the verbatim Step 0 command, raw output `210`, per-file breakdown, unrelated-match sample | pipeline 0; `wc -l` = 210 |
| `task-1-logs/step0-true-blast-radius.txt` | the true affected test/fixture set, `applies_to` defaulting proof, the colliding pinned assertion, golden check | `rg scripts/golden.sh` = **1** (no match ⇒ no golden pin moves) |

## 6. Matcher provenance (read as the brief's Interfaces section requires)

The brief instructs: read what the Task 4 `referenceTokens` matcher actually does before
implementing, reuse it if it is already left-boundary, otherwise add a **new named helper** and do
not move Task 4's pinned semantics. Finding:

- `referenceTokens` (`internal/invariants/invariants.go:913`) only builds the **token list** — the
  invariant id in registry + canonical spelling, plus every `applies_to` string likewise, deduped,
  empties dropped.
- The **matching** lives in `artifactReferencesInvariant` (`invariants.go:888`, the compile at
  `:898`): `regexp.Compile("(?i)\\b" + regexp.QuoteMeta(tok) + "\\b")` — a **full `\b…\b`
  word-boundary** match, i.e. exactly rejected-alternative (a) in the brief.

**Verdict: NOT left-boundary ⇒ reuse is impossible.** The brief's required path applies:
implement a new helper `tokenOccursLeftBound(command, token string) bool` (case-insensitive,
left boundary = position 0 or preceded by a char outside `[0-9a-z_]`, no trailing boundary,
shell quotes stripped), document in its comment that it intentionally differs from the Task 4
matcher, and leave `artifactReferencesInvariant` byte-identical so Task 4's pinned refusals
(`INV-20` must not satisfy `INV-2`, etc.) do not move.

**Second provenance finding, needs an operator ruling.** `referenceTokens` **prepends the
invariant id** to its token list, so it cannot be dropped into `ExecTouchesInvariant` — the brief
scopes the gate to the `applies_to` tokens only. Reusing `referenceTokens` as-is would let
`forge test --match-contract INV-3` satisfy the gate for `INV-3` (a command naming the *bookkeeping
id*, not the contract), which is an unreviewed hole the brief's test table does not cover. The
implementation should build its token list from `applies_to` alone (raw + `NormalizeInvID`, deduped,
empties dropped) rather than call `referenceTokens`. Flagged, not decided, because it is a
semantics choice the brief leaves implicit.

## 7. Artifacts produced by this task

- `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-1-report.md` (this file)
- `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-1-logs/step0-preflight.txt`
- `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-1-logs/step0-true-blast-radius.txt`

No commit, no push, no merge, no delegation.

## 8. What unblocks the task

One ruling from the operator:

1. **Proceed as written** (recommended if the reading below matches intent) — the literal 210 is a
   pipeline artifact, not a blast radius: 204/210 lines are unrelated `forge test` literals, and the
   true migration is **5 CLI tests + 2–3 fixture helpers + 1 pinned stderr assertion**, all inside
   `internal/cli`, with no golden movement. I can then do Steps 1–5 as a single commit, with the
   fixture migration called out in the commit body.
2. **Split the task** — gate implementation in one commit, fixture migration in a second, so the
   pinned Python-port test changes are reviewable on their own.
3. **Tighten the Step 0 probe** — if the intent was to count *invariant-closing* fixtures, the
   pipeline needs narrowing to the `invariant-verify --exec` path. Note the naive one-liner
   `rg -n 'invariant-verify.*--exec' internal/cli/*_test.go` reports **0** (the `--exec` argument
   sits on the following line in every fixture), so the narrowed probe must be multi-line-aware;
   my verified enumeration of the exec-path tests that expect exit 0 is the **5 named in §2.2**.

Also worth a ruling: whether empty `applies_to` should really refuse (the brief says yes,
consistently with Task 4) — it is what turns 5 currently-green tests red, and it is the part of the
migration that is a *law* change rather than a fixture tidy-up.

## 9. Concerns

- The brief's Step 0 probe measures mentions, not fixtures; its 210 would trip the `~20` tripwire on
  this repo even though the gate's true blast radius is ~5 tests. A future revision of the brief
  should use a narrowed probe, otherwise the tripwire is guaranteed to fire and the task can never
  start.
- The fixture migration is not the "5-minute fix if small" branch: it must (a) introduce
  `applies_to` seeding without disturbing the Task 4 artifact-path tests that share
  `t15SeedInvariant`, and (b) re-pin `TestInvariantVerifyExecRelevanceGate` part (a)'s stderr text,
  which changes a test ported 1:1 from `tests/test_attention_ledger.py`.
- `referenceTokens` prepending the invariant id is a latent trap for whoever implements
  `ExecTouchesInvariant` (see §6); reusing it would create a `--match-contract INV-3` bypass.
- I did not empirically confirm the 5-test failure set by implementing the gate: doing so would
  have meant proceeding past the tripwire the brief told me to stop at. The set is static analysis
  of fixtures and call sites, and should be re-confirmed by the red run in Step 2.

---

# Task 1 report, part 2 — implementation (supersedes the BLOCKED status above)

**STATUS: COMPLETE** — one commit, all gates green. The §1–§9 above are the *pre-ruling* record
(Step 0 tripwire, matcher provenance, static blast radius) and stand as written; the controller
ruling lifted the tripwire (the literal 210 is a probe artifact; the true radius is the pre-flight
number) and fixed the four decisions this section implements.

## 10. Identity

| | |
|---|---|
| Worktree | `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness` |
| Branch | `production-readiness` |
| BASE | `d9da34285b644e320e206694c18c546d6e664021` |
| Commit | **`55be2c2e9ab279b13d57926502e00fd7e75d2094`** — `fix(invariants): exec-relevance gate for invariant-verify (defect 6)` |
| Files in the commit | 7 (5 listed by the brief + the 3 fixture helpers it did not anticipate; 2 new tests) |
| Push / merge / delegation | none |

```
internal/invariants/invariants.go                          | 121 ++
internal/invariants/invariants_exec_relevance_test.go      | 140 ++ (new)
internal/invariants/invariants_test.go                     |  12 +-
internal/cli/cmd_invariant_verify.go                       |  10 ++
internal/cli/cmd_invariant_verify_exec_relevance_test.go   | 100 ++ (new)
internal/cli/cmd_invariant_verify_exec_test.go             |  71 +-
internal/cli/cmd_invariant_verify_test.go                  |  34 +-
```

`scripts/legacy`, `web3sec-final`, `morph`: `git diff --stat d9da3428..HEAD --` over all three is
empty — untouched, never read or written.

## 11. What the gate is (ruling 3 in full)

`invariants.ExecTouchesInvariant(c, invID, execID) (bool, string)` (`invariants.go:952`), additive,
signature exactly as the brief binds it:

- `state.AllExecs` lookup by `exec_id` → `"no-exec-record"` when absent (and when the exec store
  cannot be read: a store that cannot be read names no exec, so it fails closed);
- `command` read from the record; missing/non-string/empty → `"no-command-record"`;
- tokens built from **`applies_to` alone** via `appliesToTokens` (raw + `NormalizeInvID`, deduped,
  empties dropped) — the invariant id is **not** in scope, per ruling 3;
- `tokenOccursLeftBound(command, token)`: case-insensitive, match at position 0 or preceded by a
  byte outside `[0-9a-z_]` (`isLowerWordByte`), **no trailing boundary**;
- `stripShellQuotes` removes one layer of matching surrounding quotes first;
- no token matches → `"no-target-match"`, which is also the answer for an empty `applies_to`.

CLI (`cmd_invariant_verify.go:98`): the gate is called **after** `resolveExecArtifact` and **before**
`VerifyInvariantStatement`, and on refusal prints exactly

```
invariant verify failed: cited exec <ID> does not target any applies_to contract of <invID> (<reason>)
```

and returns 2. Deliberately not `PyReprStr`-wrapped: the brief's pinned substring
`does not target any applies_to contract of INV-3` must survive, and repr would quote the id.

**Matcher provenance verdict (unchanged from §6, now implemented):** reuse was impossible —
`artifactReferencesInvariant` compiles `(?i)\b…\b`, and `referenceTokens` prepends the invariant
id. So `tokenOccursLeftBound` is a new named helper whose comment states why the two matchers
intentionally differ, and the Task 4 matcher is byte-identical (verified: the only edit to
`invariants.go` is the +121-line insertion after `irrelevantArtifact`).

The §6-flagged `--match-contract INV-3` bypass is now **closed and pinned**:
`TestExecTouchesInvariantIgnoresInvariantID` seeds `INV-003` bound to `Staking` and requires
refusal for `--match-contract INV-003`, `--match-contract INV-3` and
`--match-path src/INV-003.t.sol`. Against a `referenceTokens`-based implementation all three would
be accepted, so the pin is real, not decorative.

## 12. Blast radius — confirmed empirically (was §2.2 static analysis)

The report's prediction is now measured, not inferred. With the gate implemented and the fixture
migration temporarily reverted (`execCamp` unbound + untargeted, `t15ExecRecord` back to
`forge test`, `TestInvariantVerifyExec` unbound), `go test ./internal/cli -run InvariantVerify`
fails **exactly 5** tests and no more:

```
--- FAIL: TestInvariantVerifyExecHappyPath                    (exit 2, no-target-match)
--- FAIL: TestInvariantVerifyExecRerunRefreshesTheSameArtifact(exit 2, no-target-match)
--- FAIL: TestInvariantVerifyExecFallsBackToTheStderrLog      (exit 2, no-target-match)
--- FAIL: TestInvariantVerifyExecRelevanceGate                (exit 2, no-target-match)
--- FAIL: TestInvariantVerifyExec                              (exit 2, no-target-match)
```

Transcript: `task-1-logs/step0-blast-radius-confirmed.txt`. The fixtures were restored from
`.scratch/keep-{exec,verify}-test.go` immediately afterwards; the restored tree is what was
committed. So the true blast radius is the pre-flight number (5 tests + 3 shared helpers), and the
brief's literal 210 measured mentions, not invariant-closing fixtures — as the controller ruled.

## 13. Red → green

**Red (before implementation)** — `task-1-logs/step2-red.txt`:

```
# websec/internal/invariants [websec/internal/invariants.test]
invariants_exec_relevance_test.go:67:17: undefined: ExecTouchesInvariant      (×6)
FAIL	websec/internal/invariants [build failed]
--- FAIL: TestInvariantVerifyRefusesUntargetedExec   exit = 0, want 2
--- FAIL: TestInvariantVerifyExecRelevanceGate       untargeted exec: exit 0, want 2
FAIL	websec/internal/cli
```

The failure mode is the defect itself: with no gate, the suite exec is **accepted** (exit 0,
`operator attestation recorded`). `TestInvariantVerifyAcceptsTargetedExec` was green in the red run
by construction — it is the positive pin that must never be broken by the gate.

**Green (after implementation)** — `task-1-logs/step4-focused-green.txt`:
`ok websec/internal/invariants`, `ok websec/internal/cli` for
`-run 'ExecTouches|InvariantVerifyExec|InvariantVerifyRefusesUntargetedExec|InvariantVerifyAcceptsTargetedExec'`.

## 14. Gates (Step 5), all exit 0

| Gate | Command | Log | Exit |
|---|---|---|---|
| vet | `go vet ./...` | `task-1-logs/step5-vet.txt` | 0 |
| tests | `go test ./... -count=1` | `task-1-logs/step5-gotest-all.txt` | 0 (no `FAIL`, no `panic:`) |
| golden | `scripts/golden.sh` | `task-1-logs/step5-golden.txt` | 0 — `GOLDEN GREEN: Go run validates` (196 steps) |
| fmt | `gofmt -l internal cmd` | — | empty (one blank-line violation was found and fixed before commit) |

No golden pin moved, as §2.2 predicted (`scripts/golden.sh` never invokes `invariant-verify`).
Env used verbatim: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod
GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`.

## 15. The two deliberate law changes (ruling 2 and ruling 4)

1. **Empty `applies_to` refuses the exec path** (`no-target-match`). This is the part that turned
   green tests red: an invariant bound to nothing cannot be exec-verified, matching Task 4's
   pinned empty-applies_to law. Pinned in `TestExecTouchesInvariantEmptyAppliesTo`.
2. **`TestInvariantVerifyExecRelevanceGate` part (a) re-pinned.** Its old assertion pinned the
   Task 4 text `does not reference INV-008`; the exec-relevance gate now runs first, so part (a)
   asserts `does not target any applies_to contract of INV-008 (no-target-match)` instead. The
   Task 4 `--exec` byte-gate pin was **not** dropped — it is kept as case (b) of the same test
   (targeted exec + generic log → `does not reference INV-008`), so both laws stay pinned on the
   `--exec` path. Both changes are reasoned in the commit body.

Fixture migration (the "5-minute fix" branch of the brief): `t15SeedInvariant`, `execCamp`,
`invExecRecord` and `testExec` each take an optional trailing `appliesTo`/`command` variadic that
defaults to the exact previous behavior, so the Task 4 artifact-path tests that share
`t15SeedInvariant` (`TestInvariantVerifyArtifact`, `TestInvariantVerifyArtifactRelevanceGate`,
`TestInvariantVerifyDisclosesOperatorAttestation` — verified call sites at
`cmd_invariant_verify_test.go:108,125,244`; note §2.2's list wrongly included
`TestInvariantVerifyUnknownIDExits2OneLine`, which uses `t15Register`, not the seeder) plus the ~15
other callers in `zz_r*`, `cmd_verify*` are byte-for-byte unperturbed — their entries stay unbound,
exactly as `seed_from_model`'s `applies_to: []` default left them.

## 16. Concerns / limits

- The gate reads the **recorded command string**, so its honesty is bounded by the exec ledger's:
  a forged or `sh -c`-wrapped record is out of scope (the brief's matcher semantics govern).
- `ExecTouchesInvariant` has no error return (the brief binds the signature), so an unreadable
  registry or exec store is folded into `no-target-match` / `no-exec-record` — fail closed, but the
  caller cannot distinguish "store broken" from "nothing matched". In the CLI flow this is
  unreachable: `resolveExecArtifact` reads both first and exits 1 on a store error (pinned by
  `TestR44aInvariantVerifyRefusesUnreadableExecStore`, still green).
- `tokenOccursLeftBound` implements the brief's literal `[0-9a-z_]` alphabet byte-wise, so a
  non-ASCII character before a token counts as a boundary. Not pinned and not reachable with
  Foundry-style ASCII contract names; noted rather than guessed at.
- Part (a) of the relevance-gate test now refuses *before* the artifact is byte-checked, so the
  Task 4 byte gate is exercised there only via case (b) — intentional, but it means the two gates'
  ordering is now itself load-bearing and should stay pinned if the order ever changes.
- `TestInvariantVerifyExecWithoutCapturedOutputExits2`, `…IncompleteExecExits2`,
  `…UnknownExecExits2`, `…UnknownInvariantExits2`, `TestInvariantVerifyRejectsBothOptions` and
  `TestInvariantVerifyRequiresOneOption` still use the *unbound* `execCamp` fixture on purpose:
  they refuse inside `resolveExecArtifact`, before the gate, so migrating them would have hidden
  the ordering this task pins.
