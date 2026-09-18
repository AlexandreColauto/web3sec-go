# Task 1 review — exec-relevance gate for invariant-verify (d9da3428..55be2c2e)

**Spec compliance: YES**
**Task quality: APPROVED with findings** (1 Important, 2 Minor — none blocking the commit)

Reviewer ran the focused tests (`go test ./internal/invariants -run ExecTouches`,
`go test ./internal/cli -run 'InvariantVerifyExec|InvariantVerifyRefusesUntargetedExec|InvariantVerifyAcceptsTargetedExec|InvariantVerifyArtifact|InvariantVerifyDiscloses'`),
a throwaway registry probe (created, run, deleted — tree left clean), and the
verbatim Step 0 probe. No tracked changes, no full-suite rerun.

## 1. Spec compliance matrix

| Binding requirement | Verdict | Evidence |
|---|---|---|
| Exported `ExecTouchesInvariant(c, invID, execID) (bool, string)`, additive, three reasons | PASS | `invariants.go:961`; reasons `no-exec-record` / `no-command-record` / `no-target-match` all pinned |
| Left-boundary matcher: case-insensitive, boundary = start or prev char ∉ `[0-9a-z_]`, **no trailing boundary** | PASS | `tokenOccursLeftBound` `invariants.go:1028-1048`; overlap-correct scan (`from = at+1`) finds a later boundary occurrence after a glued one |
| Brief test table: direct / camel `StakingTest` / `src/Staking.t.sol` accept; `Unstaking` / `OracleTest` / `forge test` reject; `EXEC-missing` → `no-exec-record` | PASS (ran) | `invariants_exec_relevance_test.go:34-68`, all green in my run |
| Quote stripping before matching | PASS | `stripShellQuotes` `invariants.go:1056` (whole command, one layer — exactly the brief's wording); pinned with `'forge test --match-contract Staking'` |
| Empty `applies_to` refuses (`no-target-match`), never wildcard | PASS (ran) | `appliesToTokens` returns empty → loop falls through; `TestExecTouchesInvariantEmptyAppliesTo` green |
| The invariant id itself must NOT satisfy the gate | PASS | `appliesToTokens` (`invariants.go:999`) uses applies_to **alone**; `TestExecTouchesInvariantIgnoresInvariantID` pins `--match-contract INV-003`/`INV-3`/`src/INV-003.t.sol` all refused — the §6-flagged bypass is closed and adversarially pinned |
| Two-gate ordering: exec-relevance after `resolveExecArtifact`, before `VerifyInvariantStatement` writes anything | PASS | `cmd_invariant_verify.go:98-107` — exactly the brief Step 3 wording |
| Bypass combinations covered both ways | PASS | Untargeted exec + invariant-naming log → refused by new gate (`TestInvariantVerifyRefusesUntargetedExec`, relCamp's suite exec log names INV-3); targeted exec + generic log → still refused by Task 4 byte gate (relevance-gate case (b), `does not reference INV-008`); honest rerun lands. Both directions pinned |
| Refusal: exit 2, exact refusal text, status UNVERIFIED, zero new `invariant.verified` events, no attestation label | PASS (ran) | `cmd_invariant_verify_exec_relevance_test.go:52-82` asserts all five, incl. the explicit event-absence loop; text matches the brief's template verbatim |
| Task 4 matcher byte-identical | PASS | `git diff d9da3428..55be2c2e -- internal/invariants/invariants.go` is a **pure insertion** (zero deleted lines); `artifactReferencesInvariant` still compiles `(?i)\b…\b` at `invariants.go:898` |
| Variadic helpers do not perturb Task 4 pins | PASS | `testExec`/`invExecRecord`/`execCamp`/`t15SeedInvariant` defaults reproduce the exact previous records (no `applies_to` key, same command strings); unbound `execCamp` callers (`exec_test.go:220,248,267,292,305`) all refuse inside `resolveExecArtifact` before the gate; `t15ExecRecord`'s unconditional command change has exactly one caller (`TestInvariantVerifyExec`, migrated); artifact-path tests (`TestInvariantVerifyArtifact*`, `…DisclosesOperatorAttestation`) use `t15Register`, not the seeder — green in my run |
| Fixture law change honestly documented | PASS | Commit body names both law changes (empty applies_to refuses; relevance-gate part (a) re-pin with the Task 4 byte-gate pin **retained** as case (b)), the empirically confirmed 5-test blast radius, and the helper-variadic strategy. Report §12 shows the reverted-fixture red run; logs present in `task-1-logs/` |
| No golden pin moved / historical fixtures untouched | PASS | Diffstat: 7 files, none under `scripts/legacy`, `web3sec-final`, `morph`; `scripts/golden.sh` never invokes `invariant-verify` (rg exit 1, verified); `task-1-logs/step5-golden.txt` = GOLDEN GREEN; `gofmt -l internal cmd` clean (re-run) |

## 2. Findings

### Important

**F1. A refused citation still mints an artifact row whose note asserts a check happened.**
`resolveExecArtifact` (`cmd_invariant_verify.go:175-181`) calls `c.RegisterOrRefresh("other",
outPath, "invariant INV-3 checked against code (exec EXEC-…)")` **before** the gate at :102
runs. I verified empirically (throwaway probe test against `relCamp`): after the refusal, the
campaign state carries a new `kind:"other"` artifact row with note `invariant INV-3 checked
against code (exec EXEC-0000000002)` — a durable record saying the invariant was checked, from a
citation the gate just refused. This contradicts the brief Step 1 prose "leaves the registry
untouched", and it is exactly the defect-6 spirit (records asserting verification that didn't
happen). Mitigations, both real: the brief's own Step 3 mandates "after artifact resolution, call
the gate", so the implementer followed the letter of the spec and the contradiction is the
brief's, not theirs; and the behavior is pre-existing for Task 4 byte-gate refusals on the `--exec`
path, so nothing regressed. Not pinned anywhere: `TestInvariantVerifyRefusesUntargetedExec`
asserts status/verified_by/verification_method/events but not registry absence.

**Concrete fix** (follow-up task, not a re-open of this one): hoist the relevance check to just
above the `RegisterOrRefresh` call — either split `resolveExecArtifact` into validate + register
and run `ExecTouchesInvariant` between them, or move it inside `resolveExecArtifact` after the
exec-record validation — then add an assertion to `TestInvariantVerifyRefusesUntargetedExec`
that `objAt(c.State(), "artifacts")` gains no row naming the invariant. Also fix the brief prose
to match whichever ordering the operator blesses.

### Minor

**F2. `appliesToTokens` widens the token set beyond the brief's literal "applies_to tokens".**
`invariants.go:999-1013` adds `NormalizeInvID(t.S)` alongside each raw token. For contract names
this is inert (`NormalizeInvID` is the identity for anything without the `INV-` prefix,
`invariants.go:1106-1123`), but an invariant whose `applies_to` literally contains e.g. `INV-03`
would now be exec-satisfiable by `--match-contract INV-3` — a canonical-spelling accept the brief's
binding semantics does not authorize. It mirrors Task 4's `referenceTokens` convention, so it is
defensible, but it is an unbriefed semantics choice made silently (report §11 mentions it only in
passing). Fix: drop the normalized variant or add one sentence to the `appliesToTokens` doc
comment stating why canonical spellings are in scope, so the next reviewer doesn't have to
re-derive it.

**F3. Step 0 probe number drifts and is un-reproducible as stated.** The report records `210`;
the verbatim probe on the committed tree returns `212` (+1 from the new `EXEC-0000000002` suite
record line in `cmd_invariant_verify_exec_test.go:335`, +1 from `execCamp`'s hoisted default
command line). Immaterial to the outcome (the controller already ruled the literal count is a
mentions-not-fixtures artifact), but the report presents 210 as the Step 0 result without noting
it was measured pre-migration and is not the committed tree's number. Fix: one clause in the
report ("210 at pre-flight; 212 on the committed tree — drift from the fixture migration, both
mentions-not-fixtures noise").

## 3. Cannot-verify items

- **Full-suite gates accepted from logs, not re-run** (per instructions): `go test ./...`,
  `go vet ./...`, `scripts/golden.sh` results rest on `task-1-logs/step5-{gotest-all,vet,golden}.txt`.
  The logs exist, are internally consistent, and I independently re-verified the two claims they
  underwrite that matter most here (Task 4 pins green in the focused run; golden.sh cannot touch
  `invariant-verify`). The 196-step golden replay itself was not re-executed.
- **Red-run transcript authenticity** (`task-1-logs/step2-red.txt`, `step0-blast-radius-confirmed.txt`):
  not independently reproducible without reverting fixtures (a tracked change). The 5-test blast
  radius is consistent with my static walk of the `execCamp` call sites and the gate's placement,
  so I have no reason to doubt it, but I did not witness it.
- **`state.AllExecs` ordering/failure modes** were taken from the report and the
  `resolveExecArtifact` twin loop (`cmd_invariant_verify.go:138-149`, same lookup shape, pinned by
  existing tests) — not audited at the `state` layer.
