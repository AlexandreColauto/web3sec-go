# Task 4 — Evidence relevance binding on invariant-verify

**Worktree:** `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
(branch `production-readiness`; main checkout untouched, nothing pushed)
**Plan:** `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` — header,
Global Constraints, Task 4 (incl. the Step 3 word-boundary amendment)
**Toolchain:** go1.26.2 linux/amd64; `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod
GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomodcache`

## 1. The law as implemented

`VerifyInvariantStatement(c, invID, artifactID)` now refuses to flip any invariant to
`CHECKED_AGAINST_CODE` unless the **cited artifact's bytes** name what it verifies:

* token set = the invariant id (registry spelling **and** `NormalizeInvID` canonical
  spelling) ∪ every `applies_to` string of the registry entry (raw **and** canonical);
* every token is `regexp.QuoteMeta`-escaped and matched as `(?i)\b<token>\b` —
  case-insensitive, word-bounded (so `INV-20`, `INV-22`, `recheckINV-2`, `INV-2x`
  never satisfy `INV-2`);
* no token match, or bytes that cannot be read → refusal with the plan's exact text:

```
artifact <id> does not reference <inv> (nor its applies_to) — cite a check that names what it verifies (invariant-verify with --exec <id> re-registers stdout as the artifact)
```

Order of operations is unchanged otherwise: unknown artifact → unknown invariant →
relevance gate → existing mutate/`LinksThenLog`/unwind flow untouched. Nothing is
written and no `invariant.verified` event is logged on a refusal.

## 2. Files changed (exact paths)

| File | Change |
| --- | --- |
| `internal/invariants/invariants.go` | gate in `VerifyInvariantStatement`; new `artifactReferencesInvariant`, `referenceTokens`, `irrelevantArtifact`; `regexp` import |
| `internal/state/artifacts.go` | exported one-line wrapper `func (c *Campaign) ResolveArtifactPath(a validation.Value) string` |
| `internal/invariants/invariants_test.go` | 7 new gate tests + fixture updates (below) |
| `internal/invariants/guard_test.go` | fixture updates (`INV-2` artifact bytes; `guardCamp` writes the file) |
| `internal/invariants/zz_r40d_test.go` | fixture update (r40d artifact names INV-1) |
| `internal/roles/roles_test.go` | fixture update (`inv-check.md` names INV-1) |
| `internal/audit/p1_sections_test.go` | fixture update (`evidence.md` names INV-1) |
| `internal/cli/cmd_invariant_verify_test.go` | new `t15RegisterCheck`, `TestInvariantVerifyArtifactRelevanceGate`; `t15ExecRecord` stdout names INV-1; `TestInvariantVerifyArtifact` uses the honest helper |
| `internal/cli/cmd_invariant_verify_exec_test.go` | new `TestInvariantVerifyExecRelevanceGate` (end-to-end `--exec`); honest stdout/stderr fixtures |
| `internal/state/artifacts_test.go` | new `TestResolveArtifactPath` (wrapper ≡ internal seam, abs + relative) |
| `scripts/verify-full.sh` | P1/P2/P3 artifact fixture `note.md` now names INV-1 (fixture-necessity proven, §6) |
| `scripts/golden/artifact.md` | golden artifact now names INV-2 (fixture-necessity proven, §6) |

No other file was touched. `scripts/runbook-walkthrough.sh` and
`scripts/legacy/campaigns/*` are **unchanged** (see §6).

## 3. TDD evidence

### 3.1 RED — before the implementation

```
$ go test ./internal/invariants -run 'TestVerify' -count=1
--- FAIL: TestVerifyRefusesIrrelevantArtifact (0.00s)
    invariants_test.go:974: expected error containing "does not reference", got nil
--- FAIL: TestVerifyRefusesNearMissInvariantID (0.00s)
    invariants_test.go:1030: expected error containing "does not reference INV-2", got nil
--- FAIL: TestVerifyEmptyAppliesToDoesNotBypass (0.00s)
    invariants_test.go:1092: expected error containing "does not reference INV-2", got nil
--- FAIL: TestVerifyAcceptsRegistrySpellingOfZeroPaddedID (0.01s)
    invariants_test.go:1135: expected error containing "does not reference INV-002", got nil
--- FAIL: TestVerifyRefusesUnreadableArtifact (0.01s)
    invariants_test.go:1151: expected error containing "does not reference INV-2", got nil
FAIL	websec/internal/invariants	0.037s

$ go test ./internal/cli -run 'TestInvariantVerify' -count=1
--- FAIL: TestInvariantVerifyExecRelevanceGate (0.01s)
    cmd_invariant_verify_exec_test.go:331: generic output: exit 0, want 2 ("")
FAIL	websec/internal/cli	0.084s

$ go test ./internal/state -run TestResolveArtifactPath -count=1
internal/state/artifacts_test.go:423:13: undefined: ResolveArtifactPath
FAIL	websec/internal/state [build failed]
```

The two *accept* tests (`TestVerifyAcceptsRelevantArtifact`,
`TestVerifyAcceptsAppliesToArtifact`) pass before and after — they are the regression
half of the law (an honest artifact must never be refused).

### 3.2 GREEN — after the implementation

```
$ go test ./internal/invariants ./internal/cli ./internal/roles ./internal/audit -count=1
ok  	websec/internal/invariants	0.242s
ok  	websec/internal/cli	29.185s
ok  	websec/internal/roles	0.429s
ok  	websec/internal/audit	0.220s
EXIT=0
```
(log: `.scratch/sdd/task-4-logs/gate-4packages.txt`)

```
$ go test ./... -count=1          # background job bash-13, exit code 0
ok  	websec/internal/cli	32.431s
ok  	websec/internal/completion	0.672s
... (60 packages, all ok) ...
ok  	websec/internal/state	11.679s
ok  	websec/internal/wilson	0.004s
?   	websec/scripts/archive/oq3check-main.go.txt	[no test files]
[status: completed, exit code: 0]
```

```
$ go vet ./...
EXIT=0
```
(log: `.scratch/sdd/task-4-logs/gate-vet.txt`)

`gofmt -l internal cmd` → empty.

### 3.3 Golden pins (Global Constraints)

```
$ bash scripts/golden.sh                # job bash-14, exit code 0
golden run complete: campaign C-34c0ce6f4b (196 steps, Go-only)
tree: campaign C-34c0ce6f4b well-formed (180 events, chain intact; 99 files archived)
steps: 196 commands (declared nonzero: gate-h1=1, gate-h3=1, ...), 5 with declared output markers
step 07 audit-json: 14 audit sections + ok (ok=True) present
step 164 audit-json-final: 15 audit sections + ok (ok=True) present
GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)
```
The golden recipe's `invariant-verify INV-2 --artifact <art[0]>` step is one of the 196
steps whose declared exit code (0) was validated — it passed **only** because
`scripts/golden/artifact.md` now names INV-2 (§6 proves the old bytes are refused).

```
$ bash scripts/runbook-walkthrough.sh   # job bash-15, exit code 0
[PASS] §cheat invariant-verify            exit=0
...
walkthrough: 150 passed, 0 failed
WALKTHROUGH GREEN: every RUNBOOK command matched its documented behavior
```
The runbook row cites `scripts/golden/h1-withdraw-double-count.json` as the artifact for
INV-1. That file needs **no change**: it contains `"path": "src/Vault.sol"` / `"contract":
"Vault"`, and the entry's `applies_to` is `["Vault"]`, so the word-bounded,
case-insensitive token `Vault` matches (proven directly in §6, exit 0).

```
$ bash scripts/verify-full.sh           # job bash-16 (see §7 for its result)
```

### 3.4 Legacy fixture (Global Constraints)

`scripts/legacy/campaigns/C-45488bdaf5` is read-only Python-era history (its INV-1
`verified_by` points at a scratch path that no longer exists). The gate lives in the
**verify path only**, so reading/auditing is untouched:

```
$ cp -r scripts/legacy/campaigns/C-45488bdaf5 .scratch/task4-legacy2/campaigns/
$ ./webv2 --root . audit C-45488bdaf5
audit PASS: event_log=0 problem(s), artifacts=0 problem(s), execs=0 problem(s),
findings=0 problem(s), projection=0 problem(s), snapshots=0 problem(s),
relations=0 problem(s), floor_policy=0 problem(s), stage_completions=0 problem(s),
baselines=0 problem(s), invariant_verification=0 problem(s), sequence_coverage=0
problem(s), probe_surface=0 problem(s), unpriceable=0 problem(s)
audit exit: 0
$ ./webv2 --root . verify C-45488bdaf5
{ "events": 54, "ok": true, ... }
verify exit: 0
```

No legacy artifact was re-registered and no gate was weakened.

## 4. Every call-site fixture changed (and why)

Enumerated with `rg -n "VerifyInvariantStatement" internal/ --glob '*.go'`; each row is a
test fixture that modelled an artifact **without** naming the invariant, i.e. an artifact
the new law must refuse. They are now honest artifacts (they name what they verify).

| # | Call site | Before | After | Why |
| --- | --- | --- | --- | --- |
| 1 | `invariants_test.go:387` (`TestVerifyRequiresRegisteredArtifact`) | `"checked against src/V.sol L40\n"` | `"INV-2 checked against src/V.sol L40\n"` | the test asserts the verify *succeeds*; the artifact must be honest |
| 2 | `invariants_test.go:590` `scenarioCamp` (`OTH-fixed001`/`OTH-fixed002`) | files did not exist at all | `inv-check.md` = `INV-2 … / INV-3 …`, `fuzz.md` = `INV-3 fuzz property held over 200 runs` | the twin scenario verifies INV-2 via fixed001 and INV-3 via fixed001/fixed002; the rows now point at real, honest bytes (registry goldens unchanged: no new events) |
| 3 | `guard_test.go:230` (`TestGuardrailPassesAfterVerification`) | `"checked\n"` | `"INV-2 checked\n"` | asserts the guardrail passes *after* verification |
| 4 | `guard_test.go:719` `guardCamp` (`OTH-fixed001`) | file absent | `inv-check.md` = `INV-2 checked against src/V.sol L40` | the golden's final `verified_passes` row verifies INV-2 through this row |
| 5 | `zz_r40d_test.go:93` (r40d unwind pin) | `"# r40d"` | `"# r40d\nINV-1 checked against src/V.sol L1\n"` | the retry leg must land the flip; the refusal leg still refuses for the ledger reason first (unchanged) |
| 6 | `roles/roles_test.go:762` | `"checked\n"` | `"INV-1 checked\n"` | asserts `BuildCriticContext` reflects a real verification |
| 7 | `audit/p1_sections_test.go:484` | `"checked against code\n"` | `"INV-1 checked against code\n"` | `inv_clean` oracle (`checked:1, problems:[], ok:true`) requires the API verify to land |
| 8 | `cli/cmd_invariant_verify_test.go` `t15ExecRecord` stdout | `"PASS: invariant check\n"` | `"INV-1: totalAssets monotone except withdraw\nPASS: invariant check\n"` | the `--exec` happy path registers the exec's stdout as the artifact |
| 9 | `cli/cmd_invariant_verify_exec_test.go` `invExecRecord` stdout | `"PASS: test_liveness\n"` | `"INV-008: the fee accumulator holds\nPASS: test_liveness\n"` | ditto for INV-008 |
| 10 | `cli/cmd_invariant_verify_exec_test.go` stderr-fallback row | `"FAIL: test_liveness\n"` | `"INV-008: …\nFAIL: test_liveness\n"` | the stderr fallback is registered as the artifact |
| 11 | `cli/cmd_invariant_verify_test.go:75` (`TestInvariantVerifyArtifact`) | `t15Register` → bytes `"x\n"` | new `t15RegisterCheck` → `"INV-1 checked against src/V.sol#L40\n"` | `t15Register` stays content-free for the artifact-list tests that share it |

**Unchanged call sites** (already honest, verified by grep + green suite):
`cli/cmd_gate_checklist_test.go:610` (`invID+" checked against src/V.sol#L40"`),
`reproduction/reproduction_test.go:609/619` and `:655/664` (both cite `INV-1`),
`orchestrator/port_test.go:619` (`"INV-002 checked against src/Vault.sol"` — passes on the
raw registry-spelling token; this is the zero-padded equivalence case, pinned by test),
`state/zz_r35_test.go:234` (comment only), and the hand-edited-status test at
`guard_test.go:481` (never calls the verify API).

## 5. New tests (all in the two changed test files + one state test)

* `TestVerifyRefusesIrrelevantArtifact` — generic `go test ./...` log; byte-exact refusal
  asserted; axis unmoved (`status` stays `UNVERIFIED`, `verified_by` absent, **no**
  `invariant.verified` event).
* `TestVerifyAcceptsRelevantArtifact` — the plan's verbatim row.
* `TestVerifyRefusesNearMissInvariantID` — `INV-20`, `INV-22`, `recheckINV-2`, `INV-2x`
  all refused for INV-2 (the plan's required negative row).
* `TestVerifyAcceptsAppliesToArtifact` — `applies_to` token match, case-insensitive,
  with the id absent from the bytes.
* `TestVerifyEmptyAppliesToDoesNotBypass` — empty `applies_to` is not a wildcard: prose
  about the invariant's *subject* is refused; the id token alone still satisfies.
* `TestVerifyAcceptsRegistrySpellingOfZeroPaddedID` — registry key `INV-002` accepts both
  `INV-002` and `INV-2` bytes, and `INV-020` is refused.
* `TestVerifyRefusesUnreadableArtifact` — missing file ⇒ refusal (fail closed).
* `TestInvariantVerifyExecRelevanceGate` (cli) — **the `--exec` end-to-end row the brief
  asked for**: generic captured output ⇒ exit 2 + the refusal on stderr + axis unmoved;
  the honest rerun ⇒ exit 0, `CHECKED_AGAINST_CODE`, `verified_by` resolved to the exec's
  stdout path.
* `TestInvariantVerifyArtifactRelevanceGate` (cli) — the `--artifact` half: one-line
  exit-2 refusal, axis unmoved, then an honest artifact lands.
* `TestResolveArtifactPath` (state) — exported wrapper ≡ internal seam for absolute and
  relative stored paths.

## 6. Script/golden fixture changes, with necessity proof

Two committed script fixtures registered artifacts whose bytes named nothing. Rather
than weaken the gate they were re-registered with honest bytes in this same commit
(Global Constraints: "a legacy artifact that no longer satisfies the relevance gate is
re-registered with an honest artifact in the same commit").

**`scripts/golden/artifact.md`** (golden recipe: `invariant-verify <cid> INV-2 --artifact
art[0]`, model `scripts/golden/model.json`, INV-2 `applies_to: ["Vault"]`):

```
# old bytes: "# Golden check artifact\n\nThe withdraw path double-counts the caller's
#            share balance before burning\nit. This file is the registered artifact the
#            invariant check cites.\n"
$ ./webv2 --root . invariant-verify $CID INV-2 --artifact REP-05ba614a
invariant verify failed: 'artifact REP-05ba614a does not reference INV-2 (nor its
applies_to) — cite a check that names what it verifies (invariant-verify with --exec <id>
re-registers stdout as the artifact)'
OLD-CONTENT exit: 2

# new bytes: "# Golden check artifact\n\nINV-2 checked against Vault: the total assets
#             must always cover the sum of\nall user claims. This file is the
#             registered artifact the invariant check\ncites.\n"
INV-2: CHECKED_AGAINST_CODE (artifact REP-91182d3d)
NEW-CONTENT exit: 0
```
(scratch campaign `.scratch/task4-repro`, binary built from this worktree)

**`scripts/verify-full.sh`** (`printf 'verify-p1 cross-audit artifact\n' >
"$P1F/fixtures/note.md"`, cited by the three P1/P2/P3 `invariant-verify … INV-1 --artifact
"$REP{,2,3}"` rows; model fixture INV-1 `applies_to: ["Vault"]`):

```
$ ./webv2 --root . invariant-verify $CID INV-1 --artifact REP-d8a1a7ac   # "INV-1 verify-p1 cross-audit artifact"
INV-1: CHECKED_AGAINST_CODE (artifact REP-d8a1a7ac)
VERIFY-FULL note.md fixture (INV-1) exit: 0
$ ./webv2 --root . invariant-verify $CID INV-1 --artifact REP-70a9cd95   # old "verify-p1 cross-audit artifact"
invariant verify failed: 'artifact REP-70a9cd95 does not reference INV-1 (nor its
applies_to) — …'
OLD note.md fixture exit: 2
```

**`scripts/runbook-walkthrough.sh` — NOT changed** (no weakening needed; the fixture
already satisfies the gate through `applies_to`):

```
$ ./webv2 --root . invariant-verify $CID INV-1 --artifact REP-1757b9bc   # scripts/golden/h1-…json
INV-1: CHECKED_AGAINST_CODE (artifact REP-1757b9bc)
RUNBOOK-ARTIFACT(INV-1 via applies_to Vault) exit: 0
```

## 7. Design decisions / deviations worth a reviewer's eye

1. **The `--exec` note does NOT count as evidence (the brief's premise was wrong).**
   The brief said `resolveExecArtifact`'s note `"invariant %s checked against code (exec
   %s)"` contains the id "so the `--exec` path keeps working". Verified by reading the
   code and by test: that note is written into the artifact **registry row**
   (`campaign_state.json → artifacts[].note`), **not** into the artifact file. The gate
   reads the file (the exec's captured stdout/stderr). Counting the note would make the
   gate vacuous for `--exec` — `resolveExecArtifact` always writes the id into the note,
   so *every* exec would pass, which is exactly the Morph INV-003 defect the task exists
   to close. The `--exec` path therefore keeps working when the captured output names the
   invariant (or an `applies_to` target) — the plan's Step 6 wording ("contains the id
   only if the operator's command did — that is the law working"). Pinned by
   `TestInvariantVerifyExecRelevanceGate` (generic output ⇒ exit 2; honest output ⇒ exit
   0 end-to-end).
2. **Token set is a superset of the plan's "normalized inv id".** The registry keeps the
   model's spelling (`SeedFromModel` stores the raw id: `INV-002` stays `INV-002`), so a
   normalized-only token (`INV-2`) would *falsely refuse* an honest artifact that cites
   the registry's own spelling. Each candidate therefore contributes both its raw and its
   `NormalizeInvID` form. This preserves the plan's normalization requirement and its
   intent ("so `inv_002`-style spellings match too") without opening a word-boundary hole
   (`INV-020` vs `INV-002` is refused — pinned by test).
3. **Unreadable artifact bytes ⇒ the same refusal (fail closed).** The plan specifies one
   new message; a file we cannot read cannot name what it verifies, so it is refused with
   that message rather than waved through. A distinct I/O message would be a reasonable
   follow-up (see §8).
4. **Event/save/unwind flow untouched.** The gate returns before any mutation, so the
   r40d unwind pin and every other refusal path are unchanged (green).
5. **`ResolveArtifactPath` is a method** (`func (c *Campaign) ResolveArtifactPath(a
   validation.Value) string`) — the unexported seam needs `c.Root`, so a package-level
   function could not be a one-line wrapper.

## 8. Pre-existing failure found (NOT caused by this task): `-race` lock test

`scripts/verify-full.sh` step 4 (`go test -race ./...`) is **red on this box at HEAD**:

```
--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (5.13s)
    processlock_r13_test.go:156: worker 2: exit status 1
        campaign C-lmwrace001 is locked by another process (waited 5s; holder:
        <pid> /tmp/go-build…/state.test -test.run=TestConcurrentLoadModifyWritesLoseNothing)
    processlock_r13_test.go:185: ledger lost a class: 5 of 6
FAIL	websec/internal/state	66.342s
FAIL [step 4: go test -race]
```

Proof that Task 4 is not the cause — the identical failure reproduces with my two
`internal/state` files reverted to HEAD:

```
$ git checkout -- internal/state/artifacts.go internal/state/artifacts_test.go
$ go test -race ./internal/state -run TestConcurrentLoadModifyWritesLoseNothing -count=1
--- FAIL: TestConcurrentLoadModifyWritesLoseNothing (5.08s)
    processlock_r13_test.go:156: worker 2: exit status 1
        campaign C-lmwrace001 is locked by another process (waited 5s; holder: 2468111 …)
FAIL	websec/internal/state	5.098s
CLEAN-EXIT=1
$ (files restored: git diff --stat internal/state → 6 + 38 insertions, as before)
```

The 5s lock-wait timeout in the test is simply too tight for six concurrent
race-instrumented worker processes on this machine; the non-race run of the same test
passes (`go test ./... -count=1` green, job bash-13). **Task 4 touches no locking code**
(`internal/state/artifacts.go` gains one pure method; the gate runs before any mutation).

Because `verify-full.sh` is fail-fast, its steps 5-13 never executed in that run. A
scratch copy with only step 4 replaced by a recorded note was run so the remaining steps
(asset pack, determinism, golden, crash smoke, legacy cross-audit, P1/P2/P3 CLI smokes —
which include the three `invariant-verify … --artifact "$REP{,2,3}"` rows that consume the
changed `note.md` fixture) still produce evidence:

```
$ bash .scratch/task4-repro/verify-full-norace.sh      # job bash-17
… steps 1-11 PASS (vet, build, test, determinism, asset pack, golden, crash smoke,
  legacy cross-audit, P1 smoke incl. `invariant-verify … --artifact "$REP"`,
  P2 smoke incl. `invariant-verify … --artifact "$REP2"`, P3 smoke incl.
  `invariant-verify … --artifact "$REP3"`) …
FAIL [step 12: smoke audit --json sections]
AssertionError: P3 smoke audit: 15 sections, want 14
```

**Step 12 is a second pre-existing failure, also not caused by this task.** The P3 smoke
records a price (`p3_ok "price set" …`, committed at HEAD), so `prices.json` +
`price.set` exist and the presence-gated `price_table` section (registered *after* the 14
ported sections, `internal/audit/sections/register.go`) renders → 15 sections. The
committed helper `p2_sections_ok` asserts `len(secs) == 14` with no `price_table` in its
`want` list, and there is no P3-specific helper in the script. Proof with a binary built
from unmodified sources (my two source files reverted to HEAD, rebuilt, then restored):

```
$ ./.scratch/task4-repro/webv2-head --root .scratch/verify-p1/smoke3 audit C-10ab2d8738 --json
HEAD binary sections: 15
['artifacts', 'baselines', 'event_log', 'execs', 'findings', 'floor_policy',
 'invariant_verification', 'price_table', 'probe_surface', 'projection', 'relations',
 'sequence_coverage', 'snapshots', 'stage_completions', 'unpriceable']
```

Identical to the count produced by the Task 4 binary — so `verify-full.sh` cannot reach
step 13 on this branch either way. Both pre-existing reds (step 4, step 12) are recorded
here for the orchestrator; fixing them is outside Task 4's file set.

## 9. Concerns / follow-ups for the reviewer

1. **The gate is prospective, not retroactive.** Existing campaigns whose invariants are
   already `CHECKED_AGAINST_CODE` behind a generic artifact keep that status — nothing
   re-validates history. That matches the plan (the gate sits in the verify path), but it
   means the Morph-style closure is prevented, not repaired. A retro-detection pass
   (audit section listing `verified_by` artifacts that fail the relevance test) would be a
   separate task and is explicitly out of Task 4's scope.
2. **The `--exec` behavior tightening is real.** An operator whose check output does not
   name the invariant now gets exit 2 and must re-run the check so its captured output
   names the invariant (the refusal text says exactly that). This is the plan's intent
   ("contains the id only if the operator's command did — that is the law working"), but
   it is a user-visible behavior change worth a runbook/prompt line; `docs/` is out of
   bounds for this task.
3. **Unreadable artifact ⇒ relevance refusal** (§7.3). If the team wants I/O errors to be
   distinguishable, a second message ("artifact <id> cannot be read: …") is a small
   follow-up; I kept the plan's single specified message to stay inside the spec.
4. **Bytes are read whole** (`os.ReadFile`, as the plan sanctions). `internal/state`
   registration does not enforce a size cap that I could find, so a pathological
   multi-GB artifact would be read into memory at verify time. A `Stat`+bounded reader
   would harden this; not required by the plan.
5. **The gate judges the CURRENT bytes, not the registered sha.** An artifact whose file
   drifted after registration is evaluated on the drifted bytes (pre-existing behavior:
   `VerifyInvariantStatement` never re-hashed). `artifact-reconcile` remains the drift
   detector. Not worsened by Task 4, but the relevance law inherits it.
6. **`go test -race ./...` is red at HEAD** (§8) — a pre-existing environment failure that
   will block any future `verify-full.sh` run until the test's lock wait is raised or the
   machine is less loaded. Not fixed here (out of scope, and the fix would touch the
   processlock test's timing).
7. **`verify-full.sh` step 12 is red at HEAD too** (§8, `price_table` vs the hard-coded 14)
   — also not fixed here: the file is in my changed set only for the `note.md` fixture
   line, and rewriting the section assertion is a different task's call.
8. **`internal/state` already exports `ResolveArtifactPathFor(c *Campaign, p string)`** for
   a raw path string; the new `(c *Campaign) ResolveArtifactPath(a validation.Value)` is the
   plan's wrapper over the Value-taking `resolveArtifactPath` seam, so the two are not
   duplicates (one takes a path, one takes an artifact row).

### 8.1 Note on the final artifact

After all evidence above was collected, the implementation files were accidentally reverted
during the clean-HEAD experiment and were re-applied verbatim; the whole chain (4 packages,
`./...`, `go vet`, `scripts/golden.sh`) was then re-run on the restored bytes:
`.scratch/sdd/task-4-logs/post-restore-verify.txt` (all green). The committed bytes are the
ones that passed that final chain.

## 10. Status

**Commit:** `37511ec8714ca5a89cdfd99238e1dcf23fd90b6b` — `fix(invariants): evidence
relevance binding on invariant-verify` (12 files, +470/-14, staged by exact path;
`git status` clean afterwards, nothing pushed).

DONE_WITH_CONCERNS — the law, its tests, the fixture sweep and all Task-4 gates are green;
the concerns are the two pre-existing `verify-full.sh` failures (§8) and the follow-ups
in §9.

## 11. Command log (exact commands + exit statuses)

| Command | Exit | Where |
| --- | --- | --- |
| `go test ./internal/invariants -run 'TestVerify' -count=1` (RED) | 1 | §3.1 |
| `go test ./internal/cli -run 'TestInvariantVerify' -count=1` (RED) | 1 | §3.1 |
| `go test ./internal/state -run TestResolveArtifactPath -count=1` (RED, build failed) | 1 | §3.1 |
| `go test ./internal/invariants ./internal/cli ./internal/roles ./internal/audit -count=1` | 0 | `.scratch/sdd/task-4-logs/gate-4packages.txt` |
| `go test ./... -count=1` | 0 | job bash-13 (60 packages) |
| `go vet ./...` | 0 | `.scratch/sdd/task-4-logs/gate-vet.txt` |
| `gofmt -l internal cmd` | 0 (no output) | §3.2 |
| `bash scripts/golden.sh` | 0 | job bash-14, GOLDEN GREEN |
| `bash scripts/runbook-walkthrough.sh` | 0 | job bash-15, 150 passed / 0 failed |
| `bash scripts/verify-full.sh` | **step 4 FAIL (pre-existing)** | job bash-16, §8 |
| `bash .scratch/task4-repro/verify-full-norace.sh` | **step 12 FAIL (pre-existing)** | job bash-17, §8 |
| `go test -race ./internal/state -run TestConcurrentLoadModifyWritesLoseNothing -count=1` | 1 | §8 (also 1 on a clean HEAD tree) |
| `go test ./internal/invariants ./internal/cli ./internal/roles ./internal/audit -count=1` (post-restore) | 0 | `.scratch/sdd/task-4-logs/post-restore-verify.txt` |
| `go test ./... -count=1` (post-restore) | 0 | same log (`EXITALL=0`) |
| `go vet ./...` (post-restore) | 0 | same log (`EXITVET=0`) |
| `bash scripts/golden.sh` (post-restore) | 0 | same log (`EXITGOLDEN=0`) |
| `./webv2 --root . audit C-45488bdaf5` / `verify` (legacy fixture) | 0 / 0 | §3.4 |
| fixture-necessity repro (old/new golden + note.md bytes, runbook artifact) | 2 / 0 / 0 | §6 |
