# Task 3 report — per-machine liveness coverage gate (the G-01 gap)

Worktree: `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
Branch: `production-readiness` (no push)
Commit: `bbe5a0306643bd4d67634fa02877ed71ded14fdd` — `fix(invariants): per-machine liveness coverage gate`
Files committed (staged by exact path, nothing else in the commit):

```
internal/invariants/invariants.go       |  34 ++++++--
internal/invariants/invariants_test.go  | 143 +++++++++++++++++++++++++++++++++
2 files changed, 172 insertions(+), 5 deletions(-)
```

`git status --short` after the commit: empty (clean tree). Base for this task: `b47d893e`
(Task 2's commit).

## 1. Law implemented

`seedLiveness` (internal/invariants/invariants.go:461) previously returned early whenever
**any** registered invariant had `kind == "liveness"` — a global presence check. It now
counts coverage **per state machine**:

| coverage | behaviour |
| --- | --- |
| no state machines in the model | unchanged: early `return nil` (before any coverage math) |
| zero machines covered by any registered `kind=liveness` entry's `applies_to` | unchanged synthesis path (template naming every machine) |
| partial (≥1 machine covered AND ≥1 uncovered) | **refusal**, no synthesis, naming the uncovered machines |
| full coverage (every machine covered) | no synthesis, no error |

Refusal text, byte-exact (no prefix/suffix added):

```
protocol model: state machine(s) relay, staking have no liveness invariant (one per machine — stage 37)
```

Implementation detail: the old `kinds` map was deleted (it became dead code); coverage is
built from `reg` entries whose `kind == "liveness"`, unioning their `applies_to` strings,
then compared against the model's `state_machines[].name` list in model order. Uncovered
names are reported in model order, joined with `", "`.

## 2. Unwind discipline — verified answer

**The refusal happens BEFORE any write, so no unwind is needed.** Evidence:

* In `seedLiveness` the refusal is returned before `validation.SetOrAppend(reg.O, ...)`
  and before `c.Log("invariants.liveness_template", ...)`.
* `SeedFromModel` (invariants.go:372) returns `validation.VNull(), err` on that error and
  never reaches `SaveLinks`/`LinksThenLog` (line 399-401), so `artifacts/invariant_links.json`
  is never written.
* Empirically, unit test `TestPartialLivenessCoverageRefused` asserts, after the refusal:
  `LoadLinks` registry size `0`, `linksPath(c)` does not exist, and `c.Events()` contains no
  `invariants.liveness_template` event. End-to-end CLI run (section 5) confirms the same:
  the campaign's `artifacts/` contains only `protocol_model.json`, no
  `invariant_links.json`, and the ledger has no `invariants.liveness_template` row.
* Pre-existing context, stated for precision: the *caller*
  `orchestrator.LoadProtocolModel` saves the model artifact (`protocolgraph.SaveModel`,
  model.go:19) and logs `artifact.registered`/`protocol_model.loaded` **before** seeding.
  On a refusal those artifacts/events therefore exist while the registry is untouched —
  byte-identical to the pre-existing seed refusals (`'id'` / `'statement'` missing,
  invariants.go:386/392), which also occur after `SaveModel`. No new half-land class was
  introduced; the invariant registry itself is never partially written.

## 3. Tests (TDD)

Appended to `internal/invariants/invariants_test.go` (end of file, new section
"per-machine liveness coverage (Task 3, the G-01 gap)"):

1. `TestPartialLivenessCoverageRefused` — the brief's test, expanded. Asserts the exact
   refusal text, that the **covered** machine (`vault-lifecycle`) is *not* named, and that
   no registry state/event landed.
2. `TestZeroLivenessStillSynthesizes` — the brief's test, expanded: `INV-4.synthesized ==
   "liveness-template"`.
3. `TestFullLivenessCoverageNeedsNoTemplate` — added by me (third branch of the stated law,
   not in the brief): full coverage neither synthesizes nor refuses, and a re-seed stays
   idempotent (no `INV-5`).

Fixture literal: the plan sketch called the base fixture `modelWithInvariants()`, but that
shared fixture carries **no** `state_machines` (it is used by ~10 unrelated tests, whose
shapes depend on it), so the brief's "expand the placeholder into the full literal model"
instruction is satisfied with a local helper `livenessMachinesModel()`: three machines
(`vault-lifecycle`, `relay`, `staking`) + three model invariants (`INV-1..INV-3`) — which is
exactly the shape implied by the brief's expected `INV-4` template id. Helper
`livenessModelCovering(machine)` turns `invariants[0]` into `kind=liveness` with
`applies_to=[machine]`. No placeholders remain in the test file.

**Red run** (before implementation):

```
$ go test ./internal/invariants -run 'TestPartialLivenessCoverageRefused|TestZeroLivenessStillSynthesizes' -count=1
--- FAIL: TestPartialLivenessCoverageRefused (0.01s)
    invariants_test.go:870: expected error containing "protocol model: state machine(s) relay, staking have no liveness invariant (one per machine — stage 37)", got nil
FAIL
FAIL	websec/internal/invariants	0.012s
```

(Zero-liveness test passed on the red run — synthesis is the pre-existing behaviour.)

**Green run** (after implementation):

```
$ gofmt -l internal/invariants/          # (no output)
$ go test ./internal/invariants -run 'LivenessCoverage|ZeroLiveness|FullLiveness|PartialLiveness' -v -count=1
=== RUN   TestPartialLivenessCoverageRefused
--- PASS: TestPartialLivenessCoverageRefused (0.00s)
=== RUN   TestZeroLivenessStillSynthesizes
--- PASS: TestZeroLivenessStillSynthesizes (0.00s)
=== RUN   TestFullLivenessCoverageNeedsNoTemplate
--- PASS: TestFullLivenessCoverageNeedsNoTemplate (0.00s)
ok  	websec/internal/invariants	0.012s
```

## 4. Gates (all commands with `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod
GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod`)

| # | command | result |
| --- | --- | --- |
| 1 | `go test ./internal/invariants ./internal/orchestrator ./internal/cli -count=1` | PASS — `Go test: 1182 passed in 3 packages`, exit 0 (orchestrator port fixture green untouched) |
| 2 | `go test ./... -run 'Legacy' -count=1` | PASS — `23 passed in 73 packages`, exit 0 |
| 3 | `go test ./... -count=1` | PASS — `Go test: 5017 passed in 73 packages`, exit 0 |
| 4 | `go vet ./...` | clean, exit 0 |
| 5 | `gofmt -l internal/invariants/` | no output |

## 5. Legacy / fixture checks

* **`scripts/legacy/campaigns/C-45488bdaf5`** (the Python-reference fixture): its
  `artifacts/protocol_model.json` has `state_machines: []` (and INV-1/INV-2, both
  `economic`), so `seedLiveness` early-returns on `len(machines) == 0`; the new gate cannot
  fire. Verified end-to-end with the built CLI:
  ```
  $ webv2 --root .scratch/task3-legacy audit C-45488bdaf5   -> "audit PASS: ... 0 problem(s)"   AUDIT_EXIT=0
  $ webv2 --root .scratch/task3-legacy verify C-45488bdaf5  -> {"ok": true, "problems": [], ...} VERIFY_EXIT=0
  ```
* **Repo-wide sweep** for any JSON model with both `state_machines` and a `kind=liveness`
  invariant: `0` hits. The embedded legacy fixture in `internal/orchestrator/testdata/oracles.json`
  has one machine (`vault-lifecycle`) and no liveness invariant in the model, i.e. zero
  coverage → synthesis, matching its recorded `invariants.liveness_template` event; the
  orchestrator port tests stay green.
* **No fixture needed sanitizing** — the gate was not weakened anywhere.
* End-to-end CLI evidence (built binary, scratch campaign):
  * partial model (liveness covering only `vault-lifecycle` of three machines) →
    `PARTIAL_EXIT=2`, stderr:
    `model load failed: protocol model: state machine(s) relay, staking have no liveness invariant (one per machine — stage 37)`;
    `artifacts/` = `protocol_model.json` only; no `invariant_links.json`; no
    `invariants.liveness_template` event.
  * same model with the liveness kind flipped to `economic` (zero coverage) →
    `ZERO_EXIT=0`, `invariant registry: 3 invariant(s) (2 from this load)`, registry:
    `[('INV-1','economic',None,...), ('INV-2','economic',None,...), ('INV-3','liveness','liveness-template',['vault-lifecycle','relay','staking'])]`
    — synthesis unchanged.

## 6. Concerns / deviations

1. **Brief test vs. brief law, one assertion.** The plan skeleton's partial-coverage test
   asserted `strings.Contains(err.Error(), "vault-lifecycle")` while describing
   `vault-lifecycle` as the *covered* machine — i.e. the skeleton asserted the error names
   the covered machine. The authoritative law in the task brief ("returns an error naming
   the uncovered machines, refusal text exactly …") says the opposite. I implemented and
   asserted the law: the error contains the full exact refusal naming `relay, staking`, and
   the test additionally asserts that the covered machine is **not** named. If the plan
   intended `vault-lifecycle` in the message, the fixture (not the gate) should change.
2. **`modelWithInvariants()` is not the brief's fixture.** It has no `state_machines` and
   only two invariants, so it cannot produce the brief's expected `INV-4`. I did not widen
   the shared fixture (it would have changed ~10 unrelated tests); the literal lives in a
   local helper instead.
3. **Third test added** (`TestFullLivenessCoverageNeedsNoTemplate`) beyond the brief's two.
   It pins the third branch of the stated law (full coverage → no synthesis, no refusal,
   idempotent re-seed). It was written after the implementation, so it has no red run of its
   own; the two brief tests were red-first.
4. **Semantics choice worth a reviewer's eye:** "zero coverage" is defined as *no machine
   covered by a liveness entry*, so a registry holding a liveness entry with an empty or
   non-model `applies_to` now **synthesizes** where the old global check would have stayed
   silent. This is what the task brief prescribes ("zero liveness coverage across machines
   keeps synthesis unchanged") and it is the only reading under which the partial/zero split
   is well defined.
5. No CLI output/golden changes: the refusal only changes an error path; `scripts/golden.sh`
   / runbook pins were not touched (not required — no pinned output changes). The full
   `go test ./...` run includes the golden-pin tests and is green.
