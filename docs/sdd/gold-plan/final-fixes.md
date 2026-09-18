# Final fix wave — gold-findings closure plan

Branch `production-readiness`, base `bc80d151`. Mandate: `final-review.md` findings
**F-B** (Go, P1) and **F-A** (doc, IMPORTANT). Two commits, one per finding.

Range after this wave: `bc80d151` → `50d6da9c` (F-B) → `64d7b11b` (F-A).

---

## Commit 1 — F-B: refused invariant-verify citations mint no artifact row

**`50d6da9c6015657afdb69a227f5739385f788303`**
`fix(cli): refused invariant-verify citations mint no artifact row (defect 6 residue)`

Files (exact-path staging, 2 files, +25/−10):

- `internal/cli/cmd_invariant_verify.go`
- `internal/cli/cmd_invariant_verify_exec_relevance_test.go`

### What was wrong

`resolveExecArtifact` called `RegisterOrRefresh` with the note
`invariant INV-3 checked against code (exec EXEC-…)` **before**
`runInvariantVerify` ran the exec-relevance gate. A citation the gate then
refused left a durable artifact row asserting the verification it had just
refused — a live instance of the defect-6 record class this plan exists to close.

### Red (test added first, against unmodified code)

Added to `TestInvariantVerifyRefusesUntargetedExec`: after the existing
status/verified_by/verification_method/event assertions, walk
`c.State()["artifacts"]` and fail if any row's `note` names the invariant.

```
$ go test ./internal/cli -run TestInvariantVerifyRefusesUntargetedExec -count=1
--- FAIL: TestInvariantVerifyRefusesUntargetedExec (0.01s)
    cmd_invariant_verify_exec_relevance_test.go:91: refused citation minted artifact row OTH-06102e5c: note "invariant INV-3 checked against code (exec EXEC-0000000002)"
FAIL
FAIL	websec/internal/cli	0.019s
```

The failing note is the defect verbatim: the row claims "checked against code"
for a citation the gate refused one frame later.

### Fix

Hoisted the gate into `resolveExecArtifact`, immediately **after** the
`isFile(outPath)` check and **before** `RegisterOrRefresh`; deleted the gate
block from `runInvariantVerify`. Refusal text byte-identical
(`invariant verify failed: cited exec %s does not target any applies_to contract
of %s (%s)`, return 2), so no pin moved. Ordering of every earlier refusal is
unchanged (unknown invariant → missing exec → incomplete/refused exec → no
captured output → exec-relevance → mint), so the gate still cannot fire ahead of
a refusal that used to win.

### Green (at HEAD)

```
$ go test ./internal/cli -run 'TestInvariantVerify(RefusesUntargetedExec|ExecRelevanceGate|AcceptsTargetedExec|ExecHappyPath)' -count=1 -v
--- PASS: TestInvariantVerifyRefusesUntargetedExec (0.01s)
--- PASS: TestInvariantVerifyAcceptsTargetedExec (0.01s)
--- PASS: TestInvariantVerifyExecHappyPath (0.01s)
--- PASS: TestInvariantVerifyExecRelevanceGate (0.01s)
ok  	websec/internal/cli	0.044s

$ go test ./internal/cli ./internal/invariants -count=1
ok  	websec/internal/cli	33.080s
ok  	websec/internal/invariants	0.235s

$ go test ./... -count=1
TEST_EXIT=0
$ go vet ./...
VET_EXIT=0
$ gofmt -l internal cmd
(no output)

$ bash scripts/golden.sh
GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)
GOLDEN_PIPE_EXIT=0
  run root: .scratch/golden/root   archived tree: .scratch/golden/tree-go
  (196 steps, campaign C-34c0ce6f4b, 179 events, chain intact, 99 files archived)

$ python3 -m unittest scripts.eval_gold_test
Ran 26 tests in 1.049s — OK
```

Golden ran with the fix in the working tree; the Go tree is byte-identical to
commit 1 (`git diff` clean for Go after staging), so the green run is commit 1's
tree. **No pin moved** — as the final review predicted, no existing test asserted
registry state on any refusal path; only the new assertion does.

### Deliberately not expanded

`TestInvariantVerifyExecRelevanceGate` case (b) (targeted command, generic log)
still mints before Task 4's byte gate refuses — the final review's stated
residual, which predates this plan and stays parked with its own pins. D2
(`appliesToTokens` doc-comment) and D4 (reachability test comment) were
optional fold-ins, not part of the F-B/F-A mandate; left parked untouched.

---

## Commit 2 — F-A: fresh-campaign requirement for the partial-coverage refusal

**`64d7b11b`** `docs(eval): fresh-campaign requirement for the partial-coverage
refusal example`

File: `docs/eval/morph-rerun-protocol.md` §3.2-1 (1 file, +7/−1).

### Scratch reproduction (both flows, 2026-09-18, binary built from this tree)

Fixtures written to `.scratch/f-a/{skeleton,variant}.json` exactly as the doc
prints them; campaigns created with `webv2 init --program "Morph L2"` in an
isolated `HOME` under `.scratch/f-a/ws`.

**Fresh campaign → §3.2-1 variant** (the doc's quoted output):

```
$ webv2 model C-b7adb30545 ../variant.json
EXIT=2
[stderr]
model load failed: protocol model: state machine(s) rollup_finalization have no liveness invariant (one per machine — stage 37)
```

**In-sequence §3.1 → §3.2-1, same campaign** (the doc's own prescribed order):

```
$ webv2 model C-36f576bbc2 ../skeleton.json
model loaded: 0 actors, 0 assets, 0 invariants
  reconciliation: model covers every documented invariant id
EXIT=0
[stderr]
  WARNING: the model declares no invariants — the invariant registry was seeded with NOTHING (invariants.seed_empty logged). Every evidence level rise will be guardrail-blocked until the model is refined.

$ webv2 model C-36f576bbc2 ../variant.json
EXIT=2
[stderr]
model load failed: protocol model: state machine(s) message_queue have no liveness invariant (one per machine — stage 37)
```

Registry after the §3.1 load — the mechanism, read directly:

```
campaigns/C-36f576bbc2/artifacts/invariant_links.json
INV-1 | applies_to= ['rollup_finalization'] | source= model | statement= LIVENESS: every modeled state machine must be able to advanc…
```

(unchanged after the refused variant load: the variant's `INV-1` refreshed that
row in place, `applies_to: ["message_queue"]` never landed, so coverage stayed
`{rollup_finalization}` and the uncovered machine was `message_queue`.)

### Doc fix

Replaced the bare lead-in "Verbatim output from a scratch campaign" in §3.2-1
with the fresh-campaign requirement and the in-sequence expectation:

> Load this variant in a **fresh campaign**. In the §3.1 → §3.2-1 sequence the
> skeleton's synthesized `INV-1` liveness template already covers
> `rollup_finalization`; the variant's `INV-1` refreshes that row in place, its
> `applies_to` never lands, and the gate instead names the *other* machine —
> `state machine(s) message_queue have no liveness invariant` (reproduced
> 2026-09-18). Verbatim output from a fresh scratch campaign, 2026-09-18 (exit 2):

The quoted `rollup_finalization` refusal stays as printed because it is real —
in a fresh campaign — and is now labelled as such. The §3.1 block's own
"loads, exit 0" quote was left alone (it is accurate in a fresh campaign, and
the new paragraph names the sequence interaction explicitly).

Docs-only commit: no Go, no fixtures, no pins. `go test ./...` state is
commit 1's.

---

## Status

| # | Finding | Status | Hash | Test line |
|---|---|---|---|---|
| 1 | F-B (P1) | DONE — red→green, no pin moved | `50d6da9c` | `--- PASS: TestInvariantVerifyRefusesUntargetedExec (0.01s)` + `ok websec/internal/cli` |
| 2 | F-A (doc) | DONE — both flows reproduced, quote now qualified | `64d7b11b` | n/a (docs-only; scratch reproduction above) |

Constraints held: stdlib only, no new module deps, historical fixtures untouched,
no golden re-pin, exact-path staging, refusal semantics never weakened, no
push/merge/delegate.
