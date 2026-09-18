# Task 4A fix round 1 — scoped re-review (521eecfd..f13ae1df)

Reviewer verdicts. Read-only on tracked files; every gate below was re-run by the
reviewer, and the byte-delta and hash claims were re-derived with the reviewer's
own independent tooling (Python deep-diff + own `state.eventHash` reimplementation),
not the implementer's logs.

## Verdicts

### Finding 1 (BLOCKING): twin byte-parity tests — re-pin JUSTIFIED, proof CREDIBLE → ADDRESSED

**Additivity — confirmed independently.** The only non-test references to
`verification_method` in the repo are the two writes in
`invariants.VerifyInvariantStatement` (entry + event data) and the pure-label
helper `VerificationMethod` (`invariants.go:799-808`), which no gate calls.
- `internal/invariants/guard.go` `AssertInvariantsVerified`/`IsVerified` read
  `status`, `verified_by`, `contradiction`, `source`, and event `ref`/`type`/
  `data.artifact`/`data.evidence` — never the new key.
- `internal/audit/sections/invariantverification.go` (§11) reads `status`,
  `verified_by`, `verification.harness`, and `IsVerified` — never the new key.
- `internal/state/artifacts.go` `artifactIDCitedByEvents` reads only
  `data.artifact` on `invariant.verified` — unaffected.
Unknown JSON keys are ignored by all readers, so no verdict can move.

**Byte-delta proof — credible; reviewer re-derived it.** Independent deep-diff of
521eecfd vs f13ae1df fixtures: `scenario_links.json` 2 adds,
`guard_links.json` 1 add, `scenario_steps.json` 14 adds — every add is exactly
`verification_method = "operator-attestation"`, zero removals, zero value
changes, zero type changes. Every inserted key sits immediately after
`verified_by` or (for a later-contradicted entry whose `verified_by` was popped)
immediately before `contradiction` — matching `SetOrAppend` append-after-existing
semantics, i.e. pure derived consequence.

**JSONL re-chaining — proven, not assumed.** The reviewer's own Python
reimplementation of `state.eventHash` (sha256 over `CanonSpaced` =
CPython `json.dumps(sort_keys=True, ensure_ascii=True)` of the six picked fields
`{seq,at,type,ref,data,prev_hash}`, per `internal/state/chain.go`) reproduces
BOTH revisions' chains byte-exactly:
`521eecfd` PASS (4+14 events), `f13ae1df` PASS (4+14 events). Non-hash fields per
line differ only by the sanctioned key; hash churn begins exactly at the first
changed event (guard seq 3, scenario seq 7) and is pure prev_hash propagation.
No hash was hand-edited.

**Ruling fit.** `internal/invariants/testdata/*` are pinned expectations, not
legacy-compatibility fixtures; `scripts/legacy` is byte-identical across the
range (tree hash `f62c95c0a947f94e15328ee0d08fc1b70ab31ec6` verified,
`git diff 521eecfd..f13ae1df -- scripts/` empty). Renames are in place with
honest header comments (twin retired at P4 → fixtures pin GO behavior, re-pin
reason cited); old names gone; the temporary capture harness
(`zz_repin_capture_test.go`) was never committed and is absent. Commit message
body carries the reasoning per the deliberate-pin-update constraint.

### Finding 2: CLI help line — ADDRESSED

HEAD `internal/cli/cmd_invariant_verify.go:238-241` reads
`invariant-verify <campaign> <inv_id>  record an operator attestation
(attribution, not mechanical proof)`. The old misleading string "mark an
invariant verified" is absent from every tracked file; the help itself now
discloses attribution-not-proof. `internal/cli` tests pass unmodified.

### Sanctioned deviation: fifth file `scenario_steps.json` — APPROVED

Necessity proven from the test code: `scenarioChecker.step` compares
`validation.DumpIndented(LoadLinks(c))` against each step's embedded `links`
snapshot (steps 5..12 carry the attested INV-2/INV-3 entries), so a stale steps
fixture keeps `TestLinkScenarioMatchesGoPin` red and the brief's own exit-0 gate
is unreachable without it. The file lives under the same pinned-expectation
testdata directory, sits in the same test, and its delta is the identical
sanctioned add (14 adds, 0 other) — this is the ruling applied consistently, not
the brief's "any other delta = BLOCKED" condition. Disclosed in report §3 and in
the commit body's SCOPE NOTE. Approved.

### New breakage in the fix diff — NONE

Fix diff is 8 files / +86/-27 exactly as advertised; HEAD `f13ae1df`, tracked
tree clean. Reviewer-re-run gates, all matching the report:
`go test ./internal/invariants ./internal/cli -count=1` exit 0;
`go test ./... -count=1` real exit 0, 71 `ok`, no FAIL/panic;
`go vet ./...` clean; `gofmt -l internal/ cmd/` empty.
No production code path changed (the only non-test source edit is the string
literal); no reader, schema, or gate touches the new key.

## Deferred minors (out of scope; no loop extension)

1. `guard_test.go:777` doc comment leads with `TestGuardMessagesMatchesGoPin`
   ("Matches") while the function is `TestGuardMessagesMatchGoPin` — go-doc
   convention nit, no tool enforces it.
2. Same header says the guard reads "only status, verified_by and
   contradiction" — it also reads `source` (the documented-invariant exemption).
   Understated, immaterial to additivity.
3. Design observation on the PARENT commit, faithfully recorded by the re-pinned
   fixtures: a verified-then-contradicted entry keeps `verification_method`
   while `verified_by` is popped and status becomes CONTRADICTED. Harmless today
   (no gate reads the key); worth clearing on contradict if any future consumer
   treats the key as live-verification provenance.
4. Sibling tests still named `…Match/MatchesPythonTwin` (constants, docscan)
   keep honest parity pins — their fixtures did not drift; renaming them was
   outside this brief.

## Summary

- Finding 1: **ADDRESSED** — re-pin justified; additivity and byte-delta
  independently re-derived by the reviewer (including both chains' hashes).
- Finding 2: **ADDRESSED** — help line discloses attestation; old string gone.
- Fifth-file deviation: **APPROVED** (necessary for the gate; same sanctioned
  delta; disclosed).
- New breakage: **none**. Tree is green and ready to proceed.
