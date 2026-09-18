# Final fix review — gold-findings closure fix wave (`bc80d151..64d7b11b`)

**Role:** scoped re-review of the two must-fix commits (`50d6da9c` F-B, `64d7b11b` F-A).
Read-only; no tracked changes made. Findings inputs: `final-review.md` (F-B, F-A),
`final-fixes.md`, diff in `final-fix-review-package.md`.

## Gates re-run at HEAD (`64d7b11b`), this session

| Gate | Result |
|---|---|
| `go test ./... -count=1` | **exit 0** (local GOCACHE/GOMODCACHE overlay; workspace cache is read-only) |
| `go vet ./...` | clean (exit 0) |
| `python3 -m unittest scripts.eval_gold_test` | **26/26 OK** |
| `bash scripts/golden.sh` | **GREEN, re-run live this session** — 196 steps, campaign `C-34c0ce6f4b`, exit 0 (matches `final-fixes.md` byte-for-byte), so **no pin moved** is confirmed first-hand, not inherited |
| `git status` after review | only `.scratch/` + pre-existing untracked `.superpowers/`; zero tracked changes |

---

## F-B — refused citations mint no artifact row — **ADDRESSED**

Commit `50d6da9c`, files `internal/cli/cmd_invariant_verify.go` +
`cmd_invariant_verify_exec_relevance_test.go` (+22/−10 Go, +13 test). Check by check:

1. **Gate hoisted into `resolveExecArtifact` before `RegisterOrRefresh`** — verified by
   direct read at HEAD: the gate block now sits at `cmd_invariant_verify.go:169-180`,
   immediately after the `isFile(outPath)` refusal and immediately before the
   `note := fmt.Sprintf("invariant %s checked against code (exec %s)"…)` +
   `c.RegisterOrRefresh(...)` pair. The old gate block is deleted from
   `runInvariantVerify` (the diff hunk removes it verbatim). A refused citation now
   returns `("", 2)` from inside `resolveExecArtifact` and never reaches the mint.
2. **Refusal text + exit 2 byte-identical** — the moved block's format string
   (`"invariant verify failed: cited exec %s does not target any applies_to contract of %s (%s)\n"`)
   and `return 2` are character-for-character the same as the deleted block (only the
   signature-mandated `return "", 2` differs mechanically). No pin depended on the text;
   golden re-run GREEN confirms no output pin moved.
3. **Registry-absence assertion added and red-first proven** — the test now walks
   `c.State()["artifacts"]` after the existing status/verified_by/event assertions and
   fails on any row whose `note` names `INV-3`. **Red-first independently reproduced by
   this reviewer**: re-applying `bc80d151`'s `cmd_invariant_verify.go` against the HEAD
   test file in a scratch copy fails with exactly the defect —
   `refused citation minted artifact row OTH-657d765b: note "invariant INV-3 checked against code (exec EXEC-0000000002)"`;
   at HEAD the same test passes. All four focused invariant-verify tests pass at HEAD.
4. **No pin moved** — `golden.sh` GREEN re-run live (above); full suite exit 0; scorer
   26/26. Confirms the fix doc's claim that no existing test asserted registry state on
   any refusal path.
5. **`resolveExecArtifact` single caller unaffected** — repo-wide search: exactly one
   caller (`runInvariantVerify`, line 94). The `--artifact` path never enters the
   function; the ordering of every earlier refusal (unknown invariant → missing exec →
   incomplete/refused exec → no captured output) is unchanged — all still precede the
   gate, exactly as before the move.

### Breakage scan of the F-B diff — none found

- The only behavioral reorder is gate-before-`RegisterOrRefresh`. A citation that passes
  the gate takes the identical path as before; a citation that fails it previously minted
  the poisoned row and *then* refused, so the reorder is the fix itself, not a regression.
- The gate still runs before `VerifyInvariantStatement` writes anything (fix sketch from
  the final review honored exactly).
- The test change is purely additive — no existing assertion was removed or weakened.

---

## F-A — §3.2-1 quoted refusal unreachable in-sequence — **ADDRESSED**

Commit `64d7b11b`, docs-only, one paragraph in `docs/eval/morph-rerun-protocol.md`
(+7/−1). Check by check:

1. **Fresh-campaign requirement stated** — the §3.2-1 lead-in now opens "Load this
   variant in a **fresh campaign**" (doc lines 193-199), and the quoted output is
   relabelled "Verbatim output from a fresh scratch campaign, 2026-09-18 (exit 2)".
2. **In-sequence `message_queue` expectation named** — the new text states the
   mechanism explicitly: the skeleton's synthesized `INV-1` covers
   `rollup_finalization`, the variant's `INV-1` refreshes that row in place, its
   `applies_to` never lands, and "the gate instead names the *other* machine —
   `state machine(s) message_queue have no liveness invariant`". Both flows now have a
   stated, correct expected output; the G-01 payoff line is coherent under either.
3. **Quotes match real scratch runs** — verified against the on-disk scratch evidence
   and source, not just the fix doc's claims:
   - `.scratch/f-a/ws/campaigns/C-36f576bbc2/artifacts/invariant_links.json` (the
     in-sequence campaign) contains exactly one `INV-1`, `source: model`,
     `synthesized: liveness-template`, `applies_to: ["rollup_finalization"]` — the
     mechanism the new paragraph describes, read first-hand.
   - `.scratch/f-a/ws/campaigns/C-b7adb30545/` (the fresh campaign) has **no**
     `invariant_links.json` — the fresh-campaign refusal fires "before any write",
     consistent with the quoted output and §3.2-1's own preamble.
   - The quoted refusal text matches the implemented format string byte-for-byte
     (`internal/invariants/invariants.go:500`: `"protocol model: state machine(s) %s
     have no liveness invariant (one per machine — stage 37)"` under the `model load
     failed: ` wrapper).
   - The `.scratch/f-a/{skeleton,variant}.json` fixtures match the JSON the doc prints.

---

## New Critical/Important breakage introduced by the fix diff — NONE

Both commits are minimal and exactly scoped: one gate move + one additive test assertion
(Go), one paragraph (docs). No golden coverage touched, no pin moved (golden re-run GREEN
this session), refusal semantics strengthened not weakened, historical fixtures and all
other files untouched. The parked residual (`TestInvariantVerifyExecRelevanceGate` case
(b) still minting before Task 4's byte gate) was correctly **not** expanded, matching the
final review's ruling.

## Verdict

| Finding | Verdict |
|---|---|
| **F-B** (P1 — refused citation mints artifact row) | **ADDRESSED** |
| **F-A** (IMPORTANT — §3.2-1 refusal unreachable in-sequence) | **ADDRESSED** |
| New breakage in `bc80d151..64d7b11b` | **None** |

**PLAN COMPLETE.** Both must-fix items are closed with red→green and first-hand
reproduction evidence; every gate is green at HEAD in this session.
