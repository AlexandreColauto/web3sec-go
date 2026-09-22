# Task 1 re-review (fix round 1) — mutation-verified

**Scope reviewed:** the fix round the implementer recorded in
`.superpowers/sdd/2026-09-21-v16-p1-p2-record-and-evidence/task-1-report.md`
§"Fix round 1", against the three findings of
`docs/sdd/v16-p0/task-1-review.md` (two must-fix, one should-fix).

I did not write the fix and did not take its word for anything: every claim
below is the output of a mutation applied to the real tree, run, and reverted.
No file was fixed by me and nothing was committed.

**Tree state.** `469d8425` + the same 9 modified files and 12 untracked paths
the first review recorded; unchanged before and after this review
(`git status --short` compared at both ends). The fix changed exactly four
files, which I confirmed against the first review's own pinned hashes
(`.scratch/review/orig_sha.json`):

| file | pre-review sha256 | now | verdict |
|---|---|---|---|
| `internal/regression/regression.go` | `d41b2012…` | `f9575f76…` | changed (the fix) |
| `internal/regression/run.go` | `843a31ec…` | `50ed05da…` | changed (the fix) |
| `internal/audit/sections/regressionsuite.go` | `71cba6a3…` | `caa6b088…` | changed (the fix) |
| `internal/regression/target_test.go` | (not pinned) | `5097754c…` | changed (the fix) |
| `internal/regression/target.go` | `30b5a99f…` | `30b5a99f…` | **unchanged** |
| `internal/cli/cmd_regress.go` | `964b6946…` | `964b6946…` | **unchanged** |
| `internal/cli/cmd_regress_test.go` | `d557817b…` | `d557817b…` | **unchanged** |

A `find … -newer docs/sdd/v16-p0/task-1-review.md` sweep over `internal/`,
`assets/`, `docs/` and `scripts/` returns those four files and nothing else
(`internal/regression/target.go` also shows an mtime after the review, but that
is **my own** mutation harness restoring it — its content hash is unchanged).
So the report's "no `assets/` file was touched, so
`sync-asset-manifest.py` was not required" is correct, and the fix's blast
radius is exactly the four files it claims.

**Verdict: approve.** All three findings are genuinely fixed, and — this is the
part the first review could not say — the fixed tests now fail, for the right
reasons, under nine independent mutations. Two new minor items came in with the
fix (N1, N2 below); neither is a live defect and neither blocks.

---

## 1. MUST-FIX 1 — the ledger-law test could not fail — **FIXED, mutation-proven**

The defect was that the fixture was refused by `checkTargetSpec` before
`writeThenLog` was reached, so the test asserted nothing. Three things had to
become true, and each is now independently falsifiable.

### 1a. The fixture survives `checkTargetSpec` and the error is the ledger's

`TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails` now uses
`CommitHint: "main"` (non-empty, so the `RecordID`/`Repo` rule at
`target.go:58-61` does not fire) and `blockEvents` points `c.EventsPath` at a
directory, so `c.Log` fails **after** `validation.WriteJson` has landed the
projection. The test additionally requires the error to contain
`"events-as-a-directory"`.

Mutation **M-E** puts the *original* broken fixture back (drops
`CommitHint: "main"`):

```
--- FAIL: TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails
    target_test.go:211: err = a scabench target with an empty dataset commit field
    must still name its --record-id and --repo: … , want the ledger's own failure —
    a spec refusal never reaches the unwind this test exists to exercise
```

That is the exact defect the first review reported, now caught by the test's own
assertion. The guard is load-bearing.

### 1b. The unwind is really exercised

Mutation **M-A** (`restoreBytes` body replaced by `return nil` — no unwind at
all):

```
--- FAIL: TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails
    target_test.go:216: the projection survived a failed ledger write:
      […/regression/targets/T-0ec120295e12.json]
--- FAIL: TestWriteThenLogRestoresAPreExistingRecordOnAFailedRewrite
    target_test.go:272: the refused pin left resolved_sha
      "fe913cf530e2b800c43cf24ddc2a5ab87178ce6d" on the record
```

The first line is the proof that matters: the projection **was written** and
survived only because the restore was disabled — i.e. the test now reaches
`writeThenLog` and observes its post-write state. Under the pre-fix code the
same mutation left the package green (the first review's M1/M8).

### 1c. Breaking the ledger write itself is caught

| # | mutation (real tree, then reverted) | test(s) | result |
|---|---|---|---|
| M-C1 | `c.Log(eventType, ref, &data)` → `validation.VNull(), error(nil)` (the first review's M9: **no event is ever written**) | the two unwind tests + `TestEachWriterAppendsExactlyOneChainedEvent` | **FAIL ×3**: `target_test.go:209: AddTarget accepted a target whose ledger event could not be written`; `:270: PinTarget accepted a pin whose ledger event could not be written`; `:315: 1 event(s) in the ledger after the mutation, want 2 — exactly one hash-chained event per mutation` |
| M-C2 | `err != nil` → `err != nil && false` (the unwind branch made unreachable — the first review's M8) | the two unwind tests | **FAIL ×2**: `AddTarget accepted a target whose ledger event could not be written` / `PinTarget accepted …` |
| M-D | `blockEvents` made a no-op — `c.EventsPath` is never repointed, so **`c.Log` succeeds when it should not** | the two unwind tests | **FAIL ×2**: `AddTarget accepted a target whose ledger event could not be written`; `PinTarget accepted a pin whose ledger event could not be written` |
| M-I | `c.Log` called **twice** per mutation | `TestEachWriterAppendsExactlyOneChainedEvent` | **FAIL**: `3 event(s) in the ledger after the mutation, want 2` |
| M-M | the ledger writes a bogus `prev_hash` (`internal/state/eventlog.go:367` → `"deadbeef"`) | `TestEachWriterAppendsExactlyOneChainedEvent` | **FAIL**: `event prev_hash = "deadbeef", want the previous event_hash "bb99fbfc…"` |

M-D is the "remove the failure injection / make `c.Log` succeed" case asked for:
the test fails in the right way, at the assertion that the writer must not
accept a mutation whose event was not written. M-C1 is the sharper one — it is
the first review's M9, which left four packages green before this round, and it
is now caught by three tests including the count assertion. M-I and M-M show
the "exactly one hash-chained event" half is not decorative either: the count
and the chain link are both falsifiable.

**Baseline (unmutated), for the record:**

```
--- PASS: TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails (0.00s)
--- PASS: TestWriteThenLogRestoresAPreExistingRecordOnAFailedRewrite (0.02s)
--- PASS: TestEachWriterAppendsExactlyOneChainedEvent (0.01s)
ok  websec/internal/regression  0.039s
```

---

## 2. MUST-FIX 2 — the unwind destroyed a committed record — **FIXED, both cases**

### The code, read against `findings.SaveThenLog`

`writeThenLog` (`internal/regression/regression.go:126-153`) now snapshots the
prior bytes **before** the projection write and undoes the write through
`restoreBytes`:

```go
prevRaw, hadPrev, err := prevBytes(path)          // :131
if err != nil { return validation.VNull(), err }  // fail BEFORE writing
if err := validation.WriteJson(path, doc, ""); err != nil { … }   // :135
if _, err := c.Log(eventType, ref, &data); err != nil {           // :138
    if rErr := restoreBytes(path, prevRaw, hadPrev); rErr != nil {
        return … "ledger write failed (%v) (UNWIND ALSO FAILED: %v — the "+
            "projection may hold post-write bytes with no event; …)"   // :145
    }
    return validation.VNull(), err
}
```

`restoreBytes` (`:175-180`) removes only when `had == false` and otherwise
writes the snapshot back with `os.WriteFile(path, raw, 0o644)`; `prevBytes`
(`:159-168`) reports absence on `os.IsNotExist` and propagates any other read
error. That is behaviourally the same law as
`internal/findings/storage.go`'s `prevBytes`/`restoreBytes`/`SaveThenLog`
(`storage.go:166-206`), and the "UNWIND ALSO FAILED" voice is preserved — the
failed-restore case cannot be laundered into a clean error. The diff against
the first review's preserved pre-fix copy
(`.scratch/review/regression.go.orig`, sha256 `d41b2012…`, byte-identical to
the hash the first review pinned) is exactly this change and nothing else:

```
-		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
-			return validation.VNull(), fmt.Errorf(
-				"ledger write failed (%v) and the projection could not be unwound "+
-					"(%v) — the campaign store needs a manual clean", err, rmErr)
+		if rErr := restoreBytes(path, prevRaw, hadPrev); rErr != nil {
+			return … "(UNWIND ALSO FAILED: %v …)"
```

The comment's structural claim — "Every writer in this package goes through
here; there is no second path" — holds: `validation.WriteJson` appears exactly
once in the package (line 135), and the only writers are `AddTarget` (new id),
`RecordRun` (new id) and `PinTarget` (the existing path, the only rewrite).

### Both cases are tested, and each test fails when its behaviour breaks

| # | mutation (real tree, then reverted) | test(s) | result |
|---|---|---|---|
| M-A | `restoreBytes` → `return nil` | the two unwind tests | **FAIL ×2** — see §1b; the new-record case is caught by `the projection survived a failed ledger write`, the rewrite case by `the refused pin left resolved_sha …` |
| M-B | `restoreBytes` → the **ORIGINAL unconditional `os.Remove(path)`** | the two unwind tests | **FAIL**: only the rewrite test, `target_test.go:272: DATA LOSS: the failed pin removed the committed target record T-f2fdcb29505f`. The new-record test still **passes** — correct, that case was never the bug, and it is the control that shows the two tests discriminate |
| M-J | `prevBytes` always reports absence (`had == false`) | the two unwind tests | **FAIL**: rewrite test, `DATA LOSS: the failed pin removed the committed target record T-ecc3c98a4780` |
| M-N | `restoreBytes` writes `{"x":1}` instead of the snapshot | the two unwind tests | **FAIL**: `the restored record is not the pre-pin bytes: before {…"target_id": "T-671830445d75"…} after {"x":1}` |

So the **new-record** case (delete is correct) is pinned by the projection-gone
assertion, and the **rewrite** case (prior bytes restored, not deleted) is
pinned by three independent mutations: dropping the restore, reverting to the
old `os.Remove`, and corrupting the restored bytes. M-B in particular is the
regression test for this exact bug: re-introducing the shipped defect fails the
new test with the DATA LOSS line the first review predicted. `assertRestoredTo`
checks the right three facts — `Target` still returns `ok=true`, the refused pin
left no `resolved_sha`, and the on-disk bytes equal the pre-pin bytes.

**Caveat — N1 below:** the rewrite test proves the record was restored, but does
not pin *why* the pin failed. See §5.

---

## 3. SHOULD-FIX 3 — the comment described a check the code does not perform — **FIXED**

`internal/audit/sections/regressionsuite.go:11-24` no longer claims a snapshot
read-back. It now says `problems` "carries the five states that cannot be true
of a healthy suite, the same five `assets/runbook/RUNBOOK.md` §11 lists", names
them (three target-side, two run-side), and states explicitly that the pin's
EQUALITY rule is enforced on the write path (`checkPin`) and "is deliberately
NOT re-verified here: this section reads target and run records only and never
opens a snapshot".

Checked against the code, not the comment:

- `targetProblems` (`:98-114`) has exactly three arms — `sha == ""`,
  `!sha40.MatchString(sha)`, `sid == ""`. ✓
- `suiteRuns` (`:117-143`) has exactly two problem sites — `!byID[tid]` and
  `measurement != "rediscovery"`. ✓
- The section reads no snapshot: `rg snapshot internal/audit/sections/regressionsuite.go`
  matches only comment text and the `snapshot_id` *key name* of a target record;
  the only readers called are `regression.LoadTargets` and `regression.LoadRuns`,
  neither of which opens `snapshots/<id>/snapshot.json` (that read lives in
  `target.go`'s `readSnapshot`, reached only from `checkPin`). ✓
- RUNBOOK §11 (`assets/runbook/RUNBOOK.md:1741-1747`) lists the same five:
  "a target with no `resolved_sha`, a non-40-hex SHA, a missing snapshot
  binding, a run naming no target record, or a run without the D8 label". ✓

The doc comment now matches the code and the RUNBOOK. The report's choice
(comment, not implementation) is defensible: implementing the check would mean
a new snapshot read on the audit surface for a state `checkPin` refuses at write
time — the untestable-defensive-branch class the first review already flagged.

---

## 4. Regression check — nothing else broke

Run on the real tree, unmutated, with `GOCACHE=$PWD/.scratch/gocache`:

```
$ go test ./internal/regression ./internal/audit/... ./internal/cli ./internal/validation -count=1
ok  	websec/internal/regression	0.106s
ok  	websec/internal/audit	0.423s
ok  	websec/internal/audit/sections	0.989s
ok  	websec/internal/cli	34.544s
ok  	websec/internal/validation	0.138s

$ go test ./... -count=1                     # whole repo, background job
=== full suite exit: 0 ===                  # every package ok, no FAIL lines

$ go vet ./internal/regression ./internal/audit/...
(no output, exit 0)

$ golangci-lint run ./internal/regression/... ./internal/audit/sections/... --new-from-rev HEAD
(no output, exit 0)                          # v1.64.8
```

That reproduces all three verification commands the fix report printed,
including the `funlen`/statement-count claim that forced `assertRestoredTo`
(the lint gate is clean on the new test file). The first review's other
findings (MINOR 1–5, OBSERVATIONS) are untouched by this round, as the report
says; nothing about them regressed.

## 5. What the fix introduced — new findings

**N1 (should-fix, low) — the new rewrite test passes vacuously if `PinTarget`
refuses *before* the write.** The new-record test guards against exactly the
MUST-FIX-1 failure mode by asserting the error names the ledger
(`"events-as-a-directory"`); `TestWriteThenLogRestoresAPreExistingRecordOnAFailedRewrite`
only asserts `err != nil`. Mutation **M-G** makes `checkPin` refuse
unconditionally (a pre-write refusal inside `PinTarget`):

```
### M-G  checkPin ALWAYS refuses (pre-write refusal inside PinTarget)  ->  PASS
    | ok  	websec/internal/regression	0.022s
```

The test passes because the record was never touched: `Target` still returns
`ok=true`, `resolved_sha` is empty, and the bytes equal `before`. So if
`checkPin` (or `requireTarget`, or the spec validation) ever starts refusing the
fixture's real snapshot, this test silently stops testing the restore. This is
the same class as MUST-FIX 1 — not a hole in today's coverage (M-A/M-B/M-J/M-N
all fail it) but a missing one-line assertion. Fix: require the error to contain
`"events-as-a-directory"`, as the sibling test does.

**N2 (minor) — the new "UNWIND ALSO FAILED" branch has no test.** It is new
code introduced by this round (`regression.go:139-149`) and it is reachable —
`os.WriteFile`/`os.Remove` can fail — but `rg 'UNWIND' internal/regression/*_test.go`
is empty. The repo already tests the analogous `findings` branch and has the
technique: `internal/maximization/zz_r42_test.go:270-300` `chmod 0444`s the
target file so the restore cannot land, then asserts the message and that the
file was not half-changed. Same treatment would cover it here. Not a defect;
noted because the first review's own "untested defensive branch" observation
class applies to new code too.

**N3 (note) — the double-failure path does not wrap the ledger error.**
`findings.SaveThenLog` returns `fmt.Errorf("%w (UNWIND ALSO FAILED: %v …)", err, rerr)`;
the new code uses `%v` for `err` as well, so on that path `errors.Is(err, ledgerErr)`
is false (it is true on the ordinary refusal path, which returns `err` raw).
No caller or test does `errors.Is` on `writeThenLog`'s error today
(`rg 'errors\.Is' internal/regression internal/cli/cmd_regress.go` is empty), so
this is cosmetic — but the comment claims to follow `SaveThenLog`, and `%w` is
the part of that pattern the `findings` version deliberately kept.

**N4 (note) — the corrected `kindName` comment makes one claim of its own that
does not hold.** The body is genuinely byte-for-byte
`internal/pipeline/status.go:182` (verified by extracting both function bodies
and comparing: `True`), and the "unexported, so a copy is required" reasoning is
correct. But "the same decision the two other copies record" overstates: the
`pipeline` copy has no comment at all, and `completion/support.go:110`'s
comment describes the Python type name, not a duplication decision. Given that
this round exists partly to remove a false claim from a comment, the phrase is
worth trimming.

No swallowed error, no unreachable branch, and no second write path was
introduced: `prevBytes`'s non-`IsNotExist` error is returned, `restoreBytes`'s
error is named rather than dropped, and `validation.WriteJson` still has exactly
one call site. The duplicated `prevBytes`/`restoreBytes` are the sanctioned
house-rule copy (`internal/findings/storage.go:193,201` are the only other
copies) and the comment says so.

## 6. What I could not verify

- **`run.go` and `regressionsuite.go` could not be diffed byte-for-byte.** Both
  are untracked and no pre-fix copy exists (`.scratch/review/` kept only
  `regression.go.orig` and `cmd_regress.go.orig`). I verified their *current*
  content against the review's quoted pre-fix text (the section comment's
  removed sentence, the `kindName` claim) and against the code, and the
  behavioural surface is green — but a silent non-comment edit in those two
  files would not have been visible to me. Everything I could pin is pinned.
- `scripts/verify-full.sh` (14 steps, heavy) was not run — same limitation the
  first review recorded. The presence-gate claim it would settle is unaffected
  by this round (the section's code did not change).
- The ScaBench baseline runner and the Nethermind judge arm (no
  `OPENAI_API_KEY`) — unchanged from the first review, and unrelated to these
  three findings.
- I did not re-verify the operator run / gate record (`docs/gates/v16-P0.md`),
  the schema discipline, or MINOR 1–5; the first review settled them and this
  round's four-file diff does not touch them.

## 7. Scratch edits, and the state I left

Every mutation was applied to the real tree, run with `-count=1`, and reverted
from a byte-exact backup; the harness asserts the restored sha256 equals the
pre-mutation hash on every single mutation, and it never once mismatched. Final
hashes (unchanged from before this review):

```
f9575f76…  internal/regression/regression.go
30b5a99f…  internal/regression/target.go
50ed05da…  internal/regression/run.go
5097754c…  internal/regression/target_test.go
caa6b088…  internal/audit/sections/regressionsuite.go
760812e4…  internal/state/eventlog.go     (mutated once, restored)
```

`git status --short` at the end is identical to `git status --short` at the
start (9 modified, the same 12 untracked paths). No implementation file, no
test, no record and no asset was left modified; nothing was committed. Review
artifacts — the harness and the mutation specs — live under
`.scratch/rereview/` (git-ignored), and the only file this review created
outside it is this one.
