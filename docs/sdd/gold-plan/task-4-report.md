# Task 4 report — offline gold scorer (`scripts/eval-gold.py`)

**STATUS: COMPLETE** — commit `8b2886ec` on `production-readiness` (BASE `280e348d`).

**Test summary:** `python3 scripts/eval_gold_test.py` → 25/25 OK (red-first: 25 failures before the scorer existed), `python3 -m unittest scripts.eval_gold_test` → 25/25 OK, `go test ./... -count=1` → 71 packages ok / 0 FAIL, `go vet ./...` → clean; the real benchmark against the real Morph campaign reproduces the hand-produced 0/2 in one command.

```
$ python3 scripts/eval-gold.py --gold .../web3sec-final/targets/gold-findings.json \
      --campaign .../morph/campaigns/C-7f1005ecd5
{"found": [], "missed": ["G-01", "G-02"], "false_positives": 0, "pass": false,
 "bonus": false, "verdict": "FAIL", "verdict_note": "", "operator_confirmed": {}}
exit=0
```

## Step 0 — the real campaign record (the brief's names were wrong; corrected)

`rg -n "links\.json|events\.jsonl|findings" internal/state` + the real records on disk:

| brief says | the REAL record says | where it is pinned in Go |
|---|---|---|
| `findings.json` (one JSON array) | `findings/F-<id>.json`, **one finding object per file** | `internal/state/campaign.go` (`Campaign.FindingsDir` = `<root>/campaigns/<id>/findings`), `internal/findings/storage.go` (`FindingPath`, `LoadAllFindings` → `validation.ListPrefixedOptional(dir, "F-", ".json")`) |
| `id` | `finding_id` | `findings.SaveFinding` → `validation.Validate(_, "finding", 1)` against `assets/schema/finding.schema.json` |
| `bug_class` | `root_cause.class` | same schema (`root_cause.required: [class, description]`) |
| `text` | `title` + `root_cause.description` (+ optional `root_cause.mechanism`) | same schema |
| `primary_functions` (string array) | `affected[].function` (optional per item, `path` required) | same schema |
| `artifacts` (array of artifact ids) | `evidence[].artifact_id` | same schema |
| `links.json` (from the Step 0 grep) | `artifacts/invariant_links.json` — not part of this scoring contract | `internal/invariants.SaveLinks` (`internal/state/artifacts.go:824`) |
| `events.jsonl` | `events.jsonl` — **correct as briefed** | `internal/state/campaign.go` (`Campaign.EventsPath`) |

Real records inspected: `scripts/legacy/campaigns/C-45488bdaf5/findings/F-*.json` (2 findings; all 14
schema-`required` keys present) and the real Morph campaign
`/home/xand/Projects/dsh-plugins/websec2/morph/campaigns/C-7f1005ecd5` (empty `findings/` + a 62-line
`events.jsonl`). The two names the brief got right (`events.jsonl`, campaign-dir layout) were kept; the
findings-store names were replaced with the real ones everywhere (scorer, tests, schema comment block).
**The plan was corrected in the same commit** (`docs/superpowers/plans/2026-09-18-gold-findings-closure.md`,
Task 4 Interfaces bullet) and its Task 5 protocol now pins the verified test invocation.

## What was built

* `scripts/eval-gold.py` (344 lines) — offline scorer, stdlib only (`argparse`, `json`, `re`, `sys`,
  `pathlib`). Its top comment block is the pinned contract: real file names, real field spellings, and the
  Go structs/validators each one mirrors.
* `scripts/eval_gold_test.py` (377 lines) — `unittest`, stdlib only; synthetic campaign dirs in
  `tempfile.mkdtemp()` in the pinned layout, a synthetic benchmark with the real `gold-findings.json`
  schema. No pip, no network, no target.

Decision table as implemented (all pinned by tests):

* `found` — gold ids whose `match_criteria` + `primary_functions` match a campaign finding at an accepted
  evidence state; `missed` is the complement, both in benchmark order.
* **Accepted evidence state** — the benchmark's own words (`scoring.pass`): `CONFIRMED` with E4+ evidence
  (highest `evidence[].level` ≥ E4, the ladder of `internal/findings.EVIDENCE_ORDER`), **or**
  `HYPOTHESIS`/`INVESTIGATING` with a reproduced PoC attempt (`verification.reproduction.attempts[].outcome
  == "reproduced"`); "the correct root cause named" is the criteria match itself.
* **Matching** — ≥ `MIN_KEYWORD_HITS` (3) distinct `match_criteria` content tokens **and** one
  `primary_function`, each tested as `(?i)\b<tok>\b` over the finding's prose (`title` +
  `root_cause.description` + `root_cause.mechanism`); the function also matches against
  `affected[].function`. `\b` is correct here and deliberately differs from Task 1's command matcher
  (commented in both the module docstring and `word_hit`).
* `false_positives` — campaign findings at `CONFIRMED` matching no gold's criteria (status-based, per the
  brief's row); a matched finding is never counted, and a criteria-matching finding that is *not* accepted
  (e.g. `CONFIRMED` with only E2 evidence) is neither `found` nor an FP.
* `pass` = `G-01` in `found` (independent of FPs and of `--confirm`); `bonus` = `pass` and `G-02` in
  `found`.
* `verdict` — `PASS_WITH_BONUS` if bonus; `PASS` if pass and `false_positives <` budget;
  `PARTIAL_RESULT` if pass and `>=` budget; `FAIL` otherwise. **The budget is parsed at runtime out of
  `scoring.false_positive_budget`'s prose** (`(\d+)\s*\+?\s*FPs?` → 10 in the real file); a benchmark whose
  budget prose carries no number is refused (exit 2), never defaulted.
* `verdict_note` — non-empty exactly for `PARTIAL_RESULT` (contains `partial result` + the FP count) and/or
  found golds lacking operator confirmation (`operator semantic confirmation pending for: G-01`); `"; "`
  joins both; `""` otherwise.
* `operator_confirmed` — `{gold_id: bool}`, keys = found ∪ `--confirm` ids, `true` only for ids passed to
  `--confirm`. Advisory: `--confirm G-01` on a FAIL run still reports `{"G-01": true}` and does not move
  `pass`/`verdict`.
* Exit codes — `0` on any well-formed scoring run; `2` with a one-line `eval-gold: …` stderr message (no
  traceback) for: gold file absent, campaign dir absent, `findings/` absent, `events.jsonl` absent,
  unparseable JSON/JSONL, findings schema drift, gold schema drift, unreadable budget, unknown `--confirm`
  id. `events.jsonl` is read line-by-line and validated only (a whole-file `json.load` cannot read it).
* The scorer never writes: a test hashes the campaign tree and the benchmark before/after a run.

## Evidence (logs in `task-4-logs/`)

| log | result |
|---|---|
| `red.txt` | 25 tests, 25 failures (scorer did not exist) |
| `python-test-script.log`, `python-test-module.log`, `python-test-postcommit.log` | 25/25 OK, exit 0 |
| `real-run.log` | real benchmark × real Morph campaign = the 0/2 verdict, exit 0; `--confirm G-01` stays FAIL; unknown `--confirm` → exit 2 `names no gold finding`; missing dir → exit 2 `not found` |
| `gotest-all.log` / `gotest-postcommit.log` | `go test ./... -count=1` → 71 ok, 0 FAIL, exit 0 |
| `govet.log` / `govet-postcommit.log` | `go vet ./...` → exit 0, empty |

Go gate invocation (needed in this session's sandbox, see concern 6):
`GOTOOLCHAIN=local GOMODCACHE=$PWD/.scratch/gomodcache GOCACHE=$PWD/.scratch/gocache
GOPATH=$PWD/.scratch/gopath GOSUMDB=off GOFLAGS=-mod=mod go test ./... -count=1`.

## Concerns / deliberate decisions for the reviewer

1. **Accepted-state breadth.** The benchmark's parenthetical (HYPOTHESIS/INVESTIGATING + named root cause +
   working PoC draft) is machine-checked as "status ∈ {HYPOTHESIS, INVESTIGATING} **and** a reproduced
   attempt", because the brief's `found` row says "at an accepted evidence state" while its FP row says
   "at CONFIRMED". If the reviewer rules that only `CONFIRMED` may be accepted, set `POC_STATUSES = ()` —
   one line, and the `test_hypothesis_*` tests document the current behavior.
2. **Missing `findings/` dir is refused (exit 2), not scored as empty.** The Go store's `r43a` rule
   (`validation.ListPrefixedOptional`) treats a missing findings dir as an empty campaign, but the brief's
   exit-code contract explicitly lists "either pinned file absent" → exit 2, and silently scoring a broken
   record as 0/2 is exactly the mis-scoring the schema-drift guard exists to prevent. The real Morph
   campaign has an *empty but present* `findings/`, so the repeatable 0/2 path is unaffected.
3. **The keyword quorum is a heuristic** (3 tokens + 1 function), named in the code with a `ponytail:`
   ceiling note. It is not a semantic matcher; the benchmark's FP budget and `--confirm` are the human
   layer over it. No real Morph finding exists to calibrate against (the campaign produced none), so the
   quorum is validated only by synthetic fixtures — a fresh re-run's first real finding is the calibration
   datum.
4. **`operator_confirmed` keeps a confirmation of a *missed* gold** (key present, `true`) rather than
   dropping the operator's input on the floor; it still cannot affect `pass`/`bonus`/`verdict`.
5. **`bug_class_accept` is deliberately not gated on** — it is an any-of accept-list, and the brief's
   decision table does not gate on it (documented in the scorer docstring).
6. **Sandbox: Go caches are read-only here.** `/home/xand/go/pkg/mod`, `/home/xand/go/pkg/sumdb` and
   `/home/xand/.cache/go-build` are read-only under this session's `workspace-write` policy, so the plain
   `go test ./...` from the brief fails with `[setup failed]` on every package (first `gotest-all.log`
   run) — that is environment, not regression. The green runs above used workspace-local caches
   (`.scratch/gomodcache`, `.scratch/gocache`, `.scratch/gopath`) plus `GOTOOLCHAIN=local`; the installed
   toolchain is `go1.26.6`, identical to `go.mod`'s `toolchain go1.26.6`, so `GOTOOLCHAIN=local` runs the
   same compiler. If Task 3's `71 ok` run used the host caches, its sandbox was wider than this one.
7. **The real benchmark is outside this repo** (`/home/xand/Projects/dsh-plugins/websec2/web3sec-final/…`),
   so the tests build a synthetic benchmark (hermetic, no external path) and the real file was used only
   for the manual evidence run in `real-run.log`.
8. **No CI wiring** — per the brief, `verify-full.sh` was not touched (the 13-step pin stays).
9. Historical fixtures untouched (`scripts/legacy/…` unchanged; the commit contains only the two new
   scripts + the plan correction).

---

# Fix round 1 (review findings MEDIUM-1, LOW-2, LOW-3)

**STATUS: COMPLETE** — commit `e28efeed` on `production-readiness` (BASE `99e7e906`, the review round's
HEAD). No push, no merge, no delegation. Files touched, both by exact path: `scripts/eval_gold_test.py`
(tests) and `scripts/eval-gold.py` (comments only — zero behavior change).

## What changed, per finding

* **MEDIUM-1 (boundary not pinned) — closed.** Added the missing exactly-at-budget fixtures so the `>=`
  comparison itself is pinned, not just 9/11 either side of it:
  * new module fixture `FIXTURE_CAMPAIGN_G01_AND_10_FPS` (`campaign([g01()] + fps(10))`, built once in
    `setUpModule()`), asserted in `test_fp_budget_is_verdict_affecting_at_boundary`: `10 FPs` →
    `false_positives == 10` and `verdict == "PARTIAL_RESULT"`. The pre-existing 9-FP under-budget (`PASS`)
    and 11-FP over-budget cases are kept unchanged in the same test.
  * `test_fp_budget_boundary_comes_from_the_benchmark_string` (budget 5 from prose) gained the same
    exact-boundary assertion: `fps(5)` → `5` FPs → `PARTIAL_RESULT`, keeping the 4 (`PASS`) and 6
    (`PARTIAL_RESULT`) cases.
* **LOW-2 (dead `INVESTIGATING` branch) — closed, comment only.** `scripts/eval-gold.py` `POC_STATUSES`
  now carries the contract note: `INVESTIGATING` is **not** in `assets/schema/finding.schema.json`'s
  `status` enum (`HYPOTHESIS, NEEDS_RESEARCH, PROVISIONALLY_VALID, POSSIBLE, CONFIRMED, …`), so the store
  can never emit it and no schema-validated finding reaches that path — it is kept only because the
  benchmark's `scoring.pass` prose names it, and is not a live accept path. The module docstring's
  MATCHING paragraph points at that note. No code, no enum, no behavior change.
* **LOW-3 (bonus short-circuit unpinned) — closed.** New `test_bonus_short_circuits_the_fp_budget`:
  G-01 + G-02 both found **and** `fps(10)` (exactly the budget) → `found == ["G-01","G-02"]`,
  `false_positives == 10`, `bonus is True`, `verdict == "PASS_WITH_BONUS"`, `verdict_note == ""` (no
  partial-result note). Confirmed with `--confirm G-01 --confirm G-02` so the empty note pins the
  *absence of the partial note*, not the pending-confirmation note.

Not touched: `scripts/legacy/…`, `verify-full.sh`, the plan doc, any Go file. `scripts/eval-gold.py`'s
diff is 7 added / 1 changed line, all inside comments/docstring.

## Evidence

| gate | result |
|---|---|
| `python3 scripts/eval_gold_test.py` (post-commit) | `Ran 26 tests … OK`, exit 0 (was 25 tests; +1 new test) |
| `python3 -m unittest scripts.eval_gold_test` (post-commit) | `Ran 26 tests … OK`, exit 0 |
| red-check: boundary mutant | mutated `elif false_positives < budget:` → `elif false_positives <= budget:` once, ran the suite: `FAILED (failures=2)` — exactly `test_fp_budget_is_verdict_affecting_at_boundary` and `test_fp_budget_boundary_comes_from_the_benchmark_string`, 2 `AssertionError`s (the new at-budget assertions). File restored from the pre-mutation copy; suite re-run `OK`. The off-by-one can no longer pass. |
| `go vet ./...` (hygiene; no Go change) | exit 0, empty — run as `GOTOOLCHAIN=local GOMODCACHE=$PWD/.scratch/gomodcache GOCACHE=$PWD/.scratch/gocache GOPATH=$PWD/.scratch/gopath GOSUMDB=off GOFLAGS=-mod=mod go vet ./...` (same workspace-local caches as concern 6) |
| `git status --short` after commit | only the pre-existing untracked `.superpowers/`; both scripts clean |

Fix commit: `e28efeed test(eval): pin FP-budget boundary and bonus short-circuit (review round 1)`
(2 files changed, 28 insertions, 2 deletions).
