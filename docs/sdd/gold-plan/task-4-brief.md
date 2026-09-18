### Task 4: offline gold scorer (`scripts/eval-gold.py`)

The 0/2 score was produced by hand. This task makes it a repeatable command with hermetic tests, honoring the benchmark's own `match_criteria`, `pass`, `bonus`, and `false_positive_budget` strings verbatim (read from `web3sec-final/targets/gold-findings.json`, never re-typed). The scorer is offline analysis of a finished campaign record — it never runs tooling against a target.

**Files:**
- Create: `scripts/eval-gold.py`
- Test: `scripts/eval_gold_test.py` (Python unittest, stdlib only)

**Interfaces:**
- Consumes: `web3sec-final/targets/gold-findings.json` schema: top-level `gold_findings[]` each with `gold_id`, `bug_class_accept`, `match_criteria`, `expected_severity`, `primary_functions`; top-level `scoring` with `pass`, `bonus`, `false_positive_budget`.
- Consumes (pinned campaign-dir contract — the implementer does NOT reverse-engineer it mid-task): a campaign dir containing
  - `findings.json` — a JSON array of finding objects with at least `id`, `status`, `bug_class`, `text`, `primary_functions` (string array), `artifacts` (array of artifact ids);
  - `events.jsonl` — one JSON object per line (parse line-by-line; `json.load` on the whole file WILL fail).
  The exact real file names and field spellings are confirmed in Step 0 (`rg -n "links.json|events.jsonl|findings" internal/state` and one real campaign fixture) and pinned in a schema comment block at the top of `eval-gold.py` referencing the Go structs (`internal/state`) they mirror. The test harness builds synthetic campaign dirs with exactly this layout; if the real names differ from these two, the fixtures follow the REAL names (discovered in Step 0) and this plan's names are corrected in the same commit.
- Produces: `python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir> [--confirm G-ID ...]` — exit 0 on any well-formed scoring run (scoring is not a gate); exit 2 with a clean stderr message (no raw traceback) when inputs are missing/malformed (gold file absent, campaign dir absent, either pinned file absent, unparseable JSON/JSONL, or a `--confirm` id that names no gold finding). Stdout is one JSON object with EXACTLY this schema (the full decision table the tests pin):

  | field | type | semantics |
  |---|---|---|
  | `found` | array of gold ids | gold findings whose `match_criteria` keywords and `primary_functions` match a campaign finding (word-boundary keyword match, `(?i)\b<tok>\b` here — finding TEXT is natural language prose, where `\b` IS correct; this deliberately differs from Task 1's command matcher, which operates on shell commands) at an accepted evidence state |
  | `missed` | array of gold ids | the complement |
  | `false_positives` | int | count of campaign findings at `CONFIRMED` that match no gold's criteria |
  | `pass` | bool | true iff G-01 is in `found`. **Independent of FP count and of operator confirmation.** |
  | `bonus` | bool | true iff `pass` AND G-02 in `found` |
  | `verdict` | string | `PASS_WITH_BONUS` if bonus; `PASS` if pass AND `false_positives < 10`; `PARTIAL_RESULT` if pass AND `false_positives >= 10` (the benchmark's own words: "buries it under 10+ FPs is a partial result" — the budget is verdict-affecting at that boundary, read from `scoring.false_positive_budget` at runtime, not hardcoded); `FAIL` otherwise |
  | `verdict_note` | string | non-empty exactly when: `verdict == "PARTIAL_RESULT"` (contains `partial result` plus the FP count) OR any found gold lacks operator confirmation (`operator semantic confirmation pending for: G-01`); empty string otherwise |
  | `operator_confirmed` | object keyed by gold id | `--confirm G-01` sets `true`; default `false` for every found gold. Advisory only — it never changes `pass`/`bonus`/`verdict`; it exists so a human semantic judgment is not silently laundered into the machine verdict |

- [ ] **Step 1: Write the failing tests**

`scripts/eval_gold_test.py` builds synthetic campaign dirs in `tempfile.mkdtemp()` with the pinned layout and asserts the decision table:

```python
class TestGoldScorer(unittest.TestCase):
    def test_empty_campaign_scores_fail(self):
        out = run_scorer(FIXTURE_CAMPAIGN_EMPTY)
        self.assertEqual(out["found"], [])
        self.assertFalse(out["pass"])
        self.assertEqual(out["verdict"], "FAIL")

    def test_g01_confirmed_scores_pass_pending_confirmation(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01)
        self.assertEqual(out["found"], ["G-01"])
        self.assertTrue(out["pass"])                       # pass is independent of confirmation
        self.assertEqual(out["verdict"], "PASS")
        self.assertFalse(out["operator_confirmed"]["G-01"])
        self.assertIn("operator semantic confirmation pending", out["verdict_note"])
        confirmed = run_scorer(FIXTURE_CAMPAIGN_G01, confirm=["G-01"])
        self.assertTrue(confirmed["operator_confirmed"]["G-01"])
        self.assertEqual(confirmed["verdict_note"], "")

    def test_fp_budget_is_verdict_affecting_at_boundary(self):
        under = run_scorer(FIXTURE_CAMPAIGN_G01_AND_9_FPS)
        self.assertEqual(under["verdict"], "PASS")
        over = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
        self.assertEqual(over["false_positives"], 11)
        self.assertEqual(over["verdict"], "PARTIAL_RESULT")
        self.assertIn("partial result", over["verdict_note"])

    def test_missing_campaign_file_exits_cleanly(self):
        rc, err = run_scorer_raw(MISSING_DIR)
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)

    def test_unknown_confirm_id_exits_cleanly(self):
        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, confirm=["G-99"])
        self.assertEqual(rc, 2)
        self.assertIn("no gold finding", err)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 scripts/eval_gold_test.py`
Expected: FAIL — `eval-gold.py` does not exist.

- [ ] **Step 3: Implement the scorer**

Pure stdlib: `argparse`, `json`, `re`, `pathlib`, `sys`. Before parsing anything, verify every input file exists and print `eval-gold: <path> not found` to stderr with `sys.exit(2)` on absence — never a raw `FileNotFoundError` traceback. Parse `events.jsonl` line-by-line (`for line in f`). Schema-drift guard: the file's top comment block pins the campaign-dir contract with the Go struct names it mirrors, and the scorer asserts the expected top-level keys exist in the findings JSON before scoring, failing loudly with `eval-gold: campaign findings schema mismatch (expected keys: ...)` on drift instead of silently mis-scoring. Keyword matching over finding text uses `(?i)\b<tok>\b` (correct here: natural-language prose). The scorer never mutates the campaign or the benchmark file.

- [ ] **Step 4: Tests pass, then wire the invocation into the docs ONLY**

Run: `python3 scripts/eval_gold_test.py` (PASS) and `python3 -m unittest scripts.eval_gold_test` if the scripts dir is importable — pin whichever invocation works without path hacks in the Task 5 protocol. Do NOT add it to `verify-full.sh` (the 13-step pin is deliberate; a python step would add an interpreter dependency to the release gate — YAGNI).

- [ ] **Step 5: Commit**

```bash
git add scripts/eval-gold.py scripts/eval_gold_test.py
git commit -m "feat(eval): offline gold scorer honoring benchmark match criteria"
```

---

