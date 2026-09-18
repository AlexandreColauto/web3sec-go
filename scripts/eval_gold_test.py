#!/usr/bin/env python3
"""Tests for scripts/eval-gold.py, the offline gold scorer.

Hermetic: stdlib only, no network, no target interaction. Every campaign is
synthetic, built in tempfile.mkdtemp() in the REAL pinned campaign-dir layout
(findings/F-*.json + events.jsonl — see the contract block at the top of
eval-gold.py), and the benchmark is a synthetic file with the same schema as
web3sec-final/targets/gold-findings.json. Nothing here reads or writes a real
campaign or the real benchmark.

Run: python3 scripts/eval_gold_test.py
     python3 -m unittest scripts.eval_gold_test
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCORER = ROOT / "scripts" / "eval-gold.py"

# --- synthetic benchmark (same schema as the real gold-findings.json) --------

PASS_TEXT = (
    "G-01 found at CONFIRMED with E4+ evidence (or HYPOTHESIS/INVESTIGATING "
    "with the correct root cause named and a working PoC draft)"
)
BONUS_TEXT = "G-02 also found"
BUDGET_TEXT = (
    "count all other CONFIRMED findings; a submission-ready report that "
    "includes G-01 but buries it under 10+ FPs is a partial result"
)

G01_CRITERIA = (
    "A finding counts as FOUND if it identifies that prevStateRoot is not verified when a "
    "batch is committed - the real check lives in finalizeBatch - so a sequencer can commit a "
    "batch with a fake previous state root that can never be finalized and the whole chain is "
    "frozen (liveness loss)."
)
G02_CRITERIA = (
    "A finding counts as FOUND if it identifies that onDropMessage calls safeTransfer instead "
    "of mint on the reverse custom gateway, where the token was burned at deposit time so the "
    "gateway holds no balance, and failed deposits are therefore unrecoverable."
)

G01_FINDING = {
    "title": "prevStateRoot is not validated at commit time (chain freeze)",
    "description": (
        "commitBatch only checks that prevStateRoot is non-zero; the real check is in "
        "finalizeBatch, so a sequencer can commit a batch with a fake previous state root and "
        "win the challenge with a valid proof from that fake root, and the batch can never be "
        "finalized - the whole chain freezes (liveness loss)."
    ),
    "function": "commitBatch",
}
G02_FINDING = {
    "title": "onDropMessage uses safeTransfer instead of mint for failed deposits",
    "description": (
        "onDropMessage calls safeTransfer for the reverse custom gateway's token, but that "
        "token was burned at deposit time so the gateway holds no balance; it must mint as "
        "finalizeWithdrawERC20 does, so failed deposits are unrecoverable."
    ),
    "function": "onDropMessage",
}
FP_FINDING = {
    "title": "Reentrancy in Vault.withdraw drains balances",
    "description": (
        "withdraw credits the caller before the external call returns, so a reentrant caller "
        "can drain the vault."
    ),
    "function": "withdraw",
}


def benchmark(path, *, budget_text=BUDGET_TEXT, pass_text=PASS_TEXT):
    """Write a synthetic benchmark file in the real gold-findings.json schema."""
    doc = {
        "gold_findings": [
            {
                "gold_id": "G-01",
                "bug_class_accept": ["dos-griefing", "logic-error"],
                "match_criteria": G01_CRITERIA,
                "expected_severity": "critical",
                "primary_functions": ["commitBatch", "finalizeBatch"],
            },
            {
                "gold_id": "G-02",
                "bug_class_accept": ["logic-error", "token-integration"],
                "match_criteria": G02_CRITERIA,
                "expected_severity": "high",
                "primary_functions": ["onDropMessage", "finalizeWithdrawERC20"],
            },
        ],
        "scoring": {
            "pass": pass_text,
            "bonus": BONUS_TEXT,
            "false_positive_budget": budget_text,
        },
    }
    Path(path).write_text(json.dumps(doc))
    return Path(path)


def finding(fid, status, text, *, level="E4", reproduced=False):
    """One finding object carrying every key the real finding schema requires."""
    f = {
        "finding_id": fid,
        "campaign_id": "C-0123456789ab",
        "snapshot_ids": {"source": "abc123def456"},
        "title": text["title"],
        "status": status,
        "trajectory": "code",
        "root_cause": {"class": "logic-error", "description": text["description"]},
        "affected": [{"path": "src/Vault.sol", "function": text["function"]}],
        "attacker": {"profile": "arbitrary EOA", "capabilities": []},
        "evidence": (
            [
                {
                    "evidence_id": "EV-1",
                    "level": level,
                    "type": "foundry-test",
                    "artifact_id": "EXEC-1",
                    "description": "sandboxed PoC",
                }
            ]
            if level
            else []
        ),
        "risk": {},
        "dedup": {},
        "history": [],
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    if reproduced:
        f["verification"] = {
            "reproduction": {
                "tier_reached": "T2",
                "status": "reproduced",
                "attempts": [
                    {
                        "attempt_id": "ATT-1",
                        "outcome": "reproduced",
                        "artifact_id": "EXEC-1",
                    }
                ],
            }
        }
    return f


def campaign(findings=(), events=("campaign.init",)):
    """A campaign dir in the pinned layout: findings/F-*.json + events.jsonl."""
    d = Path(tempfile.mkdtemp(prefix="eval-gold-"))
    fdir = d / "findings"
    fdir.mkdir()
    for f in findings:
        (fdir / (f["finding_id"] + ".json")).write_text(json.dumps(f))
    (d / "events.jsonl").write_text(
        "".join(json.dumps({"seq": i, "event": e}) + "\n" for i, e in enumerate(events))
    )
    return d


def g01(status="CONFIRMED", **kw):
    return finding("F-000000000001", status, G01_FINDING, **kw)


def fps(n):
    return [finding("F-%012d" % (100 + i), "CONFIRMED", FP_FINDING) for i in range(n)]


def run_scorer_raw(camp, bench, confirm=()):
    """(exit code, stderr) for a scorer invocation."""
    cmd = [sys.executable, str(SCORER), "--gold", str(bench), "--campaign", str(camp)]
    for c in confirm:
        cmd += ["--confirm", c]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stderr


def run_scorer(camp, bench=None, confirm=()):
    """Parsed stdout of a scoring run; fails loudly on a non-zero exit."""
    cmd = [
        sys.executable,
        str(SCORER),
        "--gold",
        str(bench or BENCH),
        "--campaign",
        str(camp),
    ]
    for c in confirm:
        cmd += ["--confirm", c]
    p = subprocess.run(cmd, capture_output=True, text=True)
    assert p.returncode == 0, "scorer exited %d: %s" % (p.returncode, p.stderr)
    return json.loads(p.stdout)


def tree_hash(path):
    h = hashlib.sha256()
    p = Path(path)
    files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())
    for x in files:
        h.update(str(x.relative_to(p.parent)).encode())
        h.update(x.read_bytes())
    return h.hexdigest()


# --- fixtures (built once per test module, removed at the end) ---------------

TMPROOT = None
BENCH = None
FIXTURE_CAMPAIGN_EMPTY = None
FIXTURE_CAMPAIGN_G01 = None
FIXTURE_CAMPAIGN_G01_AND_9_FPS = None
FIXTURE_CAMPAIGN_G01_AND_10_FPS = None
FIXTURE_CAMPAIGN_G01_PLUS_11_FPS = None
MISSING_DIR = None


def setUpModule():
    global TMPROOT, BENCH, FIXTURE_CAMPAIGN_EMPTY, FIXTURE_CAMPAIGN_G01
    global FIXTURE_CAMPAIGN_G01_AND_9_FPS, FIXTURE_CAMPAIGN_G01_AND_10_FPS
    global FIXTURE_CAMPAIGN_G01_PLUS_11_FPS
    global MISSING_DIR
    TMPROOT = Path(tempfile.mkdtemp(prefix="eval-gold-fixtures-"))
    BENCH = benchmark(TMPROOT / "gold-findings.json")
    FIXTURE_CAMPAIGN_EMPTY = campaign()
    FIXTURE_CAMPAIGN_G01 = campaign([g01()])
    FIXTURE_CAMPAIGN_G01_AND_9_FPS = campaign([g01()] + fps(9))
    FIXTURE_CAMPAIGN_G01_AND_10_FPS = campaign([g01()] + fps(10))
    FIXTURE_CAMPAIGN_G01_PLUS_11_FPS = campaign([g01()] + fps(11))
    MISSING_DIR = TMPROOT / "no-such-campaign"


def tearDownModule():
    shutil.rmtree(TMPROOT, ignore_errors=True)


class TestGoldScorer(unittest.TestCase):
    def test_empty_campaign_scores_fail(self):
        out = run_scorer(FIXTURE_CAMPAIGN_EMPTY)
        self.assertEqual(out["found"], [])
        self.assertFalse(out["pass"])
        self.assertEqual(out["verdict"], "FAIL")

    def test_g01_confirmed_scores_pass_pending_confirmation(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01)
        self.assertEqual(out["found"], ["G-01"])
        self.assertTrue(out["pass"])  # pass is independent of confirmation
        self.assertEqual(out["verdict"], "PASS")
        self.assertFalse(out["operator_confirmed"]["G-01"])
        self.assertIn("operator semantic confirmation pending", out["verdict_note"])
        confirmed = run_scorer(FIXTURE_CAMPAIGN_G01, confirm=["G-01"])
        self.assertTrue(confirmed["operator_confirmed"]["G-01"])
        self.assertEqual(confirmed["verdict_note"], "")

    def test_fp_budget_is_verdict_affecting_at_boundary(self):
        under = run_scorer(FIXTURE_CAMPAIGN_G01_AND_9_FPS)
        self.assertEqual(under["verdict"], "PASS")
        # exactly at the budget (10): pins `>=`, not `>` — an off-by-one fails here
        at = run_scorer(FIXTURE_CAMPAIGN_G01_AND_10_FPS)
        self.assertEqual(at["false_positives"], 10)
        self.assertEqual(at["verdict"], "PARTIAL_RESULT")
        over = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
        self.assertEqual(over["false_positives"], 11)
        self.assertEqual(over["verdict"], "PARTIAL_RESULT")
        self.assertIn("partial result", over["verdict_note"])

    def test_missing_campaign_file_exits_cleanly(self):
        rc, err = run_scorer_raw(MISSING_DIR, BENCH)
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)

    def test_unknown_confirm_id_exits_cleanly(self):
        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, BENCH, confirm=["G-99"])
        self.assertEqual(rc, 2)
        self.assertIn("no gold finding", err)

    # --- the rest of the pinned decision table -------------------------------

    def test_stdout_is_exactly_the_pinned_schema(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01)
        self.assertEqual(
            set(out),
            {
                "found",
                "missed",
                "false_positives",
                "pass",
                "bonus",
                "verdict",
                "verdict_note",
                "operator_confirmed",
            },
        )
        self.assertIsInstance(out["found"], list)
        self.assertIsInstance(out["missed"], list)
        self.assertIsInstance(out["false_positives"], int)
        self.assertIsInstance(out["pass"], bool)
        self.assertIsInstance(out["bonus"], bool)
        self.assertIsInstance(out["verdict"], str)
        self.assertIsInstance(out["verdict_note"], str)
        self.assertIsInstance(out["operator_confirmed"], dict)

    def test_empty_campaign_misses_both_and_counts_no_fps(self):
        out = run_scorer(FIXTURE_CAMPAIGN_EMPTY)
        self.assertEqual(out["missed"], ["G-01", "G-02"])
        self.assertEqual(out["false_positives"], 0)
        self.assertEqual(out["verdict_note"], "")
        self.assertEqual(out["operator_confirmed"], {})

    def test_bonus_when_both_golds_found(self):
        camp = campaign([g01(), finding("F-000000000002", "CONFIRMED", G02_FINDING)])
        out = run_scorer(camp, confirm=["G-01", "G-02"])
        self.assertEqual(out["found"], ["G-01", "G-02"])
        self.assertEqual(out["missed"], [])
        self.assertTrue(out["pass"])
        self.assertTrue(out["bonus"])
        self.assertEqual(out["verdict"], "PASS_WITH_BONUS")
        self.assertEqual(out["verdict_note"], "")
        self.assertEqual(out["false_positives"], 0)

    def test_bonus_short_circuits_the_fp_budget(self):
        camp = campaign(
            [g01(), finding("F-000000000002", "CONFIRMED", G02_FINDING)] + fps(10)
        )
        out = run_scorer(camp, confirm=["G-01", "G-02"])
        self.assertEqual(out["found"], ["G-01", "G-02"])
        self.assertEqual(out["false_positives"], 10)  # at the budget, still bonus
        self.assertTrue(out["bonus"])
        self.assertEqual(out["verdict"], "PASS_WITH_BONUS")
        self.assertEqual(out["verdict_note"], "")  # no partial-result note

    def test_matched_finding_is_not_a_false_positive(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01)
        self.assertEqual(out["false_positives"], 0)

    def test_false_positives_count_only_confirmed_findings(self):
        camp = campaign(
            [g01()]
            + fps(3)
            + [
                finding("F-000000000009", "HYPOTHESIS", FP_FINDING),
                finding("F-000000000010", "DISPROVED", FP_FINDING),
            ]
        )
        out = run_scorer(camp)
        self.assertEqual(out["false_positives"], 3)

    def test_confirmed_without_e4_evidence_is_not_found(self):
        camp = campaign([g01(level="E2")])
        out = run_scorer(camp)
        self.assertEqual(out["found"], [])
        self.assertFalse(out["pass"])
        self.assertEqual(out["false_positives"], 0)  # it matches a gold's criteria

    def test_hypothesis_with_working_poc_counts_as_found(self):
        camp = campaign([g01(status="HYPOTHESIS", reproduced=True)])
        out = run_scorer(camp)
        self.assertEqual(out["found"], ["G-01"])

    def test_hypothesis_without_poc_is_missed(self):
        camp = campaign([g01(status="HYPOTHESIS")])
        out = run_scorer(camp)
        self.assertEqual(out["found"], [])

    def test_fp_budget_boundary_comes_from_the_benchmark_string(self):
        bench = benchmark(
            TMPROOT / "bench-budget-5.json",
            budget_text="buries it under 5+ FPs is a partial result",
        )
        self.assertEqual(
            run_scorer(campaign([g01()] + fps(4)), bench)["verdict"], "PASS"
        )
        at = run_scorer(campaign([g01()] + fps(5)), bench)  # exactly the budget
        self.assertEqual(at["false_positives"], 5)
        self.assertEqual(at["verdict"], "PARTIAL_RESULT")
        over = run_scorer(campaign([g01()] + fps(6)), bench)
        self.assertEqual(over["false_positives"], 6)
        self.assertEqual(over["verdict"], "PARTIAL_RESULT")

    def test_partial_result_note_names_the_fp_count(self):
        out = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
        self.assertIn("11", out["verdict_note"])

    def test_scorer_does_not_mutate_its_inputs(self):
        camp, bench = FIXTURE_CAMPAIGN_G01_AND_9_FPS, BENCH
        before = (tree_hash(camp), tree_hash(bench))
        run_scorer(camp, bench, confirm=["G-01"])
        self.assertEqual(before, (tree_hash(camp), tree_hash(bench)))

    # --- malformed inputs: exit 2, clean stderr ------------------------------

    def test_missing_gold_file_exits_cleanly(self):
        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, TMPROOT / "no-such-gold.json")
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)

    def test_missing_events_jsonl_exits_cleanly(self):
        camp = campaign([g01()])
        (camp / "events.jsonl").unlink()
        rc, err = run_scorer_raw(camp, BENCH)
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)

    def test_missing_findings_dir_exits_cleanly(self):
        camp = campaign([g01()])
        shutil.rmtree(camp / "findings")
        rc, err = run_scorer_raw(camp, BENCH)
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)

    def test_unparseable_finding_json_exits_cleanly(self):
        camp = campaign([g01()])
        (camp / "findings" / "F-broken.json").write_text("{not json")
        rc, err = run_scorer_raw(camp, BENCH)
        self.assertEqual(rc, 2)
        self.assertIn("F-broken.json", err)
        self.assertNotIn("Traceback", err)

    def test_unparseable_events_jsonl_exits_cleanly(self):
        camp = campaign([g01()])
        (camp / "events.jsonl").write_text('{"seq": 0}\n{"seq": 1}\nnot json\n')
        rc, err = run_scorer_raw(camp, BENCH)
        self.assertEqual(rc, 2)
        self.assertIn("line 3", err)
        self.assertNotIn("Traceback", err)

    def test_events_jsonl_whole_file_load_would_fail(self):
        # The pinned contract: two objects on two lines. A whole-file json.load
        # cannot read it, so a scorer that passes here parses line-by-line.
        camp = campaign([g01()], events=("a", "b"))
        self.assertEqual(run_scorer(camp)["found"], ["G-01"])

    def test_findings_schema_drift_exits_cleanly(self):
        broken = g01()
        del broken["root_cause"]
        camp = campaign([broken])
        rc, err = run_scorer_raw(camp, BENCH)
        self.assertEqual(rc, 2)
        self.assertIn("campaign findings schema mismatch", err)
        self.assertIn("root_cause", err)
        self.assertNotIn("Traceback", err)

    def test_gold_schema_drift_exits_cleanly(self):
        bench = TMPROOT / "bench-no-scoring.json"
        bench.write_text(json.dumps({"gold_findings": []}))
        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, bench)
        self.assertEqual(rc, 2)
        self.assertIn("gold file schema mismatch", err)
        self.assertNotIn("Traceback", err)

    def test_unreadable_budget_exits_cleanly(self):
        bench = benchmark(
            TMPROOT / "bench-no-budget.json", budget_text="no number here"
        )
        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, bench)
        self.assertEqual(rc, 2)
        self.assertIn("false_positive_budget", err)
        self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
