# Gold Task 4 review package
## commits (280e348d..8b2886ec)
8b2886ec feat(eval): offline gold scorer honoring benchmark match criteria
## diffstat
 .../plans/2026-09-18-gold-findings-closure.md      |   5 +-
 scripts/eval-gold.py                               | 344 +++++++++++++++++++
 scripts/eval_gold_test.py                          | 377 +++++++++++++++++++++
 3 files changed, 724 insertions(+), 2 deletions(-)
## full diff (-U10)
diff --git a/docs/superpowers/plans/2026-09-18-gold-findings-closure.md b/docs/superpowers/plans/2026-09-18-gold-findings-closure.md
index 12a85795..f64ad8f8 100644
--- a/docs/superpowers/plans/2026-09-18-gold-findings-closure.md
+++ b/docs/superpowers/plans/2026-09-18-gold-findings-closure.md
@@ -342,22 +342,23 @@ git commit -m "feat(briefing): evidence reachability line (class confirm floor v
 
 The 0/2 score was produced by hand. This task makes it a repeatable command with hermetic tests, honoring the benchmark's own `match_criteria`, `pass`, `bonus`, and `false_positive_budget` strings verbatim (read from `web3sec-final/targets/gold-findings.json`, never re-typed). The scorer is offline analysis of a finished campaign record — it never runs tooling against a target.
 
 **Files:**
 - Create: `scripts/eval-gold.py`
 - Test: `scripts/eval_gold_test.py` (Python unittest, stdlib only)
 
 **Interfaces:**
 - Consumes: `web3sec-final/targets/gold-findings.json` schema: top-level `gold_findings[]` each with `gold_id`, `bug_class_accept`, `match_criteria`, `expected_severity`, `primary_functions`; top-level `scoring` with `pass`, `bonus`, `false_positive_budget`.
 - Consumes (pinned campaign-dir contract — the implementer does NOT reverse-engineer it mid-task): a campaign dir containing
-  - `findings.json` — a JSON array of finding objects with at least `id`, `status`, `bug_class`, `text`, `primary_functions` (string array), `artifacts` (array of artifact ids);
+  - `findings/F-<id>.json` — ONE finding object per file, not a `findings.json` array. CORRECTED 2026-09-18 at Step 0 from the real record: the store is `internal/state.Campaign.FindingsDir` = `<root>/campaigns/<id>/findings`, listed as `F-*.json` by `internal/findings.LoadAllFindings` via `validation.ListPrefixedOptional(dir, "F-", ".json")` (`internal/findings/storage.go`), e.g. `scripts/legacy/campaigns/C-45488bdaf5/findings/F-df01bb454ed5.json`. Field spellings are the finding schema's (`assets/schema/finding.schema.json`), not the plan's: `finding_id` (not `id`), `status`, `root_cause.class` (not `bug_class`), `title` + `root_cause.description` (not `text`), `affected[].function` (not `primary_functions`), `evidence[].artifact_id` (not `artifacts`);
   - `events.jsonl` — one JSON object per line (parse line-by-line; `json.load` on the whole file WILL fail).
+  (The Step 0 grep's `links.json` is really `artifacts/invariant_links.json` — `internal/invariants.SaveLinks` — and is not part of this scoring contract.)
   The exact real file names and field spellings are confirmed in Step 0 (`rg -n "links.json|events.jsonl|findings" internal/state` and one real campaign fixture) and pinned in a schema comment block at the top of `eval-gold.py` referencing the Go structs (`internal/state`) they mirror. The test harness builds synthetic campaign dirs with exactly this layout; if the real names differ from these two, the fixtures follow the REAL names (discovered in Step 0) and this plan's names are corrected in the same commit.
 - Produces: `python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir> [--confirm G-ID ...]` — exit 0 on any well-formed scoring run (scoring is not a gate); exit 2 with a clean stderr message (no raw traceback) when inputs are missing/malformed (gold file absent, campaign dir absent, either pinned file absent, unparseable JSON/JSONL, or a `--confirm` id that names no gold finding). Stdout is one JSON object with EXACTLY this schema (the full decision table the tests pin):
 
   | field | type | semantics |
   |---|---|---|
   | `found` | array of gold ids | gold findings whose `match_criteria` keywords and `primary_functions` match a campaign finding (word-boundary keyword match, `(?i)\b<tok>\b` here — finding TEXT is natural language prose, where `\b` IS correct; this deliberately differs from Task 1's command matcher, which operates on shell commands) at an accepted evidence state |
   | `missed` | array of gold ids | the complement |
   | `false_positives` | int | count of campaign findings at `CONFIRMED` that match no gold's criteria |
   | `pass` | bool | true iff G-01 is in `found`. **Independent of FP count and of operator confirmation.** |
   | `bonus` | bool | true iff `pass` AND G-02 in `found` |
@@ -441,21 +442,21 @@ The score only moves when a fresh operator campaign runs against the pinned targ
 - Consumes: `scripts/eval-gold.py` (Task 4); `web3sec-final/targets/gold-findings.json` (benchmark, read-only); the contamination check recorded in the benchmark (`contamination_check.checked: 2026-09-07` — the protocol re-runs it); `docs/eval-methodology.md` (claim-intake rubric for anything the re-run learns).
 - Produces: the canonical re-run checklist.
 
 - [ ] **Step 1: Write the protocol document**
 
 Content (all sections mandatory, no placeholders):
 
 1. **Pinned target**: Morph L2 @ vulnerable commit `22ca805e` (verify the checkout hash before starting; record the actual hash). **A fresh `bash scripts/release.sh` on THIS checkout is required before discovery starts and must print `RELEASE OK`** — an archived log from a different commit (`docs/sdd/release-final.log` @ `10182b5c`) proves a different checkout was clean and is cited only as evidence the script itself works, never as a substitute for the fresh run. Repeatability is the point of the measurement loop.
 2. **Contamination re-check**: the global store it reads (`~/.webv2/shared-memory`) is machine-global, not repo-local — run the check FIRST, before any campaign work populates the store, on a clean environment; record the date + result in the campaign record. Note for CI: runners with persistent home dirs will fail this check by design — that is the check working, not a bug. Re-run against the benchmark's `contamination_check` keyword list (copy it verbatim from the JSON).
 3. **Campaign protocol**: fresh campaign; model the protocol including `rollup_finalization` as a state machine (the hardening branch's per-machine liveness gate now refuses the model without it — that gate firing is expected and is itself a test of the hardening work); run the lifecycle machines' probes (`probes run --emit`) while discovery is open (the Task 11 cold-probe warning will nag until this happens — expected); close invariants only with execs that target `applies_to` (Task 1 gate now refuses suite-run citations — expected).
-4. **Scoring**: `python3 scripts/eval-gold.py --gold web3sec-final/targets/gold-findings.json --campaign <dir>` (invocation pinned exactly as Task 4 Step 4 verified); operator semantic confirmation via `--confirm G-01` after reading the match evidence; record the JSON verdict and the FP count in the campaign record. FP-budget language comes from the benchmark's `scoring.false_positive_budget` verbatim.
+4. **Scoring**: `python3 scripts/eval-gold.py --gold web3sec-final/targets/gold-findings.json --campaign <dir>` (invocation pinned exactly as Task 4 Step 4 verified); operator semantic confirmation via `--confirm G-01` after reading the match evidence; record the JSON verdict and the FP count in the campaign record. FP-budget language comes from the benchmark's `scoring.false_positive_budget` verbatim. The scorer's own gate, from the repo root with no path hacks: `python3 -m unittest scripts.eval_gold_test` (also runnable as `python3 scripts/eval_gold_test.py`; both verified green 2026-09-18, 25 tests).
 5. **Honesty rules**: no score pressure on the record; a miss is recorded as a miss with the failure analysis (the 0/2 eval's diagnosis is the template); numbers learned during the re-run enter framework DATA only through the `docs/eval-methodology.md` provenance rubric.
 6. **Out of scope**: no exploit development automation, no CI execution of the protocol, no benchmark edits (the benchmark file is read-only evidence; changing it invalidates the comparison to 0/2).
 
 - [ ] **Step 2: Verify the protocol's commands actually exist**
 
 Run every command the protocol names with `--help` or against a scratch campaign (never against the pinned target): `webv2 probes run --emit`, `python3 scripts/eval-gold.py --help`, and confirm `scripts/release.sh` exists and is runnable on a scratch checkout (the canonical green full-run evidence remains `docs/sdd/release-final.log`; Task 5 does not re-run a full release — the protocol itself requires the operator's fresh run at execution time).
 Expected: all commands resolve; any drift is fixed in the doc before commit.
 
 - [ ] **Step 3: Commit**
 
diff --git a/scripts/eval-gold.py b/scripts/eval-gold.py
new file mode 100644
index 00000000..6dd38e47
--- /dev/null
+++ b/scripts/eval-gold.py
@@ -0,0 +1,344 @@
+#!/usr/bin/env python3
+"""eval-gold.py — offline gold scorer for the gold-findings benchmark.
+
+Offline analysis of a FINISHED campaign record: it never runs tooling against a
+target, never touches the network, and never mutates the campaign dir or the
+benchmark file.
+
+    python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir> \
+        [--confirm G-01 ...]
+
+Exit 0 on any well-formed scoring run (scoring is not a gate); exit 2 with a
+clean one-line stderr message (never a traceback) when an input is missing or
+malformed. Stdout is one JSON object:
+    {found, missed, false_positives, pass, bonus, verdict, verdict_note,
+     operator_confirmed}
+The decision table is pinned by scripts/eval_gold_test.py.
+
+CAMPAIGN-DIR CONTRACT (pinned 2026-09-18 from the real record on disk, Step 0;
+the plan's provisional single `findings.json` array DOES NOT EXIST):
+
+  <campaign-dir>/findings/F-<id>.json   one finding object per file.
+      Mirrors internal/state.Campaign.FindingsDir (internal/state/campaign.go:
+      filepath.Join(root, "campaigns", <id>, "findings")) and the store's own
+      listing, internal/findings.FindingPath / LoadAllFindings
+      (internal/findings/storage.go: FindingPath -> <dir>/<finding_id>.json,
+      LoadAllFindings -> validation.ListPrefixedOptional(dir, "F-", ".json")).
+      The "F-"/".json" prefix/suffix pair is the store's, not ours.
+      Keys read here, all in assets/schema/finding.schema.json `required`
+      (every write goes through findings.SaveFinding ->
+      validation.Validate(_, "finding", 1)):
+        finding_id, status, title, root_cause{class, description, mechanism?},
+        affected[]{path, function?}, evidence[]{level},
+        verification.reproduction.attempts[]{outcome}
+      The plan's `id` / `bug_class` / `text` / `primary_functions` / `artifacts`
+      spellings do NOT exist in the record; the real spellings above govern.
+      Any drift (a missing required key) is refused loudly, never scored.
+
+  <campaign-dir>/events.jsonl           one JSON object per line.
+      Mirrors internal/state.Campaign.EventsPath (internal/state/campaign.go);
+      read line-by-line — json.load() on the whole file cannot work. Parsed for
+      well-formedness only: the ledger is the campaign's audit trail, and the
+      scorer reads no verdict out of it.
+
+  (The plan's `links.json` is really artifacts/invariant_links.json —
+  internal/invariants.SaveLinks; it is not part of this scoring contract.)
+
+BENCHMARK: web3sec-final/targets/gold-findings.json, read-only. match_criteria,
+pass, bonus and false_positive_budget are honoured verbatim from the file —
+nothing about the benchmark is re-typed here except the two gold ids its own
+scoring.pass / scoring.bonus strings name ("G-01 found at CONFIRMED with E4+
+evidence ...", "G-02 also found"). The FP budget boundary is parsed out of
+scoring.false_positive_budget at runtime.
+
+MATCHING: a gold is FOUND when some campaign finding AT AN ACCEPTED EVIDENCE
+STATE matches it. Accepted = CONFIRMED with E4+ evidence (the benchmark's own
+words) or HYPOTHESIS/INVESTIGATING with a reproduced PoC attempt. A match is
+>= MIN_KEYWORD_HITS distinct match_criteria tokens plus one primary_function,
+each tested as (?i)\\b<tok>\\b over the finding's natural-language text. \\b is
+correct here (prose); it deliberately differs from the Task 1 command matcher
+(internal/invariants), which reads shell commands, not prose. `bug_class_accept`
+is an any-of list of classes a finding MAY carry, so the decision table does not
+gate on it and neither does the scorer.
+"""
+import argparse
+import json
+import re
+import sys
+from pathlib import Path
+
+# --- pinned contract ---------------------------------------------------------
+
+CAMPAIGN_FINDINGS_SUBDIR = "findings"    # state.Campaign.FindingsDir
+CAMPAIGN_EVENTS_FILE = "events.jsonl"    # state.Campaign.EventsPath
+FINDING_PREFIX, FINDING_SUFFIX = "F-", ".json"
+
+# assets/schema/finding.schema.json `required` — the schema every stored
+# finding was validated against (findings.SaveFinding).
+FINDING_REQUIRED_KEYS = ("finding_id", "campaign_id", "snapshot_ids", "title",
+                         "status", "trajectory", "root_cause", "attacker",
+                         "evidence", "risk", "dedup", "history", "created_at",
+                         "updated_at")
+GOLD_REQUIRED_KEYS = ("gold_findings", "scoring")
+SCORING_REQUIRED_KEYS = ("pass", "bonus", "false_positive_budget")
+
+# The benchmark's scoring.pass / scoring.bonus name these ids verbatim; the FP
+# budget is the one boundary read from the file at runtime.
+PASS_GOLD_ID = "G-01"
+BONUS_GOLD_ID = "G-02"
+
+# "E4+ evidence" = ladder index of E4 in internal/findings.EVIDENCE_ORDER.
+MIN_EVIDENCE_INDEX = 4
+POC_STATUSES = ("HYPOTHESIS", "INVESTIGATING")
+
+# ponytail: a fixed quorum, not a semantic matcher — the benchmark's FP budget
+# and --confirm are the human layer over it. Raise it if real findings from
+# other bug classes start matching a gold's criteria by keyword alone.
+MIN_KEYWORD_HITS = 3
+
+STOPWORDS = frozenset("""
+the a an and or of to in on for with from by is are was were be been being it
+its this that these those as at if then than when where which who whom whose
+while only also not no nor so such into over under out up must can could should
+would may might will shall does do did done have has had having there here
+their them they we you your our his her he she but because before after during
+about above below between each other others same both few more most some any
+all every own too very just don own s t re ve ll d m
+""".split())
+
+WORD_RE = re.compile(r"[a-z][a-z0-9_]{3,}")
+BUDGET_RE = re.compile(r"(\d+)\s*\+?\s*FPs?\b", re.I)
+
+
+def fail(msg):
+    """The one exit-2 path: a clean stderr line, never a traceback."""
+    print("eval-gold: " + msg, file=sys.stderr)
+    raise SystemExit(2)
+
+
+def read_json(path):
+    if not path.is_file():
+        fail("%s not found" % path)
+    try:
+        return json.loads(path.read_text())
+    except OSError as e:
+        fail("%s cannot be read: %s" % (path, e))
+    except ValueError as e:                       # includes UnicodeDecodeError
+        fail("%s is not valid JSON: %s" % (path, e))
+
+
+def read_findings(campaign_dir):
+    """The findings store, in the store's own F-*.json order, drift-checked."""
+    fdir = campaign_dir / CAMPAIGN_FINDINGS_SUBDIR
+    if not fdir.is_dir():
+        fail("%s not found" % fdir)
+    out = []
+    for p in sorted(fdir.glob(FINDING_PREFIX + "*" + FINDING_SUFFIX)):
+        f = read_json(p)
+        if not isinstance(f, dict):
+            fail("%s is not a JSON object" % p)
+        missing = [k for k in FINDING_REQUIRED_KEYS if k not in f]
+        if missing:
+            fail("campaign findings schema mismatch (expected keys: %s): %s "
+                 "lacks %s" % (", ".join(FINDING_REQUIRED_KEYS), p,
+                               ", ".join(missing)))
+        out.append(f)
+    return out
+
+
+def read_events(path):
+    """events.jsonl line-by-line: a whole-file json.load cannot read it."""
+    if not path.is_file():
+        fail("%s not found" % path)
+    try:
+        with path.open() as fh:
+            for n, line in enumerate(fh, 1):
+                if not line.strip():
+                    continue          # a trailing newline is not a record
+                try:
+                    obj = json.loads(line)
+                except ValueError as e:
+                    fail("%s line %d is not valid JSON: %s" % (path, n, e))
+                if not isinstance(obj, dict):
+                    fail("%s line %d is not a JSON object" % (path, n))
+    except OSError as e:
+        fail("%s cannot be read: %s" % (path, e))
+
+
+def word_hit(text, token):
+    """(?i)\\b<tok>\\b over prose. Word boundaries are correct here because the
+    haystack is natural language; the Task 1 command matcher reads shell
+    commands and therefore matches differently on purpose."""
+    return re.search(r"(?i)\b%s\b" % re.escape(token), text) is not None
+
+
+def criteria_tokens(criteria):
+    return {t for t in WORD_RE.findall(criteria.lower()) if t not in STOPWORDS}
+
+
+def finding_text(f):
+    rc = f.get("root_cause") if isinstance(f.get("root_cause"), dict) else {}
+    parts = (f.get("title"), rc.get("description"), rc.get("mechanism"))
+    return " ".join(p for p in parts if isinstance(p, str))
+
+
+def finding_functions(f):
+    affected = f.get("affected")
+    return {a["function"].lower() for a in affected or []
+            if isinstance(a, dict) and isinstance(a.get("function"), str)}
+
+
+def matches(gold, f):
+    """Keyword quorum over the finding text + one primary_function."""
+    text = finding_text(f)
+    hits = sum(1 for t in criteria_tokens(str(gold.get("match_criteria", "")))
+               if word_hit(text, t))
+    if hits < MIN_KEYWORD_HITS:
+        return False
+    fns = finding_functions(f)
+    for fn in gold.get("primary_functions") or []:
+        if isinstance(fn, str) and (fn.lower() in fns or word_hit(text, fn)):
+            return True
+    return False
+
+
+def evidence_index(f):
+    best = 0
+    for e in f.get("evidence") or []:
+        lvl = e.get("level") if isinstance(e, dict) else None
+        if isinstance(lvl, str) and re.fullmatch(r"E([0-7])", lvl):
+            best = max(best, int(lvl[1]))
+    return best
+
+
+def poc_reproduced(f):
+    v = f.get("verification")
+    rep = v.get("reproduction") if isinstance(v, dict) else None
+    attempts = rep.get("attempts") if isinstance(rep, dict) else None
+    return any(isinstance(a, dict) and a.get("outcome") == "reproduced"
+               for a in attempts or [])
+
+
+def accepted(f):
+    """The benchmark's own accepted states (scoring.pass): CONFIRMED with E4+
+    evidence, or HYPOTHESIS/INVESTIGATING with the root cause named (that is the
+    criteria match itself) and a working PoC draft (a reproduced attempt)."""
+    if f.get("status") == "CONFIRMED" and evidence_index(f) >= MIN_EVIDENCE_INDEX:
+        return True
+    return f.get("status") in POC_STATUSES and poc_reproduced(f)
+
+
+def false_positive_budget(gold):
+    """The boundary, parsed out of the benchmark's own prose at runtime."""
+    text = gold["scoring"].get("false_positive_budget")
+    m = BUDGET_RE.search(text) if isinstance(text, str) else None
+    if not m:
+        fail("cannot read the false-positive budget from "
+             "scoring.false_positive_budget (%r)" % (text,))
+    return int(m.group(1))
+
+
+def score(gold, campaign_dir, confirms):
+    golds = gold["gold_findings"]
+    ids = [g.get("gold_id") for g in golds]
+    for c in confirms:
+        if c not in ids:
+            fail("--confirm %s names no gold finding" % c)
+    findings = read_findings(campaign_dir)
+    read_events(campaign_dir / CAMPAIGN_EVENTS_FILE)
+
+    live = [f for f in findings if accepted(f)]
+    found = [gid for gid, g in zip(ids, golds)
+             if any(matches(g, f) for f in live)]
+    false_positives = sum(1 for f in findings if f.get("status") == "CONFIRMED"
+                          and not any(matches(g, f) for g in golds))
+    budget = false_positive_budget(gold)
+
+    passed = PASS_GOLD_ID in found
+    bonus = passed and BONUS_GOLD_ID in found
+    if bonus:
+        verdict = "PASS_WITH_BONUS"
+    elif not passed:
+        verdict = "FAIL"
+    elif false_positives < budget:
+        verdict = "PASS"
+    else:
+        verdict = "PARTIAL_RESULT"
+
+    notes = []
+    if verdict == "PARTIAL_RESULT":
+        notes.append("partial result: %d false positives at or above the "
+                     "benchmark's budget of %d" % (false_positives, budget))
+    pending = [g for g in found if g not in confirms]
+    if pending:
+        notes.append("operator semantic confirmation pending for: %s"
+                     % ", ".join(pending))
+    return {
+        "found": found,
+        "missed": [g for g in ids if g not in found],
+        "false_positives": false_positives,
+        "pass": passed,
+        "bonus": bonus,
+        "verdict": verdict,
+        "verdict_note": "; ".join(notes),
+        # Advisory only: a confirmed-but-missed gold still shows the operator's
+        # judgment rather than dropping it on the floor.
+        "operator_confirmed": {g: g in confirms
+                               for g in sorted(set(found) | set(confirms))},
+    }
+
+
+def load_gold(path):
+    gold = read_json(path)
+    if not isinstance(gold, dict):
+        fail("%s is not a JSON object" % path)
+    missing = [k for k in GOLD_REQUIRED_KEYS if k not in gold]
+    if missing:
+        fail("gold file schema mismatch (expected keys: %s): %s lacks %s"
+             % (", ".join(GOLD_REQUIRED_KEYS), path, ", ".join(missing)))
+    if not isinstance(gold["gold_findings"], list):
+        fail("gold file schema mismatch (gold_findings must be an array)")
+    if not isinstance(gold["scoring"], dict):
+        fail("gold file schema mismatch (scoring must be an object)")
+    missing = [k for k in SCORING_REQUIRED_KEYS if k not in gold["scoring"]]
+    if missing:
+        fail("gold file schema mismatch (scoring lacks: %s)"
+             % ", ".join(missing))
+    for g in gold["gold_findings"]:
+        if not isinstance(g, dict) or not isinstance(g.get("gold_id"), str):
+            fail("gold file schema mismatch (every gold finding needs a "
+                 "gold_id)")
+    return gold
+
+
+def main(argv=None):
+    ap = argparse.ArgumentParser(
+        prog="eval-gold.py",
+        description="Score a finished campaign record against the gold-findings "
+                    "benchmark (offline; never touches a target).")
+    ap.add_argument("--gold", required=True,
+                    help="the benchmark file (web3sec-final/targets/"
+                         "gold-findings.json), read-only")
+    ap.add_argument("--campaign", required=True,
+                    help="a finished campaign dir (findings/F-*.json + "
+                         "events.jsonl)")
+    ap.add_argument("--confirm", action="append", default=[], metavar="G-ID",
+                    help="operator semantic confirmation of a gold finding "
+                         "(advisory; never changes pass/bonus/verdict)")
+    args = ap.parse_args(argv)
+    try:
+        gold = load_gold(Path(args.gold))
+        campaign_dir = Path(args.campaign)
+        if not campaign_dir.is_dir():
+            fail("%s not found" % campaign_dir)
+        out = score(gold, campaign_dir, args.confirm)
+    except SystemExit:
+        raise
+    except (OSError, ValueError, KeyError, TypeError) as e:
+        fail(str(e))
+    print(json.dumps(out))
+    return 0
+
+
+if __name__ == "__main__":
+    sys.exit(main())
diff --git a/scripts/eval_gold_test.py b/scripts/eval_gold_test.py
new file mode 100644
index 00000000..680e075d
--- /dev/null
+++ b/scripts/eval_gold_test.py
@@ -0,0 +1,377 @@
+#!/usr/bin/env python3
+"""Tests for scripts/eval-gold.py, the offline gold scorer.
+
+Hermetic: stdlib only, no network, no target interaction. Every campaign is
+synthetic, built in tempfile.mkdtemp() in the REAL pinned campaign-dir layout
+(findings/F-*.json + events.jsonl — see the contract block at the top of
+eval-gold.py), and the benchmark is a synthetic file with the same schema as
+web3sec-final/targets/gold-findings.json. Nothing here reads or writes a real
+campaign or the real benchmark.
+
+Run: python3 scripts/eval_gold_test.py
+     python3 -m unittest scripts.eval_gold_test
+"""
+import hashlib
+import json
+import shutil
+import subprocess
+import sys
+import tempfile
+import unittest
+from pathlib import Path
+
+ROOT = Path(__file__).resolve().parent.parent
+SCORER = ROOT / "scripts" / "eval-gold.py"
+
+# --- synthetic benchmark (same schema as the real gold-findings.json) --------
+
+PASS_TEXT = ("G-01 found at CONFIRMED with E4+ evidence (or HYPOTHESIS/INVESTIGATING "
+             "with the correct root cause named and a working PoC draft)")
+BONUS_TEXT = "G-02 also found"
+BUDGET_TEXT = ("count all other CONFIRMED findings; a submission-ready report that "
+               "includes G-01 but buries it under 10+ FPs is a partial result")
+
+G01_CRITERIA = ("A finding counts as FOUND if it identifies that prevStateRoot is not verified when a "
+                "batch is committed - the real check lives in finalizeBatch - so a sequencer can commit a "
+                "batch with a fake previous state root that can never be finalized and the whole chain is "
+                "frozen (liveness loss).")
+G02_CRITERIA = ("A finding counts as FOUND if it identifies that onDropMessage calls safeTransfer instead "
+                "of mint on the reverse custom gateway, where the token was burned at deposit time so the "
+                "gateway holds no balance, and failed deposits are therefore unrecoverable.")
+
+G01_FINDING = {
+    "title": "prevStateRoot is not validated at commit time (chain freeze)",
+    "description": ("commitBatch only checks that prevStateRoot is non-zero; the real check is in "
+                    "finalizeBatch, so a sequencer can commit a batch with a fake previous state root and "
+                    "win the challenge with a valid proof from that fake root, and the batch can never be "
+                    "finalized - the whole chain freezes (liveness loss)."),
+    "function": "commitBatch",
+}
+G02_FINDING = {
+    "title": "onDropMessage uses safeTransfer instead of mint for failed deposits",
+    "description": ("onDropMessage calls safeTransfer for the reverse custom gateway's token, but that "
+                    "token was burned at deposit time so the gateway holds no balance; it must mint as "
+                    "finalizeWithdrawERC20 does, so failed deposits are unrecoverable."),
+    "function": "onDropMessage",
+}
+FP_FINDING = {
+    "title": "Reentrancy in Vault.withdraw drains balances",
+    "description": ("withdraw credits the caller before the external call returns, so a reentrant caller "
+                    "can drain the vault."),
+    "function": "withdraw",
+}
+
+
+def benchmark(path, *, budget_text=BUDGET_TEXT, pass_text=PASS_TEXT):
+    """Write a synthetic benchmark file in the real gold-findings.json schema."""
+    doc = {
+        "gold_findings": [
+            {"gold_id": "G-01", "bug_class_accept": ["dos-griefing", "logic-error"],
+             "match_criteria": G01_CRITERIA, "expected_severity": "critical",
+             "primary_functions": ["commitBatch", "finalizeBatch"]},
+            {"gold_id": "G-02", "bug_class_accept": ["logic-error", "token-integration"],
+             "match_criteria": G02_CRITERIA, "expected_severity": "high",
+             "primary_functions": ["onDropMessage", "finalizeWithdrawERC20"]},
+        ],
+        "scoring": {"pass": pass_text, "bonus": BONUS_TEXT,
+                    "false_positive_budget": budget_text},
+    }
+    Path(path).write_text(json.dumps(doc))
+    return Path(path)
+
+
+def finding(fid, status, text, *, level="E4", reproduced=False):
+    """One finding object carrying every key the real finding schema requires."""
+    f = {
+        "finding_id": fid,
+        "campaign_id": "C-0123456789ab",
+        "snapshot_ids": {"source": "abc123def456"},
+        "title": text["title"],
+        "status": status,
+        "trajectory": "code",
+        "root_cause": {"class": "logic-error", "description": text["description"]},
+        "affected": [{"path": "src/Vault.sol", "function": text["function"]}],
+        "attacker": {"profile": "arbitrary EOA", "capabilities": []},
+        "evidence": ([{"evidence_id": "EV-1", "level": level, "type": "foundry-test",
+                       "artifact_id": "EXEC-1", "description": "sandboxed PoC"}] if level else []),
+        "risk": {}, "dedup": {}, "history": [],
+        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
+    }
+    if reproduced:
+        f["verification"] = {"reproduction": {"tier_reached": "T2", "status": "reproduced",
+                                              "attempts": [{"attempt_id": "ATT-1",
+                                                            "outcome": "reproduced",
+                                                            "artifact_id": "EXEC-1"}]}}
+    return f
+
+
+def campaign(findings=(), events=("campaign.init",)):
+    """A campaign dir in the pinned layout: findings/F-*.json + events.jsonl."""
+    d = Path(tempfile.mkdtemp(prefix="eval-gold-"))
+    fdir = d / "findings"
+    fdir.mkdir()
+    for f in findings:
+        (fdir / (f["finding_id"] + ".json")).write_text(json.dumps(f))
+    (d / "events.jsonl").write_text(
+        "".join(json.dumps({"seq": i, "event": e}) + "\n" for i, e in enumerate(events)))
+    return d
+
+
+def g01(status="CONFIRMED", **kw):
+    return finding("F-000000000001", status, G01_FINDING, **kw)
+
+
+def fps(n):
+    return [finding("F-%012d" % (100 + i), "CONFIRMED", FP_FINDING) for i in range(n)]
+
+
+def run_scorer_raw(camp, bench, confirm=()):
+    """(exit code, stderr) for a scorer invocation."""
+    cmd = [sys.executable, str(SCORER), "--gold", str(bench), "--campaign", str(camp)]
+    for c in confirm:
+        cmd += ["--confirm", c]
+    p = subprocess.run(cmd, capture_output=True, text=True)
+    return p.returncode, p.stderr
+
+
+def run_scorer(camp, bench=None, confirm=()):
+    """Parsed stdout of a scoring run; fails loudly on a non-zero exit."""
+    cmd = [sys.executable, str(SCORER), "--gold", str(bench or BENCH),
+           "--campaign", str(camp)]
+    for c in confirm:
+        cmd += ["--confirm", c]
+    p = subprocess.run(cmd, capture_output=True, text=True)
+    assert p.returncode == 0, "scorer exited %d: %s" % (p.returncode, p.stderr)
+    return json.loads(p.stdout)
+
+
+def tree_hash(path):
+    h = hashlib.sha256()
+    p = Path(path)
+    files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())
+    for x in files:
+        h.update(str(x.relative_to(p.parent)).encode())
+        h.update(x.read_bytes())
+    return h.hexdigest()
+
+
+# --- fixtures (built once per test module, removed at the end) ---------------
+
+TMPROOT = None
+BENCH = None
+FIXTURE_CAMPAIGN_EMPTY = None
+FIXTURE_CAMPAIGN_G01 = None
+FIXTURE_CAMPAIGN_G01_AND_9_FPS = None
+FIXTURE_CAMPAIGN_G01_PLUS_11_FPS = None
+MISSING_DIR = None
+
+
+def setUpModule():
+    global TMPROOT, BENCH, FIXTURE_CAMPAIGN_EMPTY, FIXTURE_CAMPAIGN_G01
+    global FIXTURE_CAMPAIGN_G01_AND_9_FPS, FIXTURE_CAMPAIGN_G01_PLUS_11_FPS
+    global MISSING_DIR
+    TMPROOT = Path(tempfile.mkdtemp(prefix="eval-gold-fixtures-"))
+    BENCH = benchmark(TMPROOT / "gold-findings.json")
+    FIXTURE_CAMPAIGN_EMPTY = campaign()
+    FIXTURE_CAMPAIGN_G01 = campaign([g01()])
+    FIXTURE_CAMPAIGN_G01_AND_9_FPS = campaign([g01()] + fps(9))
+    FIXTURE_CAMPAIGN_G01_PLUS_11_FPS = campaign([g01()] + fps(11))
+    MISSING_DIR = TMPROOT / "no-such-campaign"
+
+
+def tearDownModule():
+    shutil.rmtree(TMPROOT, ignore_errors=True)
+
+
+class TestGoldScorer(unittest.TestCase):
+    def test_empty_campaign_scores_fail(self):
+        out = run_scorer(FIXTURE_CAMPAIGN_EMPTY)
+        self.assertEqual(out["found"], [])
+        self.assertFalse(out["pass"])
+        self.assertEqual(out["verdict"], "FAIL")
+
+    def test_g01_confirmed_scores_pass_pending_confirmation(self):
+        out = run_scorer(FIXTURE_CAMPAIGN_G01)
+        self.assertEqual(out["found"], ["G-01"])
+        self.assertTrue(out["pass"])                       # pass is independent of confirmation
+        self.assertEqual(out["verdict"], "PASS")
+        self.assertFalse(out["operator_confirmed"]["G-01"])
+        self.assertIn("operator semantic confirmation pending", out["verdict_note"])
+        confirmed = run_scorer(FIXTURE_CAMPAIGN_G01, confirm=["G-01"])
+        self.assertTrue(confirmed["operator_confirmed"]["G-01"])
+        self.assertEqual(confirmed["verdict_note"], "")
+
+    def test_fp_budget_is_verdict_affecting_at_boundary(self):
+        under = run_scorer(FIXTURE_CAMPAIGN_G01_AND_9_FPS)
+        self.assertEqual(under["verdict"], "PASS")
+        over = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
+        self.assertEqual(over["false_positives"], 11)
+        self.assertEqual(over["verdict"], "PARTIAL_RESULT")
+        self.assertIn("partial result", over["verdict_note"])
+
+    def test_missing_campaign_file_exits_cleanly(self):
+        rc, err = run_scorer_raw(MISSING_DIR, BENCH)
+        self.assertEqual(rc, 2)
+        self.assertIn("not found", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_unknown_confirm_id_exits_cleanly(self):
+        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, BENCH, confirm=["G-99"])
+        self.assertEqual(rc, 2)
+        self.assertIn("no gold finding", err)
+
+    # --- the rest of the pinned decision table -------------------------------
+
+    def test_stdout_is_exactly_the_pinned_schema(self):
+        out = run_scorer(FIXTURE_CAMPAIGN_G01)
+        self.assertEqual(set(out), {"found", "missed", "false_positives", "pass",
+                                    "bonus", "verdict", "verdict_note",
+                                    "operator_confirmed"})
+        self.assertIsInstance(out["found"], list)
+        self.assertIsInstance(out["missed"], list)
+        self.assertIsInstance(out["false_positives"], int)
+        self.assertIsInstance(out["pass"], bool)
+        self.assertIsInstance(out["bonus"], bool)
+        self.assertIsInstance(out["verdict"], str)
+        self.assertIsInstance(out["verdict_note"], str)
+        self.assertIsInstance(out["operator_confirmed"], dict)
+
+    def test_empty_campaign_misses_both_and_counts_no_fps(self):
+        out = run_scorer(FIXTURE_CAMPAIGN_EMPTY)
+        self.assertEqual(out["missed"], ["G-01", "G-02"])
+        self.assertEqual(out["false_positives"], 0)
+        self.assertEqual(out["verdict_note"], "")
+        self.assertEqual(out["operator_confirmed"], {})
+
+    def test_bonus_when_both_golds_found(self):
+        camp = campaign([g01(), finding("F-000000000002", "CONFIRMED", G02_FINDING)])
+        out = run_scorer(camp, confirm=["G-01", "G-02"])
+        self.assertEqual(out["found"], ["G-01", "G-02"])
+        self.assertEqual(out["missed"], [])
+        self.assertTrue(out["pass"])
+        self.assertTrue(out["bonus"])
+        self.assertEqual(out["verdict"], "PASS_WITH_BONUS")
+        self.assertEqual(out["verdict_note"], "")
+        self.assertEqual(out["false_positives"], 0)
+
+    def test_matched_finding_is_not_a_false_positive(self):
+        out = run_scorer(FIXTURE_CAMPAIGN_G01)
+        self.assertEqual(out["false_positives"], 0)
+
+    def test_false_positives_count_only_confirmed_findings(self):
+        camp = campaign([g01()] + fps(3)
+                        + [finding("F-000000000009", "HYPOTHESIS", FP_FINDING),
+                           finding("F-000000000010", "DISPROVED", FP_FINDING)])
+        out = run_scorer(camp)
+        self.assertEqual(out["false_positives"], 3)
+
+    def test_confirmed_without_e4_evidence_is_not_found(self):
+        camp = campaign([g01(level="E2")])
+        out = run_scorer(camp)
+        self.assertEqual(out["found"], [])
+        self.assertFalse(out["pass"])
+        self.assertEqual(out["false_positives"], 0)   # it matches a gold's criteria
+
+    def test_hypothesis_with_working_poc_counts_as_found(self):
+        camp = campaign([g01(status="HYPOTHESIS", reproduced=True)])
+        out = run_scorer(camp)
+        self.assertEqual(out["found"], ["G-01"])
+
+    def test_hypothesis_without_poc_is_missed(self):
+        camp = campaign([g01(status="HYPOTHESIS")])
+        out = run_scorer(camp)
+        self.assertEqual(out["found"], [])
+
+    def test_fp_budget_boundary_comes_from_the_benchmark_string(self):
+        bench = benchmark(TMPROOT / "bench-budget-5.json",
+                          budget_text="buries it under 5+ FPs is a partial result")
+        self.assertEqual(run_scorer(campaign([g01()] + fps(4)), bench)["verdict"], "PASS")
+        over = run_scorer(campaign([g01()] + fps(6)), bench)
+        self.assertEqual(over["false_positives"], 6)
+        self.assertEqual(over["verdict"], "PARTIAL_RESULT")
+
+    def test_partial_result_note_names_the_fp_count(self):
+        out = run_scorer(FIXTURE_CAMPAIGN_G01_PLUS_11_FPS)
+        self.assertIn("11", out["verdict_note"])
+
+    def test_scorer_does_not_mutate_its_inputs(self):
+        camp, bench = FIXTURE_CAMPAIGN_G01_AND_9_FPS, BENCH
+        before = (tree_hash(camp), tree_hash(bench))
+        run_scorer(camp, bench, confirm=["G-01"])
+        self.assertEqual(before, (tree_hash(camp), tree_hash(bench)))
+
+    # --- malformed inputs: exit 2, clean stderr ------------------------------
+
+    def test_missing_gold_file_exits_cleanly(self):
+        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, TMPROOT / "no-such-gold.json")
+        self.assertEqual(rc, 2)
+        self.assertIn("not found", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_missing_events_jsonl_exits_cleanly(self):
+        camp = campaign([g01()])
+        (camp / "events.jsonl").unlink()
+        rc, err = run_scorer_raw(camp, BENCH)
+        self.assertEqual(rc, 2)
+        self.assertIn("not found", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_missing_findings_dir_exits_cleanly(self):
+        camp = campaign([g01()])
+        shutil.rmtree(camp / "findings")
+        rc, err = run_scorer_raw(camp, BENCH)
+        self.assertEqual(rc, 2)
+        self.assertIn("not found", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_unparseable_finding_json_exits_cleanly(self):
+        camp = campaign([g01()])
+        (camp / "findings" / "F-broken.json").write_text("{not json")
+        rc, err = run_scorer_raw(camp, BENCH)
+        self.assertEqual(rc, 2)
+        self.assertIn("F-broken.json", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_unparseable_events_jsonl_exits_cleanly(self):
+        camp = campaign([g01()])
+        (camp / "events.jsonl").write_text('{"seq": 0}\n{"seq": 1}\nnot json\n')
+        rc, err = run_scorer_raw(camp, BENCH)
+        self.assertEqual(rc, 2)
+        self.assertIn("line 3", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_events_jsonl_whole_file_load_would_fail(self):
+        # The pinned contract: two objects on two lines. A whole-file json.load
+        # cannot read it, so a scorer that passes here parses line-by-line.
+        camp = campaign([g01()], events=("a", "b"))
+        self.assertEqual(run_scorer(camp)["found"], ["G-01"])
+
+    def test_findings_schema_drift_exits_cleanly(self):
+        broken = g01()
+        del broken["root_cause"]
+        camp = campaign([broken])
+        rc, err = run_scorer_raw(camp, BENCH)
+        self.assertEqual(rc, 2)
+        self.assertIn("campaign findings schema mismatch", err)
+        self.assertIn("root_cause", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_gold_schema_drift_exits_cleanly(self):
+        bench = TMPROOT / "bench-no-scoring.json"
+        bench.write_text(json.dumps({"gold_findings": []}))
+        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, bench)
+        self.assertEqual(rc, 2)
+        self.assertIn("gold file schema mismatch", err)
+        self.assertNotIn("Traceback", err)
+
+    def test_unreadable_budget_exits_cleanly(self):
+        bench = benchmark(TMPROOT / "bench-no-budget.json",
+                          budget_text="no number here")
+        rc, err = run_scorer_raw(FIXTURE_CAMPAIGN_G01, bench)
+        self.assertEqual(rc, 2)
+        self.assertIn("false_positive_budget", err)
+        self.assertNotIn("Traceback", err)
+
+
+if __name__ == "__main__":
+    unittest.main(verbosity=2)
