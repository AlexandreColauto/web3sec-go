#!/usr/bin/env python3
"""eval-gold.py — offline gold scorer for the gold-findings benchmark.

Offline analysis of a FINISHED campaign record: it never runs tooling against a
target, never touches the network, and never mutates the campaign dir or the
benchmark file.

    python3 scripts/eval-gold.py --gold <gold-findings.json> --campaign <dir> \
        [--confirm G-01 ...]

Exit 0 on any well-formed scoring run (scoring is not a gate); exit 2 with a
clean one-line stderr message (never a traceback) when an input is missing or
malformed. Stdout is one JSON object:
    {found, missed, false_positives, pass, bonus, verdict, verdict_note,
     operator_confirmed}
The decision table is pinned by scripts/eval_gold_test.py.

CAMPAIGN-DIR CONTRACT (pinned 2026-09-18 from the real record on disk, Step 0;
the plan's provisional single `findings.json` array DOES NOT EXIST):

  <campaign-dir>/findings/F-<id>.json   one finding object per file.
      Mirrors internal/state.Campaign.FindingsDir (internal/state/campaign.go:
      filepath.Join(root, "campaigns", <id>, "findings")) and the store's own
      listing, internal/findings.FindingPath / LoadAllFindings
      (internal/findings/storage.go: FindingPath -> <dir>/<finding_id>.json,
      LoadAllFindings -> validation.ListPrefixedOptional(dir, "F-", ".json")).
      The "F-"/".json" prefix/suffix pair is the store's, not ours.
      Keys read here, all in assets/schema/finding.schema.json `required`
      (every write goes through findings.SaveFinding ->
      validation.Validate(_, "finding", 1)):
        finding_id, status, title, root_cause{class, description, mechanism?},
        affected[]{path, function?}, evidence[]{level},
        verification.reproduction.attempts[]{outcome}
      The plan's `id` / `bug_class` / `text` / `primary_functions` / `artifacts`
      spellings do NOT exist in the record; the real spellings above govern.
      Any drift (a missing required key) is refused loudly, never scored.

  <campaign-dir>/events.jsonl           one JSON object per line.
      Mirrors internal/state.Campaign.EventsPath (internal/state/campaign.go);
      read line-by-line — json.load() on the whole file cannot work. Parsed for
      well-formedness only: the ledger is the campaign's audit trail, and the
      scorer reads no verdict out of it.

  (The plan's `links.json` is really artifacts/invariant_links.json —
  internal/invariants.SaveLinks; it is not part of this scoring contract.)

BENCHMARK: web3sec-final/targets/gold-findings.json, read-only. match_criteria,
pass, bonus and false_positive_budget are honoured verbatim from the file —
nothing about the benchmark is re-typed here except the two gold ids its own
scoring.pass / scoring.bonus strings name ("G-01 found at CONFIRMED with E4+
evidence ...", "G-02 also found"). The FP budget boundary is parsed out of
scoring.false_positive_budget at runtime.

MATCHING: a gold is FOUND when some campaign finding AT AN ACCEPTED EVIDENCE
STATE matches it. Accepted = CONFIRMED with E4+ evidence (the benchmark's own
words) or HYPOTHESIS/INVESTIGATING with a reproduced PoC attempt. A match is
>= MIN_KEYWORD_HITS distinct match_criteria tokens plus one primary_function,
each tested as (?i)\\b<tok>\\b over the finding's natural-language text. \\b is
correct here (prose); it deliberately differs from the Task 1 command matcher
(internal/invariants), which reads shell commands, not prose. `bug_class_accept`
is an any-of list of classes a finding MAY carry, so the decision table does not
gate on it and neither does the scorer.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# --- pinned contract ---------------------------------------------------------

CAMPAIGN_FINDINGS_SUBDIR = "findings"    # state.Campaign.FindingsDir
CAMPAIGN_EVENTS_FILE = "events.jsonl"    # state.Campaign.EventsPath
FINDING_PREFIX, FINDING_SUFFIX = "F-", ".json"

# assets/schema/finding.schema.json `required` — the schema every stored
# finding was validated against (findings.SaveFinding).
FINDING_REQUIRED_KEYS = ("finding_id", "campaign_id", "snapshot_ids", "title",
                         "status", "trajectory", "root_cause", "attacker",
                         "evidence", "risk", "dedup", "history", "created_at",
                         "updated_at")
GOLD_REQUIRED_KEYS = ("gold_findings", "scoring")
SCORING_REQUIRED_KEYS = ("pass", "bonus", "false_positive_budget")

# The benchmark's scoring.pass / scoring.bonus name these ids verbatim; the FP
# budget is the one boundary read from the file at runtime.
PASS_GOLD_ID = "G-01"
BONUS_GOLD_ID = "G-02"

# "E4+ evidence" = ladder index of E4 in internal/findings.EVIDENCE_ORDER.
MIN_EVIDENCE_INDEX = 4
POC_STATUSES = ("HYPOTHESIS", "INVESTIGATING")

# ponytail: a fixed quorum, not a semantic matcher — the benchmark's FP budget
# and --confirm are the human layer over it. Raise it if real findings from
# other bug classes start matching a gold's criteria by keyword alone.
MIN_KEYWORD_HITS = 3

STOPWORDS = frozenset("""
the a an and or of to in on for with from by is are was were be been being it
its this that these those as at if then than when where which who whom whose
while only also not no nor so such into over under out up must can could should
would may might will shall does do did done have has had having there here
their them they we you your our his her he she but because before after during
about above below between each other others same both few more most some any
all every own too very just don own s t re ve ll d m
""".split())

WORD_RE = re.compile(r"[a-z][a-z0-9_]{3,}")
BUDGET_RE = re.compile(r"(\d+)\s*\+?\s*FPs?\b", re.I)


def fail(msg):
    """The one exit-2 path: a clean stderr line, never a traceback."""
    print("eval-gold: " + msg, file=sys.stderr)
    raise SystemExit(2)


def read_json(path):
    if not path.is_file():
        fail("%s not found" % path)
    try:
        return json.loads(path.read_text())
    except OSError as e:
        fail("%s cannot be read: %s" % (path, e))
    except ValueError as e:                       # includes UnicodeDecodeError
        fail("%s is not valid JSON: %s" % (path, e))


def read_findings(campaign_dir):
    """The findings store, in the store's own F-*.json order, drift-checked."""
    fdir = campaign_dir / CAMPAIGN_FINDINGS_SUBDIR
    if not fdir.is_dir():
        fail("%s not found" % fdir)
    out = []
    for p in sorted(fdir.glob(FINDING_PREFIX + "*" + FINDING_SUFFIX)):
        f = read_json(p)
        if not isinstance(f, dict):
            fail("%s is not a JSON object" % p)
        missing = [k for k in FINDING_REQUIRED_KEYS if k not in f]
        if missing:
            fail("campaign findings schema mismatch (expected keys: %s): %s "
                 "lacks %s" % (", ".join(FINDING_REQUIRED_KEYS), p,
                               ", ".join(missing)))
        out.append(f)
    return out


def read_events(path):
    """events.jsonl line-by-line: a whole-file json.load cannot read it."""
    if not path.is_file():
        fail("%s not found" % path)
    try:
        with path.open() as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue          # a trailing newline is not a record
                try:
                    obj = json.loads(line)
                except ValueError as e:
                    fail("%s line %d is not valid JSON: %s" % (path, n, e))
                if not isinstance(obj, dict):
                    fail("%s line %d is not a JSON object" % (path, n))
    except OSError as e:
        fail("%s cannot be read: %s" % (path, e))


def word_hit(text, token):
    """(?i)\\b<tok>\\b over prose. Word boundaries are correct here because the
    haystack is natural language; the Task 1 command matcher reads shell
    commands and therefore matches differently on purpose."""
    return re.search(r"(?i)\b%s\b" % re.escape(token), text) is not None


def criteria_tokens(criteria):
    return {t for t in WORD_RE.findall(criteria.lower()) if t not in STOPWORDS}


def finding_text(f):
    rc = f.get("root_cause") if isinstance(f.get("root_cause"), dict) else {}
    parts = (f.get("title"), rc.get("description"), rc.get("mechanism"))
    return " ".join(p for p in parts if isinstance(p, str))


def finding_functions(f):
    affected = f.get("affected")
    return {a["function"].lower() for a in affected or []
            if isinstance(a, dict) and isinstance(a.get("function"), str)}


def matches(gold, f):
    """Keyword quorum over the finding text + one primary_function."""
    text = finding_text(f)
    hits = sum(1 for t in criteria_tokens(str(gold.get("match_criteria", "")))
               if word_hit(text, t))
    if hits < MIN_KEYWORD_HITS:
        return False
    fns = finding_functions(f)
    for fn in gold.get("primary_functions") or []:
        if isinstance(fn, str) and (fn.lower() in fns or word_hit(text, fn)):
            return True
    return False


def evidence_index(f):
    best = 0
    for e in f.get("evidence") or []:
        lvl = e.get("level") if isinstance(e, dict) else None
        if isinstance(lvl, str) and re.fullmatch(r"E([0-7])", lvl):
            best = max(best, int(lvl[1]))
    return best


def poc_reproduced(f):
    v = f.get("verification")
    rep = v.get("reproduction") if isinstance(v, dict) else None
    attempts = rep.get("attempts") if isinstance(rep, dict) else None
    return any(isinstance(a, dict) and a.get("outcome") == "reproduced"
               for a in attempts or [])


def accepted(f):
    """The benchmark's own accepted states (scoring.pass): CONFIRMED with E4+
    evidence, or HYPOTHESIS/INVESTIGATING with the root cause named (that is the
    criteria match itself) and a working PoC draft (a reproduced attempt)."""
    if f.get("status") == "CONFIRMED" and evidence_index(f) >= MIN_EVIDENCE_INDEX:
        return True
    return f.get("status") in POC_STATUSES and poc_reproduced(f)


def false_positive_budget(gold):
    """The boundary, parsed out of the benchmark's own prose at runtime."""
    text = gold["scoring"].get("false_positive_budget")
    m = BUDGET_RE.search(text) if isinstance(text, str) else None
    if not m:
        fail("cannot read the false-positive budget from "
             "scoring.false_positive_budget (%r)" % (text,))
    return int(m.group(1))


def score(gold, campaign_dir, confirms):
    golds = gold["gold_findings"]
    ids = [g.get("gold_id") for g in golds]
    for c in confirms:
        if c not in ids:
            fail("--confirm %s names no gold finding" % c)
    findings = read_findings(campaign_dir)
    read_events(campaign_dir / CAMPAIGN_EVENTS_FILE)

    live = [f for f in findings if accepted(f)]
    found = [gid for gid, g in zip(ids, golds)
             if any(matches(g, f) for f in live)]
    false_positives = sum(1 for f in findings if f.get("status") == "CONFIRMED"
                          and not any(matches(g, f) for g in golds))
    budget = false_positive_budget(gold)

    passed = PASS_GOLD_ID in found
    bonus = passed and BONUS_GOLD_ID in found
    if bonus:
        verdict = "PASS_WITH_BONUS"
    elif not passed:
        verdict = "FAIL"
    elif false_positives < budget:
        verdict = "PASS"
    else:
        verdict = "PARTIAL_RESULT"

    notes = []
    if verdict == "PARTIAL_RESULT":
        notes.append("partial result: %d false positives at or above the "
                     "benchmark's budget of %d" % (false_positives, budget))
    pending = [g for g in found if g not in confirms]
    if pending:
        notes.append("operator semantic confirmation pending for: %s"
                     % ", ".join(pending))
    return {
        "found": found,
        "missed": [g for g in ids if g not in found],
        "false_positives": false_positives,
        "pass": passed,
        "bonus": bonus,
        "verdict": verdict,
        "verdict_note": "; ".join(notes),
        # Advisory only: a confirmed-but-missed gold still shows the operator's
        # judgment rather than dropping it on the floor.
        "operator_confirmed": {g: g in confirms
                               for g in sorted(set(found) | set(confirms))},
    }


def load_gold(path):
    gold = read_json(path)
    if not isinstance(gold, dict):
        fail("%s is not a JSON object" % path)
    missing = [k for k in GOLD_REQUIRED_KEYS if k not in gold]
    if missing:
        fail("gold file schema mismatch (expected keys: %s): %s lacks %s"
             % (", ".join(GOLD_REQUIRED_KEYS), path, ", ".join(missing)))
    if not isinstance(gold["gold_findings"], list):
        fail("gold file schema mismatch (gold_findings must be an array)")
    if not isinstance(gold["scoring"], dict):
        fail("gold file schema mismatch (scoring must be an object)")
    missing = [k for k in SCORING_REQUIRED_KEYS if k not in gold["scoring"]]
    if missing:
        fail("gold file schema mismatch (scoring lacks: %s)"
             % ", ".join(missing))
    for g in gold["gold_findings"]:
        if not isinstance(g, dict) or not isinstance(g.get("gold_id"), str):
            fail("gold file schema mismatch (every gold finding needs a "
                 "gold_id)")
    return gold


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="eval-gold.py",
        description="Score a finished campaign record against the gold-findings "
                    "benchmark (offline; never touches a target).")
    ap.add_argument("--gold", required=True,
                    help="the benchmark file (web3sec-final/targets/"
                         "gold-findings.json), read-only")
    ap.add_argument("--campaign", required=True,
                    help="a finished campaign dir (findings/F-*.json + "
                         "events.jsonl)")
    ap.add_argument("--confirm", action="append", default=[], metavar="G-ID",
                    help="operator semantic confirmation of a gold finding "
                         "(advisory; never changes pass/bonus/verdict)")
    args = ap.parse_args(argv)
    try:
        gold = load_gold(Path(args.gold))
        campaign_dir = Path(args.campaign)
        if not campaign_dir.is_dir():
            fail("%s not found" % campaign_dir)
        out = score(gold, campaign_dir, args.confirm)
    except SystemExit:
        raise
    except (OSError, ValueError, KeyError, TypeError) as e:
        fail(str(e))
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
