#!/usr/bin/env python3
"""minicertora-scorecard.py — grade the prover on the evalsuite (L6b).

WHAT THIS INSTRUMENT IS
-----------------------
An operator-side scorecard.  It reads RAW minicertora tool output — one JSON
object per line, exactly what `cli.py` prints.  The tool prints three line
shapes, and all three are scored:

  * a REPORT line — `build_report`'s 23 keys (`schema_version ... ghosts`),
    plus a top-level `invariant` object on an invariant line (24 keys);
  * a WHOLE-TARGET refusal envelope — 3 keys, `{"verdict": "UNKNOWN",
    "reason", "details"}` (`cli.py::_emit_abort` / `_emit_refusal`), printed
    when the run is rejected before any rule is decided (`rejected-feature:
    packed-storage:Packed.b` is the canonical one).  It names no rule and no
    contract, so only the file name can join it (tier 3 below);
  * an UNDECIDED envelope — 4 keys, `{"verdict": "UNKNOWN", "rule", "reason",
    "details"}` (`cli.py::_emit_undecided`), one per declaration the abort left
    undecided: it names a rule, so it joins like a report line.

It joins those lines to the evalsuite cases and prints one row per bug class:

    class	cases	detected	proven_silence	refused	refusal_histogram

`--json` emits the same rows as JSON objects, sorted by class.  Exit 0 means
"the scorecard ran"; it does NOT mean the prover is good — read the numbers.

THE SHAPE LAW (final review, F1)
--------------------------------
Those three shapes are the input contract on the LIVE path too, not only inside
`--self-test`.  Every line read from `--results` is classified BEFORE it can
offer a join key; a line that is none of the three is not tool output and is
EXCLUDED from scoring, named on stderr per line as `<file>:<line>: why`, and the
run CONTINUES as a loud partial — exactly like the unjoined-line accounting.  A
hard error was the alternative; it was rejected because one stray line should
not throw away a whole prover run (the unreadable input — not JSON, not an
object, a broken class map — keeps its hard error).

Why this is load-bearing: a verdict-bearing line that matches no shape still
carries a `verdict`, and the tier-3 stem join below needs no shape at all — so a
hand-made `{"verdict": "PROVEN"}` dropped into `results/<Contract>.jsonl` used to
join on the file stem and manufacture `proven_silence` out of nothing, with no
record on stderr and no trace in the numbers.  Excluded lines now never enter
`detected`/`proven_silence`/`refused`/the histogram; they are counted in the
stderr summary and each is named with its reason.

LAW (Wave L-system, L6b)
------------------------
A template-seeded scaffold is starting content, never evidence.  And no
minicertora rung moves any gate until an operator runs this scorecard on the
REAL evalsuite with the REAL tool: this wave ships only the instrument plus a
fixture self-test, which proves the parsing/join arithmetic and nothing at all
about the prover.  The fixture lines are hand-made and shape-audited against
what `cli.py` can print — each line is by construction something the tool could
have emitted, but the fixture is not a prover measurement.  (Two of the five are
quoted verbatim from real reject/VIOLATED runs to keep that claim honest; see
the fixture itself.)

THE JOIN (read this before trusting a row)
------------------------------------------
`assets/evalsuite/cases.json` carries NO contract name and NO rule id.  Its
per-case keys are `case_id, source{dataset,record_id,url}, partition,
program{program,platform,chains}, gold{outcome,bug_class,severity,root_cause,
locations[{file}]}, code{repo,commit,files[],snapshot_note}, created_at,
deployed_at, schema_version, notes`.  `program.program` is the ES *file stem*
(`ES01VaultMissingAuth`), while a tool line's `contract` is the Solidity
contract name (`VaultMissingAuth`) — the two differ on every real case, and
nothing links a rule id to a case.

Each line offers exactly ONE key, chosen by the line's shape — a three-tier
ladder, never a rule-or-contract blend (a line that HAS a rule is joined on
that rule and nothing else, so a rule the class map does not know stays a
visible unjoined line instead of being rescued by a contract-name match):

  1. the line has a `rule` -> that rule name (report lines and undecided
     envelopes);
  2. else the line has a `contract` (no rule) -> that contract name;
  3. else — a rule-less, contract-less refusal envelope -> the stem of the
     results file the line came from.

Tier 3 is why the operator convention is: **write each target's lines to
`<Contract>.jsonl`**, named for the Solidity contract (e.g.
`results/Counter.jsonl`, `results/Packed.jsonl`).  A whole-target abort
envelope carries no name of its own, so the file it lands in is the only
honest join key — and it must be a `tie_key` the class map knows (the fixture
maps `Packed` that way).

  * `--class-map FILE` (TSV: `tie_key<TAB>case_id`, `#` comments, an optional
    leading `key\ttie_key`-style header is dropped) maps a line's offered key
    to a `case_id`.  This is the mechanism the REAL evalsuite needs; it is what
    makes the join explicit and auditable instead of a guess.  A duplicate
    `tie_key`, or a `case_id` that is absent from `cases.json`, is a hard error
    (a join table that silently overwrites or drops a row is a wrong scorecard,
    and a silently-wrong scorecard is worse than no scorecard).  Key that table
    by **rule id** for report lines — a rule id is what ties a verdict, and a
    **contract-name row matters only for that target's rule-less abort
    envelope**, which joins on the results-file stem.
  * Without `--class-map` the join is exact-string equality against the
    case-derived keys `{case_id, program.program, source.record_id}` plus the
    stem of every `gold.locations[].file` / `code.files[]` path.  That is the
    zero-config path for fixtures whose names actually line up; on the real
    evalsuite it ties nothing, which is why the operator passes `--class-map`.

A line is TIED to a case when its offered key is one of that case's keys.  Lines
that tie to no case are counted on stderr and otherwise ignored.

THE THREE STATES (per case)
---------------------------
  * `detected`       — some tied line shows `verdict == "VIOLATED"`.
  * `proven_silence` — the case is a known-bad row (gold.outcome is not in the
                       clean set below) and it has >=1 tied line, ALL of which
                       are `PROVEN`: the prover proved it clean.  A clean
                       control row whose tied lines are all PROVEN does NOT
                       count — that is the control working.
  * `refused`        — some tied line is `UNKNOWN` with a `reason` in the
                       honest-refusal / tool-error / model-bug classes.  A tied
                       refusal ENVELOPE counts exactly like a report line: the
                       3-key whole-target abort and the 4-key undecided line
                       both land here, with their reason in the histogram.

`class/cases/detected/proven_silence/refused` are CASE counts; the refusal
histogram counts the refusing LINES by reason (`reason=count,...`, sorted,
`-` when empty; a JSON object in `--json` mode).

REFUSAL REASON CODES (hardcoded set, kept as a constant)
--------------------------------------------------------
The closed set below is the honest-refusal + tool-error + model-bug half of
`internal/harness/disposition.go::dispositionOf` — 17 codes, mirrored by hand
because this script is stdlib-only and never loads Go (the L6b brief said "15";
the Go source has 12 honest-refusal + 1 tool-error + 4 model-bug = 17, and the
semantics win over the count):

  honest-refusal (12): unsupported-feature, unsupported-opcode,
    unsupported-storage-layout, rejected-feature, unrecognized-dispatcher,
    external-call-abstraction, summary-unverified,
    multi-call-ambiguous-call-site, multi-call-inner-arg-unsupported,
    multi-call-stmt-between-calls, invariant-uninitialized,
    invariant-unchecked-functions
  tool-error (1):      tool-error
  model-bug (4):       unresolved-phi-source, unresolved-branch-cond,
                       modelling-inconsistency, solver-disagreement

A code outside this set (escalate-*, spec-rewrite, witness-triage) is a
different disposition and is deliberately NOT a refusal here.

`--self-test` runs the pinned fixture under `scripts/golden/scorecard-fixture/`
and exits nonzero on ANY byte difference between what the fixture produces and
the expected rows pinned below as string constants.  It also AUDITS every
fixture line against the three shapes `cli.py` can actually print (23-key
report, 24-key invariant report, 3-key whole-target abort, 4-key undecided) and
against the `_extract` reality that a PROVEN line carries no model — so a
fixture line the tool could never print fails the self-test instead of quietly
redefining the instrument's input contract.  Three further checks pin THE SHAPE
LAW on the live path: a verdict-bearing 1-key probe line (the F1 review's
`{"verdict": "PROVEN"}`, plus a `VIOLATED` sibling that would move `detected`)
is excluded, named on stderr, and leaves the pinned rows byte-identical; and a
lone 1-key PROVEN probe cannot manufacture `proven_silence` on a bad case.
"""
import argparse
import io
import json
import pathlib
import sys

VIOLATED, PROVEN, UNKNOWN = "VIOLATED", "PROVEN", "UNKNOWN"

REFUSAL_REASONS = frozenset({
    # honest-refusal: a shape this tool cannot express or check
    "unsupported-feature",
    "unsupported-opcode",
    "unsupported-storage-layout",
    "rejected-feature",
    "unrecognized-dispatcher",
    "external-call-abstraction",
    "summary-unverified",
    "multi-call-ambiguous-call-site",
    "multi-call-inner-arg-unsupported",
    "multi-call-stmt-between-calls",
    "invariant-uninitialized",
    "invariant-unchecked-functions",
    # tool-error: genuine breakage
    "tool-error",
    # model-bug: the pipeline disagreed with itself
    "unresolved-phi-source",
    "unresolved-branch-cond",
    "modelling-inconsistency",
    "solver-disagreement",
})

# Outcomes that mean "this row is not a planted bug".  Anything else — including
# a missing or unrecognized outcome — is treated as a known-bad row, so a
# malformed case can never be silently scored as a clean control.
CLEAN_OUTCOMES = frozenset({
    "confirmed-not-exploitable", "not-exploitable", "clean", "benign",
})

HEADER = ("class", "cases", "detected", "proven_silence", "refused",
          "refusal_histogram")

# --- the three line shapes cli.py can print (shape audit + join ladder) ------
# build_report's key set: `report/reconstruct.py::build_report`, 23 keys.
REPORT_KEYS = frozenset({
    "schema_version", "tool_version", "spec_version", "solc_version",
    "evm_version", "optimizer_enabled", "yul_artifact", "contract", "rule",
    "verdict", "confidence", "reason", "details", "assumptions", "bounds",
    "params", "env", "initial_storage", "calls", "final_storage",
    "failed_assertion", "warnings", "ghosts",
})
# A whole-target refusal: `cli.py::_emit_abort` / `_emit_refusal`.
ABORT_KEYS = frozenset({"verdict", "reason", "details"})
# One declaration the abort left undecided: `cli.py::_emit_undecided`.
UNDECIDED_KEYS = frozenset({"verdict", "rule", "reason", "details"})
# A call row: `cli.py::_extract` (note `revert_paths_excluded`, renamed from
# `reverted` in critic round 32).  The audit pins this so a stale key name in
# the fixture cannot pass as tool output.  `target` is null for an unqualified
# `f(...)` call and the contract name for `C.f(...)` (`spec/parser.py::call_name`).
CALL_KEYS = frozenset({"step", "function", "target", "args", "env",
                       "revert_paths_excluded", "reentrant", "overrides"})
# A call row's per-step env: `cli.py::_call_env` emits exactly these two.
CALL_ENV_KEYS = frozenset({"msg.sender", "msg.value"})

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE / "golden" / "scorecard-fixture"


def shape_of(line):
    """THE SHAPE LAW's one classifier: is this line a shape `cli.py` prints?

    Returns `(kind, why)`: `kind` is `"report"`, `"abort"`, `"undecided"` or
    None; `why` is the human-readable reason when `kind` is None.  Both the
    fixture audit (`audit_lines`, via `--self-test`) and the live score path
    (`screen_lines`) call THIS function, so the instrument can never grade a
    line it would refuse to accept as tool output.

    The shapes, exactly (extra keys are NOT admitted: a 25-key line is not the
    23/24-key report shape, it is a line from some other tool or version):
    the report line (`REPORT_KEYS`, + `invariant`), the 3-key whole-target
    abort envelope, the 4-key undecided envelope — the two envelopes only with
    `verdict == "UNKNOWN"`, because that is the only verdict those emitters
    print."""
    keys = set(line)
    if keys == ABORT_KEYS:
        if line.get("verdict") != UNKNOWN:
            return None, ("3-key whole-target abort envelope carries verdict %r, "
                          "not %r" % (line.get("verdict"), UNKNOWN))
        return "abort", None
    if keys == UNDECIDED_KEYS:
        if line.get("verdict") != UNKNOWN:
            return None, ("4-key undecided envelope carries verdict %r, not %r"
                          % (line.get("verdict"), UNKNOWN))
        return "undecided", None
    if REPORT_KEYS <= keys:
        extra = keys - REPORT_KEYS
        if extra - {"invariant"}:
            return None, ("report-shaped line carries unexpected extra key(s) "
                          "%s; the shape is the 23-key report, or 24 with "
                          "`invariant`" % sorted(extra))
        return "report", None
    return None, ("%d key(s) %s: not the 23-key report, the 24-key `invariant` "
                  "report, the 3-key whole-target abort or the 4-key undecided "
                  "envelope" % (len(keys), sorted(keys)))


def screen_lines(lines):
    """THE SHAPE LAW on the live path: keep only real tool lines.

    Returns `(kept, excluded)`, where `excluded` holds one `origin: why`
    string per dropped line — the operator sees which file:line was thrown
    away and for what reason, and the run continues.  No count in `score` can
    ever include a dropped line: nothing downstream re-reads the raw list."""
    kept, excluded = [], []
    for line in lines:
        kind, why = shape_of(line)
        if kind is None:
            excluded.append("%s: %s" % (getattr(line, "origin", "<line>"), why))
            continue
        kept.append(line)
    return kept, excluded


def emit_shape_problems(problems, stream=None):
    """Write THE SHAPE LAW's per-line exclusions; returns how many.

    One line per dropped line, prefixed so the warning is greppable, and used
    by both `main` and `--self-test` (the self-test pins these bytes)."""
    out = sys.stderr if stream is None else stream
    for p in problems:
        out.write("scorecard: excluded by the shape law: %s\n" % p)
    return len(problems)


def load_cases(path):
    """Read an evalsuite-shaped cases.json (a JSON array)."""
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("scorecard: %s: expected a JSON array of cases" % path)
    for i, case in enumerate(data):
        if not isinstance(case, dict) or not case.get("case_id"):
            raise SystemExit(
                "scorecard: %s: row %d is not a case object with case_id" % (path, i))
    return data


def load_class_map(path):
    """Read the `tie_key<TAB>case_id` join table.

    Returns `({tie_key: case_id}, {tie_key: line_number})`.  A duplicate
    `tie_key` is a hard error: the old code overwrote silently, which turns a
    fat-fingered join table into a scorecard that reports a join it never made.
    """
    out, where = {}, {}
    for n, raw in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) != 2:
            raise SystemExit("scorecard: %s:%d: expected `tie_key<TAB>case_id`"
                             % (path, n))
        key, cid = cols
        if not key or not cid:
            raise SystemExit("scorecard: %s:%d: empty column" % (path, n))
        if key.lower() in ("key", "tie_key", "rule", "contract") and \
                cid.lower() in ("case_id", "case", "target"):
            continue  # optional header
        if key in out:
            raise SystemExit(
                "scorecard: %s:%d: duplicate tie_key %r (already mapped to %r "
                "on line %d)" % (path, n, key, out[key], where[key]))
        out[key], where[key] = cid, n
    return out, where


def validate_class_map(class_map, where, cases, path):
    """Every `case_id` in the join table must exist in `cases.json`.

    A typo'd case id is a row the operator believes is joined and which the
    scorecard silently drops; naming both the line and the missing id makes the
    failure fixable from the message alone."""
    known = {c["case_id"] for c in cases}
    missing = [(k, cid, where.get(k)) for k, cid in sorted(class_map.items())
               if cid not in known]
    if missing:
        raise SystemExit("\n".join(
            "scorecard: %s:%s: tie_key %r points at case_id %r, which is not "
            "in the cases file" % (path, ln, k, cid)
            for k, cid, ln in missing))


def load_join(path, cases):
    """Load and validate a class map (the join table)."""
    class_map, where = load_class_map(path)
    validate_class_map(class_map, where, cases, path)
    return class_map


class ResultLine(dict):
    """One parsed tool line, carrying the results file it came from.

    `stem` (the file name without `.jsonl`) is the tier-3 join key for a
    whole-target refusal envelope, which names neither a rule nor a contract.
    """
    __slots__ = ("stem", "origin")


def load_results(directory):
    """Read every *.jsonl under `directory`: one JSON object per line, exact
    tool shape. A malformed line is a hard error — a scorecard that silently
    drops unparsable output would report a clean prover on a broken run."""
    directory = pathlib.Path(directory)
    files = sorted(directory.glob("*.jsonl"))
    if not files:
        raise SystemExit("scorecard: no *.jsonl result files under %s" % directory)
    lines = []
    for f in files:
        for n, raw in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SystemExit("scorecard: %s:%d: not JSON: %s" % (f, n, exc))
            if not isinstance(obj, dict):
                raise SystemExit("scorecard: %s:%d: not a JSON object" % (f, n))
            line = ResultLine(obj)
            line.stem, line.origin = f.stem, "%s:%d" % (f.name, n)
            lines.append(line)
    return lines


def line_tie_key(line):
    """The single key this line offers to the join ladder.

    1. `rule`     — a report line or an undecided envelope;
    2. `contract` — a report line with no rule;
    3. the results file stem — a rule-less, contract-less refusal envelope.
    """
    if line.get("rule"):
        return line["rule"]
    if line.get("contract"):
        return line["contract"]
    return getattr(line, "stem", None)


def case_keys(case, by_case):
    """Every string a result line may use to tie to this case."""
    keys = {case.get("case_id"),
            (case.get("program") or {}).get("program"),
            (case.get("source") or {}).get("record_id")}
    paths = list(((case.get("gold") or {}).get("locations") or []))
    paths += list(((case.get("code") or {}).get("files") or []))
    for entry in paths:
        f = (entry or {}).get("file") if isinstance(entry, dict) else entry
        if f:
            keys.add(pathlib.Path(f).stem)
    keys |= by_case.get(case.get("case_id"), set())
    return {k for k in keys if k}


def score(cases, lines, class_map=None):
    """Join `lines` to `cases` and roll up one row per bug_class (sorted).

    THE SHAPE LAW runs FIRST (`screen_lines`): a line matching none of the
    three printed shapes is dropped and named in `stats["shape_problems"]`
    before any join key is computed, so it cannot reach
    `detected`/`proven_silence`/`refused`.  Returns (rows, stats); rows are
    dicts keyed by HEADER, with refusal_histogram as {reason: count}.  `stats`
    counts `lines` (everything read: scored + excluded), `scored_lines`,
    `tied`, `unjoined`, `refusal_lines`, `excluded` and `shape_problems`."""
    lines, shape_problems = screen_lines(lines)
    by_case = {}
    for key, cid in (class_map or {}).items():
        by_case.setdefault(cid, set()).add(key)
    per_case = []
    tied_ids, unjoined, refusing = set(), 0, 0
    for i, case in enumerate(cases):
        keys = case_keys(case, by_case)
        tied = [l for l in lines if line_tie_key(l) in keys]
        for l in tied:
            tied_ids.add(id(l))
        verdicts = [l.get("verdict") for l in tied]
        bad = (case.get("gold") or {}).get("outcome") not in CLEAN_OUTCOMES
        refusals = [l for l in tied if l.get("verdict") == UNKNOWN
                    and l.get("reason") in REFUSAL_REASONS]
        refusing += len(refusals)
        per_case.append({
            "class": (case.get("gold") or {}).get("bug_class") or "<unknown>",
            "order": i,
            "cases": 1,
            "detected": int(VIOLATED in verdicts),
            "proven_silence": int(bool(tied) and bad
                                  and all(v == PROVEN for v in verdicts)),
            "refused": int(bool(refusals)),
            "hist": [l.get("reason") for l in refusals],
        })
    unjoined = len(lines) - len(tied_ids)
    rows = {}
    for c in per_case:
        row = rows.setdefault(c["class"], {
            "class": c["class"], "cases": 0, "detected": 0,
            "proven_silence": 0, "refused": 0, "refusal_histogram": {}})
        for k in ("cases", "detected", "proven_silence", "refused"):
            row[k] += c[k]
        for reason in c["hist"]:
            row["refusal_histogram"][reason] = \
                row["refusal_histogram"].get(reason, 0) + 1
    ordered = sorted(rows.values(), key=lambda r: r["class"])
    stats = {"lines": len(lines) + len(shape_problems), "tied": len(tied_ids),
             "unjoined": unjoined, "refusal_lines": refusing,
             "scored_lines": len(lines), "excluded": len(shape_problems),
             "shape_problems": shape_problems}
    return ordered, stats


def histogram_text(hist):
    if not hist:
        return "-"
    return ",".join("%s=%d" % (k, hist[k]) for k in sorted(hist))


def render_tsv(rows):
    out = ["\t".join(HEADER)]
    for r in rows:
        out.append("\t".join([
            r["class"], str(r["cases"]), str(r["detected"]),
            str(r["proven_silence"]), str(r["refused"]),
            histogram_text(r["refusal_histogram"])]))
    return "\n".join(out) + "\n"


def render_json(rows):
    payload = [{k: (r[k] if k != "refusal_histogram"
                    else dict(sorted(r[k].items()))) for k in HEADER}
               for r in rows]
    return json.dumps(payload, indent=2) + "\n"


def audit_lines(lines):
    """Check every fixture line is a shape `cli.py` can actually print.

    The fixture is the instrument's input contract: a hand-made line that the
    tool could never emit silently redefines what "raw tool output" means, and
    every later run is graded against it.  This audits, per line:

      * the key set is exactly one of the three printed shapes — a report line
        (23 keys, + `invariant` = 24 on an invariant line), a whole-target
        abort (3 keys), an undecided envelope (4 keys), and the two envelopes
        only with `verdict == "UNKNOWN"` (this is `shape_of`, the same
        classifier the live score path enforces);
      * every call row carries `cli.py::_extract`'s call keys — notably
        `revert_paths_excluded`, not its pre-round-32 name `reverted`;
      * a PROVEN line's `params`/`initial_storage`/`final_storage`/
        `failed_assertion` are empty and its `reason` is null, because the
        tool populates those from a SAT model and a PROVEN line has none
        (`cli.py::_extract` is called with `query=None`);
      * a rule-less, contract-less line carries no report fields (it is the
        tier-3 refusal envelope).

    Returns a list of human-readable problems (empty == clean)."""
    problems = []

    def bad(fmt, *a):
        problems.append("%s: %s" % (getattr(line, "origin", "<line>"), fmt % a))

    for line in lines:
        kind, why = shape_of(line)
        if kind is None:
            bad("%s", why)
            continue
        if kind == "abort":
            if not getattr(line, "stem", None):
                bad("whole-target envelope has no results-file stem to join on")
            continue
        if kind == "undecided":
            continue
        inv = line.get("invariant")
        if inv is not None and (not isinstance(inv, dict)
                                or set(inv) != {"name", "per_function", "init",
                                                "witness_function"}):
            bad("invariant object is not `_invariant_report`'s shape: %r", inv)
        for i, call in enumerate(line.get("calls") or []):
            if not isinstance(call, dict) or set(call) != CALL_KEYS:
                bad("call %d is not `_extract`'s call shape (missing %s, "
                    "extra %s)", i,
                    sorted(CALL_KEYS - set(call or {})),
                    sorted(set(call or {}) - CALL_KEYS))
                continue
            env = call.get("env")
            if env is not None and set(env) != CALL_ENV_KEYS:
                bad("call %d env keys %s are not `_call_env`'s",
                    i, sorted(env))
        if line.get("verdict") == PROVEN:
            for k in ("params", "initial_storage", "final_storage",
                      "failed_assertion"):
                if line.get(k) != {}:
                    bad("PROVEN line carries %s=%r; the tool has no SAT model "
                        "on a PROVEN line, so it is empty", k, line.get(k))
            if line.get("reason") is not None:
                bad("PROVEN line carries reason=%r; the tool prints null",
                    line.get("reason"))
            if (line.get("bounds") or {}).get("loop_bound_exhaustive") is not True:
                bad("PROVEN line has loop_bound_exhaustive != true")
    return problems


# --- pinned fixture expectations (--self-test) ------------------------------
# The pinned fixture is the spec: hand-made cases, five result lines across the
# five `<Contract>.jsonl` files, and the exact expected stdout of the runs
# self-test performs (rows + the line-shape audit). The no-class-map pin is
# deliberate: it asserts the join is explicit, not accidental.
PINNED_TSV = 'class\tcases\tdetected\tproven_silence\trefused\trefusal_histogram\naccess-control\t2\t1\t0\t1\trejected-feature=1\narithmetic-overflow\t3\t1\t1\t0\t-\n'
PINNED_JSON = '[\n  {\n    "class": "access-control",\n    "cases": 2,\n    "detected": 1,\n    "proven_silence": 0,\n    "refused": 1,\n    "refusal_histogram": {\n      "rejected-feature": 1\n    }\n  },\n  {\n    "class": "arithmetic-overflow",\n    "cases": 3,\n    "detected": 1,\n    "proven_silence": 1,\n    "refused": 0,\n    "refusal_histogram": {}\n  }\n]\n'
PINNED_NOJOIN_TSV = 'class\tcases\tdetected\tproven_silence\trefused\trefusal_histogram\naccess-control\t2\t0\t0\t0\t-\narithmetic-overflow\t3\t0\t0\t0\t-\n'
# The shape audit's pinned summary: 5 fixture lines, 4 report lines (one of
# them an invariant line) and 1 whole-target refusal envelope.
PINNED_SHAPES = ('shapes OK: 5 lines = 4 report (1 with `invariant`) '
                 '+ 1 whole-target refusal envelope\n')
# THE SHAPE LAW on the live path (final review, F1).  The probes are the
# review's 1-key `{"verdict": "PROVEN"}` plus a `VIOLATED` sibling, appended by
# hand to `results/Packed.jsonl` — whose stem IS the tier-3 join key for the bad
# `ES94Packed` case (CASE-000000000105, access-control).  Two pins, because the
# two failure modes differ: the PROVEN probe used to manufacture
# `proven_silence` when it was a case's ONLY tied line (the `lone` fixture
# below), while on the pinned fixture only the VIOLATED sibling moves a number,
# which is what makes the "rows unchanged" pin non-vacuous.
PROBE_LINES = (("Packed.jsonl:2", {"verdict": PROVEN}),
               ("Packed.jsonl:3", {"verdict": VIOLATED}))
PINNED_PROBE_STDERR = (
    'scorecard: excluded by the shape law: Packed.jsonl:2: 1 key(s) '
    "['verdict']: not the 23-key report, the 24-key `invariant` report, the "
    '3-key whole-target abort or the 4-key undecided envelope\n'
    'scorecard: excluded by the shape law: Packed.jsonl:3: 1 key(s) '
    "['verdict']: not the 23-key report, the 24-key `invariant` report, the "
    '3-key whole-target abort or the 4-key undecided envelope\n')
# A results dir holding ONLY the 1-key PROVEN probe in `Packed.jsonl`: the pre-F1
# code tied it to the bad ES94Packed case and reported proven_silence=1 out of
# nothing; now it is excluded and scores nothing (every count 0, exactly the
# all-zero rows the no-class-map control shows).  The check appends the
# `excluded=` count so the drop is pinned too, not just the empty rows.
PINNED_PROBE_ONLY_TSV = ('class\tcases\tdetected\tproven_silence\trefused'
                         '\trefusal_histogram\naccess-control\t2\t0\t0\t0\t-\n'
                         'arithmetic-overflow\t3\t0\t0\t0\t-\n')


def fixture_inputs():
    """The pinned fixture: cases, parsed result lines, validated class map."""
    cases = load_cases(FIXTURE / "cases.json")
    lines = load_results(FIXTURE / "results")
    return cases, lines, load_join(FIXTURE / "class-map.tsv", cases)


def shape_summary(lines):
    """The audit's one-line summary (pinned), or the problems themselves."""
    problems = audit_lines(lines)
    if problems:
        return "\n".join(problems) + "\n"
    report = [l for l in lines if REPORT_KEYS <= set(l)]
    invariant = [l for l in report if "invariant" in l]
    abort = [l for l in lines if set(l) == ABORT_KEYS]
    undecided = [l for l in lines if set(l) == UNDECIDED_KEYS]
    return ("shapes OK: %d lines = %d report (%d with `invariant`) "
            "+ %d whole-target refusal envelope%s\n"
            % (len(lines), len(report), len(invariant), len(abort),
               "" if not undecided else
               " + %d undecided" % len(undecided)))


def probe_lines(origins):
    """Synthesize live-path probe lines: 1-key objects as `Packed.jsonl` lines.

    They are built here rather than shipped in the fixture directory so the
    pinned fixture stays exactly five legal lines — a probe in the fixture
    would (correctly) fail the line-shape audit."""
    out = []
    for origin, obj in origins:
        line = ResultLine(obj)
        line.stem, line.origin = "Packed", origin
        out.append(line)
    return out


def self_test():
    """Run the fixture and byte-compare against the pins above."""
    cases, lines, class_map = fixture_inputs()
    probes = probe_lines(PROBE_LINES)
    probe_rows, probe_stats = score(cases, lines + probes, class_map)
    probe_err = io.StringIO()
    emit_shape_problems(probe_stats["shape_problems"], probe_err)
    lone_rows, lone_stats = score(cases, probe_lines(PROBE_LINES[:1]), class_map)
    checked = [
        ("TSV rows", render_tsv(score(cases, lines, class_map)[0]), PINNED_TSV),
        ("JSON rows", render_json(score(cases, lines, class_map)[0]), PINNED_JSON),
        ("TSV rows, no class map", render_tsv(score(cases, lines, {})[0]),
         PINNED_NOJOIN_TSV),
        ("fixture line shapes", shape_summary(lines), PINNED_SHAPES),
        ("live shape law: probe lines excluded, rows unchanged",
         render_tsv(probe_rows), PINNED_TSV),
        ("live shape law: probe exclusions named on stderr",
         probe_err.getvalue(), PINNED_PROBE_STDERR),
        ("live shape law: lone 1-key PROVEN probe manufactures nothing",
         "%sexcluded=%d\n" % (render_tsv(lone_rows), lone_stats["excluded"]),
         PINNED_PROBE_ONLY_TSV + "excluded=1\n"),
    ]
    bad = 0
    for label, got, want in checked:
        if got == want:
            print("self-test: %s match pinned bytes (%d bytes)"
                  % (label, len(got)))
            continue
        bad += 1
        print("self-test: MISMATCH in %s" % label, file=sys.stderr)
        g, w = got.splitlines(), want.splitlines()
        for i in range(max(len(g), len(w))):
            gl = g[i] if i < len(g) else "<missing>"
            wl = w[i] if i < len(w) else "<missing>"
            if gl != wl:
                print("  line %d\n    got:  %r\n    want: %r"
                      % (i + 1, gl, wl), file=sys.stderr)
    if bad:
        print("self-test: FAILED (%d/%d checks)" % (bad, len(checked)),
              file=sys.stderr)
        return 1
    print("self-test: OK (%d/%d checks)" % (len(checked), len(checked)))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Score minicertora tool lines against the evalsuite cases.")
    ap.add_argument("--results", help="dir of *.jsonl tool report lines")
    ap.add_argument("--cases", help="evalsuite-shaped cases.json")
    ap.add_argument("--class-map",
                    help="TSV `tie_key<TAB>case_id` join table (a line's rule, "
                         "else its contract, else its results-file stem -> case)")
    ap.add_argument("--json", action="store_true",
                    help="emit the rows as JSON objects instead of TSV")
    ap.add_argument("--self-test", action="store_true",
                    help="run the pinned fixture and exit nonzero on any "
                         "byte difference")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.results or not args.cases:
        ap.error("--results and --cases are required (or use --self-test)")
    cases = load_cases(args.cases)
    lines = load_results(args.results)
    class_map = load_join(args.class_map, cases) if args.class_map else {}
    rows, stats = score(cases, lines, class_map)
    emit_shape_problems(stats["shape_problems"])
    if stats["excluded"]:
        sys.stderr.write("scorecard: %d line(s) excluded by the shape law "
                         "(named above; not scored)\n" % stats["excluded"])
    sys.stderr.write(
        "scorecard: %d result lines, %d tied to a case, %d unjoined\n"
        % (stats["lines"], stats["tied"], stats["unjoined"]))
    if not class_map:
        sys.stderr.write("scorecard: no --class-map: join is exact-string on "
                         "case_id / program / record_id / source file stems\n")
    sys.stdout.write(render_json(rows) if args.json else render_tsv(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
