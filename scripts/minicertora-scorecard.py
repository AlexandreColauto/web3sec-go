#!/usr/bin/env python3
"""minicertora-scorecard.py — grade the prover on the evalsuite (L6b).

WHAT THIS INSTRUMENT IS
-----------------------
An operator-side scorecard.  It reads RAW minicertora tool output — one JSON
object per line, exactly what `cli.py` prints (build_report's 23 keys:
`schema_version ... ghosts`, plus a top-level `invariant` object on invariant
lines) — joins those lines to the evalsuite cases, and prints one row per bug
class:

    class	cases	detected	proven_silence	refused	refusal_histogram

`--json` emits the same rows as JSON objects, sorted by class.  Exit 0 means
"the scorecard ran"; it does NOT mean the prover is good — read the numbers.

LAW (Wave L-system, L6b)
------------------------
A template-seeded scaffold is starting content, never evidence.  And no
minicertora rung moves any gate until an operator runs this scorecard on the
REAL evalsuite with the REAL tool: this wave ships only the instrument plus a
fixture self-test, which proves the parsing/join arithmetic and nothing at all
about the prover.  The fixture rows are hand-made; they are not tool output.

THE JOIN (read this before trusting a row)
------------------------------------------
`assets/evalsuite/cases.json` carries NO contract name and NO rule id.  Its
per-case keys are `case_id, source{dataset,record_id,url}, partition,
program{program,platform,chains}, gold{outcome,bug_class,severity,root_cause,
locations[{file}]}, code{repo,commit,files[],snapshot_note}, created_at,
deployed_at, schema_version, notes`.  `program.program` is the ES *file stem*
(`ES01VaultMissingAuth`), while a tool line's `contract` is the Solidity
contract name (`VaultMissingAuth`) — the two differ on every real case, and
nothing links a rule id to a case.  So:

  * `--class-map FILE` (TSV: `tie_key<TAB>case_id`, `#` comments, an optional
    leading `key\ttie_key`-style header is dropped) maps a result line's `rule`
    OR `contract` to a `case_id`.  This is the mechanism the REAL evalsuite
    needs; it is what makes the join explicit and auditable instead of a guess.
  * Without `--class-map` the join is exact-string equality against the
    case-derived keys `{case_id, program.program, source.record_id}` plus the
    stem of every `gold.locations[].file` / `code.files[]` path.  That is the
    zero-config path for fixtures whose names actually line up; on the real
    evalsuite it ties nothing, which is why the operator passes `--class-map`.

A result line is TIED to a case when its `rule` or its `contract` is one of that
case's keys (the case's own derived keys, or a key the class map points at the
case).  Lines that tie to no case are counted on stderr and otherwise ignored.

THE THREE STATES (per case)
---------------------------
  * `detected`       — some tied line shows `verdict == "VIOLATED"`.
  * `proven_silence` — the case is a known-bad row (gold.outcome is not in the
                       clean set below) and it has >=1 tied line, ALL of which
                       are `PROVEN`: the prover proved it clean.  A clean
                       control row whose tied lines are all PROVEN does NOT
                       count — that is the control working.
  * `refused`        — some tied line is `UNKNOWN` with a `reason` in the
                       honest-refusal / tool-error / model-bug classes.

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
the expected rows pinned below as string constants.
"""
import argparse
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

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE / "golden" / "scorecard-fixture"


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
    """Read the `tie_key<TAB>case_id` join table. Returns {tie_key: case_id}."""
    out = {}
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
        out[key] = cid
    return out


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
            lines.append(obj)
    return lines


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

    Returns (rows, stats); rows are dicts keyed by HEADER, with
    refusal_histogram as {reason: count}."""
    by_case = {}
    for key, cid in (class_map or {}).items():
        by_case.setdefault(cid, set()).add(key)
    per_case = []
    tied_ids, unjoined, refusing = set(), 0, 0
    for i, case in enumerate(cases):
        keys = case_keys(case, by_case)
        tied = [l for l in lines
                if l.get("rule") in keys or l.get("contract") in keys]
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
    stats = {"lines": len(lines), "tied": len(tied_ids), "unjoined": unjoined,
             "refusal_lines": refusing}
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


# --- pinned fixture expectations (--self-test) ------------------------------
# The pinned fixture is the spec: hand-made rows, hand-made cases, and the
# exact expected stdout of the two runs self-test performs. The no-class-map
# pin is deliberate: it asserts the join is explicit, not accidental.
PINNED_TSV = 'class\tcases\tdetected\tproven_silence\trefused\trefusal_histogram\naccess-control\t2\t1\t0\t1\tunsupported-storage-layout=1\narithmetic-overflow\t3\t1\t1\t0\t-\n'
PINNED_JSON = '[\n  {\n    "class": "access-control",\n    "cases": 2,\n    "detected": 1,\n    "proven_silence": 0,\n    "refused": 1,\n    "refusal_histogram": {\n      "unsupported-storage-layout": 1\n    }\n  },\n  {\n    "class": "arithmetic-overflow",\n    "cases": 3,\n    "detected": 1,\n    "proven_silence": 1,\n    "refused": 0,\n    "refusal_histogram": {}\n  }\n]\n'
PINNED_NOJOIN_TSV = 'class\tcases\tdetected\tproven_silence\trefused\trefusal_histogram\naccess-control\t2\t0\t0\t0\t-\narithmetic-overflow\t3\t0\t0\t0\t-\n'


def run_fixture(class_map=None):
    cases = load_cases(FIXTURE / "cases.json")
    lines = load_results(FIXTURE / "results")
    if class_map is None:
        class_map = load_class_map(FIXTURE / "class-map.tsv")
    return score(cases, lines, class_map)


def self_test():
    """Run the fixture and byte-compare against the pins above."""
    checked = [
        ("TSV rows", render_tsv(run_fixture()[0]), PINNED_TSV),
        ("JSON rows", render_json(run_fixture()[0]), PINNED_JSON),
        ("TSV rows, no class map", render_tsv(run_fixture({})[0]),
         PINNED_NOJOIN_TSV),
    ]
    bad = 0
    for label, got, want in checked:
        if got == want:
            print("self-test: %s match pinned fixture (%d bytes)"
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
                    help="TSV `tie_key<TAB>case_id` join table (rule or "
                         "contract name -> case)")
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
    class_map = load_class_map(args.class_map) if args.class_map else {}
    rows, stats = score(cases, lines, class_map)
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
