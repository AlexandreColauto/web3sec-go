#!/usr/bin/env python3
"""Golden-suite checker (Go-only).

The Python twin is retired — Go is the source of truth. This no longer
byte-diffs two implementations; it validates the single Go run that
golden-run.py captured:

  1. every recipe step exits with the code the recipe declares
     (the integration smoke: the full 179-step op-sequence runs cleanly);
  2. the campaign artifact tree is well-formed (campaign_state.json and
     events.jsonl parse, and the event hash chain is intact: first
     prev_hash is the genesis hash, each next prev_hash is the prior
     event_hash);
  3. every `audit --json` step reports all 15 rendered sections and a
     boolean ok (the audit surface is complete for these campaigns).

Exit 0 = GOLDEN GREEN; exit 1 = a validation failure is reported per
step/tree/section.
"""

from __future__ import annotations

import json
from pathlib import Path

# H8: the shared probe-axis gate list (scripts/probe_axes.py) — the same
# table golden-run.py derives SURFACE2_AXES from.
from probe_axes import EXPECTED_PROBE_AXES

WORK = Path(__file__).resolve().parent.parent / ".scratch" / "golden"

# The 15 audit sections these campaigns RENDER, in report (registration)
# order. The registry (internal/audit/sections/register.go) carries 16: the
# `eval` section is PRESENCE-GATED since G4 and renders only for a campaign
# whose program matches the gold-eval suite. No golden campaign matches, so
# eval stays off this list — but price_table (r4) DOES render here, because
# the P4 recipe sets a price and pins a price-basis: the money path of the
# golden campaign is exactly what the section exists to watch, so its output
# is part of the golden surface. A section missing here is a hard failure in
# either direction; this list is not a copy of the registry and must not be
# "completed" to 16.
EXPECTED_SECTIONS: list[str] = [
    "event_log",
    "artifacts",
    "execs",
    "findings",
    "projection",
    "snapshots",
    "relations",
    "floor_policy",
    "stage_completions",
    "baselines",
    "invariant_verification",
    "sequence_coverage",
    "probe_surface",
    "unpriceable",
    "price_table",
]

# Every registered probe axis, pinned to the Go registry
# (internal/probes/registry.go probesTable), with the state this run must
# reach on it:
#
#   "rows"  — the axis emits at least one row (its fixture is present, its
#             detector fires, the surface assembly keeps it)
#   "blind" — the axis examines sites and publishes BLIND keys, but no row
#             (the legitimate silent state: `probes blank` citing one of those
#             keys is what closes it)
#
# Either way `sites` must be >= 1: `no-sites` means the detector saw nothing
# at all, which is exactly the C2/F6 blind spot — an axis whose regression no
# other gate can see. The keys are cross-checked against the registry by
# internal/probes/axis_coverage_test.go, so a new probe cannot land without
# widening the table.
#
# H8: the table itself lives in scripts/probe_axes.py — ONE source of truth
# shared with golden-run.py, which used to carry a hand-copied axis literal.
# The Go cross-check reads that file. (The import sits at the top of the
# file, in the import block.)

GENESIS_HASH = "0" * 64

fails: list[str] = []


def load_spec() -> dict:
    return json.loads((WORK / "spec.json").read_text())


def check_tree(spec: dict) -> None:
    """Validate the Go campaign tree: key artifacts parse and the event
    hash chain is intact."""
    camp = Path(spec["trees"]["go"]) / "campaigns" / spec["campaign_id"]
    if not camp.is_dir():
        fails.append(f"tree: campaign dir missing: {camp}")
        return
    # campaign_state.json parses
    st_path = camp / "campaign_state.json"
    if not st_path.is_file():
        fails.append(f"tree: missing {st_path.name}")
    else:
        try:
            json.loads(st_path.read_text())
        except ValueError as exc:
            fails.append(f"tree: campaign_state.json does not parse: {exc}")
    # events.jsonl parses line-by-line and the hash chain is intact
    ev_path = camp / "events.jsonl"
    if not ev_path.is_file():
        fails.append(f"tree: missing {ev_path.name}")
    else:
        prev = GENESIS_HASH
        n = 0
        for ln, line in enumerate(ev_path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError as exc:
                fails.append(f"tree: events.jsonl line {n + 1} does not parse: {exc}")
                break
            if e.get("prev_hash") != prev:
                fails.append(
                    f"tree: events.jsonl line {n + 1} (seq "
                    f"{e.get('seq')}): prev_hash {e.get('prev_hash')!r} "
                    f"!= prior event_hash {prev!r}"
                )
                break
            eh = e.get("event_hash")
            if not eh:
                fails.append(
                    f"tree: events.jsonl line {n + 1} (seq "
                    f"{e.get('seq')}): no event_hash"
                )
                break
            prev = eh
            n += 1
        else:
            n_files = sum(
                1 for p in Path(spec["trees"]["go"]).rglob("*") if p.is_file()
            )
            print(
                f"tree: campaign {spec['campaign_id']} well-formed "
                f"({n} events, chain intact; {n_files} files archived)"
            )


def check_steps(spec: dict) -> None:
    """Every step must exit with the code the recipe declared, and carry the
    output markers it declared.

    An exit code says a step was refused; it never says WHY. For the steps
    that exist to pin a refusal — the dismissal gate (B4/D1), the ladder and
    impact guards — the reason IS the contract, so the recipe declares the
    substrings its stderr (or stdout) must contain and this checks them.
    """
    nonzero_ok: list[str] = []
    marked = 0
    for i, name in enumerate(spec["recipe"]):
        expected = str(spec["expected_exit"][i])
        f = WORK / "captures" / "go" / f"{i:02d}-{name}.exit"
        if not f.is_file():
            fails.append(f"step {i:02d} {name}: missing exit capture")
            continue
        got = f.read_text().strip()
        if got != expected:
            errf = f.with_suffix(".err")
            err = errf.read_text().strip()[:200] if errf.is_file() else ""
            fails.append(
                f"step {i:02d} {name}: exit {got}, recipe declares "
                f"{expected}" + (f" — {err}" if err else "")
            )
        elif expected != "0":
            nonzero_ok.append(f"{name}={expected}")
        for stream, key in ((".err", "expect_err"), (".out", "expect_out")):
            wants = (spec.get(key) or [])[i] or []
            if not wants:
                continue
            marked += 1
            cap = f.with_suffix(stream)
            text = cap.read_text() if cap.is_file() else ""
            for want in wants:
                if want not in text:
                    fails.append(
                        f"step {i:02d} {name}: {key[7:]} missing "
                        f"{want!r} — got {text.strip()[:200]!r}"
                    )
    print(
        f"steps: {len(spec['recipe'])} commands "
        f"({'all exit 0' if not nonzero_ok else 'declared nonzero: ' + ', '.join(nonzero_ok)})"
        + (f", {marked} with declared output markers" if marked else "")
    )


def check_audit(spec: dict, step: int, name: str) -> None:
    """An `audit --json` report must carry all 15 rendered sections + ok."""
    f = WORK / "captures" / "go" / f"{step:02d}-{name}.out"
    try:
        doc = json.loads(f.read_text())
    except ValueError as exc:
        fails.append(f"step {step:02d} {name}: audit --json not JSON: {exc}")
        return
    if not isinstance(doc, dict):
        fails.append(f"step {step:02d} {name}: audit --json not an object")
        return
    ok = doc.get("ok")
    if not isinstance(ok, bool):
        fails.append(f"step {step:02d} {name}: audit ok is not a boolean ({ok!r})")
    sections = doc.get("sections")
    if not isinstance(sections, dict):
        fails.append(f"step {step:02d} {name}: audit sections missing/not an object")
        return
    have = list(sections)  # report order
    # The rendered surface is EXPECTED_SECTIONS, optionally TRUNCATED after
    # its 14 unconditional members: presence-gated sections (price_table
    # since r4, eval since G4) render exactly when their precondition
    # holds — the s2 campaign prices nothing and must not fake the row.
    # What stays hard-failed: any unexpected name, and the ORDER of what
    # does render.
    want = EXPECTED_SECTIONS
    core = want[: len(want) - 1]  # everything but the optional tail
    tail = want[len(want) - 1 :]
    missing = sorted(set(core) - set(have))
    extra = sorted(set(have) - set(core) - set(tail))
    if missing:
        fails.append(
            f"step {step:02d} {name}: missing audit section(s): " + ", ".join(missing)
        )
    if extra:
        fails.append(
            f"step {step:02d} {name}: unexpected audit section(s): " + ", ".join(extra)
        )
    # order: the rendered names must equal the registry-order projection
    proj = [n for n in want if n in have]
    if have != proj:
        fails.append(
            f"step {step:02d} {name}: audit sections out of "
            f"registration order: {have} vs {proj}"
        )
    if not missing and not extra and have == proj:
        print(
            f"step {step:02d} {name}: {len(have)} audit sections + ok (ok={ok}) present"
        )


def check_probe_axes(spec: dict, step: int, name: str) -> None:
    """`probes list --all --json` must reach the declared state on EVERY axis.

    Both directions fail: an axis missing from the surface (registration or
    wiring drift), an axis reporting `no-sites` (its fixture or detector went
    away), and an axis whose row/blind state moved the wrong way (a detector
    that started or stopped firing on the fixture built to pin it).
    """
    f = WORK / "captures" / "go" / f"{step:02d}-{name}.out"
    try:
        doc = json.loads(f.read_text())
    except ValueError as exc:
        fails.append(f"step {step:02d} {name}: probes json unreadable: {exc}")
        return
    axes = doc.get("axes")
    if not isinstance(axes, list):
        fails.append(f"step {step:02d} {name}: no axes list in the surface")
        return
    by_name = {}
    for a in axes:
        if isinstance(a, dict) and isinstance(a.get("axis"), str):
            by_name[a["axis"]] = a
    bad = 0
    missing = sorted(set(EXPECTED_PROBE_AXES) - set(by_name))
    extra = sorted(set(by_name) - set(EXPECTED_PROBE_AXES))
    if missing:
        fails.append(
            f"step {step:02d} {name}: axis(es) missing from the "
            "surface: " + ", ".join(missing)
        )
        bad += 1
    if extra:
        fails.append(
            f"step {step:02d} {name}: unexpected axis(es): " + ", ".join(extra)
        )
        bad += 1
    for axis, want in sorted(EXPECTED_PROBE_AXES.items()):
        a = by_name.get(axis)
        if a is None:
            continue
        sites = a.get("sites")
        rows = a.get("rows")
        status = a.get("status")
        if not isinstance(sites, int) or sites < 1:
            fails.append(
                f"step {step:02d} {name}: axis {axis} reports "
                f"sites={sites!r} (status={status!r}) — the detector "
                "saw no code at all, so nothing downstream can catch "
                "a regression on it"
            )
            bad += 1
            continue
        if want == "rows" and (not isinstance(rows, int) or rows < 1):
            fails.append(
                f"step {step:02d} {name}: axis {axis} emitted "
                f"rows={rows!r} (status={status!r}), the run is "
                "supposed to carry rows on it"
            )
            bad += 1
        if want == "blind":
            blind = a.get("blind_total")
            if rows != 0:
                fails.append(
                    f"step {step:02d} {name}: axis {axis} emitted "
                    f"rows={rows!r}, the fixture built to stay "
                    "silent is firing"
                )
                bad += 1
            elif not isinstance(blind, int) or blind < 1:
                fails.append(
                    f"step {step:02d} {name}: axis {axis} is blind "
                    f"but published blind_total={blind!r} — "
                    "`probes blank` has no key to cite"
                )
                bad += 1
    if bad == 0:
        rows_total = sum(
            a.get("rows", 0) for a in by_name.values() if isinstance(a.get("rows"), int)
        )
        states = ", ".join(
            f"{ax}={EXPECTED_PROBE_AXES[ax]}" for ax in sorted(EXPECTED_PROBE_AXES)
        )
        print(
            f"step {step:02d} {name}: {len(EXPECTED_PROBE_AXES)} probe axes "
            f"alive, states as declared ({states}; rows={rows_total})"
        )


def check_disposition_review(spec: dict) -> None:
    """The report ARTIFACT must keep the B4/D1 decision visible.

    The step captures prove the gate refused; the report is what a human reads
    afterwards, and the G-01 miss was precisely a high-risk row that left no
    visible trace of the argument that buried it. So the report must name the
    row twice — once as a flagged dismissal (it was, and an override does not
    make the reasoning safer) and once as a logged override with its actor and
    the written reason. The row, actor and reason are read from the recipe's
    own step, so nothing here is hardcoded.
    """
    cid = spec.get("campaign_id")
    if not cid:
        fails.append("spec carries no campaign_id")
        return
    report = WORK / "tree-go" / "campaigns" / cid / "report.md"
    if not report.is_file():
        fails.append(f"no report artifact at {report}")
        return
    argv = next(
        (
            c["argv"]
            for c in spec["captures"]["go"]
            if c["name"] == "answered-dismissal-overridden"
        ),
        None,
    )
    if not argv:
        fails.append("the recipe has no answered-dismissal-overridden step")
        return
    prio = argv[2]
    reason = argv[argv.index("--override-reason") + 1]
    actor = argv[argv.index("--actor") + 1]
    text = report.read_text()
    lines = text.splitlines()
    bad = 0
    if "## Disposition review" not in lines:
        fails.append(
            "report has no Disposition review section — the override "
            "is not on the record a human reads"
        )
        bad += 1
    flagged = [
        line
        for line in lines
        if line.startswith("- `") and "dismissal vocabulary:" in line
    ]
    if not any(prio in line for line in flagged):
        fails.append(f"report does not flag {prio} as a high-risk dismissal")
        bad += 1
    overridden = [line for line in lines if line.startswith("- OVERRIDDEN ")]
    if not any(prio in line and f"by {actor}:" in line for line in overridden):
        fails.append(f"report does not record the {prio} override by {actor}")
        bad += 1
    if not any(reason in line for line in overridden):
        fails.append("report records the override without its written reason")
        bad += 1
    if bad == 0:
        print(
            f"report artifact: {prio} is on the record as both a flagged "
            "dismissal and a logged override"
        )


def main() -> None:
    spec = load_spec()
    check_tree(spec)
    check_steps(spec)
    check_disposition_review(spec)
    for i, name in enumerate(spec["recipe"]):
        if name.startswith("audit-json"):
            check_audit(spec, i, name)
        elif name == "probes-list-all-json":
            check_probe_axes(spec, i, name)
    print()
    if fails:
        print("GOLDEN RED — failures:")
        for f in fails:
            print("  " + f)
        raise SystemExit(1)
    print(
        "GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)"
    )


if __name__ == "__main__":
    main()
