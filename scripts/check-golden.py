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
  3. every `audit --json` step reports all 14 registered sections and a
     boolean ok (the audit surface is complete).

Exit 0 = GOLDEN GREEN; exit 1 = a validation failure is reported per
step/tree/section.
"""
from __future__ import annotations

import json
from pathlib import Path

WORK = Path(__file__).resolve().parent.parent / ".scratch" / "golden"

# The 14 audit sections in report (registration) order — pinned to the Go
# registry (internal/audit/sections/register.go). A section missing here is
# a hard failure in either direction.
EXPECTED_SECTIONS: list[str] = [
    "event_log", "artifacts", "execs", "findings", "projection",
    "snapshots", "relations", "floor_policy", "stage_completions",
    "baselines", "invariant_verification", "sequence_coverage",
    "probe_surface", "unpriceable",
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
# widening this table.
EXPECTED_PROBE_AXES: dict[str, str] = {
    "accumulator-skew": "blind",
    "enforcement-timing": "blind",
    "guard-short-circuit": "rows",
    "incentive-inversion": "rows",
    "liveness": "rows",
    "primitive-symmetry": "rows",
}

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
                fails.append(f"tree: events.jsonl line {n + 1} does not "
                             f"parse: {exc}")
                break
            if e.get("prev_hash") != prev:
                fails.append(f"tree: events.jsonl line {n + 1} (seq "
                             f"{e.get('seq')}): prev_hash {e.get('prev_hash')!r} "
                             f"!= prior event_hash {prev!r}")
                break
            eh = e.get("event_hash")
            if not eh:
                fails.append(f"tree: events.jsonl line {n + 1} (seq "
                             f"{e.get('seq')}): no event_hash")
                break
            prev = eh
            n += 1
        else:
            n_files = sum(1 for p in
                          Path(spec["trees"]["go"]).rglob("*") if p.is_file())
            print(f"tree: campaign {spec['campaign_id']} well-formed "
                  f"({n} events, chain intact; {n_files} files archived)")


def check_steps(spec: dict) -> None:
    """Every step must exit with the code the recipe declared."""
    nonzero_ok: list[str] = []
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
            fails.append(f"step {i:02d} {name}: exit {got}, recipe declares "
                         f"{expected}" + (f" — {err}" if err else ""))
        elif expected != "0":
            nonzero_ok.append(f"{name}={expected}")
    print(f"steps: {len(spec['recipe'])} commands "
          f"({'all exit 0' if not nonzero_ok else 'declared nonzero: ' + ', '.join(nonzero_ok)})")


def check_audit(spec: dict, step: int, name: str) -> None:
    """An `audit --json` report must carry all 14 sections + boolean ok."""
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
        fails.append(f"step {step:02d} {name}: audit ok is not a boolean "
                     f"({ok!r})")
    sections = doc.get("sections")
    if not isinstance(sections, dict):
        fails.append(f"step {step:02d} {name}: audit sections missing/not an "
                     f"object")
        return
    have = set(sections)
    want = set(EXPECTED_SECTIONS)
    missing = sorted(want - have)
    extra = sorted(have - want)
    if missing:
        fails.append(f"step {step:02d} {name}: missing audit section(s): "
                     + ", ".join(missing))
    if extra:
        fails.append(f"step {step:02d} {name}: unexpected audit section(s): "
                     + ", ".join(extra))
    if not missing and not extra:
        print(f"step {step:02d} {name}: {len(have)} audit sections + ok "
              f"(ok={ok}) present")


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
        fails.append(f"step {step:02d} {name}: axis(es) missing from the "
                     "surface: " + ", ".join(missing))
        bad += 1
    if extra:
        fails.append(f"step {step:02d} {name}: unexpected axis(es): "
                     + ", ".join(extra))
        bad += 1
    for axis, want in sorted(EXPECTED_PROBE_AXES.items()):
        a = by_name.get(axis)
        if a is None:
            continue
        sites = a.get("sites")
        rows = a.get("rows")
        status = a.get("status")
        if not isinstance(sites, int) or sites < 1:
            fails.append(f"step {step:02d} {name}: axis {axis} reports "
                         f"sites={sites!r} (status={status!r}) — the detector "
                         "saw no code at all, so nothing downstream can catch "
                         "a regression on it")
            bad += 1
            continue
        if want == "rows" and (not isinstance(rows, int) or rows < 1):
            fails.append(f"step {step:02d} {name}: axis {axis} emitted "
                         f"rows={rows!r} (status={status!r}), the run is "
                         "supposed to carry rows on it")
            bad += 1
        if want == "blind":
            blind = a.get("blind_total")
            if rows != 0:
                fails.append(f"step {step:02d} {name}: axis {axis} emitted "
                             f"rows={rows!r}, the fixture built to stay "
                             "silent is firing")
                bad += 1
            elif not isinstance(blind, int) or blind < 1:
                fails.append(f"step {step:02d} {name}: axis {axis} is blind "
                             f"but published blind_total={blind!r} — "
                             "`probes blank` has no key to cite")
                bad += 1
    if bad == 0:
        rows_total = sum(a.get("rows", 0) for a in by_name.values()
                         if isinstance(a.get("rows"), int))
        states = ", ".join(f"{ax}={EXPECTED_PROBE_AXES[ax]}"
                           for ax in sorted(EXPECTED_PROBE_AXES))
        print(f"step {step:02d} {name}: {len(EXPECTED_PROBE_AXES)} probe axes "
              f"alive, states as declared ({states}; rows={rows_total})")


def main() -> None:
    spec = load_spec()
    check_tree(spec)
    check_steps(spec)
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
    print("GOLDEN GREEN: Go run validates (exit codes, tree + event chain, "
          "audit surface)")


if __name__ == "__main__":
    main()
