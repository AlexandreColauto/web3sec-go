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


def main() -> None:
    spec = load_spec()
    check_tree(spec)
    check_steps(spec)
    for i, name in enumerate(spec["recipe"]):
        if name.startswith("audit-json"):
            check_audit(spec, i, name)
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
