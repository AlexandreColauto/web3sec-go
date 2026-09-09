#!/usr/bin/env python3
"""Golden-suite checker (Tasks 17 + 24).

Byte-diffs the two twin artifact trees (campaign_state.json, events.jsonl,
the pinned snapshot tree incl. snapshot.json) and every captured
command's stdout/stderr/exit. Normalizes exactly two classes of
legitimate differences, each recorded in KNOWN_DIVERGENCES.md:

  1. the run root path (and the target path) — replaced by <ROOT>/<TGT>;
  2. environment_hash + every manifest_hash derived from it — the
     environment fingerprint hashes the runtime (python X vs go Y), which
     can never match across implementations; replaced by <ENVHASH>.

Everything else must be byte-identical, including every event hash: both
twins run under the SAME root path (the event chain hashes absolute
artifact paths) and finding ids are pinned into the same stream in both
twins (WEBV2_FINDING_IDS=pin + scripts/golden/sitecustomize.py), because
the Python reference mints finding ids from a raw uuid4 that the
WEBV2_UUID pin never reached. Since v3 the uuid seed is per step
(<seed>:<step>), so distinct commands cannot collide on the same id.

The `audit --json` steps compare EVERY section: Go's audit registry now
has all 14 sections in the reference's order (D2 closed 2026-09-09), so a
section present on one side only is a failure in either direction.

Exit 0 = GOLDEN GREEN; exit 1 = divergence reported per file/step.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

WORK = Path(__file__).resolve().parent.parent / ".scratch" / "golden"
# D2 CLOSED (2026-09-09, commit 5160b1a): the Go audit registry registers
# all 14 reference sections in the reference's order, so no section is
# Python-only any more. Kept as an empty set so an accidental re-introduction
# is a hard failure, not a silent pass.
PY_ONLY_SECTIONS: set[str] = set()

fails: list[str] = []


def load_spec() -> dict:
    return json.loads((WORK / "spec.json").read_text())


def normalizers(spec: dict, twin: str) -> list[tuple[re.Pattern, str]]:
    """(pattern, replacement) pairs applied to both text and bytes."""
    ns = []
    ns.append((re.compile(re.escape(spec["roots"][twin])), "<ROOT>"))
    ns.append((re.compile(re.escape(spec["target"])), "<TGT>"))
    # environment_hash values: extract from each twin's snapshot.json.
    for t in ("py", "go"):
        snaps = sorted((Path(spec["trees"][t]) / "campaigns" /
                        spec["campaign_id"] / "snapshots").glob("*/snapshot.json"))
        for snap in snaps:
            doc = json.loads(snap.read_text())
            env = (doc.get("manifest") or {}).get("environment_hash")
            man = (doc.get("manifest") or {}).get("manifest_hash")
            for val in (env, man):
                if val:
                    ns.append((re.compile(re.escape(val)), "<ENVHASH>"))
    return ns


def norm_text(spec: dict, twin: str, text: str) -> str:
    for pat, repl in normalizers(spec, twin):
        text = pat.sub(repl, text)
    return text


def norm_bytes(spec: dict, twin: str, data: bytes) -> bytes:
    return norm_text(spec, twin, data.decode("utf-8", "replace")).encode("utf-8")


def diff_tree(spec: dict) -> None:
    py_root = Path(spec["trees"]["py"]) / "campaigns" / spec["campaign_id"]
    go_root = Path(spec["trees"]["go"]) / "campaigns" / spec["campaign_id"]
    py_files = sorted(p.relative_to(py_root).as_posix() for p in py_root.rglob("*")
                      if p.is_file())
    go_files = sorted(p.relative_to(go_root).as_posix() for p in go_root.rglob("*")
                      if p.is_file())
    for f in sorted(set(py_files) - set(go_files)):
        fails.append(f"tree: py-only file {f}")
    for f in sorted(set(go_files) - set(py_files)):
        fails.append(f"tree: go-only file {f}")
    for f in sorted(set(py_files) & set(go_files)):
        a = norm_bytes(spec, "py", (py_root / f).read_bytes())
        b = norm_bytes(spec, "go", (go_root / f).read_bytes())
        if a != b:
            fails.append(f"tree: {f} differs")
            la = a.decode("utf-8", "replace").splitlines()
            lb = b.decode("utf-8", "replace").splitlines()
            for i in range(max(len(la), len(lb))):
                xa = la[i] if i < len(la) else "<missing>"
                xb = lb[i] if i < len(lb) else "<missing>"
                if xa != xb:
                    fails.append(f"    line {i+1} py: {xa[:200]}")
                    fails.append(f"    line {i+1} go: {xb[:200]}")
                    break
    if not any(x.startswith("tree:") for x in fails):
        print(f"tree: {len(py_files)} files byte-MATCH (normalized)")


def audit_json_step(spec: dict, step: int, name: str) -> None:
    """Compare an `audit --json` report on every shared section."""
    def report(twin: str) -> dict:
        f = WORK / "captures" / twin / f"{step:02d}-{name}.out"
        return json.loads(norm_text(spec, twin, f.read_text()))

    a, b = report("py"), report("go")
    sa, sb = a.get("sections", {}), b.get("sections", {})
    go_only = sorted(set(sb) - set(sa))
    py_only = sorted(set(sa) - set(sb))
    for k in go_only:
        fails.append(f"step {step:02d} {name}: go-only audit section {k}")
    for k in py_only:
        if k not in PY_ONLY_SECTIONS:
            fails.append(f"step {step:02d} {name}: undocumented py-only audit "
                         f"section {k} (add to PY_ONLY_SECTIONS + "
                         f"KNOWN_DIVERGENCES if intended)")
    shared = sorted(set(sa) & set(sb))
    bad = [k for k in shared if sa[k] != sb[k]]
    if a.get("campaign_id") != b.get("campaign_id") or a.get("ok") != b.get("ok"):
        bad.append("<ok/campaign_id>")
    if bad:
        fails.append(f"step {step:02d} {name}: audit sections differ: "
                     + ", ".join(bad))
        for k in bad:
            if k in sa or k in sb:
                fails.append(f"    section {k}:\n"
                             f"      py: {json.dumps(sa.get(k), sort_keys=True)[:400]}\n"
                             f"      go: {json.dumps(sb.get(k), sort_keys=True)[:400]}")
    else:
        print(f"step {step:02d} {name}: {len(shared)} audit section(s) + ok "
              f"MATCH (py-only: {', '.join(py_only) or 'none'})")


def diff_steps(spec: dict) -> None:
    nonzero_ok = []
    for i, name in enumerate(spec["recipe"]):
        expected = spec["expected_exit"][i]
        for ext in ("out", "err", "exit"):
            a = (WORK / "captures" / "py" / f"{i:02d}-{name}.{ext}").read_text()
            b = (WORK / "captures" / "go" / f"{i:02d}-{name}.{ext}").read_text()
            if ext == "exit":
                if a.strip() != b.strip():
                    fails.append(f"step {i:02d} {name}: exit py={a.strip()} "
                                 f"go={b.strip()}")
                elif a.strip() != str(expected):
                    fails.append(f"step {i:02d} {name}: exit {a.strip()}, "
                                 f"recipe declares {expected}")
                elif expected != 0:
                    nonzero_ok.append(f"{name}={expected}")
                continue
            if name.startswith("audit-json") and ext == "out":
                continue  # handled by audit_json_step
            na, nb = norm_text(spec, "py", a), norm_text(spec, "go", b)
            # D2 CLOSED: the plain `audit` summary line lists all 14 sections
            # in the reference's order in BOTH twins, so it is compared
            # byte-for-byte with no token filtering.
            if na != nb:
                fails.append(f"step {i:02d} {name}.{ext} differs")
                la, lb = na.splitlines(), nb.splitlines()
                for j in range(max(len(la), len(lb))):
                    xa = la[j] if j < len(la) else "<missing>"
                    xb = lb[j] if j < len(lb) else "<missing>"
                    if xa != xb:
                        fails.append(f"    line {j+1} py: {xa[:200]}")
                        fails.append(f"    line {j+1} go: {xb[:200]}")
                        break
    print(f"steps: {len(spec['recipe'])} commands x 2 twins "
          f"({'all exit 0' if not nonzero_ok else 'declared nonzero: ' + ', '.join(nonzero_ok)})")


def main() -> None:
    spec = load_spec()
    diff_tree(spec)
    diff_steps(spec)
    for i, name in enumerate(spec["recipe"]):
        if name.startswith("audit-json"):
            audit_json_step(spec, i, name)
    print()
    if fails:
        print("GOLDEN RED — divergences:")
        for f in fails:
            print("  " + f)
        sys.exit(1)
    print("GOLDEN GREEN: all artifacts and command outputs byte-match "
          "(normalized per KNOWN_DIVERGENCES)")


if __name__ == "__main__":
    main()
