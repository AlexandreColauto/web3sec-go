#!/usr/bin/env python3
"""Golden-suite checker (Task 17).

Byte-diffs the two twin artifact trees (campaign_state.json, events.jsonl,
the pinned snapshot tree incl. snapshot.json) and every captured
command's stdout/stderr/exit. Normalizes exactly two classes of
legitimate differences, each recorded in KNOWN_DIVERGENCES.md:

  1. the twin root path (and the target path) — replaced by <ROOT>/<TGT>;
  2. environment_hash + every manifest_hash derived from it — the
     environment fingerprint hashes the runtime (python X vs go Y), which
     can never match across implementations; replaced by <ENVHASH>.

Everything else must be byte-identical. The audit --json step compares
only the six P0 sections (the Python report's extra P1+ sections are an
expected, recorded difference).

Exit 0 = GOLDEN GREEN; exit 1 = divergence reported per file/step.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

WORK = Path(__file__).resolve().parent.parent / ".scratch" / "golden"
P0_SECTIONS = ["event_log", "artifacts", "execs",
               "findings", "projection", "snapshots"]

fails: list[str] = []


def load_spec() -> dict:
    spec = json.loads((WORK / "spec.json").read_text())
    return spec


def normalizers(spec: dict, twin: str) -> list[tuple[re.Pattern, str]]:
    """(pattern, replacement) pairs applied to both text and bytes."""
    ns = []
    for t, tag in (("py", "<ROOT>"), ("go", "<ROOT>")):
        if t == twin:
            ns.append((re.compile(re.escape(spec["roots"][t])), tag))
    ns.append((re.compile(re.escape(spec["target"])), "<TGT>"))
    # environment_hash values: extract from each twin's snapshot.json.
    for t in ("py", "go"):
        snaps = sorted((Path(spec["roots"][t]) / "campaigns" /
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
    text = data.decode("utf-8", "replace")
    return norm_text(spec, twin, text).encode("utf-8")


def diff_tree(spec: dict) -> None:
    py_root = Path(spec["roots"]["py"]) / "campaigns" / spec["campaign_id"]
    go_root = Path(spec["roots"]["go"]) / "campaigns" / spec["campaign_id"]
    py_files = sorted(p.relative_to(py_root).as_posix() for p in py_root.rglob("*")
                      if p.is_file())
    go_files = sorted(p.relative_to(go_root).as_posix() for p in go_root.rglob("*")
                      if p.is_file())
    only_py = set(py_files) - set(go_files)
    only_go = set(go_files) - set(py_files)
    for f in sorted(only_py):
        fails.append(f"tree: py-only file {f}")
    for f in sorted(only_go):
        fails.append(f"tree: go-only file {f}")
    for f in sorted(set(py_files) & set(go_files)):
        a = norm_bytes(spec, "py", (py_root / f).read_bytes())
        b = norm_bytes(spec, "go", (go_root / f).read_bytes())
        if a != b:
            fails.append(f"tree: {f} differs")
            la, lb = a.decode("utf-8", "replace").splitlines(), \
                b.decode("utf-8", "replace").splitlines()
            for i in range(max(len(la), len(lb))):
                xa = la[i] if i < len(la) else "<missing>"
                xb = lb[i] if i < len(lb) else "<missing>"
                if xa != xb:
                    fails.append(f"    line {i+1} py: {xa[:200]}")
                    fails.append(f"    line {i+1} go: {xb[:200]}")
                    break
    if not any(x.startswith("tree:") for x in fails):
        print(f"tree: {len(py_files)} files byte-MATCH (normalized)")


def audit_json_step(spec: dict, step: int) -> None:
    """Compare the audit --json report on its P0 sections only."""
    def p0_report(twin: str) -> dict:
        f = WORK / "captures" / twin / f"{step:02d}-audit-json.out"
        doc = json.loads(norm_text(spec, twin, f.read_text()))
        return {"campaign_id": doc["campaign_id"], "ok": doc["ok"],
                "sections": {k: doc["sections"][k]
                             for k in P0_SECTIONS if k in doc["sections"]}}
    a, b = p0_report("py"), p0_report("go")
    if a != b:
        fails.append(f"step {step:02d} audit-json P0 sections differ")
        for k in sorted(set(a["sections"]) | set(b["sections"])):
            if a["sections"].get(k) != b["sections"].get(k):
                fails.append(f"    section {k}:\n"
                             f"      py: {json.dumps(a['sections'].get(k), sort_keys=True)[:300]}\n"
                             f"      go: {json.dumps(b['sections'].get(k), sort_keys=True)[:300]}")
    else:
        print(f"step {step:02d} audit-json: P0 sections + ok MATCH "
              f"(py has {len(json.loads((WORK / 'captures' / 'py' / f'{step:02d}-audit-json.out').read_text())['sections'])} "
              f"sections, go {len(json.loads((WORK / 'captures' / 'go' / f'{step:02d}-audit-json.out').read_text())['sections'])} — "
              f"py-only P1+ expected)")


def p0_summary_prefix(line: str) -> str:
    """The audit summary line reduced to its six P0 section tokens, in
    order: 'audit <VERDICT>: event_log=N problem(s), ..., snapshots=N
    problem(s)'. P1+ tokens (Python-only until P1+ lands) are dropped."""
    head = line.split(":", 1)[0]
    toks = re.findall(r"(\w+)=(\d+) problem\(s\)", line)
    keep = [f"{k}={v} problem(s)" for k, v in toks if k in P0_SECTIONS]
    return f"{head}: {', '.join(keep)}"


def diff_steps(spec: dict) -> None:
    for i, name in enumerate(spec["recipe"]):
        for ext in ("out", "err", "exit"):
            a = (WORK / "captures" / "py" / f"{i:02d}-{name}.{ext}").read_text()
            b = (WORK / "captures" / "go" / f"{i:02d}-{name}.{ext}").read_text()
            if ext == "exit":
                if a.strip() != b.strip():
                    fails.append(f"step {i:02d} {name}: exit py={a.strip()} "
                                 f"go={b.strip()}")
                continue
            if name == "audit-json" and ext == "out":
                continue  # handled by audit_json_step
            na, nb = norm_text(spec, "py", a), norm_text(spec, "go", b)
            if name == "audit" and ext == "out":
                # KNOWN_DIVERGENCE (audit P0 subset): the plain summary
                # line lists every section the implementation has — 12 in
                # Python, 6 in Go. Compare the six P0 tokens in order;
                # the problem lines that follow must still be identical.
                la, lb = na.splitlines(), nb.splitlines()
                if la and lb and la[0].startswith("audit ") and lb[0].startswith("audit "):
                    if p0_summary_prefix(la[0]) != p0_summary_prefix(lb[0]):
                        fails.append(f"step {i:02d} audit: P0 summary prefix differs\n"
                                     f"    py: {la[0]}\n    go: {lb[0]}")
                    la, lb = la[1:], lb[1:]
                na, nb = "\n".join(la), "\n".join(lb)
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
    exits = all((WORK / "captures" / t / f"{i:02d}-{n}.exit").read_text().strip() == "0"
                for t in ("py", "go") for i, n in enumerate(spec["recipe"]))
    print(f"steps: {len(spec['recipe'])} commands x 2 twins "
          f"({'all exit 0' if exits else 'NONZERO EXIT PRESENT'})")


def main() -> None:
    spec = load_spec()
    diff_tree(spec)
    diff_steps(spec)
    audit_json_step(spec, spec["recipe"].index("audit-json"))
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
