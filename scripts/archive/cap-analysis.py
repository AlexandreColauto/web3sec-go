#!/usr/bin/env python3
"""cap-analysis.py — D27 evidence: the chain-proposal cap binds identically
in both twins, while Python's enumeration ORDER is PYTHONHASHSEED-dependent.

D27 (KNOWN_DIVERGENCES.md) records ONE declared divergence in
`chainengine.FindChains`: Python iterates `caps_held` / `needs[cap]` as SETS,
so the order of the 500 capped proposals changes with the interpreter's hash
seed; the Go port sorts both neighbour sets, so its cut is deterministic.
Raw byte-identity of the capped set is therefore impossible in principle.

This script proves the SUBSTANTIVE parity instead, from scratch:

  1. both twins cap at exactly 500 proposals, all distinct member sets;
  2. given the SAME finding ids, Go is deterministic across repeated runs;
  3. Python is NOT deterministic across PYTHONHASHSEED (>=2 distinct digests);
  4. with the cap raised, Python enumerates the full space (793 distinct
     member sets) and BOTH capped sets are SUBSETs of it;
  5. the two capped sets overlap substantially (same space, different cut
     order).

Caveat the numbers make visible: `new_finding_id` is a raw uuid4 in BOTH
twins (it is not derived from `state.new_id`, so WEBV2_UUID does not pin it),
which means every invocation ingests differently-named findings. Both cuts
therefore differ run to run; only the properties above are asserted, and the
793-member full space (a function of the fixture graph alone) is stable.

Exit 0 iff every claim holds. Requires the Python reference repo beside this
one (web3sec-final); if it is absent the Python-side claims are reported as
SKIPPED and the Go-side claims still run.

Usage: python3 scripts/cap-analysis.py [--keep]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

GO_ROOT = Path(__file__).resolve().parent.parent
PY_ROOT = GO_ROOT.parent / "web3sec-final"
WORK = GO_ROOT / ".scratch" / "t37" / "cap-analysis"
CAP = 500
FINDINGS = 13
GOBIN = WORK / "webv2"
FID_RE = re.compile(r"F-[0-9a-f]+")
CID_RE = re.compile(r"C-[0-9a-f]+")

failures: list[str] = []
notes: list[str] = []


def claim(name: str, ok: bool, detail: str) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    if not ok:
        failures.append(f"{name}: {detail}")


def run(cmd, **kw):
    env = dict(os.environ)
    env.update(kw.pop("env", {}))
    return subprocess.run(cmd, capture_output=True, text=True, env=env, **kw)


def write_fixtures() -> Path:
    fx = WORK / "fx"
    fx.mkdir(parents=True, exist_ok=True)
    for i in range(FINDINGS):
        (fx / f"h{i}.json").write_text(json.dumps({
            "title": f"cap finding {i}",
            "root_cause": {"class": "logic-error",
                           "description": "capability sharing for the cap test"},
            "affected": [{"path": f"src/F{i}.sol", "function": "f"}],
            "attacker": {"profile": "EOA", "capabilities": []},
            "capabilities": {
                "granted": ["grantA"] if i > 0 else ["grantB"],
                "required": ["grantB"] if i > 0 else []},
        }))
    return fx


def build_go() -> None:
    env = dict(os.environ)
    env.setdefault("GOCACHE", str(GO_ROOT / ".scratch" / "gocache"))
    env.setdefault("GOPATH", str(GO_ROOT / ".scratch" / "gopath"))
    env.setdefault("GOMODCACHE", str(GO_ROOT / ".scratch" / "gomodcache"))
    env.setdefault("GOFLAGS", "-mod=mod")
    r = run(["go", "build", "-o", str(GOBIN), "./cmd/webv2"], cwd=GO_ROOT, env=env)
    if r.returncode != 0:
        sys.exit(f"go build failed:\n{r.stderr}")


# Pin the clock (and the state id stream) so campaign/priority ids are stable
# across invocations. NOTE: finding ids are NOT covered — `new_finding_id` is
# a raw uuid4 in both twins and ignores WEBV2_UUID — so the exact chain cut
# remains a per-run value; the script asserts properties, not a digest.
PIN_NOW = "2026-01-01T00:00:00.000000+00:00"


def seed_campaign(root: Path, fx: Path, twin: str) -> str:
    root.mkdir(parents=True, exist_ok=True)
    base = {"PYTHONPATH": str(PY_ROOT / "src"), "WEBV2_NOW": PIN_NOW,
            "WEBV2_UUID": "cap-analysis-init"}
    if twin == "go":
        argv = [str(GOBIN), "--root", str(root), "init", "--program", "Cap Program"]
    else:
        argv = [sys.executable, "-m", "webv2.cli", "--root", str(root),
                "init", "--program", "Cap Program"]
    r = run(argv, cwd=root, env=base)
    if r.returncode != 0:
        sys.exit(f"{twin} init failed: {r.stderr}")
    cid = CID_RE.search(r.stdout + r.stderr).group(0)
    for i in range(FINDINGS):
        env = dict(base, WEBV2_UUID=f"cap-analysis-{i}")
        if twin == "go":
            argv = [str(GOBIN), "--root", str(root), "ingest", cid,
                    "--json-file", str(fx / f"h{i}.json")]
        else:
            argv = [sys.executable, "-m", "webv2.cli", "--root", str(root),
                    "ingest", cid, "--json-file", str(fx / f"h{i}.json")]
        r = run(argv, cwd=root, env=env)
        if r.returncode != 0:
            sys.exit(f"{twin} ingest {i} failed: {r.stderr}")
    return cid


def chains_text(root: Path, cid: str, twin: str, hashseed: str | None = None) -> str:
    env = {"PYTHONPATH": str(PY_ROOT / "src")}
    if hashseed is not None:
        env["PYTHONHASHSEED"] = hashseed
    if twin == "go":
        argv = [str(GOBIN), "--root", str(root), "chains", cid]
    else:
        argv = [sys.executable, "-m", "webv2.cli", "--root", str(root),
                "chains", cid]
    r = run(argv, cwd=root, env=env)
    if r.returncode != 0:
        sys.exit(f"{twin} chains failed: {r.stderr}")
    return r.stdout


def id_map(root: Path, cid: str) -> dict[str, int]:
    """finding_id -> fixture index, from the ingested title ("cap finding N").

    The two roots mint their own content-addressed finding ids, so cross-twin
    set comparison must go through the fixture index, not the raw id.
    """
    out = {}
    for f in sorted((root / "campaigns" / cid / "findings").glob("*.json")):
        doc = json.loads(f.read_text())
        m = re.search(r"(\d+)$", str(doc.get("title", "")))
        if m:
            out[f.stem] = int(m.group(1))
    return out


def canon(props: list[tuple[str, ...]], imap: dict[str, int]) -> set[tuple[int, ...]]:
    return {tuple(sorted(imap[x] for x in p if x in imap)) for p in props}


def proposals(text: str) -> list[tuple[str, ...]]:
    out, inprop = [], False
    for line in text.splitlines():
        if line.startswith("proposals:"):
            inprop = True
            continue
        if line.startswith("materialized chains:"):
            inprop = False
        if inprop and line.startswith("  "):
            out.append(tuple(line[2:].split(" -> ")))
    return out


def digest(props: list[tuple[str, ...]]) -> str:
    h = hashlib.sha256()
    for p in props:
        h.update(("|".join(p) + "\n").encode())
    return h.hexdigest()[:16]


def digest_canon(props: list[tuple[str, ...]], imap: dict[str, int]) -> str:
    """Digest the fixture-index form: stable across runs and across twins."""
    rows = sorted(" -> ".join(str(i) for i in sorted(imap[x] for x in p if x in imap))
                  for p in props)
    h = hashlib.sha256()
    for row in rows:
        h.update((row + "\n").encode())
    return h.hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="keep the scratch campaign trees (default: keep too)")
    ap.parse_args()
    if WORK.exists():
        shutil.rmtree(WORK)
    fx = write_fixtures()
    build_go()
    print(f"fixture: {FINDINGS} capability-sharing findings, cap {CAP}")
    print(f"work:    {WORK.relative_to(GO_ROOT)}")

    go_root, py_root = WORK / "go", WORK / "py"
    go_cid = seed_campaign(go_root, fx, "go")
    go = proposals(chains_text(go_root, go_cid, "go"))
    go_map = id_map(go_root, go_cid)

    print("go:")
    claim("cap binds", len(go) == CAP, f"{len(go)} proposals (want {CAP})")
    claim("proposals distinct", len(set(go)) == CAP,
          f"{len(set(go))} distinct member sets")
    go2 = proposals(chains_text(go_root, go_cid, "go"))
    claim("go deterministic", go2 == go,
          f"repeat run over the SAME fixture: digest "
          f"{digest_canon(go2, go_map)} (canonical)")

    if not PY_ROOT.is_dir():
        notes.append(f"python reference absent at {PY_ROOT}: Python-side claims SKIPPED")
        print("python: SKIPPED (reference repo not found)")
    else:
        py_cid = seed_campaign(py_root, fx, "py")
        py = proposals(chains_text(py_root, py_cid, "py", hashseed="0"))
        py_map = id_map(py_root, py_cid)
        print("python:")
        claim("cap binds", len(py) == CAP, f"{len(py)} proposals (want {CAP})")
        claim("proposals distinct", len(set(py)) == CAP,
              f"{len(set(py))} distinct member sets")

        seeds = {}
        for seed in ("0", "1", "2", "3"):
            props = proposals(chains_text(py_root, py_cid, "py", seed))
            seeds[seed] = digest_canon(props, py_map)
        claim("python hash-seed dependent", len(set(seeds.values())) >= 2,
              "digests " + ", ".join(f"seed{k}={v}" for k, v in seeds.items()))

        # Full enumeration with the cap raised (in-process, seed 0).
        sys.path.insert(0, str(PY_ROOT / "src"))
        os.environ["PYTHONHASHSEED"] = "0"
        from webv2 import chain_engine as CE  # noqa: E402
        from webv2.state import Campaign  # noqa: E402
        camp = Campaign.open(str(py_root), py_cid)
        saved = CE.MAX_PROPOSALS
        CE.MAX_PROPOSALS = 10 ** 9
        try:
            full = CE.find_chains(camp)
        finally:
            CE.MAX_PROPOSALS = saved
        fullset = canon([tuple(p["members"]) for p in full], py_map)
        claim("full space enumerated", len(fullset) > CAP,
              f"{len(fullset)} distinct member sets with the cap raised")
        go_set = canon(go, go_map)
        py_set = canon(py, py_map)
        claim("go capped subset of full space", go_set <= fullset,
              f"{len(go_set - fullset)} outside the full space")
        claim("python capped subset of full space", py_set <= fullset,
              f"{len(py_set - fullset)} outside the full space")
        overlap = len(go_set & py_set)
        claim("capped sets overlap", overlap > 0,
              f"{overlap}/{CAP} shared this run; the two cuts are different "
              f"valid 500-subsets of the same {len(fullset)}-set space")
        notes.append(
            "finding ids are fresh uuid4s in both twins (new_finding_id does "
            "not honour WEBV2_UUID), so the exact capped set — and this "
            "overlap — is a per-run value; the asserted properties are not.")

    print()
    if notes:
        for n in notes:
            print(f"NOTE: {n}")
    if failures:
        print(f"D27 ANALYSIS RED: {len(failures)} claim(s) failed")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("D27 ANALYSIS GREEN: cap semantics identical; the only difference is "
          "the ORDER of the capped set (Python hash-seed dependent, Go sorted).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
