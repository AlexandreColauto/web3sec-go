#!/usr/bin/env python3
"""Golden-suite orchestrator (Task 17).

Builds the Go binary, then runs the SAME scripted P0 op-sequence through
the Python webv2 CLI and the Go webv2 binary — both with the clock pinned
(WEBV2_NOW, monotonic +1s per step) and the id stream pinned
(WEBV2_UUID seed, identical derivation in both twins) — into two fresh
roots, capturing every command's stdout/stderr/exit and the resulting
artifact trees for check-golden.py to byte-diff.

The recipe (P0 command surface, documented in docs/gates/P0-gate.md):
    01 init      init --program Golden
    02 status    status <cid>
    03 snap      snap <cid> <target>
    04 log       log <cid>
    05 verify    verify <cid>
    06 audit     audit <cid>
    07 status    status <cid>
    08 audit     audit <cid> --json
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

GO_ROOT = Path(__file__).resolve().parent.parent
PY_ROOT = GO_ROOT.parent / "web3sec-final"
WORK = GO_ROOT / ".scratch" / "golden"
GOBIN = WORK / "webv2"
SEED = "golden-p0"
NOW_BASE = datetime.datetime(2026, 9, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)

RECIPE_NAMES = [
    "init", "status", "snap", "log", "verify", "audit", "status", "audit-json",
]


def now_for(step: int) -> str:
    t = NOW_BASE + datetime.timedelta(seconds=step)
    return t.isoformat(timespec="microseconds").replace("+00:00", "+00:00")


def make_target() -> Path:
    tgt = WORK / "target"
    shutil.rmtree(tgt, ignore_errors=True)
    (tgt / "src").mkdir(parents=True)
    (tgt / "data").mkdir()
    (tgt / "foundry.toml").write_text('[profile.default]\nsol = "0.8.24"\n')
    (tgt / "src" / "Vault.sol").write_text(
        "contract Vault { uint256 public total; }")
    (tgt / "src" / "Other.sol").write_text("contract Other { }")
    for i in range(3):
        (tgt / "data" / f"f{i:04d}.dat").write_bytes(b"x" * 32)
    return tgt


def build_go() -> None:
    env = dict(os.environ,
               GOCACHE=str(GO_ROOT / ".scratch" / "gocache"),
               GOPATH=str(GO_ROOT / ".scratch" / "gomod"))
    r = subprocess.run(["go", "build", "-o", str(GOBIN), "./cmd/webv2"],
                       cwd=GO_ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"go build failed:\n{r.stderr}")


def run_step(twin: str, root: Path, argv: list[str], step: int) -> tuple[int, str, str]:
    now = now_for(step)
    env = dict(os.environ, WEBV2_NOW=now, WEBV2_UUID=SEED)
    if twin == "py":
        env["PYTHONPATH"] = str(PY_ROOT / "src")
        cmd = [sys.executable, "-m", "webv2.cli", "--root", str(root)] + argv
        cwd = PY_ROOT
    else:
        cmd = [str(GOBIN), "--root", str(root)] + argv
        cwd = GO_ROOT
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd)
    return r.returncode, r.stdout, r.stderr


def main() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "captures").mkdir(parents=True)
    build_go()
    make_target()

    roots = {}
    captures = {}
    cid = {}
    for twin in ("py", "go"):
        root = WORK / twin
        root.mkdir(parents=True)
        roots[twin] = str(root)
        caps = WORK / "captures" / twin
        caps.mkdir(parents=True)
        captures[twin] = []
        for i, name in enumerate(RECIPE_NAMES):
            if name == "init":
                argv = ["init", "--program", "Golden"]
            else:
                cid_t = cid[twin]
                argv = {
                    "status": ["status", cid_t],
                    "snap": ["snap", cid_t, str(WORK / "target")],
                    "log": ["log", cid_t],
                    "verify": ["verify", cid_t],
                    "audit": ["audit", cid_t],
                    "audit-json": ["audit", cid_t, "--json"],
                }[name]
            code, out, err = run_step(twin, root, argv, i)
            (caps / f"{i:02d}-{name}.out").write_text(out)
            (caps / f"{i:02d}-{name}.err").write_text(err)
            (caps / f"{i:02d}-{name}.exit").write_text(str(code))
            captures[twin].append({"name": name, "argv": argv, "exit": code})
            if name == "init":
                m = re.search(r"C-[0-9a-f]+", out)
                if not m:
                    sys.exit(f"{twin} init did not print a campaign id:\n{out}")
                cid[twin] = m.group(0)
            if code != 0:
                print(f"[warn] {twin} step {i:02d}-{name} exit {code}: {err.strip()[:200]}")

    if cid["py"] != cid["go"]:
        sys.exit(f"campaign ids differ: py={cid['py']} go={cid['go']} "
                 "(pinned id stream out of sync)")

    spec = {
        "seed": SEED,
        "now_base": NOW_BASE.isoformat(),
        "roots": roots,
        "target": str(WORK / "target"),
        "campaign_id": cid["py"],
        "recipe": RECIPE_NAMES,
        "captures": captures,
    }
    (WORK / "spec.json").write_text(json.dumps(spec, indent=1))
    print(f"golden run complete: campaign {cid['py']}")
    print(f"  py root: {roots['py']}")
    print(f"  go root: {roots['go']}")


if __name__ == "__main__":
    main()
