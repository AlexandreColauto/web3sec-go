#!/usr/bin/env python3
"""Golden-suite orchestrator (Task 17).

Builds the Go binary, then runs the SAME scripted op-sequence through the
Python webv2 CLI and the Go webv2 binary — both with the clock pinned
(WEBV2_NOW, monotonic +1s per step) and the id stream pinned
(WEBV2_UUID seed, identical derivation in both twins) — into two fresh
roots, capturing every command's stdout/stderr/exit and the resulting
artifact trees for check-golden.py to byte-diff.

The recipe has two halves:

  P0 (steps 00..07, kept verbatim from golden v1 — see docs/gates/P0-gate.md)
      init / status / snap / log / verify / audit / status / audit --json

  P1 (steps 08.., docs/gates/golden-v2.md) — the ported P1 CLI surface:
      model, plan, ingest x4 (two flagged near-duplicate pairs), dedup,
      resolve-candidate (same + distinct), prioritize, repro-queue,
      floors set/list/json/unset, answered (priority + lens), plan --rebuild,
      verdict, recall, gate (all / one / economic / --explain),
      prove (bare + --stage), waive, artifact-register, artifact-list,
      invariant-verify, invariant-contradict, budget, scope, hint,
      then a 5th finding ingested in a state the CONFIRMED gate accepts
      (its dry-run PASSES, the counterweight to the two failing dry-runs),
      moved HYPOTHESIS -> POSSIBLE -> CONFIRMED through the CLI,
      then the closing status/audit/audit --json/log/verify.

Fixtures live under scripts/golden/ and are referenced by paths RELATIVE to
the Go repo root; both twins run with cwd=GO_ROOT so a relative path means
the same file in both. The snapshot target is materialized in a temp dir
OUTSIDE any git repository on purpose: inside a repo the `git-clean`
ladder pins a `git worktree` whose `.git` file embeds a per-process
gitdir, which is not reproducible across twins (or runs).
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GO_ROOT = Path(__file__).resolve().parent.parent
PY_ROOT = GO_ROOT.parent / "web3sec-final"
WORK = GO_ROOT / ".scratch" / "golden"
GOBIN = WORK / "webv2"
SEED = "golden-p0"
NOW_BASE = datetime.datetime(2026, 9, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
FIX = "scripts/golden"          # fixture dir, relative to GO_ROOT


def now_for(step: int) -> str:
    t = NOW_BASE + datetime.timedelta(seconds=step)
    return t.isoformat(timespec="microseconds").replace("+00:00", "+00:00")


def make_target() -> Path:
    """Materialize the pinned target OUTSIDE the repo (see module docstring)."""
    tgt = Path(tempfile.mkdtemp(prefix="webv2-golden-v2-target-"))
    (tgt / "src").mkdir(parents=True)
    (tgt / "docs").mkdir()
    (tgt / "data").mkdir()
    (tgt / "foundry.toml").write_text('[profile.default]\nsol = "0.8.24"\n')
    # v1's bulk-default prune fixture (data/ is always pruned from a pin)
    for i in range(3):
        (tgt / "data" / f"f{i:04d}.dat").write_bytes(b"x" * 32)
    (tgt / "src" / "Vault.sol").write_text(
        "// Golden Vault\ncontract Vault { uint256 public total; }\n")
    (tgt / "src" / "Other.sol").write_text("contract Other { }\n")
    # Documented invariants: INV-1..INV-4 mirror the model, INV-9 is
    # documented-but-missing-from-the-model (reconciliation must report it),
    # and INV-4's line carries intent language (donations are by design) so
    # the finding bound to INV-4 owes a shield adjudication at the gate.
    (tgt / "docs" / "INVARIANTS.md").write_text(
        "# Golden Vault invariants\n"
        "\n"
        "INV-1: only the admin role may withdraw assets from the vault.\n"
        "INV-2: the total assets must always cover the sum of all user claims.\n"
        "INV-3: the pause role can only be granted through the timelock.\n"
        "INV-4: the share price must not move in favor of existing shares; "
        "out-of-band donations are by design and accrue to stakers.\n"
        "INV-9: the oracle price must be fresh within one block.\n")
    return tgt


def render_gate_pass_payload(artifact_id: str) -> Path:
    """Materialize h5 with its evidence pointing at the artifact the recipe
    registered (the fixture ships a REP-00000000 placeholder; the artifact
    id is minted from the pinned stream while the run proceeds)."""
    out_dir = WORK / "payloads"
    out_dir.mkdir(parents=True, exist_ok=True)
    src = (GO_ROOT / FIX / "h5-gate-pass.json").read_text()
    out = out_dir / "h5-gate-pass.json"
    out.write_text(src.replace("REP-00000000", artifact_id))
    return out


def build_go() -> None:
    env = dict(os.environ,
               GOCACHE=str(GO_ROOT / ".scratch" / "gocache"),
               GOPATH=str(GO_ROOT / ".scratch" / "gopath"),
               GOMODCACHE=str(GO_ROOT / ".scratch" / "gomodcache"),
               GOFLAGS="-mod=mod")
    r = subprocess.run(["go", "build", "-o", str(GOBIN), "./cmd/webv2"],
                       cwd=GO_ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"go build failed:\n{r.stderr}")


def run_step(twin: str, root: Path, argv: list[str], step: int,
             fid_base: int) -> tuple[int, str, str]:
    now = now_for(step)
    # WEBV2_FINDING_IDS=pin + WEBV2_FINDING_ID_SEQ: Python's
    # findings.new_finding_id is a raw uuid4, so the two twins must be
    # pinned through the same stream (see scripts/golden/sitecustomize.py
    # and cmd/webv2/main.go). WEBV2_GLOBAL_MEMORY_DIR points at an empty
    # dir: the operator's ~/.webv2/shared-memory store must never leak into
    # a deterministic cross-twin comparison.
    env = dict(os.environ, WEBV2_NOW=now, WEBV2_UUID=SEED,
               WEBV2_FINDING_IDS="pin", WEBV2_FINDING_ID_SEQ=str(fid_base),
               WEBV2_GLOBAL_MEMORY_DIR=str(WORK / "shared-memory"))
    # Both twins run with cwd=GO_ROOT so a relative fixture path resolves to
    # the same file; the Python package is located via PYTHONPATH.
    cwd = GO_ROOT
    if twin == "py":
        env["PYTHONPATH"] = os.pathsep.join(
            [str(GO_ROOT / "scripts" / "golden"), str(PY_ROOT / "src")])
        cmd = [sys.executable, "-m", "webv2.cli", "--root", str(root)] + argv
    else:
        cmd = [str(GOBIN), "--root", str(root)] + argv
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd)
    return r.returncode, r.stdout, r.stderr


# ---------------------------------------------------------------------------
# recipe
#
# Each entry: name, argv(state), expected exit code. `state` carries the ids
# the pinned id stream minted (campaign, findings in ingest order, artifacts),
# so later steps can reference them without hardcoding.
# ---------------------------------------------------------------------------

def recipe(state: dict) -> list[dict]:
    cid = state["cid"]
    # Pad to a fixed width: the recipe is built before the run mints any ids,
    # and rebuilt before every step, so by the time a step that references
    # f[i]/art[i] executes the real id is there. The step LIST never changes
    # shape, which is what the capture index depends on.
    f = (state["findings"] + ["<F?>"] * 5)[:5]   # [h1..h5]
    art = (state["artifacts"] + ["<ART?>"] * 2)[:2]
    return [
        # ---- P0 half: verbatim golden v1 (docs/gates/P0-gate.md) ----------
        {"name": "init", "exit": 0,
         "argv": ["init", "--program", "Golden"]},
        {"name": "status", "exit": 0, "argv": ["status", cid]},
        {"name": "snap", "exit": 0,
         "argv": ["snap", cid, state["target"]]},
        {"name": "log", "exit": 0, "argv": ["log", cid]},
        {"name": "verify", "exit": 0, "argv": ["verify", cid]},
        {"name": "audit", "exit": 0, "argv": ["audit", cid]},
        {"name": "status2", "exit": 0, "argv": ["status", cid]},
        {"name": "audit-json", "exit": 0, "argv": ["audit", cid, "--json"]},

        # ---- P1 half -----------------------------------------------------
        {"name": "model-load", "exit": 0,
         "argv": ["model", cid, f"{FIX}/model.json"]},
        {"name": "model-show", "exit": 0, "argv": ["model", cid]},
        {"name": "plan", "exit": 0, "argv": ["plan", cid]},
        # the bounty gate reads the policy, so scope must precede it
        {"name": "scope", "exit": 0,
         "argv": ["scope", cid, "--policy", f"{FIX}/policy.json"]},

        {"name": "ingest-h1", "exit": 0, "findings": 1,
         "argv": ["ingest", cid, "--json-file", f"{FIX}/h1-withdraw-double-count.json",
                  "--stage", "golden", "--trajectory", "code"]},
        {"name": "ingest-h2", "exit": 0, "findings": 1,
         "argv": ["ingest", cid, "--json-file", f"{FIX}/h2-deposit-double-mint.json",
                  "--stage", "golden", "--trajectory", "code"]},
        {"name": "ingest-h3", "exit": 0, "findings": 1,
         "argv": ["ingest", cid, "--json-file", f"{FIX}/h3-share-price-inflation.json",
                  "--stage", "golden", "--trajectory", "economic"]},
        {"name": "ingest-h4", "exit": 0, "findings": 1,
         "argv": ["ingest", cid, "--json-file", f"{FIX}/h4-oracle-spot-price.json",
                  "--stage", "golden", "--trajectory", "code"]},

        {"name": "dedup", "exit": 0, "argv": ["dedup", cid]},
        {"name": "resolve-same", "exit": 0,
         "argv": ["resolve-candidate", cid, f[1], f[0], "--verdict", "same",
                  "--actor", "golden"]},
        {"name": "resolve-distinct", "exit": 0,
         "argv": ["resolve-candidate", cid, f[3], f[2], "--verdict", "distinct",
                  "--actor", "golden"]},

        {"name": "prioritize", "exit": 0, "argv": ["prioritize", cid]},
        {"name": "repro-queue", "exit": 0, "argv": ["repro-queue", cid]},

        {"name": "floors-set", "exit": 0,
         "argv": ["floors", cid, "set", "logic-error", "E4",
                  "--actor", "golden", "--reason",
                  "the target ships a fork runner, so E4 is reachable"]},
        {"name": "floors-list", "exit": 0, "argv": ["floors", cid]},
        {"name": "floors-json", "exit": 0, "argv": ["floors", cid, "--json"]},
        {"name": "floors-unset", "exit": 0,
         "argv": ["floors", cid, "unset", "logic-error",
                  "--actor", "golden", "--reason",
                  "back to the class default floor"]},

        {"name": "answered-priority", "exit": 0,
         "argv": ["answered", cid, "Q-001", "answered",
                  "--reason", "the drain-capable role is a single multisig, not reachable",
                  "--ref", f[0], "--actor", "golden"]},
        {"name": "plan-readonly", "exit": 0, "argv": ["plan", cid]},
        {"name": "plan-rebuild", "exit": 0, "argv": ["plan", cid, "--rebuild"]},

        {"name": "verdict-h1", "exit": 0,
         "argv": ["verdict", cid, f[0], "--verdict", "confirmed",
                  "--reason", "the double-count is a real accounting defect, code path is reachable"]},
        {"name": "recall-h1", "exit": 0,
         "argv": ["recall", cid, "--finding", f[0], "--mode", "negative"]},
        {"name": "recall-h3", "exit": 0,
         "argv": ["recall", cid, "--finding", f[2], "--mode", "comparative",
                  "--note", "analogous donation inflation seen in a prior share-vault campaign"]},

        {"name": "gate-all", "exit": 0, "argv": ["gate", cid]},
        {"name": "gate-h1", "exit": 1, "argv": ["gate", cid, f[0]]},
        {"name": "gate-h3", "exit": 1, "argv": ["gate", cid, f[2]]},
        {"name": "gate-explain", "exit": 0,
         "argv": ["gate", "--explain", "evidence-floor"]},

        {"name": "prove-all", "exit": 0, "argv": ["prove", cid]},
        {"name": "prove-learning", "exit": 1,
         "argv": ["prove", cid, "--stage", "learning"]},
        {"name": "waive-learning", "exit": 0,
         "argv": ["waive", cid, "learning",
                  "--reason", "the golden suite records the waiver path, not a real gap",
                  "--actor", "golden"]},
        {"name": "prove-learning2", "exit": 0,
         "argv": ["prove", cid, "--stage", "learning"]},

        {"name": "artifact-register", "exit": 0, "artifacts": 1,
         "argv": ["artifact-register", cid, f"{FIX}/artifact.md",
                  "--kind", "report", "--note", "withdraw path check notes"]},
        {"name": "artifact-list", "exit": 0, "argv": ["artifact-list", cid]},
        {"name": "artifact-list-kind", "exit": 0,
         "argv": ["artifact-list", cid, "--kind", "report"]},
        # h5 is ingested in a state the CONFIRMED gate accepts: a
        # reproduced attempt plus an E7 evidence item bound to the artifact
        # registered above. Its `gate` dry-run therefore PASSES (exit 0) —
        # the counterweight to gate-h1/gate-h3 — and the two `move` steps
        # below walk the legal HYPOTHESIS -> POSSIBLE -> CONFIRMED path, so
        # the closing status/audit/verify steps see a genuinely CONFIRMED
        # finding.
        {"name": "ingest-h5", "exit": 0, "findings": 1, "render_h5": True,
         "argv": ["ingest", cid, "--json-file",
                  ".scratch/golden/payloads/h5-gate-pass.json",
                  "--stage", "golden", "--trajectory", "code"]},
        {"name": "verdict-h5", "exit": 0,
         "argv": ["verdict", cid, f[4], "--verdict", "confirmed",
                  "--reason", "the rounding delta is a real payout defect on a reachable path"]},
        {"name": "recall-h5", "exit": 0,
         "argv": ["recall", cid, "--finding", f[4], "--mode", "negative"]},
        {"name": "gate-h5-pass", "exit": 0, "argv": ["gate", cid, f[4]]},
        {"name": "move-h5-possible", "exit": 0,
         "argv": ["move", cid, f[4], "POSSIBLE", "--reason",
                  "the golden suite advances the gated finding to POSSIBLE",
                  "--actor", "golden"]},
        {"name": "move-h5-confirmed", "exit": 0,
         "argv": ["move", cid, f[4], "CONFIRMED", "--reason",
                  "the golden suite closes the gated finding to CONFIRMED",
                  "--actor", "golden"]},

        {"name": "invariant-verify", "exit": 0,
         "argv": ["invariant-verify", cid, "INV-2", "--artifact", art[0]]},
        {"name": "invariant-contradict", "exit": 0,
         "argv": ["invariant-contradict", cid, "INV-3",
                  "--evidence", "src/Other.sol#L1"]},

        {"name": "budget-set", "exit": 0,
         "argv": ["budget", cid, "--set", "2500", "--actor", "golden"]},
        {"name": "budget-json", "exit": 0, "argv": ["budget", cid, "--json"]},
        {"name": "hint", "exit": 0,
         "argv": ["hint", cid, "--kind", "priority",
                  "--content", "prefer the accounting path over the oracle path",
                  "--source-ref", f[0], "--actor", "golden"]},
        {"name": "answered-lens", "exit": 0,
         "argv": ["answered", cid, "L-01", "answered",
                  "--reason", "no reachable permanently-stuck state in this state machine",
                  "--families", "none-applicable", "--actor", "golden"]},

        # ---- closing half: same P0 verbs again, now over the P1 state ----
        {"name": "status-final", "exit": 0, "argv": ["status", cid]},
        {"name": "audit-final", "exit": 0, "argv": ["audit", cid]},
        {"name": "audit-json-final", "exit": 0, "argv": ["audit", cid, "--json"]},
        {"name": "log-tail", "exit": 0, "argv": ["log", cid, "--tail", "5"]},
        {"name": "verify-final", "exit": 0, "argv": ["verify", cid]},
    ]


FID_RE = re.compile(r"ingested (F-[0-9a-f]+)")
ART_RE = re.compile(r"^([A-Z]{3}-[0-9a-f]+):", re.M)


def main() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "captures").mkdir(parents=True)
    build_go()
    target = make_target()

    roots: dict[str, str] = {}
    trees: dict[str, str] = {}
    captures: dict[str, list] = {}
    states: dict[str, dict] = {}
    # BOTH twins run under the SAME root path, sequentially: every event
    # hash covers absolute artifact paths, so two different roots could
    # never produce the same event chain. The Python tree is archived to
    # .scratch/golden/tree-py before the Go run re-creates .scratch/golden/root.
    root = WORK / "root"
    for twin in ("py", "go"):
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        roots[twin] = str(root)
        caps = WORK / "captures" / twin
        caps.mkdir(parents=True)
        captures[twin] = []
        state = {"cid": "", "findings": [], "artifacts": [],
                 "target": str(target)}
        states[twin] = state
        # The step LIST is state-independent, but each step's argv embeds ids
        # the pinned stream mints while the run proceeds, so it is rebuilt
        # from the live state before every step.
        n_steps = len(recipe(state))
        i = 0
        fid_base = 0
        while i < n_steps:
            st = recipe(state)[i]
            argv = [str(a) for a in st["argv"]]
            if st.get("render_h5"):
                render_gate_pass_payload(state["artifacts"][0])
            code, out, err = run_step(twin, root, argv, i, fid_base)
            name = st["name"]
            (caps / f"{i:02d}-{name}.out").write_text(out)
            (caps / f"{i:02d}-{name}.err").write_text(err)
            (caps / f"{i:02d}-{name}.exit").write_text(str(code))
            captures[twin].append({"name": name, "argv": argv, "exit": code,
                                   "expect_exit": st["exit"]})
            if st.get("findings"):
                for _ in range(st["findings"]):
                    m = FID_RE.search(out)
                    if not m:
                        sys.exit(f"{twin} step {i:02d}-{name}: no finding id in stdout:\n{out}")
                    state["findings"].append(m.group(1))
                fid_base += st["findings"]
            if st.get("artifacts"):
                for _ in range(st["artifacts"]):
                    m = ART_RE.search(out)
                    if not m:
                        sys.exit(f"{twin} step {i:02d}-{name}: no artifact id in stdout:\n{out}")
                    state["artifacts"].append(m.group(1))
            if name == "init":
                m = re.search(r"C-[0-9a-f]+", out)
                if not m:
                    sys.exit(f"{twin} init did not print a campaign id:\n{out}")
                state["cid"] = m.group(0)
            if code != st["exit"]:
                print(f"[warn] {twin} step {i:02d}-{name}: exit {code}, "
                      f"expected {st['exit']}: {err.strip()[:200]}")
            i += 1
        archived = WORK / f"tree-{twin}"
        shutil.rmtree(archived, ignore_errors=True)
        shutil.move(str(root), str(archived))
        trees[twin] = str(archived)

    if states["py"]["cid"] != states["go"]["cid"]:
        sys.exit(f"campaign ids differ: py={states['py']['cid']} "
                 f"go={states['go']['cid']} (pinned id stream out of sync)")

    spec = {
        "seed": SEED,
        "now_base": NOW_BASE.isoformat(),
        "roots": roots,
        "trees": trees,
        "target": str(target),
        "campaign_id": states["py"]["cid"],
        "recipe": [c["name"] for c in captures["py"]],
        "expected_exit": [c["expect_exit"] for c in captures["py"]],
        "captures": captures,
    }
    (WORK / "spec.json").write_text(json.dumps(spec, indent=1))
    print(f"golden run complete: campaign {states['py']['cid']} "
          f"({len(spec['recipe'])} steps x 2 twins)")
    print(f"  run root (both twins): {roots['py']}")
    print(f"  archived trees: {trees['py']} | {trees['go']}")


if __name__ == "__main__":
    main()
