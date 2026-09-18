#!/usr/bin/env python3
"""Golden-suite orchestrator (Tasks 17 + 24).

The Python twin is retired (Go is the source of truth). Builds the Go
binary and runs the scripted op-sequence through the Go webv2 CLI with the
clock pinned (WEBV2_NOW, monotonic +1s per step) and the id stream pinned
(WEBV2_UUID seed) into a fresh root, capturing every command's
stdout/stderr/exit and the resulting artifact tree for check-golden.py to
validate (declared exit codes, tree + event-chain integrity, audit surface).

The recipe has four halves:

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

  P2 (docs/gates/golden-v3.md) — the ported P2 evidence-execution surface:
      two more gate-passing findings that GRANT / REQUIRE the same
      capability (h6/h7) moved to CONFIRMED, the exec ledger
      (exec --dry-run / host exec / failed exec / execs / execs --json /
      execs --id / classify), an out-of-band E4 exec record seeded by the
      harness, mint (the ATT-/EV- id families), the full variant ladder
      lifecycle (start / show / add / explore x4 / repro / set-maximal /
      complete / report) on the CONFIRMED h5, both byte-comparable
      `ladder disprove` GUARD branches (short reason, reproduced rung — the
      happy path writes negative memory, KNOWN_DIVERGENCES D18), chains +
      terminals + privileged over the capability graph (the CHAIN- id
      family), `sequence verify` over the empty coverage state (the real
      fork run needs docker/anvil and lives in scripts/p2-docker-e2e.sh),
      and impact (priced, priced+artifact, and the UNPRICEABLE named
      decision).

  P4 (docs/gates/P4-gate.md) — the ported P4 surface, over the committed
      P4 fixture (scripts/golden/p4/, built from the read-only reference by
      scripts/golden/p4/build.py): the sft verb group (list / lint x3 /
      split / report / export x2 / backfill) against a per-twin store copy,
      with the post-split store bytes compared as a tree file. The three P4
      env seams (WEBV2_POC_ROOT / WEBV2_EVAL_DIR / WEBV2_SFT_STORE) now
      point at the fixture, so the existing P3 `corpus-surface` step runs
      against the REAL 30-record DeFiHackLabs slice + the REAL 4-case eval
      store and its shape matches carry record_id / memory_ids / bug_class
      attribution (the fixture's shared-memory store seeds the published
      `ingest:defihacklabs:<record_id>` rows the attribution joins on).

  P3 (docs/gates/golden-v4.md) — the ported P3 surface, over a target that
      now carries the reference probes package's own Solidity fixtures:
      index / sinks / prescreen (+ --json), the probe surface (run / list /
      list --all / list --axis / the named `blank` attestation / run --emit
      twice), relations --rebuild + view, resemble, corpus-surface, negative
      memory (ladder disprove on h7 -> MEM- queue -> human approve ->
      publish -> globalize -> shared / shared --verify), brief (+ --json /
      --deep), report, recency (+ --json), baseline list, forkdiff (+
      --json), cost x2, yields, price set/table, price-basis, env doctor
      (+ --json), doctor (+ --json), the `run` halt (exit 3), and complete
      (guard + success). A SECOND campaign closes the recipe with
      `snap --deployment/--chain` (D19): its pin members, manifest roots,
      events and summary lines are byte-compared, and it is kept last so a
      fork-pinned snapshot cannot rewrite campaign 1's P1/P2 outputs.

  ID PINNING (v3 extension): the reference mints every `new_id` family
      (C-, EXEC-, EV-, ATT-, LAD-, R-, CHAIN-, REP-, ECO-, PRC-) from
      `sha256("<WEBV2_UUID>:<per-process counter>")`, and EVERY CLI
      invocation is a fresh process whose counter restarts at 0. A single
      global seed therefore makes the first id of every command identical
      (two `exec` calls would mint the SAME EXEC- id). v3 pins
      `WEBV2_UUID=<seed>:<step>` instead: every step derives the same id per
      step, and distinct steps can no longer collide. The finding-id pin
      (`WEBV2_FINDING_IDS=pin`) keeps its
      own running `WEBV2_FINDING_ID_SEQ` stream on top of the per-step seed;
      the v4 additions are `WEBV2_COST_IDS=pin` + `WEBV2_COST_ID_SEQ` (the
      cost id is a RAW uuid4 in the reference, like the finding id). The
      v4 absent-store pins `WEBV2_EVAL_DIR` / `WEBV2_POC_ROOT` are GONE in
      v5 — both now point at the committed P4 fixture (see D26).

Fixtures live under scripts/golden/ and are referenced by paths RELATIVE to
the Go repo root; cwd=GO_ROOT so a relative path means
the same file in both. The snapshot target is materialized in a temp dir
OUTSIDE any git repository on purpose: inside a repo the `git-clean`
ladder pins a `git worktree` whose `.git` file embeds a per-process
gitdir, which is not reproducible across runs.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# H8: the probe-axis gate list is shared with check-golden.py (the scripts/
# dir is sys.path[0] when this file is run as a script, as golden.sh does).
from probe_axes import SURFACE2_AXES

GO_ROOT = Path(__file__).resolve().parent.parent
WORK = GO_ROOT / ".scratch" / "golden"
GOBIN = WORK / "webv2"
SEED = "golden-p2"
NOW_BASE = datetime.datetime(2026, 9, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
FIX = "scripts/golden"  # fixture dir, relative to GO_ROOT
# Golden v5 (T38): the P4 fixture. A 30-record REAL DeFiHackLabs slice,
# a 4-case eval store and the sft store + lint fixtures, all built from
# the read-only reference by scripts/golden/p4/build.py. The three P4
# env seams point here (see run_step); WEBV2_SFT_STORE is a per-twin
# copy inside the run root because `sft split` writes the store.
P4_FIX = FIX + "/p4"
P4_DATASETS = P4_FIX + "/datasets"
P4_EVAL = P4_FIX + "/eval"
P4_SFT = P4_FIX + "/sft"
# Golden G16 (T19): the second probe-surface recipe. The first campaign pins
# two axes BLIND on purpose (accumulator/blind + assertion_strength/clean, so
# `probes blank` has a disposition to record) — which means a regression that
# stops those detectors emitting rows moves no expectation in that run (the
# C2/F6 blind spot). The surface2 campaign carries >=1 ROW on every registered
# axis (the buggy fixture families + the leaky assertion pair), and the P5
# phase below fails the run loudly if any axis drops to zero rows. That is
# the rot gate: every probe axis carries rows or the suite is red.
#
# H8: SURFACE2_AXES is DERIVED from the one shared gate list
# (scripts/probe_axes.py) — the same table check-golden.py enforces. It used
# to be a hand-copied literal here, so a seventh axis could land in the
# checker and never reach this recipe's per-axis assertion.
SURFACE2_FIX = FIX + "/fixtures-surface"


def now_for(step: int) -> str:
    t = NOW_BASE + datetime.timedelta(seconds=step)
    return t.isoformat(timespec="microseconds").replace("+00:00", "+00:00")


def seed_for(step: int) -> str:
    """The per-step WEBV2_UUID pin (see the module docstring, ID PINNING).

    Every CLI command is a fresh process whose new_id counter restarts at 0,
    so a single global seed would mint the SAME first id in every command
    (two `exec` calls would collide on one EXEC- id). Each step receives the
    same per-step seed, so ids stay deterministic AND unique across
    the recipe."""
    return f"{SEED}:{step:02d}"


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
        "// Golden Vault\ncontract Vault { uint256 public total; }\n"
    )
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
        "INV-9: the oracle price must be fresh within one block.\n"
    )
    # P3 (v4): a real structural surface for index / sinks / prescreen /
    # probes. The fixtures are the reference probes package's own vectors
    # (single-sourced, so they cannot drift from the ported probe code):
    # `accumulator/blind` + `assertion_strength/clean` publish BLIND keys
    # (so `probes blank` has a disposition to record) while `cursor`,
    # `custody` and `short_circuit` emit rows, and the custody pair carries
    # the unguarded-transfer path `sinks` reports. Each fixture gets its
    # own subdirectory: `cursor` and `assertion_strength` both ship a
    # `Rollup.sol`, and the probe ordering is path-based.
    # The five fixtures are chosen so that EVERY registered axis is alive in
    # this run, and so that BOTH legitimate axis states are exercised (C2/F6:
    # before this, two axes reported 0 sites and nothing noticed):
    #
    #   accumulator/blind        -> accumulator-skew    BLIND (sites>0, no row)
    #   assertion_strength/clean -> enforcement-timing  BLIND
    #   cursor/buggy             -> liveness            rows
    #   custody/buggy            -> primitive-symmetry  rows
    #   short_circuit/buggy      -> guard-short-circuit rows
    #   (the campaign's INV-1..INV-9 feed trust-assumption -> incentive-
    #    inversion rows)
    #
    # The two `blind` fixtures are as load-bearing as the three `buggy` ones:
    # they publish the BLIND keys the `probes blank` step cites, and they prove
    # the detectors stay silent on code without the pattern. check-golden.py
    # asserts this axis->state table over the capture, and
    # internal/probes/axis_coverage_test.go proves the complementary side
    # (every axis CAN emit rows, on the buggy corpus, through the same
    # production pipeline) while keeping the checker's table and the registry
    # from drifting apart.
    probe_fixtures = (
        "accumulator/blind",
        "cursor/buggy",
        "assertion_strength/clean",
        "custody/buggy",
        "short_circuit/buggy",
    )
    fixture_root = GO_ROOT / "internal" / "probes" / "testdata" / "probes"
    for sub in probe_fixtures:
        dest = tgt / "probes" / sub.replace("/", "_")
        dest.mkdir(parents=True)
        for f in sorted((fixture_root / sub).glob("*.sol")):
            dest.joinpath(f.name).write_text(f.read_text())
    return tgt


def make_surface2_target() -> Path:
    """Materialize the G16 second-surface target OUTSIDE the repo.

    Same contract as make_target (temp dir outside any git repo, so no
    git-clean worktree pin leaks in): the static Vault/Other/docs shell the
    `model` step loads, plus the fixtures-surface Solidity trees — the buggy
    fixture families (byte copies of the reference probes package's own
    vectors) and the leaky assertion-strength pair (Own asserts the concept
    at class 4, Consumer inherits it and writes state under a class-0 guard
    without asserting). Every registered probe axis fires >=1 row on this
    target; the trust-assumption rows come from FIX/model.json (INV-1 names
    the trusted admin), loaded by the P5 `model-s2` step."""
    tgt = Path(tempfile.mkdtemp(prefix="webv2-golden-surface2-target-"))
    (tgt / "src").mkdir(parents=True)
    (tgt / "docs").mkdir()
    (tgt / "foundry.toml").write_text('[profile.default]\nsol = "0.8.24"\n')
    (tgt / "src" / "Vault.sol").write_text(
        "// Golden Vault\ncontract Vault { uint256 public total; }\n"
    )
    (tgt / "src" / "Other.sol").write_text("contract Other { }\n")
    (tgt / "docs" / "INVARIANTS.md").write_text(
        "# Golden Vault invariants\n"
        "\n"
        "INV-1: only the admin role may withdraw assets from the vault.\n"
        "INV-2: the total assets must always cover the sum of all user claims.\n"
        "INV-3: the pause role can only be granted through the timelock.\n"
        "INV-4: the share price must not move in favor of existing shares; "
        "out-of-band donations are by design and accrue to stakers.\n"
        "INV-9: the oracle price must be fresh within one block.\n"
    )
    fixture_root = GO_ROOT / SURFACE2_FIX
    for sub in sorted(p for p in fixture_root.iterdir() if p.is_dir()):
        dest = tgt / sub.name
        dest.mkdir(parents=True)
        for f in sorted(sub.glob("*.sol")):
            dest.joinpath(f.name).write_text(f.read_text())
    return tgt


def render_gate_pass_payload(artifact_id: str, fixture: str) -> Path:
    """Materialize a gate-pass fixture with its evidence pointing at the
    artifact the recipe registered (the fixtures ship a REP-00000000
    placeholder; the artifact id is minted from the pinned stream while the
    run proceeds)."""
    out_dir = WORK / "payloads"
    out_dir.mkdir(parents=True, exist_ok=True)
    src = (GO_ROOT / FIX / fixture).read_text()
    out = out_dir / fixture
    out.write_text(src.replace("REP-00000000", artifact_id))
    return out


# --- out-of-band E4 exec records (golden v3) --------------------------------
#
# The ladder's `repro` step mints E4 evidence, which the reference only
# accepts from an exec record whose profile is a container/VM profile. The
# default golden suite must stay docker-free, so the harness SEEDS one
# externally-reported exec record exactly the way
# sandbox.register_exec does (origin="externally-reported", empty
# tool_versions, a passing stdout.log) — the same out-of-band registration
# the reference's own CLI test performs with `register_exec`. The record is
# byte-identical by construction (same content, same root
# path), so the tree diff still proves the rest of the P2 surface.
SEEDED_EXEC_STDOUT = "Suite result: ok. 1 passed; 0 failed\n"


def seeded_exec_id(n: int) -> str:
    """A deterministic EXEC- id for the harness-seeded record. Deliberately
    NOT drawn from the CLI's per-process new_id stream: the seeded record is
    harness input, and its id must never collide with an id a real `exec`
    command minted (or will mint) in the same campaign."""
    b = bytearray(hashlib.sha256(f"{SEED}:seed-exec:{n}".encode()).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return "EXEC-" + bytes(b).hex()[:10]


def seed_exec(
    root: Path, cid: str, step: int, n: int, finding_id: str, command: str, exec_id: str
) -> None:
    out_dir = root / "campaigns" / cid / "execs" / exec_id
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / "stdout.log"
    stderr_path = out_dir / "stderr.log"
    stdout_path.write_text(SEEDED_EXEC_STDOUT)
    stderr_path.write_text("")
    at = now_for(step)
    rec = {
        "exec_id": exec_id,
        "campaign_id": cid,
        "profile": "docker-networkless",
        "finding_id": finding_id,
        "artifact_id": None,
        "command": command,
        "workdir": None,
        "policy_verdict": {
            "allowed": True,
            "violations": [],
            "checked_rules": [
                "network-egress-tool",
                "privilege-escalation",
                "destructive-path",
                "secret-access",
                "external-publish",
                "system-write",
            ],
        },
        "environment": {
            "tool_versions": {},
            "env_keys": [],
            "network_access": "none",
            "filesystem": "sandbox-tmp",
        },
        "container": None,
        "origin": "externally-reported",
        "reported_by": "golden-harness",
        "input_hashes": {},
        "started_at": at,
        "finished_at": at,
        "exit_status": 0,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "artifact_hashes": {
            "stdout.log": hashlib.sha256(stdout_path.read_bytes()).hexdigest(),
            "stderr.log": hashlib.sha256(stderr_path.read_bytes()).hexdigest(),
        },
    }
    (out_dir / "exec_record.json").write_text(json.dumps(rec, indent=1) + "\n")


def build_go() -> None:
    env = dict(
        os.environ,
        GOCACHE=str(GO_ROOT / ".scratch" / "gocache"),
        GOPATH=str(GO_ROOT / ".scratch" / "gopath"),
        GOMODCACHE=str(GO_ROOT / ".scratch" / "gomodcache"),
        GOFLAGS="-mod=mod",
    )
    r = subprocess.run(
        ["go", "build", "-o", str(GOBIN), "./cmd/webv2"],
        cwd=GO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        sys.exit(f"go build failed:\n{r.stderr}")


def run_step(
    twin: str, root: Path, argv: list[str], step: int, fid_base: int, sft_store: str
) -> tuple[int, str, str]:
    now = now_for(step)
    # WEBV2_FINDING_IDS=pin + WEBV2_FINDING_ID_SEQ: the finding id is a raw
    # uuid4, so every id minter is pinned through one stream (cmd/webv2).
    # WEBV2_GLOBAL_MEMORY_DIR points at an empty
    # dir: the operator's ~/.webv2/shared-memory store must never leak into
    # a deterministic comparison against the committed oracle.
    env = dict(
        os.environ,
        WEBV2_NOW=now,
        WEBV2_UUID=seed_for(step),
        WEBV2_FINDING_IDS="pin",
        WEBV2_FINDING_ID_SEQ=str(fid_base),
        WEBV2_COST_IDS="pin",
        WEBV2_COST_ID_SEQ=str(fid_base),
        # Golden v5: the P4 seams point at the committed fixture
        # (was: absent dirs, D26). WEBV2_SFT_STORE is the per-twin
        # store copy inside the run root.
        WEBV2_EVAL_DIR=str(GO_ROOT / P4_EVAL),
        WEBV2_POC_ROOT=str(GO_ROOT / P4_DATASETS),
        WEBV2_SFT_STORE=sft_store,
        WEBV2_BASELINES_DIR=str(WORK / "baselines"),
        WEBV2_PROMPTS_BASE=str(GO_ROOT / "assets"),
        WEBV2_GLOBAL_MEMORY_DIR=str(WORK / "shared-memory"),
    )
    # cwd=GO_ROOT so a relative fixture path resolves to the committed file.
    r = subprocess.run(
        [str(GOBIN), "--root", str(root)] + argv,
        capture_output=True,
        text=True,
        env=env,
        cwd=GO_ROOT,
    )
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
    f = (state["findings"] + ["<F?>"] * 7)[:7]  # [h1..h5, h6, h7]
    art = (state["artifacts"] + ["<ART?>"] * 2)[:2]
    ex = (state["execs"] + ["<EXEC?>"] * 2)[:2]
    rung = (state["rungs"] + ["<R?>"] * 2)[:2]
    # P3: the BLIND axis/key `probes list --all --json` published, the MEM-
    # row the disproved rung queued, and the PRC- price row.
    blind = (state.get("blind", []) + ["<AXIS?>", "<KEY?>"])[:2]
    mem = (state.get("mem", []) + ["<MEM?>"])[:1]
    prc = (state.get("prc", []) + ["<PRC?>"])[:1]
    # The plan priority of the FIRST high-risk probe row (tier 0 or
    # assertion_gap >= 3): the row the B4/D1 dismissal gate protects. Absent
    # until `probes run --emit` minted it; a step list built before that
    # references the placeholder and is never reached.
    dr = state.get("dr") or "<DROW?>"
    dr2 = state.get("dr2") or "<DROW2?>"
    drsym = state.get("drsym") or "<DSYM?>"
    # The active snapshot root: `index`/`sinks`/`prescreen`/`recency`/
    # `forkdiff` all take --src, and the audit's probe_surface section
    # compares the probe rows' index_sha against the index of the ACTIVE
    # SNAPSHOT root. Indexing the raw target instead would leave a second
    # index (different path prefixes => different sha) and the closing
    # audit would report the probe surface stale.
    snap_src = state.get("snapshot") or "<SNAP?>"
    cid2 = state.get("cid2") or "<C2?>"
    # P5 (G16): the second surface campaign + its snapshot root. Same
    # placeholder discipline as cid2/snap_src above: steps built before the
    # ids are minted reference these and are never reached until they are.
    cid3 = state.get("cid3") or "<C3?>"
    snap2 = state.get("snap2") or "<SNAP2?>"
    # The halves below each return their contiguous block of steps,
    # concatenated in the same order as the single list this used to be.
    ids = {"cid": cid, "f": f, "art": art, "ex": ex, "rung": rung,
           "blind": blind, "mem": mem, "prc": prc, "dr": dr, "dr2": dr2,
           "drsym": drsym, "snap_src": snap_src, "cid2": cid2,
           "cid3": cid3, "snap2": snap2}
    return (
        recipe_p0(state, ids)
        + recipe_p1_model(state, ids)
            + recipe_p1_ingest(state, ids)
            + recipe_p1_resolve(state, ids)
            + recipe_p1_floors(state, ids)
            + recipe_p1_gate(state, ids)
            + recipe_p1_artifact(state, ids)
            + recipe_p1_h5(state, ids)
            + recipe_p1_h6(state, ids)
            + recipe_p1_h7(state, ids)
            + recipe_p1_close(state, ids)
            + recipe_p2_exec(state, ids)
            + recipe_p2_mint(state, ids)
            + recipe_p2_ladder_start(state, ids)
            + recipe_p2_ladder_explore(state, ids)
            + recipe_p2_ladder_repro(state, ids)
            + recipe_p2_ladder_disprove(state, ids)
            + recipe_p2_chains(state, ids)
            + recipe_p2_impact(state, ids)
            + recipe_p3_index(state, ids)
            + recipe_p3_probes(state, ids)
            + recipe_p3_dismissal(state, ids)
            + recipe_p3_dismissal_override(state, ids)
            + recipe_p3_relations(state, ids)
            + recipe_p3_memory(state, ids)
            + recipe_p3_brief(state, ids)
            + recipe_p3_baseline(state, ids)
            + recipe_p3_economics(state, ids)
            + recipe_p3_finish(state, ids)
            + recipe_closing(state, ids)
            + recipe_d19(state, ids)
            + recipe_p4_sft(state, ids)
            + recipe_p5_surface2(state, ids)
    )


def recipe_p0(state: dict, ids: dict) -> list[dict]:
    """The P0 half: verbatim golden v1 steps."""
    cid = ids['cid']
    return [
        {"name": "init", "exit": 0, "argv": ["init", "--program", "Golden"]},
        # ---- P0 half: verbatim golden v1 (docs/gates/P0-gate.md) ----------
        {"name": "status", "exit": 0, "argv": ["status", cid]},
        {
            "name": "snap",
            "exit": 0,
            "snapshot": 1,
            "argv": ["snap", cid, state["target"]],
        },
        {"name": "log", "exit": 0, "argv": ["log", cid]},
        {"name": "verify", "exit": 0, "argv": ["verify", cid]},
        {"name": "audit", "exit": 0, "argv": ["audit", cid]},
        {"name": "status2", "exit": 0, "argv": ["status", cid]},
        {"name": "audit-json", "exit": 0, "argv": ["audit", cid, "--json"]},

    ]


def recipe_p1_model(state: dict, ids: dict) -> list[dict]:
    """P1 opening: model load/show, plan, and scope."""
    cid = ids['cid']
    return [
        # ---- P1 half -----------------------------------------------------
        {"name": "model-load", "exit": 0, "argv": ["model", cid, f"{FIX}/model.json"]},
        {"name": "model-show", "exit": 0, "argv": ["model", cid]},
        {"name": "plan", "exit": 0, "argv": ["plan", cid]},
        # the bounty gate reads the policy, so scope must precede it
        {
            "name": "scope",
            "exit": 0,
            "argv": ["scope", cid, "--policy", f"{FIX}/policy.json"],
        },

    ]


def recipe_p1_ingest(state: dict, ids: dict) -> list[dict]:
    """P1 findings: the four ingestions and dedup."""
    cid = ids['cid']
    return [
        {
            "name": "ingest-h1",
            "exit": 0,
            "findings": 1,
            "argv": [
                "ingest",
                cid,
                "--json-file",
                f"{FIX}/h1-withdraw-double-count.json",
                "--stage",
                "golden",
                "--trajectory",
                "code",
            ],
        },
        {
            "name": "ingest-h2",
            "exit": 0,
            "findings": 1,
            "argv": [
                "ingest",
                cid,
                "--json-file",
                f"{FIX}/h2-deposit-double-mint.json",
                "--stage",
                "golden",
                "--trajectory",
                "code",
            ],
        },
        {
            "name": "ingest-h3",
            "exit": 0,
            "findings": 1,
            "argv": [
                "ingest",
                cid,
                "--json-file",
                f"{FIX}/h3-share-price-inflation.json",
                "--stage",
                "golden",
                "--trajectory",
                "economic",
            ],
        },
        {
            "name": "ingest-h4",
            "exit": 0,
            "findings": 1,
            "argv": [
                "ingest",
                cid,
                "--json-file",
                f"{FIX}/h4-oracle-spot-price.json",
                "--stage",
                "golden",
                "--trajectory",
                "code",
            ],
        },
        {"name": "dedup", "exit": 0, "argv": ["dedup", cid]},

    ]


def recipe_p1_resolve(state: dict, ids: dict) -> list[dict]:
    """P1 candidate resolution, prioritization, repro queue."""
    cid = ids['cid']
    f = ids['f']
    return [
        {
            "name": "resolve-same",
            "exit": 0,
            "argv": [
                "resolve-candidate",
                cid,
                f[1],
                f[0],
                "--verdict",
                "same",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "resolve-distinct",
            "exit": 0,
            "argv": [
                "resolve-candidate",
                cid,
                f[3],
                f[2],
                "--verdict",
                "distinct",
                "--actor",
                "golden",
            ],
        },
        {"name": "prioritize", "exit": 0, "argv": ["prioritize", cid]},
        {"name": "repro-queue", "exit": 0, "argv": ["repro-queue", cid]},

    ]


def recipe_p1_floors(state: dict, ids: dict) -> list[dict]:
    """P1 floors lifecycle, answered-priority, and plan pinning."""
    cid = ids['cid']
    f = ids['f']
    return [
        {
            "name": "floors-set",
            "exit": 0,
            "argv": [
                "floors",
                cid,
                "set",
                "logic-error",
                "E4",
                "--actor",
                "golden",
                "--reason",
                "the target ships a fork runner, so E4 is reachable",
            ],
        },
        {"name": "floors-list", "exit": 0, "argv": ["floors", cid]},
        {"name": "floors-json", "exit": 0, "argv": ["floors", cid, "--json"]},
        {
            "name": "floors-unset",
            "exit": 0,
            "argv": [
                "floors",
                cid,
                "unset",
                "logic-error",
                "--actor",
                "golden",
                "--reason",
                "back to the class default floor",
            ],
        },
        {
            "name": "answered-priority",
            "exit": 0,
            "argv": [
                "answered",
                cid,
                "Q-001",
                "answered",
                "--reason",
                "the drain-capable role is a single multisig, not reachable",
                "--ref",
                f[0],
                "--actor",
                "golden",
            ],
        },
        {"name": "plan-readonly", "exit": 0, "argv": ["plan", cid]},
        {"name": "plan-rebuild", "exit": 0, "argv": ["plan", cid, "--rebuild"]},

    ]


def recipe_p1_gate(state: dict, ids: dict) -> list[dict]:
    """P1 gating: verdicts, recalls, gate runs, prove/waive."""
    cid = ids['cid']
    f = ids['f']
    return [
        {
            "name": "verdict-h1",
            "exit": 0,
            "argv": [
                "verdict",
                cid,
                f[0],
                "--verdict",
                "confirmed",
                "--reason",
                "the double-count is a real accounting defect, code path is reachable",
            ],
        },
        {
            "name": "recall-h1",
            "exit": 0,
            "argv": ["recall", cid, "--finding", f[0], "--mode", "negative"],
        },
        {
            "name": "recall-h3",
            "exit": 0,
            "argv": [
                "recall",
                cid,
                "--finding",
                f[2],
                "--mode",
                "comparative",
                "--note",
                "analogous donation inflation seen in a prior share-vault campaign",
            ],
        },
        {"name": "gate-all", "exit": 0, "argv": ["gate", cid]},
        {"name": "gate-h1", "exit": 1, "argv": ["gate", cid, f[0]]},
        {"name": "gate-h3", "exit": 1, "argv": ["gate", cid, f[2]]},
        {
            "name": "gate-explain",
            "exit": 0,
            "argv": ["gate", "--explain", "evidence-floor"],
        },
        {"name": "prove-all", "exit": 0, "argv": ["prove", cid]},
        {
            "name": "prove-learning",
            "exit": 1,
            "argv": ["prove", cid, "--stage", "learning"],
        },
        {
            "name": "waive-learning",
            "exit": 0,
            "argv": [
                "waive",
                cid,
                "learning",
                "--reason",
                "the golden suite records the waiver path, not a real gap",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "prove-learning2",
            "exit": 0,
            "argv": ["prove", cid, "--stage", "learning"],
        },

    ]


def recipe_p1_artifact(state: dict, ids: dict) -> list[dict]:
    """P1 artifact registration and listing."""
    cid = ids['cid']
    return [
        {
            "name": "artifact-register",
            "exit": 0,
            "artifacts": 1,
            "argv": [
                "artifact-register",
                cid,
                f"{FIX}/artifact.md",
                "--kind",
                "report",
                "--note",
                "withdraw path check notes",
            ],
        },
        {"name": "artifact-list", "exit": 0, "argv": ["artifact-list", cid]},
        {
            "name": "artifact-list-kind",
            "exit": 0,
            "argv": ["artifact-list", cid, "--kind", "report"],
        },

    ]


def recipe_p1_h5(state: dict, ids: dict) -> list[dict]:
    """P1 h5: the finding ingested in a gate-passing state, moved to CONFIRMED."""
    cid = ids['cid']
    f = ids['f']
    return [
        # h5 is ingested in a state the CONFIRMED gate accepts: a
        # reproduced attempt plus an E7 evidence item bound to the artifact
        # registered above. Its `gate` dry-run therefore PASSES (exit 0) —
        # the counterweight to gate-h1/gate-h3 — and the two `move` steps
        # below walk the legal HYPOTHESIS -> POSSIBLE -> CONFIRMED path, so
        # the closing status/audit/verify steps see a genuinely CONFIRMED
        # finding.
        {
            "name": "ingest-h5",
            "exit": 0,
            "findings": 1,
            "render": "h5-gate-pass.json",
            "argv": [
                "ingest",
                cid,
                "--json-file",
                ".scratch/golden/payloads/h5-gate-pass.json",
                "--stage",
                "golden",
                "--trajectory",
                "code",
            ],
        },
        {
            "name": "verdict-h5",
            "exit": 0,
            "argv": [
                "verdict",
                cid,
                f[4],
                "--verdict",
                "confirmed",
                "--reason",
                "the rounding delta is a real payout defect on a reachable path",
            ],
        },
        {
            "name": "recall-h5",
            "exit": 0,
            "argv": ["recall", cid, "--finding", f[4], "--mode", "negative"],
        },
        {"name": "gate-h5-pass", "exit": 0, "argv": ["gate", cid, f[4]]},
        {
            "name": "move-h5-possible",
            "exit": 0,
            "argv": [
                "move",
                cid,
                f[4],
                "POSSIBLE",
                "--reason",
                "the golden suite advances the gated finding to POSSIBLE",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "move-h5-confirmed",
            "exit": 0,
            "argv": [
                "move",
                cid,
                f[4],
                "CONFIRMED",
                "--reason",
                "the golden suite closes the gated finding to CONFIRMED",
                "--actor",
                "golden",
            ],
        },

    ]


def recipe_p1_h6(state: dict, ids: dict) -> list[dict]:
    """P1 h6: the capability GRANT, moved to CONFIRMED."""
    cid = ids['cid']
    f = ids['f']
    return [
        # h6 GRANTS the pause capability and h7 REQUIRES it; both carry the
        # same gate-passing shape as h5 (reproduced attempt + E7 evidence
        # bound to the registered artifact), so both can be moved to
        # CONFIRMED and the chain engine materializes a CHAIN- link from
        # h6 to h7. That is what exercises the CHAIN-<8> id family.
        {
            "name": "ingest-h6",
            "exit": 0,
            "findings": 1,
            "render": "h6-grants-pause.json",
            "argv": [
                "ingest",
                cid,
                "--json-file",
                ".scratch/golden/payloads/h6-grants-pause.json",
                "--stage",
                "golden",
                "--trajectory",
                "code",
            ],
        },
        {
            "name": "verdict-h6",
            "exit": 0,
            "argv": [
                "verdict",
                cid,
                f[5],
                "--verdict",
                "confirmed",
                "--reason",
                "the operator handover is a real capability grant",
            ],
        },
        {
            "name": "recall-h6",
            "exit": 0,
            "argv": ["recall", cid, "--finding", f[5], "--mode", "negative"],
        },
        {"name": "gate-h6-pass", "exit": 0, "argv": ["gate", cid, f[5]]},
        {
            "name": "move-h6-possible",
            "exit": 0,
            "argv": [
                "move",
                cid,
                f[5],
                "POSSIBLE",
                "--reason",
                "the golden suite advances the granter to POSSIBLE",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "move-h6-confirmed",
            "exit": 0,
            "argv": [
                "move",
                cid,
                f[5],
                "CONFIRMED",
                "--reason",
                "the golden suite closes the granter to CONFIRMED",
                "--actor",
                "golden",
            ],
        },

    ]


def recipe_p1_h7(state: dict, ids: dict) -> list[dict]:
    """P1 h7: the capability REQUIRE, moved to CONFIRMED."""
    cid = ids['cid']
    f = ids['f']
    return [
        {
            "name": "ingest-h7",
            "exit": 0,
            "findings": 1,
            "render": "h7-requires-pause.json",
            "argv": [
                "ingest",
                cid,
                "--json-file",
                ".scratch/golden/payloads/h7-requires-pause.json",
                "--stage",
                "golden",
                "--trajectory",
                "code",
            ],
        },
        {
            "name": "verdict-h7",
            "exit": 0,
            "argv": [
                "verdict",
                cid,
                f[6],
                "--verdict",
                "confirmed",
                "--reason",
                "the freeze is a real denial of withdrawal",
            ],
        },
        {
            "name": "recall-h7",
            "exit": 0,
            "argv": ["recall", cid, "--finding", f[6], "--mode", "negative"],
        },
        {"name": "gate-h7-pass", "exit": 0, "argv": ["gate", cid, f[6]]},
        {
            "name": "move-h7-possible",
            "exit": 0,
            "argv": [
                "move",
                cid,
                f[6],
                "POSSIBLE",
                "--reason",
                "the golden suite advances the needer to POSSIBLE",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "move-h7-confirmed",
            "exit": 0,
            "argv": [
                "move",
                cid,
                f[6],
                "CONFIRMED",
                "--reason",
                "the golden suite closes the needer to CONFIRMED",
                "--actor",
                "golden",
            ],
        },

    ]


def recipe_p1_close(state: dict, ids: dict) -> list[dict]:
    """P1 closing: invariants, budget, hint, answered lens."""
    cid = ids['cid']
    f = ids['f']
    art = ids['art']
    return [
        {
            "name": "invariant-verify",
            "exit": 0,
            "argv": ["invariant-verify", cid, "INV-2", "--artifact", art[0]],
        },
        {
            "name": "invariant-contradict",
            "exit": 0,
            "argv": [
                "invariant-contradict",
                cid,
                "INV-3",
                "--evidence",
                "src/Other.sol#L1",
            ],
        },
        {
            "name": "budget-set",
            "exit": 0,
            "argv": ["budget", cid, "--set", "2500", "--actor", "golden"],
        },
        {"name": "budget-json", "exit": 0, "argv": ["budget", cid, "--json"]},
        {
            "name": "hint",
            "exit": 0,
            "argv": [
                "hint",
                cid,
                "--kind",
                "priority",
                "--content",
                "prefer the accounting path over the oracle path",
                "--source-ref",
                f[0],
                "--actor",
                "golden",
            ],
        },
        {
            "name": "answered-lens",
            "exit": 0,
            "argv": [
                "answered",
                cid,
                "L-01",
                "answered",
                "--reason",
                "no reachable permanently-stuck state in this state machine",
                "--families",
                "none-applicable",
                "--actor",
                "golden",
            ],
        },

    ]


def recipe_p2_exec(state: dict, ids: dict) -> list[dict]:
    """P2 exec ledger: dry-run, host run, failing run, views, classifier."""
    cid = ids['cid']
    f = ids['f']
    ex = ids['ex']
    return [
        {
            "name": "exec-dry",
            "exit": 0,
            "argv": [
                "exec",
        # ---- P2 half: the ported evidence-execution surface (golden v3) ---
        # exec ledger: the dry-run preview (no record), a real host-readonly
        # run (EXEC-<10>), a deliberately failing run, the three read views
        # and the failure classifier.
                cid,
                "--command",
                "forge test --match-test test_withdraw",
                "--profile",
                "docker-networkless",
                "--dry-run",
            ],
        },
        {
            "name": "exec-host",
            "exit": 0,
            "execs": 1,
            "argv": ["exec", cid, "--command", "echo golden-exec", "--finding", f[0]],
        },
        {
            "name": "exec-fail",
            "exit": 0,
            "execs": 1,
            "argv": ["exec", cid, "--command", "exit 7", "--finding", f[0]],
        },
        {"name": "execs", "exit": 0, "argv": ["execs", cid]},
        {"name": "execs-json", "exit": 0, "argv": ["execs", cid, "--json"]},
        {"name": "execs-id", "exit": 0, "argv": ["execs", cid, "--id", ex[0]]},
        {"name": "classify", "exit": 0, "argv": ["classify", cid, ex[1]]},

    ]


def recipe_p2_mint(state: dict, ids: dict) -> list[dict]:
    """P2 harness-seeded exec record and the mint path."""
    cid = ids['cid']
    f = ids['f']
    return [
        # An out-of-band E4 exec record (harness-seeded: the default suite
        # stays docker-free) and the mint path that records an ATT-<6>
        # attempt plus an EV-<8> evidence item on h1.
        {
            "name": "seed-exec-mint",
            "seed_exec": {
                "n": 0,
                "finding": 0,
                "command": "forge test --match-test test_withdraw",
            },
        },
        {
            "name": "mint",
            "exit": 0,
            "argv": [
                "mint",
                cid,
                f[0],
                "--exec",
                seeded_exec_id(0),
                "--description",
                "unit PoC drains the vault in one withdraw",
                "--tier",
                "T2",
                "--type",
                "foundry-test",
            ],
        },

    ]


def recipe_p2_ladder_start(state: dict, ids: dict) -> list[dict]:
    """P2 variant ladder: start, show, first rung."""
    cid = ids['cid']
    f = ids['f']
    return [
        # the full variant ladder lifecycle on the CONFIRMED h5: start ->
        # add_variant -> the five axes -> reproduce_rung (a seeded E4 record)
        # -> set_maximal -> complete -> report.
        {"name": "ladder-start", "exit": 0, "argv": ["ladder", cid, "start", f[4]]},
        {"name": "ladder-show", "exit": 0, "argv": ["ladder", cid, "show", f[4]]},
        {
            "name": "ladder-add",
            "exit": 0,
            "rungs": 1,
            "argv": [
                "ladder",
                cid,
                "add",
                f[4],
                "--name",
                "dust",
                "--description",
                "dust the pool with one wei",
                "--axes",
                "capital-minimization",
                "--capital",
                "1",
                "--ratio",
                "1",
                "--removes",
                "victim stakes",
            ],
        },

    ]


def recipe_p2_ladder_explore(state: dict, ids: dict) -> list[dict]:
    """P2 variant ladder: the four explore axes."""
    cid = ids['cid']
    f = ids['f']
    return [
        {
            "name": "ladder-explore-cap-saturation",
            "exit": 0,
            "argv": [
                "ladder",
                cid,
                "explore",
                f[4],
                "-",
                "cap-saturation",
                "--note",
                "considered, not applicable here",
            ],
        },
        {
            "name": "ladder-explore-precondition-removal",
            "exit": 0,
            "argv": [
                "ladder",
                cid,
                "explore",
                f[4],
                "-",
                "precondition-removal",
                "--note",
                "considered, not applicable here",
            ],
        },
        {
            "name": "ladder-explore-role-conflation",
            "exit": 0,
            "argv": [
                "ladder",
                cid,
                "explore",
                f[4],
                "-",
                "role-conflation",
                "--note",
                "considered, not applicable here",
            ],
        },

    ]


def recipe_p2_ladder_repro(state: dict, ids: dict) -> list[dict]:
    """P2 variant ladder: last explore, seeded repro."""
    cid = ids['cid']
    f = ids['f']
    rung = ids['rung']
    return [
        {
            "name": "ladder-explore-ordering-permutation",
            "exit": 0,
            "argv": [
                "ladder",
                cid,
                "explore",
                f[4],
                "-",
                "ordering-permutation",
                "--note",
                "considered, not applicable here",
            ],
        },
        {
            "name": "seed-exec-ladder",
            "seed_exec": {
                "n": 1,
                "finding": 4,
                "command": "forge test --match-test test_preview_redeem",
            },
        },
        {
            "name": "ladder-repro",
            "exit": 0,
            "argv": [
                "ladder",
                cid,
                "repro",
                f[4],
                rung[0],
                "--exec",
                seeded_exec_id(1),
            ],
        },

    ]


def recipe_p2_ladder_disprove(state: dict, ids: dict) -> list[dict]:
    """P2 variant ladder: both disprove GUARD branches, set-maximal, complete, report."""
    cid = ids['cid']
    f = ids['f']
    rung = ids['rung']
    return [
        # disprove: only the two GUARD branches are byte-comparable. The
        # happy path queues negative memory, which the reference writes as a
        # campaigns/<cid>/memory/MEM-*.json row PLUS a memory.queued event —
        # the learning seam is a no-op (KNOWN_DIVERGENCES D18), so
        # exercising it would fork the event chain. Both guards below abort
        # before any write, so they compare byte-for-byte.
        {
            "name": "ladder-disprove-short-reason",
            "exit": 2,
            "argv": ["ladder", cid, "disprove", f[4], rung[0], "--reason", "nope"],
        },
        {
            "name": "ladder-set-maximal",
            "exit": 0,
            "argv": ["ladder", cid, "set-maximal", f[4], rung[0]],
        },
        {
            "name": "ladder-disprove-reproduced",
            "exit": 2,
            "argv": [
                "ladder",
                cid,
                "disprove",
                f[4],
                rung[0],
                "--reason",
                "the corrected claim did not survive review",
            ],
        },
        {
            "name": "ladder-complete",
            "exit": 0,
            "argv": ["ladder", cid, "complete", f[4]],
        },
        {"name": "ladder-report", "exit": 0, "argv": ["ladder", cid, "report", f[4]]},

    ]


def recipe_p2_chains(state: dict, ids: dict) -> list[dict]:
    """P2 capability graph, terminals, privileged, sequence coverage."""
    cid = ids['cid']
    f = ids['f']
    return [
        # capability graph: h6 grants the pause capability h7 requires, so
        # the chain engine links them and proposes the pair. NOTE: `chains`
        # computes and REPORTS; it materializes nothing, and the reference
        # has no CLI verb for `materialize_chain`, so no CHAIN-<8> file
        # exists in either tree (the CHAIN- id stream is pinned by
        # construction and covered by the chainengine unit tests).
        {"name": "chains", "exit": 0, "argv": ["chains", cid]},
        {"name": "terminals", "exit": 0, "argv": ["terminals", cid]},
        {"name": "privileged", "exit": 0, "argv": ["privileged", cid]},
        # sequence coverage: the golden has no anvil/fork, so `run` is out of
        # reach (scripts/p2-docker-e2e.sh runs it for real). `verify` is a
        # pure state read and must agree byte-for-byte on the vacuous
        # verdict — the h5 ladder finding declares no multi-step
        # exploit_sequence, so coverage is "not sequence-required".
        {
            "name": "sequence-verify",
            "exit": 0,
            "argv": ["sequence", "verify", cid, f[4]],
        },

    ]


def recipe_p2_impact(state: dict, ids: dict) -> list[dict]:
    """P2 impact: priced, priced+artifact, UNPRICEABLE, incomplete refusal."""
    cid = ids['cid']
    f = ids['f']
    return [
        # impact: priced, priced + E7 artifact mint, the UNPRICEABLE named
        # decision, and the documented exit-2 refusal of an incomplete one.
        {
            "name": "impact-priced",
            "exit": 0,
            "argv": [
                "impact",
                cid,
                f[0],
                "--extractable",
                "1000",
                "--max-loss",
                "5000",
                "--required-capital",
                "100",
            ],
        },
        {
            "name": "impact-artifact",
            "exit": 0,
            "argv": [
                "impact",
                cid,
                f[0],
                "--extractable",
                "1000",
                "--artifact",
                f"{FIX}/artifact.md",
                "--description",
                "the priced impact carried by the report",
            ],
        },
        {
            "name": "impact-unpriceable",
            "exit": 0,
            "argv": [
                "impact",
                cid,
                f[2],
                "--unpriceable",
                "--ceiling",
                "no defensible USD figure",
                "--reason",
                "the affected asset has no observable market",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "impact-unpriceable-incomplete",
            "exit": 2,
            "argv": [
                "impact",
                cid,
                f[2],
                "--unpriceable",
                "--ceiling",
                "no defensible USD figure",
            ],
        },

    ]


def recipe_p3_index(state: dict, ids: dict) -> list[dict]:
    """P3 structural surface: index, sinks, prescreen over the snapshot."""
    cid = ids['cid']
    snap_src = ids['snap_src']
    return [
        # ---- P3 half (golden v4, docs/gates/golden-v4.md) ----------------
        # Structural surface: index / sinks / prescreen over the target's
        # real Solidity (src/ + the probes/ fixture trees make_target
        # materializes).
        {"name": "index", "exit": 0, "argv": ["index", cid, "--src", snap_src]},
        {
            "name": "index-json",
            "exit": 0,
            "argv": ["index", cid, "--src", snap_src, "--json"],
        },
        {"name": "sinks", "exit": 0, "argv": ["sinks", cid, "--src", snap_src]},
        {
            "name": "sinks-json",
            "exit": 0,
            "argv": ["sinks", cid, "--src", snap_src, "--json"],
        },
        {"name": "prescreen", "exit": 0, "argv": ["prescreen", cid, "--src", snap_src]},
        {
            "name": "prescreen-json",
            "exit": 0,
            "argv": ["prescreen", cid, "--src", snap_src, "--json"],
        },

    ]


def recipe_p3_probes(state: dict, ids: dict) -> list[dict]:
    """P3 probe surface: run, list views, blank attestation, --emit."""
    cid = ids['cid']
    blind = ids['blind']
    return [
        # Mechanical candidate surface: run (rows + published BLIND keys),
        # the operator view (all / one axis / json), the named blank
        # attestation that closes a BLIND axis, and --emit (plan
        # obligations, idempotent on the second run).
        {"name": "probes-run", "exit": 0, "argv": ["probes", cid, "run"]},
        {
            "name": "probes-list-all",
            "exit": 0,
            "argv": ["probes", cid, "list", "--all"],
        },
        {
            "name": "probes-list-all-json",
            "exit": 0,
            "blind": 1,
            "argv": ["probes", cid, "list", "--all", "--json"],
        },
        {"name": "probes-list", "exit": 0, "argv": ["probes", cid, "list"]},
        {
            "name": "probes-list-axis",
            "exit": 0,
            "argv": ["probes", cid, "list", "--axis", blind[0]],
        },
        {
            "name": "probes-list-axis-json",
            "exit": 0,
            "argv": ["probes", cid, "list", "--axis", blind[0], "--json"],
        },
        {
            "name": "probes-blank",
            "exit": 0,
            "argv": [
                "probes",
                cid,
                "blank",
                "--axis",
                blind[0],
                "--anchor-blind",
                blind[1],
                "--reason",
                "the cited key is the only write on this axis",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "probes-list-after-blank",
            "exit": 0,
            "argv": ["probes", cid, "list", "--all"],
        },
        {
            "name": "probes-run-emit",
            "exit": 0,
            "argv": ["probes", cid, "run", "--emit"],
        },
        {
            "name": "probes-run-emit-again",
            "exit": 0,
            "argv": ["probes", cid, "run", "--emit"],
        },
        {"name": "plan-after-emit", "exit": 0, "argv": ["plan", cid]},

    ]


def recipe_p3_dismissal(state: dict, ids: dict) -> list[dict]:
    """P3 B4/D1 disposition gate: the structural closure pair."""
    cid = ids['cid']
    dr = ids['dr']
    dr2 = ids['dr2']
    drsym = ids['drsym']
    return [
        {
            "name": "probes-highrisk-json",
            "exit": 0,
            "dr": 1,
        # ---- B4/D1: the disposition gate, end to end --------------------
        # The G-01 miss: a tier-0 row at rank 1 discharged `answered` (safe)
        # on free prose, accepted because a row is "an obligation to look, not
        # a claim". These four steps pin the answer to it: the same closure
        # with dismissal vocabulary is REFUSED, the override needs its own
        # reason, the terminal spelling works and ANNOUNCES itself, and the
        # report keeps the decision visible (asserted below as markers, and
        # the override event is pinned by the event chain).
            "argv": ["probes", cid, "list", "--json"],
        },
        # v3, the structural layer. v2 catches the WORDS a dismissal uses; a
        # reason written to dodge that table is still not a disposition. The
        # first step refuses prose that names nothing a reader can open (and
        # says which symbols it would have accepted); the second closes the
        # OTHER tier-0 row by naming its own code — the rule has to be
        # satisfiable, or it is just a wall.
        {
            "name": "answered-structural-refused",
            "exit": 2,
            "err": [
                "names nothing from the row's own surface entry",
                "quote the code the row is about",
                "override explicitly",
            ],
            "argv": [
                "answered",
                cid,
                dr,
                "answered",
                "--reason",
                "the flow looked fine when I traced it by hand",
                "--anchor",
                "custody",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "answered-structural-accepted",
            "exit": 0,
            "out": [dr2 + ": status -> answered"],
            "argv": [
                "answered",
                cid,
                dr2,
                "answered",
                "--reason",
                drsym + " pays out along the same path it asserts",
                "--anchor",
                "custody",
                "--actor",
                "golden",
            ],
        },

    ]


def recipe_p3_dismissal_override(state: dict, ids: dict) -> list[dict]:
    """P3 B4/D1 disposition gate: dismissal refusal and the reasoned override."""
    cid = ids['cid']
    dr = ids['dr']
    return [
        {
            "name": "answered-dismissal-refused",
            "exit": 2,
            "err": [
                "the closure reason uses dismissal vocabulary",
                "on a high-risk row",
                "refutation that runs",
            ],
            "argv": [
                "answered",
                cid,
                dr,
                "answered",
                "--reason",
                "liveness-only: the owner can revert, no economic impact",
                "--anchor",
                "custody",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "answered-dismissal-override-unreasoned",
            "exit": 2,
            "err": ["--override-dismissal needs --override-reason"],
            "argv": [
                "answered",
                cid,
                dr,
                "answered",
                "--reason",
                "liveness-only: the owner can revert, no economic impact",
                "--anchor",
                "custody",
                "--override-dismissal",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "answered-dismissal-overridden",
            "exit": 0,
            "out": [
                "dismissal overridden: "
                + dr
                + " logged as probe.dismissal_overridden (actor golden)"
            ],
            "argv": [
                "answered",
                cid,
                dr,
                "answered",
                "--reason",
                "liveness-only: the owner can revert, no economic impact",
                "--anchor",
                "custody",
                "--override-dismissal",
                "--override-reason",
                "the operator accepts the risk in writing for this run",
                "--actor",
                "golden",
            ],
        },

    ]


def recipe_p3_relations(state: dict, ids: dict) -> list[dict]:
    """P3 relations, resemble, corpus sweep."""
    cid = ids['cid']
    f = ids['f']
    return [
        # Research memory graph (typed edges) + the derived capability delta.
        {
            "name": "relations-rebuild",
            "exit": 0,
            "argv": ["relations", cid, "--rebuild"],
        },
        {"name": "relations-view", "exit": 0, "argv": ["relations", cid]},
        {"name": "resemble", "exit": 0, "argv": ["resemble", cid, f[0]]},
        # Corpus sweep. Runs with an ABSENT eval + PoC store
        # (WEBV2_EVAL_DIR / WEBV2_POC_ROOT, see D26): the eval store and the
        # DeFiHackLabs dataset are unported (P4), and an absent corpus root
        # is the module's documented legitimate input state. The step still
        # pins the class-probe layer, the exposure ordering and the report
        # artifact byte-for-byte.
        {"name": "corpus-surface", "exit": 0, "argv": ["corpus-surface", cid]},

    ]


def recipe_p3_memory(state: dict, ids: dict) -> list[dict]:
    """P3 negative memory: disprove, queue, approve, publish, globalize, shared."""
    cid = ids['cid']
    f = ids['f']
    rung = ids['rung']
    mem = ids['mem']
    return [
        # Negative knowledge -> memory queue -> human approval -> publish to
        # the shared store -> globalize -> both-tier view. A fresh rung on
        # the CONFIRMED h7 is disproved (its ladder is untouched by P2), so
        # learning.queue_memory writes the MEM- row the rest of the block
        # consumes.
        {"name": "ladder-start-h7", "exit": 0, "argv": ["ladder", cid, "start", f[6]]},
        {
            "name": "ladder-add-h7",
            "exit": 0,
            "rungs": 1,
            "argv": [
                "ladder",
                cid,
                "add",
                f[6],
                "--name",
                "p3-dead-end",
                "--description",
                "drain the vault in one transaction",
                "--axes",
                "precondition-removal",
                "--capital",
                "1",
                "--ratio",
                "1",
                "--removes",
                "the timelock",
            ],
        },
        {
            "name": "ladder-disprove-h7",
            "exit": 0,
            "argv": [
                "ladder",
                cid,
                "disprove",
                f[6],
                rung[1],
                "--reason",
                "the removed timelock precondition is enforced by the "
                "guard the rung cannot bypass",
            ],
        },
        {"name": "memory-list", "exit": 0, "memory": 1, "argv": ["memory", cid]},
        {
            "name": "memory-approve",
            "exit": 0,
            "argv": ["memory", cid, "--approve", mem[0], "--by", "golden"],
        },
        {"name": "memory-list-after", "exit": 0, "argv": ["memory", cid]},
        {"name": "publish", "exit": 0, "argv": ["publish", cid, "--actor", "golden"]},
        {
            "name": "globalize-root",
            "exit": 0,
            "argv": ["globalize", "--actor", "golden", "--tier", "root"],
        },
        {"name": "shared", "exit": 0, "argv": ["shared"]},
        {"name": "shared-verify", "exit": 0, "argv": ["shared", "--verify"]},

    ]


def recipe_p3_brief(state: dict, ids: dict) -> list[dict]:
    """P3 operator cockpit: brief, report, recency."""
    cid = ids['cid']
    snap_src = ids['snap_src']
    return [
        # Operator cockpit + report + recency.
        {"name": "brief", "exit": 0, "argv": ["brief", cid]},
        {"name": "brief-json", "exit": 0, "argv": ["brief", cid, "--json"]},
        {"name": "brief-deep", "exit": 0, "argv": ["brief", cid, "--deep"]},
        {"name": "report", "exit": 0, "argv": ["report", cid]},
        {
            "name": "recency",
            "exit": 0,
            "argv": ["recency", cid, "--target", state["target"], "--src", snap_src],
        },
        {
            "name": "recency-json",
            "exit": 0,
            "argv": [
                "recency",
                cid,
                "--target",
                state["target"],
                "--src",
                snap_src,
                "--json",
            ],
        },

    ]


def recipe_p3_baseline(state: dict, ids: dict) -> list[dict]:
    """P3 baseline store lifecycle and forkdiff."""
    cid = ids['cid']
    snap_src = ids['snap_src']
    return [
        # Baseline store: full lifecycle against ONE scratch store pinned by
        # WEBV2_BASELINES_DIR (D24: the reference hangs the store off its
        # own package root off cwd; the harness points it at
        # .scratch/golden/baselines and resets it per run). list (empty) ->
        # forkdiff (no baselines) -> add the target as a baseline -> list ->
        # forkdiff (score 1.00 against itself) -> remove -> list (empty).
        {"name": "baseline-list-empty", "exit": 0, "argv": ["baseline", "list"]},
        {
            "name": "forkdiff-no-baselines",
            "exit": 0,
            "argv": ["forkdiff", cid, "--src", snap_src],
        },
        {
            "name": "forkdiff-no-baselines-json",
            "exit": 0,
            "argv": ["forkdiff", cid, "--src", snap_src, "--json"],
        },
        {
            "name": "baseline-add",
            "exit": 0,
            "argv": [
                "baseline",
                "add",
                "golden-baseline",
                "--path",
                state["target"],
                "--source-url",
                "https://example.invalid/golden",
                "--license",
                "MIT",
            ],
        },
        {"name": "baseline-list", "exit": 0, "argv": ["baseline", "list"]},
        {"name": "forkdiff", "exit": 0, "argv": ["forkdiff", cid, "--src", snap_src]},
        {
            "name": "forkdiff-json",
            "exit": 0,
            "argv": ["forkdiff", cid, "--src", snap_src, "--json"],
        },
        {
            "name": "baseline-remove",
            "exit": 0,
            "argv": ["baseline", "remove", "golden-baseline"],
        },
        {"name": "baseline-list-after", "exit": 0, "argv": ["baseline", "list"]},

    ]


def recipe_p3_economics(state: dict, ids: dict) -> list[dict]:
    """P3 economics: costs, yields, price table, price basis."""
    cid = ids['cid']
    f = ids['f']
    prc = ids['prc']
    return [
        # Economics: operator-reported costs, yield, the price table and the
        # price-basis pin.
        {
            "name": "cost-model",
            "exit": 0,
            "argv": [
                "cost",
                cid,
                "--kind",
                "model",
                "--amount",
                "12.5",
                "--trajectory",
                "code",
                "--actor",
                "golden",
            ],
        },
        {
            "name": "cost-human",
            "exit": 0,
            "argv": [
                "cost",
                cid,
                "--kind",
                "human-review",
                "--amount",
                "40",
                "--finding",
                f[0],
                "--actor",
                "golden",
            ],
        },
        {"name": "yields", "exit": 0, "argv": ["yields", cid]},
        {
            "name": "price-set",
            "exit": 0,
            "price": 1,
            "argv": [
                "price",
                cid,
                "set",
                "ETH",
                "3000",
                "--source",
                "coingecko",
                "--as-of",
                "2026-09-08T00:00:00+00:00",
                "--actor",
                "golden",
            ],
        },
        {"name": "price-table", "exit": 0, "argv": ["price", cid, "table"]},
        {"name": "price-basis", "exit": 0, "argv": ["price-basis", cid, f[0], prc[0]]},

    ]


def recipe_p3_finish(state: dict, ids: dict) -> list[dict]:
    """P3 env/doctor, the run halt, and campaign completion."""
    cid = ids['cid']
    return [
        # Environment + health, then the pipeline walk. `doctor --json`
        # reports campaign_state.json's byte size, which embeds the model
        # stage's prompt path (D25: the Go embed mirror adds an `assets/`
        # segment), so it must run BEFORE `run` records that note.
        {"name": "env-doctor", "exit": 1, "argv": ["env", "doctor"]},
        {"name": "env-doctor-json", "exit": 0, "argv": ["env", "doctor", "--json"]},
        {"name": "doctor", "exit": 0, "argv": ["doctor", cid]},
        {"name": "doctor-json", "exit": 0, "argv": ["doctor", cid, "--json"]},
        # `run` halts at the first model stage (exit 3, "needs-model"); the
        # printed prompt path differs by D25 and is normalized by
        # check-golden.py.
        {"name": "run", "exit": 3, "argv": ["run", cid]},
        {
            "name": "complete-short-reason",
            "exit": 2,
            "argv": ["complete", cid, "--actor", "golden", "--reason", "nope"],
        },
        {
            "name": "complete",
            "exit": 0,
            "argv": [
                "complete",
                cid,
                "--actor",
                "golden",
                "--reason",
                "all golden passes closed with evidence",
            ],
        },

    ]


def recipe_closing(state: dict, ids: dict) -> list[dict]:
    """Closing P0 verbs, now over the P1 state."""
    cid = ids['cid']
    return [
        # ---- closing half: same P0 verbs again, now over the P1 state ----
        {"name": "status-final", "exit": 0, "argv": ["status", cid]},
        {"name": "audit-final", "exit": 0, "argv": ["audit", cid]},
        {"name": "audit-json-final", "exit": 0, "argv": ["audit", cid, "--json"]},
        {"name": "log-tail", "exit": 0, "argv": ["log", cid, "--tail", "5"]},
        {"name": "verify-final", "exit": 0, "argv": ["verify", cid]},

    ]


def recipe_d19(state: dict, ids: dict) -> list[dict]:
    """D19: a second campaign with deployment/chain pins."""
    cid2 = ids['cid2']
    return [
        {
            "name": "init-c2",
            "exit": 0,
            "cid2": 1,
            "argv": ["init", "--program", "Golden Two"],
        },
        {
            "name": "snap-c2-deployment-chain",
            "exit": 0,
            "argv": [
                "snap",
        # ---- D19 golden coverage: a SECOND campaign ---------------------
        # `snap --deployment/--chain` attaches both pins at snap time. Kept
        # last on purpose: a fork-pinned snapshot changes the plan's
        # reachability lines and the sequence-coverage verdict, which would
        # rewrite campaign 1's already-compared P1/P2 outputs. The two
        # summary lines, the manifest roots (deployment_merkle_root /
        # chain_fingerprint), the pin members and the two
        # snapshot.*_attached events are all byte-compared here.
                cid2,
                state["target"],
                "--deployment",
                f"{FIX}/deployment.json",
                "--chain",
                f"{FIX}/chain.json",
            ],
        },
        {"name": "status-c2", "exit": 0, "argv": ["status", cid2]},
        {"name": "audit-c2", "exit": 0, "argv": ["audit", cid2]},
        {"name": "verify-c2", "exit": 0, "argv": ["verify", cid2]},

    ]


def recipe_p4_sft(state: dict, ids: dict) -> list[dict]:
    """P4 sft verb group over the committed fixture store."""
    cid = ids['cid']
    f = ids['f']
    return [
        # ---- P4 golden coverage (v5, T38) --------------------------------
        # The sft verb group over the committed fixture store (WEBV2_SFT_STORE
        # -> <root>/sft-store/examples.json, a per-twin copy). The store
        # carries the reference's 2 curated examples + 2 constructed drafts;
        # `split` writes it back, so the post-split bytes are a tree file
        # (root/sft-store/) compared byte-for-byte. Lint is run on FILES: the
        # curated PASS, the hard dedup refusal, and the rubric refusal (the
        # refusal text is golden-pinned, exit 1). Kept last: sft touches no
        # campaign artifact, but a store write must not sit between two
        # steps that read the store.
        {"name": "sft-list", "exit": 0, "argv": ["sft", "list"]},
        {
            "name": "sft-list-curated",
            "exit": 0,
            "argv": ["sft", "list", "--status", "curated"],
        },
        {
            "name": "sft-list-draft",
            "exit": 0,
            "argv": ["sft", "list", "--status", "draft"],
        },
        {
            "name": "sft-lint-pass",
            "exit": 0,
            "argv": ["sft", "lint", f"{P4_SFT}/lint-pass.json"],
        },
        {
            "name": "sft-lint-dedup",
            "exit": 1,
            "argv": ["sft", "lint", f"{P4_SFT}/lint-dedup.json"],
        },
        {
            "name": "sft-lint-reject",
            "exit": 1,
            "argv": ["sft", "lint", f"{P4_SFT}/lint-reject.json"],
        },
        {"name": "sft-split", "exit": 0, "argv": ["sft", "split", "--seed", "42"]},
        {"name": "sft-list-split", "exit": 0, "argv": ["sft", "list"]},
        {
            "name": "sft-list-training",
            "exit": 0,
            "argv": ["sft", "list", "--partition", "training"],
        },
        {"name": "sft-report", "exit": 0, "argv": ["sft", "report"]},
        {"name": "sft-export", "exit": 0, "argv": ["sft", "export"]},
        {
            "name": "sft-export-training",
            "exit": 0,
            "argv": ["sft", "export", "--partition", "training"],
        },
        {"name": "sft-backfill", "exit": 0, "argv": ["sft", "backfill", cid, f[0]]},

    ]


def recipe_p5_surface2(state: dict, ids: dict) -> list[dict]:
    """P5 (G16): the second probe-surface campaign."""
    cid3 = ids['cid3']
    snap2 = ids['snap2']
    return [
        {
            "name": "init-s2",
            "exit": 0,
            "cid3": 1,
            "argv": ["init", "--program", "Surface Two"],
        },
        {
            "name": "snap-s2",
            "exit": 0,
            "snapshot2": 1,
        # ---- P5 golden coverage (G16, T19): the second probe surface -----
        # A THIRD campaign over the fixtures-surface target (make_surface2_
        # target): the same surface-producing spine the first campaign uses
        # up to probe+audit (init / snap / model / index / probes run /
        # plan / probes run --emit / list --all --json / audit / audit
        # --json / verify), only pointed at the new target dir. The fixture
        # set is chosen so EVERY registered axis emits >=1 row (the buggy
        # families for the four row-axes of campaign 1, the leaky Own/
        # Consumer pair for enforcement-timing, accumulator/buggy for
        # accumulator-skew, FIX/model.json for incentive-inversion) — and
        # the `surface2` step below fails the run loudly if any axis ever
        # drops to zero rows. Kept last: a new campaign touches no existing
        # artifact, and its steps append after every P0-P4 index, so no
        # existing capture moves.
            "argv": ["snap", cid3, state["target2"]],
        },
        {"name": "model-s2", "exit": 0, "argv": ["model", cid3, f"{FIX}/model.json"]},
        {"name": "index-s2", "exit": 0, "argv": ["index", cid3, "--src", snap2]},
        {"name": "probes-run-s2", "exit": 0, "argv": ["probes", cid3, "run"]},
        {"name": "plan-s2", "exit": 0, "argv": ["plan", cid3]},
        {
            "name": "probes-run-emit-s2",
            "exit": 0,
            "argv": ["probes", cid3, "run", "--emit"],
        },
        {
            "name": "probes-list-all-json-s2",
            "exit": 0,
            "surface2": 1,
            "argv": ["probes", cid3, "list", "--all", "--json"],
        },
        {"name": "audit-s2", "exit": 0, "argv": ["audit", cid3]},
        {"name": "audit-json-s2", "exit": 0, "argv": ["audit", cid3, "--json"]},
        {"name": "verify-s2", "exit": 0, "argv": ["verify", cid3]},

    ]




FID_RE = re.compile(r"ingested (F-[0-9a-f]+)")
ART_RE = re.compile(r"^([A-Z]{3}-[0-9a-f]+):", re.M)
EXEC_RE = re.compile(r"(EXEC-[0-9a-f]+)")
RUNG_RE = re.compile(r"rung (R-[0-9a-z]+) recorded")


def check_surface2(
    twin: str, step: int, name: str, out: str, root: Path, cid3: str
) -> None:
    """The G16 rot gate: every registered axis carries >=1 row, and the
    surface artifact carries every required key of probe_surface.schema.json.

    This is the in-process half of the gate (it fails the RUN, not just the
    checker): if a detector, the index, or the assembly stops producing rows
    for an axis on the all-buggy corpus, golden-run.py exits loudly naming
    the dark axis. The schema half is a stdlib-only required-keys check that
    mirrors check-golden.py's spot checks — it reads the schema's own
    `required` arrays, so the gate tracks the schema without a dependency."""
    try:
        doc = json.loads(out)
    except ValueError as exc:
        sys.exit(f"{twin} step {step:02d}-{name}: not JSON: {exc}")
    axes = doc.get("axes")
    if not isinstance(axes, list):
        sys.exit(
            f"{twin} step {step:02d}-{name}: no axes list in the surface:\n{out[:400]}"
        )
    by_name = {
        a["axis"]: a
        for a in axes
        if isinstance(a, dict) and isinstance(a.get("axis"), str)
    }
    for axis in SURFACE2_AXES:
        a = by_name.get(axis)
        if a is None:
            sys.exit(
                f"{twin} step {step:02d}-{name}: SURFACE2 ROT — axis "
                f"{axis!r} missing from the surface (registration or "
                f"wiring drift); every probe axis must carry >=1 row"
            )
        sites = a.get("sites")
        rows = a.get("rows")
        if not isinstance(sites, int) or sites < 1:
            sys.exit(
                f"{twin} step {step:02d}-{name}: SURFACE2 ROT — axis "
                f"{axis!r} reports sites={sites!r}: the detector saw no "
                f"code at all"
            )
        if not isinstance(rows, int) or rows < 1:
            sys.exit(
                f"{twin} step {step:02d}-{name}: SURFACE2 ROT — axis "
                f"{axis!r} emitted rows={rows!r} (status="
                f"{a.get('status')!r}): an axis went dark and nothing "
                f"else in the suite would notice"
            )
    # Schema half: the artifact probe_surface.json must carry every required
    # key of assets/schema/probe_surface.schema.json (top object, axes
    # items, rows items, missing items, stats).
    art = root / "campaigns" / cid3 / "artifacts" / "probe_surface.json"
    if not art.is_file():
        sys.exit(
            f"{twin} step {step:02d}-{name}: SURFACE2 ROT — surface "
            f"artifact missing: {art}"
        )
    try:
        surface = json.loads(art.read_text())
    except ValueError as exc:
        sys.exit(f"{twin} step {step:02d}-{name}: surface artifact not JSON: {exc}")
    schema = json.loads(
        (GO_ROOT / "assets" / "schema" / "probe_surface.schema.json").read_text()
    )
    missing_keys: list[str] = []

    def require(obj: object, required: list, where: str) -> None:
        if not isinstance(obj, dict):
            missing_keys.append(f"{where}: not an object")
            return
        for k in required:
            if k not in obj:
                missing_keys.append(f"{where}: required key {k!r} absent")

    require(surface, schema.get("required", []), "surface")
    props = schema.get("properties", {})
    for section, key in (("axes", "axis"), ("rows", "row_id"), ("missing", "axis")):
        item_schema = props.get(section, {}).get("items", {})
        items = surface.get(section)
        if not isinstance(items, list):
            missing_keys.append(f"surface.{section}: not a list")
            continue
        for n, item in enumerate(items):
            require(item, item_schema.get("required", []), f"surface.{section}[{n}]")
    require(
        surface.get("stats"),
        props.get("stats", {}).get("required", []),
        "surface.stats",
    )
    if missing_keys:
        sys.exit(
            f"{twin} step {step:02d}-{name}: SURFACE2 ROT — surface "
            f"artifact fails the probe_surface schema required-keys "
            f"check:\n  " + "\n  ".join(missing_keys)
        )
    n_rows = len(surface.get("rows", []))
    print(
        f"[surface2] {len(SURFACE2_AXES)} axes carry rows "
        f"(total {n_rows} emitted), schema required-keys ok"
    )


def main_run_twin(twin: str, root: Path, target: Path, target2: Path,
                  acc: dict) -> None:
    """One twin's capture pass: fresh root, seeded stores, every step,
    archived tree."""
    roots = acc["roots"]
    trees = acc["trees"]
    captures = acc["captures"]
    declared = acc["declared"]
    states = acc["states"]
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    # The baseline store is pinned (WEBV2_BASELINES_DIR) at ONE scratch
    # path so both twins print the same store path; reset it per twin
    # so each starts from the same empty store.
    shutil.rmtree(WORK / "baselines", ignore_errors=True)
    # Golden v5 (T38): the per-twin sft store is a copy of the fixture
    # inside the run root, so `sft split` mutates a throwaway file and
    # the bytes after the split are archived + compared with the
    # campaign tree. The shared-memory store is reset to the fixture's
    # 20 published prior rows per twin, so publish/globalize/shared see
    # the same starting store in both twins (previously the Go run saw
    # the Python run's leftovers).
    sft_store = root / "sft-store" / "examples.json"
    sft_store.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(GO_ROOT / P4_SFT / "examples.json", sft_store)
    shutil.rmtree(WORK / "shared-memory", ignore_errors=True)
    shutil.copytree(GO_ROOT / P4_FIX / "shared-memory", WORK / "shared-memory")
    roots[twin] = str(root)
    caps = WORK / "captures" / twin
    caps.mkdir(parents=True)
    captures[twin] = []
    declared[twin] = []
    state = {
        "cid": "",
        "findings": [],
        "artifacts": [],
        "execs": [],
        "rungs": [],
        "target": str(target),
        "snapshot": "",
        "cid2": "",
        "blind": [],
        "mem": [],
        "prc": [],
        "dr": "",
        "dr2": "",
        "drsym": "",
    }
    # P5 (G16): the second surface campaign's target + ids. Appended
    # keys only — every P0-P4 placeholder above resolves exactly as
    # before, so no existing capture moves.
    state["target2"] = str(target2)
    state["snap2"] = ""
    state["cid3"] = ""
    states[twin] = state
    main_run_steps(twin, root, sft_store, caps, state, acc)
    archived = WORK / f"tree-{twin}"
    shutil.rmtree(archived, ignore_errors=True)
    shutil.move(str(root), str(archived))
    trees[twin] = str(archived)


def main_run_steps(twin: str, root: Path, sft_store: Path, caps: Path,
                   state: dict, acc: dict) -> None:
    """Rebuild the recipe per step, run it, capture it, and harvest the
    ids it minted."""
    captures = acc["captures"]
    declared = acc["declared"]
    # The step LIST is state-independent, but each step's argv embeds ids
    # the pinned stream mints while the run proceeds, so it is rebuilt
    # from the live state before every step.
    n_steps = len(recipe(state))
    i = 0
    fid_base = 0
    while i < n_steps:
        st = recipe(state)[i]
        argv = [str(a) for a in st.get("argv", [])]
        name = st["name"]
        if st.get("render"):
            render_gate_pass_payload(state["artifacts"][0], st["render"])
        if st.get("seed_exec"):
            # Harness input, not twin output: the SAME externally-reported
            # E4 record is written into both trees at this step (see the
            # seed_exec docstring). The capture is a synthetic note so the
            # step list stays parallel.
            info = st["seed_exec"]
            eid = seeded_exec_id(info["n"])
            seed_exec(
                root,
                state["cid"],
                i,
                info["n"],
                state["findings"][info["finding"]],
                info["command"],
                eid,
            )
            code = 0
            err = ""
            out = (
                f"seeded externally-reported exec {eid} "
                f"(profile docker-networkless, exit 0)\n"
            )
        else:
            code, out, err = run_step(twin, root, argv, i, fid_base, str(sft_store))
        (caps / f"{i:02d}-{name}.out").write_text(out)
        (caps / f"{i:02d}-{name}.err").write_text(err)
        (caps / f"{i:02d}-{name}.exit").write_text(str(code))
        captures[twin].append(
            {
                "name": name,
                "argv": argv,
                "exit": code,
                "expect_exit": st.get("exit", 0),
            }
        )
        declared[twin].append(
            {"err": st.get("err") or [], "out": st.get("out") or []}
        )
        main_harvest_ids(twin, i, out, st, state)
        if st.get("findings"):
            fid_base += st["findings"]
        main_harvest_snapshots(twin, i, out, st, state, root)
        main_harvest_views(twin, i, out, st, state)
        main_harvest_tail(twin, i, out, st, state)
        if code != st.get("exit", 0):
            print(
                f"[warn] {twin} step {i:02d}-{name}: exit {code}, "
                f"expected {st['exit']}: {err.strip()[:200]}"
            )
        i += 1


def main_harvest_ids(twin: str, i: int, out: str, st: dict,
                     state: dict) -> None:
    """Harvest the pinned-stream ids a step's stdout minted
    (findings/artifacts/execs/rungs/campaigns)."""
    name = st["name"]
    if st.get("findings"):
        for _ in range(st["findings"]):
            m = FID_RE.search(out)
            if not m:
                sys.exit(
                    f"{twin} step {i:02d}-{name}: no finding id in stdout:\n{out}"
                )
            state["findings"].append(m.group(1))
    if st.get("artifacts"):
        for _ in range(st["artifacts"]):
            m = ART_RE.search(out)
            if not m:
                sys.exit(
                    f"{twin} step {i:02d}-{name}: no artifact id in stdout:\n{out}"
                )
            state["artifacts"].append(m.group(1))
    if st.get("execs"):
        for _ in range(st["execs"]):
            m = EXEC_RE.search(out)
            if not m:
                sys.exit(
                    f"{twin} step {i:02d}-{name}: no exec id in stdout:\n{out}"
                )
            state["execs"].append(m.group(1))
    if st.get("rungs"):
        for _ in range(st["rungs"]):
            m = RUNG_RE.search(out)
            if not m:
                sys.exit(
                    f"{twin} step {i:02d}-{name}: no rung id in stdout:\n{out}"
                )
            state["rungs"].append(m.group(1))
    if st.get("cid2"):
        m = re.search(r"C-[0-9a-f]+", out)
        if not m:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no campaign id in stdout:\n{out}"
            )
        state["cid2"] = m.group(0)
    if st.get("cid3"):
        # P5 (G16): the third campaign's id, minted by init-s2 from
        # the pinned per-step stream (deterministic across runs).
        m = re.search(r"C-[0-9a-f]+", out)
        if not m:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no campaign id in stdout:\n{out}"
            )
        state["cid3"] = m.group(0)


def main_harvest_snapshots(twin: str, i: int, out: str, st: dict,
                           state: dict, root: Path) -> None:
    """Resolve the content-addressed snapshot roots and run the surface2
    rot gate."""
    name = st["name"]
    if st.get("snapshot2"):
        # P5 (G16): the surface2 snapshot root (content-addressed,
        # under the THIRD campaign): the canonical --src for the P5
        # index step.
        snap_dir = root / "campaigns" / state["cid3"] / "snapshots"
        snaps = sorted(p for p in snap_dir.iterdir() if p.is_dir())
        if not snaps:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no snapshot dir under {snap_dir}"
            )
        state["snap2"] = str(snaps[-1])
    if st.get("surface2"):
        # P5 (G16): the rot gate — every axis carries >=1 row and
        # the artifact validates against probe_surface.schema.json,
        # or the run dies here naming the dark axis.
        check_surface2(twin, i, name, out, root, state["cid3"])
    if st.get("snapshot"):
        # The active snapshot root (content-addressed, identical in
        # both twins): the canonical --src for every index-consuming
        # step, and the tree the closing audit re-indexes.
        snap_dir = root / "campaigns" / state["cid"] / "snapshots"
        snaps = sorted(p for p in snap_dir.iterdir() if p.is_dir())
        if not snaps:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no snapshot dir under {snap_dir}"
            )
        state["snapshot"] = str(snaps[-1])


def main_harvest_views(twin: str, i: int, out: str, st: dict,
                       state: dict) -> None:
    """Read the probe JSON views back into state (the blind axis, the
    high-risk rows)."""
    name = st["name"]
    if st.get("blind"):
        # The BLIND axis the probes view published: the FIRST axis
        # (in the report's fixed order) whose status is "blind" and
        # which published at least one key. Both twins must select
        # the same one, or `probes blank` diverges immediately.
        try:
            doc = json.loads(out)
        except ValueError as exc:
            sys.exit(f"{twin} step {i:02d}-{name}: not JSON: {exc}")
        for ax in doc.get("axes") or []:
            keys = ax.get("blind") or []
            if ax.get("status") == "blind" and keys:
                state["blind"] = [ax.get("axis"), keys[0].get("key")]
                break
        if not state["blind"]:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no blind axis "
                f"published:\n{out[:400]}"
            )
    if st.get("dr"):
        # The first high-risk probe row's plan priority, in surface
        # order: tier 0 (the probe's most serious claim) or
        # assertion_gap >= 3 (the row asserts far beyond its
        # evidence). Both are what checkDismissalGate protects, so a
        # surface that stopped producing one means this block of the
        # recipe lost its subject — fail loudly rather than silently
        # driving the gate with a harmless row.
        try:
            doc = json.loads(out)
        except ValueError as exc:
            sys.exit(f"{twin} step {i:02d}-{name}: not JSON: {exc}")
        for row in doc.get("surface_rows") or []:
            tier = row.get("tier") or 0
            gap = row.get("assertion_gap") or 0
            if not ((tier == 0 or gap >= 3) and row.get("priority_id")):
                continue
            if not state.get("dr"):
                state["dr"] = row["priority_id"]
                # the row's own code, taken from the citation the row
                # publishes: the v3 closure below has to name it, so a
                # surface that stopped exposing anchors fails here
                # rather than silently weakening the step.
                for anchor in row.get("anchors") or []:
                    base = anchor.split("/")[-1].split("#")[0]
                    if base.endswith(".sol"):
                        state["drsym"] = base[: -len(".sol")]
                        break
            elif not state.get("dr2"):
                state["dr2"] = row["priority_id"]
        if not state.get("dr"):
            sys.exit(
                f"{twin} step {i:02d}-{name}: no high-risk probe "
                f"row in the surface:\n{out[:400]}"
            )
        if not state.get("dr2"):
            sys.exit(
                f"{twin} step {i:02d}-{name}: the surface carries "
                f"only one high-risk row, so the v3 accept step "
                f"has no second subject:\n{out[:400]}"
            )
        if not state.get("drsym"):
            sys.exit(
                f"{twin} step {i:02d}-{name}: the high-risk row "
                f"publishes no .sol anchor to cite:\n{out[:400]}"
            )


def main_harvest_tail(twin: str, i: int, out: str, st: dict,
                      state: dict) -> None:
    """Harvest the remaining id families (memory, price) and the init
    campaign id."""
    name = st["name"]
    if st.get("memory"):
        m = re.search(r"MEM-[0-9a-f]+", out)
        if not m:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no memory id in stdout:\n{out}"
            )
        state["mem"].append(m.group(0))
    if st.get("price"):
        m = re.search(r"PRC-[0-9a-f]+", out)
        if not m:
            sys.exit(
                f"{twin} step {i:02d}-{name}: no price id in stdout:\n{out}"
            )
        state["prc"].append(m.group(0))
    if name == "init":
        m = re.search(r"C-[0-9a-f]+", out)
        if not m:
            sys.exit(f"{twin} init did not print a campaign id:\n{out}")
        state["cid"] = m.group(0)


def main() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "captures").mkdir(parents=True)
    build_go()
    target = make_target()
    target2 = make_surface2_target()
    roots: dict[str, str] = {}
    trees: dict[str, str] = {}
    captures: dict[str, list] = {}
    # Per-step declared output markers (see the `err`/`out` keys on the
    # recipe steps and check-golden's check_steps).
    declared: dict[str, list] = {}
    states: dict[str, dict] = {}
    acc = {"roots": roots, "trees": trees, "captures": captures,
           "declared": declared, "states": states}
    # GO-ONLY (Python twin retired — Go is the source of truth). The single
    # Go run uses one root path; every event hash covers absolute artifact
    # paths, so the archived tree is self-consistent. The run is captured
    # (stdout/stderr/exit per step + the artifact tree) for check-golden.py
    # to validate against the recipe's declared exit codes.
    root = WORK / "root"
    for twin in ("go",):
        main_run_twin(twin, root, target, target2, acc)

    # Declared output markers, parallel to `recipe` (None where a step
    # declares none). check-golden validates them: an exit code says a
    # refusal happened, never WHY — and for the refusal steps above the why
    # is the whole point.
    spec = {
        "expect_err": [d["err"] for d in declared["go"]],
        "expect_out": [d["out"] for d in declared["go"]],
        "seed": SEED,
        "now_base": NOW_BASE.isoformat(),
        "roots": roots,
        "trees": trees,
        "target": str(target),
        "campaign_id": states["go"]["cid"],
        "recipe": [c["name"] for c in captures["go"]],
        "expected_exit": [c["expect_exit"] for c in captures["go"]],
        "captures": captures,
    }
    (WORK / "spec.json").write_text(json.dumps(spec, indent=1))
    print(
        f"golden run complete: campaign {states['go']['cid']} "
        f"({len(spec['recipe'])} steps, Go-only)"
    )
    print(f"  run root: {roots['go']}")
    print(f"  archived tree: {trees['go']}")


if __name__ == "__main__":
    main()


# Baseline note (G16, T19): before the P5 phase landed, the recipe ran 185
# steps over campaigns C-<seed:00> (P0/P1/P2/P3) and C-<seed:cid2> (D19) plus
# the P4 sft block, and the campaign-1 probe surface carried 5 rows with
# accumulator-skew=blind and enforcement-timing=blind. P5 appends 11 steps
# (init-s2 .. verify-s2) and changes no earlier index, argv, or state key —
# any byte change to an existing capture outside the new *-s2 steps is a
# regression, not an update.
