#!/usr/bin/env python3
"""Absorb new/changed Python tests into testmap.json (live reference).

web3sec-final is developed in parallel: every new Python test function must
get a row (the spec's no-silent-drops rule), and every row must keep pointing
at a function that still exists. This script is the one-command catch-up:

  * adds a row for every Python test function missing from the map, tagged
    with its phase from PHASE_BY_FILE (unknown files -> deferred-P3 + a
    warning, so a brand-new module is never silently swallowed);
  * reports rows whose Python function disappeared (renamed/deleted) —
    never deletes them: a stale row means a stale Go port to check by hand;
  * leaves real (ported) rows untouched.

Usage: python3 scripts/sync-testmap.py [--check]
  --check  exit non-zero if anything would change (CI mode)
"""
import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
GO_ROOT = HERE.parent.parent
TESTMAP = GO_ROOT / "testmap.json"

# file -> phase. Mirrors the spec-§14 module ownership; update when a new
# Python test file lands (the script warns instead of guessing silently).
PHASE_BY_FILE = {
    # P0 (ported) — a NEW test in one of these files is tagged deferred-P0
    # so check-testmap keeps the P0 slice fully-real-or-red.
    "tests/test_state.py": "deferred-P0",
    "tests/test_state_log.py": "deferred-P0",
    "tests/test_state_log_chain.py": "deferred-P0",
    "tests/test_snapshot.py": "deferred-P0",
    "tests/test_snapshot_integrity.py": "deferred-P0",
    "tests/test_snap_exclude.py": "deferred-P0",
    "tests/test_snap_toolchain.py": "deferred-P0",
    "tests/test_audit.py": "deferred-P0",
    "tests/test_root_default.py": "deferred-P0",
    "tests/test_living_artifacts.py": "deferred-P0",
    # P1
    "tests/test_findings.py": "deferred-P1",
    "tests/test_assumptions.py": "deferred-P1",
    "tests/test_memory_check_gate.py": "deferred-P1",
    "tests/test_evidence_integrity.py": "deferred-P1",
    "tests/test_floors.py": "deferred-P1",
    "tests/test_taxonomy.py": "deferred-P1",
    "tests/test_taxonomy_seed_alignment.py": "deferred-P1",
    "tests/test_capabilities.py": "deferred-P1",
    "tests/test_cap_role_labels.py": "deferred-P1",
    "tests/test_dedup_determinism.py": "deferred-P1",
    "tests/test_partition_guards.py": "deferred-P1",
    "tests/test_risk_amplifiers.py": "deferred-P1",
    "tests/test_bounty_policy.py": "deferred-P1",
    "tests/test_invariants.py": "deferred-P1",
    "tests/test_invariants_doc.py": "deferred-P1",
    "tests/test_invariants_structured.py": "deferred-P1",
    "tests/test_economics_transforms.py": "deferred-P1",
    "tests/test_lens_exhaustive.py": "deferred-P1",
    "tests/test_plan_lenses.py": "deferred-P1",
    "tests/test_symmetry_teeth.py": "deferred-P1",
    "tests/test_completion_proof.py": "deferred-P1",
    "tests/test_pipeline.py": "deferred-P1",
    "tests/test_orchestrator.py": "deferred-P1",
    "tests/test_answered.py": "deferred-P1",
    "tests/test_disproof_sibling.py": "deferred-P1",
    "tests/test_budget.py": "deferred-P1",
    "tests/test_budget_discovery.py": "deferred-P1",
    "tests/test_ingest.py": "deferred-P1",
    "tests/test_model_boundary.py": "deferred-P1",
    "tests/test_outcome_events.py": "deferred-P1",
    "tests/test_trajectory.py": "deferred-P1",
    "tests/test_routing.py": "deferred-P1",
    "tests/test_role_isolation.py": "deferred-P1",
    "tests/test_adapter_prompts.py": "deferred-P1",
    "tests/test_cli.py": "deferred-P1",
    "tests/test_cli_e2e_confirm.py": "deferred-P1",
    "tests/test_cli_gate_dryrun.py": "deferred-P1",
    "tests/test_cli_recall.py": "deferred-P1",
    "tests/test_design_upgrades.py": "deferred-P1",
    "tests/test_review_fixes.py": "deferred-P1",
    "tests/test_severity_split.py": "deferred-P1",
    # P2
    "tests/test_audit_sequence_coverage.py": "deferred-P2",
    "tests/test_chain_engine.py": "deferred-P2",
    "tests/test_exec_dry_run.py": "deferred-P2",
    "tests/test_exec_env.py": "deferred-P2",
    "tests/test_fork_poc_immunize.py": "deferred-P2",
    "tests/test_independent_verification.py": "deferred-P2",
    "tests/test_mint_citation.py": "deferred-P2",
    "tests/test_model_integration.py": "deferred-P2",
    "tests/test_planner_privileged.py": "deferred-P2",
    "tests/test_privileged_bands.py": "deferred-P2",
    "tests/test_privileged_baseline.py": "deferred-P2",
    "tests/test_runbook_flow.py": "deferred-P2",
    "tests/test_sandbox_repro.py": "deferred-P2",
    "tests/test_sandbox_solc_dir.py": "deferred-P2",
    "tests/test_sequence_coverage.py": "deferred-P2",
    "tests/test_sequence_guidance.py": "deferred-P2",
    "tests/test_sequence_pin_gate.py": "deferred-P2",
    "tests/test_sequence_runner.py": "deferred-P2",
    "tests/test_sequence_spec.py": "deferred-P2",
    "tests/test_cli_privileged.py": "deferred-P2",
    # P3 (probes/structural-index v2 land here too: pure functions over the
    # structural index, the same phase as the index itself)
    "tests/test_probes.py": "deferred-P3",
    "tests/test_structural_index_v2.py": "deferred-P3",
}
DEFAULT_PHASE = "deferred-P3"


def load_count_module():
    src = str((HERE.parent / "count-python-tests.py").resolve())
    spec = importlib.util.spec_from_loader(
        "count_python_tests_mod",
        importlib.machinery.SourceFileLoader("count_python_tests_mod", src))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    check = "--check" in sys.argv
    doc = json.loads(TESTMAP.read_text(encoding="utf-8"))
    rows = doc["rows"]
    per = load_count_module().collect()

    have = {(r["python_file"], r["python_func"]) for r in rows}
    py = {(pf, fn) for pf, fns in per.items() for fn in fns}

    added, warned = [], []
    for pf, fn in sorted(py - have):
        phase = PHASE_BY_FILE.get(pf, DEFAULT_PHASE)
        if pf not in PHASE_BY_FILE:
            warned.append(pf)
        row = {"python_file": pf, "python_func": fn}
        if phase:
            row["status"] = phase
        rows.append(row)
        added.append((pf, fn, phase))

    stale = sorted(have - py)

    if warned:
        print("WARNING: unknown python test file(s) -> %s (add to PHASE_BY_FILE):"
              % DEFAULT_PHASE)
        for pf in sorted(set(warned)):
            print("   ", pf)

    if added:
        print(f"added {len(added)} row(s):")
        for pf, fn, phase in added:
            print(f"    {pf}::{fn}  [{phase or 'real'}]")
    else:
        print("no new python test functions")

    if stale:
        print(f"STALE rows ({len(stale)}) — python function no longer exists "
              "(check the Go port by hand; not auto-removed):")
        for pf, fn in stale:
            print(f"    {pf}::{fn}")

    changed = bool(added)
    if check:
        return 1 if changed else 0
    if changed:
        TESTMAP.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {TESTMAP.relative_to(GO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
