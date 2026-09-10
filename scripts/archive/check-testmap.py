#!/usr/bin/env python3
"""Validate testmap.json against the live Python and Go trees (Task 16).

Checks:
  (a) no duplicated python_func within the same python_file
  (b) row count == count-python-tests.py grand total
  (c) every P0-slice file's function set is fully covered by REAL rows (not stubs)
  (d) every real row's go_file/go_func (or merged_into) names an EXISTING Go test

Exit 0 with a short reconciliation summary on success; non-zero with a clear
message on any failure.

Usage: python3 scripts/check-testmap.py   (from the Go repo root)
"""
import importlib.machinery
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
GO_ROOT = HERE.parent.parent
TESTMAP = GO_ROOT / "testmap.json"

P0_FILES = [
    "tests/test_state.py",
    "tests/test_state_log.py",
    "tests/test_state_log_chain.py",
    "tests/test_snapshot.py",
    "tests/test_snapshot_integrity.py",
    "tests/test_snap_exclude.py",
    "tests/test_snap_toolchain.py",
    "tests/test_audit.py",
    "tests/test_root_default.py",
    # P0 addendum (tagged 2026-09-08): register_or_refresh behavior,
    # already implemented in P0 (state/artifacts.go); the 7 tests are
    # ported as the first task of the P1 plan.
    "tests/test_living_artifacts.py",
]

FAIL = []


def fail(msg):
    FAIL.append(msg)
    print("FAIL:", msg)


def load_count_module():
    src = str((HERE.parent / "count-python-tests.py").resolve())
    spec = importlib.util.spec_from_loader(
        "count_python_tests_mod",
        importlib.machinery.SourceFileLoader("count_python_tests_mod", src))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- (a) no duplicated python_func within the same python_file -------------
def check_no_dup_python_func(doc):
    seen = {}
    for r in doc["rows"]:
        key = (r["python_file"], r["python_func"])
        if key in seen:
            fail(f"(a) duplicate python_func {key[0]}::{key[1]} "
                 f"(rows {seen[key]} and current)")
        seen[key] = True
    return len(seen)


# --- (b) row count == count-python-tests.py grand total --------------------
def check_row_count(doc):
    count_mod = load_count_module()
    per = count_mod.collect()
    grand = sum(len(v) for v in per.values())
    if len(doc["rows"]) != grand:
        fail(f"(b) testmap rows={len(doc['rows'])} but count-python-tests.py "
             f"grand total={grand}")
        # also report which python funcs in count are missing from the map
        mapped = {(r["python_file"], r["python_func"]) for r in doc["rows"]}
        missing = [(pf, fn) for pf, fs in per.items() for fn in fs
                   if (pf, fn) not in mapped]
        extra = [(r["python_file"], r["python_func"]) for r in doc["rows"]
                 if (r["python_file"], r["python_func"]) not in
                 {(pf, fn) for pf, fs in per.items() for fn in fs}]
        if missing:
            print("   missing from map (first 25):",
                  sorted(missing)[:25])
        if extra:
            print("   in map but absent from python tree (first 25):",
                  sorted(extra)[:25])
    return grand


# --- (c) every P0-slice file fully covered by REAL rows ---------------------
def check_p0_cover(doc):
    count_mod = load_count_module()
    per = count_mod.collect()
    for pf in P0_FILES:
        pyfuncs = set(per.get(pf, []))
        mapped = {r["python_func"] for r in doc["rows"]
                  if r["python_file"] == pf and "status" not in r}
        if not pyfuncs:
            fail(f"(c) P0 file {pf} has no python test functions in count script")
            continue
        stubbed = {r["python_func"] for r in doc["rows"]
                   if r["python_file"] == pf and "status" in r}
        if stubbed:
            fail(f"(c) P0 file {pf} has DEFERRED stub rows (not real): "
                 f"{sorted(stubbed)}")
        if mapped != pyfuncs:
            only_stub_or_missing = (pyfuncs - mapped)
            fail(f"(c) P0 file {pf}: real rows cover {sorted(mapped)} but "
                 f"python has {sorted(pyfuncs)}; "
                 f"missing/not-real: {sorted(only_stub_or_missing)}")
    return True


# --- (d) every real row's go_file/go_func exists ----------------------------
def index_go_tests():
    pat = re.compile(r"func\s+(Test\w+)\s*\(")
    idx = {}
    # All Go test files under internal/ (P0: state/snapshot/audit/cli;
    # P1+ adds findings/planner/pipeline/... — walk, don't enumerate).
    for f in sorted((GO_ROOT / "internal").rglob("*_test.go")):
        rel = str(f.relative_to(GO_ROOT))
        idx[rel] = set(pat.findall(f.read_text(encoding="utf-8")))
    # flatten with file context for better errors
    func_to_files = {}
    for gf, funcs in idx.items():
        for fn in funcs:
            func_to_files.setdefault(fn, set()).add(gf)
    return idx, func_to_files


def check_go_targets(doc, go_file_index, func_to_files):
    n_row = 0
    for r in doc["rows"]:
        if "status" in r:
            continue
        n_row += 1
        target = r.get("merged_into")
        if target is None:
            gf, gfunc = r.get("go_file"), r.get("go_func")
        else:
            gf, gfunc = target.get("go_file"), target.get("go_func")
        if not gf or not gfunc:
            fail(f"(d) real row {r['python_file']}::{r['python_func']} "
                 f"has no go_file/go_func or merged_into")
            continue
        if gfunc not in func_to_files:
            fail(f"(d) go_func {gfunc} (from {r['python_file']}::{r['python_func']}) "
                 f"does not exist anywhere in the Go test tree")
            continue
        if gf not in go_file_index or gfunc not in go_file_index.get(gf, set()):
            # it exists but in a different file than claimed
            fail(f"(d) go_func {gfunc} (row {r['python_file']}::{r['python_func']}) "
                 f"claimed file {gf} does not define it; found in "
                 f"{sorted(func_to_files[gfunc])}")
    return n_row


def main():
    if not TESTMAP.exists():
        print(f"FAIL: testmap.json not found at {TESTMAP}")
        return 1
    doc = json.loads(TESTMAP.read_text(encoding="utf-8"))
    rows = doc.get("rows")
    if not isinstance(rows, list) or not rows:
        print("FAIL: testmap.json has no non-empty 'rows' list")
        return 1

    n_mapped = check_no_dup_python_func(doc)
    grand = check_row_count(doc)
    check_p0_cover(doc)
    go_file_index, func_to_files = index_go_tests()
    n_real = check_go_targets(doc, go_file_index, func_to_files)

    if FAIL:
        print(f"\ncheck-testmap: {len(FAIL)} FAILURE(S) — testmap.json NOT reconciled.")
        return 1

    # Reconciliation summary
    n_deferred = len(rows) - n_real
    n_merged = sum(1 for r in rows if "status" not in r and "merged_into" in r)
    n_1to1 = n_real - n_merged
    from collections import Counter
    buckets = Counter(r["status"] for r in rows if "status" in r)
    print("testmap.json reconciled OK")
    print(f"  rows total           : {len(rows)} (matches count-python-tests.py grand total {grand})")
    print(f"  real rows (P0 slice) : {n_real}  [1:1={n_1to1}, merged={n_merged}]")
    print(f"  deferred stubs       : {n_deferred}  "
          + "  ".join(f"{k}={buckets[k]}" for k in sorted(buckets)))
    print(f"  distinct py funcs    : {n_mapped}")
    print(f"  P0 {len(P0_FILES)}-file slice     : fully real (no deferred stubs)")
    print("  go_file/go_func refs  : all exist in the Go test tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())