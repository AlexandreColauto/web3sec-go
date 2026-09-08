#!/usr/bin/env python3
"""Count Python test functions (def test_... / async def test_...) in web3sec-final.

Walks web3sec-final/tests/ and any package tests under src/webv2/.
AST-based: does not match comments or strings.

Usage: python3 scripts/count-python-tests.py   (from the Go repo root)
"""
import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
GO_ROOT = HERE.parent.parent
FINAL = GO_ROOT.parent / "web3sec-final"


def collect_funcs(path: Path):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"WARN: cannot parse {path}: {e}", file=sys.stderr)
        return []
    funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                funcs.append(node.name)
    return sorted(funcs)


def collect():
    """Return {relpath: [test func names]} for all Python test functions."""
    tests_dir = FINAL / "tests"
    src_dir = FINAL / "src" / "webv2"
    per_file = {}
    if tests_dir.is_dir():
        for p in sorted(tests_dir.glob("test_*.py")):
            per_file[f"tests/{p.name}"] = collect_funcs(p)
    # Any package tests under src/webv2/ (e.g. test_*.py or *_test.py files)
    if src_dir.is_dir():
        for p in sorted(src_dir.rglob("*.py")):
            name = p.name
            if name.startswith("test_") or name.endswith("_test.py"):
                rel = "src/webv2/" + str(p.relative_to(src_dir))
                per_file[rel] = collect_funcs(p)
    return per_file


def main():
    per_file = collect()
    total = 0
    for fname, funcs in per_file.items():
        print(f"{fname}: {len(funcs)}")
        total += len(funcs)
    print(f"TOTAL: {total}")


if __name__ == "__main__":
    main()
