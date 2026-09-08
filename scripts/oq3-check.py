#!/usr/bin/env python3
"""OQ3 checkpoint (Task 19): does santhosh-tekuri/jsonschema/v6 agree
with Python jsonschema on every known schema?

Corpus: real documents from the golden run (campaign_state.json, every
events.jsonl line, snapshot.json) plus deterministic mutations of each
(drop every top-level key; flip the first leaf to a wrong type; empty
object). Every (doc, schema) pair is validated by BOTH implementations:

  * Python: webv2.validation.validate (jsonschema, the reference lib)
  * Go:     cmd/oq3check over the byte-identical embedded assets

Verdicts are compared pair by pair; the report is a per-schema table
(schema -> pairs / py-valid / go-valid / mismatches). Exit 0 iff zero
mismatches across the whole corpus.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

GO_ROOT = Path(__file__).resolve().parent.parent
PY_ROOT = GO_ROOT.parent / "web3sec-final"
WORK = GO_ROOT / ".scratch" / "oq3"
GOTBIN = WORK / "oq3check"

sys.path.insert(0, str(PY_ROOT / "src"))
from webv2.validation import KNOWN_SCHEMAS, SchemaError, validate  # noqa: E402


def build_go() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ,
               GOCACHE=str(GO_ROOT / ".scratch" / "gocache"),
               GOPATH=str(GO_ROOT / ".scratch" / "gomod"),
               GOMODCACHE=str(GO_ROOT / ".scratch" / "gomod" / "pkg" / "mod"))
    r = subprocess.run(["go", "build", "-o", str(GOTBIN), "./cmd/oq3check"],
                       cwd=GO_ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"go build oq3check failed:\n{r.stderr}")


def corpus_docs() -> list[tuple[str, object]]:
    """(label, doc) pairs; golden artifacts if present, else a fresh
    minimal recipe through the Python CLI."""
    golden = GO_ROOT / ".scratch" / "golden"
    if not (golden / "spec.json").exists():
        golden.mkdir(parents=True, exist_ok=True)
        root = golden / "oq3root"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir()
        tgt = golden / "oq3target"
        shutil.rmtree(tgt, ignore_errors=True)
        (tgt / "src").mkdir(parents=True)
        (tgt / "foundry.toml").write_text('[profile.default]\nsol = "0.8.24"\n')
        (tgt / "src" / "V.sol").write_text("contract V { }")
        env = dict(os.environ, PYTHONPATH=str(PY_ROOT / "src"))
        def cli(*args: str) -> str:
            r = subprocess.run([sys.executable, "-m", "webv2.cli",
                                "--root", str(root), *args],
                               capture_output=True, text=True, env=env,
                               cwd=PY_ROOT)
            if r.returncode != 0:
                sys.exit(f"oq3 recipe failed: {' '.join(args)}\n{r.stderr}")
            return r.stdout
        out = cli("init", "--program", "OQ3")
        cid = [w for w in out.split() if w.startswith("C-")][0]
        cli("snap", cid, str(tgt))
        campaign_dir = root / "campaigns" / cid
    else:
        spec = json.loads((golden / "spec.json").read_text())
        cid = spec["campaign_id"]
        campaign_dir = Path(spec["roots"]["py"]) / "campaigns" / cid
    docs: list[tuple[str, object]] = [
        ("campaign_state", json.loads(
            (campaign_dir / "campaign_state.json").read_text())),
    ]
    for i, line in enumerate(
            (campaign_dir / "events.jsonl").read_text().splitlines()):
        if line.strip():
            docs.append((f"event[{i}]", json.loads(line)))
    snaps = sorted((campaign_dir / "snapshots").glob("*/snapshot.json"))
    for s in snaps:
        docs.append(("snapshot", json.loads(s.read_text())))
    return docs


def variants(label: str, doc: object) -> list[tuple[str, object]]:
    out = [(f"{label}#orig", doc)]
    if isinstance(doc, dict):
        for k in list(doc)[:4]:
            d2 = {k2: v for k2, v in doc.items() if k2 != k}
            out.append((f"{label}#drop-{k}", d2))
        # flip the first leaf to a wrong type
        d3 = json.loads(json.dumps(doc))

        def first_leaf(o) -> dict:
            stack = [o]
            while stack:
                node = stack.pop()
                if isinstance(node, dict) and node:
                    for k, v in node.items():
                        if isinstance(v, (dict, list)):
                            stack.append(v)
                        else:
                            return node, k, v
                elif isinstance(node, list) and node:
                    stack.extend(node)
            raise RuntimeError("no leaf found")

        try:
            node, key, leaf = first_leaf(d3)
            node[key] = 12345 if isinstance(leaf, str) else "nope"
            out.append((f"{label}#flip-leaf", d3))
        except RuntimeError:
            pass
    out.append((f"{label}#empty", {}))
    return out


def schema_type_flips() -> list[tuple[str, str, object]]:
    """Per schema, a doc whose top-level properties are set to the WRONG
    type (from the schema's own 'type' keyword) — exercises the type
    check on every schema, even the loose ones."""
    from webv2.validation import load_schema
    wrong = {"string": 123, "integer": "nope", "number": "nope",
             "boolean": "nope", "object": [1], "array": "nope",
             "null": 1}
    out = []
    for schema in KNOWN_SCHEMAS:
        try:
            doc_schema = load_schema(schema)
        except FileNotFoundError:
            continue
        props = (doc_schema.get("properties") or {})
        doc = {}
        for name, pspec in props.items():
            t = pspec.get("type")
            if isinstance(t, str) and t in wrong:
                doc[name] = wrong[t]
            elif isinstance(t, list):
                for t2 in t:
                    if t2 != "null" and t2 in wrong:
                        doc[name] = wrong[t2]
                        break
        out.append((schema, f"{schema}#type-flips", doc))
    return out


def main() -> None:
    build_go()
    pairs: list[tuple[str, str, object]] = []  # (schema, label, doc)
    for label, doc in corpus_docs():
        for vlabel, vdoc in variants(label, doc):
            for schema in KNOWN_SCHEMAS:
                pairs.append((schema, vlabel, vdoc))
    # Schema-driven type-flip docs: each pair targets its own schema.
    for schema, label, doc in schema_type_flips():
        pairs.append((schema, label, doc))

    # Python verdicts.
    py = []
    for schema, _label, doc in pairs:
        try:
            validate(doc, schema)
            py.append("VALID")
        except SchemaError:
            py.append("INVALID")

    # Go verdicts (one process, all pairs on stdin).
    payload = "".join(
        f"{schema}\t{json.dumps(doc, separators=(',', ':'))}\n"
        for schema, _label, doc in pairs)
    r = subprocess.run([str(GOTBIN)], input=payload,
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"go probe failed ({r.returncode}):\n{r.stderr}")
    go = r.stdout.splitlines()
    if len(go) != len(pairs):
        sys.exit(f"go probe line count {len(go)} != {len(pairs)}")

    # Per-schema table + mismatch list.
    from collections import defaultdict
    stat = defaultdict(lambda: [0, 0, 0, 0])  # pairs, pyv, gov, mism
    mism = []
    for i, (schema, label, _doc) in enumerate(pairs):
        s = stat[schema]
        s[0] += 1
        s[1] += py[i] == "VALID"
        s[2] += go[i] == "VALID"
        if py[i] != go[i]:
            s[3] += 1
            mism.append(f"{schema} {label}: py={py[i]} go={go[i]}")

    print(f"corpus: {len(pairs)} (doc, schema) pairs "
          f"({len(corpus_docs())} docs x {len(KNOWN_SCHEMAS)} schemas + mutations"
          f" + {len(schema_type_flips())} schema-driven type-flip docs)")
    print(f"{'schema':<22} {'pairs':>6} {'py-valid':>9} {'go-valid':>9} {'mism':>5}")
    for schema in KNOWN_SCHEMAS:
        p, a, b, m = stat[schema]
        print(f"{schema:<22} {p:>6} {a:>9} {b:>9} {m:>5}")
    total_m = sum(s[3] for s in stat.values())
    print()
    if mism:
        print(f"OQ3 RED — {total_m} verdict mismatches:")
        for line in mism[:20]:
            print("  " + line)
        sys.exit(1)
    print("OQ3 GREEN: Go jsonschema/v6 and Python jsonschema agree on "
          f"every (doc, schema) pair across all {len(KNOWN_SCHEMAS)} schemas")


if __name__ == "__main__":
    main()
