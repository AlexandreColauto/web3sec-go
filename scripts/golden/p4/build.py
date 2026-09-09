#!/usr/bin/env python3
"""Golden v5 (T38) P4 fixture builder.

Builds the small, REAL-FORMAT fixture the golden suite drives the P4 surface
with, by running the READ-ONLY Python reference (web3sec-final) over the real
DeFiHackLabs corpus and the reference's own store APIs. Nothing here is
hand-written: every record, case, memory row and split input is produced by
the reference library, so the fixture cannot drift from the format the port
must reproduce.

Outputs (committed under scripts/golden/p4/):

  datasets/explorer/incidents.json      a 30-incident slice, corpus order
  datasets/explorer/rootcause_data.json the RCA records joined to that slice
  datasets/DeFiHackLabs/src/test/...    the resolved PoC files
  eval/cases.json + cases.sha256        4 cases built via ingest_record+add_case
  shared-memory/{memory.json,signatures.json,manifest.json}
                                        dev-partition prior rows published
                                        through the reference's own
                                        publish_ingested path (this is what
                                        corpus_surface._attach_memory reads
                                        for memory_ids/bug_class attribution)
  sft/examples.json                     the 2 committed curated examples +
                                        2 constructed drafts
  sft/lint-pass.json                    a curated example (distinct claim) the
                                        lint ACCEPTS
  sft/lint-dedup.json                   the SAME curated example: hard dedup
                                        refusal
  sft/lint-reject.json                  a TODO skeleton the lint REFUSES

Selection rule (deterministic, no wall clock): for every canonical bug_class
the reference maps from the corpus, take the first record (corpus order) with
a resolvable PoC and the first without one; plus the first `unmapped` record
with a PoC (so the eval store exercises the unmapped counter). 30 records.

Usage: python3 scripts/golden/p4/build.py [--check]
  --check  rebuild into a temp dir and byte-compare against the committed
           fixture (proves the committed bytes still match the reference).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

GO_ROOT = Path(__file__).resolve().parents[3]
PY_ROOT = Path(os.environ.get("WEBV2_PY_ROOT",
                              GO_ROOT.parent / "web3sec-final"))
FIX = Path(__file__).resolve().parent
CORPUS = PY_ROOT / "data" / "datasets" / "DeFiHackLabs"
EXPLORER = PY_ROOT / "data" / "datasets" / "DeFiHackLabs-Incident-Explorer"

if not (PY_ROOT / "src" / "webv2").is_dir():
    sys.exit(f"reference repo not found at {PY_ROOT} "
             "(set WEBV2_PY_ROOT to the web3sec-final checkout)")
sys.path.insert(0, str(PY_ROOT / "src"))

from webv2 import eval_store as ES              # noqa: E402
from webv2 import ingest as IN                  # noqa: E402
from webv2 import shared_memory as SM           # noqa: E402
from webv2 import taxonomy as TX                # noqa: E402
from webv2.datasets import defihacklabs as DfH  # noqa: E402

# The eval-store cases: (record_id_suffix, why). The first three are mapped
# classes on both partitions; the last is the `unmapped` counter.
EVAL_RECORDS = ("summerfi", "aidc", "usm", "sodium")

# Fixed ingestion stamp so cases.json is reproducible.
BUILD_NOW = "2026-09-08T12:00:00.000000+00:00"


def select(records: list[dict], maps: dict) -> list[dict]:
    """The deterministic 30-record slice (see the module docstring)."""
    by_class: dict[tuple[str, bool], list[dict]] = {}
    unmapped_poc: list[dict] = []
    for rec in records:
        canon, _ = TX.normalize_class(rec["bug_class_label"], maps)
        has_poc = (rec.get("exploit") or {}).get("poc_path") is not None
        if canon == TX.UNMAPPED:
            if has_poc:
                unmapped_poc.append(rec)
            continue
        by_class.setdefault((canon, has_poc), []).append(rec)
    picked = []
    for key in sorted(by_class):
        picked.append(by_class[key][0])
    if unmapped_poc:
        picked.append(unmapped_poc[0])
    # corpus order: assign_ids/assign_partitions are order-sensitive, and the
    # slice must behave like the tail of the real corpus.
    order = {rec["id"]: i for i, rec in enumerate(records)}
    return sorted(picked, key=lambda rec: order[rec["id"]])


def write_slice(picked: list[dict], dest: Path) -> None:
    """Write the incidents/RCA slice in corpus order + the resolved PoCs."""
    incidents = json.loads((EXPLORER / "incidents.json").read_text())
    rca_data = json.loads((EXPLORER / "rootcause_data.json").read_text())
    want = {rec["id"] for rec in picked}
    # record id -> incident, using the FULL corpus ids (load_records is the
    # authority; the slice re-derives ids from its own subset below).
    full = DfH.load_records()
    by_id = {r["id"]: r for r in full}
    full_ids = DfH.assign_ids(incidents)
    inc_by_record = {}
    for rid, inc in zip(full_ids, incidents):
        inc_by_record[rid] = inc
    keep_ids = [rid for rid in full_ids if rid in want]
    if len(keep_ids) != len(want):
        sys.exit(f"slice selection lost records: {len(keep_ids)} vs {len(want)}")

    picked_incidents = [inc_by_record[rid] for rid in keep_ids]
    names = {str(inc.get("name") or "") for inc in picked_incidents}
    norm_names = {DfH.normalize_name(n) for n in names}
    kept_rca = {k: v for k, v in rca_data.items()
                if DfH.normalize_name(k) in norm_names}

    (dest / "explorer").mkdir(parents=True, exist_ok=True)
    (dest / "explorer" / "incidents.json").write_text(
        json.dumps(picked_incidents, indent=2) + "\n")
    (dest / "explorer" / "rootcause_data.json").write_text(
        json.dumps(kept_rca, indent=2) + "\n")

    copied = 0
    for rid in keep_ids:
        rec = by_id[rid]
        poc = (rec.get("exploit") or {}).get("poc_path")
        if not poc:
            continue
        src = CORPUS / poc
        out = dest / "DeFiHackLabs" / poc
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
        copied += 1
    print(f"slice: {len(picked_incidents)} incidents, {len(kept_rca)} RCA "
          f"records, {copied} PoC files")


def verify_slice(dest: Path, picked: list[dict]) -> list[dict]:
    """The slice must reproduce the reference's own records byte-for-byte on
    the fields the golden pins (id, poc path, partition, title)."""
    slice_records = DfH.load_records(explorer_dir=dest / "explorer",
                                     poc_root=dest / "DeFiHackLabs")
    if len(slice_records) != len(picked):
        sys.exit(f"slice has {len(slice_records)} records, expected "
                 f"{len(picked)}")
    # Pairwise by corpus order. A collision-group id may legitimately rename
    # under the subset (the suffix disambiguates within the corpus, not the
    # slice) — every OTHER pinned field must be byte-identical.
    for rec, src in zip(slice_records, picked):
        for field in ("title", "exploit", "code", "locations"):
            if rec.get(field) != src.get(field):
                sys.exit(f"slice record {rec['id']} field {field} differs "
                         f"from the full corpus")
    print(f"slice verified: {len(slice_records)} records reproduce the "
          "reference's own resolution")
    return slice_records


def build_eval(dest: Path, records: list[dict], maps: dict) -> None:
    evaldir = dest / "eval"
    evaldir.mkdir(parents=True, exist_ok=True)
    old = ES.EVAL_DIR
    ES.EVAL_DIR = evaldir
    try:
        chosen = []
        for suffix in EVAL_RECORDS:
            hit = [r for r in records if r["id"].endswith(suffix)]
            if not hit:
                sys.exit(f"eval record {suffix} not in the slice")
            chosen.append(hit[0])
        for rec in chosen:
            result = IN.ingest_record(rec, maps)
            ES.add_case(result["eval_case"])
            print(f"eval case {result['eval_case']['case_id']} "
                  f"{result['eval_case']['gold']['bug_class']} "
                  f"({result['eval_case']['partition']})")
    finally:
        ES.EVAL_DIR = old
    rep = None
    old = ES.EVAL_DIR
    ES.EVAL_DIR = evaldir
    try:
        rep = ES.verify_eval_store()
    finally:
        ES.EVAL_DIR = old
    if not rep["ok"]:
        sys.exit(f"eval store does not verify: {rep['problems']}")
    print(f"eval store: {rep['count']} cases, sidecar verifies")


def build_shared(dest: Path, records: list[dict], maps: dict) -> None:
    """Publish the dev-partition priors through the reference's own
    publish_ingested path (the same path a real ingestion run uses)."""
    shared = dest / "shared-memory"
    shared.mkdir(parents=True, exist_ok=True)
    results = [IN.ingest_record(r, maps) for r in records
               if r.get("partition") == "dev"
               and TX.normalize_class(r["bug_class_label"], maps)[0]
               != TX.UNMAPPED]
    scratch = Path(tempfile.mkdtemp(prefix="p4-eval-scratch-"))
    old = ES.EVAL_DIR
    ES.EVAL_DIR = scratch
    try:
        summary = IN.publish_ingested(results, dataset="defihacklabs",
                                      tier=shared)
    finally:
        ES.EVAL_DIR = old
        shutil.rmtree(scratch, ignore_errors=True)
    rows = SM._tier_memory(shared)
    print(f"shared memory: {summary['rows_added']} rows in "
          f"{len({w['program_key'] for w in rows})} program key(s)")
    if not rows:
        sys.exit("shared-memory fixture is empty — attribution would be blind")


def build_sft(dest: Path) -> None:
    sft_dir = dest / "sft"
    sft_dir.mkdir(parents=True, exist_ok=True)
    curated = json.loads((PY_ROOT / "sft" / "examples.json").read_text())
    examples = [json.loads(json.dumps(e)) for e in curated["examples"]]

    # A clean draft: curated example 1 with a distinct claim signature and
    # no partition (drafts are unsplit by construction).
    draft = json.loads(json.dumps(examples[0]))
    draft["id"] = "SFT-0003"
    draft["status"] = "draft"
    draft["partition"] = None
    draft["created_at"] = BUILD_NOW
    draft["curated_by"] = None
    draft["structured"]["claim"] = (
        "A reentrancy hook on the vault withdrawal path lets an attacker "
        "re-enter before the share accounting settles and drain the pool.")
    examples.append(draft)

    # The rejection candidate: a schema-valid skeleton with TODO
    # placeholders and a broken arc, exactly what `sft backfill` emits before
    # a curator fills it in.
    reject = json.loads(json.dumps(examples[0]))
    reject["id"] = "SFT-0004"
    reject["status"] = "draft"
    reject["partition"] = None
    reject["created_at"] = BUILD_NOW
    reject["curated_by"] = None
    reject["structured"] = {
        "bug_class": "TODO-bug-class",
        "claim": "TODO: one falsifiable paragraph about the defect.",
        "assumptions": [{"id": "A1", "text": "TODO: the first checkable "
                         "proposition", "status": "OPEN",
                         "reason": "TODO: state the resolving evidence"}],
        "invariants": [{"statement": "TODO: the property violated",
                        "status": "UNCHECKED", "depends_on": []}],
        "expected_impact": "TODO: state the concrete asset/actor/magnitude",
        "next_test": "",
        "pivot_count": 0,
    }
    reject["messages"][2]["content"] = (
        "OBSERVATION:\nTODO: what looked unusual, with a code reference.\n\n"
        "A1 (TODO: first checkable proposition): -> OPEN. TODO\n\n"
        "IMPACT:\nTODO: concrete asset/actor/magnitude.")
    examples.append(reject)

    store = {"version": curated.get("version", 1), "examples": examples}
    (sft_dir / "examples.json").write_text(
        json.dumps(store, indent=2, ensure_ascii=False) + "\n")

    # lint fixtures (files, not store rows).
    pass_ex = json.loads(json.dumps(examples[0]))
    pass_ex["status"] = "curated"
    pass_ex["partition"] = None
    pass_ex["structured"]["claim"] = (
        "An unguarded share-price read lets a first depositor inflate the "
        "exchange rate and mint the victim's deposit as zero shares.")
    (sft_dir / "lint-pass.json").write_text(
        json.dumps(pass_ex, indent=2, ensure_ascii=False) + "\n")

    dedup_ex = json.loads(json.dumps(examples[0]))
    dedup_ex["partition"] = None
    (sft_dir / "lint-dedup.json").write_text(
        json.dumps(dedup_ex, indent=2, ensure_ascii=False) + "\n")

    reject_ex = json.loads(json.dumps(reject))
    (sft_dir / "lint-reject.json").write_text(
        json.dumps(reject_ex, indent=2, ensure_ascii=False) + "\n")

    # Every fixture the reference reads must pass its own schema (the lint
    # itself would report a schema error instead of the rubric reason).
    from webv2.validation import validate
    for ex in examples + [pass_ex, dedup_ex, reject_ex]:
        validate(ex, "sft_example")
    print(f"sft store: {len(examples)} examples "
          f"({sum(1 for e in examples if e['status'] == 'curated')} curated, "
          f"{sum(1 for e in examples if e['status'] == 'draft')} draft) + "
          "3 lint fixtures")


def build(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    maps = TX.load_maps(["defihacklabs"])
    records = DfH.load_records()
    picked = select(records, maps)
    print(f"selected {len(picked)} records across "
          f"{len({TX.normalize_class(r['bug_class_label'], maps)[0] for r in picked})} classes")
    data_root = dest / "datasets"
    write_slice(picked, data_root)
    slice_records = verify_slice(data_root, picked)
    for rec in slice_records:
        print(f"  {rec['partition']:9} {rec['id']} "
              f"{TX.normalize_class(rec['bug_class_label'], maps)[0]}")
    # Everything downstream is built from the SLICE's own records: the
    # leakage partition is a function of the record set, so the fixture's
    # eval/shared stores must carry the slice's partitions, not the full
    # corpus's.
    build_eval(dest, slice_records, maps)
    build_shared(dest, slice_records, maps)
    build_sft(dest)


SKIP = {"build.py", "README.md"}


def digest(root: Path) -> dict[str, str]:
    """Content digest of the GENERATED fixture (the builder and its README
    are not part of the fixture bytes)."""
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.relative_to(root).as_posix() not in SKIP:
            out[p.relative_to(root).as_posix()] = hashlib.sha256(
                p.read_bytes()).hexdigest()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    os.environ["WEBV2_NOW"] = BUILD_NOW
    if not args.check:
        for name in ("datasets", "eval", "shared-memory", "sft"):
            shutil.rmtree(FIX / name, ignore_errors=True)
        build(FIX)
        total = sum(p.stat().st_size for p in FIX.rglob("*") if p.is_file())
        print(f"fixture written to {FIX} ({total} bytes)")
        return 0
    tmp = Path(tempfile.mkdtemp(prefix="p4-fixture-check-"))
    try:
        build(tmp)
        a, b = digest(FIX), digest(tmp)
        bad = 0
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                print(f"DIFF {k}")
                bad += 1
        if bad:
            print(f"fixture check RED: {bad} file(s) differ")
            return 1
        print(f"fixture check GREEN: {len(a)} files reproduce byte-for-byte")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
