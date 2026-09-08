"""Generate the byte-exact vectors for the Go invariants port (Task 8).

Oracle: the live Python reference (web3sec-final, REPO below), not hand-written
expectations. Writes goldens into internal/invariants/testdata/:

  docscan_tree.json / docscan_expected.json / intent_expected.json /
  docref_expected.json   the doc-scan and intent-claim corpus
  normalize_vectors.json / coverage_vectors.json / uncovered_vectors.json
  reconcile_vectors.json
  scenario_*.json[l]     the scripted link/verify/contradict replay, including
                         the raw invariant_links.json and hash-chained
                         events.jsonl so the Go side can compare bytes
  guard_messages.json / guard_links.json / guard_events.jsonl
                         the guardrail's exact error strings

Deterministic: the clock is pinned with WEBV2_NOW and every id is fixed here,
so re-running against the same Python tree reproduces the goldens byte for
byte (verified). Run from anywhere:  python3 scripts/invariants-vectors.py
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
from pathlib import Path

REPO = Path("/home/xand/Projects/dsh-plugins/websec2/web3sec-final")
GODIR = Path("/home/xand/Projects/dsh-plugins/websec2/web3sec-go")
sys.path.insert(0, str(REPO / "src"))
os.environ["WEBV2_NOW"] = "2026-02-01T00:00:00.000000+00:00"

from webv2 import invariants as INV  # noqa: E402
from webv2.state import Campaign  # noqa: E402
from webv2.validation import write_json  # noqa: E402

TD = GODIR / "internal" / "invariants" / "testdata"
TD.mkdir(parents=True, exist_ok=True)
SCRATCH = GODIR / ".scratch" / "t8_pyvec"
if SCRATCH.exists():
    shutil.rmtree(SCRATCH)
SCRATCH.mkdir(parents=True)


def dump(name: str, obj) -> None:
    (TD / name).write_text(
        json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def new_camp(name: str, cid: str) -> Campaign:
    root = SCRATCH / name
    root.mkdir(parents=True, exist_ok=True)
    return Campaign.init(root, "vec program", campaign_id=cid)


# ---------------------------------------------------------------- doc tree
LONG = "INV-31 " + "x" * 260 + " tail"
TREE = [
    ("README.md",
     b"# Protocol\n"
     b"INV-1 balances move atomically\n"
     b"INV-002 fees accrue to the treasury\n"
     b"prefix INV-0003 with leading text\n"
     b"xINV-4 no left boundary\n"
     b"INV-5_ underscore is a word char\n"
     b"INV-12345 too many digits\n"
     b"INV-0001 duplicate canonical id\n"
     b"INV-6\xc3\xa9 unicode word char follows\n"
     b"\xc3\xa9INV-7 unicode word char before\n"
     b"INV-8: colon boundary\n"
     b"INV-9\t tab boundary\n"),
    ("a.md", b"INV-1 duplicate in a.md\nINV-20 only here\n"),
    ("a/b.md", b"INV-21 in subdir\nINV-20 duplicate later file\n"),
    ("docs/spec.rst",
     b"INV-30 in rst\n"
     b"\x0bINV-32 vertical tab break\n"
     b"\x1cINV-33 fs break\n"
     b"\x85INV-34 nel break\n"
     b"\xe2\x80\xa8INV-35 line separator\n"
     b"INV-36 caf\xc3\xa9 ok\n"),
    ("docs/notes.txt",
     b"INV-37 invalid utf8 follows \xff\xff end\n"
     b"INV-38 truncated \xe2\x82 end\n"
     b"INV-39 overlong \xc0\x80 end\n"),
    ("docs/page.adoc", b"INV-40 adoc\n"),
    ("docs/UPPER.MD", b"INV-41 upper suffix\n"),
    ("docs/.md", b"INV-42 hidden all-dot name\n"),
    ("docs/..md", b"INV-43 hidden two-dot name\n"),
    ("docs/a.", b"INV-44 trailing dot suffix\n"),
    ("src/Vault.sol", b"// INV-45 not a doc suffix\n"),
    ("crlf.txt", b"INV-46 crlf line\r\nINV-47 next line\r\n"),
    ("long.md", (LONG + "\nINV-48 short\n").encode("utf-8")),
    ("ws.md", "  \u00a0INV-49 spaced\x1f  \n".encode("utf-8")),
    ("intent.md",
     b"# intent language\n"
     b"INV-50 the fee accrual is by design\n"
     b"INV-51 stakers get the donation which accrues pro rata\n"
     b"INV-52 this is expected behavior\n"
     b"INV-53 meant to be harmless\n"
     b"INV-54 not a bug\n"
     b"INV-55 accrue\n"
     b"INV-56 intentional\n"
     b"INV-57 intentionally broken\n"
     b"INV-58 designed to help\n"
     b"INV-59 as intended\n"
     b"INV-60 expected outcome\n"
     b"INV-61 by-design choice\n"
     b"INV-62 by design choice\n"
     b"INV-63 donation that accrue\n"
     b"INV-64 donation accrues to staker\n"
     b"INV-65 donations accrue\n"
     b"INV-66 donation " + b"y" * 41 + b" accrue\n"
     b"INV-67 no intent here at all\n"
     b"INV-68 account accrues value\n"
     b"INV-69 donated to charity\n"
     b"INV-70 intentIOnAlly done\n"),
    ("intent2.md",
     b"context above\nby design\nINV-71 window intent\n"
     b"INV-72\nintentional\n"
     b"INV-73\n\n\n\nby design\n"
     b"INV-74\n\n\nby design\n"),
    ("intent3.md",
     b"INV-90 donation " + b"y" * 38 + b" staker\n\n\n\n"
     b"INV-91 donation " + b"y" * 39 + b" staker\n\n\n\n"
     b"INV-92 donationX staker\n\n\n\n"
     b"INV-93 donation-s staker\n\n\n\n"
     b"INV-94 donationsX staker\n\n\n\n"
     b"INV-95 accrue\xc3\xa9\n\n\n\n"
     b"INV-96 \xc3\xa9accrue\n\n\n\n"
     b"INV-97 not a vulnerability\n\n\n\n"
     b"INV-98 not a concern\n\n\n\n"
     b"INV-99 BY DESIGN\n\n\n\n"
     b"INV-100 ACCRUE\n"),
]
spec = [{"path": p, "b64": base64.b64encode(b).decode("ascii")} for p, b in TREE]
dump("docscan_tree.json", {"files": spec})

camp = new_camp("docs", "C-vec00001")
snap = camp.dir / "snapshots" / "SNAPX"
snap.mkdir(parents=True)
for rel, data in TREE:
    p = snap / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

dump("docscan_expected.json", INV.documented_invariants(camp, "SNAPX"))
dump("intent_expected.json", INV.intent_claims(camp, "SNAPX"))
dump("docref_expected.json", {
    "INV-1": INV.documented_ref(camp, "INV-1", "SNAPX"),
    "INV-001": INV.documented_ref(camp, "INV-001", "SNAPX"),
    "INV-999": INV.documented_ref(camp, "INV-999", "SNAPX"),
    "nope": INV.documented_ref(camp, "nope", "SNAPX"),
})
dump("docscan_missing_snapshot.json", INV.documented_invariants(camp, "NOPE"))
dump("intent_missing_snapshot.json", INV.intent_claims(camp, "NOPE"))

# ------------------------------------------------------------ normalize ids
NORM_INPUTS = [
    "INV-1", "INV-001", "INV-0000", "INV-0", "INV-000000000000000000001",
    "INV-12345", "INV-1234", "INV-", "INV-1a", "inv-1", "INV-1 ", " INV-1",
    "INV-1\n", "INV-1\n\n", "INV-1\r", "INV-1\r\n", "INV-12-3", "INV-1.0",
    "INV-١٢", "INV-١٢٣", "INV-000١", "INV-²", "INV-٠٠١",
    "INV-1é", "éINV-1", "XINV-1", "INV-1_", "INV-1_2", "INV-99999999",
    "", "INV", "-INV-1", "INV-INV-1", "INV-1INV-2",
]
dump("normalize_vectors.json",
     [{"in": s, "out": INV.normalize_inv_id(s)} for s in NORM_INPUTS])

# --------------------------------------------------------- coverage vectors
def entry(ts, source="model", status="UNVERIFIED"):
    return {"statement": "s", "kind": "security", "severity_if_broken": "high",
            "applies_to": [], "test_status": ts, "status": status,
            "model_belief": None, "depends_on": [], "modified_by": None,
            "source": source, "findings": [], "tests": [], "detectors": [],
            "updated_at": "2026-02-01T00:00:00.000000+00:00"}


COVERAGE_CASES = []


def cov_case(name, reg):
    c = new_camp("cov_" + name, "C-vec00002")
    INV.save_links(c, {"invariants": reg})
    COVERAGE_CASES.append({"name": name, "links": {"invariants": reg},
                           "expected": INV.coverage(c)})


cov_case("empty", {})
cov_case("mixed", {
    "INV-1": entry("held"), "INV-002": entry("violated"),
    "INV-3": entry("untested"), "INV-4": entry("untestable"),
    "INV-5": entry("weird"), "INV-6": {},
})
cov_case("thirds", {"INV-1": entry("held"), "INV-2": entry("untested"),
                    "INV-3": entry("untested")})
cov_case("sixteenth", {"INV-1": entry("held")} | {
    f"INV-{i}": entry("untested") for i in range(2, 17)})
cov_case("eighths", {"INV-1": entry("held"), "INV-2": entry("held"),
                     "INV-3": entry("violated")} | {
    f"INV-{i}": entry("untested") for i in range(4, 9)})
cov_case("all_violated", {"INV-2": entry("violated"),
                          "INV-1": entry("violated")})
dump("coverage_vectors.json", COVERAGE_CASES)

# ------------------------------------------------------------ link scenario
sc = new_camp("scenario", "C-vec00003")
state = sc.state()
state["active_snapshot_id"] = "SNAPX"
state["artifacts"] = [
    {"artifact_id": "OTH-fixed001", "kind": "other",
     "path": str(sc.artifacts_dir / "inv-check.md"),
     "registered_at": "2026-02-01T00:00:00.000000+00:00", "sha256": None,
     "snapshot_id": None, "note": ""},
    {"artifact_id": "OTH-fixed002", "kind": "other",
     "path": str(sc.artifacts_dir / "fuzz.md"),
     "registered_at": "2026-02-01T00:00:00.000000+00:00", "sha256": None,
     "snapshot_id": None, "note": ""},
]
write_json(sc.state_path, state, "campaign_state")
snap2 = sc.dir / "snapshots" / "SNAPX"
snap2.mkdir(parents=True)
(snap2 / "README.md").write_text(
    "INV-1 totalAssets never decreases except via withdraw\n", encoding="utf-8")

MODEL = {"invariants": [
    {"id": "INV-1",
     "statement": "totalAssets never decreases except via withdraw",
     "severity_if_broken": "critical"},
    {"id": "INV-2", "statement": "fee accumulator cannot be set backwards",
     "severity_if_broken": "high", "model_belief": 0.6, "depends_on": ["INV-1"],
     "modified_by": "model-proposer pass 2", "status": "CHECKED_AGAINST_CODE"},
    {"id": "INV-3", "statement": "only the owner may pause", "kind": "access"},
], "state_machines": [{"name": "rollup"}, {"name": "vault"}, {"name": ""}]}

steps = []


def snap_step(label):
    steps.append({"label": label, "links": INV.load_links(sc)})


INV.seed_from_model(sc, MODEL)
snap_step("seed")
INV.link_finding(sc, "INV-2", "F-aaaaaaaaaaaa", violated=True)
snap_step("link_finding_violated")
INV.link_finding(sc, "INV-2", "F-aaaaaaaaaaaa")
snap_step("link_finding_dup")
INV.link_finding(sc, "INV-1", "F-bbbbbbbbbbbb")
snap_step("link_finding_inv1")
INV.link_test(sc, "INV-2", "OTH-fixed002")
snap_step("link_test")
INV.verify_invariant_statement(sc, "INV-2", "OTH-fixed001")
snap_step("verify")
INV.contradict_invariant_statement(sc, "INV-1", "src/V.sol#L40")
snap_step("contradict")
INV.verify_invariant_statement(sc, "INV-3", "OTH-fixed001")
snap_step("verify_inv3")
INV.verify_invariant_statement(sc, "INV-3", "OTH-fixed002")
snap_step("verify_inv3_again")
INV.contradict_invariant_statement(sc, "INV-3", "src/V.sol#L1")
snap_step("contradict_inv3")
links = INV.load_links(sc)
links["invariants"]["INV-4"] = {
    "statement": "legacy claim", "status": "held",
    "findings": [], "tests": [], "detectors": []}
INV.save_links(sc, links)
snap_step("legacy_raw")
INV.link_test(sc, "INV-4", "OTH-fixed002")
snap_step("legacy_migrated")
INV.load_links(sc)
snap_step("legacy_second_read")
dump("scenario_steps.json", steps)
dump("scenario_coverage.json", INV.coverage(sc))
dump("scenario_uncovered.json", INV.uncovered_critical(sc, MODEL))
dump("scenario_model.json", MODEL)

# ------------------------------------------------------------- reconcile
rec = new_camp("reconcile", "C-vec00004")
st = rec.state()
st["active_snapshot_id"] = "SNAPX"
write_json(rec.state_path, st, "campaign_state")
snap3 = rec.dir / "snapshots" / "SNAPX"
snap3.mkdir(parents=True)
(snap3 / "README.md").write_text(
    "INV-1 balances move atomically\nINV-002 fees accrue to the treasury\n",
    encoding="utf-8")


def model_of(ids):
    return {"invariants": [
        {"id": i, "statement": f"statement of {i}", "kind": "security",
         "severity_if_broken": "high", "applies_to": []} for i in ids]}


dump("reconcile_vectors.json", [
    {"ids": ["INV-1", "INV-2"],
     "rep": INV.reconcile(rec, model_of(["INV-1", "INV-2"]))},
    {"ids": ["INV-1"], "rep": INV.reconcile(rec, model_of(["INV-1"]))},
    {"ids": ["INV-1", "INV-2", "INV-9"],
     "rep": INV.reconcile(rec, model_of(["INV-1", "INV-2", "INV-9"]))},
    {"ids": ["INV-001", "INV-2"],
     "rep": INV.reconcile(rec, model_of(["INV-001", "INV-2"]))},
])

# ------------------------------------------------------------- guard errors
gc = new_camp("guard", "C-vec00005")
gst = gc.state()
gst["active_snapshot_id"] = "SNAPX"
gst["artifacts"] = [
    {"artifact_id": "OTH-fixed001", "kind": "other",
     "path": str(gc.artifacts_dir / "inv-check.md"),
     "registered_at": "2026-02-01T00:00:00.000000+00:00", "sha256": None,
     "snapshot_id": None, "note": ""}]
write_json(gc.state_path, gst, "campaign_state")
gsnap = gc.dir / "snapshots" / "SNAPX"
gsnap.mkdir(parents=True)
(gsnap / "README.md").write_text(
    "INV-1 totalAssets never decreases except via withdraw\n", encoding="utf-8")
INV.seed_from_model(gc, MODEL)
from webv2 import findings as F  # noqa: E402

guard_msgs = []


def guard(label, finding):
    try:
        F._assert_invariants_verified(gc, finding)
        guard_msgs.append({"label": label, "error": None})
    except ValueError as exc:
        guard_msgs.append({"label": label, "error": str(exc)})


guard("unverified_model", {"security_invariants": [{"id": "INV-2"}]})
guard("unknown_id", {"security_invariants": [{"id": "INV-999"}]})
guard("zero_padded_unknown", {"security_invariants": [{"id": "INV-9990"}]})
guard("documented_exempt", {"security_invariants": [{"id": "INV-1"}]})
guard("documented_zero_padded", {"security_invariants": [{"id": "INV-01"}]})
guard("no_invariants", {"security_invariants": []})
guard("singular_invariant", {"invariant": {"id": "INV-2"}})
guard("both_halves", {"invariant": {"id": "INV-2"},
                      "security_invariants": [{"id": "INV-2"},
                                              {"id": "INV-1"}]})
guard("non_dict_entries", {"security_invariants": ["INV-2", 5, None]})
guard("no_sec_key", {"title": "x"})
INV.verify_invariant_statement(gc, "INV-2", "OTH-fixed001")
guard("verified_passes", {"security_invariants": [{"id": "INV-2"}]})
dump("guard_messages.json", guard_msgs)

# ------------------------------------------------------------- uncovered
uc = new_camp("uncovered", "C-vec00006")


def _entry(statement, test_status="untested"):
    e = {"statement": statement, "status": "UNVERIFIED", "source": "model",
         "findings": [], "tests": [], "detectors": []}
    if test_status is not None:
        e["test_status"] = test_status
    return e


INV.save_links(uc, {"invariants": {
    "INV-1": _entry("a"),
    "INV-2": _entry("b", "untestable"),
    "INV-3": _entry("c", "held"),
    "INV-4": _entry("d", "violated"),
    "INV-005": _entry("e"),
    "INV-6": _entry("f", None),
    "INV-10": _entry("k"),
}})
UNCOV_MODEL = {"invariants": [
    {"id": "INV-1", "statement": "a", "severity_if_broken": "critical"},
    {"id": "INV-2", "statement": "b", "severity_if_broken": "high"},
    {"id": "INV-3", "statement": "c", "severity_if_broken": "critical"},
    {"id": "INV-4", "statement": "d", "severity_if_broken": "high"},
    {"id": "INV-5", "statement": "e", "severity_if_broken": "critical",
     "applies_to": ["vault"]},
    {"id": "INV-6", "statement": "f", "severity_if_broken": "critical"},
    {"id": "INV-7", "statement": "g", "severity_if_broken": "medium"},
    {"id": "INV-8", "statement": "h"},
    {"id": "INV-9", "statement": "i", "severity_if_broken": "critical"},
    {"id": "INV-010", "statement": "k", "severity_if_broken": "high"},
]}
dump("uncovered_links.json", INV.load_links(uc))
dump("uncovered_model.json", UNCOV_MODEL)
dump("uncovered_vectors.json", INV.uncovered_critical(uc, UNCOV_MODEL))

# raw twin artifacts: the strongest byte-exact comparison (hash chain included)
shutil.copyfile(sc.artifacts_dir / "invariant_links.json",
                TD / "scenario_links.json")
shutil.copyfile(sc.events_path, TD / "scenario_events.jsonl")
shutil.copyfile(gc.artifacts_dir / "invariant_links.json",
                TD / "guard_links.json")
shutil.copyfile(gc.events_path, TD / "guard_events.jsonl")

print("wrote", sorted(p.name for p in TD.iterdir()))
