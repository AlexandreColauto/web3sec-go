#!/usr/bin/env bash
#
# verify-full.sh — the single entry point that proves the repo is clean.
#
# One command (a human or CI) runs to know whether every gate is green:
# thirteen ordered steps, fail-fast with the failing step's name.
#
#   1.  go vet ./... clean
#   2.  go build ./cmd/webv2 -> /tmp/webv2
#   3.  go test ./... PASS
#   4.  go test -race ./... PASS (hard gate from day one — design 7.1)
#   5.  go test -count=1 ./... twice; normalized output identical
#       (Go==Go determinism run — design 7.1)
#   6.  asset-pack integrity: the embedded schema/archetype/playbook/prompt
#       packs match their committed SHA-256 manifest (assets package test)
#   7.  scripts/golden.sh green (Go-only since the P4 cutover)
#   8.  crash smoke: audit/verify on a truncated events.jsonl must
#       produce a verdict, not a panic (Task 7 + hardening 7.2)
#   9.  legacy cross-audit: a campaign written by the retired Python
#       reference (committed fixture, scripts/legacy/) audits + verifies
#       clean in Go, with all 15 rendered sections (17 registered; `eval` and
#       `price_table` are presence-gated, v16_coverage unconditional) and the
#       P2/P3 state readable
#  10.  P1 CLI smoke: the 21 P1 commands each invoked once in a valid shape
#       against a scratch Go campaign, asserting documented exit codes
#  11.  P2 CLI smoke: the P2 commands each invoked once in a valid shape
#       against a scratch Go campaign (exec ledger, mint, the full ladder
#       lifecycle, chains/terminals/privileged, impact, sequence verify),
#       asserting documented exit codes
#  12.  P3 CLI smoke: the P3 commands each invoked once in a valid shape
#       against a scratch Go campaign (structural surface, probes, memory/
#       publish, briefing/report, baselines/forkdiff, costs, run), then
#       the full audit + verify of the finished smoke campaign
#
# History: steps 6-8 of the pre-retirement form of this script byte-diffed
# schemas against the Python twin, ran the reference pytest suite, and
# cross-audited live between the twins. The twin was retired 2026-09-09
# (docs/archive/KNOWN_DIVERGENCES.md banner; docs/gates/P4-gate.md §9.1);
# step 9's committed fixture carries the reader-compatibility half of that
# coverage with zero external dependencies. Steps 10-12 build their
# campaigns with P2 state (exec/mint/ladder/chains/impact) AND P3 state
# (snap/index/sinks/prescreen/probes+emit/relations, a disproved rung's
# queued memory row, report.md), so the audit covers all 15 unconditional
# sections (17 registered; `eval` and `price_table` are presence-gated) incl.
# sequence_coverage and probe_surface. Step 12 also prices the campaign
# before auditing, so ITS report carries the presence-gated price_table row
# too (16 sections); steps 9-11 never price and render exactly 15.
#
# Exits non-zero at the first failing step, naming it.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# The Go caches live under .scratch so the script works in sandboxed
# environments where $HOME is not writable (GOPATH may be preset to a
# read-only location, so force both — the module set is two small deps
# and the cache persists in .scratch after the first run).
export GOCACHE="$ROOT/.scratch/gocache"
export GOPATH="$ROOT/.scratch/gomod"
export GOMODCACHE="$ROOT/.scratch/gomod/pkg/mod"

fail() {
  echo
  echo "FAIL [step $1: $2]"
  exit 1
}

TOTAL_STEPS=13

step() {
  echo
  echo "=== step $1/$TOTAL_STEPS: $2 ==="
}

# 1. vet ---------------------------------------------------------------
step 1 "go vet"
go vet ./... 2>&1 || fail 1 "go vet"
echo "ok: vet clean"

# 2. build -------------------------------------------------------------
step 2 "go build -> /tmp/webv2"
go build -o /tmp/webv2 ./cmd/webv2 || fail 2 "go build"
echo "ok: /tmp/webv2 built"

# 3. test --------------------------------------------------------------
step 3 "go test"
go test ./... 2>&1 || fail 3 "go test"
echo "ok: tests pass"

# 4. race --------------------------------------------------------------
step 4 "go test -race"
go test -race ./... 2>&1 || fail 4 "go test -race"
echo "ok: race clean"

# 5. Go==Go determinism -------------------------------------------------
step 5 "go test -count=1 twice, identical"
# Strip durations: plain output ends lines with " 0.019s"; -v output
# wraps them in parens after each test name.
norm() {
  sed -E -e 's/[[:blank:]]([0-9]+(\.[0-9]+)?s)$//' \
         -e 's/ \([0-9]+(\.[0-9]+)?s\)//g'
}
go test -count=1 ./... 2>&1 | norm > .scratch/gotest-run1.txt
go test -count=1 ./... 2>&1 | norm > .scratch/gotest-run2.txt
if ! diff -u .scratch/gotest-run1.txt .scratch/gotest-run2.txt; then
  fail 5 "go test -count=1 determinism"
fi
echo "ok: two fresh runs byte-identical (durations stripped)"

# 6. asset-pack integrity ----------------------------------------------
step 6 "asset-pack manifest"
go test ./assets -run TestAssetPackManifest -count=1 || fail 6 "asset manifest"
echo "ok: every embedded asset byte-matches the committed manifest"

# 7. golden suite ---------------------------------------------------------
step 7 "golden.sh"
scripts/golden.sh || fail 7 "golden.sh"

# 8. crash smoke ----------------------------------------------------------
step 8 "crash smoke: truncated events.jsonl"
SMOKE="$(mktemp -d)"
CID="$(/tmp/webv2 --root "$SMOKE" init --program Smoke 2>/dev/null \
  | grep -o 'C-[0-9a-f]*' | head -1)"
[ -n "$CID" ] || fail 8 "smoke init"
/tmp/webv2 --root "$SMOKE" snap "$CID" "$ROOT/assets/schema" >/dev/null 2>&1 \
  || fail 8 "smoke snap"
cp -r "$SMOKE" "$SMOKE-trunc"
ELOG="$SMOKE-trunc/campaigns/$CID/events.jsonl"
head -c $(( $(stat -c%s "$ELOG") / 2 )) "$ELOG" > "$ELOG.tmp"
mv "$ELOG.tmp" "$ELOG"
# audit: a clean error or a verdict — never a panic (exit 2 / "panic:").
AOUT="$(/tmp/webv2 --root "$SMOKE-trunc" audit "$CID" 2>&1)"
AEXIT=$?
# verify: must print its JSON verdict.
VOUT="$(/tmp/webv2 --root "$SMOKE-trunc" verify "$CID" 2>/dev/null)"
VEXIT=$?
if [ "$AEXIT" -ge 2 ] || grep -q "panic:" <<<"$AOUT" \
   || [ "$VEXIT" -ge 2 ] || grep -q "panic:" <<<"$VOUT"; then
  echo "audit exit=$AEXIT: $AOUT"
  echo "verify exit=$VEXIT: $VOUT"
  fail 8 "crash smoke (panic or bad exit)"
fi
echo "$VOUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "ok" in d' \
  || fail 8 "verify verdict not JSON"
echo "ok: audit/verify handle a corrupted log without panicking"
rm -rf "$SMOKE" "$SMOKE-trunc"

# --- shared machinery for steps 9-12 ------------------------------------
# The pinned clock (WEBV2_NOW, +1s per step, reset per campaign) and the
# pinned id stream (WEBV2_UUID, one seed PER STEP — golden v3's rule). The
# legacy fixture (step 9) was built by the Python twin under exactly this
# discipline before the retirement; the smoke campaigns (steps 10-12) use
# it for Go==Go reproducibility. Scratch lives under .scratch/verify-p1/.
P1F="$ROOT/.scratch/verify-p1"
P1BIN="$P1F/webv2"
mkdir -p "$P1F"
# The pinned-clock harness drives the SAME binary the gate builds in step 2,
# rebuilt to a stable path (steps 9-12 run it many times; /tmp/webv2 stays
# for the crash smoke).
go build -o "$P1BIN" ./cmd/webv2 || { echo "FAIL: build $P1BIN"; exit 1; }
# The probe fixture's own blind contract: one contract whose accumulator
# axis rejects every site it sees, so `probes blank` has a disposition to
# record. Used by the P3 smoke's structural leg.
P3_FIXTURE="$ROOT/internal/probes/testdata/probes/accumulator/blind"
P1_SEED="verify-p1-cross"
# The step counter lives in a FILE: every run_p1 call sits inside $(...) — a
# subshell — so a shell variable cannot carry the number back out.
P1_COUNTER="$P1F/step-counter"
p1_step_reset() { P1_STEP=0; printf '0\n' > "$P1_COUNTER"; }
p1_step_reset

# run_p1 ROOT ARGV... — one pinned-clock CLI invocation against the Go binary.
run_p1() {
  local root="$1"
  shift 1
  P1_STEP=$(( $(cat "$P1_COUNTER" 2>/dev/null || echo 0) + 1 ))
  printf '%s\n' "$P1_STEP" > "$P1_COUNTER"
  local now
  now="$(date -u -d "2026-09-09T12:00:00Z + ${P1_STEP} seconds" \
    +%Y-%m-%dT%H:%M:%S.000000+00:00)"
  # Per-step seed (golden v3's fix): every CLI invocation is a fresh process
  # whose new_id counter restarts at 0, so a single seed would make the first
  # id of EVERY command identical (two `exec` calls would mint the same EXEC-).
  local seed="$P1_SEED:$P1_STEP"
  # WEBV2_BASELINES_DIR keeps the baseline store out of the repo (D24).
  WEBV2_NOW="$now" WEBV2_UUID="$seed" WEBV2_BASELINES_DIR="$P1F/baselines" \
    "$P1BIN" --root "$root" "$@"
}

# seed_p2_exec ROOT CID FID EXEC_ID — write an externally-reported
# docker-networkless E4 exec record (the same shape scripts/golden-run.py
# seeds). It is HARNESS INPUT and lets the docker-free smoke steps exercise
# `mint` (which refuses host-readonly: "E4+ evidence requires a
# container/VM profile").
seed_p2_exec() {
  local root="$1" cid="$2" fid="$3" exid="$4"
  local d="$root/campaigns/$cid/execs/$exid"
  mkdir -p "$d" || return 1
  # forge-meaningfulness: `mint` refuses output with no test counters /
  # PASS marker, so the seeded stdout is the golden's exact string.
  printf 'Suite result: ok. 1 passed; 0 failed\n' > "$d/stdout.log"
  : > "$d/stderr.log"
  python3 - "$d" "$cid" "$fid" "$exid" <<'PY'
import hashlib, json, pathlib, sys
d, cid, fid, exid = sys.argv[1:5]
d = pathlib.Path(d)
h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
at = "2026-09-09T12:00:59.000000+00:00"
rec = {
    "exec_id": exid,
    "campaign_id": cid,
    "profile": "docker-networkless",
    "finding_id": fid,
    "artifact_id": None,
    "command": "forge test --match-test test_p2_cross",
    "workdir": None,
    "policy_verdict": {
        "allowed": True, "violations": [],
        "checked_rules": ["network-egress-tool", "privilege-escalation",
                          "destructive-path", "secret-access",
                          "external-publish", "system-write"]},
    "environment": {"tool_versions": {}, "env_keys": [],
                    "network_access": "none", "filesystem": "sandbox-tmp"},
    "container": None,
    "origin": "externally-reported",
    "reported_by": "verify-full-harness",
    "input_hashes": {},
    "started_at": at, "finished_at": at,
    "exit_status": 0,
    "stdout_path": str(d / "stdout.log"),
    "stderr_path": str(d / "stderr.log"),
    "artifact_hashes": {
        "stdout.log": h(d / "stdout.log"),
        "stderr.log": h(d / "stderr.log")},
}
(d / "exec_record.json").write_text(json.dumps(rec, indent=1) + "\n")
PY
}

# p2_sections_ok LABEL JSON — the audit --json report must carry the 14
# unconditional ported sections in the reference's order, sequence_coverage
# included (D2 closed), PLUS the v1.6 coverage section (unconditional since
# v1.6 P1/P2, registered after price_table), PLUS any of the presence-gated
# extras that render. `eval` is presence-gated since G4 and `price_table`
# since r4: each returns sections.ErrSkip when its precondition is closed, and
# AuditCampaign omits a skipped section from the report
# (internal/audit/audit.go; internal/audit/sections/pricetable.go). Step 12
# PRICES the campaign (`price set`) before it audits, so its report
# legitimately carries price_table — while step 9's legacy fixture and step
# 11's smoke campaign never priced anything and must still render exactly 15
# (14 + v16_coverage). So the gate is "14 base + v16_coverage, in order, plus
# an allowed presence-gated tail" — it must NOT be relaxed to a bare count,
# which would make a never-priced campaign that silently grew a fake price row
# pass, or a campaign whose coverage section vanished pass. Mirrors the
# allowance in scripts/check-golden.py's check_audit (its EXPECTED_SECTIONS
# keeps the 14 unconditional rows + v16_coverage and treats the presence-gated
# tail as optional): the base rows and the registration ORDER of whatever
# renders are hard failures; only the presence-gated tail is optional.
p2_sections_ok() {
  python3 -c '
import json, sys
label = sys.argv[1]
d = json.load(sys.stdin)
secs = d.get("sections") or {}
want = ["event_log", "artifacts", "execs", "findings", "projection",
        "snapshots", "relations", "floor_policy", "stage_completions",
        "baselines", "invariant_verification", "sequence_coverage",
        "probe_surface", "unpriceable"]
# Unconditional since v1.6, in registration order after the presence-gated
# tail (internal/audit/sections/register.go).
always = ["v16_coverage"]
# Presence-gated, in registration order: eval then price_table.
gated = ["eval", "price_table"]
required = want + always
missing = [x for x in required if x not in secs]
assert not missing, f"{label}: missing sections {missing}"
extra = [x for x in secs if x not in required and x not in gated]
assert not extra, f"{label}: unexpected sections {extra}"
# Order: what rendered must equal the registration-order projection of the
# base rows plus whatever gated rows rendered.
proj = [n for n in want + gated + always if n in secs]
assert list(secs) == proj, (f"{label}: sections out of registration order: "
                            f"{list(secs)} vs {proj}")
on = [n for n in gated if n in secs]
print(f"  ok {label}: {len(secs)} audit sections = 14 base + v16_coverage"
      + (f" + presence-gated {on}" if on else " (no presence-gated section rendered)")
      + ", incl sequence_coverage")
' "$1" <<<"$2"
}

# p2_full_read ROOT CID LABEL — every P2/P3-state reader must work against
# the campaign at ROOT (step 9 feeds this the LEGACY fixture: Go readers on
# Python-written state; the smoke steps feed it their own campaigns).
p2_full_read() {
  local root="$1" cid="$2" label="$3" out ladf fid
  out="$(run_p1 "$root" execs "$cid" --json 2>&1)" \
    || { echo "$out" >&2; echo "$label: execs --json failed" >&2; return 1; }
  python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d) >= 3, f"{len(d)} exec record(s), want >= 3"
print(f"  ok {sys.argv[1]}: {len(d)} exec records readable")
' "$label" <<<"$out" || return 1
  ladf="$(ls "$root/campaigns/$cid"/ladders/*.json 2>/dev/null | head -1)"
  [ -n "$ladf" ] || { echo "$label: no ladder file" >&2; return 1; }
  fid="$(basename "${ladf%.json}")"
  out="$(run_p1 "$root" ladder "$cid" report "$fid" 2>&1)" \
    || { echo "$out" >&2; echo "$label: ladder report failed" >&2; return 1; }
  grep -q '"disposition"' <<<"$out" \
    || { echo "$out" >&2; echo "$label: ladder report has no disposition" >&2; return 1; }
  grep -q '"state": "complete"' <<<"$out" \
    || { echo "$out" >&2; echo "$label: ladder is not complete" >&2; return 1; }
  echo "  ok $label: ladder report reads the completed ladder"
  out="$(run_p1 "$root" memory "$cid" 2>&1)" \
    || { echo "$out" >&2; echo "$label: memory failed" >&2; return 1; }
  grep -qE 'MEM-[0-9a-f]+' <<<"$out" \
    || { echo "$out" >&2; echo "$label: no queued memory row" >&2; return 1; }
  echo "  ok $label: memory view reads the queued negative row"
  out="$(run_p1 "$root" probes "$cid" list --all --json 2>&1)" \
    || { echo "$out" >&2; echo "$label: probes list --json failed" >&2; return 1; }
  python3 -c '
import json, sys
d = json.load(sys.stdin)
# `rows` counts EMITTED candidates: the blind fixture emits none, so the
# reader asserts the published AXES (with their blind keys) and the index
# pin instead.
axes = d.get("axes") or []
assert axes, f"no probe axes: {d}"
assert d.get("index_sha"), "no index_sha"
blind = sum(1 for a in axes if a.get("status") == "blind")
print(f"  ok {sys.argv[1]}: {len(axes)} probe axes ({blind} blind) readable")
' "$label" <<<"$out" || return 1
}

# 9. legacy cross-audit ---------------------------------------------------
# scripts/legacy/campaigns/C-45488bdaf5 was built END TO END BY THE PYTHON
# REFERENCE (its final cross-audit run, 2026-09-09 — the full P1+P2+P3 op
# sequence, pinned clock + id stream) and committed as a reader-
# compatibility fixture: everything the Go auditors and readers must accept
# from Python-era state. See scripts/legacy/README.md.
step 9 "legacy cross-audit: a reference-written campaign audits clean in Go"
LEGACY_ID=C-45488bdaf5
LEGACY_ROOT="$P1F/legacy"
rm -rf "$P1F/legacy"
mkdir -p "$LEGACY_ROOT/campaigns"
cp -r "$ROOT/scripts/legacy/campaigns/$LEGACY_ID" "$LEGACY_ROOT/campaigns/"

p1_step_reset
AOUT="$(run_p1 "$LEGACY_ROOT" audit "$LEGACY_ID" 2>&1)"; AEXIT=$?
[ "$AEXIT" -eq 0 ] || { echo "$AOUT"; fail 9 "Go audit of legacy campaign (exit $AEXIT)"; }
grep -q '^audit PASS:' <<<"$AOUT" \
  || { echo "$AOUT"; fail 9 "Go audit of legacy campaign: not PASS"; }
AJSON="$(run_p1 "$LEGACY_ROOT" audit "$LEGACY_ID" --json 2>&1)"; JEXIT=$?
[ "$JEXIT" -eq 0 ] || { echo "$AJSON"; fail 9 "Go audit --json (exit $JEXIT)"; }
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' \
  <<<"$AJSON" || fail 9 "Go audit --json: ok is not true"
VOUT="$(run_p1 "$LEGACY_ROOT" verify "$LEGACY_ID" 2>&1)"; VEXIT=$?
[ "$VEXIT" -eq 0 ] || { echo "$VOUT"; fail 9 "Go verify of legacy campaign (exit $VEXIT)"; }
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' \
  <<<"$VOUT" || fail 9 "Go verify of legacy campaign: ok is not true"
echo "ok: Go audit/verify accept the reference-written campaign (ok: true)"
p2_sections_ok "Go audit of legacy campaign" "$AJSON" \
  || fail 9 "P2 audit sections (Go reading the legacy campaign)"
p2_full_read "$LEGACY_ROOT" "$LEGACY_ID" "Go readers on legacy P2/P3 state" \
  || fail 9 "legacy full read (Go readers on reference-written state)"

# --- CLI smoke campaigns (steps 10-12) -----------------------------------
rm -rf "$P1F/fixtures" "$P1F/smoke" "$P1F/smoke2" "$P1F/smoke3" \
     "$P1F/smoke3-blind" "$P1F/legacy"
mkdir -p "$P1F/fixtures"

# Fixtures: one tiny protocol model (two invariants), two findings of the
# same class carrying the model-normalization economic signature (so the
# dedup sweep records a tier-3 candidate flag), a bounty policy, an
# artifact file.
cat > "$P1F/fixtures/model.json" <<'JSON'
{"protocol_id": "v1xfi", "name": "Verify P1 Fixture", "snapshot_id": "unpinned",
 "chains": ["ethereum"], "subsystems": ["defi-vault"],
 "contracts": [{"name": "Vault", "path": "src/Vault.sol", "role": "core",
   "in_scope": true, "entry_points": ["deposit"],
   "state_variables": [{"name": "total", "kind": "balance", "accounting": true}]}],
 "actors": [{"id": "user", "kind": "EOA", "trust": "externally-owned"}],
 "assets": [{"id": "share", "kind": "share", "decimals": 18}],
 "liabilities": [], "privileges": [], "trust_boundaries": [], "relations": [],
 "state_machines": [], "economic_relations": [],
 "invariants": [
   {"id": "INV-1", "statement": "balances move atomically", "applies_to": ["Vault"],
    "kind": "economic", "severity_if_broken": "critical"},
   {"id": "INV-2", "statement": "total tracks deposits", "applies_to": ["Vault"],
    "kind": "economic", "severity_if_broken": "high"}],
 "oracles": []}
JSON
cat > "$P1F/fixtures/f1.json" <<'JSON'
{"title": "Atomic balance violated on deposit",
 "root_cause": {"class": "logic-error", "description": "mechanism described in detail here"},
 "affected": [{"path": "src/Vault.sol", "function": "deposit"}],
 "attacker": {"profile": "arbitrary EOA", "capabilities": []},
 "invariant": {"id": "INV-1", "statement": "balances move atomically"},
 "dedup": {"economic_signature": "0123456789abcdef"}}
JSON
cat > "$P1F/fixtures/f1-pre.json" <<'JSON'
{"title": "Timelock bypass on withdraw",
 "root_cause": {"class": "logic-error", "description": "mechanism described in detail here"},
 "affected": [{"path": "src/Vault.sol", "function": "withdraw"}],
 "attacker": {"profile": "arbitrary EOA", "capabilities": []},
 "invariant": {"id": "INV-3", "statement": "the timelock gates pause"},
 "preconditions": [{"description": "the timelock is enforced",
                    "enforced_by_poc": "false"}],
 "dedup": {"economic_signature": "fedcba9876543210"}}
JSON
cat > "$P1F/fixtures/f2.json" <<'JSON'
{"title": "Atomic balance violated on withdraw",
 "root_cause": {"class": "logic-error", "description": "mechanism described in detail here"},
 "affected": [{"path": "src/Vault.sol", "function": "deposit"}],
 "attacker": {"profile": "arbitrary EOA", "capabilities": []},
 "dedup": {"economic_signature": "0123456789abcdef"}}
JSON
cat > "$P1F/fixtures/policy.json" <<'JSON'
{"program": "Verify P1 Program", "program_url": "https://example.test/p1",
 "platform": "direct", "chains": ["ethereum"],
 "scope": [{"target": "Vault", "kind": "contract"}],
 "exclusions": [{"pattern": "rounding dust", "kind": "known-issue"}],
 "severity_rules": [{"severity": "critical", "match": {"bug_classes": ["access-control"]}}],
 "poc_requirements": {"min_evidence_level": "E4", "require_fork_repro": false}}
JSON
printf 'INV-1 verify-p1 cross-audit artifact\n' > "$P1F/fixtures/note.md"

# 10. P1 CLI smoke ---------------------------------------------------------
# The 21 P1 commands, each once in a valid shape against a scratch Go
# campaign, with the exit code the CLI documents:
#   init(setup)         0   campaign created
#   model               0   model loaded from the fixture file
#   plan                0   plan derived from the model (7 priorities)
#   ingest f1           0   first finding (logic-error, cites INV-1)
#   verdict confirmed   0   critic verdict recorded (the CLI confirm path)
#   ingest f2           0   second finding (open; tier-3 twin of f1)
#   dedup               0   sweep flags the tier-3 candidate pair
#   resolve-candidate   0   pair adjudicated 'distinct'
#   prioritize          0   deterministic triage view
#   repro-queue         0   candidates ordered for repro
#   answered            0   Q-001 closed with reason + ref
#   scope               0   bounty policy loaded
#   floors              0   effective floor table
#   budget              0   cost ceiling recorded
#   hint              0   planner hint recorded
#   recall              0   graph-memory consultation recorded
#   artifact-register   0   artifact registered (REP-*)
#   artifact-list       0   artifact ledger
#   invariant-verify    0   INV-1 CHECKED_AGAINST_CODE via the artifact
#   invariant-contradict 0  INV-2 CONTRADICTED
#   gate <cid> <f1>     1   CONFIRMED dry-run: clauses fail (documented 1)
#   prove               0   completion-proof view
#   waive               0   stage proof waived with actor + reason
step 10 "P1 CLI smoke: 21 commands, documented exit codes"
P1_SEED="verify-p1-smoke"
p1_step_reset
SMOKE_ROOT="$P1F/smoke"
mkdir -p "$SMOKE_ROOT"

# p1_ok LABEL WANT_EXIT ARGV... — run against the smoke campaign, assert exit.
p1_ok() {
  local label="$1" want="$2"
  shift 2
  P1_OUT="$(run_p1 "$SMOKE_ROOT" "$@" 2>&1)"; P1_RC=$?
  if [ "$P1_RC" -ne "$want" ]; then
    echo "$P1_OUT"
    fail 10 "$label: exit $P1_RC, want $want (webv2 $*)"
  fi
  printf '  ok %-20s exit=%s  webv2 %s\n' "$label" "$P1_RC" "$*"
}

p1_ok init 0 init --program VerifyP1Smoke
CID="$(grep -oE 'C-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$CID" ] || fail 10 "smoke init: no campaign id in output"
p1_ok model 0 model "$CID" "$P1F/fixtures/model.json"
p1_ok plan 0 plan "$CID"
p1_ok "ingest f1" 0 ingest "$CID" --json-file "$P1F/fixtures/f1.json" \
  --trajectory code --stage smoke
F1="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F1" ] || fail 10 "smoke ingest f1: no finding id in output"
p1_ok "verdict confirmed" 0 verdict "$CID" "$F1" --verdict confirmed \
  --reason "verified by hand"
p1_ok "ingest f2" 0 ingest "$CID" --json-file "$P1F/fixtures/f2.json" \
  --trajectory code --stage smoke
F2="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
p1_ok dedup 0 dedup "$CID"
p1_ok "resolve-candidate" 0 resolve-candidate "$CID" "$F2" "$F1" --verdict distinct
p1_ok prioritize 0 prioritize "$CID"
p1_ok repro-queue 0 repro-queue "$CID"
p1_ok answered 0 answered "$CID" Q-001 answered --reason "covered by F1" --ref "$F1"
p1_ok scope 0 scope "$CID" --policy "$P1F/fixtures/policy.json"
p1_ok floors 0 floors "$CID" list
p1_ok budget 0 budget "$CID" --set 500 --actor operator
p1_ok hint 0 hint "$CID" --kind note --content "look at the accounting path"
p1_ok recall 0 recall "$CID" --finding "$F1"
p1_ok artifact-register 0 artifact-register "$CID" "$P1F/fixtures/note.md" --kind report
REP="$(grep -oE '^[A-Z]{2,4}-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$REP" ] || fail 10 "smoke artifact-register: no artifact id in output"
p1_ok artifact-list 0 artifact-list "$CID"
p1_ok invariant-verify 0 invariant-verify "$CID" INV-1 --artifact "$REP"
p1_ok invariant-contradict 0 invariant-contradict "$CID" INV-2 --evidence "$REP"
p1_ok "gate dry-run" 1 gate "$CID" "$F1"
p1_ok prove 0 prove "$CID"
p1_ok waive 0 waive "$CID" learning --reason "no learning artifact owed" --actor operator
echo "ok: 21 P1 commands exercised, exit codes as documented"

# 11. P2 CLI smoke ---------------------------------------------------------
# The ported P2 commands, each once in a valid shape against a scratch Go
# campaign, with the exit code the CLI documents:
#   exec (pass/fail)     0   the sandbox runs and the ledger records both
#   execs / --json / --id 0  the three ledger projections
#   classify             0   the failure classifier over the exit-7 record
#   mint                 0   E4 evidence from an out-of-band E4 record
#   ladder start/show    0   ladder created / rendered
#   ladder add           0   a variant rung (capital-minimization)
#   ladder explore x5    0   every exploration axis recorded
#   ladder repro         0   rung reproduced from the seeded E4 record
#   ladder disprove      2   guard: a reproduced rung cannot be disproved
#   ladder set-maximal   0   the claim now follows the measurement
#   ladder complete      0   ladder closed
#   ladder report        0   the JSON report
#   chains/terminals/privileged 0  capability graph + terminal + role views
#   sequence verify      0   coverage read (vacuous without a fork pin, D19)
#   impact priced        0   extractable/max-loss/required-capital
#   impact --artifact    0   E7 evidence bound to a registered artifact
#   impact --unpriceable 0   the named-decision path
#   impact (incomplete)  2   documented refusal
#   audit --json         0   all 15 unconditional sections (17 registered;
#                            eval + price_table presence-gated), seq coverage
#   verify               0   event-log integrity
step 11 "P2 CLI smoke: exec ledger, mint, ladder, chains, impact, sequence"
P1_SEED="verify-p2-smoke"
p1_step_reset
SMOKE2="$P1F/smoke2"
rm -rf "$SMOKE2"
mkdir -p "$SMOKE2"

p2_ok() {
  local label="$1" want="$2"
  shift 2
  P1_OUT="$(run_p1 "$SMOKE2" "$@" 2>&1)"; P1_RC=$?
  if [ "$P1_RC" -ne "$want" ]; then
    echo "$P1_OUT"
    fail 11 "$label: exit $P1_RC, want $want (webv2 $*)"
  fi
  printf '  ok %-24s exit=%s  webv2 %s\n' "$label" "$P1_RC" "$*"
}

p2_ok init 0 init --program VerifyP2Smoke
CID2="$(grep -oE 'C-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$CID2" ] || fail 11 "smoke init: no campaign id in output"
p2_ok model 0 model "$CID2" "$P1F/fixtures/model.json"
p2_ok "ingest f1" 0 ingest "$CID2" --json-file "$P1F/fixtures/f1.json" \
  --trajectory code --stage smoke2
F1="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F1" ] || fail 11 "smoke ingest f1: no finding id in output"
p2_ok "ingest f2" 0 ingest "$CID2" --json-file "$P1F/fixtures/f2.json" \
  --trajectory code --stage smoke2
F2="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F2" ] || fail 11 "smoke ingest f2: no finding id in output"
p2_ok "verdict confirmed" 0 verdict "$CID2" "$F1" --verdict confirmed \
  --reason "verified by hand"
p2_ok "move possible" 0 move "$CID2" "$F1" POSSIBLE --reason "triage passed"
# The model fixture declares INV-1 on the finding: the invariants guardrail
# refuses any level rise (mint) until it is log-anchored CHECKED_AGAINST_CODE
# via a registered artifact.
p2_ok "artifact-register" 0 artifact-register "$CID2" "$P1F/fixtures/note.md" \
  --kind report
REP2="$(grep -oE 'REP-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$REP2" ] || fail 11 "smoke artifact-register: no artifact id in output"
p2_ok "invariant-verify" 0 invariant-verify "$CID2" INV-1 --artifact "$REP2"
p2_ok "exec pass" 0 exec "$CID2" --command "echo p2-smoke" --finding "$F1"
p2_ok "exec fail" 0 exec "$CID2" --command "exit 7" --finding "$F1"
EXFAIL="$(grep -oE 'EXEC-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$EXFAIL" ] || fail 11 "smoke exec fail: no exec id in output"
p2_ok execs 0 execs "$CID2"
p2_ok "execs --json" 0 execs "$CID2" --json
p2_ok "execs --id" 0 execs "$CID2" --id "$EXFAIL"
p2_ok classify 0 classify "$CID2" "$EXFAIL"
SEEDEX="EXEC-$(python3 -c 'import hashlib;print(hashlib.sha256(b"verify-p2-seed-exec").hexdigest()[:10])')"
seed_p2_exec "$SMOKE2" "$CID2" "$F1" "$SEEDEX" || fail 11 "smoke seed exec"
p2_ok mint 0 mint "$CID2" "$F1" --exec "$SEEDEX" \
  --description "sandboxed PoC drains the vault in one withdraw" \
  --tier T2 --type foundry-test
p2_ok "ladder start" 0 ladder "$CID2" start "$F1"
p2_ok "ladder show" 0 ladder "$CID2" show "$F1"
p2_ok "ladder add" 0 ladder "$CID2" add "$F1" --name dust \
  --description "dust the pool with one wei" --axes capital-minimization \
  --capital 1 --ratio 1 --removes "victim stakes"
RUNG="$(grep -oE 'R-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$RUNG" ] || fail 11 "smoke ladder add: no rung id in output"
for axis in cap-saturation precondition-removal role-conflation \
            ordering-permutation; do
  p2_ok "ladder explore $axis" 0 ladder "$CID2" explore "$F1" - "$axis" \
    --note "considered, not applicable here"
done
p2_ok "ladder repro" 0 ladder "$CID2" repro "$F1" "$RUNG" --exec "$SEEDEX"
p2_ok "ladder disprove guard" 2 ladder "$CID2" disprove "$F1" "$RUNG" \
  --reason "the corrected claim did not survive review"
p2_ok "ladder set-maximal" 0 ladder "$CID2" set-maximal "$F1" "$RUNG"
p2_ok "ladder complete" 0 ladder "$CID2" complete "$F1"
p2_ok "ladder report" 0 ladder "$CID2" report "$F1"
p2_ok chains 0 chains "$CID2"
p2_ok terminals 0 terminals "$CID2"
p2_ok privileged 0 privileged "$CID2"
p2_ok "sequence verify" 0 sequence verify "$CID2" "$F1"
p2_ok "impact priced" 0 impact "$CID2" "$F1" --extractable 1000 \
  --max-loss 5000 --required-capital 100
p2_ok "impact artifact" 0 impact "$CID2" "$F1" --extractable 1000 \
  --artifact "$P1F/fixtures/note.md" \
  --description "the priced impact carried by the report"
p2_ok "impact unpriceable" 0 impact "$CID2" "$F2" --unpriceable \
  --ceiling "no defensible USD figure" \
  --reason "the affected asset has no observable market" --actor smoke
p2_ok "impact incomplete" 2 impact "$CID2" "$F2" --unpriceable \
  --ceiling "no defensible USD figure"
p2_ok "audit --json" 0 audit "$CID2" --json
p2_sections_ok "P2 smoke audit" "$P1_OUT" || fail 11 "smoke audit --json sections"
p2_ok verify 0 verify "$CID2"
echo "ok: P2 commands exercised, exit codes as documented"


# 12. P3 CLI smoke ---------------------------------------------------------
# The ported P3 commands, each once in a valid shape against a scratch Go
# campaign, with the exit code the CLI documents:
#   snap/index/sinks/prescreen 0  structural surface over the blind fixture
#   probes run/list/--all      0  the candidate surface
#   probes blank               0  the named attestation closing a BLIND axis
#   probes run --emit x2       0  plan obligations, idempotent
#   relations --rebuild        0  typed research-memory graph
#   resemble                   0  primitive-similarity search
#   corpus-surface             0  class inventory + exposure (absent corpus, D26)
#   ladder start/add/disprove  0  the D18 happy path (memory row queued)
#   memory / --approve         0  queue -> human-approved promotion
#   shield / --extraction      0  effect adjudication (both directions)
#   precondition               0  enforced / 1 unknown description (refusal)
#   publish/globalize/shared   0  root-tier publish + globalize + both-tier view
#   brief/--json/--deep/report 0  operator cockpit + report
#   recency --target/--src     0  target-vs-pin freshness
#   baseline list/add/remove   0  the lifecycle against a scratch store (D24)
#   forkdiff/--json            0  the baseline comparison
#   cost/yields                0  cost ledger + derived yield
#   price set/table/basis      0  price table + price-basis pin
#   env doctor                 0|1 environment report (0 = no issues)
#   env doctor --json          0  the machine view
#   doctor / --json            0  state-repair preflight
#   run                        3  pipeline walk halts at the first model stage
#   complete guard             2  documented refusal (short reason)
#   complete                   0  completion
#   audit / --json / verify    0  16 sections (15 unconditional + the
#                                 presence-gated price_table, priced above)
#                                 + event-log integrity
step 12 "P3 CLI smoke: index/probes/memory/publish/baselines/costs/run"
P1_SEED="verify-p3-smoke"
p1_step_reset
SMOKE3="$P1F/smoke3"
# The blank-attestation leg below needs a corpus that is genuinely blind; the
# repo-wide campaign snap-pins the whole repository, so it never has one. Its
# own scratch root keeps that corpus separate and under this step's cleanup.
SMOKE3_BLIND="$P1F/smoke3-blind"
rm -rf "$SMOKE3" "$SMOKE3_BLIND" "$P1F/baselines"
mkdir -p "$SMOKE3" "$SMOKE3_BLIND"

# p3_ok_in ROOT LABEL WANT ARGV... — p3_ok for a root other than $SMOKE3.
p3_ok_in() {
  local root="$1" label="$2" want="$3"
  shift 3
  P1_OUT="$(run_p1 "$root" "$@" 2>&1)"; P1_RC=$?
  if [ "$P1_RC" -ne "$want" ]; then
    echo "$P1_OUT"
    fail 12 "$label: exit $P1_RC, want $want (webv2 $*)"
  fi
  printf '  ok %-24s exit=%s  webv2 %s\n' "$label" "$P1_RC" "$*"
}
p3_ok() { p3_ok_in "$SMOKE3" "$@"; }

p3_ok init 0 init --program VerifyP3Smoke
CID3="$(grep -oE 'C-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$CID3" ] || fail 12 "smoke init: no campaign id in output"
p3_ok model 0 model "$CID3" "$P1F/fixtures/model.json"
p3_ok plan 0 plan "$CID3"
p3_ok "ingest f1" 0 ingest "$CID3" --json-file "$P1F/fixtures/f1.json" \
  --trajectory code --stage smoke3
F1="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F1" ] || fail 12 "smoke ingest f1: no finding id in output"
p3_ok "verdict confirmed" 0 verdict "$CID3" "$F1" --verdict confirmed \
  --reason "verified by hand"
p3_ok "move possible" 0 move "$CID3" "$F1" POSSIBLE --reason "triage passed"
p3_ok "artifact-register" 0 artifact-register "$CID3" "$P1F/fixtures/note.md" \
  --kind report
REP3="$(grep -oE 'REP-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$REP3" ] || fail 12 "smoke artifact-register: no artifact id in output"
p3_ok "invariant-verify" 0 invariant-verify "$CID3" INV-1 --artifact "$REP3"
p3_ok "exec pass" 0 exec "$CID3" --command "echo p3-smoke" --finding "$F1"
SEEDEX="EXEC-$(python3 -c 'import hashlib;print(hashlib.sha256(b"verify-p3-seed-exec").hexdigest()[:10])')"
seed_p2_exec "$SMOKE3" "$CID3" "$F1" "$SEEDEX" || fail 12 "smoke seed exec"
p3_ok mint 0 mint "$CID3" "$F1" --exec "$SEEDEX" \
  --description "sandboxed PoC drains the vault in one withdraw" \
  --tier T2 --type foundry-test
# A second finding carries a precondition row, so the `precondition`
# adjudication has a target (the first finding has none).
p3_ok "ingest f1-pre" 0 ingest "$CID3" --json-file "$P1F/fixtures/f1-pre.json" \
  --trajectory code --stage smoke3
F2="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F2" ] || fail 12 "smoke ingest f1-pre: no finding id in output"
p3_ok shield 0 shield "$CID3" "$F1" --reason "the effect is the intended transfer" \
  --actor smoke
p3_ok "shield --extraction" 0 shield "$CID3" "$F1" --extraction \
  --reason "the effect is extraction despite the documented intent" --actor smoke
p3_ok "precondition enforced" 0 precondition "$CID3" "$F2" \
  "the timelock is enforced" --enforced
p3_ok "precondition unknown (refusal)" 1 precondition "$CID3" "$F2" \
  "no such precondition here" --not-enforced
p3_ok scope 0 scope "$CID3" --policy "$P1F/fixtures/policy.json"

p3_ok snap 0 snap "$CID3" "$P3_FIXTURE"
SNAP3="$(ls -d "$SMOKE3/campaigns/$CID3"/snapshots/*/ 2>/dev/null | head -1)"
[ -n "$SNAP3" ] || fail 12 "smoke snap: no snapshot dir"
p3_ok index 0 index "$CID3" --src "$SNAP3"
p3_ok "index --json" 0 index "$CID3" --src "$SNAP3" --json
p3_ok sinks 0 sinks "$CID3" --src "$SNAP3"
p3_ok "sinks --json" 0 sinks "$CID3" --src "$SNAP3" --json
p3_ok prescreen 0 prescreen "$CID3" --src "$SNAP3"
p3_ok "prescreen --json" 0 prescreen "$CID3" --src "$SNAP3" --json
p3_ok "probes run" 0 probes "$CID3" run
p3_ok "probes list" 0 probes "$CID3" list
p3_ok "probes list --all" 0 probes "$CID3" list --all
p3_ok "probes list --all --json" 0 probes "$CID3" list --all --json
python3 -c '
import json, sys
try:
    axes = json.load(sys.stdin).get("axes") or []
except ValueError:
    print("  probes list --all --json: response is not JSON")
    sys.exit(1)
if not axes:
    print("  probes list --all --json: axes list is empty")
    sys.exit(1)
print("  ok repo-wide probes list --all --json: %d axes" % len(axes))
' <<<"$P1_OUT" || fail 12 "probes list --all --json: not JSON with a non-empty axes list"
# The repo-wide campaign above snap-pins the whole repository, so no axis is
# ever blind there. Index the assertion-strength fixture directly instead:
# unpinned from the repo, its enforcement-timing axis is `blind` (sites 4,
# rows 0), which is the precondition `probes blank` asserts.
P3_BLIND_FIXTURE="$ROOT/internal/probes/testdata/probes/assertion_strength/clean"
p3_ok_in "$SMOKE3_BLIND" "blind init" 0 init --program VerifyP3Blind
CID3B="$(grep -oE 'C-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$CID3B" ] || fail 12 "smoke blind init: no campaign id in output"
p3_ok_in "$SMOKE3_BLIND" "blind index" 0 index "$CID3B" --src "$P3_BLIND_FIXTURE"
grep -qE '^index: 4 entries' <<<"$P1_OUT" \
  || fail 12 "blind index: want 4 fixture entries, saw: $P1_OUT"
p3_ok_in "$SMOKE3_BLIND" "blind probes run" 0 probes "$CID3B" run
p3_ok_in "$SMOKE3_BLIND" "blind probes list --all --json" 0 probes "$CID3B" list --all --json
python3 -c '
import json, sys
for a in json.load(sys.stdin).get("axes") or []:
    print("  axis %-20s status=%-8s sites=%-3s rows=%-3s blind=%d" % (
        a.get("axis"), a.get("status"), a.get("sites"), a.get("rows"),
        len(a.get("blind") or [])))
' <<<"$P1_OUT"
AXIS="$(python3 -c '
import json, sys
want = ("enforcement-timing", 4, 0, 5)
d = json.load(sys.stdin)
for a in d.get("axes") or []:
    if a.get("status") == "blind" and a.get("blind"):
        got = (a["axis"], a["sites"], a["rows"], len(a.get("blind") or []))
        if got != want:
            print("  selected %s/%s/%s/%s, want %s/%s/%s/%s" % (got + want))
            sys.exit(1)
        print(a["axis"]); break
else:
    print("  no axis with status=blind and a non-empty blind list")
    sys.exit(1)
' <<<"$P1_OUT" 2>&1)" || fail 12 "smoke blind axis: $AXIS"
KEY="$(python3 -c '
import json, sys
d = json.load(sys.stdin)
for a in d.get("axes") or []:
    if a.get("status") == "blind" and a.get("blind"):
        print(a["blind"][0]["key"]); break
' <<<"$P1_OUT")"
[ -n "$AXIS" ] && [ -n "$KEY" ] || fail 12 "smoke probes: no blind axis/key published"
p3_ok_in "$SMOKE3_BLIND" "probes list --axis" 0 probes "$CID3B" list --axis "$AXIS"
p3_ok_in "$SMOKE3_BLIND" "probes blank" 0 probes "$CID3B" blank --axis "$AXIS" \
  --anchor-blind "$KEY" --reason "the cited key is the only write on this axis" \
  --actor smoke
p3_ok_in "$SMOKE3_BLIND" "probes list (after blank)" 0 probes "$CID3B" list --all
p3_ok "probes run --emit" 0 probes "$CID3" run --emit
p3_ok "probes run --emit again" 0 probes "$CID3" run --emit
p3_ok "plan after emit" 0 plan "$CID3"
p3_ok "relations --rebuild" 0 relations "$CID3" --rebuild
p3_ok relations 0 relations "$CID3"
p3_ok resemble 0 resemble "$CID3" "$F1"
p3_ok corpus-surface 0 corpus-surface "$CID3"

p3_ok "ladder start" 0 ladder "$CID3" start "$F1"
p3_ok "ladder add" 0 ladder "$CID3" add "$F1" --name p3-dead-end \
  --description "drain the vault in one transaction" \
  --axes precondition-removal --capital 1 --ratio 1 --removes "the timelock"
RUNG3="$(grep -oE 'R-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$RUNG3" ] || fail 12 "smoke ladder add: no rung id in output"
p3_ok "ladder disprove (happy)" 0 ladder "$CID3" disprove "$F1" "$RUNG3" \
  --reason "the removed timelock precondition is enforced by the guard"
p3_ok memory 0 memory "$CID3"
MEM3="$(grep -oE 'MEM-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$MEM3" ] || fail 12 "smoke memory: no MEM- id in output"
p3_ok "memory --approve" 0 memory "$CID3" --approve "$MEM3" --by smoke
p3_ok "memory (after approve)" 0 memory "$CID3"
p3_ok publish 0 publish "$CID3" --actor smoke
p3_ok "globalize --tier root" 0 globalize --actor smoke --tier root
p3_ok shared 0 shared
p3_ok "shared --verify" 0 shared --verify

p3_ok brief 0 brief "$CID3"
p3_ok "brief --json" 0 brief "$CID3" --json
p3_ok "brief --deep" 0 brief "$CID3" --deep
p3_ok report 0 report "$CID3"
p3_ok recency 0 recency "$CID3" --target "$SNAP3" --src "$SNAP3"
p3_ok "recency --json" 0 recency "$CID3" --target "$SNAP3" --src "$SNAP3" --json

p3_ok "baseline list (empty)" 0 baseline list
p3_ok "forkdiff (no baselines)" 0 forkdiff "$CID3" --src "$SNAP3"
p3_ok "baseline add" 0 baseline add smoke-baseline --path "$SNAP3" \
  --source-url "https://example.invalid/smoke" --license MIT
p3_ok "baseline list" 0 baseline list
p3_ok forkdiff 0 forkdiff "$CID3" --src "$SNAP3"
p3_ok "forkdiff --json" 0 forkdiff "$CID3" --src "$SNAP3" --json
p3_ok "baseline remove" 0 baseline remove smoke-baseline
p3_ok "baseline list (after)" 0 baseline list

p3_ok "cost model" 0 cost "$CID3" --kind model --amount 12.5 \
  --trajectory code --actor smoke
p3_ok "cost human-review" 0 cost "$CID3" --kind human-review --amount 40 \
  --finding "$F1" --actor smoke
p3_ok yields 0 yields "$CID3"
p3_ok "price set" 0 price "$CID3" set ETH 3000 --source coingecko \
  --as-of 2026-09-09T00:00:00+00:00 --actor smoke
PRC3="$(grep -oE 'PRC-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$PRC3" ] || fail 12 "smoke price set: no PRC- id in output"
p3_ok "price table" 0 price "$CID3" table
p3_ok "price-basis" 0 price-basis "$CID3" "$F1" "$PRC3"

# env doctor's exit is environment-dependent (0 = no issues found, 1 = at
# least one missing tool/daemon); both are documented, so accept either.
P1_OUT="$(run_p1 "$SMOKE3" env doctor 2>&1)"; P1_RC=$?
[ "$P1_RC" -eq 0 ] || [ "$P1_RC" -eq 1 ] \
  || { echo "$P1_OUT"; fail 12 "env doctor: exit $P1_RC, want 0 or 1"; }
printf '  ok %-24s exit=%s  webv2 env doctor\n' "env doctor" "$P1_RC"
p3_ok "env doctor --json" 0 env doctor --json
p3_ok doctor 0 doctor "$CID3"
p3_ok "doctor --json" 0 doctor "$CID3" --json

p3_ok run 3 run "$CID3"
p3_ok "complete guard" 2 complete "$CID3" --actor smoke --reason nope
p3_ok complete 0 complete "$CID3" --actor smoke \
  --reason "all smoke checks closed with evidence"
p3_ok audit 0 audit "$CID3"
p3_ok "audit --json" 0 audit "$CID3" --json
p2_sections_ok "P3 smoke audit" "$P1_OUT" || fail 12 "smoke audit --json sections"
p3_ok verify 0 verify "$CID3"
echo "ok: P3 commands exercised, exit codes as documented"

# ─────────────────────────────────────────────────────────────────────────
step 13 "runbook walkthrough: every documented command matches the binary"
# The runbook is the operator contract; this is the only gate that reads it
# end to end. It was left unenforced once already and silently rotted six
# rows deep (the 2026-09-10 leanness review found it). Never let that again:
# green means every verbatim command in assets/runbook/RUNBOOK.md exits with
# its documented code and prints its documented marker.
mkdir -p "$ROOT/.scratch"
WALK_LOG="$ROOT/.scratch/verify-walkthrough.log"
if bash "$ROOT/scripts/runbook-walkthrough.sh" > "$WALK_LOG" 2>&1; then
  echo "  ok runbook-walkthrough (134+ rows green)"
else
  grep -E "^\[FAIL\]" "$WALK_LOG" | head -10
  fail 13 "runbook-walkthrough RED — the runbook and the binary disagree"
fi
echo "ok: runbook commands all match"
# Wiring note (Wave J Task 5): this gate is daemon-free by design and must
# stay that way, so the docker e2e tiers are NOT invoked here. Say so in the
# gate output itself, not only in the README — a reader who sees 13/13 green
# must know what it does not cover.
echo "note: docker e2e tiers live in scripts/p2-docker-e2e.sh and are NOT part"
echo "      of this gate — run them separately where the daemon is up"

echo
echo "VERIFY-FULL GREEN: all 13 steps pass"