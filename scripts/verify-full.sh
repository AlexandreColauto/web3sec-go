#!/usr/bin/env bash
#
# verify-full.sh — Task 18: the single entry point the P0+P1 gate runs.
#
# One command (a human or CI) runs to know whether P0 and P1 are clean:
# thirteen ordered steps, fail-fast with the failing step's name.
#
#   1.  go vet ./... clean
#   2.  go build ./cmd/webv2 -> /tmp/webv2
#   3.  go test ./... PASS
#   4.  go test -race ./... PASS (hard gate from day one — design 7.1)
#   5.  go test -count=1 ./... twice; normalized output identical
#       (Go==Go determinism run — design 7.1)
#   6.  scripts/sync-assets.sh then diff -r <py>/schema assets/schema
#   7.  python -m pytest <py>/tests -q (reference baseline — OPT-IN via
#       WEBV2_REF_PYTEST=1; heavy, orchestrator-only, skip by default)
#   8.  testmap reconciles with the live Python tree (sync-testmap --check,
#       then check-testmap.py against count-python-tests.py)
#   9.  scripts/golden.sh green (Task 17)
#  10.  crash smoke: audit/verify on a truncated events.jsonl must
#       produce a verdict, not a panic (Task 7 + hardening 7.2)
#  11.  cross-audit Python -> Go: a CLI-built Python campaign (pinned clock
#       + id stream) must audit clean in Go — ok: true (spec 1.5 item 3)
#  12.  cross-audit Go -> Python: the same campaign built by the Go binary
#       must pass the LIVE Python audit/verify (spec 1.5 item 3)
#  13.  P1 CLI smoke: the 21 P1 commands each invoked once in a valid shape
#       against a scratch Go campaign, asserting documented exit codes
#       (fast form of spec 1.5 item 4; the full RUNBOOK walkthrough is P4)
#
# Exits non-zero at the first failing step, naming it.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYROOT="$(cd "$ROOT/.." && pwd)/web3sec-final"
cd "$ROOT"

# The Go caches live under .scratch so the script works in sandboxed
# environments where $HOME is not writable (GOPATH may be preset to a
# read-only location, so force both — the module set is two small deps
# and the cache persists in .scratch after the first run).
export GOCACHE="$ROOT/.scratch/gocache"
export GOPATH="$ROOT/.scratch/gomod"
export GOMODCACHE="$ROOT/.scratch/gomod/pkg/mod"
export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"

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

# 6. schema assets ------------------------------------------------------
step 6 "sync-assets + diff"
scripts/sync-assets.sh || fail 6 "sync-assets.sh"
diff -r "$PYROOT/schema" assets/schema || fail 6 "schema diff"
echo "ok: $(ls assets/schema | wc -l) schemas byte-identical"

# 7. Python reference baseline ------------------------------------------
# The reference suite (~1450 tests, ~217s, heavy on memory) is opt-in:
# WEBV2_REF_PYTEST=1 runs it; by default it is skipped with a note. It is
# for the orchestrator, when genuinely necessary (a phase-gate baseline
# after the Python twin moved) — never part of a subagent's work.
step 7 "python reference suite"
if [ -n "${WEBV2_REF_PYTEST:-}" ]; then
  (
    cd "$PYROOT" && PYTHONPATH=src python3 -m pytest tests -q
  ) > .scratch/pytest.log 2>&1
  PYEXIT=$?
  tail -2 .scratch/pytest.log
  [ "$PYEXIT" -eq 0 ] || fail 7 "python reference suite"
  echo "ok: reference suite green"
else
  echo "skip: reference suite (WEBV2_REF_PYTEST=1 to run; last proven green at the P1 gate, 1446 passed)"
fi

# 8. testmap ------------------------------------------------------------
step 8 "check-testmap"
# 8a. the live reference must have no unabsorbed Python tests (web3sec-final
#     is developed in parallel; run scripts/sync-testmap.py to absorb them).
python3 scripts/sync-testmap.py --check \
  || fail 8 "sync-testmap --check (new python tests not in testmap.json)"
python3 scripts/check-testmap.py || fail 8 "check-testmap"

# 9. golden suite ---------------------------------------------------------
step 9 "golden.sh (cross-twin)"
scripts/golden.sh || fail 9 "golden.sh"

# 10. crash smoke ----------------------------------------------------------
step 10 "crash smoke: truncated events.jsonl"
SMOKE="$(mktemp -d)"
CID="$(/tmp/webv2 --root "$SMOKE" init --program Smoke 2>/dev/null \
  | grep -o 'C-[0-9a-f]*' | head -1)"
[ -n "$CID" ] || fail 10 "smoke init"
/tmp/webv2 --root "$SMOKE" snap "$CID" "$PYROOT/schema" >/dev/null 2>&1 \
  || fail 10 "smoke snap"
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
  fail 10 "crash smoke (panic or bad exit)"
fi
echo "$VOUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "ok" in d' \
  || fail 10 "verify verdict not JSON"
echo "ok: audit/verify handle a corrupted log without panicking"
rm -rf "$SMOKE" "$SMOKE-trunc"

# --- P1 cross-audit + CLI smoke (spec 1.5 items 3-4) --------------------
#
# Shared machinery for steps 11-13: the pinned clock (WEBV2_NOW, +1s per
# step, reset per campaign) and the pinned id stream (WEBV2_UUID) that both
# twins honour, exactly as scripts/golden-run.py does — the campaign a twin
# builds is the same campaign logically, so the other twin's auditor must
# accept it. Scratch lives under .scratch/verify-p1/.
P1F="$ROOT/.scratch/verify-p1"
P1BIN="$P1F/webv2"
P1_STEP=0
P1_SEED="verify-p1-cross"

# run_p1 TWIN ROOT ARGV... — one pinned-clock CLI invocation.
run_p1() {
  local twin="$1" root="$2"
  shift 2
  P1_STEP=$((P1_STEP + 1))
  local now
  now="$(date -u -d "2026-09-09T12:00:00Z + ${P1_STEP} seconds" \
    +%Y-%m-%dT%H:%M:%S.000000+00:00)"
  if [ "$twin" = py ]; then
    ( cd "$PYROOT" && PYTHONPATH=src WEBV2_NOW="$now" WEBV2_UUID="$P1_SEED" \
        python3 -m webv2.cli --root "$root" "$@" )
  else
    WEBV2_NOW="$now" WEBV2_UUID="$P1_SEED" "$P1BIN" --root "$root" "$@"
  fi
}

p1_build_fail() { echo "cross-audit($1): $2" >&2; return 1; }

# build_campaign TWIN ROOT LABEL — the RUNBOOK-shaped P1 campaign through
# one twin: init, model, plan, ingest 2 findings (F1 confirmed via the
# CLI's critic-verdict path, F2 open), dedup, answered, gate dry-run (must
# exit 1 while clauses fail), artifact-register, invariant-verify. Echoes
# the campaign id; the pinned stream is rewound first so both twins build
# the same logical campaign (identical timestamps + campaign id).
build_campaign() {
  local twin="$1" root="$2" label="$3" out cid f1 f2 rep rc
  P1_STEP=0
  mkdir -p "$root" || { p1_build_fail "$label" "mkdir"; return 1; }
  out="$(run_p1 "$twin" "$root" init --program VerifyP1Cross 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "init"; return 1; }
  cid="$(grep -oE 'C-[0-9a-f]+' <<<"$out" | head -1)"
  [ -n "$cid" ] || { echo "$out" >&2; p1_build_fail "$label" "init id"; return 1; }
  out="$(run_p1 "$twin" "$root" model "$cid" "$P1F/fixtures/model.json" 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "model"; return 1; }
  out="$(run_p1 "$twin" "$root" plan "$cid" 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "plan"; return 1; }
  out="$(run_p1 "$twin" "$root" ingest "$cid" --json-file "$P1F/fixtures/f1.json" \
    --trajectory code --stage verify-p1 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "ingest f1"; return 1; }
  f1="$(grep -oE 'F-[0-9a-f]+' <<<"$out" | head -1)"
  [ -n "$f1" ] || { echo "$out" >&2; p1_build_fail "$label" "ingest f1 id"; return 1; }
  out="$(run_p1 "$twin" "$root" verdict "$cid" "$f1" --verdict confirmed \
    --reason "mechanism verified by hand" 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "verdict"; return 1; }
  out="$(run_p1 "$twin" "$root" ingest "$cid" --json-file "$P1F/fixtures/f2.json" \
    --trajectory code --stage verify-p1 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "ingest f2"; return 1; }
  f2="$(grep -oE 'F-[0-9a-f]+' <<<"$out" | head -1)"
  out="$(run_p1 "$twin" "$root" dedup "$cid" 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "dedup"; return 1; }
  out="$(run_p1 "$twin" "$root" answered "$cid" Q-001 answered \
    --reason "covered by F1" --ref "$f1" 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "answered"; return 1; }
  # Gate dry-run is read-only and exits 1 while a clause fails (documented).
  run_p1 "$twin" "$root" gate "$cid" "$f1" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 1 ] \
    || { p1_build_fail "$label" "gate dry-run exit $rc, want 1"; return 1; }
  out="$(run_p1 "$twin" "$root" artifact-register "$cid" "$P1F/fixtures/note.md" \
    --kind report 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "artifact-register"; return 1; }
  rep="$(grep -oE '^[A-Z]{2,4}-[0-9a-f]+' <<<"$out" | head -1)"
  [ -n "$rep" ] || { echo "$out" >&2; p1_build_fail "$label" "artifact id"; return 1; }
  out="$(run_p1 "$twin" "$root" invariant-verify "$cid" INV-1 --artifact "$rep" 2>&1)" \
    || { echo "$out" >&2; p1_build_fail "$label" "invariant-verify"; return 1; }
  echo "$cid"
}

# 11. cross-audit (Python -> Go) ------------------------------------------
step 11 "cross-audit: a Python-written campaign audits clean in Go"
rm -rf "$P1F/fixtures" "$P1F/pyroot" "$P1F/goroot" "$P1F/smoke"
mkdir -p "$P1F/fixtures"
go build -o "$P1BIN" ./cmd/webv2 || fail 11 "build .scratch/verify-p1/webv2"

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
printf 'verify-p1 cross-audit artifact\n' > "$P1F/fixtures/note.md"

CID_PY="$(build_campaign py "$P1F/pyroot" python)" \
  || fail 11 "cross-audit build (Python-written campaign)"
echo "ok: Python built $CID_PY (init/model/plan/ingest x2/verdict/dedup/answered/gate/artifact/invariant)"

P1_STEP=0
AOUT="$(run_p1 go "$P1F/pyroot" audit "$CID_PY" 2>&1)"; AEXIT=$?
[ "$AEXIT" -eq 0 ] || { echo "$AOUT"; fail 11 "Go audit of Python campaign (exit $AEXIT)"; }
grep -q '^audit PASS:' <<<"$AOUT" \
  || { echo "$AOUT"; fail 11 "Go audit of Python campaign: not PASS"; }
AJSON="$(run_p1 go "$P1F/pyroot" audit "$CID_PY" --json 2>&1)"; JEXIT=$?
[ "$JEXIT" -eq 0 ] || { echo "$AJSON"; fail 11 "Go audit --json (exit $JEXIT)"; }
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' \
  <<<"$AJSON" || fail 11 "Go audit --json: ok is not true"
VOUT="$(run_p1 go "$P1F/pyroot" verify "$CID_PY" 2>&1)"; VEXIT=$?
[ "$VEXIT" -eq 0 ] || { echo "$VOUT"; fail 11 "Go verify of Python campaign (exit $VEXIT)"; }
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' \
  <<<"$VOUT" || fail 11 "Go verify of Python campaign: ok is not true"
echo "ok: Go audit/verify accept the Python-written campaign (ok: true)"

# 12. cross-audit (Go -> Python) ------------------------------------------
step 12 "cross-audit: a Go-written campaign passes the LIVE Python audit"
CID_GO="$(build_campaign go "$P1F/goroot" go)" \
  || fail 12 "cross-audit build (Go-written campaign)"
[ "$CID_GO" = "$CID_PY" ] \
  || fail 12 "pinned id stream: python=$CID_PY go=$CID_GO"
echo "ok: Go built the same campaign id ($CID_GO) under the pinned stream"

P1_STEP=0
PAOUT="$(run_p1 py "$P1F/goroot" audit "$CID_GO" 2>&1)"; PAEXIT=$?
[ "$PAEXIT" -eq 0 ] || { echo "$PAOUT"; fail 12 "Python audit of Go campaign (exit $PAEXIT)"; }
grep -q '^audit PASS:' <<<"$PAOUT" \
  || { echo "$PAOUT"; fail 12 "Python audit of Go campaign: not PASS"; }
PAJSON="$(run_p1 py "$P1F/goroot" audit "$CID_GO" --json 2>&1)"; PJEXIT=$?
[ "$PJEXIT" -eq 0 ] || { echo "$PAJSON"; fail 12 "Python audit --json (exit $PJEXIT)"; }
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' \
  <<<"$PAJSON" || fail 12 "Python audit --json: ok is not true"
PVOUT="$(run_p1 py "$P1F/goroot" verify "$CID_GO" 2>&1)"; PVEXIT=$?
[ "$PVEXIT" -eq 0 ] || { echo "$PVOUT"; fail 12 "Python verify of Go campaign (exit $PVEXIT)"; }
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' \
  <<<"$PVOUT" || fail 12 "Python verify of Go campaign: ok is not true"
echo "ok: Python audit/verify accept the Go-written campaign (ok: true)"

# 13. P1 CLI smoke ---------------------------------------------------------
# The 21 P1 commands, each once in a valid shape against a scratch Go
# campaign, with the exit code the reference CLI documents:
#   init(setup)         0   campaign created
#   model               0   model loaded from the fixture file
#   plan                0   plan derived from the model (7 priorities)
#   ingest f1           0   first finding (logic-error, cites INV-1)
#   verdict confirmed   0   critic verdict recorded (the CLI confirm path)
#   ingest f2           0   second finding (open; tier-3 twin of f1)
#   dedup               0   sweep flags the tier-3 candidate pair
#   resolve-candidate   0   pair adjudicated 'distinct'. No --note: the
#                           reference writes a dict into dedup_meta.
#                           candidate_notes, which its own finding schema
#                           rejects ("is not of type 'string'") — a
#                           reference bug BOTH twins reproduce identically,
#                           so the no-note shape is the parity-clean one.
#   prioritize          0   deterministic triage view
#   repro-queue         0   candidates ordered for repro
#   answered            0   Q-001 closed with reason + ref
#   scope               0   bounty policy loaded
#   floors              0   effective floor table
#   budget              0   cost ceiling recorded
#   hint                0   planner hint recorded
#   recall              0   graph-memory consultation recorded
#   artifact-register   0   artifact registered (REP-*)
#   artifact-list       0   artifact ledger
#   invariant-verify    0   INV-1 CHECKED_AGAINST_CODE via the artifact
#   invariant-contradict 0  INV-2 CONTRADICTED
#   gate <cid> <f1>     1   CONFIRMED dry-run: clauses fail (documented 1)
#   prove               0   completion-proof view
#   waive               0   stage proof waived with actor + reason
step 13 "P1 CLI smoke: 21 commands, documented exit codes"
P1_SEED="verify-p1-smoke"
P1_STEP=0
SMOKE_ROOT="$P1F/smoke"
mkdir -p "$SMOKE_ROOT"

# p1_ok LABEL WANT_EXIT ARGV... — run against the smoke campaign, assert exit.
p1_ok() {
  local label="$1" want="$2"
  shift 2
  P1_OUT="$(run_p1 go "$SMOKE_ROOT" "$@" 2>&1)"; P1_RC=$?
  if [ "$P1_RC" -ne "$want" ]; then
    echo "$P1_OUT"
    fail 13 "$label: exit $P1_RC, want $want (webv2 $*)"
  fi
  printf '  ok %-20s exit=%s  webv2 %s\n' "$label" "$P1_RC" "$*"
}

p1_ok init 0 init --program VerifyP1Smoke
CID="$(grep -oE 'C-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$CID" ] || fail 13 "smoke init: no campaign id in output"
p1_ok model 0 model "$CID" "$P1F/fixtures/model.json"
p1_ok plan 0 plan "$CID"
p1_ok "ingest f1" 0 ingest "$CID" --json-file "$P1F/fixtures/f1.json" \
  --trajectory code --stage smoke
F1="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F1" ] || fail 13 "smoke ingest f1: no finding id in output"
p1_ok "verdict confirmed" 0 verdict "$CID" "$F1" --verdict confirmed \
  --reason "verified by hand"
p1_ok "ingest f2" 0 ingest "$CID" --json-file "$P1F/fixtures/f2.json" \
  --trajectory code --stage smoke
F2="$(grep -oE 'F-[0-9a-f]+' <<<"$P1_OUT" | head -1)"
[ -n "$F2" ] || fail 13 "smoke ingest f2: no finding id in output"
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
[ -n "$REP" ] || fail 13 "smoke artifact-register: no artifact id in output"
p1_ok artifact-list 0 artifact-list "$CID"
p1_ok invariant-verify 0 invariant-verify "$CID" INV-1 --artifact "$REP"
p1_ok invariant-contradict 0 invariant-contradict "$CID" INV-2 --evidence "$REP"
p1_ok "gate dry-run" 1 gate "$CID" "$F1"
p1_ok prove 0 prove "$CID"
p1_ok waive 0 waive "$CID" code --reason "no code artifact" --actor operator
echo "ok: 21 P1 commands exercised, exit codes as documented"

echo
echo "VERIFY-FULL GREEN: all 13 steps pass"
