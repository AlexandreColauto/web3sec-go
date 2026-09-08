#!/usr/bin/env bash
#
# verify-full.sh — Task 18: the single entry point the P0 gate runs.
#
# One command (a human or CI) runs to know whether P0 is clean: ten
# ordered steps, fail-fast with the failing step's name. Every P0 task
# ends green under this script before the gate is opened.
#
#   1.  go vet ./... clean
#   2.  go build ./cmd/webv2 -> /tmp/webv2
#   3.  go test ./... PASS
#   4.  go test -race ./... PASS (hard gate from day one — design 7.1)
#   5.  go test -count=1 ./... twice; normalized output identical
#       (Go==Go determinism run — design 7.1)
#   6.  scripts/sync-assets.sh then diff -r <py>/schema assets/schema
#   7.  python -m pytest <py>/tests -q (reference baseline still green)
#   8.  testmap reconciles with the live Python tree (sync-testmap --check,
#       then check-testmap.py against count-python-tests.py)
#   9.  scripts/golden.sh green (Task 17)
#  10.  crash smoke: audit/verify on a truncated events.jsonl must
#       produce a verdict, not a panic (Task 7 + hardening 7.2)
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

step() {
  echo
  echo "=== step $1/10: $2 ==="
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
echo "ok: 27 schemas byte-identical"

# 7. Python reference baseline ------------------------------------------
step 7 "python reference suite"
(
  cd "$PYROOT" && PYTHONPATH=src python3 -m pytest tests -q
) > .scratch/pytest.log 2>&1
PYEXIT=$?
tail -2 .scratch/pytest.log
[ "$PYEXIT" -eq 0 ] || fail 7 "python reference suite"
echo "ok: reference suite green"

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

echo
echo "VERIFY-FULL GREEN: all 10 steps pass"
