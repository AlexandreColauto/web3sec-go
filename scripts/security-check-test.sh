#!/usr/bin/env bash
#
# security-check-test.sh — hermetic acceptance tests for scripts/security-check.sh.
#
# Every case runs the gate with an isolated PATH that cannot see the real
# govulncheck: only the utilities the gate itself needs (dirname) are linked
# into a scratch bin directory. Stub scanners are harmless local shell
# scripts. No live scan, no network call, no dependency installation.
#
# One optional case (8) runs the REAL scanner inside an empty network
# namespace: it makes no network call by construction, it is the only case
# that touches a real scan, and it SKIPs with a printed reason when the scanner
# or `unshare -rn` is unavailable.
#
# Scratch state lives in a single mktemp -d directory that is removed by an
# EXIT trap; nothing outside it is touched.
#
# Exit 0 only when every case passes.

set -uo pipefail

# Resolve every external tool BEFORE any PATH isolation, so the test shell
# never depends on a lookup after the child's PATH is replaced.
BASH_BIN="$(command -v bash)"       || { echo "security-check-test: bash not found" >&2; exit 1; }
MKTEMP_BIN="$(command -v mktemp)"   || { echo "security-check-test: mktemp not found" >&2; exit 1; }
RM_BIN="$(command -v rm)"           || { echo "security-check-test: rm not found" >&2; exit 1; }
DIRNAME_BIN="$(command -v dirname)" || { echo "security-check-test: dirname not found" >&2; exit 1; }
ENV_BIN="$(command -v env)"         || { echo "security-check-test: env not found" >&2; exit 1; }
LN_BIN="$(command -v ln)"           || { echo "security-check-test: ln not found" >&2; exit 1; }
MKDIR_BIN="$(command -v mkdir)"     || { echo "security-check-test: mkdir not found" >&2; exit 1; }
CHMOD_BIN="$(command -v chmod)"     || { echo "security-check-test: chmod not found" >&2; exit 1; }
# Optional, used only by the guarded real-scanner case 8.
GO_BIN="$(command -v go || true)"

SCRIPT_DIR="$(cd "$("$DIRNAME_BIN" "${BASH_SOURCE[0]}")" && pwd)" || exit 1
CHECK="$SCRIPT_DIR/security-check.sh"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)" || exit 1

TMP="$("$MKTEMP_BIN" -d)" || exit 1
trap '"$RM_BIN" -rf "$TMP"' EXIT
# Run the whole suite from the scratch dir: proves the gate locates the
# repository from its own path, never from the caller's cwd.
cd "$TMP" || exit 1

# --- PATH isolation ---------------------------------------------------------
# The gate needs bash builtins plus dirname. govulncheck is deliberately
# absent, so the real scanner on the developer's PATH can never be found.
SAFE_BIN="$TMP/safe-bin"
"$MKDIR_BIN" -p "$SAFE_BIN"
"$LN_BIN" -s "$DIRNAME_BIN" "$SAFE_BIN/dirname"

# --- harness ---------------------------------------------------------------
PASS=0
FAILED=0
ok() { printf 'ok   - %s\n' "$1"; PASS=$((PASS + 1)); }
no() { printf 'FAIL - %s\n' "$1"; FAILED=$((FAILED + 1)); }

assert_eq() { # desc, actual, expected
  if [ "$2" = "$3" ]; then ok "$1 [$2]"; else no "$1: expected [$3], got [$2]"; fi
}
assert_has() { # desc, haystack, needle
  case "$2" in *"$3"*) ok "$1" ;; *) no "$1: missing [$3] in output: $2" ;; esac
}
assert_lacks() { # desc, haystack, needle
  case "$2" in *"$3"*) no "$1: unexpected [$3] in output: $2" ;; *) ok "$1" ;; esac
}
assert_not_invoked() { # desc
  if [ -e "$ARGV_LOG" ] || [ -e "$PWD_LOG" ]; then
    no "$1: scanner was invoked"
  else
    ok "$1"
  fi
}
assert_nonzero() { # desc, status
  if [ "$2" -ne 0 ] 2>/dev/null; then ok "$1 [$2]"; else no "$1: expected nonzero, got [$2]"; fi
}
read_log() { # $1 = log path; empty when the stub never wrote it
  if [ -e "$1" ]; then printf '%s' "$(<"$1")"; fi
}

STATUS=0
OUT=""
STUB_MSG=""
# Reported by `govulncheck -version` in the version-aware stub: a DB block, an
# empty block, or whatever the case needs.
STUB_VERSION_BLOCK=""
ARGV_LOG="$TMP/argv.log"
PWD_LOG="$TMP/pwd.log"
ENV_LOG="$TMP/env.log"
# Extra NAME=value assignments handed to the next run_check via env -i.
ENV_ARGS=()

run_check() { # $1 = child PATH, remaining args = gate arguments
  local pathv="$1"; shift
  "$RM_BIN" -f "$ARGV_LOG" "$PWD_LOG" "$ENV_LOG"
  local status=0
  OUT="$("$ENV_BIN" -i PATH="$pathv" STUB_MSG="$STUB_MSG" \
        STUB_VERSION_BLOCK="$STUB_VERSION_BLOCK" \
        STUB_ARGV_LOG="$ARGV_LOG" STUB_PWD_LOG="$PWD_LOG" STUB_ENV_LOG="$ENV_LOG" \
        "${ENV_ARGS[@]}" \
        "$BASH_BIN" "$CHECK" "$@" 2>&1)" || status=$?
  STATUS="$status"
}

make_stub() { # $1 = dir, $2 = exit status
  local d="$1" st="$2"
  "$MKDIR_BIN" -p "$d"
  {
    printf '#!%s\n' "$BASH_BIN"
    printf '%s\n' 'printf "%s\n" "$*" > "$STUB_ARGV_LOG"'
    printf '%s\n' 'pwd > "$STUB_PWD_LOG"'
    printf '%s\n' 'printf "GOCACHE=%s\n" "${GOCACHE:-<unset>}" > "$STUB_ENV_LOG"'
    printf '%s\n' 'printf "GOPATH=%s\n" "${GOPATH:-<unset>}" >> "$STUB_ENV_LOG"'
    printf '%s\n' 'printf "GOMODCACHE=%s\n" "${GOMODCACHE:-<unset>}" >> "$STUB_ENV_LOG"'
    printf '%s\n' 'printf "%s\n" "$STUB_MSG"'
    printf 'exit %s\n' "$st"
  } > "$d/govulncheck"
  "$CHMOD_BIN" +x "$d/govulncheck"
}

# A stub that answers `-version` with $STUB_VERSION_BLOCK (like the real
# govulncheck, which prints the DB block and exits 0 before scanning) and the
# scan invocation with $STUB_MSG plus the given status.
make_version_stub() { # $1 = dir, $2 = scan exit status
  local d="$1" st="$2"
  "$MKDIR_BIN" -p "$d"
  {
    printf '#!%s\n' "$BASH_BIN"
    printf '%s\n' 'printf "%s\n" "$*" > "$STUB_ARGV_LOG"'
    printf '%s\n' 'pwd > "$STUB_PWD_LOG"'
    printf '%s\n' 'printf "GOCACHE=%s\n" "${GOCACHE:-<unset>}" > "$STUB_ENV_LOG"'
    printf '%s\n' 'printf "GOPATH=%s\n" "${GOPATH:-<unset>}" >> "$STUB_ENV_LOG"'
    printf '%s\n' 'printf "GOMODCACHE=%s\n" "${GOMODCACHE:-<unset>}" >> "$STUB_ENV_LOG"'
    printf '%s\n' 'if [ "${1:-}" = "-version" ]; then'
    printf '%s\n' '  printf "%s\n" "${STUB_VERSION_BLOCK:-}"'
    printf '%s\n' '  exit 0'
    printf '%s\n' 'fi'
    printf '%s\n' 'printf "%s\n" "$STUB_MSG"'
    printf 'exit %s\n' "$st"
  } > "$d/govulncheck"
  "$CHMOD_BIN" +x "$d/govulncheck"
}

# --- 1. missing scanner, strict release mode --------------------------------
run_check "$SAFE_BIN"
assert_eq "1 missing scanner strict: exit status" "$STATUS" "2"
assert_has "1 missing scanner strict: INCOMPLETE" "$OUT" "INCOMPLETE"
assert_has "1 missing scanner strict: install guidance" "$OUT" "govulncheck"
assert_lacks "1 missing scanner strict: never PASS" "$OUT" "PASS"

# --- 2. missing scanner, explicit --development -----------------------------
run_check "$SAFE_BIN" --development
assert_eq "2 missing scanner --development: exit status" "$STATUS" "0"
assert_has "2 missing scanner --development: INCOMPLETE" "$OUT" "INCOMPLETE"
assert_has "2 missing scanner --development: release-acceptance disclosure" \
  "$OUT" "does not satisfy release acceptance"
assert_lacks "2 missing scanner --development: never PASS" "$OUT" "PASS"

# --- 3. stub scanner exit 0 -------------------------------------------------
make_stub "$TMP/stub-ok" 0
STUB_PATH="$TMP/stub-ok:$SAFE_BIN"
STUB_MSG="govulncheck: no vulnerabilities found"
run_check "$STUB_PATH"
assert_eq "3 stub exit 0: exit status" "$STATUS" "0"
assert_has "3 stub exit 0: PASS" "$OUT" "security-check: PASS"
assert_has "3 stub exit 0: scanner output forwarded" "$OUT" "no vulnerabilities found"
assert_eq "3 stub exit 0: scanner argv" "$(read_log "$ARGV_LOG")" "./..."
assert_eq "3 stub exit 0: scanner cwd is repository root" "$(read_log "$PWD_LOG")" "$ROOT"
assert_has "3 stub exit 0: GOCACHE forced to repo .scratch" \
  "$(read_log "$ENV_LOG")" "GOCACHE=$ROOT/.scratch/gocache"
assert_has "3 stub exit 0: GOPATH forced to repo .scratch" \
  "$(read_log "$ENV_LOG")" "GOPATH=$ROOT/.scratch/gomod"
assert_has "3 stub exit 0: GOMODCACHE forced to repo .scratch" \
  "$(read_log "$ENV_LOG")" "GOMODCACHE=$ROOT/.scratch/gomod/pkg/mod"
# A scanner that reports no DB provenance must produce the explicit
# "unavailable" line, never an invented date.
assert_has "3 stub exit 0: provenance line is present" \
  "$OUT" "security-check: advisory DB provenance unavailable (scanner did not report it)"
assert_lacks "3 stub exit 0: no fabricated DB date" "$OUT" "as-of"

# --- 3c. the scanner's own DB provenance is printed verbatim -----------------
# govulncheck -version prints a DB block ("DB: <url>", "DB updated: <ts>")
# before scanning. The gate must repeat it on the scan path, so an archived
# PASS is dated to the advisory DB it used.
make_version_stub "$TMP/stub-version" 0
STUB_PATH="$TMP/stub-version:$SAFE_BIN"
STUB_MSG="No vulnerabilities found."
STUB_VERSION_BLOCK="Go: go1.26.6
Scanner: govulncheck@v1.8.0
DB: https://vuln.go.dev
DB updated: 2026-09-16 18:00:43 +0000 UTC"
run_check "$STUB_PATH"
assert_eq "3c provenance stub: exit status" "$STATUS" "0"
assert_has "3c provenance stub: PASS" "$OUT" "security-check: PASS"
assert_has "3c provenance stub: DB source and timestamp reported" \
  "$OUT" "security-check: advisory DB https://vuln.go.dev as-of 2026-09-16 18:00:43 +0000 UTC"
assert_lacks "3c provenance stub: no unavailable line when reported" \
  "$OUT" "provenance unavailable"
assert_has "3c provenance stub: scan still runs with ./..." \
  "$OUT" "No vulnerabilities found."

# --- 3d. a scanner whose DB block carries no timestamp -----------------------
# govulncheck omits "DB updated" when the metadata fetch fails (offline). The
# gate must then say so instead of reusing a remembered date.
STUB_VERSION_BLOCK="Go: go1.26.6
Scanner: govulncheck@v1.8.0
DB: https://vuln.go.dev"
run_check "$STUB_PATH"
assert_eq "3d provenance without timestamp: exit status" "$STATUS" "0"
assert_has "3d provenance without timestamp: unavailable line" \
  "$OUT" "security-check: advisory DB provenance unavailable (scanner did not report it)"
assert_lacks "3d provenance without timestamp: no as-of claim" "$OUT" "as-of"
assert_lacks "3d provenance without timestamp: no fabricated date" "$OUT" "2026-"
STUB_VERSION_BLOCK=""

# --- 3b. an inherited/preset Go cache env is OVERRIDDEN (mutation check) -----
# The repo caches are plain exports, never `${VAR:-...}` defaults. A default
# form loses to an inherited GOPATH (this harness exports a read-only one) and
# the scan then resolves modules from a cache it cannot write — the Task 13
# concern-2 mechanical failure. Restoring `${VAR:-...}` must turn this case red.
ENV_ARGS=(
  GOCACHE="$TMP/preset-gocache"
  GOPATH="$TMP/preset-gopath"
  GOMODCACHE="$TMP/preset-modcache"
)
run_check "$STUB_PATH"
assert_eq "3b preset Go env: exit status" "$STATUS" "0"
assert_has "3b preset Go env: GOCACHE overridden by repo cache" \
  "$(read_log "$ENV_LOG")" "GOCACHE=$ROOT/.scratch/gocache"
assert_has "3b preset Go env: GOPATH overridden by repo cache" \
  "$(read_log "$ENV_LOG")" "GOPATH=$ROOT/.scratch/gomod"
assert_has "3b preset Go env: GOMODCACHE overridden by repo cache" \
  "$(read_log "$ENV_LOG")" "GOMODCACHE=$ROOT/.scratch/gomod/pkg/mod"
assert_lacks "3b preset Go env: preset paths never reach the scanner" \
  "$(read_log "$ENV_LOG")" "$TMP/preset-"
ENV_ARGS=()

# --- 4. stub scanner exit 1 with a finding ----------------------------------
make_stub "$TMP/stub-finding" 1
STUB_PATH="$TMP/stub-finding:$SAFE_BIN"
STUB_MSG="Vulnerability #1: GO-2024-0001 (example finding)"
run_check "$STUB_PATH"
assert_eq "4 stub exit 1 strict: exit status preserved" "$STATUS" "1"
assert_has "4 stub exit 1 strict: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_has "4 stub exit 1 strict: scanner message preserved" "$OUT" "GO-2024-0001"
assert_lacks "4 stub exit 1 strict: never PASS" "$OUT" "PASS"
run_check "$STUB_PATH" --development
assert_eq "4 stub exit 1 --development: exit status preserved" "$STATUS" "1"
assert_has "4 stub exit 1 --development: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_has "4 stub exit 1 --development: scanner message preserved" "$OUT" "GO-2024-0001"
assert_lacks "4 stub exit 1 --development: never PASS" "$OUT" "PASS"

# --- 4b. stub scanner exit 3 = govulncheck's "vulnerabilities found" ---------
# Exit status 3 is the scanner's own findings contract (x/vuln
# internal/scan/errors.go errVulnerabilitiesFound; reproduced against a
# known-vulnerable module). The gate may name that failure, and must still
# fail: naming a findings failure is not a pass.
make_stub "$TMP/stub-vulns" 3
STUB_PATH="$TMP/stub-vulns:$SAFE_BIN"
STUB_MSG="Vulnerability #1: GO-2025-3553 (example finding)"
run_check "$STUB_PATH"
assert_eq "4b findings exit 3: exit status preserved" "$STATUS" "3"
assert_has "4b findings exit 3: classified as findings" \
  "$OUT" "security-check: scan failed on findings (scanner exit status 3: vulnerabilities found), not on infrastructure"
assert_has "4b findings exit 3: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_lacks "4b findings exit 3: never PASS" "$OUT" "PASS"
assert_lacks "4b findings exit 3: not misreported as a DB failure" \
  "$OUT" "scan failed on the advisory DB"
run_check "$STUB_PATH" --development
assert_eq "4b findings exit 3 --development: exit status preserved" "$STATUS" "3"
assert_lacks "4b findings exit 3 --development: never PASS" "$OUT" "PASS"

# --- 5. stub scanner exit 7 with a network-unavailable message --------------
# An unclassified nonzero status keeps the generic line only: the gate does not
# guess whether a status it cannot attribute came from the network.
make_stub "$TMP/stub-network" 7
STUB_PATH="$TMP/stub-network:$SAFE_BIN"
STUB_MSG="govulncheck: network unavailable: dial tcp: lookup vuln.go.dev: no such host"
run_check "$STUB_PATH"
assert_eq "5 stub exit 7 strict: exit status preserved" "$STATUS" "7"
assert_has "5 stub exit 7 strict: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_has "5 stub exit 7 strict: scanner message preserved" "$OUT" "network unavailable"
assert_lacks "5 stub exit 7 strict: never PASS" "$OUT" "PASS"
assert_lacks "5 stub exit 7 strict: unattributable failure is not classified" \
  "$OUT" "scan failed on the advisory DB"
run_check "$STUB_PATH" --development
assert_eq "5 stub exit 7 --development: exit status preserved" "$STATUS" "7"
assert_has "5 stub exit 7 --development: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_has "5 stub exit 7 --development: scanner message preserved" "$OUT" "network unavailable"
assert_lacks "5 stub exit 7 --development: never PASS" "$OUT" "PASS"

# --- 5b. hermetic offline: no DB reachable, no cached DB ---------------------
# The real offline signature (probed with `unshare -rn`): govulncheck cannot
# fetch index/modules.json.gz, prints its own "fetching vulnerabilities:"
# wrapper and exits 1. No DB block, so no timestamp — the gate must report
# provenance unavailable AND classify the failure as a DB/network failure,
# while the forced repo-local caches keep the run from failing on $HOME.
# HOME and XDG_CACHE_HOME point at a nonexistent path on purpose: there is no
# local vulndb to fall back to, which is exactly the offline case.
make_version_stub "$TMP/stub-offline" 1
STUB_PATH="$TMP/stub-offline:$SAFE_BIN"
STUB_VERSION_BLOCK=""
STUB_MSG='govulncheck: fetching vulnerabilities: Get "https://vuln.go.dev/index/modules.json.gz": dial tcp 34.117.213.18:443: connect: network is unreachable'
ENV_ARGS=(HOME=/nonexistent XDG_CACHE_HOME=/nonexistent)
run_check "$STUB_PATH"
assert_eq "5b offline, no cached DB: exit status preserved" "$STATUS" "1"
assert_has "5b offline, no cached DB: provenance unavailable" \
  "$OUT" "security-check: advisory DB provenance unavailable (scanner did not report it)"
assert_has "5b offline, no cached DB: classified as a DB/network failure" \
  "$OUT" "security-check: scan failed on the advisory DB (fetch/network failure), not on findings: no finding was evaluated"
assert_has "5b offline, no cached DB: INCOMPLETE line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_lacks "5b offline, no cached DB: never PASS" "$OUT" "PASS"
assert_lacks "5b offline, no cached DB: not misreported as findings" \
  "$OUT" "scan failed on findings"
assert_has "5b offline, no cached DB: GOCACHE still repo-local" \
  "$(read_log "$ENV_LOG")" "GOCACHE=$ROOT/.scratch/gocache"
assert_has "5b offline, no cached DB: GOPATH still repo-local" \
  "$(read_log "$ENV_LOG")" "GOPATH=$ROOT/.scratch/gomod"
assert_has "5b offline, no cached DB: GOMODCACHE still repo-local" \
  "$(read_log "$ENV_LOG")" "GOMODCACHE=$ROOT/.scratch/gomod/pkg/mod"
ENV_ARGS=()

# --- 6. argument handling: unknown or extra arguments -----------------------
# A working stub stays on PATH, so an invocation would be recorded: the
# assertion is that the gate refuses to run it at all.
make_stub "$TMP/stub-unused" 0
STUB_PATH="$TMP/stub-unused:$SAFE_BIN"
STUB_MSG="scanner must not run"

run_check "$STUB_PATH" --bogus
assert_eq "6 unknown argument: exit status" "$STATUS" "2"
assert_has "6 unknown argument: usage" "$OUT" "usage"
assert_lacks "6 unknown argument: never PASS" "$OUT" "PASS"
assert_lacks "6 unknown argument: scanner output absent" "$OUT" "scanner must not run"
assert_not_invoked "6 unknown argument: no scanner invocation"

run_check "$STUB_PATH" --development --extra
assert_eq "6 extra argument after --development: exit status" "$STATUS" "2"
assert_lacks "6 extra argument after --development: never PASS" "$OUT" "PASS"
assert_not_invoked "6 extra argument after --development: no scanner invocation"

run_check "$STUB_PATH" extra
assert_eq "6 bare extra argument: exit status" "$STATUS" "2"
assert_lacks "6 bare extra argument: never PASS" "$OUT" "PASS"
assert_not_invoked "6 bare extra argument: no scanner invocation"

run_check "$STUB_PATH" --development extra
assert_eq "6 --development plus extra: exit status" "$STATUS" "2"
assert_lacks "6 --development plus extra: never PASS" "$OUT" "PASS"
assert_not_invoked "6 --development plus extra: no scanner invocation"

# --- 7. an unusable HOME never changes the gate's verdict -------------------
# $HOME=/nonexistent cannot host a Go build cache: the repo-local convention
# must keep the scan runnable, and strict mode must still fail closed.
ENV_ARGS=(HOME=/nonexistent)
run_check "$SAFE_BIN"
assert_eq "7 missing scanner, HOME=/nonexistent: exit status" "$STATUS" "2"
assert_has "7 missing scanner, HOME=/nonexistent: INCOMPLETE" "$OUT" "INCOMPLETE"
assert_lacks "7 missing scanner, HOME=/nonexistent: never PASS" "$OUT" "PASS"

STUB_MSG="govulncheck: no vulnerabilities found"
run_check "$STUB_PATH"
assert_eq "7 stub exit 0, HOME=/nonexistent: exit status" "$STATUS" "0"
assert_has "7 stub exit 0, HOME=/nonexistent: repo-local GOCACHE" \
  "$(read_log "$ENV_LOG")" "GOCACHE=$ROOT/.scratch/gocache"
ENV_ARGS=()

# --- 8. real scanner in an empty network namespace (optional, guarded) -------
# The only case that runs the real scanner: it proves the fail-closed law holds
# when the advisory DB cannot be reached at all, WITH the forced repo-local
# caches in place — a missing DB is a gate failure, not something a cache can
# paper over. No network call is made by construction (the namespace has no
# route), and the case SKIPs with a printed reason when the scanner or
# `unshare -rn` is unavailable.
REAL_SCANNER="$ROOT/.scratch/gomod/bin/govulncheck"
UNSHARE_BIN="$(command -v unshare || true)"
TIMEOUT_BIN="$(command -v timeout || true)"
# govulncheck shells out to `go`, and a version-manager shim on PATH may itself
# need the network: prefer the real toolchain binary behind GOROOT. Without it
# the offline run fails before the DB fetch (still fail-closed, but it proves
# nothing about the DB path), so the classification is then not asserted.
GOROOT_DIR=""
if [ -n "$GO_BIN" ]; then GOROOT_DIR="$("$GO_BIN" env GOROOT 2>/dev/null || true)"; fi
REAL_GO_DIR=""
if [ -n "$GOROOT_DIR" ] && [ -x "$GOROOT_DIR/bin/go" ]; then REAL_GO_DIR="$GOROOT_DIR/bin"; fi
if [ ! -x "$REAL_SCANNER" ]; then
  printf 'skip - 8 real scanner offline: no scanner at %s\n' "$REAL_SCANNER"
elif [ -z "$UNSHARE_BIN" ] || ! "$UNSHARE_BIN" -rn true 2>/dev/null; then
  printf 'skip - 8 real scanner offline: unshare -rn is unavailable here\n'
else
  NET_BIN="$TMP/net-bin"
  "$MKDIR_BIN" -p "$NET_BIN"
  "$LN_BIN" -s "$REAL_SCANNER" "$NET_BIN/govulncheck"
  "$LN_BIN" -s "$DIRNAME_BIN" "$NET_BIN/dirname"
  NET_PATH="$NET_BIN"
  if [ -n "$REAL_GO_DIR" ]; then NET_PATH="$NET_BIN:$REAL_GO_DIR"; fi
  NET_STATUS=0
  if [ -n "$TIMEOUT_BIN" ]; then
    OUT="$("$TIMEOUT_BIN" 300 "$UNSHARE_BIN" -rn "$ENV_BIN" -i PATH="$NET_PATH" \
          "$BASH_BIN" "$CHECK" 2>&1)" || NET_STATUS=$?
  else
    OUT="$("$UNSHARE_BIN" -rn "$ENV_BIN" -i PATH="$NET_PATH" \
          "$BASH_BIN" "$CHECK" 2>&1)" || NET_STATUS=$?
  fi
  STATUS="$NET_STATUS"
  assert_nonzero "8 real scanner offline: gate fails closed" "$STATUS"
  assert_lacks "8 real scanner offline: never PASS" "$OUT" "PASS"
  assert_has "8 real scanner offline: INCOMPLETE line" \
    "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
  if [ -n "$REAL_GO_DIR" ]; then
    assert_has "8 real scanner offline: provenance unavailable, no invented date" \
      "$OUT" "security-check: advisory DB provenance unavailable (scanner did not report it)"
    assert_has "8 real scanner offline: classified as a DB/network failure" \
      "$OUT" "security-check: scan failed on the advisory DB"
    assert_lacks "8 real scanner offline: not misreported as findings" \
      "$OUT" "scan failed on findings"
  else
    printf 'note - 8 real scanner offline: no real toolchain behind GOROOT; DB classification not asserted\n'
  fi
fi

# --- summary ----------------------------------------------------------------
printf '\n%s\n' "----------------------------------------"
printf 'security-check-test: %d passed, %d failed\n' "$PASS" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
