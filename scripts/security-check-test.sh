#!/usr/bin/env bash
#
# security-check-test.sh — hermetic acceptance tests for scripts/security-check.sh.
#
# Every case runs the gate with an isolated PATH that cannot see the real
# govulncheck: only the utilities the gate itself needs (dirname) are linked
# into a scratch bin directory. Stub scanners are harmless local shell
# scripts. No live scan, no network call, no dependency installation.
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
read_log() { # $1 = log path; empty when the stub never wrote it
  if [ -e "$1" ]; then printf '%s' "$(<"$1")"; fi
}

STATUS=0
OUT=""
STUB_MSG=""
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

# --- 5. stub scanner exit 7 with a network-unavailable message --------------
make_stub "$TMP/stub-network" 7
STUB_PATH="$TMP/stub-network:$SAFE_BIN"
STUB_MSG="govulncheck: network unavailable: dial tcp: lookup vuln.go.dev: no such host"
run_check "$STUB_PATH"
assert_eq "5 stub exit 7 strict: exit status preserved" "$STATUS" "7"
assert_has "5 stub exit 7 strict: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_has "5 stub exit 7 strict: scanner message preserved" "$OUT" "network unavailable"
assert_lacks "5 stub exit 7 strict: never PASS" "$OUT" "PASS"
run_check "$STUB_PATH" --development
assert_eq "5 stub exit 7 --development: exit status preserved" "$STATUS" "7"
assert_has "5 stub exit 7 --development: INCOMPLETE or findings line" \
  "$OUT" "security-check: INCOMPLETE or findings (scanner failed)"
assert_has "5 stub exit 7 --development: scanner message preserved" "$OUT" "network unavailable"
assert_lacks "5 stub exit 7 --development: never PASS" "$OUT" "PASS"

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

# --- summary ----------------------------------------------------------------
printf '\n%s\n' "----------------------------------------"
printf 'security-check-test: %d passed, %d failed\n' "$PASS" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
