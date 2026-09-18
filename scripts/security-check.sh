#!/usr/bin/env bash
#
# security-check.sh — release dependency-scan gate (T13A: fail closed).
#
# Strict release mode (no arguments):
#   * govulncheck ./... must run from the repository root and exit 0.
#   * Missing scanner  => INCOMPLETE + install guidance, exit 2.
#   * Any nonzero scan => INCOMPLETE or findings, scanner status preserved.
#   * A failed scan is never reported as PASS.
#
# Development mode (--development):
#   * ONLY a missing scanner may be skipped (exit 0), with an explicit
#     disclosure that the result does not satisfy release acceptance.
#   * A scanner that runs and fails still fails, status preserved.
#
# Advisory DB freshness:
#   * Every scan prints the advisory-DB provenance the scanner itself reports
#     (`security-check: advisory DB <source> as-of <timestamp>`), or the
#     explicit "provenance unavailable" line when the scanner reports none.
#     A PASS is only meaningful as-of that DB, so the gate never invents a date.
#   * The scanner's nonzero status is preserved verbatim; the gate only adds a
#     line classifying the failure it can prove from the scanner's own report
#     (advisory-DB fetch failure vs. vulnerabilities found). Classification
#     never softens the verdict: a failed scan is still a failed gate.
#
# This script installs, downloads and updates nothing: it looks for an
# already-installed govulncheck on PATH and runs it as-is. No eval, no
# go get, no configuration switches.
#
# Exit: 0 only when the scan genuinely passed (or a development-mode skip);
#       2 for usage errors and for a missing scanner in strict mode;
#       otherwise the scanner's own nonzero status.

set -euo pipefail

usage() {
  printf 'usage: %s [--development]\n' "$0" >&2
  printf '  (no argument)  strict release gate: a missing scanner is INCOMPLETE\n' >&2
  printf '  --development  local development: only a missing scanner may skip\n' >&2
}

development=0
if [ "$#" -gt 0 ]; then
  case "$1" in
    --development) development=1 ;;
    *)
      printf 'security-check: unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
fi
if [ "$#" -gt 1 ]; then
  printf 'security-check: unexpected extra argument: %s\n' "$2" >&2
  usage
  exit 2
fi

# Repository root from this script's own location: the scan must run there
# regardless of the caller's cwd.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"

# The Go caches live under .scratch so the script works in sandboxed
# environments where $HOME is not writable. These are FORCED, not
# `${VAR:-default}` fallbacks: an inherited GOPATH may point at a read-only
# location (this harness exports GOPATH=$HOME/go), which would defeat the
# convention and make the scanner die on a download lock instead of scanning.
# Same plain-export rule as scripts/verify-full.sh.
#
# Where the VULN DB lives (probed 2026-09-18 against govulncheck@v1.8.0): the
# x/vuln client has NO on-disk vulnerability database. It fetches the index and
# entries over HTTP per run and writes nothing under $HOME, XDG_CACHE_HOME or
# GOPATH — a fresh HOME, a fresh XDG_CACHE_HOME and a read-only HOME all give
# byte-identical results in ~1.2s, and `find` shows no cache directory created.
# So there is no HOME-dependent stale-DB cache to redirect and no env var or
# flag that selects one (`-db` picks a *different* database, not a cache; the
# only env the scanner reads is what the `go` command it shells out to uses).
# The forced GOCACHE/GOPATH/GOMODCACHE above therefore cover every
# HOME-sensitive piece of scan state there is. Do NOT add a VULNDB/cache-dir
# variable here: it would be theatre, not hardening. The consequence is
# documented in SECURITY.md: with no local DB, a PASS cannot go stale locally,
# but it is only valid as-of the timestamp printed below.
export GOCACHE="$root/.scratch/gocache"
export GOPATH="$root/.scratch/gomod"
export GOMODCACHE="$root/.scratch/gomod/pkg/mod"

scanner="$(command -v govulncheck || true)"
if [ -z "$scanner" ]; then
  printf 'security-check: INCOMPLETE - govulncheck was not found on PATH\n' >&2
  printf 'security-check: nothing is installed here; install the scanner yourself:\n' >&2
  printf 'security-check:   go install golang.org/x/vuln/cmd/govulncheck@latest\n' >&2
  printf 'security-check: then re-run: bash scripts/security-check.sh\n' >&2
  if [ "$development" -eq 1 ]; then
    printf 'security-check: development mode: dependency scan skipped; this result does not satisfy release acceptance.\n' >&2
    exit 0
  fi
  printf 'security-check: strict release mode: refusing to report success without a scan.\n' >&2
  exit 2
fi

cd "$root"
printf 'security-check: running %s ./... from %s\n' "$scanner" "$root" >&2

# Advisory DB provenance, printed on every scan so an archived PASS is dated to
# the DB it used. `govulncheck -version` prints "DB: <url>" and
# "DB updated: <timestamp>"; the timestamp is the database's own last-modified
# as reported by a live metadata fetch (x/vuln internal/client.LastModifiedTime
# — see docs), and the line is simply absent when that fetch fails, so an
# offline run reports no timestamp rather than a stale one.
#
# The probe runs BEFORE the scan, so the timestamp printed is a conservative
# (never newer than the scan's own) statement of the DB the scan used. The
# probe's own failure is ignored: it must never change the verdict, and a
# scanner that does not implement -version simply yields "unavailable".
version_out="$("$scanner" -version 2>/dev/null || true)"
db_source=""
db_updated=""
while IFS= read -r line; do
  case "$line" in
    'DB updated: '*) db_updated="${line#DB updated: }" ;;
    'DB: '*) db_source="${line#DB: }" ;;
  esac
done <<<"$version_out"

if [ -n "$db_updated" ]; then
  printf 'security-check: advisory DB %s as-of %s\n' \
    "${db_source:-<source not reported>}" "$db_updated" >&2
else
  printf 'security-check: advisory DB provenance unavailable (scanner did not report it)\n' >&2
fi

# The scanner's report is replayed verbatim (stdout and stderr merged, so the
# gate can classify the failure without swallowing a word of it). This gate
# still never guesses: the classification below quotes the scanner's own exit
# status and its own message, and never turns a failure into a pass.
status=0
scan_output="$("$scanner" ./... 2>&1)" || status=$?
if [ -n "$scan_output" ]; then
  printf '%s\n' "$scan_output"
fi

if [ "$status" -eq 0 ]; then
  printf 'security-check: PASS\n'
  exit 0
fi

# Failure classification, only where the scanner's own report makes it provable:
#   * "fetching vulnerabilities: ..." is govulncheck's own wrapper for a failed
#     advisory-DB fetch (x/vuln internal/vulncheck/fetch.go); offline runs fail
#     here before any finding can be evaluated.
#   * exit status 3 is govulncheck's documented result for vulnerabilities found
#     (x/vuln internal/scan/errors.go: errVulnerabilitiesFound; reproduced with
#     a known-vulnerable module, which exited 3).
# Anything else stays unclassified rather than guessed at.
case "$scan_output" in
  *'fetching vulnerabilities:'*)
    printf 'security-check: scan failed on the advisory DB (fetch/network failure), not on findings: no finding was evaluated\n' >&2
    ;;
  *)
    if [ "$status" -eq 3 ]; then
      printf 'security-check: scan failed on findings (scanner exit status 3: vulnerabilities found), not on infrastructure\n' >&2
    fi
    ;;
esac

printf 'security-check: INCOMPLETE or findings (scanner failed)\n' >&2
exit "$status"
