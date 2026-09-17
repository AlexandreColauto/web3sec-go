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

# The scanner's own stdout/stderr is forwarded untouched: this gate never
# guesses what a failure means (network, findings, crash).
status=0
"$scanner" ./... || status=$?

if [ "$status" -eq 0 ]; then
  printf 'security-check: PASS\n'
  exit 0
fi

printf 'security-check: INCOMPLETE or findings (scanner failed)\n' >&2
exit "$status"
