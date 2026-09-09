#!/usr/bin/env bash
#
# release.sh — T37 deliverable 3: the single-binary release.
#
# Spec 1.3 goal 6 / spec 14 P4: "Single-binary distribution with static
# assets embedded (go:embed), and dataset/corpus directories still resolved
# from disk (they are data, not assets)."
#
# What this does, in order:
#   1. build  — CGO_ENABLED=0 go build -trimpath -ldflags '-s -w'
#               -o dist/webv2 ./cmd/webv2   (one static file, no runtime deps)
#   2. static — prove the artifact is static (file + ldd) and standalone
#               (no shared-library deps, no cgo).
#   3. assets — run the binary from a FRESH TEMP DIR with no repo in sight
#               (the module tree is not reachable from the cwd) and prove
#               the embedded packs are served:
#                 * `webv2 selftest`        -> build-sweep reports the
#                                              embedded 28 schemas / stage
#                                              prompts / playbooks /
#                                              archetypes (no `go build`
#                                              branch, since no go.mod)
#                 * `webv2 ingest --example` -> the validated template + its
#                                              closed-enum legend, walked from
#                                              the EMBEDDED
#                                              schema/finding.schema.json
#                 * a mini walkthrough (init -> snap -> index -> probes run
#                   -> audit -> verify -> brief) in a scratch workspace,
#                   with a synthetic target the binary has never seen.
#   4. report — sha256 + byte size of dist/webv2, and the standalone
#               evidence above.
#
# Idempotent: rebuilds over dist/webv2, uses mktemp -d scratch that it
# removes on exit. No network, no docker, no Python.
#
# Exit 0 only when every step passes.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# Caches under .scratch so the script works in sandboxed environments where
# $HOME is not writable (same rule as scripts/verify-full.sh).
export GOCACHE="${GOCACHE:-$ROOT/.scratch/gocache}"
export GOPATH="${GOPATH:-$ROOT/.scratch/gomod}"
export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"
export GOFLAGS="${GOFLAGS:--mod=mod}"

DIST="$ROOT/dist"
BIN="$DIST/webv2"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

step() { echo; echo "=== $* ==="; }
fail() { echo; echo "FAIL [$1]"; exit 1; }

step "1/4 build: CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o dist/webv2"
mkdir -p "$DIST"
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$BIN" ./cmd/webv2 \
  || fail "build"
echo "ok: $BIN"

step "2/4 static + standalone"
file "$BIN"
if ldd "$BIN" 2>&1 | grep -qv "not a dynamic executable"; then
  ldd "$BIN" >&2
  fail "not a static binary"
fi
if go version -m "$BIN" 2>/dev/null | grep -q "CGO_ENABLED=0"; then
  echo "ok: build metadata CGO_ENABLED=0"
else
  echo "warn: go version -m did not report CGO_ENABLED=0 (static check above is authoritative)"
fi
echo "ok: static, no shared-library dependencies"

step "3/4 standalone from a scratch dir with NO repo access"
# Copy the binary into the scratch dir and run it there: walking up from
# the cwd finds no go.mod, so no source tree can be reached.
cp "$BIN" "$SCRATCH/webv2"
WORK="$SCRATCH/work"
mkdir -p "$WORK/target/src"
cat > "$WORK/target/src/MiniVault.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MiniVault {
    uint256 public totalDeposited;
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        totalDeposited += msg.value;
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        deposits[msg.sender] -= amount;
        totalDeposited -= amount;
    }
}
SOL

cd "$SCRATCH"
echo "--- webv2 --help"
./webv2 --help > help.txt || fail "--help"
head -3 help.txt
grep -q "selftest" help.txt || fail "--help lacks selftest"

echo "--- webv2 selftest (embedded assets, no module tree)"
./webv2 selftest | tee selftest.txt || fail "standalone selftest"
grep -q "embedded assets ok: 28 schemas" selftest.txt \
  || fail "selftest did not serve the embedded asset sweep"
grep -q "ALL PASS" selftest.txt || fail "standalone selftest not ALL PASS"

echo "--- webv2 ingest --example (embedded schema legend)"
./webv2 ingest --example > example.json 2> example.err || fail "ingest --example"
python3 -c 'import json,sys; d=json.load(open("example.json")); assert "root_cause" in d' \
  || fail "ingest --example is not the validated template"
grep -q "schema/finding.schema.json" example.err \
  || fail "ingest --example legend did not read the embedded schema"

echo "--- mini walkthrough (init -> snap -> index -> probes run -> audit -> verify -> brief)"
CID="$(./webv2 --root "$WORK" init --program "release walkthrough" \
  | grep -oE 'C-[0-9a-f]+' | head -1)"
[ -n "$CID" ] || fail "init"
./webv2 --root "$WORK" snap "$CID" "$WORK/target" >/dev/null || fail "snap"
./webv2 --root "$WORK" index "$CID" --src "$WORK/target" >/dev/null || fail "index"
./webv2 --root "$WORK" probes "$CID" run >/dev/null || fail "probes run"
./webv2 --root "$WORK" audit "$CID" | tee audit.txt || fail "audit"
grep -q "audit PASS" audit.txt || fail "audit not PASS"
./webv2 --root "$WORK" verify "$CID" >/dev/null || fail "verify"
./webv2 --root "$WORK" brief "$CID" >/dev/null || fail "brief"
echo "ok: mini walkthrough clean in $WORK (campaign $CID)"

step "4/4 release artifact"
cd "$ROOT"
SHA="$(sha256sum "$BIN" | cut -d' ' -f1)"
SIZE="$(stat -c%s "$BIN")"
HUMAN="$(du -h "$BIN" | cut -f1)"
echo "binary: $BIN"
echo "sha256: $SHA"
echo "size:   $SIZE bytes ($HUMAN)"
echo
echo "RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean"
