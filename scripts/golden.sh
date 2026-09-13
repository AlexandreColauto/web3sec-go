#!/usr/bin/env bash
# Golden suite v5 (Tasks 17 + 24 + 32 + 38): the scripted P0+P1+P2+P3+P4
# op-sequence, run against the Go binary with a pinned clock, a pinned id
# stream, an isolated global memory store seeded from the P4 fixture, one
# pinned baseline store, aligned prompt roots, the same run root and the
# committed P4 fixture behind WEBV2_POC_ROOT / WEBV2_EVAL_DIR /
# WEBV2_SFT_STORE. The pins exist so a 179-step sequence of FRESH PROCESSES
# replays reproducibly; check-golden.py then validates the resulting tree
# (declared exit codes, intact event chain, 14 audit sections).
# Go-only since the twin retired 2026-09-09; the P4 recipe and its fixture
# are the frozen oracle. See docs/gates/P4-gate.md and golden-v5.
set -u
cd "$(dirname "$0")/.."
export GOCACHE="$PWD/.scratch/gocache"
export GOPATH="$PWD/.scratch/gopath"
export GOMODCACHE="$PWD/.scratch/gomodcache"
export GOFLAGS=-mod=mod
# Formatting gate (critic I-9): a repo whose law is gofmt-clean must not carry
# drift into a golden run. Cheap, deterministic, fails before the long replay.
unformatted=$(gofmt -l internal cmd 2>/dev/null)
if [ -n "$unformatted" ]; then
  echo "golden: gofmt drift:"; echo "$unformatted"; exit 1
fi

python3 scripts/golden-run.py || { echo "golden: run failed"; exit 1; }
python3 scripts/check-golden.py
