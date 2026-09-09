#!/usr/bin/env bash
# Golden suite v5 (Tasks 17 + 24 + 32 + 38): the scripted P0+P1+P2+P3+P4
# op-sequence through both twins with a pinned clock, a pinned id stream, an
# isolated global memory store seeded from the P4 fixture, one pinned
# baseline store, aligned prompt roots, the same run root and the committed
# P4 fixture behind WEBV2_POC_ROOT / WEBV2_EVAL_DIR / WEBV2_SFT_STORE;
# byte-diff every artifact and capture.
# See docs/gates/P4-gate.md (P4), golden-v4.md (P3), golden-v3.md (P2),
# golden-v2.md (P1).
set -u
cd "$(dirname "$0")/.."
export GOCACHE="$PWD/.scratch/gocache"
export GOPATH="$PWD/.scratch/gopath"
export GOMODCACHE="$PWD/.scratch/gomodcache"
export GOFLAGS=-mod=mod
python3 scripts/golden-run.py || { echo "golden: run failed"; exit 1; }
python3 scripts/check-golden.py
