#!/usr/bin/env bash
# Golden suite v4 (Tasks 17 + 24 + 32): the scripted P0+P1+P2+P3 op-sequence
# through both twins with a pinned clock, a pinned id stream, an isolated
# global memory store, one pinned baseline store, aligned prompt roots and
# the same run root; byte-diff every artifact and capture.
# See docs/gates/golden-v4.md (P3), golden-v3.md (P2), golden-v2.md (P1).
set -u
cd "$(dirname "$0")/.."
export GOCACHE="$PWD/.scratch/gocache"
export GOPATH="$PWD/.scratch/gopath"
export GOMODCACHE="$PWD/.scratch/gomodcache"
export GOFLAGS=-mod=mod
python3 scripts/golden-run.py || { echo "golden: run failed"; exit 1; }
python3 scripts/check-golden.py
