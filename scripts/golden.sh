#!/usr/bin/env bash
# Golden suite v3 (Tasks 17 + 24): the scripted P0+P1+P2 op-sequence through
# both twins with a pinned clock, a pinned id stream, an isolated global
# memory store and the same run root; byte-diff every artifact and capture.
# See docs/gates/golden-v3.md (P2) and docs/gates/golden-v2.md (P1).
set -u
cd "$(dirname "$0")/.."
export GOCACHE="$PWD/.scratch/gocache"
export GOPATH="$PWD/.scratch/gopath"
export GOMODCACHE="$PWD/.scratch/gomodcache"
export GOFLAGS=-mod=mod
python3 scripts/golden-run.py || { echo "golden: run failed"; exit 1; }
python3 scripts/check-golden.py
