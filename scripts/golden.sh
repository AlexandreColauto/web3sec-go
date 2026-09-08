#!/usr/bin/env bash
# Golden suite v1 (Task 17): same scripted P0 op-sequence through both
# twins with pinned clock + pinned id stream; byte-diff everything.
set -u
cd "$(dirname "$0")/.."
python3 scripts/golden-run.py || { echo "golden: run failed"; exit 1; }
python3 scripts/check-golden.py
