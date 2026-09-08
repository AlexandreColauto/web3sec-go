#!/usr/bin/env bash
#
# sync-assets.sh — Task 15: copy the Python reference schemas into the Go
# embedded assets and verify the result is byte-identical.
#
# Contract (docs/superpowers/plans/2026-09-08-p0-trust-core.md, Task 15):
#   * copies web3sec-final/schema/*.json -> assets/schema/
#   * verifies ALL 27 files are byte-identical (diff -r)
#   * exits non-zero with a clear message on any drift or count mismatch
#     (must be exactly 27 files)
#
# Paths are resolved relative to the repo root, so this works when run from
# anywhere (it locates the repo root by walking up from this script's own
# path, not from $PWD).
set -euo pipefail

# Locate the repo root from the script's real path, independent of $PWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC="$ROOT/../web3sec-final/schema"
if [ ! -d "$SRC" ]; then
    # Fall back to an absolute known location for the reference repo.
    SRC="/home/xand/Projects/dsh-plugins/websec2/web3sec-final/schema"
fi
DEST="$ROOT/assets/schema"

# --- 1. Source count must be exactly 27.
if [ ! -d "$SRC" ]; then
    echo "error: reference schema dir not found: $SRC" >&2
    echo "error: expected web3sec-final/schema next to the repo root" >&2
    exit 1
fi

src_count="$(ls "$SRC"/*.json 2>/dev/null | wc -l)"
if [ "$src_count" -ne 27 ]; then
    echo "error: source schema dir has $src_count .json files, want exactly 27: $SRC" >&2
    exit 1
fi

# --- 2. Copy every schema into the destination.
mkdir -p "$DEST"
cp "$SRC"/*.json "$DEST"/

# --- 3. Destination must hold exactly 27 .json files.
dest_count="$(ls "$DEST"/*.json 2>/dev/null | wc -l)"
if [ "$dest_count" -ne 27 ]; then
    echo "error: destination schema dir has $dest_count .json files, want exactly 27: $DEST" >&2
    exit 1
fi

# --- 4. Byte-identical check across the whole directory.
if ! diff -rq "$SRC" "$DEST" >/tmp/sync-assets-diff.$$ 2>&1; then
    echo "error: assets/schema is not byte-identical to web3sec-final/schema:" >&2
    cat /tmp/sync-assets-diff.$$ >&2
    rm -f /tmp/sync-assets-diff.$$
    exit 1
fi
rm -f /tmp/sync-assets-diff.$$

echo "ok: assets/schema is byte-identical to $SRC ($src_count/27 schemas)"
