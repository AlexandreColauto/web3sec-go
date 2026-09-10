#!/usr/bin/env bash
#
# sync-assets.sh — Task 15: copy the Python reference schemas into the Go
# embedded assets and verify the result is byte-identical.
#
# Contract (docs/superpowers/plans/2026-09-08-p0-trust-core.md, Task 15):
#   * copies web3sec-final/schema/*.json -> assets/schema/
#   * verifies every file is byte-identical (diff -r)
#   * the expected set is derived from the reference's KNOWN_SCHEMAS tuple
#     (single source of truth — the reference is developed in parallel, so
#     a hardcoded count drifts every time a schema is added)
#   * exits non-zero with a clear message on any drift or count mismatch
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

# --- 1. The expected schema set comes from the reference's KNOWN_SCHEMAS.
if [ ! -d "$SRC" ]; then
    echo "error: reference schema dir not found: $SRC" >&2
    echo "error: expected web3sec-final/schema next to the repo root" >&2
    exit 1
fi

VALIDATION_PY="$SRC/../src/webv2/validation.py"
if [ ! -f "$VALIDATION_PY" ]; then
    echo "error: reference validation.py not found: $VALIDATION_PY" >&2
    exit 1
fi

known_names="$(python3 - "$VALIDATION_PY" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"KNOWN_SCHEMAS\s*=\s*\((.*?)\)", src, re.S)
if not m:
    sys.exit("error: KNOWN_SCHEMAS tuple not found in validation.py")
for name in re.findall(r'"([^"]+)"', m.group(1)):
    print(name)
PY
)" || exit 1
want_count="$(printf '%s\n' "$known_names" | wc -l)"

src_count="$(ls "$SRC"/*.json 2>/dev/null | wc -l)"
if [ "$src_count" -ne "$want_count" ]; then
    echo "error: source schema dir has $src_count .json files, but" \
         "KNOWN_SCHEMAS lists $want_count: $SRC" >&2
    exit 1
fi
# every KNOWN_SCHEMAS entry must have a file (a name without a schema
# would validate at runtime in Python and silently miss in Go).
while IFS= read -r name; do
    [ -f "$SRC/$name.schema.json" ] || {
        echo "error: KNOWN_SCHEMAS names '$name' but" \
             "$SRC/$name.schema.json does not exist" >&2
        exit 1
    }
done <<< "$known_names"

# --- 2. Copy every schema into the destination.
mkdir -p "$DEST"
rm -f "$DEST"/*.json
cp "$SRC"/*.json "$DEST"/

# --- 3. Destination must hold exactly the expected number.
dest_count="$(ls "$DEST"/*.json 2>/dev/null | wc -l)"
if [ "$dest_count" -ne "$want_count" ]; then
    echo "error: destination schema dir has $dest_count .json files," \
         "want exactly $want_count: $DEST" >&2
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

echo "ok: assets/schema is byte-identical to $SRC ($src_count/$want_count schemas)"
