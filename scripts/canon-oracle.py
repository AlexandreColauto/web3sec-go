#!/usr/bin/env python3
"""CPython oracle for the Go canonical JSON encoder (P0 Task 1).

Reads one JSON document per line on stdin; writes two lines per document:
  line 1: spaced  = json.dumps(v, sort_keys=True, ensure_ascii=True)
  line 2: compact = same, separators=(",", ":")

Pinned to CPython 3.14.7 behavior. The Go differential test
(internal/validation/fuzz/canon_oracle_test.go) feeds it the same document
text the Go side parses, then byte-diffs the encoder outputs. The canonical
output is always a single line (all control characters are escaped), so the
line framing is safe.
"""

import json
import sys


def main() -> int:
    write = sys.stdout.write
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        v = json.loads(line)
        write(json.dumps(v, sort_keys=True, ensure_ascii=True) + "\n")
        write(
            json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            + "\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
