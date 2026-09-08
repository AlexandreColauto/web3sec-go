"""Golden-suite shim: make the Python twin's finding ids deterministic.

`webv2.findings.new_finding_id` mints `F-` ids from a RAW `uuid.uuid4()`,
bypassing `webv2.state.new_id` — so the documented `WEBV2_UUID` pin does
not reach it and the reference twin emits different finding ids on every
run. A Go port cannot reproduce a random id, and every artifact that
embeds one (finding file names, event payloads, event hashes) is then
un-matchable.

This module is imported by CPython at startup (sitecustomize) when the
golden harness puts scripts/golden on PYTHONPATH, and ONLY when
WEBV2_UUID is set. `uuid.uuid4` is rerouted to
`sha256("<seed>:fid:<n>")[:16]` (version/variant bits forced) where `n`
is `WEBV2_FINDING_ID_SEQ` (the harness's running count of finding ids
minted so far, since each CLI command is a fresh process) plus the
per-process draw index. The Go twin installs the byte-identical minter
under WEBV2_FINDING_IDS=pin. No reference file is edited.
"""
from __future__ import annotations

import hashlib
import os
import uuid as _uuid

if os.environ.get("WEBV2_UUID"):
    _SEED = os.environ["WEBV2_UUID"]
    _BASE = int(os.environ.get("WEBV2_FINDING_ID_SEQ", "0") or "0")
    _DRAWS = [0]

    def _pinned_uuid4() -> _uuid.UUID:
        n = _BASE + _DRAWS[0]
        _DRAWS[0] += 1
        b = bytearray(hashlib.sha256(f"{_SEED}:fid:{n}".encode()).digest()[:16])
        b[6] = (b[6] & 0x0F) | 0x40   # version 4
        b[8] = (b[8] & 0x3F) | 0x80   # variant 10
        return _uuid.UUID(bytes=bytes(b))

    _uuid.uuid4 = _pinned_uuid4
