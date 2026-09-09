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

Three store roots are repointed by the same harness:

  * ``WEBV2_EVAL_DIR`` -> ``webv2.eval_store.EVAL_DIR`` (the eval store
    is unported in Go — see D26) — an ABSENT store, which is a documented
    legitimate input state;
  * ``WEBV2_POC_ROOT`` -> ``webv2.datasets.defihacklabs`` dataset roots
    (POC_ROOT + EXPLORER_DIR/INCIDENTS_FILE/ROOTCAUSE_FILE; the
    DeFiHackLabs clone and its incident explorer live beside the
    reference repo, and both the shape leg and poc_missing attribution
    read them) — likewise ABSENT;
  * ``WEBV2_BASELINES_DIR`` -> ``webv2.forkdiff.BASELINES_DIR`` — one
    scratch dir shared with the Go twin (D24), so baseline add/list/
    remove/forkdiff compare without writing either repo;
  * ``WEBV2_PROMPTS_BASE`` -> ``webv2.adapter`` prompt root (D25) — the Go
    twin's byte-identical go:embed mirror, so the prompt path printed by
    ``run``/``status`` (and hashed into the run event) is the same string
    in both twins.

The patch is installed with a meta-path finder so the module is patched
after its own import, without importing webv2 at interpreter startup.
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

    # ---- absent-store pinning -------------------------------------------
    import importlib.util as _ilu
    import sys as _sys

    _PATCHES = {
        "webv2.eval_store": ("EVAL_DIR", "WEBV2_EVAL_DIR"),
        "webv2.forkdiff": ("BASELINES_DIR", "WEBV2_BASELINES_DIR"),
    }
    _PATCHES = {m: (a, os.environ[e]) for m, (a, e) in _PATCHES.items()
                if os.environ.get(e)}

    _poc_base = os.environ.get("WEBV2_POC_ROOT")
    if _poc_base:
        import pathlib as _pl

        _base = _pl.Path(_poc_base)
        _PATCHES["webv2.datasets.defihacklabs"] = (
            "DATASET_ROOTS",
            {"EXPLORER_DIR": _base / "explorer",
             "INCIDENTS_FILE": _base / "explorer" / "incidents.json",
             "ROOTCAUSE_FILE": _base / "explorer" / "rootcause_data.json",
             "POC_ROOT": _base / "DeFiHackLabs"},
        )

    # D25: the reference resolves every stage prompt against its own package
    # root (<pyroot>/prompts[/_legacy]); the Go twin must serve the same
    # files from its go:embed mirror (<goroot>/assets/prompts[/_legacy]).
    # The two packs are byte-identical (verify-full's sync-assets step
    # enforces that), but the ABSOLUTE path is printed by `run`/`status` and
    # lands inside the run event, whose hash covers it — so the twin event
    # chains could never agree. Repoint the reference at the Go mirror: both
    # twins then print and hash the SAME path. No reference file is edited.
    _prompts_base = os.environ.get("WEBV2_PROMPTS_BASE")
    if _prompts_base:
        import pathlib as _pl2

        _PATCHES["webv2.adapter"] = ("PROMPTS_BASE", _pl2.Path(_prompts_base))

    if _PATCHES:
        import pathlib as _pathlib

        class _StorePatcher:
            """Patches a module's store-root attributes right after import."""

            def find_spec(self, fullname, path=None, target=None):
                if fullname not in _PATCHES:
                    return None
                attr, value = _PATCHES[fullname]
                _sys.meta_path.remove(self)
                try:
                    spec = _ilu.find_spec(fullname)
                finally:
                    _sys.meta_path.insert(0, self)
                if spec is None or spec.loader is None:
                    return spec
                orig_exec = spec.loader.exec_module

                def exec_module(module, _orig=orig_exec, _attr=attr,
                                _value=value):
                    _orig(module)
                    if isinstance(_value, dict):
                        for k, v in _value.items():
                            setattr(module, k, v)
                    elif _attr == "PROMPTS_BASE":
                        # resolve_prompt is the ONE path builder the CLI uses
                        # (`run`/`status`); rebase it on the embed mirror and
                        # keep the two dir constants (used by the pack-drift
                        # check) consistent.
                        module.PROMPTS_DIR = _value / "prompts"
                        module.LEGACY_PROMPTS_DIR = _value / "prompts_legacy"

                        def resolve_prompt(stage, _m=module, _b=_value):
                            rel = _m.stage_config(stage)["prompt"]
                            return (_b / rel).resolve() if rel else None

                        module.resolve_prompt = resolve_prompt
                    else:
                        setattr(module, _attr, _pathlib.Path(_value))

                spec.loader.exec_module = exec_module
                return spec

        _sys.meta_path.insert(0, _StorePatcher())
