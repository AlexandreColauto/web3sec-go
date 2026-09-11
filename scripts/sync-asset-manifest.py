#!/usr/bin/env python3
"""Regenerate assets/testdata/asset_manifest.json — the SHA-256 manifest of
every embedded asset pack.

The manifest pins the byte content of the nine go:embed packs (schema,
archetypes, playbooks, prompts, prompts_legacy, runbook, evalsuite,
taxonomy, protocol) exactly as the
binary sees them. assets.TestAssetPackManifest compares the EMBEDDED bytes
against it, so an asset edit without a manifest update fails the test —
this replaces the old twin checkout byte-identity comparisons.

Usage (from the repo root):
    python3 scripts/sync-asset-manifest.py           # rewrite the manifest
    python3 scripts/sync-asset-manifest.py --check   # exit 1 if stale

Patterns mirror the //go:embed directives in assets/*.go — if a directive
changes, change the entry here and vice versa.
"""
import fnmatch
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
MANIFEST = ASSETS / "testdata" / "asset_manifest.json"

# pack name -> (embed root, glob patterns), mirroring the go:embed directives.
PACKS = {
    "schema": ("schema", ["*.schema.json"]),
    "archetypes": ("archetypes", ["*.yaml"]),
    "playbooks": ("playbooks", ["*.yaml"]),
    "prompts": ("prompts", ["*.md"]),
    "prompts_legacy": ("prompts_legacy", ["*.md"]),
    "runbook": ("runbook", ["RUNBOOK.md", "AGENT_BOOTSTRAP.md"]),
    "evalsuite": ("evalsuite", ["cases.json", "src/*.sol"]),
    "taxonomy": ("taxonomy", ["class_weights.json", "aliases.json"]),
    "protocol": ("protocol", ["*.json"]),
}


def build() -> dict:
    packs = {}
    for name, (root, patterns) in PACKS.items():
        base = ASSETS / root
        entries = {}
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(base).as_posix()
            if not any(fnmatch.fnmatch(rel, pat) for pat in patterns):
                continue
            data = p.read_bytes()
            entries[rel] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        packs[name] = dict(sorted(entries.items()))
    return {"version": 1, "packs": packs}


def main() -> int:
    new = build()
    text = json.dumps(new, indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv[1:]:
        if MANIFEST.exists() and MANIFEST.read_text(encoding="utf-8") == text:
            print("asset manifest is current")
            return 0
        print("STALE: run python3 scripts/sync-asset-manifest.py", file=sys.stderr)
        return 1
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(text, encoding="utf-8")
    n = sum(len(v) for v in new["packs"].values())
    print(f"wrote {MANIFEST.relative_to(ROOT)}: {n} files in {len(new['packs'])} packs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
