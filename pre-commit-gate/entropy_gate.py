#!/usr/bin/env python3
"""
entropy-gate -- a language-aware pre-commit gate against code entropy.

Three layers:

  0. Router    Classify every staged file by language. A language with no
               checks configured is a HARD ERROR, not a silent skip.
  1. aislop    Cross-language AI-slop layer (narrative comments, TODO stubs,
               console.log leftovers, unused imports). Complements layer 2.
  2. Structural Per-language linters for the four entropy levers:
               repetition, massive functions, dead weight, hidden coupling.

Ratchets:
  - Implicit: layer-2 file-scoped checks only ever see staged files.
  - Explicit: repo-scoped checks are compared against .entropy-baseline.json.

Stdlib only. Python 3.9+ (tomllib optional; a tiny parser is used as fallback).

Exit codes: 0 clean | 1 entropy violations | 2 configuration/tooling error
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import NamedTuple

VERSION = "1.1.0"
CONFIG_NAME = ".entropy-gate.toml"
BASELINE_NAME = ".entropy-baseline.json"

EXIT_OK, EXIT_VIOLATION, EXIT_CONFIG = 0, 1, 2

# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

# Paths and tool output are not guaranteed to be valid UTF-8 (a filename can be
# any byte sequence bar '/' and NUL). Without this, printing such a path raises
# UnicodeEncodeError and the gate dies with a traceback instead of a verdict.
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(Exception):
        _stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


red = lambda s: _c("1;31", s)
green = lambda s: _c("1;32", s)
yellow = lambda s: _c("1;33", s)
dim = lambda s: _c("2", s)
bold = lambda s: _c("1", s)
cyan = lambda s: _c("1;36", s)


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_IGNORE_PATHS = [
    "node_modules/", ".git/", "vendor/", "dist/", "build/", "coverage/",
    ".next/", ".venv/", "venv/", "__pycache__/", "target/", ".mypy_cache/",
    ".pytest_cache/", "migrations/", "generated/", "third_party/", ".idea/",
    # The gate must not grade itself: without this, committing the tool into a
    # repo blocks on its own .sh/.py files.
    "entropy-gate/",
]

# Non-code files we never try to classify.
DEFAULT_IGNORE_EXTENSIONS = [
    ".md", ".rst", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".lock", ".sum", ".mod", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".css", ".scss", ".less", ".html",
    ".csv", ".pdf", ".mp4", ".env", ".gitignore", ".editorconfig",
    ".dockerignore", ".prettierrc", ".log",
]

DEFAULT_THRESHOLDS = {
    "cyclomatic": 10,
    "cognitive": 15,
    "function_lines": 30,
    "file_lines": 300,
    "nesting": 3,
    "params": 4,
    "duplication_percent": 3.0,
}

# Inline TOML handed to ruff so thresholds come from one place.
RUFF_SELECT = "E4,E7,E9,F,I,UP,B,SIM,C901,PLR0911,PLR0912,PLR0913,PLR0915,ERA,ARG,RUF"

# RUF001/002/003 flag "ambiguous unicode" -- en dashes, curly quotes and
# ellipses in prose. That is typography, not entropy, and blocking a commit over
# a dash in a docstring is how a gate earns --no-verify. Ignored rather than
# dropped from the select so the rest of RUF still runs.
RUFF_IGNORE = "RUF001,RUF002,RUF003"


def ruff_inline_config(t: dict) -> str:
    return "\n".join([
        f"lint.mccabe.max-complexity = {t['cyclomatic']}",
        f"lint.pylint.max-branches = {max(6, t['cyclomatic'])}",
        f"lint.pylint.max-args = {t['params']}",
        f"lint.pylint.max-statements = {t['function_lines']}",
        "lint.pylint.max-returns = 6",
        "lint.pylint.max-locals = 15",
    ])


# --------------------------------------------------------------------------- #
# Language presets -- the four entropy levers per language
# --------------------------------------------------------------------------- #
#
# scope:
#   "file" -> runs on the staged files of this language (implicit ratchet)
#   "repo" -> runs once over the whole project when a file is staged;
#             needs the baseline ratchet
# count:
#   None            -> pass/fail on exit code
#   "lines"         -> number of non-empty output lines (baseline metric)
#   "regex:<pat>"   -> number of regex matches (baseline metric)

def PRESETS(t: dict) -> dict:
    return {
        "python": {
            "extensions": [".py", ".pyi"],
            "checks": [
                {
                    "name": "ruff",
                    # Repo scope, like golangci-lint below. A file-scoped ruff
                    # judges the WHOLE staged file by exit code, so any
                    # pre-existing finding anywhere in a file you touch blocks
                    # the commit -- touching a file is not a ratchet. Repo scope
                    # + a count makes the metric the repo-wide number of
                    # findings, which the baseline then pins as a ceiling.
                    "scope": "repo",
                    # No {files}: ruff has no --new-from-rev, so the ratchet is
                    # the baseline rather than the diff.
                    "command": ["ruff", "check", "--no-fix", "--output-format", "concise",
                                "--select", RUFF_SELECT, "--ignore", RUFF_IGNORE,
                                "--config", "{ruff_config}", "."],
                    # One match per "path.py:line:col:" finding; ruff's summary
                    # and fixable lines never match this, and .pyi is covered.
                    "count": "regex:^\\S+\\.pyi?:\\d+:\\d+:",
                    "error_regex": "^error: ",
                    "install": "pip install ruff",
                },
                {
                    "name": "ruff-format",
                    # Same shape, and the same flaw: file scope + exit code
                    # means pre-existing drift anywhere in a file you touch
                    # blocks the commit (8 files here are already unformatted).
                    # Repo scope + a count pins "how many files are unformatted"
                    # as the ceiling instead, so reformatting stays your choice.
                    "scope": "repo",
                    # One "Would reformat: <path>" line per unformatted file;
                    # the trailing "N files would be reformatted" summary does
                    # not match, so it cannot inflate the metric.
                    "command": ["ruff", "format", "--check", "."],
                    "count": "regex:^Would reformat: ",
                    "error_regex": "^error: ",
                    "install": "pip install ruff",
                },
                {
                    "name": "radon",
                    "scope": "file",
                    "command": ["radon", "cc", "-s", "--min", "C", "{files}"],
                    # radon exits 0 whether or not it finds anything, so the
                    # count IS the verdict. Only function lines match -- the
                    # filename header radon prints above them must not count,
                    # or every file would look like a finding.
                    "count": "regex:^\\s+[A-Z] \\d+:\\d+",
                    # radon prints "<file>" then an indented "ERROR: ..." line,
                    # so the marker is never at the start of the output.
                    "error_regex": "^\\s*ERROR|^usage: ",
                    "install": "pip install radon",
                },
                {
                    "name": "vulture",
                    "scope": "repo",
                    "command": ["vulture", ".", "--min-confidence", "80"],
                    "count": "lines",
                    "install": "pip install vulture",
                    "enabled_by_default": False,
                },
            ],
        },
        "go": {
            "extensions": [".go"],
            "checks": [
                {
                    "name": "gofmt",
                    "scope": "file",
                    "command": ["gofmt", "-l", "{files}"],
                    # gofmt -l exits 0 while listing unformatted files, so an
                    # exit-code-only judgement would let every unformatted Go
                    # file through. One line per offending file == the metric.
                    "count": "lines",
                    "install": "https://go.dev/dl/",
                },
                {
                    "name": "golangci-lint",
                    "scope": "repo",
                    # --new-from-rev gives us the ratchet for free when HEAD exists.
                    "command": ["golangci-lint", "run", "./...", "--new-from-rev", "HEAD"],
                    "workdir": "{go_dir}",
                    # Count issue headers, not the multi-line context they print.
                    "count": "regex:^\\S+\\.go:\\d+",
                    "install": "go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest",
                },
            ],
        },
        "javascript": {
            "extensions": [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"],
            "checks": [
                {
                    "name": "eslint",
                    "scope": "file",
                    # --max-warnings=0 is load-bearing: the entropy rules in the
                    # shipped template are warnings, and eslint exits 0 on a
                    # warn-only run, so without it the whole eslint layer would
                    # silently pass.
                    "command": ["eslint", "--no-warn-ignored", "--max-warnings=0",
                                "{files}"],
                    # Missing config / bad plugin / bad pattern are setup problems.
                    "error_regex": "^(Oops! Something went wrong!|ESLint couldn't find|"
                                   "Error: |Invalid |No files matching the pattern)",
                    "install": "npm i -D eslint typescript-eslint eslint-plugin-sonarjs",
                },
                {
                    "name": "tsc",
                    "scope": "repo",
                    "when_extensions": [".ts", ".tsx", ".mts", ".cts"],
                    "command": ["tsc", "--noEmit"],
                    # TypeScript 7 exits 0 with no output when there is no
                    # tsconfig.json at all -- which the ratchet would otherwise
                    # read as "improved to 0". Refuse to score without one.
                    "requires_config": ["tsconfig.json"],
                    # Only errors anchored to a file+line. Bare "error TS18003"
                    # is a tsconfig problem, not entropy.
                    "count": "regex:^.+\\(\\d+,\\d+\\): error TS",
                    # tsc exits 2 when it reports type errors, so a non-zero
                    # exit is a verdict here, not a crash.
                    "findings_exit": [1, 2],
                    "error_regex": "^error TS\\d+",
                    "install": "npm i -D typescript",
                },
                {
                    "name": "knip",
                    "scope": "repo",
                    "command": ["knip", "--no-exit-code", "--no-config-hints"],
                    "count": "lines",
                    "error_regex": "^ERROR:",
                    "install": "npm i -D knip",
                },
                {
                    "name": "dependency-cruiser",
                    "scope": "repo",
                    "command": ["depcruise", ".", "--output-type", "err"],
                    "count": "regex:^error\\b",
                    "install": "npm i -D dependency-cruiser",
                    "enabled_by_default": False,
                },
                {
                    "name": "jscpd",
                    "scope": "repo",
                    "command": ["jscpd", "-t", "{duplication_percent}", "-k", "50",
                                "-i", "node_modules,dist,coverage", "."],
                    "count": "lines",
                    "install": "npm i -D jscpd",
                    "enabled_by_default": False,
                },
            ],
        },
    }


# --------------------------------------------------------------------------- #
# Minimal TOML fallback (only what this config needs)
# --------------------------------------------------------------------------- #

try:
    import tomllib
    from tomllib import TOMLDecodeError as TomlError
    _HAVE_TOML = True
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore
        from tomli import TOMLDecodeError as TomlError  # type: ignore
        _HAVE_TOML = True
    except ModuleNotFoundError:
        tomllib = None  # type: ignore
        _HAVE_TOML = False
        # A type that is never raised, so the isinstance() check in
        # find_config() still works when neither parser is installed.
        TomlError = type("TomlError", (Exception,), {})  # type: ignore


def load_toml(path: Path) -> dict:
    if _HAVE_TOML:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    return _mini_toml(path.read_text())


def _strip_comment(line: str) -> str:
    """Drop a trailing # comment, ignoring # inside quoted strings."""
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _mini_toml(text: str) -> dict:
    """Parse the restricted TOML subset used by .entropy-gate.toml."""
    root: dict = {}
    cur = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i]).strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            raise ValueError(
                "array-of-tables ([[...]]) needs a real TOML parser; "
                "use Python 3.11+ or `pip install tomli`. "
                "Inline tables inside `checks = [ ... ]` work everywhere.")
        if line.startswith("["):
            key = line[1:-1].strip()
            node = root
            parts = key.split(".")
            for p in parts[:-1]:
                node = node.setdefault(p.strip(), {})
            cur = node.setdefault(parts[-1].strip(), {})
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().strip('"')
        v = v.strip()
        if v.startswith("[") and not v.endswith("]"):
            while i < len(lines) and not v.endswith("]"):
                v += " " + _strip_comment(lines[i]).strip()
                i += 1
        cur[k] = _mini_value(v)
    return root


def _mini_value(v: str):
    v = v.strip()
    if v.startswith("#"):
        return ""
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if v.startswith("'") and v.endswith("'"):
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        out = []
        for elem in _split_items(v[1:-1].strip()):
            if elem.startswith("{"):
                table = {}
                for piece in _split_items(elem[1:-1].strip()):
                    if "=" in piece:
                        pk, _, pv = piece.partition("=")
                        table[pk.strip().strip('"')] = _mini_value(pv.strip())
                out.append(table)
            else:
                out.append(_mini_value(elem))
        return out
    if v in ("true", "false"):
        return v == "true"
    with contextlib.suppress(ValueError):
        return int(v)
    with contextlib.suppress(ValueError):
        return float(v)
    return v


def _split_items(s: str) -> list[str]:
    """Split on top-level commas, respecting quotes and nested brackets."""
    items: list[str] = []
    buf, depth, quote = "", 0, None
    for ch in s:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf += ch
        elif ch in "{[":
            depth += 1
            buf += ch
        elif ch in "}]":
            depth -= 1
            buf += ch
        elif ch == "," and depth == 0:
            items.append(buf)
            buf = ""
        else:
            buf += ch
    if buf.strip():
        items.append(buf)
    return [i.strip() for i in items if i.strip()]


# --------------------------------------------------------------------------- #
# Git
# --------------------------------------------------------------------------- #

def git(*args: str, cwd: str = ".") -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                       text=True, encoding="utf-8", errors="surrogateescape",
                       check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def repo_root() -> Path:
    return Path(git("rev-parse", "--show-toplevel").strip())


def has_head(cwd: str = ".") -> bool:
    r = subprocess.run(["git", "rev-parse", "--verify", "HEAD"],
                       cwd=cwd, capture_output=True, text=True)
    return r.returncode == 0


def staged_files(root: Path) -> list[str]:
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z", cwd=str(root))
    return [p for p in out.split("\0") if p]


def staged_line_delta(root: Path, cfg: "Config | None" = None) -> int:
    """Lines added by the staged diff, ignoring what the gate does not grade.

    The gate's own directory and the configured ignore_paths are excluded, so
    the first commit after installing (which adds the whole gate) does not trip
    the giant-diff guard. Binary files report "-" and are skipped.
    """
    out = git("diff", "--cached", "--numstat", cwd=str(root))
    total = 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        path = parts[-1]
        if cfg is not None and should_ignore(path, cfg):
            continue
        total += int(parts[0])
    return total


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

class Config:
    def __init__(self, raw: dict, root: Path):
        self.root = root

        # The gate must never grade itself -- but it cannot rely on being
        # vendored as "entropy-gate/". Derive the path from where this script
        # actually lives, so any install directory name is ignored.
        self.self_paths: list[str] = []
        try:
            rel = Path(__file__).resolve().parent.relative_to(root.resolve())
            if str(rel) != ".":
                self.self_paths = [rel.as_posix().rstrip("/") + "/"]
        except (ValueError, OSError):
            pass  # engine lives outside the repo: nothing to exclude

        s = raw.get("settings", {}) or {}
        if not isinstance(s, dict):
            raise ValueError("[settings] must be a table")
        known_settings = {
            "ignore_paths", "ignore_extensions", "fail_on_unknown_language",
            "max_staged_lines", "parallel", "bin_dirs",
        }
        unknown_settings = set(s) - known_settings
        if unknown_settings:
            raise ValueError(
                f"[settings] has unknown key(s): {', '.join(sorted(unknown_settings))}. "
                f"Known: {', '.join(sorted(known_settings))}")
        self.ignore_paths = _as_str_list(s.get("ignore_paths"), "settings.ignore_paths",
                                         default=DEFAULT_IGNORE_PATHS)
        # A bare string here would be iterated per character: ".json" would
        # quietly ignore .j/.s/.o/.n files too, turning a fail-closed block on an
        # unconfigured language into a silent pass.
        self.ignore_extensions = set(
            e.lower() if e.startswith(".") else "." + e.lower()
            for e in _as_str_list(s.get("ignore_extensions"),
                                  "settings.ignore_extensions",
                                  default=DEFAULT_IGNORE_EXTENSIONS)
        )
        self.fail_on_unknown_language = _as_bool(
            s.get("fail_on_unknown_language"), "settings.fail_on_unknown_language", True)
        self.max_staged_lines = _as_int(s.get("max_staged_lines"),
                                         "settings.max_staged_lines", 1200, minimum=0)
        self.parallel = _as_bool(s.get("parallel"), "settings.parallel", True)

        self.thresholds = dict(DEFAULT_THRESHOLDS)
        user_thresholds = raw.get("thresholds", {}) or {}
        if not isinstance(user_thresholds, dict):
            raise ValueError("[thresholds] must be a table of numbers")
        unknown = set(user_thresholds) - set(DEFAULT_THRESHOLDS)
        if unknown:
            # A typo'd threshold silently keeps the default, so the number the
            # user set never takes effect and nothing says so.
            raise ValueError(
                f"[thresholds] has unknown key(s): {', '.join(sorted(unknown))}. "
                f"Known: {', '.join(sorted(DEFAULT_THRESHOLDS))}")
        for k, v in user_thresholds.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(f"thresholds.{k} must be a number, got "
                                 f"{type(v).__name__} ({v!r})")
            # ruff_inline_config() interpolates most of these straight into
            # ruff's TOML, where max-complexity/max-args/max-statements are
            # unsigned integers. A float or an absurdly large value makes ruff
            # reject the generated config, and a rejected check is only a note
            # -- so the main Python check would be dead while the gate exited 0.
            if k != "duplication_percent":
                if not isinstance(v, int):
                    raise ValueError(
                        f"thresholds.{k} must be a whole number, got {v!r} "
                        f"(ruff rejects a fractional limit)")
                if not 1 <= v <= 100000:
                    raise ValueError(
                        f"thresholds.{k} must be between 1 and 100000, got {v!r}")
            elif not math.isfinite(v) or not 0 < v <= 100:
                raise ValueError(
                    f"thresholds.duplication_percent must be a percentage "
                    f"between 0 and 100, got {v!r}")
        self.thresholds.update(user_thresholds)
        self.thresholds["ruff_config"] = ruff_inline_config(self.thresholds)
        self.thresholds["duplication_percent"] = str(self.thresholds["duplication_percent"])
        self.thresholds["go_dir"] = self._detect_go_dir()
        for k, v in list(self.thresholds.items()):
            self.thresholds[k] = str(v)

        a = raw.get("aislop", {}) or {}
        if not isinstance(a, dict):
            raise ValueError("[aislop] must be a table")
        unknown_aislop = set(a) - {"enabled", "fail_below", "extra_args"}
        if unknown_aislop:
            raise ValueError(
                f"[aislop] has unknown key(s): {', '.join(sorted(unknown_aislop))}. "
                f"Known: enabled, fail_below, extra_args")
        self.aislop_mode = str(a.get("enabled", "require")).lower()
        if self.aislop_mode not in ("require", "optional", "off"):
            # `enabled = true` reads naturally next to [languages.*] booleans and
            # would otherwise silently downgrade the strictest shipped setting.
            raise ValueError(
                f"[aislop] enabled = {a.get('enabled')!r} is not valid; use "
                f'"require", "optional" or "off"')
        self.aislop_fail_below = _as_int(a.get("fail_below"), "[aislop] fail_below", 0,
                                         minimum=0)
        # A bare string would be exploded into single-character argv entries.
        self.aislop_extra = _as_str_list(a.get("extra_args"), "[aislop] extra_args")

        # Extra lookup dirs only. PATH is always searched *first* (see
        # resolve_binary) so a committed executable inside the repo cannot
        # shadow a system binary at commit time.
        self.bin_dirs = [root / d for d in
                         _as_str_list(s.get("bin_dirs"), "settings.bin_dirs",
                                      default=["node_modules/.bin"])]

        # languages: preset + user overrides
        presets = PRESETS(DEFAULT_THRESHOLDS)
        unknown_top = set(raw) - {"settings", "thresholds", "aislop", "languages"}
        if unknown_top:
            raise ValueError(
                f"{CONFIG_NAME} has unknown section(s): "
                f"{', '.join(sorted(unknown_top))}. Known: settings, thresholds, "
                f"aislop, languages")
        user_langs = raw.get("languages", {}) or {}
        if not isinstance(user_langs, dict):
            raise ValueError("[languages] must be a table of languages")
        self.languages: dict[str, dict] = {}

        # One builder for both preset and user-defined languages. They used to
        # be separate loops, and the user-language one drifted: disable/enable
        # silently did nothing there for three review rounds.
        def build(name: str, extensions, checks, u: dict, default_scope: str) -> dict:
            known = {"enabled", "extensions", "disable", "enable", "extra", "checks"}
            unknown = set(u) - known
            if unknown:
                raise ValueError(
                    f"languages.{name} has unknown key(s): "
                    f"{', '.join(sorted(unknown))}. Known: {', '.join(sorted(known))}")
            merged = {"extensions": list(extensions), "checks": list(checks)}
            merged["enabled"] = _as_bool(u.get("enabled"), f"languages.{name}.enabled",
                                         True)
            if u.get("extensions"):
                merged["extensions"] = _as_str_list(
                    u["extensions"], f"languages.{name}.extensions")
            disabled = set(_as_str_list(u.get("disable"), f"languages.{name}.disable"))
            # `enable` is the only way to switch on checks that ship off by
            # default (dependency-cruiser, jscpd, vulture).
            enabled_extra = set(_as_str_list(u.get("enable"), f"languages.{name}.enable"))
            # `checks` is accepted as a synonym for `extra`: the README documents
            # `checks` for adding a language, and silently ignoring either
            # spelling would mean a check that never runs.
            merged["checks"] += _normalize_checks(
                _as_check_list(u, name, "extra") + _as_check_list(u, name, "checks"),
                default_scope=default_scope)
            # Applied after the extras are merged, so disable/enable also work on
            # checks the user added -- and a name that matches nothing is
            # reported instead of silently doing nothing.
            matched = set()
            for chk in merged["checks"]:
                chk.setdefault("enabled", chk.get("enabled_by_default", True))
                if chk["name"] in disabled:
                    chk["enabled"] = False
                    matched.add(chk["name"])
                if chk["name"] in enabled_extra:
                    chk["enabled"] = True
                    matched.add(chk["name"])
            ghost = (disabled | enabled_extra) - matched
            if ghost:
                known = ", ".join(sorted(c["name"] for c in merged["checks"])) or "(none)"
                raise ValueError(
                    f"languages.{name}: disable/enable names no check: "
                    f"{', '.join(sorted(ghost))}. Known checks: {known}")
            return merged

        for name, spec in presets.items():
            u = user_langs.get(name, {}) or {}
            self.languages[name] = build(name, spec["extensions"], spec["checks"], u, "repo")

        # user-defined languages (the extension point)
        for name, u in user_langs.items():
            if name in presets or not isinstance(u, dict):
                continue
            if not _as_str_list(u.get("extensions"), f"languages.{name}.extensions"):
                raise ValueError(
                    f"languages.{name}: extensions = [...] is required for a "
                    f"language that is not built in")
            self.languages[name] = build(name, [], [], u, "repo")

        for name, spec in self.languages.items():
            for chk in spec.get("checks", []):
                _validate_check(name, chk, self.root)

    def _detect_go_dir(self) -> str:
        """Go modules often live in a subdirectory; find the shallowest go.mod."""
        if (self.root / "go.mod").exists():
            return "."
        best = None
        for p in sorted(self.root.rglob("go.mod")):
            rel = p.parent.relative_to(self.root)
            if any(part in ("node_modules", ".git", "vendor") for part in rel.parts):
                continue
            if best is None or len(rel.parts) < len(best.parts):
                best = rel
        return str(best) if best else "."

    def ext_map(self) -> dict[str, str]:
        m: dict[str, str] = {}
        for lang, spec in self.languages.items():
            if not spec.get("enabled", True):
                continue
            for e in spec["extensions"]:
                m[e.lower() if e.startswith(".") else "." + e.lower()] = lang
        return m

    def all_ext_map(self) -> dict[str, str]:
        """Every configured extension, including disabled languages."""
        m: dict[str, str] = {}
        for lang, spec in self.languages.items():
            for e in spec["extensions"]:
                m[e.lower() if e.startswith(".") else "." + e.lower()] = lang
        return m


def _exit_codes(c: dict, name: str) -> list[int]:
    """Exit codes a check uses to mean "findings", for crash_suspect()."""
    value = c.get("findings_exit")
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"check {name!r}: findings_exit must be an array of "
                         f"integers, e.g. [1, 2]")
    out = []
    for v in value:
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            raise ValueError(f"check {name!r}: findings_exit must contain positive "
                             f"integers, got {v!r}")
        out.append(v)
    return out


def _normalize_checks(items, default_scope: str) -> list[dict]:
    out = []
    for c in items:
        if not isinstance(c, dict):
            # Skipping it would mean a check the user believes is configured
            # never runs and never says why.
            raise ValueError(
                f"each entry in a checks/extra array must be a table like "
                f'{{ name = "x", command = ["tool"] }}, got {type(c).__name__} ({c!r})')
        cmd = c.get("command")
        if isinstance(cmd, str):
            import shlex
            cmd = shlex.split(cmd)
        if not cmd:
            # Dropping it silently would mean a check that never runs and never
            # says why -- the exact class of bug this gate exists to catch.
            raise ValueError(
                f"check {c.get('name', '<unnamed>')!r} has no `command`; "
                f"every check needs command = [\"tool\", \"--flag\"]")
        known = {"name", "scope", "command", "count", "error_regex", "install",
                 "workdir", "when_extensions", "requires_config", "required",
                 "enabled", "enabled_by_default", "findings_exit"}
        unknown = set(c) - known
        if unknown:
            # A typo'd `count` would drop the metric and the check would then be
            # judged by exit code alone -- a tool that reports findings with
            # exit 0 would pass. Dead keys are how a check quietly stops working.
            raise ValueError(
                f"check {c.get('name', '<unnamed>')!r} has unknown key(s): "
                f"{', '.join(sorted(unknown))}. Known: {', '.join(sorted(known))}")
        name = c.get("name", "custom")
        if not isinstance(name, str):
            raise ValueError(f"check name must be a string, got "
                             f"{type(name).__name__} ({name!r})")
        install = c.get("install", "")
        if not isinstance(install, str):
            raise ValueError(f"check {name!r}: install must be a string, got "
                             f"{type(install).__name__} ({install!r})")
        bad = [a for a in cmd if not isinstance(a, str)]
        if bad:
            raise ValueError(
                f"check {c.get('name', '<unnamed>')!r}: every element of command "
                f"must be a string, got {type(bad[0]).__name__} ({bad[0]!r})")
        workdir = c.get("workdir")
        if workdir is not None and not isinstance(workdir, str):
            raise ValueError(
                f"check {c.get('name', '<unnamed>')!r}: workdir must be a string, "
                f"got {type(workdir).__name__}")
        out.append({
            "name": name,
            "scope": c.get("scope", default_scope),
            "command": list(cmd),
            "findings_exit": _exit_codes(c, name),
            "enabled_by_default": _as_bool(c.get("enabled_by_default"),
                                            f"check {name!r}.enabled_by_default", True),
            "count": c.get("count"),
            "error_regex": c.get("error_regex"),
            "install": install,
            "workdir": workdir,
            # Passed through raw: coercing here would mangle a bare string into
            # a character list before _validate_check can reject it.
            "when_extensions": c.get("when_extensions"),
            "requires_config": c.get("requires_config"),
            "required": _as_bool(c.get("required"), f"check {name!r}.required", False),
            # `enabled` wins if given; otherwise an off-by-default check stays
            # off. Setting it unconditionally made enabled_by_default dead on
            # user-added checks -- accepted, validated, and ignored.
            "enabled": _as_bool(
                c.get("enabled", c.get("enabled_by_default")),
                f"check {name!r}.enabled",
                _as_bool(c.get("enabled_by_default"),
                         f"check {name!r}.enabled_by_default", True)),
        })
    return out


def _as_bool(value, where: str, default: bool) -> bool:
    """Return a config value that must be a real boolean.

    `fail_on_unknown_language = "false"` is truthy, so a user asking for the
    lenient behaviour would silently keep the strict one.
    """
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{where} must be true or false, got "
                         f"{type(value).__name__} ({value!r})")
    return value


def _as_int(value, where: str, default: int, minimum: int | None = None) -> int:
    """Return a config value that must be a real integer.

    int() happily takes "1200", 12.7 and True, so a wrong-typed threshold would
    be coerced rather than reported -- and `12.7` silently becomes `12`.
    """
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where} must be an integer, got "
                         f"{type(value).__name__} ({value!r})")
    if minimum is not None and value < minimum:
        raise ValueError(f"{where} must be >= {minimum}, got {value}")
    return value


def _as_str_list(value, where: str, default=None) -> list[str]:
    """Return a config value that must be an array of strings.

    `extensions = ".rs"` is valid TOML and reads fine, but list(".rs") is
    ['.', '.r', '.s'], so the user's files stop matching and get reported as an
    unconfigured language -- a baffling way to learn about a typo. Likewise
    set("radon") for `disable = "radon"` disables nothing at all.
    """
    if value is None:
        return list(default or [])
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ValueError(
            f"{where} must be an array of strings, e.g. [\"a\", \"b\"] "
            f"(got {type(value).__name__})")
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{where} must contain only strings, got "
                             f"{type(item).__name__} ({item!r})")
    return list(value)


def _as_check_list(lang_spec: dict, lang: str, key: str) -> list:
    """Return a language's `extra`/`checks` as a list of tables.

    `extra = { ... }` instead of `extra = [ { ... } ]` is valid TOML and reads
    fine, but list()-ing a dict yields its key strings, so the check would be
    dropped without a word. Reject it instead.
    """
    value = lang_spec.get(key)
    if value is None:
        return []
    if isinstance(value, dict):
        raise ValueError(
            f"languages.{lang}.{key} is a table; it must be an array of tables -- "
            f"write {key} = [ {{ ... }} ]")
    if not isinstance(value, list):
        raise ValueError(
            f"languages.{lang}.{key} must be an array of tables, got "
            f"{type(value).__name__}")
    return value


def _validate_check(lang: str, chk: dict, root: Path | None = None) -> None:
    """Compile the check's regexes now, so a typo is a config error (exit 2)
    rather than a traceback in the middle of a commit."""
    where = f"languages.{lang} check {chk['name']!r}"
    for field in ("when_extensions", "requires_config"):
        # A bare string is iterated per character downstream: when_extensions
        # ".rs" would match nothing (the check silently never runs) and
        # requires_config "tsconfig.json" would look for a file called "t".
        chk[field] = _as_str_list(chk.get(field), f"{where}.{field}")
    for field in ("error_regex", "count"):
        spec = chk.get(field)
        if spec is None:
            continue
        if not isinstance(spec, str):
            # Skipping it here would surface later as an AttributeError from
            # inside the structural layer, blamed on the TOML.
            raise ValueError(f"{where}: {field} must be a string, got "
                             f"{type(spec).__name__} ({spec!r})")
        pattern = spec[len("regex:"):] if spec.startswith("regex:") else spec
        try:
            re.compile(pattern, re.MULTILINE)
        except re.error as exc:
            raise ValueError(f"{where}: invalid {field} pattern {pattern!r}: {exc}") from exc
    if chk.get("count") and not (chk["count"] == "lines"
                                 or chk["count"].startswith("regex:")):
        raise ValueError(
            f"{where}: count must be \"lines\" or \"regex:<pattern>\", "
            f"got {chk['count']!r}")
    if chk.get("scope") not in ("file", "repo"):
        raise ValueError(f"{where}: scope must be \"file\" or \"repo\", "
                         f"got {chk.get('scope')!r}")
    # `scope = "file"` is what makes a check see only the staged files. Without
    # the {files} placeholder the command cannot be narrowed, so it would run
    # over the whole repo and block a commit of clean code on old debt -- the
    # opposite of the implicit ratchet this scope promises.
    wd = chk.get("workdir")
    if wd and root is not None and not _PLACEHOLDER.search(wd):
        # A literal workdir that does not exist would silently measure the wrong
        # tree; a placeholder ({go_dir}) is only resolvable at run time.
        if not (root / wd).is_dir():
            raise ValueError(
                f"{where}: workdir = \"{wd}\" is not a directory under {root}")
    if chk.get("scope") == "file" and "{files}" not in chk.get("command", []):
        raise ValueError(
            f"{where}: scope = \"file\" needs a {{files}} argument so the check "
            f"only sees staged files. Add it, or use scope = \"repo\" if the "
            f"tool cannot take a file list.")


def find_config(root: Path) -> Config:
    p = root / CONFIG_NAME
    if not p.exists():
        return Config({}, root)
    try:
        return Config(load_toml(p), root)
    except Exception as exc:
        # tomllib.TOMLDecodeError subclasses ValueError, so this branch has to
        # come first or the hint below can never print.
        hint = ""
        if "Invalid initial character" in str(exc) or "Unclosed" in str(exc):
            # The usual cause is a check table split across lines: a TOML inline
            # table must fit on one line, unlike the array that holds it.
            hint = ("\n  Hint: each check table must fit on one line -- "
                    '{ name = "x", command = ["tool"] } -- '
                    "only the array around it may span lines.")
        if isinstance(exc, (ValueError, TypeError)) and not isinstance(exc, TomlError):
            raise ConfigError(f"{CONFIG_NAME}: {exc}") from exc
        raise ConfigError(f"{CONFIG_NAME} is not valid TOML: {exc}{hint}") from exc


class ConfigError(Exception):
    """Raised when the config cannot be read. Always reported as exit 2."""


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def should_ignore(path: str, cfg: Config) -> bool:
    p = path.replace("\\", "/")
    for x in (*cfg.self_paths, *cfg.ignore_paths):
        x = x.rstrip("/")
        if p.startswith(x + "/") or ("/" + x + "/") in p:
            return True
    return False


# classify() return markers, distinct from None ("deliberately ignored").
UNKNOWN = "\x00unknown"    # code-looking file we have no checks for -> block
DISABLED = "\x00disabled"  # language explicitly turned off -> skip silently


def classify(path: str, cfg: Config) -> str | None:
    """Language name, UNKNOWN, DISABLED, or None (ignore)."""
    if should_ignore(path, cfg):
        return None
    ext = os.path.splitext(path)[1].lower()
    if not ext or ext in cfg.ignore_extensions:
        return None
    lang = cfg.all_ext_map().get(ext)
    if lang is None:
        return UNKNOWN
    if not cfg.languages[lang].get("enabled", True):
        return DISABLED
    return lang


# --------------------------------------------------------------------------- #
# Running checks
# --------------------------------------------------------------------------- #

class Finding:
    def __init__(self, lang: str, check: str, message: str, blocking: bool = True):
        self.lang, self.check, self.message, self.blocking = lang, check, message, blocking


def resolve_binary(name: str, cfg: Config) -> str | None:
    if "/" in name:
        # Repo-relative first: the gate is documented as runnable from anywhere,
        # and resolving against the process cwd made the same command work from
        # the repo root and silently "not found" from a subdirectory.
        cand = cfg.root / name
        if cand.exists():
            return str(cand)
        return name if os.path.exists(name) else None
    # PATH wins over repo-local dirs: never execute repo-controlled content
    # in preference to the tool the user actually installed.
    found = shutil.which(name)
    if found:
        return found
    for d in cfg.bin_dirs:
        cand = d / (name + ".exe" if os.name == "nt" else name)
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return None


# Tolerant of inner whitespace: eslint.config.mjs writes `{ max: { cyclomatic } }`,
# and a strict \{\w+\} silently substituted nothing there -- producing a config
# that threw ReferenceError, which the eslint check then reported as a tooling
# note. The whole eslint layer never ran and nothing said so.
_PLACEHOLDER = re.compile(r"\{\s*(\w+)\s*\}")


def expand(tokens: list[str], ctx: dict) -> list[str]:
    """Substitute {name} placeholders; leave unknown braces (globs) alone."""
    out = []
    for t in tokens:
        out.append(_PLACEHOLDER.sub(lambda m: ctx.get(m.group(1), m.group(0)), t))
    return out


def chunked(items: list[str], size: int = 60) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)] or [[]]


def run_stdout(argv: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
    """Like run(), but keeps stdout and stderr apart.

    A tool whose stdout is parsed as JSON must not have its stderr merged in:
    a stray warning would corrupt the payload and the layer would fail closed
    on a perfectly healthy run.
    """
    try:
        r = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="surrogateescape",
                           timeout=timeout)
    except FileNotFoundError:
        return 127, "", f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s: {' '.join(argv[:3])}"
    return r.returncode, r.stdout, r.stderr


def crash_suspect(rc: int, chk: dict) -> bool:
    """True when a non-zero exit is a crash rather than a verdict.

    `1` is the near-universal "findings found" code (ruff, eslint, golangci-lint
    all use it), so it is never a crash. A negative code means the process was
    killed -- an OOM-killed linter is a crash, not a result. Anything above 1 is
    a crash unless the check declares it with `findings_exit` (tsc reports type
    errors with exit 2).

    Exit code alone, deliberately: an earlier version also required stderr to be
    non-empty, which let a crash with a quiet stderr be scored as a verdict.
    """
    if rc == 0 or rc == 1:
        return False
    if rc < 0:
        return True
    allowed = chk.get("findings_exit")
    return not (allowed and rc in allowed)


def _crash_msg(rc: int, err: str) -> str:
    how = "was killed by a signal" if rc < 0 else f"exited {rc}"
    msg = f"{how} -- treated as a crash, not a result."
    if err.strip():
        msg += "\n" + "\n".join(err.strip().splitlines()[:3])
    return msg


def _stderr_note(chk: dict, metric: int | None, rc: int, err: str) -> str | None:
    """Say so when a counted check wrote to stderr and stdout held no findings."""
    if metric == 0 and err.strip() and chk.get("count"):
        return (f"counted 0 findings from stdout; stderr had output that was not "
                f"counted: " + " | ".join(err.strip().splitlines()[:2]))
    return None


def count_metric(output: str, spec: str | None) -> int | None:
    if not spec or not output:
        return 0 if spec else None
    if spec == "lines":
        return len([l for l in output.splitlines() if l.strip()])
    if spec.startswith("regex:"):
        return len(re.findall(spec[len("regex:"):], output, re.MULTILINE))
    return None


class CheckResult(NamedTuple):
    """Outcome of one check.

    `tooling` is a real field rather than a "[tooling] " prefix on the output:
    a marker carried inside the tool's own text can be forged by that text, and
    a check whose findings began with the literal string would be reclassified
    as "skipped" and silently dropped.
    """

    ok: bool
    output: str
    metric: int | None
    rc: int
    tooling: str | None = None
    # A crash is fatal (the gate cannot pass); a missing binary or an absent
    # config file is a note, because the language may still be covered by a
    # sibling check. Conflating the two let a crashed check print "treated as a
    # crash" and then sail through on a healthy sibling's result.
    fatal: bool = False
    note: str | None = None


def execute_check(lang: str, chk: dict, files: list[str], cfg: Config) -> CheckResult:
    cmd = list(chk["command"])
    binary = resolve_binary(cmd[0], cfg)
    if binary is None:
        hint = chk.get("install") or f"install {cmd[0]}"
        # rc=127 mirrors the shell's "command not found" so the caller can treat
        # this as a tooling error rather than a finding.
        return CheckResult(False, "", None, 127,
                           f"`{cmd[0]}` not found.\n  install: {hint}")

    uses_files = any(t == "{files}" for t in cmd)
    argv0 = [binary] + cmd[1:]
    ctx = dict(cfg.thresholds)

    # Checks may need to run in a subdirectory (e.g. a nested Go module).
    cwd = cfg.root
    wd = chk.get("workdir")
    if wd:
        wd = expand([wd], ctx)[0]
        cand = (cfg.root / wd).resolve()
        if not cand.is_dir():
            # Falling back to the repo root would quietly measure the wrong
            # tree -- a typo'd workdir must not decide what gets checked.
            return CheckResult(
                False, "", None, 0,
                f"`{cmd[0]}` has workdir = \"{wd}\", which is not a directory "
                f"under {cfg.root}.")
        cwd = cand

    err_re = chk.get("error_regex")

    # Some tools silently succeed when their config is absent (tsc without a
    # tsconfig.json exits 0 and prints nothing), which the ratchet would read as
    # "improved to 0". Refuse to score rather than report a fake clean run.
    for want in chk.get("requires_config", []):
        if not (cwd / expand([want], ctx)[0]).exists():
            return CheckResult(
                False, "", None, 0,
                f"`{cmd[0]}` needs {want}, which is not in {cwd}.\n"
                f"  create it (see the templates) or disable this check.")

    if chk["scope"] == "file" and uses_files:
        outs, all_out, worst, err_seen, killed = [], [], 0, "", False
        regex_text = None
        for group in chunked(files):
            if not group:
                continue
            argv = expand(argv0, ctx)
            argv = [t for tok in argv for t in (group if tok == "{files}" else [tok])]
            rc, out, err = run_stdout(argv, cwd)
            # A later chunk must never erase an earlier signal death: max() of
            # (-9, 0) is 0, which read as a clean run.
            killed = killed or rc < 0
            worst = max(worst, rc)
            merged = "\n".join(x for x in (out, err) if x).strip()
            if rc < 0 or crash_suspect(rc, chk):
                return CheckResult(False, merged, None, rc, _crash_msg(rc, err),
                                   fatal=True)
            if err_re and re.search(err_re, merged, re.MULTILINE):
                # Remember it and keep going: returning here would skip the
                # remaining chunks, so a crash in one of them would go unseen.
                # Kept apart from err_seen so the note quotes the output that
                # actually caused the skip, not a later chunk's stderr.
                if regex_text is None:
                    regex_text = merged
            if out:
                outs.append(out)
            if merged:
                all_out.append(merged)
            if err.strip():
                err_seen = err.strip()
        combined = "\n".join(all_out)
        if killed or crash_suspect(worst, chk):
            # Crash first: a tool that died must not be downgraded to a note
            # just because its dying words matched its own error_regex.
            code = -9 if killed and worst >= 0 else worst
            return CheckResult(False, combined, None, code,
                               _crash_msg(code, err_seen), fatal=True)
        # A file-scoped check that declares a count is judged by that count, not
        # by the exit code: gofmt -l and radon cc both exit 0 while reporting
        # findings, so exit-code-only judgement would pass everything.
        # Counted from stdout only. Merging stderr in meant a deprecation
        # warning from a clean run was counted as a finding (a false block), and
        # a crash's stderr text could be counted as the metric.
        if regex_text is not None:
            return CheckResult(True, combined, None, worst, regex_text)
        metric = count_metric("\n".join(outs), chk.get("count"))
        note = _stderr_note(chk, metric, worst, err_seen)
        if metric is not None:
            return CheckResult(metric == 0, combined, metric, worst, note=note)
        return CheckResult(worst == 0, combined, None, worst, note=note)

    argv = expand(argv0, ctx)
    if has_head(str(cwd)) is False and "--new-from-rev" in argv:
        i = argv.index("--new-from-rev")
        argv = argv[:i] + argv[i + 2:]
    rc, out, err = run_stdout(argv, cwd)
    merged = "\n".join(x for x in (out, err) if x).strip()

    # A crash outranks error_regex: a tool that died must not be downgraded to a
    # note just because its dying words matched its own error pattern.
    if rc < 0 or crash_suspect(rc, chk):
        return CheckResult(False, merged, None, rc, _crash_msg(rc, err), fatal=True)

    # A tool that could not run is a tooling problem, never an entropy finding.
    # Otherwise "Unable to find package.json" would be counted as slop.
    if err_re and re.search(err_re, merged, re.MULTILINE):
        return CheckResult(True, merged, None, rc, merged)

    # Counted from stdout only: stderr is where tools put warnings and crash
    # text, and counting either as a finding produced false blocks and phantom
    # improvements.
    metric = count_metric(out, chk.get("count"))
    return CheckResult(rc == 0, merged, metric, rc,
                       note=_stderr_note(chk, metric, rc, err))


# --------------------------------------------------------------------------- #
# aislop layer
# --------------------------------------------------------------------------- #

def run_aislop(cfg: Config, staged: list[str]):
    """Return (findings, notes, tooling)."""
    findings: list[Finding] = []
    notes: list[str] = []
    tooling: list[str] = []
    if cfg.aislop_mode == "off":
        return findings, notes, tooling

    binary = resolve_binary("aislop", cfg)
    if binary is None:
        # "require" is enforced as a config error (exit 2) in cmd_hook, before
        # we get here. Anything else is advisory.
        notes.append("aislop not found -- the AI-slop layer did not run. "
                     "install: npm i -D aislop")
        return findings, notes, tooling

    # Exclude the gate's own directory whatever it is called, unless the user
    # already told aislop what to exclude.
    extra = list(cfg.aislop_extra)
    if cfg.self_paths and "--exclude" not in extra:
        extra += ["--exclude", cfg.self_paths[0].rstrip("/")]

    def _unevaluated(reason: str):
        """A required layer that did not produce a score cannot read as a pass."""
        if cfg.aislop_mode == "require":
            tooling.append(f"aislop: {reason}")
        else:
            notes.append(f"aislop: {reason} -- the AI-slop layer did not run.")
        return findings, notes, tooling

    argv = [binary, "scan", "--staged", "--json", *extra]
    # stdout only: aislop's stdout is parsed as JSON, so a warning on stderr must
    # not be merged in and turn a healthy run into a "no JSON" tooling error.
    rc, out, err = run_stdout(argv, cfg.root)
    detail = f" (rc={rc})"
    if err.strip():
        detail += "; stderr: " + " | ".join(err.strip().splitlines()[:2])
    if not out.strip().startswith("{"):
        return _unevaluated(f"produced no JSON{detail}")
    if rc not in (0, 1):
        # 0 and 1 are aislop's documented exits. Anything else means it did not
        # finish, and a half-written payload still parses as valid JSON -- so a
        # truncated diagnostics list must not be read as "nothing found".
        return _unevaluated(f"did not finish{detail}")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return _unevaluated(f"JSON unparseable ({exc})")
    if not isinstance(data, dict):
        return _unevaluated(f"JSON is a {type(data).__name__}, not an object")

    coverage = data.get("coverage")
    if coverage is None:
        coverage = {}
    if not isinstance(coverage, dict):
        return _unevaluated(f"JSON 'coverage' is a {type(coverage).__name__}, not an object")
    diagnostics = data.get("diagnostics")
    if diagnostics is None:
        diagnostics = []
    if not isinstance(diagnostics, list):
        return _unevaluated(f"JSON 'diagnostics' is a {type(diagnostics).__name__}, not a list")

    score = data.get("score")
    if score is not None and (isinstance(score, bool)
                              or not isinstance(score, (int, float))
                              or not math.isfinite(score)):
        # NaN/inf are floats, so isinstance alone would let `"score": NaN`
        # through -- and every comparison against NaN is False, so it would
        # silently satisfy the score gate forever.
        return _unevaluated(f"JSON 'score' is not a usable number ({score!r})")
    label = data.get("label", "")
    scoreable = coverage.get("scoreable", True)
    if not isinstance(scoreable, bool):
        return _unevaluated(f"JSON 'coverage.scoreable' is a "
                            f"{type(scoreable).__name__}, not a boolean")

    # A well-formed response that simply carries no score is still a response
    # this layer cannot act on. In require mode that is a tooling error, not a
    # pass -- otherwise a half-broken aislop silently disables the whole layer.
    # Diagnostics are still collected either way.
    def _no_score(reason: str) -> None:
        if cfg.aislop_mode == "require":
            tooling.append(f"aislop: {reason}")
        else:
            notes.append(f"aislop: {reason} -- the AI-slop layer did not run.")

    if not scoreable:
        dom = coverage.get("dominantUnsupported")
        _no_score(f"withheld the score: this repo is dominated by an unsupported "
                  f"language ({dom}); supported files: {coverage.get('supportedFiles')}, "
                  f"unsupported: {coverage.get('unsupportedFiles')}")
    elif score is None:
        _no_score("returned no score")

    for d in diagnostics:
        if not isinstance(d, dict):
            continue
        sev = d.get("severity", "info")
        if sev not in ("error", "warning"):
            continue
        f = d.get("filePath", "?")
        if not isinstance(f, str):
            f = str(f)
        if staged and not any(f.endswith(s) or s.endswith(f) for s in staged):
            continue
        findings.append(Finding(
            "aislop", f"aislop/{d.get('rule', '?')}",
            f"{f}:{d.get('line', '?')} [{sev}] {d.get('message', '')}",
            blocking=(sev == "error"),
        ))

    if score is not None and score < cfg.aislop_fail_below:
        findings.append(Finding(
            "aislop", "aislop/score",
            f"aislop score {score} ({label}) is below the gate "
            f"({cfg.aislop_fail_below})",
        ))
    return findings, notes, tooling


# --------------------------------------------------------------------------- #
# Baseline (repo-scoped ratchet)
# --------------------------------------------------------------------------- #

def baseline_path(cfg: Config) -> Path:
    return cfg.root / BASELINE_NAME


def load_baseline(cfg: Config, notes: list[str] | None = None) -> dict:
    """Read the stored metrics, tolerating a hand-edited or truncated file.

    A baseline that cannot be parsed must not crash the gate (it is a file in
    the repo, so it is exactly the kind of thing that gets corrupted), and it
    must not be trusted either -- an unusable entry is dropped, which makes the
    affected check report "no baseline recorded" rather than a bogus pass.
    """
    p = baseline_path(cfg)
    if not p.exists():
        return {}

    def _bad(reason: str) -> dict:
        if notes is not None:
            notes.append(f"{BASELINE_NAME} {reason}; ignoring it. Re-capture with "
                         f"`entropy-gate baseline --write`.")
        return {}

    try:
        raw = p.read_text()
    except OSError as exc:
        return _bad(f"could not be read ({exc})")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _bad(f"is not valid JSON ({exc})")
    if not isinstance(data, dict) or not isinstance(data.get("metrics"), dict):
        return _bad("has no 'metrics' object")

    metrics = {k: v for k, v in data["metrics"].items()
               if isinstance(v, int) and not isinstance(v, bool)}
    dropped = len(data["metrics"]) - len(metrics)
    if dropped and notes is not None:
        notes.append(f"{BASELINE_NAME}: ignored {dropped} non-integer metric(s).")
    return {"metrics": metrics}


def write_baseline(cfg: Config, metrics: dict) -> Path:
    p = baseline_path(cfg)
    # Merge instead of replace: a capture only measures the languages staged in
    # *this* commit, so replacing the map would erase every other language's
    # debt and re-block it as "no baseline recorded".
    merged = dict(load_baseline(cfg).get("metrics", {}))
    merged.update(metrics)
    payload = {
        "schema": "entropy-gate.baseline.v1",
        "metrics": dict(sorted(merged.items())),
    }
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return p


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def collect_languages(files: list[str], cfg: Config):
    """Split staged files into per-language buckets plus diagnostic buckets."""
    langs: dict[str, list[str]] = {}
    unknown: list[str] = []
    disabled: list[str] = []
    missing: list[str] = []
    dangling: list[str] = []
    for f in files:
        path = cfg.root / f
        # Staged but deleted from the worktree: linting it would make the whole
        # batch error out. Reported, never silently dropped.
        if not path.exists():
            # A dangling symlink is legitimate committable content with nothing
            # to lint, so it is not the "content we cannot read" failure case.
            (dangling if os.path.lexists(path) else missing).append(f)
            continue
        lang = classify(f, cfg)
        if lang is None:
            continue
        if lang == DISABLED:
            disabled.append(f)
            continue
        if lang == UNKNOWN:
            unknown.append(f)
            continue
        langs.setdefault(lang, []).append(f)
    return langs, unknown, disabled, missing, dangling


def divergent_files(root: Path, staged: list[str]) -> list[str] | None:
    """Returns None when git could not answer -- the caller must fail closed."""
    """Staged files whose worktree content differs from the index.

    Every layer reads the worktree, so a file staged clean and then edited in
    place would be checked in its *unstaged* form. Passing then would mean the
    commit was never actually checked -- so we fail closed instead.

    -z + core.quotepath=false: without them git octal-quotes any path with a
    non-ASCII byte, the name never matches the staged list, and the divergence
    goes undetected exactly for the files nobody looks at.
    """
    try:
        out = git("-c", "core.quotepath=false", "diff", "--name-only", "-z",
                  "--", *staged, cwd=str(root))
    except RuntimeError:
        # "Could not tell" is not "nothing diverged": returning [] here would
        # silently skip the guard that stops a half-staged file being committed
        # in its unstaged form.
        return None
    dirty = {p for p in out.split("\0") if p}
    return [f for f in staged if f in dirty]


def run_structural(langs: dict[str, list[str]], cfg: Config, baseline: dict):
    findings: list[Finding] = []
    notes: list[str] = []
    metrics: dict[str, int] = {}
    tooling: list[str] = []
    ran: dict[str, int] = {}          # checks that produced a real result
    applicable: dict[str, int] = {}   # checks that were scheduled for a language

    jobs = []
    for lang, files in langs.items():
        spec = cfg.languages[lang]
        for chk in spec.get("checks", []):
            if not chk.get("enabled", True):
                continue
            we = chk.get("when_extensions")
            if we and not any(f.lower().endswith(tuple(e.lower() for e in we)) for f in files):
                continue
            jobs.append((lang, chk, files))
            applicable[lang] = applicable.get(lang, 0) + 1

    def work(job):
        lang, chk, files = job
        return (lang, chk) + tuple(execute_check(lang, chk, files, cfg))

    results = []
    if cfg.parallel and len(jobs) > 1:
        with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
            results = list(ex.map(work, jobs))
    else:
        results = [work(j) for j in jobs]

    for lang, chk, ok, out, metric, rc, tooling_msg, fatal, chk_note in results:
        key = f"{lang}/{chk['name']}"
        scope = chk.get("scope", "repo")

        if tooling_msg is not None:
            body = tooling_msg
            if fatal:
                # A crash means the gate cannot do its job -- never a note,
                # never a pass, whatever else ran for this language.
                tooling.append(f"{key}: " + "\n".join(body.splitlines()[:5]))
            elif rc == 127 and chk.get("required"):
                # A check the user marked `required` that is not installed means
                # the gate cannot do its job -- never a note, never a pass.
                tooling.append(f"{key}: required tool is not installed.\n"
                               + "\n".join(body.splitlines()[:3]))
            else:
                notes.append(f"{key}: skipped -- " + " | ".join(body.splitlines()[:3]))
            continue

        if chk_note:
            notes.append(f"{key}: " + chk_note)

        # A linter that crashed or timed out produced no trustworthy result.
        # Treating that as "zero findings" would be a silent pass. A check that
        # declares a count is judged strictly: if it exited non-zero and the
        # count matched nothing, either it crashed or its output format drifted
        # -- and a regex that no longer matches would otherwise read as clean
        # forever. Checks without a count keep the looser rule, because tools
        # like ruff legitimately exit 1 to mean "findings found".
        if metric is not None:
            if rc != 0 and metric == 0:
                tooling.append(f"{key}: exited {rc} but reported nothing matching its "
                               f"count pattern -- treated as a crash or a format "
                               f"change, not a pass.\n"
                               + "\n".join(out.splitlines()[:5]))
                continue
        elif rc > 1:
            tooling.append(f"{key}: exited {rc} with no findings -- treated as a "
                           f"crash/timeout, not a pass.\n"
                           + "\n".join(out.splitlines()[:5]))
            continue

        ran[lang] = ran.get(lang, 0) + 1

        # File-scoped checks have an implicit ratchet: they only ever see staged
        # files, so a nonzero count is a violation outright -- never something to
        # compare against a stored baseline.
        if metric is not None and scope == "file":
            if metric > 0:
                findings.append(Finding(lang, key, out or f"{metric} finding(s)"))
            continue

        if metric is not None:
            metrics[key] = metric
            prev = baseline.get("metrics", {}).get(key)
            if prev is None:
                if metric > 0:
                    notes.append(
                        f"{key}: {metric} finding(s), no baseline recorded. "
                        f"Run `entropy-gate baseline --write` to lock this in, "
                        f"or fix them now."
                    )
                    findings.append(Finding(lang, key, out or f"{metric} finding(s)"))
                    continue
                continue
            if metric > prev:
                findings.append(Finding(
                    lang, key,
                    f"{key}: {metric} finding(s) is above the baseline of {prev} "
                    f"(regression +{metric - prev}).\n{out}",
                ))
            elif metric < prev:
                notes.append(f"{key}: improved {prev} -> {metric}; consider `baseline --write`")
            continue

        if not ok:
            findings.append(Finding(lang, key, out or f"{key} failed"))

    # A language whose every check was skipped is not "clean" -- it is
    # unevaluated, and the README's promise is that this can never read as a
    # pass. That includes checks skipped by `when_extensions` and languages
    # whose checks are all disabled: an enabled language with staged files must
    # be evaluated, or the language itself must be switched off explicitly.
    for lang, files in sorted(langs.items()):
        if ran.get(lang, 0):
            continue
        spec = cfg.languages.get(lang, {})
        enabled = [c["name"] for c in spec.get("checks", []) if c.get("enabled", True)]
        if applicable.get(lang, 0):
            why = (f"none of the configured checks could run for {len(files)} staged "
                   f"file(s) ({', '.join(enabled)})")
        elif enabled:
            why = (f"{len(files)} staged file(s), but none of the enabled checks "
                   f"({', '.join(enabled)}) apply to them")
        else:
            why = (f"{len(files)} staged file(s), but every check for this language "
                   f"is disabled in the config")
        tooling.append(
            f"{lang}: {why} -- this language was never evaluated. Enable a check, or "
            f"set [languages.{lang}] enabled = false to skip it explicitly.")

    return findings, notes, metrics, tooling


def cmd_hook(cfg: Config, args) -> int:
    if os.environ.get("ENTROPY_GATE_SKIP"):
        print(yellow("entropy-gate: skipped (ENTROPY_GATE_SKIP set)"))
        return EXIT_OK

    root = cfg.root
    staged = staged_files(root)
    if not staged:
        print(green("entropy-gate: nothing staged"))
        return EXIT_OK

    langs, unknown, disabled, missing, dangling = collect_languages(staged, cfg)

    checked = sum(len(v) for v in langs.values())
    print(bold(f"entropy-gate {VERSION}")
          + dim(f"  ·  {checked} of {len(staged)} staged file(s) in scope"))
    if langs:
        print("  languages: " + ", ".join(
            cyan(f"{k} ({len(v)})") for k, v in sorted(langs.items())))
    print()

    notes: list[str] = []

    # --- Fail closed: worktree must match what is being committed ---------- #
    tracked = [f for fs in langs.values() for f in fs]
    if not getattr(args, "allow_divergence", False):
        dirty = divergent_files(root, tracked)
        if dirty is None:
            print(red("✖ could not compare the worktree with the index"))
            print("  `git diff --name-only` failed, so the gate cannot tell whether")
            print("  it is looking at the content you are committing.")
            print()
            return EXIT_CONFIG
        if dirty:
            print(red("✖ worktree differs from the index for staged file(s):"))
            for f in dirty[:10]:
                print(f"    {f}")
            if len(dirty) > 10:
                print(f"    ... and {len(dirty) - 10} more")
            print()
            print("  Checks read the worktree, so passing here would mean the commit")
            print("  was never actually checked. Stage the version you intend to")
            print("  commit (`git add <file>`), or pass --allow-divergence if you are")
            print("  deliberately committing a partial hunk you have verified.")
            return EXIT_CONFIG

    # --- Router: unconfigured language is a hard error -------------------- #
    if unknown:
        exts = sorted({os.path.splitext(f)[1] for f in unknown})
        print(red("✖ No entropy checks configured for language(s): " + ", ".join(exts)))
        for f in unknown[:10]:
            print(f"    {f}")
        if len(unknown) > 10:
            print(f"    ... and {len(unknown) - 10} more")
        print()
        print("  Add a language block to " + bold(CONFIG_NAME) + ":")
        print(dim(textwrap_block(exts)))
        if cfg.fail_on_unknown_language:
            print()
            print(red("  Commit blocked. Set settings.fail_on_unknown_language = false "
                      "to downgrade to a warning."))
            return EXIT_CONFIG
        notes.append("skipped unconfigured language(s): " + ", ".join(exts))

    if disabled:
        notes.append(f"{len(disabled)} file(s) skipped: language disabled in config")
    if dangling:
        # A symlink to a path that does not exist: committable content, but
        # there is no file behind it to lint.
        notes.append(f"{len(dangling)} staged symlink(s) point at a missing target "
                     f"and were not checked: " + ", ".join(dangling[:3]))

    # --- Fail closed: a staged file that is gone from the worktree --------- #
    # The index says "add/modify", the worktree says "nothing there". We cannot
    # read the content being committed, so we cannot check it -- and committing
    # it unchecked is exactly the silent pass this gate exists to prevent.
    if missing:
        print(red("✖ staged file(s) no longer exist in the worktree:"))
        for f in missing[:10]:
            print(f"    {f}")
        if len(missing) > 10:
            print(f"    ... and {len(missing) - 10} more")
        print()
        print("  Their staged content cannot be read, so it was never checked.")
        print("  Re-stage (`git add -A`) or drop them from the index "
              "(`git restore --staged <file>`).")
        return EXIT_CONFIG

    # --- Layer 1: aislop must be present when required -------------------- #
    if cfg.aislop_mode == "require" and resolve_binary("aislop", cfg) is None:
        print(red("✖ aislop is required but not installed"))
        print("  install: npm i -D aislop")
        print('  or relax it: [aislop] enabled = "optional"')
        return EXIT_CONFIG

    # --- Diff size guard (AI slop signature) ------------------------------ #
    if cfg.max_staged_lines:
        delta = staged_line_delta(root, cfg)
        if delta > cfg.max_staged_lines:
            notes.append(
                f"staged diff adds {delta} lines (limit {cfg.max_staged_lines}). "
                f"Split the commit -- large diffs are where slop hides."
            )

    findings: list[Finding] = []

    # --- Layer 1: aislop -------------------------------------------------- #
    # A layer that raises must never surface as a traceback with exit 1 ("entropy
    # violations"): it is a tooling failure, and the gate fails closed on those.
    try:
        a_findings, a_notes, a_tooling = run_aislop(cfg, staged)
    except Exception as exc:  # noqa: BLE001 -- last line of defence
        a_findings, a_notes = [], []
        a_tooling = [f"aislop layer raised {type(exc).__name__}: {exc}"]
    findings += a_findings
    notes += a_notes

    # --- Layer 2: structural ---------------------------------------------- #
    baseline = load_baseline(cfg, notes)
    try:
        s_findings, s_notes, metrics, tooling = run_structural(langs, cfg, baseline)
    except Exception as exc:  # noqa: BLE001
        s_findings, s_notes, metrics = [], [], {}
        tooling = [f"structural layer raised {type(exc).__name__}: {exc}"]
    findings += s_findings
    notes += s_notes
    tooling = a_tooling + tooling

    # `hook --write-baseline` is the same capture as `baseline --write`, so it
    # gets the same refusals. Writing while a check cannot run would lock in a
    # zero for debt that was never measured.
    write_error = None
    if args.write_baseline:
        force = getattr(args, "force", False)
        if tooling and not force:
            write_error = ("refusing to record a baseline while a check cannot run -- "
                           "the missing counts would be locked in as zero")
        elif not metrics and not force:
            write_error = ("refusing to record a baseline with no metrics -- nothing "
                           "was measured, so this capture would record nothing")

    # A refused capture is itself the reason this run exits 2, so it belongs in
    # the tooling block: printing a green "✔ passed" and then a refusal (or the
    # other way round) is the self-contradicting transcript this ordering exists
    # to prevent.
    if write_error:
        tooling = tooling + [write_error + "\n  Use --force to override."]

    rc = report(findings, notes, tooling)

    # Written only after the verdict, so the transcript never reads "baseline
    # written" before the commit it just blocked.
    if args.write_baseline and not write_error:
        p = write_baseline(cfg, metrics)
        print(green(f"✔ baseline written to {p}"))
        for k, v in sorted(metrics.items()):
            print(f"  {k}: {v}")
        if rc != EXIT_OK:
            print(yellow("  note: those counts are now the baseline, so this debt "
                         "will not block again."))
        print()

    if write_error:
        return EXIT_CONFIG
    return rc


def textwrap_block(exts: list[str]) -> str:
    """Emit a ready-to-paste config block per unknown extension."""
    out = [""]
    for e in exts:
        name = e.lstrip(".") or "unknown"
        out += [
            f"    [languages.{name}]",
            "    enabled = true",
            f'    extensions = ["{e}"]',
            "    checks = [",
            # One line per table: TOML forbids newlines inside an inline table,
            # so a wrapped one would be rejected the moment it was pasted.
            '      { name = "linter", scope = "repo", command = ["your-linter", '
            '"--flag"], count = "lines" },',
            "    ]",
            "",
        ]
    return "\n".join(out)


def report(findings: list[Finding], notes: list[str],
           tooling: list[str] | None = None) -> int:
    tooling = tooling or []
    blocking = [f for f in findings if f.blocking]
    advisory = [f for f in findings if not f.blocking]

    if notes:
        print(yellow("notes"))
        for n in notes:
            print("  · " + n)
        print()

    if advisory:
        print(yellow(f"warnings ({len(advisory)})"))
        for f in advisory:
            print(f"  · [{f.check}] {f.message}")
        print()

    if tooling:
        print(red("✖ tooling error -- the gate could not do its job, so it cannot pass"))
        for t in tooling:
            print("  " + t.replace("\n", "\n  "))
        print()

    if not blocking:
        if tooling:
            # Never print "passed" and then an error: the gate did not pass.
            return EXIT_CONFIG
        print(green("✔ entropy-gate passed") + dim("  ·  entropy only goes down from here"))
        return EXIT_OK

    print(red(f"✖ entropy-gate blocked the commit ({len(blocking)} blocking finding(s))"))
    print()
    by_lang: dict[str, list[Finding]] = {}
    for f in blocking:
        by_lang.setdefault(f.lang, []).append(f)
    for lang, fs in sorted(by_lang.items()):
        print(bold(f"  {lang}"))
        for f in fs:
            head = f"    ✖ {f.check}"
            print(head)
            for line in f.message.splitlines():
                print(dim(f"      {line}"))
        print()
    print(dim("  Fix these rather than using --no-verify. If a finding is wrong,"))
    print(dim("  tune .entropy-gate.toml or re-capture with `entropy-gate baseline --write`."))
    return EXIT_CONFIG if tooling else EXIT_VIOLATION


def cmd_baseline(cfg: Config, args) -> int:
    staged = staged_files(cfg.root) or []
    langs, unknown, _, _, _ = collect_languages(staged, cfg)
    if unknown:
        # Same shape as the hook's message: extensions, not raw paths, plus the
        # ready-to-paste block -- the condition is identical, so the advice is.
        exts = sorted({Path(f).suffix.lower() or f for f in unknown})
        print(red("✖ unconfigured language(s): " + ", ".join(exts)))
        print(textwrap_block(exts))
        return EXIT_CONFIG
    if not langs:
        print(red("✖ nothing staged, or nothing staged matches a configured language"))
        print("  Stage the files you want measured, then re-run.")
        return EXIT_CONFIG
    _, _, metrics, tooling = run_structural(langs, cfg, {})
    if tooling:
        for t in tooling:
            print(yellow("  ! " + t.replace("\n", "\n    ")))
    if args.write:
        if tooling and not getattr(args, "force", False):
            # A check that could not run would be recorded as 0, and the ratchet
            # would then treat the debt it never measured as paid off.
            print(red("✖ refusing to write a baseline while a check cannot run -- "
                      "the missing counts would be locked in as zero"))
            print("  Fix the tooling above, then re-run. Use --force to override.")
            return EXIT_CONFIG
        if not metrics and not getattr(args, "force", False):
            print(red("✖ refusing to record a baseline with no metrics -- nothing "
                      "was measured, so this capture would record nothing"))
            print("  Stage files first. Use --force if you really mean it.")
            return EXIT_CONFIG
        p = write_baseline(cfg, metrics)
        print(green(f"✔ baseline written to {p}"))
        for k, v in sorted(metrics.items()):
            print(f"  {k}: {v}")
    else:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    return EXIT_OK


def cmd_doctor(cfg: Config, args) -> int:
    print(bold(f"entropy-gate {VERSION}  ·  doctor"))
    print()
    aislop = resolve_binary("aislop", cfg)
    print(f"  aislop           {'✔ ' + aislop if aislop else '✖ not found (npm i -D aislop)'}")
    print()
    for lang, spec in sorted(cfg.languages.items()):
        print(bold(f"  {lang}") + dim(f"  ({', '.join(spec['extensions'])})"))
        for chk in spec.get("checks", []):
            b = resolve_binary(chk["command"][0], cfg)
            state = green("✔") if b else yellow("✖")
            tail = dim(f" [{chk['scope']}]") + (dim(" (off)") if not chk.get("enabled", True) else "")
            extra = "" if b else dim(f"  install: {chk.get('install','')}")
            print(f"    {state} {chk['name']:<20}{tail}{extra}")
        print()
    return EXIT_OK


def cmd_init(cfg: Config, args) -> int:
    import stat
    here = Path(__file__).resolve().parent
    target = cfg.root

    cfg_src = here / CONFIG_NAME
    cfg_dst = target / CONFIG_NAME
    if not cfg_dst.exists():
        cfg_dst.write_text(cfg_src.read_text() if cfg_src.exists() else DEFAULT_CONFIG)
        print(green(f"✔ wrote {cfg_dst}"))
    else:
        print(dim(f"· {cfg_dst} exists, leaving it alone"))

    # Only write templates for languages the repo actually contains. Dropping
    # eslint.config.mjs into a Go+Python repo just generates findings on a file
    # the project never asked for.
    present = {
        p.suffix.lower()
        for p in cfg.root.rglob("*")
        if p.is_file() and not should_ignore(
            str(p.relative_to(cfg.root)).replace("\\", "/"), cfg)
    }
    requires = {
        ".golangci.yml": {".go"},
        "eslint.config.mjs": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"},
        "tsconfig.json": {".ts", ".tsx", ".mts", ".cts"},
        "knip.json": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
        ".dependency-cruiser.cjs": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
        ".importlinter": {".py", ".pyi"},
    }

    tmpl_src = here / "templates"
    if tmpl_src.is_dir():
        for t in sorted(tmpl_src.iterdir()):
            if t.name in requires and not (present & requires[t.name]):
                print(dim(f"· {t.name} not needed for this repo, skipped"))
                continue
            dst = target / t.name
            if dst.exists():
                print(dim(f"· {dst.name} exists, leaving it alone"))
                continue
            # Substitute {cyclomatic} & friends so [thresholds] is the single
            # source of truth instead of a "keep in sync" comment.
            raw = t.read_text()
            filled = _PLACEHOLDER.sub(
                lambda m: cfg.thresholds.get(m.group(1), m.group(0)), raw)
            dst.write_text(filled)
            suffix = " (thresholds applied)" if filled != raw else ""
            print(green(f"✔ wrote {dst.name}{suffix}"))

    hooks = here / ".githooks"
    if hooks.is_dir():
        for h in hooks.iterdir():
            h.chmod(h.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        def _is_ours(value: str) -> bool:
            """True when an existing core.hooksPath already points at us."""
            p = Path(value)
            p = p if p.is_absolute() else (target / p)
            try:
                return p.resolve() == hooks.resolve()
            except OSError:
                return False

        wanted = str(hooks.relative_to(target) if hooks.is_relative_to(target) else hooks)
        existing = subprocess.run(["git", "config", "--get", "core.hooksPath"],
                                  cwd=str(target), capture_output=True,
                                  text=True).stdout.strip()
        if existing and not _is_ours(existing):
            # Never silently disable husky/pre-commit. install.sh prints the same
            # guidance; this guard is what makes that promise true.
            print(yellow(f"! core.hooksPath is already set to {existing}; leaving it alone"))
            print(dim("  To run entropy-gate alongside it, add a pre-commit entry:"))
            print(dim(f"      python3 {here / 'entropy_gate.py'} hook"))
        else:
            subprocess.run(["git", "config", "core.hooksPath", wanted], cwd=str(target))
            print(green(f"✔ git core.hooksPath -> {hooks}"))
    return EXIT_OK


def cmd_selftest(cfg: Config, args) -> int:
    """Pure-logic checks that need no linters installed."""
    passed, failed = 0, 0

    def check(name, got, want):
        nonlocal passed, failed
        if got == want:
            passed += 1
        else:
            failed += 1
            print(red(f"  ✖ {name}\n      got:  {got!r}\n      want: {want!r}"))

    sample = """
[settings]
max_staged_lines = 1200   # a comment
[thresholds]
cyclomatic = 10
[languages.rust]
enabled = true
extensions = [".rs"]
checks = [
  { name = "clippy", scope = "repo", command = ["cargo", "clippy"] },
]
"""
    if _HAVE_TOML:
        check("mini parser == tomllib", _mini_toml(sample), tomllib.loads(sample))
    check("comment stripped", _mini_toml("a = 1 # x\n")["a"], 1)
    check("quoted hash kept", _mini_toml('a = "v#x"\n')["a"], "v#x")
    check("bool parsed", _mini_toml("a = true\n")["a"], True)
    check("inline table list",
          _mini_toml('c = [{ n = "x", s = "repo" }]\n')["c"],
          [{"n": "x", "s": "repo"}])
    check("array of tables errors",
          "raises" if _raises(lambda: _mini_toml("[[a]]\nb = 1\n")) else "ok", "raises")

    c = Config({}, Path("."))
    check("unknown ext -> UNKNOWN", classify("a.rs", c), UNKNOWN)
    check("ignored ext -> None", classify("a.md", c), None)
    check("known ext -> python", classify("a.py", c), "python")
    check("vendor ignored", classify("vendor/a.py", c), None)
    c.languages["python"]["enabled"] = False
    check("disabled lang -> DISABLED", classify("a.py", c), DISABLED)
    check("disabled not in ext_map", "python" in c.ext_map(), False)

    check("count regex", count_metric("a.go:1: x\na.go:2: y\n  ctx", "regex:^\\S+\\.go:\\d+"), 2)
    check("count lines", count_metric("a\n\nb\n", "lines"), 2)
    check("placeholder keeps globs",
          expand(["--ext", "{js,ts}", "{cyclomatic}"], {"cyclomatic": "10"}),
          ["--ext", "{js,ts}", "10"])

    print(green(f"✔ selftest: {passed} passed") if not failed
          else red(f"✖ selftest: {failed} failed, {passed} passed"))
    return EXIT_OK if not failed else EXIT_CONFIG


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


DEFAULT_CONFIG = """# entropy-gate configuration
# Docs: see README.md in this directory

[settings]
fail_on_unknown_language = true      # unconfigured language => block the commit
max_staged_lines = 1200              # 0 disables; guards against giant AI diffs
parallel = true
# ignore_paths = ["node_modules/", "dist/"]
# ignore_extensions = [".md", ".json"]

[aislop]
enabled = "require"                  # require | optional | off
fail_below = 0                       # block when aislop score drops below this

[thresholds]
cyclomatic = 10                      # per function
cognitive = 15
function_lines = 30
file_lines = 300
nesting = 3
params = 4
duplication_percent = 3.0

# --- the three configured languages -------------------------------------- #

[languages.python]
enabled = true
# disable = ["vulture"]             # opt out of a single check

[languages.go]
enabled = true

[languages.javascript]
enabled = true
# disable = ["knip"]

# --- adding a language later ---------------------------------------------- #
# Uncomment and fill in; until then, committing these files is blocked.
#
# [languages.rust]
# enabled = true
# extensions = [".rs"]
# checks = [
#   { name = "clippy", scope = "repo", command = ["cargo", "clippy", "--", "-W", "pedantic"] },
# ]
"""


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="entropy-gate",
        description="Language-aware pre-commit gate against code entropy.")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hook", help="pre-commit entrypoint (staged files)")
    h.add_argument("--write-baseline", action="store_true",
                   help="re-capture repo-scoped metrics instead of comparing")
    h.add_argument("--force", action="store_true",
                   help="with --write-baseline: write even if a check could not run")
    h.add_argument("--allow-divergence", action="store_true",
                   help="do not fail when the worktree differs from the index")
    h.set_defaults(func=cmd_hook)

    c = sub.add_parser("check", help="same as hook")
    c.add_argument("--write-baseline", action="store_true")
    c.add_argument("--force", action="store_true")
    c.add_argument("--allow-divergence", action="store_true")
    c.set_defaults(func=cmd_hook)

    b = sub.add_parser("baseline", help="measure repo-scoped checks")
    b.add_argument("--write", action="store_true")
    b.add_argument("--force", action="store_true",
                   help="record a baseline even if a check could not run, or if "
                        "nothing was measured")
    b.set_defaults(func=cmd_baseline)

    d = sub.add_parser("doctor", help="show tool availability")
    d.set_defaults(func=cmd_doctor)

    i = sub.add_parser("init", help="write config + templates + install hook")
    i.set_defaults(func=cmd_init)

    s = sub.add_parser("selftest", help="run built-in logic checks (no linters needed)")
    s.set_defaults(func=cmd_selftest)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # selftest exercises pure logic and must run outside a repository.
    if getattr(args, "func", None) is cmd_selftest:
        return args.func(Config({}, Path(".").resolve()), args)

    try:
        root = repo_root()
    except Exception as exc:
        print(red(f"✖ not a git repository ({exc})"), file=sys.stderr)
        return EXIT_CONFIG
    try:
        cfg = find_config(root)
    except ConfigError as exc:
        print(red(f"✖ {exc}"), file=sys.stderr)
        print("  Fix the config or delete it to fall back to defaults.", file=sys.stderr)
        return EXIT_CONFIG

    try:
        return args.func(cfg, args)
    except ConfigError as exc:
        print(red(f"✖ {exc}"), file=sys.stderr)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        print(red("✖ interrupted"), file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001 -- last line of defence
        # An escaping traceback exits 1, and 1 means "entropy violations". A
        # crash is a tooling failure, so it must exit 2 and say so in one line.
        if os.environ.get("ENTROPY_GATE_TRACEBACK"):
            raise
        print(red(f"✖ entropy-gate crashed: {type(exc).__name__}: {exc}"),
              file=sys.stderr)
        print("  That is a bug in the gate, not a verdict on your code. Re-run with "
              "ENTROPY_GATE_TRACEBACK=1 for the full traceback.", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())

