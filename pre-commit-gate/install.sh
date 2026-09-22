#!/usr/bin/env sh
#
# Install entropy-gate into the current git repository.
#
#   ./install.sh              # wire the hook + write config/templates
#   ./install.sh --tools      # also install aislop and the language linters
#   ./install.sh --uninstall  # remove the hook wiring
#
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"

if [ -z "$ROOT" ]; then
  echo "entropy-gate: not inside a git repository" >&2
  exit 2
fi

GATE_DIR="$ROOT/entropy-gate"
if [ "$HERE" != "$GATE_DIR" ]; then
  # Running from a vendored copy somewhere else; install into entropy-gate/.
  GATE_DIR="$HERE"
fi

case "${1:-}" in
--uninstall)
  # Only clear the wiring if it is ours. Unsetting a husky/pre-commit
  # hooksPath would silently disable those hooks -- the install path refuses
  # to clobber them, so the uninstall path must not either.
  EXISTING="$(git -C "$ROOT" config --get core.hooksPath || true)"
  case "$EXISTING" in
    "")       EXISTING_ABS="" ;;
    /*)       EXISTING_ABS="$EXISTING" ;;
    *)        EXISTING_ABS="$ROOT/$EXISTING" ;;
  esac
  if [ -z "$EXISTING" ]; then
    echo "· core.hooksPath is not set; nothing to remove"
  elif [ "$EXISTING_ABS" = "$GATE_DIR/.githooks" ]; then
    git -C "$ROOT" config --unset core.hooksPath || true
    echo "✔ removed core.hooksPath (was $EXISTING)"
  else
    echo "! core.hooksPath points at $EXISTING, which is not this gate."
    echo "  Leaving it alone; remove it yourself if you really mean to."
  fi
  exit 0
  ;;
esac

command -v python3 >/dev/null 2>&1 || {
  echo "entropy-gate: python3 required" >&2
  exit 2
}

echo "entropy-gate installer"
echo "  repo:  $ROOT"
echo "  gate:  $GATE_DIR"
echo

# --- 1. config + templates ------------------------------------------------- #
# First, and before the hook wiring can abort: the config is useful even if the
# wiring has to be left alone, and the abort path below says so.
# Deliberately not `|| true`: if init fails, the install did not happen and
# saying "done" would be a lie.
python3 "$GATE_DIR/entropy_gate.py" init

# --- 2. hook wiring -------------------------------------------------------- #
HOOKS="$GATE_DIR/.githooks"
mkdir -p "$HOOKS"
chmod +x "$HOOKS/pre-commit" 2>/dev/null || true

EXISTING="$(git -C "$ROOT" config --get core.hooksPath || true)"
# git stores whatever we wrote, which may be relative to the repo root; compare
# resolved paths so re-running the installer is not mistaken for a conflict.
case "$EXISTING" in
  "")       EXISTING_ABS="" ;;
  /*)       EXISTING_ABS="$EXISTING" ;;
  *)        EXISTING_ABS="$ROOT/$EXISTING" ;;
esac

# Prefer a repo-relative path so moving or re-cloning the repo does not break
# the hook wiring.
REL_HOOKS="${HOOKS#"$ROOT"/}"
if [ -n "$EXISTING" ] && [ "$EXISTING_ABS" != "$HOOKS" ]; then
  echo "! core.hooksPath is already set to: $EXISTING"
  echo "  Overwriting it would disable existing hooks (husky, pre-commit, ...)."
  echo "  To use entropy-gate alongside them, add a pre-commit entry that runs:"
  echo "      python3 $GATE_DIR/entropy_gate.py hook"
  echo "  Aborting without changing core.hooksPath."
  echo
  echo "! not wired up: entropy-gate will NOT run on commit until core.hooksPath"
  echo "  points at $REL_HOOKS, or you add the pre-commit entry above."
  echo "  Config and templates were still written; re-run this script after you"
  echo "  have cleared core.hooksPath."
  exit 0
else
  git -C "$ROOT" config core.hooksPath "$REL_HOOKS"
  echo "✔ git config core.hooksPath = $REL_HOOKS"
  case "$HOOKS" in
    "$ROOT"/*) : ;;
    *)
      # The hooks dir lives outside this repo, so the hook cannot find the
      # engine by looking under $ROOT -- it falls back to the copy sitting next
      # to itself, which is this checkout. Say so, because a shared hooksPath
      # is easy to set up wrong.
      echo "  note: the hook lives outside the repo; it will run the engine from"
      echo "        $GATE_DIR/entropy_gate.py"
      ;;
  esac
fi

# --- 3. optional tooling --------------------------------------------------- #
if [ "${1:-}" = "--tools" ]; then
  echo
  echo "installing tooling..."
  if command -v npm >/dev/null 2>&1; then
    # Only the checks that ship ENABLED. dependency-cruiser and jscpd are
    # opt-in (they need your real package layout) -- installing them while
    # their check is off makes knip report them as unused devDependencies.
    npm install --save-dev aislop knip \
      eslint @eslint/js typescript-eslint eslint-plugin-sonarjs \
      typescript 2>&1 | tail -3 || true
    echo "  opt-in, install only if you enable them:"
    echo "    npm i -D dependency-cruiser jscpd"
  else
    echo "  ! npm not found; skipping JS tooling"
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -m pip install --user ruff radon vulture import-linter 2>&1 | tail -3 || true
  fi
  if command -v go >/dev/null 2>&1; then
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>&1 | tail -3 || true
  fi
fi

echo
echo "done. Next steps:"
echo "  1. Review .entropy-gate.toml"
echo "  2. python3 $GATE_DIR/entropy_gate.py doctor"
echo "  3. python3 $GATE_DIR/entropy_gate.py baseline --write   # lock in today's debt"
echo "  4. git add -A && git commit   # the hook runs now"
