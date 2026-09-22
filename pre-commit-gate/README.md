# entropy-gate

A pre-commit gate that stops code entropy — and specifically AI-generated slop —
from entering your repository.

It detects the language of every staged file, runs the right checks for that
language, and **blocks the commit when a language has no checks configured**.
Uncovered languages are a loud failure, never a silent pass.

---

## Why three layers

These layers catch fundamentally different things. Running only one leaves a
large, measurable hole. Measured on the author's fixture with deliberate slop in
Go, Python, and TypeScript (`dupl`/`unused` via golangci-lint, narrative
comments and TODO stubs via aislop):

| Signal | `aislop` alone | structural linters alone |
|---|---|---|
| Go duplication (`Handle`/`Handle2` clone) | ✗ missed | ✓ caught (`dupl`) |
| Go dead code (`unusedHelper`) | ✗ missed | ✓ caught (`unused`) |
| Go complexity / function length | ✗ (defaults far looser) | ✓ with your thresholds |
| Narrative comments ("This function processes…") | ✓ caught | ✗ impossible |
| TODO/FIXME stubs | ✓ caught | ✗ impossible |
| `console.log` leftovers | ✓ caught | ✗ impossible |
| Unused imports (Python) | ✓ caught | ✓ caught |

| Layer | What it is | What it catches |
|---|---|---|
| **0. Router** | extension → language | *guarantees coverage* — an unconfigured language blocks the commit |
| **1. `aislop`** | cross-language AI-slop scanner, 0–100 score | narrative comments, TODO stubs, debug leftovers, dead patterns |
| **2. Structural** | per-language linters | the four entropy levers: repetition, massive functions, dead weight, hidden coupling |

Reference for layer 1: [github.com/scanaislop/aislop](https://github.com/scanaislop/aislop)

---

## Install

```bash
# into your repo (any directory name works; entropy-gate/ is conventional)
cp -r entropy-gate /path/to/your/repo/
cd /path/to/your/repo
./entropy-gate/install.sh            # wires the hook, writes config + templates
./entropy-gate/install.sh --tools    # also installs aislop + the language linters
```

`install.sh` sets `git config core.hooksPath entropy-gate/.githooks`, so the
hook is version controlled and applies to **agent commits too**, not just yours.
That matters: a hook in `.git/hooks/` is invisible to git and easy to lose.
If `core.hooksPath` is already set (husky, pre-commit, …), the installer leaves
it alone and tells you how to chain entropy-gate instead.

Verify:

```bash
python3 entropy-gate/entropy_gate.py doctor
```

---

## What the repo tracks, and what each machine installs

A ratchet that exists on one machine is a habit, not a ratchet. The gate is
reproducible from the repository; only the linters are local.

**Tracked — the gate itself.**

| Path | What it is |
|---|---|
| `pre-commit-gate/entropy_gate.py` | the engine (stdlib only; Python 3.11+ for `tomllib`) |
| `pre-commit-gate/.githooks/pre-commit` | the hook shim git runs |
| `pre-commit-gate/templates/` | the config templates `init` writes (`.golangci.yml`, `eslint.config.mjs`, `tsconfig.json`, `.importlinter`, `knip.json`, `.dependency-cruiser.cjs`) |
| `pre-commit-gate/install.sh` | the installer: config + templates + `core.hooksPath` |
| `pre-commit-gate/README.md`, `pre-commit-gate/LEARNINGS.md` | the docs |
| `.entropy-gate.toml` | this repo's live config (languages, thresholds) |
| `.entropy-baseline.json` | the committed ceiling for the repo-scoped metrics |

`.entropy-baseline.json` has a consumer in the tree: **`scripts/verify-full.sh`
step 14** measures the repo with this engine and fails when any metric is above
the committed ceiling. Without that step the file is a number with no reader —
editable upward, with nothing in the tree to object.

**Not tracked — machine-local, and rebuildable.** All of these are in
`.gitignore`: `pre-commit-gate/.repomap-cache.v1/` (the repomap cache),
`pre-commit-gate/.scratch/`, `pre-commit-gate/__pycache__/`, `.scratch/`,
`.gocache/`. None of them is needed to run the gate.

`pre-commit-gate/.entropy-gate.toml` is untracked too: it is the copy `init`
seeds a missing repo-root config from, and it differs from the engine's
embedded `DEFAULT_CONFIG` only in comments. The live config is the tracked
`.entropy-gate.toml` at the repo root.

**Each machine installs for itself.** The engine is stdlib-only; every check
tool is an external dependency. Versions used by the author's machine — a
linter upgrade can move a parsed count, so re-capture the baseline after one:

| Tool | Serves | Here | Install |
|---|---|---|---|
| `python3` ≥ 3.11 | the engine (`tomllib`) | 3.14.7 | your OS |
| `ruff` | `python/ruff`, `python/ruff-format` | 0.15.1 | `pip install ruff` |
| `radon` | `python/radon` (file-scoped) | not installed | `pip install radon` |
| `golangci-lint` | `go/golangci-lint` | v1.64.8 | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| `eslint` | `javascript/eslint` | 10.8.1 | `npm i -D eslint typescript-eslint eslint-plugin-sonarjs` |
| `tsc`, `knip` | `javascript/tsc`, `javascript/knip` | not installed | `npm i -D typescript knip` |
| `aislop` | layer 1 (this repo requires it) | not installed | `npm i -D aislop` |

and one git setting, which lives in `.git/config` and never in the tree:

```bash
git config core.hooksPath pre-commit-gate/.githooks
```

`./pre-commit-gate/install.sh` sets it, and never overwrites an existing
config. Until it is set the hook does not fire — but `scripts/verify-full.sh`
step 14 still enforces the ceiling, which is the point of tracking the engine.
Run `doctor` first on a new machine to see what is actually installed.

**A missing linter is not a pass.** The hook reports a missing tool as a note
and skips the check; if *every* check for a language was skipped that becomes a
tooling error (exit `2`). But when one check for a language did run, a missing
sibling simply yields no metric — so on a machine without `ruff`, `python/ruff`
is never measured and the commit is compared against a ceiling nobody read.
Step 14 closes that: a baseline metric that was not measured is a named
failure, not a green line.

---

## Usage

```bash
entropy-gate hook                 # what the pre-commit hook runs (staged files)
entropy-gate hook --allow-divergence   # permit unstaged edits in staged files
entropy-gate baseline --write     # lock in today's debt, then enforce "no worse"
entropy-gate doctor               # which tools are installed for which language
entropy-gate init                 # write config + tool templates (never overwrites)
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | entropy violations — fix the code |
| `2` | the gate could not do its job: unconfigured language, a check that could not run, bad config, worktree/index divergence, or a staged file missing from the worktree |

`2` is never a pass. If the gate cannot evaluate the commit, it does not let
the commit through — see [Fail-closed](#fail-closed) below. When a run finds
real violations *and* cannot evaluate something, the exit code is `2`: "could
not do its job" outranks "found problems", because the reported findings are
only the ones that survived a partial run.

```bash
entropy-gate selftest      # built-in logic checks, no linters needed
```

---

## The ratchet — the part that makes this stick

Do not try to fix everything at once. That is how these efforts die. Two
independent ratchets do the work:

**1. Implicit.** Structural file-scoped checks only ever see *staged* files.
Anything already committed is grandfathered for free.

**2. Explicit.** Repo-scoped checks (knip, golangci-lint, tsc, ruff,
ruff-format) can't be scoped to a diff, so their finding counts are stored in
`.entropy-baseline.json`:

```bash
python3 entropy-gate/entropy_gate.py baseline --write
```

A repo-scoped check then fails only when its count **exceeds** the baseline,
so existing debt is grandfathered and new debt blocks. When you clean
something up, re-capture — the gate reports each check that improved so you
know when the baseline is worth refreshing.

A capture only measures the languages staged in that commit, so `baseline
--write` **merges** into the existing file instead of replacing it. Replacing
would erase every other language's recorded debt, which then re-blocks as "no
baseline recorded".

Two honest limits of this ratchet:

- It compares **counts**, not identities. Swapping three old findings for
  three new ones will not be caught. If you need identity-level precision,
  use `--new-from-rev` (Go) or aislop's fingerprint baseline.
- Counts come from parsing tool output, so a linter that changes its output
  format can shift the number. Re-capture after upgrading a linter.

`golangci-lint` additionally gets `--new-from-rev HEAD`, so on Go it is a true
"new issues only" gate with no baseline file needed.

`baseline --write` refuses to record a baseline that measured nothing, and
refuses while any check cannot run — a count it could not measure would be
locked in as zero, and the ratchet would treat debt it never saw as paid off.
`hook --write-baseline` is the same capture and enforces the same two
refusals. Use `--force` to override either.

A `.entropy-baseline.json` that is corrupt or hand-edited is never trusted:
entries that are not integers are dropped and the file is reported as ignored,
so the affected checks say "no baseline recorded" instead of comparing against
nonsense.

---

## Fail-closed

The gate refuses to pass when it cannot actually evaluate the commit:

- **Worktree differs from index.** Every check reads the worktree, so if you
  stage a clean version and then edit the file, passing would mean the commit
  was never checked. The gate blocks and tells you to re-stage. Use
  `--allow-divergence` only when you have deliberately committed a partial
  hunk and verified it yourself.
- **A staged file is gone from the worktree.** The index says "add/modify" but
  there is nothing to read, so the content being committed cannot be checked.
  Re-stage or drop it from the index.
- **A linter crashed.** For a check without a `count`, a non-zero exit is read
  as "findings found" (ruff exits 1 that way), so only exit codes above 1 are
  treated as crashes. A check that *does* declare a `count` is judged strictly:
  a non-zero exit that matched nothing is a crash or a changed output format,
  and either way it must not read as clean. Exit `1` always means "findings
  found"; a negative code (the process was killed, e.g. by the OOM killer) or
  any code above 1 is a crash, even when stdout matched the count — a dying tool
  prints partial output, and partial output below the baseline would otherwise
  read as an improvement. A tool that legitimately reports findings with an exit
  above 1 (tsc uses 2) declares `findings_exit = [1, 2]` on the check. A crash
  is fatal: it is a tooling error whether or not another check for that language
  ran, and it makes `baseline --write` refuse. Counts are read from a tool's
  stdout only, so a warning on stderr is never counted as a finding.
- **No check ran for a staged language.** A missing tool is a note while some
  other check for that language still covers the file. But if a language has
  staged files and *zero* checks ran — all unavailable, all skipped by
  `when_extensions`, or all disabled — that language was never evaluated: exit
  2. Enable a check, or set `[languages.x] enabled = false` to skip the
  language explicitly. Mark a single check `required = true` to make its
  absence fatal on its own.
- **A check's config is absent** (`requires_config`): `tsc` without a
  `tsconfig.json` exits 0 and prints nothing, which would otherwise be recorded
  as "improved to 0". The gate skips the check instead of scoring it.
- **The aislop layer could not run** — a crash, non-JSON output, or an
  unexpected JSON shape (a `diagnostics` list that isn't one, a non-numeric
  `score`) while `enabled = "require"`.
- **The config is invalid** — one line, no traceback. Regexes in `error_regex`
  and `count` are compiled at load time so a typo is a config error, and a
  check table without a `command` is rejected rather than silently dropped.
- **An unconfigured language** — see [Adding a language](#adding-a-language).

## Configuration — `.entropy-gate.toml`

```toml
[settings]
fail_on_unknown_language = true      # unconfigured language => block
max_staged_lines = 1200              # 0 disables; guards against giant AI diffs
parallel = true

[aislop]
enabled = "require"                  # require | optional | off
fail_below = 0                       # block when the score drops below this

[thresholds]
cyclomatic = 10                      # per function
cognitive = 15
function_lines = 30
file_lines = 300
nesting = 3
params = 4
duplication_percent = 3.0

[languages.python]
enabled = true
# disable = ["vulture"]

[languages.go]
enabled = true

[languages.javascript]
enabled = true
# disable = ["knip"]
```

Two settings decide what the gate never looks at. `ignore_extensions` skips by
suffix, and `ignore_paths` defaults to `migrations/`, `generated/`, `dist/`,
`build/`, `vendor/`, `node_modules/`, `.venv/`, `__pycache__/` and friends —
staged files under those paths are skipped without a word, so widen or narrow
the list deliberately. `bin_dirs` adds lookup directories for check binaries
(default `node_modules/.bin`); `PATH` is always searched first, so a committed
executable cannot shadow a system binary at commit time.

The Python checks pass ruff their own `--select` and `--ignore`, so a lenient
`[tool.ruff] ignore` in `pyproject.toml` does not weaken the gate — that is
deliberate, since a rule set an AI can edit is not a gate. To silence a finding
you disagree with, use `disable = [...]` here or a `# noqa` with a reason.

### What runs, per language

| Language | Check | Scope | Tool | Catches |
|---|---|---|---|---|
| Python | `ruff` | repo | ruff | complexity (`C901`), too many branches/args/statements, commented-out code (`ERA`) |
| Python | `ruff-format` | repo | ruff | formatting drift |
| Python | `radon` | file | radon | complexity report, rank C and worse |
| Python | `vulture` *(off)* | repo | vulture | dead code, unreachable functions |
| Go | `gofmt` | file | gofmt | formatting drift |
| Go | `golangci-lint` | repo | golangci-lint | `dupl`, `gocyclo`, `gocognit`, `funlen`, `nestif`, `goconst`, `unused` |
| JS/TS | `eslint` | file | eslint + sonarjs | complexity, max-depth, max-lines-per-function, max-params, cognitive complexity |
| JS/TS | `tsc` | repo | tsc `--noEmit` | type errors under `strict` |
| JS/TS | `knip` | repo | knip | unused exports, files, dependencies — *the AI-scaffolding detector* |
| JS/TS | `dependency-cruiser` *(off)* | repo | depcruise | circular imports, layer violations |
| JS/TS | `jscpd` *(off)* | repo | jscpd | cross-file duplication % |

`scope: file` = runs only on staged files (implicit ratchet). Such a check
must take a `{files}` argument — that is what narrows it to the staged set, and
a check that cannot be narrowed would silently run repo-wide and block clean
commits on old debt, so the gate rejects it at load time.
`scope: repo` = runs once over the project, compared against the baseline.

Files with no extension, and the extensions listed in
`settings.ignore_extensions`, are never classified — there is no language to
route them to. Everything else with an extension is either checked or blocks the
commit as unconfigured.

Two of these tools exit 0 while reporting problems — `gofmt -l` lists
unformatted files and `radon cc` prints rank-C functions, both with a zero exit
code. The gate therefore judges a file-scoped check **by its `count`** when one
is declared, not by the exit code, and the shipped `gofmt` and `radon` checks
declare one. Same reasoning for eslint: its template rules are warnings, so the
check runs with `--max-warnings=0`. If you add a check whose tool reports
findings on stdout and exits 0, give it a `count` or it will never block.

---

## Adding a language

This is the extension point the router is built around. Until you add it,
committing files of that language **fails with exit code 2** and prints a
ready-to-paste config block:

```
✖ No entropy checks configured for language(s): .rs
    src/main.rs

  Add a language block to .entropy-gate.toml:

    [languages.rust]
    enabled = true
    extensions = [".rs"]
    checks = [
      { name = "linter", scope = "repo", command = ["your-linter", "--flag"], count = "lines" },
    ]
```

Then it's just a matter of filling in real commands:

```toml
[languages.rust]
enabled = true
extensions = [".rs"]
checks = [
  { name = "clippy", scope = "repo", command = ["cargo", "clippy", "--", "-W", "pedantic"], count = "lines" },
  # cargo fmt cannot take a file list, so this one is repo-scoped.
  { name = "fmt",    scope = "repo", command = ["cargo", "fmt", "--", "--check"] },
]
```

Check fields:

| Field | Meaning |
|---|---|
| `name` | label used in output and as the baseline key |
| `scope` | `file` (staged files) or `repo` (whole project) |
| `command` | argv list; `{files}` expands to staged files (file scope only) |
| `count` | `"lines"` or `"regex:<pattern>"`. On a **repo** check it is the baseline metric; on a **file** check it is the verdict (nonzero = violation), which is how you gate a tool that exits 0 while reporting findings |
| `error_regex` | if the output matches this, it's a *tooling* problem, not entropy — skipped, not counted. Findings the check printed for earlier files are discarded with it, so the run reports the skip rather than a partial count |
| `requires_config` | files that must exist before the check is meaningful (e.g. `tsconfig.json`); otherwise it is skipped rather than scored |
| `findings_exit` | exit codes that mean "findings found" for this tool, so a higher exit is not mistaken for a crash (tsc ships `[1, 2]`) |
| `workdir` | run the check here instead of the repo root; a literal path that does not exist is a config error |
| `enabled_by_default` | ship the check off and require `enable = [...]` to switch it on |
| `required` | `true` makes a missing binary a hard tooling error on its own, instead of a note |
| `workdir` | run in a subdirectory; `{go_dir}` resolves to the shallowest `go.mod` |
| `when_extensions` | only run when a staged file has one of these extensions |

Add checks to a built-in language with `extra = [ … ]` (the same table format).
`checks = [ … ]` is accepted as a synonym, and is what you use for a language
you define yourself:

```toml
[languages.python]
enabled = true
# A check table must fit on one line -- TOML inline tables cannot span lines.
# Only the array around them may.
extra = [
  { name = "import-linter", scope = "repo", count = "lines", command = ["lint-imports"], error_regex = "^ERROR" },
]
```

Placeholders available in `command` / `workdir`: every key under
`[thresholds]` (`{cyclomatic}`, `{params}`, …) plus `{files}`, `{go_dir}`.

---

## Notes specific to AI-generated bloat

- **`knip` and `vulture`** catch the unused exports and defensive scaffolding
  LLMs reliably leave behind. This is the highest-value check for agent code.
- **`dupl` / `jscpd`** catch the near-identical repeated blocks generative code
  produces constantly. In testing this was the single biggest win, and the one
  most likely to be missed by a generic scanner.
- **`max_staged_lines`** flags oversized diffs, which is where slop hides.
- The `--new-from-rev HEAD` flag on `golangci-lint` means Go debt can't grow
  even if the baseline file is stale.

### The caveat that matters

Linting will not fix architectural entropy. If functions are massive because
responsibilities are muddled, the fix is layering — enforce dependency
direction with `dependency-cruiser` (JS/TS) or `import-linter` (Python) so
modules can't reach sideways. Both ship as templates, both are **off by
default** because they need your real package layout:

```toml
[languages.javascript]
enable = ["dependency-cruiser", "jscpd"]   # opt IN (these ship off)

[languages.python]
enable = ["vulture"]
disable = ["radon"]                        # opt OUT (these ship on)
```

`disable` switches off any check by name, including one you added yourself;
`enable` is the only way to switch on a check that ships **off**. Naming a
check that does not exist is a config error rather than a silent no-op.

## Templates

`entropy-gate init` writes only the templates for languages your repo
actually contains — a Go+Python repo does not get `eslint.config.mjs`.

Two of the generated templates encode opinions you are expected to edit before
the gate is useful on a real project:

- `tsconfig.json` includes `**/*.ts` etc. by default, so it covers TypeScript
  wherever it lives. If your build generates `.ts` files into an output
  directory, add it to `exclude` or `tsc` will check generated code.
- `.golangci.yml` and `.dependency-cruiser.cjs` are tuned for a repo that
  already has some structure; the templates say which lever switches each one
  on (`enable = [...]` for the checks that ship disabled).

`{cyclomatic}`-style placeholders in `.golangci.yml` and `eslint.config.mjs`
are substituted from `[thresholds]` at init time, so the config really is the
single source of truth. Edit `[thresholds]`, re-run `init`, don't hand-edit
the generated files.

The gate ignores its own directory and passes a matching `--exclude` to
aislop, so it does not grade itself. The path is derived from where the engine
actually lives, so the directory name does not matter — `entropy-gate/` is
just the conventional one.

---

## Bypass

```bash
ENTROPY_GATE_SKIP=1 git commit ...   # prints a warning, does not run
git commit --no-verify               # git's own bypass
```

Both are discouraged, and the failure output is designed so that fixing is
faster than skipping. If a finding is genuinely wrong, tune
`.entropy-gate.toml` or re-capture the baseline rather than bypassing.

Environment variables: `ENTROPY_GATE_SKIP`, `ENTROPY_GATE_SCRIPT`,
`ENTROPY_GATE_PYTHON`, `ENTROPY_GATE_TRACEBACK` (re-raise instead of turning a
crash into a one-line exit 2), `NO_COLOR`.

An unexpected crash inside the gate is reported as one line and exits `2`, never
as a traceback with exit `1` — `1` is reserved for "this commit contains
entropy", and a bug in the gate must not be mistaken for a verdict on your code.

---

## Suppressing findings

Use each tool's own mechanism so suppressions stay local and reviewable:

- ruff: `# noqa: C901`
- eslint: `// eslint-disable-next-line complexity`
- golangci-lint: `//nolint:dupl` (or the `issues` section of `.golangci.yml`)
- aislop: `// aislop-ignore-next-line ai-slop/narrative-comment -- reason`

---

## Tooling errors vs. entropy

A tool that cannot run (missing binary, no `package.json`, no
`eslint.config.mjs`, bad tsconfig) is reported as a **note**, never counted as
a finding. Otherwise "Unable to find package.json" would be scored as slop and
the baseline would drift on environment noise.

Each check declares an `error_regex` that distinguishes "the tool ran and
found things" from "the tool could not run". If you add a check whose tool has
an unusual usage-error format, set `error_regex` for it. Use `doctor` to see
what is actually installed.
