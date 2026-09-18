# Task 13 — remediation report (advisory-driven dependency bump)

**Worktree:** `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
**Branch:** `production-readiness`
**Base HEAD at dispatch:** `fc9241d4` (`fix(release): security-check uses repo Go cache convention`)
**Commit:** `ac11de2c` — `fix(deps): advisory-driven bump x/text v0.39.0 + toolchain go1.26.6 (govulncheck)` (exact paths: `go.mod`, `go.sum`, `README.md`)
**Scope:** `go.mod`, `go.sum`, one `README.md` verification-table row. `scripts/legacy` untouched. No other dependency touched. No push / merge / delegation.

---

## 1. Why this task exists

The Task 13A gate (`scripts/security-check.sh`, strict release mode) was wired and
hermetically tested, but the first two *live* runs could not establish a verdict:
run 1 failed on a missing repo cache convention (script env fixed in `fc9241d4`),
run 2 returned **GATE_EXIT=3 — real findings**. This task remediates the findings
that run produced, then re-runs the same real gate.

---

## 2. Before — real gate verdict (reproduced at base HEAD, verbatim)

Command (exactly as briefed, `GOPATH`/`GOMODCACHE` as inherited from the harness;
see §5 for why the cache source matters):

```
PATH="$PWD/.scratch/gomod/bin:$PATH" bash scripts/security-check.sh
```

Raw log: `.scratch/sdd/task-13-logs/before-gate.log` (113 lines).

Verbatim excerpt — the whole Symbol Results section, the trailing summary and the
gate's own exit line:

```
security-check: running /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness/.scratch/gomod/bin/govulncheck ./... from /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness
=== Symbol Results ===

Vulnerability #1: GO-2026-6218
    Avoid quadratic complexity in resolvePath in net/url
  More info: https://pkg.go.dev/vuln/GO-2026-6218
  Standard library
    Found in: net/url@go1.26.2
    Fixed in: net/url@go1.26.6
    Example traces found:
      #1: internal/validation/schema.go:133:29: validation.ValidateDefinition calls jsonschema.Compiler.Compile, which eventually calls url.URL.Parse
      #2: internal/validation/schema.go:133:29: validation.ValidateDefinition calls jsonschema.Compiler.Compile, which eventually calls url.URL.ResolveReference

Vulnerability #2: GO-2026-6090
    Limit handshake messages we are willing to accept post-handshake in
    crypto/tls
  More info: https://pkg.go.dev/vuln/GO-2026-6090
  Standard library
    Found in: crypto/tls@go1.26.2
    Fixed in: crypto/tls@go1.26.6
    Example traces found:
      #1: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do, which eventually calls tls.Conn.HandshakeContext
      #2: internal/snapshot/hashing.go:179:10: snapshot.ContentHash calls io.Copy, which eventually calls tls.Conn.Read
      #3: internal/backtest/backtest.go:144:13: backtest.Run calls fmt.Fprintf, which calls tls.Conn.Write
      #4: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do, which eventually calls tls.Dialer.DialContext

Vulnerability #3: GO-2026-5972
    Enforce maximum recursion depth in encoding/asn1
  More info: https://pkg.go.dev/vuln/GO-2026-5972
  Standard library
    Found in: encoding/asn1@go1.26.2
    Fixed in: encoding/asn1@go1.26.6
    Example traces found:
      #1: internal/classweights/classweights.go:29:9: classweights.Load calls sync.Once.Do, which eventually calls asn1.Unmarshal

Vulnerability #4: GO-2026-5970
    Infinite loop on invalid input in golang.org/x/text
  More info: https://pkg.go.dev/vuln/GO-2026-5970
  Module: golang.org/x/text
    Found in: golang.org/x/text@v0.14.0
    Fixed in: golang.org/x/text@v0.39.0
    Example traces found:
      #1: internal/protocolgraph/protocolgraph.go:267:26: protocolgraph.WhoCan calls cases.Caser.String, which eventually calls norm.Form.Properties

Vulnerability #5: GO-2026-5856
    Invoking Encrypted Client Hello privacy leak in crypto/tls
  More info: https://pkg.go.dev/vuln/GO-2026-5856
  Standard library
    Found in: crypto/tls@go1.26.2
    Fixed in: crypto/tls@go1.26.5
    Example traces found:
      #1: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do, which eventually calls tls.Conn.HandshakeContext
      #2: internal/snapshot/hashing.go:179:10: snapshot.ContentHash calls io.Copy, which eventually calls tls.Conn.Read
      #3: internal/backtest/backtest.go:144:13: backtest.Run calls fmt.Fprintf, which calls tls.Conn.Write
      #4: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do, which eventually calls tls.Dialer.DialContext

Vulnerability #6: GO-2026-5039
    Arbitrary inputs are included in errors without any escaping in
    net/textproto
  More info: https://pkg.go.dev/vuln/GO-2026-5039
  Standard library
    Found in: net/textproto@go1.26.2
    Fixed in: net/textproto@go1.26.4
    Example traces found:
      #1: internal/harness/rederive.go:661:20: harness.ReadExecStdout calls io.ReadAll, which eventually calls textproto.Reader.ReadMIMEHeader

Vulnerability #7: GO-2026-5037
    Inefficient candidate hostname parsing in crypto/x509
  More info: https://pkg.go.dev/vuln/GO-2026-5037
  Standard library
    Found in: crypto/x509@go1.26.2
    Fixed in: crypto/x509@go1.26.4
    Example traces found:
      #1: internal/snapshot/hashing.go:179:10: snapshot.ContentHash calls io.Copy, which eventually calls x509.Certificate.Verify
      #2: internal/snapshot/hashing.go:179:10: snapshot.ContentHash calls io.Copy, which eventually calls x509.Certificate.VerifyHostname
      #3: internal/snapshot/pin.go:522:15: snapshot.PinSourceSnapshot calls fmt.Fprintln, which eventually calls x509.HostnameError.Error

Vulnerability #8: GO-2026-5026
    Invoking failure to reject ASCII-only Punycode-encoded labels in
    golang.org/x/net/idna
  More info: https://pkg.go.dev/vuln/GO-2026-5026
  Standard library
    Found in: net/http@go1.26.2
    Fixed in: net/http@go1.26.6
    Example traces found:
      #1: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do

Vulnerability #9: GO-2026-4971
    Panic in Dial and LookupPort when handling NUL byte on Windows in net
  More info: https://pkg.go.dev/vuln/GO-2026-4971
  Standard library
    Found in: net@go1.26.2
    Fixed in: net@go1.26.3
    Example traces found:
      #1: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do, which eventually calls net.Dialer.DialContext

Vulnerability #10: GO-2026-4918
    Infinite loop in HTTP/2 transport when given bad SETTINGS_MAX_FRAME_SIZE in
    net/http/internal/http2 in golang.org/x/net
  More info: https://pkg.go.dev/vuln/GO-2026-4918
  Standard library
    Found in: net/http@go1.26.2
    Fixed in: net/http@go1.26.3
    Example traces found:
      #1: internal/envgo/env.go:247:24: envgo.realHTTPDo calls http.Client.Do

Your code is affected by 10 vulnerabilities from 1 module and the Go standard library.
This scan also found 5 vulnerabilities in packages you import and 7
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
Use '-show verbose' for more details.
security-check: INCOMPLETE or findings (scanner failed)
GATE_EXIT=3
```

**Before verdict:** `GATE_EXIT=3` — 10 CALLED vulnerabilities (9 stdlib + 1 module),
plus 5 import-level and 7 require-level uncalled. Scanner:
`govulncheck@v1.8.0`, DB `https://vuln.go.dev`, DB updated `2026-09-16 18:00:43 UTC`.
The gate correctly refused to report PASS.

### 2.1 Advisory-ID correction (honest note)

The dispatch brief (and the ledger line it came from) named the x/text finding
`GO-2026-4970`. The **live scan says `GO-2026-5970`**, and the advisory database
agrees:

| ID | what it actually is | affected | fixed in |
|----|--------------------|----------|----------|
| GO-2026-4970 | *stdlib* `os.Root` symlink + trailing-slash escape (CVE-2026-39822) — **not** x/text | `os` (stdlib) | go1.25.12 / go1.26.x |
| GO-2026-5970 | *"Infinite loop on invalid input in golang.org/x/text"* (CVE-2026-56852, `x/text/unicode/norm`) — the one in this scan | `golang.org/x/text` | v0.39.0 |

Both IDs were checked against `https://vuln.go.dev/ID/<id>.json` on this machine.
The remediation target (`golang.org/x/text` → v0.39.0) is identical either way, so
the work is unaffected; only the transcribed ID in the brief was wrong.

---

## 3. Change made (minimal, advisory-driven)

`go.mod` before → after (`git diff go.mod`):

```diff
@@ -2,11 +2,13 @@ module websec
 
 go 1.26.2
 
+toolchain go1.26.6
+
 require (
 	github.com/pelletier/go-toml/v2 v2.4.3
 	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
 )
 
-require golang.org/x/text v0.14.0
+require golang.org/x/text v0.39.0
 
 require gopkg.in/yaml.v3 v3.0.1
```

`go.sum`: two additive lines only (`golang.org/x/text v0.39.0 h1:` / ` .../go.mod h1:`).

Why this shape:

* **`toolchain go1.26.6`** clears all 9 stdlib findings — every one of them is
  reported against `@go1.26.2` and fixed in `go1.26.3`–`go1.26.6`, so the
  highest fixed version in the set (1.26.6) is the minimum toolchain that clears
  the whole set. The `go 1.26.2` *minimum* is kept, as instructed, and stays
  honest: `1.26.2` is the language/API minimum, the toolchain line is the
  security floor.
* **`golang.org/x/text v0.39.0`** is exactly the fixed version named by the
  advisory; nothing was bumped to "latest".
* **No `go` directive change was needed.** x/text v0.39.0's own `go.mod` declares
  `go 1.25.0`, which is below our existing `go 1.26.2`, so the module requires
  nothing higher. (`v0.14.0` declared `go 1.18`.)
* **No new indirect requirements.** x/text v0.39.0's `x/tools`, `x/mod`, `x/sync`
  requirements are all `// tagx:ignore` (build-tag-gated generator deps), so the
  build graph gained nothing; `go.mod` still lists only the same four modules.
* `go get` under the repo caches (`GOCACHE=.scratch/gocache`,
  `GOPATH=.scratch/gomod`, `GOMODCACHE=.scratch/gomod/pkg/mod`) with
  `GOTOOLCHAIN=auto` downloaded and selected go1.26.6 on the first command
  (`go: downloading go1.26.6 (linux/amd64)`).

Commands run (raw logs: `.scratch/sdd/task-13-logs/go-get.log`,
`.scratch/sdd/task-13-logs/env.log`):

```
go version                 # -> go version go1.26.6 linux/amd64
go get golang.org/x/text@v0.39.0
                           # -> go: upgraded golang.org/x/text v0.14.0 => v0.39.0  (exit 0)
go list -m golang.org/x/text   # -> golang.org/x/text v0.39.0
```

---

## 4. After — real gate verdict (verbatim)

Raw log: `.scratch/sdd/task-13-logs/after-gate-repocache.log` (whole file, 3 lines):

```
security-check: running /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness/.scratch/gomod/bin/govulncheck ./... from /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness
No vulnerabilities found.
security-check: PASS
GATE_EXIT=0
```

**After verdict: `GATE_EXIT=0` — PASS, "No vulnerabilities found."** All 10 CALLED
findings cleared (9 stdlib by the toolchain, GO-2026-5970 by the x/text bump).
This is the same scanner (`govulncheck@v1.8.0`), same DB, same script, and the
scan was run **after** the remediation at the same HEAD lineage.

---

## 5. Environment artifact found while re-running the gate (recorded honestly)

The *literal* briefed command —

```
PATH="$PWD/.scratch/gomod/bin:$PATH" bash scripts/security-check.sh
```

— first returned `GATE_EXIT=1` **after** the bump, with a mechanical failure, not
findings (raw log `.scratch/sdd/task-13-logs/after-gate.log`):

```
govulncheck: loading packages:
There are errors with the provided package patterns:

/home/xand/go/pkg/mod/github.com/santhosh-tekuri/jsonschema/v6@v6.0.3/kind/kind.go:8:2: open /home/xand/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.39.0.lock: read-only file system
/home/xand/go/pkg/mod/github.com/santhosh-tekuri/jsonschema/v6@v6.0.3/kind/kind.go:8:2: could not import golang.org/x/text/message (invalid package name: "")
... (13 more lines, all the same two shapes)
security-check: INCOMPLETE or findings (scanner failed)
GATE_EXIT=1
```

Cause: the harness exports `GOPATH=/home/xand/go`. `scripts/security-check.sh`
resolves its caches as `GOPATH="${GOPATH:-$root/.scratch/gomod}"` and
`GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"`, so an inherited `GOPATH` wins over
the repo convention, and the scan then resolves modules from the read-only
`$HOME/go/pkg/mod`. That worked at base HEAD only because `x/text v0.14.0` was
already in the HOME cache; `v0.39.0` is not, so the scanner tried to write a
download lock there and was refused. This is the **same class of defect** as the
one fixed in `fc9241d4` (the gate not pinning its own caches), surfacing from the
other direction: the `${VAR:-default}` fallbacks do not override an inherited
`GOPATH`.

The verdict in §4 was therefore taken with the repo convention made explicit —
exactly the cache paths the script's own defaults intend, and the same
`.scratch/gomod/pkg/mod` cache that Task 13A/`fc9241d4`, `verify-full.sh` and
`release.sh` use:

```
PATH="$PWD/.scratch/gomod/bin:$PATH" GOCACHE="$PWD/.scratch/gocache" \
  GOPATH="$PWD/.scratch/gomod" GOMODCACHE="$PWD/.scratch/gomod/pkg/mod" \
  bash scripts/security-check.sh
```

Both runs are kept verbatim above; neither is presented as the other. Fixing the
script's env handling (e.g. unconditional repo-cache export, or documenting that
`GOPATH` must not be inherited) is **out of scope** for this task's exact-path
commit (`go.mod`, `go.sum`, `README.md`) and is left as a follow-up — see §8.

---

## 6. Full gates

The dispatch worktree was **not clean** when this task started: `git status` showed
two unrelated, pre-existing uncommitted files from the interrupted Task 7 fix
round 1 (`internal/orchestrator/status.go`, `internal/orchestrator/next_actions_cli_test.go`,
+286/−15, carrying a deliberate mid-flight pin re-write). Those files were left
untouched and are **not** in this commit. Because they change behaviour the test
and golden gates observe, the battery was run twice: once in the worktree as-is,
once in a clean tree containing HEAD plus only this task's change. Both are
reported verbatim; neither is presented as the other.

### 6.1 In the dispatch worktree, as-is (used for the gate verdict)

| gate | command | exit | raw log |
|------|---------|------|---------|
| build | `go build ./...` | **0** | `.scratch/sdd/task-13-logs/build.log` |
| test | `go test ./... -count=1` | **1** | `.scratch/sdd/task-13-logs/test.log` |
| vet | `go vet ./...` | **0** | `.scratch/sdd/task-13-logs/vet.log` |
| golden | `scripts/golden.sh` | **1** | `.scratch/sdd/task-13-logs/golden.log` |
| runbook walkthrough | `scripts/runbook-walkthrough.sh` | **1** | `.scratch/sdd/task-13-logs/runbook.log` |

**Attribution — every failure is the pre-existing Task 7 diff, not this change.**
71 packages ran: 70 `ok`, 1 `FAIL` (`websec/internal/orchestrator`, 2.248s).
Exactly four tests fail, all of them about `next_actions` contract text that
`status.go` is being rewritten to emit in that in-flight change:

```
--- FAIL: TestGoldenVectors (1.99s)            # existing test
    golden_test.go:293: step 3 next_actions: value mismatch
      got:  "webv2 resolve-candidate C-oracle00001 <finding> <other> --verdict <same-or-distinct> --note <note>"
      want: "webv2 resolve-candidate C-oracle00001 <finding> <other> --verdict <same|distinct> --note <note>"
--- FAIL: TestNextActionsConcreteFixtures     # new test from the in-flight file
--- FAIL: TestNextActionsLeadWithTheProofClosingCommand   # new test from the in-flight file
--- FAIL: TestNextActionsProofClosingPinIsNotVacuous      # new test from the in-flight file
FAIL	websec/internal/orchestrator	2.248s
EXIT=1
```

`golden.sh` never reached its replay: it failed in its own cheap gofmt pre-gate
(`golden: gofmt drift: internal/orchestrator/next_actions_cli_test.go`), because
the in-flight working copy of that file is unformatted. Proof that this is the
in-flight copy and not HEAD:

```
$ git show HEAD:internal/orchestrator/next_actions_cli_test.go > head_copy.go && gofmt -l head_copy.go
(no output — HEAD copy is gofmt-clean)
$ gofmt -l internal/orchestrator/next_actions_cli_test.go
internal/orchestrator/next_actions_cli_test.go
```

`runbook-walkthrough.sh` failed exactly one row, and it is the row that runs the
whole suite:

```
[FAIL] §0     selftest-full                  exit=1  exit 1, want 0
walkthrough: 149 passed, 1 failed
WALKTHROUGH RED: 1 command(s) did not match the runbook
EXIT=1
```

### 6.2 In a clean tree — HEAD + only this task's change (attribution run)

Method: `git archive HEAD | tar -x -C .scratch/t13-clean`, then copied the three
changed files in. Verified that the tree differs from HEAD by exactly this task's
change:

```
$ git --git-dir=../../.git --work-tree=. diff --stat HEAD -- go.mod go.sum README.md
README.md | 1 +
go.mod    | 4 +++-
go.sum    | 2 ++
3 files changed, 6 insertions(+), 1 deletion(-)
```

Same commands, same caches, `go version go1.26.6 linux/amd64`, `gofmt -l internal cmd`
empty:

| gate | exit | tail of raw log |
|------|------|-----------------|
| build | **0** | `EXIT=0` (`.scratch/sdd/task-13-logs/clean-build.log`) |
| test | **0** | 71 packages `ok`, **0** `FAIL` lines (`.scratch/sdd/task-13-logs/clean-test.log`) |
| vet | **0** | `EXIT=0` (`.scratch/sdd/task-13-logs/clean-vet.log`) |
| golden | **0** | `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)` (`.scratch/sdd/task-13-logs/clean-golden.log`) |
| runbook walkthrough | **0** | `walkthrough: 150 passed, 0 failed` / `WALKTHROUGH GREEN: every RUNBOOK command matched its documented behavior` (`.scratch/sdd/task-13-logs/clean-runbook.log`) |
| security gate (repeat) | **0** | `No vulnerabilities found.` / `security-check: PASS` (`.scratch/sdd/task-13-logs/clean-gate.log`) |

The security gate was re-run here too, so the PASS in §4 is not an artifact of
the in-flight code either (govulncheck is call-graph based, so the call graph
being scanned matters).

**Conclusion:** HEAD + this task's change is gate-green across all five gates.
The worktree's test/golden/runbook failures are collateral from the unrelated
uncommitted Task 7 work and are not part of this commit.

---

## 7. README (trivial, one line — taken)

Added one row to the `## Verification` table, as Task 13's plan text calls for
(README.md line 132):

```
| dependency scan | `scripts/security-check.sh` | govulncheck: nothing this code calls is a known vulnerability; a missing scanner or findings is INCOMPLETE/failed, never PASS |
```

Placed before the `release` row, matching the table's existing style (gate name,
backticked command, one-line "what it proves"). No other README change.

Note: Task 13's plan text also mentions an optional new step 14 in
`scripts/verify-full.sh`; Task 13A shipped the gate as `scripts/security-check.sh`
invoked from `scripts/release.sh` (line 158) instead, and `verify-full.sh` has no
govulncheck step. Touching it is outside this task's exact-path commit, so it was
left alone — see §8.

---

## 8. Concerns / follow-ups (not fixed here)

1. **`scripts/security-check.sh` inherits a foreign `GOPATH` (§5).** The gate's
   cache defaults are `${VAR:-...}`, so an exported `GOPATH=/home/xand/go` (as in
   this harness) defeats the repo-cache convention and the scan dies on a
   read-only `$HOME` module cache — a mechanical `GATE_EXIT=1`, not findings.
   `scripts/release.sh` has the same `${VAR:-...}` shape and would hit it too.
   This is the same defect class as `fc9241d4`. Fix would be to export the repo
   caches unconditionally (as `golden.sh` and `verify-full.sh` already do) or to
   document that `GOPATH` must not be inherited. **Out of scope for an
   exact-path `go.mod`/`go.sum`/`README.md` commit.**
2. **The task-13 environment is not clean:** `internal/orchestrator/status.go` and
   `internal/orchestrator/next_actions_cli_test.go` are still dirty from the
   interrupted Task 7 fix round 1, and they are what make `go test ./...`,
   `scripts/golden.sh` and `scripts/runbook-walkthrough.sh` red in the worktree.
   Whoever finishes Task 7 must land them; the 🔴 rows in §6.1 will go green (or
   the pins will, if those are deliberate re-pins).
3. **`go.sum` keeps the stale `golang.org/x/text v0.14.0` lines.** Deliberate: no
   `go mod tidy` was run (it can rewrite unrelated requirements), and stale
   `go.sum` lines are harmless. Prune only as part of a reviewed tidy.
4. **The brief's advisory ID for the x/text finding was wrong** (`GO-2026-4970` is
   a stdlib `os.Root` issue); the real one is `GO-2026-5970` (§2.1). Worth
   correcting in the ledger so the record names the advisory that was actually
   closed.
5. **Uncalled findings remain.** The scan reports 5 import-level and 7
   require-level uncalled vulnerabilities; `govulncheck` exits 0 for those and the
   gate is PASS. That is the intended semantics (only CALLED findings fail), but
   it means "PASS" here means "nothing this code calls is known-vulnerable", not
   "the dependency graph is clean".
6. **Toolchain floor.** `go 1.26.2` remains the language minimum while the
   security floor is `toolchain go1.26.6`. A build that sets `GOTOOLCHAIN=local`
   on a machine with go1.26.2 would silently fall back below the security floor
   and the gate would fail again. Acceptable (fail-closed), but it is a real
   coupling worth knowing.

---

## 9. Raw evidence index (all under `.scratch/sdd/task-13-logs/`)

| file | what it is |
|------|-----------|
| `before-gate.log` | pre-remediation real gate run — `GATE_EXIT=3`, 10 CALLED |
| `go-get.log` | toolchain download + `go get x/text@v0.39.0` |
| `after-gate.log` | post-bump gate with inherited `GOPATH` — mechanical `GATE_EXIT=1` (§5) |
| `after-gate-repocache.log` | post-bump gate with repo caches — `GATE_EXIT=0`, PASS (§4) |
| `clean-gate.log` | same gate in the clean attribution tree — PASS |
| `env.log` | go version / go env / module version in the gate env |
| `build.log`, `test.log`, `vet.log`, `golden.log`, `runbook.log` | worktree battery (§6.1) |
| `clean-env.log`, `clean-build.log`, `clean-test.log`, `clean-vet.log`, `clean-golden.log`, `clean-runbook.log` | clean-tree battery (§6.2) |
| `run-gates.sh`, `run-gates-clean.sh` | the two runners (scratch, not committed) |
| `unformatted-check/head_next_actions_cli_test.go` | HEAD copy used for the gofmt attribution |

The 562 MB clean attribution tree (`.scratch/t13-clean/`) was deleted after the run
to leave the worktree tidy; it is reconstructible in two commands, documented in
§6.2, and `.scratch/sdd/task-13-logs/run-gates-clean.sh` re-runs the whole battery
against it. All logs above are kept.

---

## 10. Final state

* HEAD = `ac11de2c`, working tree clean **except** the two pre-existing
  uncommitted Task 7 files (`internal/orchestrator/status.go`,
  `internal/orchestrator/next_actions_cli_test.go`) — untouched by this task.
* `scripts/legacy` never opened. No other dependency bumped. Nothing pushed,
  merged or delegated.
* Security gate: **before `GATE_EXIT=3` (10 CALLED) → after `GATE_EXIT=0` (PASS,
  "No vulnerabilities found.")**.
