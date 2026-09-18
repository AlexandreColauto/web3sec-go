# Task 5 report — artifact-register deduplicates by resolved path

**Status:** DONE_WITH_CONCERNS (premise correction: no production change was
required; the law already held at HEAD, and the deliverable is the regression
test that pins it)
**Commit:** `1e6412e5` — `fix(state): artifact-register deduplicates by resolved path`
**Branch/worktree:** `production-readiness` @
`/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
**Base:** `37511ec8` (Task 4)
**Files changed:** `internal/cli/cmd_artifact_register_test.go` (+130/-0) — ONE file, test only.

---

## 1. The brief, verbatim (plan Task 5 + Phase B preamble)

> **Law:** registering the same file twice (relative then absolute, or any path
> spelling) yields the SAME artifact id and an `artifact.refreshed` event —
> never a second row. Use the existing `RegisterOrRefresh`
> (state/artifacts.go:434); if its semantics differ (it matches on stored path
> string), extend IT to resolve first — one fix in the shared function, not
> per-CLI.
> **Test:** register `target/a.sol`, then `./target/a` from inside the root →
> same id, one row, second event says refreshed.

Root-cause placement the orchestrator required: fix in the SHARED seam
(`RegisterOrRefresh`), not in the CLI handler; the handler must stay a thin
pass-through.

## 2. Finding: the seam ALREADY resolves both sides — the plan's premise is stale

`internal/state/artifacts.go` (`RegisterOrRefreshKeptGhosts`, the worker behind
`RegisterOrRefresh`), lines 460-473 at HEAD:

```go
	if _, err := os.Stat(path); err != nil {
		return "", nil, fmt.Errorf("%s", path)
	}
	resolved := resolvePath(path)          // :463  incoming spelling resolved
	st, err := c.State()
	if err != nil {
		return "", nil, err
	}
	var same []validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if resolvePath(c.resolveArtifactPath(a)) == resolved {   // :470  stored row resolved
			same = append(same, a)
		}
	}
```

`resolvePath` (artifacts.go:25) is `filepath.Abs` + `filepath.EvalSymlinks` —
i.e. the comparison key is already the RESOLVED file, not the stored path
string. `git log -S` shows that comparison has been there since the P0 port
(`d07ef68d`), and the plan's own P0 reference doc
(`docs/superpowers/plans/2026-09-08-p0-trust-core.md:435`) says the Python
reference does the same: *"resolved path; find existing artifacts with same
resolved path"*.

The CLI half of the fix the plan asks for landed even earlier, as r34 F3
(`af3be559`, 2026-09-15) — the handler replaced the append primitive with the
seam:

```diff
-	aid, err := c.RegisterArtifact(kind, path, note, snap)
+	aid, err := c.RegisterOrRefresh(kind, path, note, snap,
+		artifactRegisterRefreshReason)
```

so `internal/cli/cmd_artifact_register.go:127` now calls
`c.RegisterOrRefreshKeptGhosts(kind, path, note, snap,
artifactRegisterRefreshReason)`. The handler holds no dedup logic to thin out.

**Single writer check.** `rg 'RegisterArtifact\('` over `internal/` (excluding
tests) returns exactly two hits: its definition (artifacts.go:113) and the
seam's not-registered branch (artifacts.go:530). `arts.A = append(arts.A, rec)`
occurs once in the tree (artifacts.go:161). So every artifact row in every
campaign is minted through the resolved-path seam; there is no second
row-minting route to fix, in the CLI or elsewhere.

**Conclusion:** extending `RegisterOrRefresh` "to resolve first" is already
done; there is nothing to extend, and I did not churn the hot function (r15
lock window / r16 unwind laws untouched, byte-for-byte).

## 3. Evidence — the law already holds, for ten spellings

A scratch probe (deleted before commit; `internal/cli/zz_scratch_probe_test.go`,
run with `go test ./internal/cli -run TestZZProbeSpellings -count=1 -v`) drove
the real verb over one file under every spelling an operator can type. Raw
output:

```
spelling "target/a.sol"                     id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "./target/a.sol"                   id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "/tmp/.../001/target/a.sol"        id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "/tmp/.../001/target/../target/a.sol" id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "/tmp/.../001//target//a.sol"      id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "target/./a.sol"                   id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "target/../target/a.sol"           id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "alias/a.sol"   (symlinked dir)    id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "flink.sol"     (symlink to file)  id=OTH-bf8e14f5 rows=1 stored=[target/a.sol]
spelling "hard.sol"      (hard link)        id=OTH-7076ef4c rows=2 stored=[target/a.sol hard.sol]
```

Nine spellings of one file collapse to one row with one id; a hard link (a
genuinely different resolved path, same inode) correctly mints its own row,
which is exactly what "deduplicates by resolved path" means.

## 4. Red evidence — the pin is real, not a tautology

Because the law already holds, the test cannot be red against HEAD. I proved
it is a genuine pin by counterfactual: patch the code back to each shape the
fix exists to prevent, run the new test, restore.

**Counterfactual 1 — route the verb through the append primitive (pre-r34-F3
shape):** temporarily replaced the `RegisterOrRefreshKeptGhosts` call in
`cmd_artifact_register.go` with `c.RegisterArtifact(kind, path, note, snap)`.

```
--- FAIL: TestArtifactRegisterDeduplicatesByResolvedPath (0.00s)
    cmd_artifact_register_test.go:130: spelling "./target/a.sol" minted OTH-af3319c9,
    want the row already registered at this file (OTH-9674b4a2);
    all ids: [OTH-9674b4a2 OTH-af3319c9 OTH-c6d242d1 OTH-cff2d350]
FAIL
FAIL	websec/internal/cli	0.011s
EXIT=1
```

**Counterfactual 2 — replace the seam's `resolvePath` comparison with a bare
`filepath.Abs` (no `EvalSymlinks`):** temporarily rewrote artifacts.go:470.

```
--- FAIL: TestArtifactRegisterDeduplicatesByResolvedPath (0.01s)
    cmd_artifact_register_test.go:143: spelling "alias/a.sol" minted OTH-d322b9ac,
    want the row already registered at this file (OTH-fb35dfed);
    all ids: [OTH-fb35dfed OTH-fb35dfed OTH-fb35dfed OTH-fb35dfed OTH-d322b9ac]
FAIL
FAIL	websec/internal/cli	0.015s
EXIT=1
```

Both patches were reverted immediately (`git checkout --`, `cp` restore);
`git status --short` showed only the test file modified before commit. The
second counterfactual is why the symlinked-directory spelling is in the table:
it is the arm that fails for an `Abs`-only compare, so the test pins
`EvalSymlinks` behaviour and not merely path cleaning.

**Green (restored HEAD):**

```
=== RUN   TestArtifactRegisterDeduplicatesByResolvedPath
--- PASS: TestArtifactRegisterDeduplicatesByResolvedPath (0.01s)
PASS
ok  	websec/internal/cli	0.015s
EXIT=0
```

## 5. The test (table test in the handler's `_test.go`)

`internal/cli/cmd_artifact_register_test.go`,
`TestArtifactRegisterDeduplicatesByResolvedPath` — drives the real CLI verb
through `run(t, "--root", root, "artifact-register", c.CampaignID, spelling)`,
with the process cwd moved into the campaign root so the relative spellings
resolve the way an operator's shell resolves them (`defer os.Chdir(cwd)`).

Table of spellings registered in order over ONE file (`target/a.sol`):
bare relative `target/a.sol`; dot-prefixed `./target/a.sol`; absolute `abs`;
uncleaned `root + "/target/../target/a.sol"`; through a symlinked directory
`alias/a.sol` (fixture: `alias -> target`).

Assertions (all in the plan's list plus two strengthenings):

1. all five success lines carry the SAME artifact id (plan: "same artifact id
   across all three");
2. exactly one row in state (`r34ArtifactRows`, plan: "exactly one row");
3. that row's id is the first id;
4. **strengthening:** the row's stored `path` is still `target/a.sol` — a
   re-spelling refreshes the row, it does not re-key it, so the registry stays
   stable for every reader that resolves the stored path against the root;
5. `refresh_count == len(spellings)-1` (one registration + four refreshes);
6. the event log holds exactly one `artifact.registered` and one
   `artifact.refreshed` per later spelling — the EXISTING vocabulary
   (plan: "match existing vocabulary, do not invent a new event type"); no new
   event type was added anywhere;
7. a distinct file (`target/b.sol`) still mints a distinct id and takes the
   registry to two rows (plan: "distinct files still mint distinct ids").

Note on the plan's literal `./target/a`: the fixture file is `target/a.sol`, so
a path spelled `./target/a` would be a DIFFERENT (nonexistent) file and the verb
would exit 2 with `artifact register failed: no such file` — correct behaviour,
not dedup. I read the plan's `./target/a` as shorthand for the same file under a
dot-prefixed relative spelling and used `./target/a.sol`.

## 6. Gates — exact commands and outcomes

All run from the worktree root with
`GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomodcache`.

| # | Command | Outcome |
|---|---------|---------|
| 1 | `gofmt -l internal/cli/` | no output (clean) |
| 2 | `go test ./internal/cli -run 'TestArtifactRegister' -count=1 -v` | **exit 0** — 6/6 PASS (`TestArtifactRegister`, `…DefaultsToKindOther`, `…MissingFileExits2`, `…MissingArgsIsArgparse`, `…DeduplicatesByResolvedPath`, `…PrintsTheImmutabilityNotice`) |
| 3 | `go test ./internal/state ./internal/cli -count=1` | **exit 0** — `ok websec/internal/state 13.435s`, `ok websec/internal/cli 32.120s` |
| 4 | `go test ./internal/state -run Legacy -count=1` | **exit 0** — `ok websec/internal/state 0.008s` (legacy fixture anchors still read/audit clean) |
| 5 | `go test ./... -count=1` | **exit 0** — every package `ok` (57 packages; `internal/sandbox 51.8s` the longest; no FAIL, no `[build failed]`) |
| 6 | `go vet ./...` | **exit 0** — no output |
| 7 | `git status --short` after commit | clean; commit touches one file |

Full-suite tail (job `bash-19`, `FULL_EXIT=0`):

```
ok  	websec/internal/cli	32.078s
ok  	websec/internal/sandbox	51.824s
ok  	websec/internal/state	12.123s
ok  	websec/internal/validation	0.318s
?   	websec/scripts/archive/oq3check-main.go.txt	[no test files]
FULL_EXIT=0
```

## 7. Golden / runbook pins

The plan's Global Constraints require `scripts/golden.sh`,
`scripts/runbook-walkthrough.sh` and `python3 scripts/check-golden.py` for any
task that CHANGES CLI OUTPUT. This task changes no production code, so no CLI
byte can move. I still checked whether any pin asserts duplicate-row behaviour
(the case the brief called out):

- `rg -n "artifact-register" scripts/golden scripts/runbook-walkthrough.sh` →
  exactly one hit: `scripts/runbook-walkthrough.sh:442`, which registers
  `h1-withdraw-double-count.json --kind report` ONCE and asserts
  `kind=report`; no second registration, no spelling variant.
- `scripts/golden/` contains no `artifact-register` step and no
  "one registry row" expectation.
- `assets/runbook/RUNBOOK.md:1691-1696` states the law the code already
  honours ("A path holds **one** registry row …"), so no pin needed updating
  and nothing was edited.

No golden/runbook file was touched; there is no pin drift to disclose.

## 8. Diff summary

```
$ git show --stat 1e6412e5
 internal/cli/cmd_artifact_register_test.go | 130 +++++++++++++++++++++++++++++
 1 file changed, 130 insertions(+)
```

Production diff: **none** (deliberate — see §2/§3). `internal/state/artifacts.go`
and `internal/cli/cmd_artifact_register.go` are byte-identical to `37511ec8`;
the r15 campaign-lock window and the r16 `rawState`/`unwindState` refusal laws
were never touched, and no file outside my task was staged
(`git add internal/cli/cmd_artifact_register_test.go`, no `-A`/`.`).

## 9. Concerns

1. **Premise correction, not a failed task.** The plan's Task 5 conditional
   ("if its semantics differ…") is false at HEAD: the seam resolves both sides
   (artifacts.go:463/470, since the P0 port `d07ef68d`) and the verb routes
   through it (r34 F3, `af3be559`, 2026-09-15). I therefore delivered the
   plan's TEST (the durable pin) and no production change, rather than inventing
   a refactor to look busy. If the orchestrator wants a production diff anyway,
   the honest candidates are cosmetic (extract the comparison into a named
   `sameResolvedPath` helper) and I do not recommend them.
2. **The commit subject is the mandated one** (`fix(state): …`) while the change
   is test-only. I kept the mandated message per the brief and put the premise
   correction in the commit body so the record is not misleading.
3. **Where the real friction, if any, still lives.** The plan's own line numbers
   (RegisterOrRefresh at :434 vs :440 at HEAD) suggest Task 5 was written from a
   reading of this tree, so I treated it as a possible false positive rather
   than assuming a hidden defect. If an operator round was actually burned by
   duplicate rows, the surviving candidate causes are OUTSIDE this verb:
   (a) Task 6's `index` rewrite path, (b) the deliberate r35 F1 kept-ghost
   exception where one path legitimately holds two rows because a live citation
   names the older id (`RegisterOrRefreshKeptGhosts`, artifacts.go:488-523) —
   the RUNBOOK's "one row" sentence has no exception clause for that shape, and
   that is a DOC issue, not a dedup bug; (c) r34's recorded residual that
   `--note`/`--snapshot_id` are ignored on the re-register path (af3be559 commit
   body). None is in Task 5's scope and I touched none of them.
4. **Adjacent inconsistency, deliberately not fixed (scope):** the artifacts
   audit section (`internal/audit/sections/artifacts.go:32-39`) resolves stored
   paths with `filepath.Join(c.Root, path)` and NO `EvalSymlinks`, while the
   seam's dedup key does expand symlinks. For a symlinked stored path the audit
   re-hashes the symlink target anyway (os.Stat follows links), so no false
   red is reachable in the cases I tested; but the two "resolved" notions are
   not the same function. Flagging it for the final review triage rather than
   widening this task.
5. **Golden/runbook not re-run** (see §7 for why they cannot drift: test-only
   change, no CLI output path touched). If the review requires the full
   `scripts/golden.sh` + `check-golden.py` run as a formality, it is cheap to
   re-run on the same commit; I skipped it to avoid a concurrent writer
   clobbering `.scratch/golden/` while sibling tasks run.

## 10. How to reproduce (reviewer checklist)

```bash
cd /home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness
export GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod \
       GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomodcache

# green pin
go test ./internal/cli -run TestArtifactRegisterDeduplicatesByResolvedPath -count=1 -v

# counterfactual 1 (red): the pre-r34-F3 append primitive.
#   In internal/cli/cmd_artifact_register.go replace
#     aid, kept, err := c.RegisterOrRefreshKeptGhosts(kind, path, note, snap,
#         artifactRegisterRefreshReason)
#   with
#     aid, err := c.RegisterArtifact(kind, path, note, snap)
#     var kept []state.KeptGhost
#   then:
go test ./internal/cli -run TestArtifactRegisterDeduplicatesByResolvedPath -count=1
git checkout -- internal/cli/cmd_artifact_register.go

# counterfactual 2 (red): Abs-only comparison at artifacts.go:470.
#   Replace `resolvePath(c.resolveArtifactPath(a)) == resolved` with
#   `absOnly(c.resolveArtifactPath(a)) == absOnly(path)` (+ a small absOnly
#   helper, and `_ = resolved` to keep the compiler happy), then:
go test ./internal/cli -run TestArtifactRegisterDeduplicatesByResolvedPath -count=1
git checkout -- internal/state/artifacts.go
```

Commit under review: `1e6412e5` (parent `37511ec8`). Only
`internal/cli/cmd_artifact_register_test.go` is in it.
