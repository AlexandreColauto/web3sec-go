# Task 5 review — artifact-register deduplicates by resolved path

**Commit under review:** `1e6412e5` (parent `37511ec8`) — `fix(state): artifact-register deduplicates by resolved path`
**Reviewer mode:** read-only, independent; no tracked file modified, no delegation.
**Verdicts:** **Spec compliance: YES** · **Quality: APPROVED with findings** (2 Low, 5 Info; none blocking)

---

## 0. What the commit is

`git diff --name-only 37511ec8..1e6412e5` → **one file**, `internal/cli/cmd_artifact_register_test.go` (+130/-0, test-only).
`internal/state/artifacts.go` and `internal/cli/cmd_artifact_register.go` are byte-identical across the range; no
fixture, golden, runbook, or `testdata` file moved. Working tree of tracked files is clean.
`.scratch/sdd/task-5-review-package.md` is byte-identical to the commit on its added lines
(`diff <(git diff 37511ec8..1e6412e5 | rg '^\+') <(rg '^\+' package)` → identical); only the hunk context width differs.

## 1. Does the premise correction hold? (the "no production change" claim)

Verified independently at `1e6412e5`, every line the report cites:

| Claim | Reality |
|---|---|
| `resolvePath` = Abs + EvalSymlinks | `internal/state/artifacts.go:25-34` ✓ |
| seam resolves the **incoming** spelling | `artifacts.go:463` `resolved := resolvePath(path)` ✓ |
| seam resolves **every stored row** before comparing | `artifacts.go:469-473` `resolvePath(c.resolveArtifactPath(a)) == resolved` ✓ (dedup key is the resolved file, not the stored string) |
| CLI verb routes through the seam, handler thin | `internal/cli/cmd_artifact_register.go:127` calls `c.RegisterOrRefreshKeptGhosts(...)`; the handler holds no dedup logic ✓ |
| `RegisterArtifact` has **no** dedup and is single-writer | repo-wide non-test `rg 'RegisterArtifact\('` → exactly two hits: the definition `artifacts.go:113` (fresh id minted at `:128`, `arts.A = append` at `:161`) and the seam's not-registered branch `artifacts.go:530` ✓ — no second row-minting route exists |
| refresh bookkeeping the test asserts | `refreshArtifact` bumps `refresh_count` by one (`artifacts.go:342-350`) and logs `artifact.refreshed` (`:373`) ✓ |
| plan premise is stale | plan `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md:235` says `RegisterOrRefresh` at `:434`; it is at `:440`, and the conditional ("if it matches on stored path string, extend IT") is false at HEAD ✓ |

So "extend the shared seam to resolve first" was already true in the shared seam, and the plan's own fallback
branch did not apply. Accepting a test-only deliverable is the honest read of the brief, not a dodge: the durable
artifact the plan asked for is the pin.

## 2. Does the test actually pin the law? (identity · rows · refresh)

`TestArtifactRegisterDeduplicatesByResolvedPath`, `internal/cli/cmd_artifact_register_test.go:95-206` (committed revision).
It drives the **real verb in-process** (`run` → `cli.Run`, `internal/cli/cli_test.go:26`) over ONE file
(`target/a.sol`) under five spellings: bare relative, `./`-prefixed, absolute, uncleaned absolute, through a
symlinked directory (`alias -> target`), with cwd moved into the campaign root so relative spellings resolve as an
operator's shell resolves them.

Assertions, and whether each is load-bearing (not tautological):

- **Identity** (`:141-146`): all five success-line ids must equal the first. `r34Id` parses stdout's `ID:` prefix, so a
  minted second row fails here. ✓ real check.
- **Row count** (`:147-152`): `r34ArtifactRows` is the raw `objAt(st,"artifacts").A` projection (`zz_r34_test.go:37-46`),
  unfiltered — not a kind-scoped or list-rendered subset. Exactly 1 required. ✓
- **No re-keying** (`:157-161`): the row's stored `path` must still be `target/a.sol` — a refresh must not rewrite the
  row's key. ✓ strengthening the plan.
- **Refresh bookkeeping** (`:166-167`): `refresh_count == 4` (`len(spellings)-1`), and `refreshArtifact` is the only writer. ✓
- **Events** (`:171-190`): exactly one `artifact.registered` and exactly four `artifact.refreshed`, using the existing
  vocabulary; no new event type anywhere in the commit. ✓ (the whole log is counted, see Info-4)
- **Distinct files stay distinct** (`:192-206`): `target/b.sol` must mint a *different* id and take the registry to 2 rows.
  Fails if dedup degenerated into "refresh whatever is there". ✓

**Independently reproduced green:** `go test ./internal/cli -run TestArtifactRegisterDeduplicatesByResolvedPath -count=1 -v`
→ `PASS` / `ok websec/internal/cli 0.015s` / exit 0. Run at HEAD (`913b089e`), which is safe for this purpose: the only
commit between `1e6412e5` and HEAD is docs-only, and the three relevant Go files are byte-identical to the reviewed commit
(`git diff --stat 1e6412e5..HEAD -- <the three>` → empty).
`gofmt -l internal/cli internal/state` → no output.

## 3. Not a duplicate of what the tree already pinned

`zz_r34_test.go` (`TestR34ArtifactRegisterReRegisterKeepsOneRow`, `:90-154`) and its same-kind sibling already pin
one-row-per-path, `refresh_count`, `kind_migrated` and the last-event shape — but **every one of them registers the
same absolute string twice** (`path := filepath.Join(c.Root, "dump.json")`). No prior test crosses the *spelling*
axis (relative / dot-prefixed / absolute / uncleaned / symlinked directory). The new test is additive and fills exactly
the gap the plan named. `zz_r35_test.go` / `zz_r44a_test.go` also use the verb but on the kept-ghost and reconcile
laws, not dedup-by-spelling.

## 4. Findings

**Low-1 — Counterfactual 1's transcript does not match the committed test.**
`.scratch/sdd/task-5-report.md` §4 shows CF1 failing at `cmd_artifact_register_test.go:130` with a **4-element** id list
(`[OTH-9674b4a2 OTH-af3319c9 OTH-c6d242d1 OTH-cff2d350]`) while the narrative says "five spellings → five ids, five rows".
In the committed file the identity `t.Fatalf` lives at **line 143** and line 130 is the closing brace of the `spellings`
literal; the table has five entries, so an after-the-loop report must print five ids. CF2's transcript (`:143`, five ids,
failing on `alias/a.sol`) *does* match the committed revision. Read: CF1 was captured against an earlier 4-spelling draft,
before the symlink arm was added. The conclusion is still sound — `RegisterArtifact` mints a fresh id at
`state/artifacts.go:128` and appends at `:161` with no comparison at all, so the committed test cannot be green through
that route — but the report presents both red runs as if executed on the delivered file. Fix the record (re-run CF1 on the
committed test, or annotate which draft each transcript came from). No product impact; the pin is real either way.

**Low-2 — No Task 5 evidence artifacts were left behind.**
`.scratch/sdd/` holds captured logs for Tasks 2 and 4 (`task2-full-test.txt`, `task2-golden.txt`, `task2-vet.txt`,
`task-4-logs/`) but nothing for Task 5: `full-test.txt` / `green-focused.txt` / `vet.txt` are timestamped 18:38–18:39,
i.e. earlier tasks, and `rg -l "DeduplicatesByResolvedPath" .scratch/` matches only the report and the review package.
So §6's gate table (the `go test ./...` "57 packages ok", `go vet` clean, legacy-anchor run) is prose-only and
unverifiable after the fact. The reviewer re-ran only the focused pin (green, §2); per the brief the full suite was not
re-run. For the remaining tasks, capture the run to `.scratch/sdd/task-N-*.txt` — cheap, and it makes the gate column
auditable instead of attestable.

**Info-3 — Two arms the report shows were never pinned.** §3's ten-spelling probe (`flink.sol` symlink-to-file,
`hard.sol` hard link → its own id) lived in `internal/cli/zz_scratch_probe_test.go`, which is not in the commit and has
no history in any ref (`git log --all --` → empty, file absent). The symlink-to-*file* arm and especially the hard-link
arm are the sharpest statement of "distinct resolved files retain distinct ids" (same inode, different resolved path) and
would cost ~6 lines to fold into the existing table. Unpinned today ⇒ a future "optimisation" that dedups by inode would
pass the tree.

**Info-4 — Event assertions count types only.** `:175-190` tallies `artifact.registered` / `artifact.refreshed` across
the whole log without checking each refresh event's `artifact_id`/`ref`, its `data.refresh_count`, or ordering. On a
campaign freshly created by `t15Campaign` (`cmd_dedup_test.go:28-37`, empty registry) that is a strong check, and §2's
`refresh_count == 4` on the row closes the same hole from the other side. Naming the ref on each counted event would
make it immune to a stranger artifact ever appearing in this fixture.

**Info-5 — Stored-path assertion is order-coupled.** `:157-161` requires `path == "target/a.sol"`, which holds only
because the *first* spelling is the relative one; reordering the table breaks it for a reason unrelated to the law. The
comment at `:153-156` states the intent, so this is accepted as-is; if the table ever grows, assert "stored path is the
first registration's spelling" instead of a literal.

**Info-6 — `os.Chdir` in a process-wide test binary.** The test changes the process cwd (`:114-122`) with
`defer os.Chdir(cwd)`. Safe today: `rg -n "t.Parallel\(\)" internal/cli/*_test.go` → zero hits, and Go runs tests in a
package sequentially otherwise, so no sibling test observes the wrong cwd. A future `t.Parallel()` in this package that
resolves a relative path would race it — worth knowing, not worth changing.

**Info-7 — Commit label vs content.** `fix(state):` on a test-only change in `internal/cli`. Mandated by the brief, and
disclosed in report §9.2; the body's PREMISE CORRECTION section keeps the record honest, so no history rewrite is asked for.

## 5. Unverified claims the reviewer could not confirm (and how much they matter)

- §6 rows 3–5 (package pair `ok`, `-run Legacy` anchors, full `go test ./...`) and row 6 (`go vet ./...`): no captured
  log (§ Low-2) and the full suite was out of review scope. Low risk: the commit cannot affect any other package — the
  one file is a `_test.go` and it defines exactly one new `Test…` function plus no shared helpers, so no other test's
  inputs move.
- §3's ten-spelling probe table: unreproducible from the tree (Info-3). The five spellings the committed test does pin
  were re-run green.
- §4 CF1: transcript mismatched (Low-1). CF2 is consistent with the delivered file and is the arm that actually proves
  `EvalSymlinks` is load-bearing.
- §7's golden/runbook survey: spot-checked and accurate — `rg -n "artifact-register" scripts/golden scripts/runbook-walkthrough.sh`
  returns exactly `scripts/runbook-walkthrough.sh:442` (one registration, `kind=report`), and the law text is at
  `assets/runbook/RUNBOOK.md:1691-1696`. Skipping `scripts/golden.sh` on a test-only change is defensible; the report says so.
- Report §9.4's adjacent flag is **accurate and correctly deferred**: `internal/audit/sections/artifacts.go:31-39` and
  `state.resolveArtifactPath` (`artifacts.go:201-207`) join without `EvalSymlinks`, while the seam's dedup key expands
  symlinks. Rows written by `RegisterArtifact` store an already-resolved relative path, so a symlinked stored path needs
  a hand-edited state to appear — carry it to final triage, don't widen Task 5.

## 6. Verdicts

**Spec compliance: YES.** The plan's Task 5 law is pinned at the CLI verb for the required spelling set, with one row,
one id, one `artifact.registered` plus one `artifact.refreshed` per later spelling, and distinct files minting distinct
ids; the plan's conditional production half was verified false at HEAD, so no shared-seam change was owed and none was
invented. Root-cause placement requirement (law in the seam, handler thin) is honoured and re-pinned by a comment.

**Quality: APPROVED with findings** — Low-1 (stale CF1 transcript: correct the evidence record) and Low-2 (no captured
Task 5 gate logs) are documentation/provenance, not defects in the delivered code; Info-3 is the only substantive
coverage suggestion worth a follow-up line in the final task list. No production change is requested.
