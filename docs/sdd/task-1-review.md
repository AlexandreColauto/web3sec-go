# Task 1 Review — Reject ambiguous duplicate JSON object keys

- **Reviewer:** independent, read-only. No tracked changes; all scratch work under `.scratch/sdd/` (gitignored) and cleaned up.
- **Worktree:** `.worktrees/production-readiness` @ `16b3bc3a` (clean tree, Task 1 code unchanged since its commit).
- **Plan:** `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` § Task 1.

## Commit identification (correction to dispatch range)

The dispatched range `b0006c4a~4..b0006c4a` contains **pre-plan** commits (63d7def7 runbook/anchor docs, 17bf9c55 symmetry gating, 6ec374aa plan errata, b0006c4a gitignore) — none touch `internal/jval`. Task 1's actual commit is:

- **`115ba97f` — `fix(jval): reject duplicate JSON object keys`** — the direct child of `b0006c4a` (`git log --oneline --reverse b0006c4a..e4a3dc01~1` = exactly this one commit; the plan doc itself landed afterwards in `e4a3dc01`).
- Touches exactly `internal/jval/parse.go` (+5) and `internal/jval/parse_test.go` (+34, new file — matches plan's "create; the package has no test file today").
- No later commit modifies either file (`git log HEAD -- internal/jval` = 115ba97f, 31f777bc only).

## Spec verification

| Plan requirement | Evidence | Result |
| --- | --- | --- |
| Guard in `case '{'` of `parseValue`, `seen := make(map[string]struct{})` per object | parse.go:59, allocated inside the branch → per-object, fresh per nesting level | ✓ |
| Check after `key, ok := keyTok.(string)`, before consuming the value | parse.go:65–72, dup check precedes `dec.Token()` for the value | ✓ |
| Error text exactly `json: duplicate object key %q` | parse.go:70 verbatim vs plan line 37/83 | ✓ |
| No new public API; `ParseOrdered` signature unchanged | only the body changed; `git show 115ba97f` shows no signature diff | ✓ |
| No custom `\uXXXX` unescape (dead code per plan's Unicode note) | none added; escape aliasing handled by `encoding/json` pre-decode, proven by the `\u0061` test case passing | ✓ |
| Test file exactly as specified | parse_test.go is byte-identical to the plan's Step 1 block (incl. both test funcs and comments) | ✓ |
| Commit message `fix(jval): reject duplicate JSON object keys`, only task-owned files | commit subject matches; diff = the 2 owned files only | ✓ |
| No fixture weakening / canonicalizing duplicates to get green | `git diff --stat b0006c4a 115ba97f -- assets scripts` = empty; `scripts/legacy` untouched | ✓ |

## Semantic checks (re-derived, not taken from reports)

- **Per-object scope:** `seen` lives inside `case '{'`, so a nested object starts with an empty map; sibling/outer objects never share keys. Test `{"outer":{"a":1,"a":2}}` pins nested detection; `[{"a":1},{"a":2}]` pins separate-object allowance and asserts parsed values (1 and 2) survive intact.
- **Escape aliasing:** `{"a":1,"\u0061":2}` and `{"":1,"":2}` both rejected — the seen-map lookup operates on the decoded semantic key, exactly the property the plan's Unicode note requires.
- **Fail-closed propagation:** all `ParseOrdered` callers (`assets/evalsuite.go`, `internal/validation` wrappers, costs, doctor, datasets, …) thread `err` up; no caller swallows parse errors.

## Gates I ran myself (repo-local Go cache per `scripts/verify-full.sh` convention; sandbox `$HOME` caches are read-only)

| Gate | Result |
| --- | --- |
| `go test ./internal/jval -count=1 -v` | PASS — RejectsDuplicateKeys ✓, AllowsKeysInSeparateObjects ✓ |
| **Red state** (parent `115ba97f^` jval package + the new test file, staged in `.scratch/sdd/task1-redcheck` then removed) | **FAIL as planned** — all 4 duplicate-key cases return `<nil>` on parent code; AllowsKeysInSeparateObjects passes (red-green evidence honest) |
| `go test ./... -count=1` | GREEN, exit 0 — all 44+ packages ok, incl. `validation`, `validation/fuzz`, `state`, `sandbox` (51.9s) |
| `go vet ./...` | clean, exit 0 |
| `gofmt -l internal/jval/` | empty |
| `go test ./internal/state -run Legacy -count=1` | ok — historical fixtures unaffected |

## Findings

1. **(Info, dispatch-level)** The instructed commit range `b0006c4a~4..b0006c4a` predates the plan and does not contain Task 1; the Task 1 commit is `115ba97f` (first commit after `b0006c4a`, before the plan doc `e4a3dc01`). Future Task-N dispatches should use the plan-commit-relative ranges (`e4a3dc01..`).
2. **(Info, pre-existing/elsewhere)** Duplicate-key law for *YAML* was deliberately split out as Task 16 (`78f755bb` note, implemented in `b00532ca`) — out of Task 1 scope, correctly so.

No blocking findings. No gate weakened, no fixture touched, no dead code added.

## Verdicts

- **Spec compliance: YES** — implementation, tests, error text, scope, and commit discipline match the plan Task 1 spec exactly, with honest red-green evidence.
- **Quality: APPROVED** — minimal 5-line fix at the shared root, per-object semantics correct, escape aliasing handled by the stdlib as the plan verified, full gates green.
