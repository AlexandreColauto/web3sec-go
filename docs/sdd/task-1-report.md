# Task 1 Report — Reject ambiguous duplicate JSON object keys

**Status:** DONE
**Commit:** `115ba97fd96ceec8c5733d6c8b45277b98441448` — `fix(jval): reject duplicate JSON object keys`
**Branch/worktree:** `production-readiness` @ `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness`
**Base:** `b0006c4abb0735cf4e93789b3b59cc6a91d48d81`
**Files in commit (exactly two):** `internal/jval/parse.go`, `internal/jval/parse_test.go`

All `go` commands ran with the sandbox-safe cache prefix:

```
GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod
```

---

## Step 1 — Test file written first (TDD)

`internal/jval/parse_test.go` was created verbatim from the brief's Step 1 listing:
`TestParseOrderedRejectsDuplicateKeys` (4 raw inputs: `{"a":1,"a":2}`,
`{"outer":{"a":1,"a":2}}`, `{"a":1,"\u0061":2}`, `{"":1,"":2}`) and
`TestParseOrderedAllowsKeysInSeparateObjects` (`[{"a":1},{"a":2}]`).
No unescape helper was added — the brief's verified Unicode note holds
(`encoding/json` decodes `\uXXXX` before `dec.Token()` returns the key, so
`seen` already keys on the semantic string; the `\u0061` case passes without it).

## Step 2 — RED (before implementation)

Command:

```
go test ./internal/jval -run 'TestParseOrdered' -count=1 -v
```

Exit status: **1** (`FAIL websec/internal/jval`). Excerpt (`.scratch/sdd/red-verbose.txt`):

```
=== RUN   TestParseOrderedRejectsDuplicateKeys
    parse_test.go:21: ParseOrdered("{\"a\":1,\"a\":2}"): want duplicate-key error, got <nil>
    parse_test.go:21: ParseOrdered("{\"outer\":{\"a\":1,\"a\":2}}"): want duplicate-key error, got <nil>
    parse_test.go:21: ParseOrdered("{\"a\":1,\"\\u0061\":2}"): want duplicate-key error, got <nil>
    parse_test.go:21: ParseOrdered("{\"\":1,\"\":2}"): want duplicate-key error, got <nil>
--- FAIL: TestParseOrderedRejectsDuplicateKeys (0.00s)
=== RUN   TestParseOrderedAllowsKeysInSeparateObjects
--- PASS: TestParseOrderedAllowsKeysInSeparateObjects (0.00s)
FAIL
FAIL	websec/internal/jval	0.002s
FAIL
```

This is exactly the required red shape: all four duplicate-key cases fail with
`nil` error today, and the separate-objects case already passes (proving the new
test pins a real gap and does not simply demand a blanket refusal).

## Step 3 — Implementation

`internal/jval/parse.go`, `parseValue`, `case '{'` — one `seen` map per object,
guard placed after the key type assertion and before the value token is consumed:

```go
v := Value{Kind: Obj}
seen := make(map[string]struct{})
for dec.More() {
        keyTok, err := dec.Token()
        ...
        key, ok := keyTok.(string)
        if !ok {
                return VNull(), fmt.Errorf("json: object key is %v, not string", keyTok)
        }
        if _, dup := seen[key]; dup {
                return VNull(), fmt.Errorf("json: duplicate object key %q", key)
        }
        seen[key] = struct{}{}
        valTok, err := dec.Token()
```

`ParseOrdered`'s signature is unchanged; the only new behavior is the error path
`json: duplicate object key %q`. `seen` is allocated inside the `case '{'` branch,
so the guard is per-object and the same key in sibling/nested/array-element
objects stays valid.

## Step 4 — GREEN

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/jval -run 'TestParseOrdered' -count=1 -v` | 0 | both tests PASS |
| `gofmt -l internal/jval/` | 0 | no output (formatted) |
| `go test ./internal/jval ./internal/validation ./internal/harness ./internal/state -count=1` | 0 | all 4 packages `ok` |
| `go test ./internal/state -run Legacy -count=1 -v` | 0 | `TestEventLegacyAnchor` PASS, `TestVerifyLogLegacyOnly` PASS |

Green excerpt (`.scratch/sdd/green-verbose.txt`):

```
=== RUN   TestParseOrderedRejectsDuplicateKeys
--- PASS: TestParseOrderedRejectsDuplicateKeys (0.00s)
=== RUN   TestParseOrderedAllowsKeysInSeparateObjects
--- PASS: TestParseOrderedAllowsKeysInSeparateObjects (0.00s)
PASS
ok  	websec/internal/jval	0.001s
```

Focused-package excerpt (`.scratch/sdd/green-focused.txt`):

```
ok  	websec/internal/jval	0.001s
ok  	websec/internal/validation	0.125s
ok  	websec/internal/harness	0.106s
ok  	websec/internal/state	10.139s
```

## Step 5 — Full gates

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./... -count=1` | 0 | every package `ok`; no failures (`.scratch/sdd/full-test.txt`) |
| `go vet ./...` | 0 | no output, clean (`.scratch/sdd/vet.txt`, 0 bytes) |

## Legacy fixture verification — no fixture changes needed

Two independent checks, both clean:

1. **Semantic duplicate-key scan of every committed JSON fixture.** A Python
   `json.loads(..., object_pairs_hook=...)` scan over `scripts/legacy/`,
   `scripts/`, `assets/`, and `internal/` (337 `*.json` files):
   `scanned=337 files_with_duplicate_keys=0`. No fixture can trip the new gate.

2. **`scripts/verify-full.sh` step 9 replicated against the real binary** — the
   step-9 body was run verbatim (pinned clock `WEBV2_NOW`, `WEBV2_UUID`,
   `WEBV2_BASELINES_DIR`, the same `run_p1` shape) on a fresh copy of the
   reference-written campaign `C-45488bdaf5`:

```
audit exit=0
audit PASS: event_log=0 problem(s), artifacts=0 ... unpriceable=0 problem(s)
audit --json exit=0
  ok: 14 audit sections incl sequence_coverage
verify exit=0
=== STEP 9 EQUIVALENT: PASS (audit PASS, audit --json ok:true 14 sections, verify ok:true) ===
```

(The helper functions `p2_sections_ok`/`p2_full_read` were inlined in the
replication; `audit PASS:` with all 14 sections at 0 problems and `verify` at
`ok: true` are step 9's acceptance conditions. Full `verify-full.sh` was not run
end-to-end — see Concerns.)

**Fixture changes: none.** The gate was not weakened and no legacy artifact
required sanitizing.

## Diff summary

```
internal/jval/parse.go      |  5 +++++
internal/jval/parse_test.go | 34 ++++++++++++++++++++++++++++++++++
2 files changed, 39 insertions(+)
```

`git show --stat HEAD` confirms exactly those two paths; `git status --short` is
empty after the commit (no stray files staged, `git add -A` never used).

## Step 7 — Independent review

Deferred to the orchestrator: the brief assigns Task 1 Step 7 to a
`union-alpha` reviewer over `BASE..HEAD` (`b0006c4..115ba97`). Not performed in
this session.

## Concerns

1. **The plan document is not present in this worktree.** The brief's path
   `docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md` does not exist
   under the worktree; the file is **untracked in the main checkout**
   (`?? docs/superpowers/plans/2026-09-17-trust-boundary-hardening.md`). I read
   it from the main checkout (read-only, header + Global Constraints + Task 1
   only) and touched nothing outside the worktree. If Task 1's report is
   expected to reference a committed plan, that plan must be committed
   separately by the orchestrator — it was out of bounds for this commit.
2. **Full `scripts/verify-full.sh` was not run end-to-end** (steps 1-8, 10-13):
   the brief asked for step 9 specifically, and steps 1-5 (vet/build/test/
   race/determinism) duplicate gates I ran individually plus a `-race` run not
   requested for this non-concurrent task. Step 9 was replicated faithfully and
   passed. If the orchestrator wants the whole script as the acceptance bar, it
   should be run once at the phase level.
3. **Memory cost of the guard.** `seen` allocates one map per object, so a
   deeply nested document allocates one map per object level. This is the
   brief's prescribed implementation and is negligible relative to the
   `json.Decoder` token allocation per key; noted only for completeness.
4. **Duplicate keys are refused, not canonicalized.** Any *future* fixture or
   corpus file containing duplicate keys will now fail closed at
   `ParseOrdered`. This is the intended law (last-wins and first-wins readers
   can no longer disagree), but it is a behavior change for previously
   "accepted" ambiguous input; the error text `json: duplicate object key %q`
   is the only signal.

