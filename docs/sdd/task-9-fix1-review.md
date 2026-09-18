# Task 9 fix-round-1 review — F1 (leading word boundary) / F2 (absence precedence)

- **Reviewer:** independent read-only re-review; no delegation, no tracked changes (tree clean at review start and end; the temporary probe file was deleted after its run)
- **Scope:** `git diff eb44603a..HEAD -- internal/envgo internal/sandbox` at HEAD `6fdec840`; the fix commit also carries `internal/cli/cmd_classify_toolabsent_test.go`, which the brief's diff path excludes — verified separately via `git show 6fdec840 --stat` (5 files, +141/−18, matching the report's scope line)
- **Inputs:** `task-9-review.md` (F1/F2), `task-9-fix1-report.md`, the diff, the fix's own logs in `.scratch/sdd/task-9-fix1-logs/`, and a fresh adversarial probe run by this review
- **Method:** every load-bearing claim re-verified from primary evidence — mirrored-block byte comparison, focused + full-suite re-runs, and an independent probe (16 law rows + mirror equality over the sandbox default; probe source deleted after the run, `git status --porcelain` clean)

## Verdicts

| Item | Verdict |
| --- | --- |
| F1 — missing leading word boundary in `toolAbsentRe` | **ADDRESSED** |
| F2 — `toolAbsent` precedence over `logicHit` misroutes hypothesis-space captures | **ADDRESSED** (review option b) |
| Both regex copies identical (r38 rail) | **VERIFIED** |
| Runbook law satisfied on all pinned adversarial rows | **VERIFIED** |
| No previously-green row flipped | **VERIFIED** (full suite re-run: 71 ok, 0 FAIL) |
| New Critical/Important breakage | **NONE** (two documented observations, §3) |

## 1. F1 — ADDRESSED

- The `tok :=` line is now `` `\b(?:` + tool + `)[\s:,;)"'\]}]` `` in **both** copies (`classifier.go:71`, `envseam.go:85`); the doc comment now names BOTH boundaries as load-bearing (trailing delimiter → `forge-std` stays out; leading `\b` → `broadcast`/`forecast`/`recast` stay out).
- Pinned so the boundary is load-bearing in tests, not comments: `broadcast-not-found-stays-setup` (envgo table + sandbox mirror + CLI verb, all asserting SETUP, note without `foundryup`, and — at the CLI — no `toolchain binary absent` signal), `forecast-word-stays-unknown` (unknown), plus a signal-level row (`TestToolchainAbsenceSignalIsRecorded`: broadcast must not invent the absence signal).
- Independently probed by this review: `broadcast not found for script deploy` (bare, no `Error:`) → **unknown**; `forecast data not found` → **unknown**; real absence forms unchanged — `cast: not found`, `/usr/bin/cast: not found`, `anvil not found`, `no forge installed` → **environment** with the absence signal.
- **Residual (documented, not a regression):** colon-delimited variants `Error: broadcast: not found` and `recast: not found` still route **environment** — via the *unchanged* `shellAbsentRe` arm `^[^\n]{0,80}: not found$`, not via `forgeAbsentRe`. This behavior is byte-identical to `eb44603a` (shellAbsentRe untouched in the diff), so it is the pre-existing shell widening already disclosed as F2's second path and re-disclosed in the fix report's residual section — not something this fix introduced or was scoped to fix. Recorded here so the next reviewer does not mistake it for an F1 escape.

## 2. F2 — ADDRESSED (precedence option b)

- The class switch in **both** copies is now `solcFailed → dockerHit → logicHit → toolAbsent → setupHit → unknown` (`classifier.go:178`, `envseam.go:217`); `shellAbsentRe` untouched, per the report's rationale (anchoring would drop a real bare `jq: command not found` out of the law's evidence — sound; the finding's letter was the precedence, and option (b) was one of the review's two sanctioned fixes).
- The named adversarial capture is pinned at **all three surfaces** and asserts exactly what F2 demanded: `sh: 1: helper.sh: command not found` + `assertion failed: x != y` → **logic**, note = the LOGIC note, `noteWithout` "do NOT spend a fresh-context retry" (envgo), signals carry **both** patterns (absent + logic), mirror row keeps envgo ≡ sandbox default, CLI row forbids the retry-denial string in operator output.
- Independently probed: pure echo (no logic signal) stays **environment** — the disclosed widening survives, now subordinate; real binary + echoed assertion (`solc: not installed` + `assertion failed`) → **logic** with both signals, which is the law's own direction (LOGIC is the only class that argues the hypothesis).
- The F2 **second path** (`sh: 1: /tmp/ffi-probe.sh: not found`, missing repository *script*) is unchanged → environment. Accepted: the review's option (a) could not have fixed it either (the line starts `sh:`), no script-vs-binary rule exists in the runbook, and the fix report discloses it verbatim as residual. Consistent with the routing-hint framing the original review endorsed.

## 3. Observations (not findings — no Critical/Important breakage found)

1. **The swap moved `logicHit` above `setupHit` too, and the fix report does not say so.** At `eb44603a` the order was `… toolAbsent → setupHit → logicHit`, so a capture with BOTH setup and logic text routed **setup**; the fix's move puts `logicHit` above `setupHit`, so `Error: compilation failed` + `assertion failed` now routes **logic** (probed by this review). Direction is law-consistent — LOGIC is the only class that argues the hypothesis, and this is the same rationale as F2 — and no pinned row anywhere exercises the co-occurrence (the full suite re-run below is 0 FAIL), so nothing flipped. But it is a second precedence change beyond the finding's letter and deserves a line in the report when cited downstream.
2. **Shell-widening colon residual** (see §1): `broadcast: not found` / `recast: not found` / `forecast: not found` reach ENVIRONMENT through `shellAbsentRe`'s generic `^[^\n]{0,80}: not found$` arm. Pre-existing at the base commit and disclosed; noted so it is not re-discovered as an F1 regression later.

## 4. Mirror identity + r38 rail — VERIFIED

- Byte comparison at HEAD: the `toolAbsentRe` doc+func block (1 207 B, sha256 `d1d49d4d…`), the signals/notes/`toolAbsentNote` block (2 119 B, `1abdacc5…`) and the class switch (270 B, `17d0a6cf…`) are **identical** across `classifier.go` and `envseam.go`; the full +/- line set of the diff is exactly the three intended changes per copy (doc comment, `\b` in `tok`, switch swap) — nothing else moved.
- `TestToolchainAbsenceIsMirroredInTheSandboxDefault` gained 3 differential rows (`solc-colon`, `broadcast`, `echoed+assertion`); every one of this review's 16 probe rows also asserted `CanonCompact(envgo) == CanonCompact(sandbox default)` — no mirror mismatch.
- The exit-127 early-return path (`classifyDockerLevelExit`) is untouched by the diff and the exit-127 pin (`missing-forge-exit127-host`) still passes.

## 5. Gates re-run by THIS review (not accepted from logs)

| Gate | Result |
| --- | --- |
| `go test ./internal/envgo ./internal/sandbox -count=1` | ok 0.599s / 49.319s |
| `go test ./internal/cli -run TestClassifyVerb -count=1` | ok |
| `go test ./... -count=1` | **exit 0 — 71 ok, 0 FAIL** (`.scratch/sdd/t9fix1-review-fulltest.txt`) |
| `gofmt -l` (3 changed packages) | empty |
| `go vet` (3 changed packages) | exit 0 |

## 6. Fix-report honesty — VERIFIED

- All cited logs exist in `.scratch/sdd/task-9-fix1-logs/` and match their claims: `red-envgo-sandbox.txt` shows the F1/F2 rows red with the exact pre-fix classes; `red-cli.txt` shows `TestClassifyVerbToolAbsenceBoundaries` red; `green-focused.txt` / `full-test.txt` / `vet.txt` / `probe.txt` as claimed; `briefed-command-as-written.txt` documents the module-cache gate failure honestly.
- The red-gate caveat (cache prefix fails as briefed; repo-cache convention used) matches `task-9-report.md`'s documented convention.
- Global Constraints: 5 files only, stdlib only, no dep/status/scheduler change, no out-of-bounds file; `git status --porcelain` clean before and after this review.

## 7. Cannot-verify items (separate, per brief)

- Wall-clock ordering of the red runs vs the source edit (logs are dated/ordered evidence only; the stash-style pre-fix red is not reproduced here — the passing full suite plus the red logs' failure messages are the operative guarantee).
- Parity of the Python twin classifier with the new precedence — out of scope as in the original review; no Python harness touched.
- `git push`/merge state — not checked (read-only, no remote operations).
