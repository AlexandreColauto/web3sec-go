# Task 9 review — classify maps missing-compiler to ENVIRONMENT

- **Reviewer:** independent read-only review; no delegation, no tracked changes, no full-suite rerun
- **Scope:** commit `eb44603a` (`b77eb7fa..eb44603a`), worktree `.worktrees/production-readiness`, HEAD clean at `eb44603a`
- **Inputs:** plan §Task 9 (lines 254-257) + Global Constraints v3, `task-9-report.md`, `task-9-review-package.md`, RUNBOOK/AGENT_BOOTSTRAP, the diff, and the task-9-logs
- **Method:** every load-bearing claim re-verified from primary evidence, plus a fresh adversarial probe against `envgo.ClassifyFailure` (constructed records via `sandbox.RegisterExec`; probe sources deleted after the run)

## Verdicts

| Item | Verdict |
| --- | --- |
| Spec compliance (plan §Task 9 acceptance contract) | **YES** |
| Task quality | **FINDINGS** (2 — one Medium, one Medium-likelihood/Low-blast-radius regex hardening; both one-hunk fixes, not revert-the-task) |

The named acceptance contract is met and honestly evidenced: the runbook was read first, the law reds are genuine, the class/note/signal behavior matches §Task 9, and no pin asserted the old class. The findings are about the *widened* regexes Task 9 introduced beyond the named fixtures — both create false-ENVIRONMENT paths the implementer partially disclosed but did not pin or bound.

## 1. Runbook law (checked FIRST, as the plan requires) — VERIFIED

- `assets/runbook/RUNBOOK.md:46-53` is exactly the §0 solc paragraph the report quotes: "a missing solc binary is an **environment failure, not a harness bug**", svm-layout/`WEBV2_SOLC_DIR` provisioning, "tells you NOT to spend a fresh-context retry". Line refs check out.
- `assets/runbook/RUNBOOK.md:942-945` is exactly the §6a row: "**ENVIRONMENT** (daemon down, image missing, solc download cut — … do NOT spend a fresh-context retry), **SETUP** (retry in a fresh context …), **LOGIC** (the only class that argues the hypothesis)". "image missing" names ENVIRONMENT verbatim — so the `missing-docker-image` row's class is the runbook's own law, not an invention.
- Full-vocabulary sweep (`rg -i "missing|not found|not installed|command not found"` over RUNBOOK + AGENT_BOOTSTRAP): no row anywhere routes a missing tool to SETUP. `AGENT_BOOTSTRAP.md:64` agrees. The STOP-condition reasoning in report §1 is sound.

## 2. Spec contract — VERIFIED

- Test: `missing-solc` → class `environment`, note names the fix (`svm cache`, `WEBV2_SOLC_DIR`, `webv2 env doctor`, "do NOT spend a fresh-context retry") — pinned three places (envgo table, sandbox table, CLI verb test) and reproduced independently.
- Law reds verified in logs: `red-focused.txt` (13 FAILs, the exact setup/unknown messages quoted in report §4), `red-mutation.txt` (20 FAILs incl. the CLI verb), `red-mutation-sandbox.txt` (5 FAILs). Source hashes for the stash mutation recorded (`md5-*.txt`).
- The hypothesis-space boundary never moved: `hypothesis-compile-error` → setup, `forge-std` library → setup (note must NOT contain `foundryup` — asserted), `module not found` → setup, logic → logic, unclassified → unknown. The `forge-std` delimiter guard (`tok` requires a trailing `[\s:,;)"'\]}]`) does protect `forge-std/Test.sol` from `forgeAbsentRe` — verified by test and by reading the pattern.
- Gates re-run by this review (focused, not full-suite): `go test ./internal/envgo ./internal/sandbox -count=1` ok (0.583s / 49.2s), `go test ./internal/cli -run TestClassifyVerbMissingToolchainIsEnvironment -count=1` ok, `gofmt -l` empty, `go vet` exit 0 — all at `eb44603a` on a clean tree, with the report's documented module-cache env.
- Global Constraints: 5 files only, stdlib only, no new dep/status/scheduler, `scripts/legacy/**` and out-of-bounds files untouched (`git status --porcelain` empty at review time).

## 3. Pins — VERIFIED (nothing asserted the old class)

`scripts/check-golden.py` carries no classify/class assertion (0 hits for `classif|ENVIRONMENT|SETUP`); `golden-run.py`'s classify call runs on the `exit 7` fixture (no tool-absent text); `runbook-walkthrough.sh:384` checks exit status only; no golden/legacy fixture contains not-found text. No pin file was modified — correct.

## 4. Sandbox seam mirror — VERIFIED (byte-identical, r38-railed)

- The shared code added to `internal/envgo/classifier.go` and `internal/sandbox/envseam.go` is **byte-identical**: var-addition block (`solcAbsentRe`…`shellAbsentRe`, 609 B) and the function block (`toolAbsentRe`…`toolAbsentNote`, 3226 B) hash equal across both files; the two integration hunks inside `ClassifyFailure`/`defaultClassifyFailure` are byte-identical. The only difference in the region is the sandbox copy's extra provenance comment ("This is a transcription…") — desirable, and the only sane difference.
- Minor: report §3b's evidence hash ("sha256 fd9bf0a11d0e16d7, 3214 bytes") is **not reproducible** with any obvious boundary of the block it labels (measured: 609 B and 3226 B for the two natural sub-blocks). The underlying claim (identity) is true and independently verified; the quoted digest is dead weight as stated. Cosmetic.
- r38 rail: `internal/envgo/zz_r38a_test.go:TestR38WiredCopyMatchesSandboxDefault` + `internal/cli/zz_r38a_test.go:279` exist as described; the new `TestToolchainAbsenceIsMirroredInTheSandboxDefault` is a genuine differential (CanonCompact compare over 7 rows including the library-stays-setup row). The report's honest caveat (the mirror test passes under pre-fix sources because both copies go stale together — so it is a rail, not a law test) is correct and correctly reasoned.
- Changing `envseam.go` beyond the plan's `Files:` line was the right call: it is the seam fallback, and leaving it stale is the r36 bug class in reverse.

## 5. Hedged docker-image row — VERIFIED honest

`dockerErrRe` does not match "docker image … not found" (its image patterns are `no such image`/`pull access denied`), so the row genuinely takes the `toolAbsent` path with `noteDockerAbsent`, which names both readings ("either the docker CLI is not on this box's PATH or the image it needs is not there") and routes to `webv2 env doctor` instead of asserting a diagnosis. The test row's `noteWithout` asserts the unhedged CLI-claim string is absent. Class ENVIRONMENT is §6a-verbatim ("image missing"). Honest; no finding.

## 6. Findings

### F1 — Medium — `toolAbsentRe` lacks a leading word boundary: "broadcast"/"forecast" classify as a missing foundry tool
- **Where:** `internal/envgo/classifier.go` (`func toolAbsentRe`, the `tok :=` line, new file ~line 76) and its byte-identical mirror `internal/sandbox/envseam.go` (~line 105).
- **Evidence (reproduced this review):** `Error: broadcast not found for script deploy` → class **environment**, note "the foundry toolchain (forge/cast/anvil) is not on this box's PATH — install it with `foundryup`…". `forecast data not found` → same. Cause: `tok := `(?:` + tool + `)[\s:…]`` has a trailing delimiter but **no leading `\b`**, so the `cast` inside `broadcast`/`forecast`/`recast` matches `forgeAbsentRe`. A missing forge *broadcast artifact* (or any text ending in "cast" before "not found") is repository setup — SETUP by the implementer's own §3a boundary — and now silently loses the fresh-context retry. This is the r36 bug's mirror image, introduced by Task 9.
- **Fix:** `\b(?:` + tool + `)[\s:,;)"'\]}]` in both copies; pin with rows `broadcast-not-found-stays-setup` / `forecast-word-stays-unknown` in `TestToolchainAbsenceClassifiesEnvironment` (and one sandbox row), so the delimiter guard's mirror (leading boundary) is load-bearing in tests, not just comments.

### F2 — Medium (low likelihood, law clause broken) — the `shellAbsentRe` widening CAN misclassify a hypothesis-space failure that merely echoes a subprocess not-found
- **Where:** `internal/envgo/classifier.go` (`shellAbsentRe` definition; the `case toolAbsent != "":` arm placed above `case setupHit`/`case logicHit` in the class switch) and the byte-identical mirror in `internal/sandbox/envseam.go`.
- **Evidence (reproduced this review):** a capture of `sh: 1: helper.sh: command not found` + `assertion failed: x != y` (a test whose vm.ffi/helper subprocess hit a missing command, then the assertion failed) → class **environment**, note "a toolchain binary this run needs is not on this box … do NOT spend a fresh-context retry", even though the logic signal is also recorded. The `toolAbsent` arm outranks `logicHit`, so any capture that merely *echoes* a not-found line is routed away from the only class that argues the hypothesis — a direct violation of the plan law's second clause ("only hypothesis-space failures stay SETUP") in an adversarial-but-plausible capture. Second path: `sh: 1: /tmp/ffi-probe.sh: not found` (a missing *repository script*, not a binary) → environment via `^[^\n]{0,80}: not found$`, inconsistent with the report's own repo-artifact=SETUP boundary.
- **Assessment:** report §3a/§8.2 disclosed the widening but understated exactly this failure mode ("an absent binary is not hypothesis-space" — true, but the *trigger* is the phrase occurring anywhere in the capture, not a verified absent binary, and it outranks logic evidence). Mitigations that keep it below blocking: signals always list both patterns, the class is documented as "a routing hint, not a verdict", and the named law fixtures are all correct. Not a revert; a hardening.
- **Fix (either or both, in both copies):** (a) anchor `shellAbsentRe` to shell/exec prefixes instead of a bare phrase — e.g. require the line to start `sh:`, `bash:`, `dash:`, `<n>:` or `exec:`/`executable file not found in $PATH`; (b) order `case logicHit:` above `case toolAbsent != ""` in the switch (the Task 9 reds only need precedence over `setupHit`; no existing law row has logic+absence co-occurring), letting the note map handle the combined case; (c) pin the adversarial capture above as a row asserting class `logic` (or at minimum a note that does not deny the retry).

### Cosmetic — report §3b digest not reproducible (see §4). No action required beyond re-deriving or dropping the hash if this file is cited downstream.

## 7. Adjudication of the implementer's five concerns (report §8)

1. **`envseam.go` changed though plan named only `internal/envgo` — ACCEPTED.** Verified byte-identical hunks + extended r38 rail; leaving the fallback stale is the exact r36 defect class. The alternative (drop the sandbox hunk) would ship a two-law classifier.
2. **`shellAbsentRe` wider than the plan's parenthetical — PARTIALLY ACCEPTED, see F2.** The direction (absent binary ≠ hypothesis) is right; the trigger as written is unanchored and outranks logic evidence. One-hunk hardening, mirrored.
3. **`docker image … not found` SETUP→ENVIRONMENT — ACCEPTED.** §6a says "image missing" verbatim; the hedged note is verified honest (§5); pinned by the `missing-docker-image` row so it cannot drift.
4. **Mutation-based red for the CLI test — ACCEPTED.** Plainly disclosed (§4/§8.4), logs present (`red-mutation.txt`, 20 FAILs), stash hashes recorded; the envgo/sandbox reds are pre-implementation.
5. **No delegation/dep/enum — VERIFIED** from the diff (5 files, stdlib regex/strings only).

## 8. Cannot-verify items (separate, per brief)

- **Full-suite/race/golden/walkthrough gates:** not re-run (brief forbids full-suite reruns). Accepted from logs (`full-test.txt`, `golden.txt`, `runbook.txt`, `vet.txt` show exit 0; no FAIL lines; log commands recorded verbatim). The focused re-runs above cover every changed package's new tests.
- **Red-run provenance before implementation:** the envgo/sandbox red logs are dated/ordered evidence only; I cannot prove wall-clock ordering of file writes. The mutation run (stash + md5 pins) makes the pre-fix red reproducible, which is the stronger guarantee anyway.
- **The report's §3b sha256 `fd9bf0a11d0e16d7` / 3214 B:** not reproducible with the stated label (identity itself verified by other means). Listed here rather than as a finding because the substantive claim is true.
- **Behavior of the Python twin classifier** (the Go code transcribes Python patterns per the file header): no Python harness was touched or run in this task; parity of the Python side with the new Go law is out of scope for this diff and unverified.
