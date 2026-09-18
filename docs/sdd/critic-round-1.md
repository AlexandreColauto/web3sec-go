# Critic round 1 — production-readiness branch (final critic, independent)

- **Critic:** independent, read-only. Nothing changed, nothing delegated; evidence re-derived with git + local runs.
- **Range:** `b0006c4a..16b3bc3a` (30 commits), worktree `.worktrees/production-readiness`, tree clean except untracked `.scratch` evidence.
- **Inputs:** plan (2026-09-17-trust-boundary-hardening.md, v3), `.scratch/sdd/progress.md`, task reports/reviews, the diffs themselves.

## Checks I ran myself (not taken from reports)

| Check | Result |
| --- | --- |
| `go test ./... -count=1` | GREEN (re-run twice, pipefail-checked) |
| `go vet ./...` | clean (exit 0) |
| `scripts/golden.sh` + `python3 scripts/check-golden.py` | GREEN (exit 0, 196 steps) |
| `scripts/runbook-walkthrough.sh` | GREEN — 150 passed / 0 failed |
| `scripts/security-check-test.sh` | GREEN — 56 passed / 0 failed |
| Real `govulncheck` gate (`scripts/security-check.sh`, scanner found at `.scratch/gomod/bin`) | **PASS, exit 0** — "No vulnerabilities found", independently re-run by this critic |
| `scripts/verify-full.sh` | **RED — fails at step 4** (`go test -race`), see Finding 1 |
| `go test -race ./internal/state -count=1` | **RED** (deterministic, twice, in isolation) — same finding |
| Cross-compile claims in SECURITY.md | VERIFIED: `GOOS=linux` builds; `GOOS=darwin` and `GOOS=windows` both fail exactly where the doc says (`setProcGroup`/`killGroup`, `syscall.Flock`) |
| `git diff b0006c4a..HEAD -- scripts/legacy` | EMPTY — historical fixtures byte-untouched ✓ |
| Diff spot-checks | Task 1 (`115ba97f`), Task 3 (`bbe5a030`), Task 4A (`521eecfd`), Task 12 (`1a03c8ca`), Task 16 (`b00532ca`), Task 2 (`b47d893e`), Task 5 (`1e6412e5`) all match their plan specs; test deletions are honest expectation re-pins, no gate weakened |
| `go.mod` | minimal: `x/text v0.14.0→v0.39.0` + `toolchain go1.26.6`; no dependency creep |

## SCORE

**7/10** — the engineering substance, honesty discipline, and the three operator-corrected
acceptance rules are genuinely delivered and independently re-verifiable, but the plan's own
Definition-of-Done gate `verify-full.sh green at final HEAD` is **false on this machine**
(deterministic `-race` failure in `internal/state`), and independent-review evidence is not
persisted for roughly a third of the tasks.

## FINDINGS

### F1 — CRITICAL — verify-full.sh is RED at final HEAD; DoD gate unmet; ledger's final claim overstates

- **Evidence:** I ran `bash scripts/verify-full.sh` to completion: `FAIL [step 4: go test -race]`
  — `TestConcurrentLoadModifyWritesLoseNothing` (`internal/state/processlock_r13_test.go:156,185`)
  fails as *"campaign … is locked by another process (waited 5s …)"* → *"ledger lost a class: 5 of 6"*.
  Reproduced **deterministically, twice, including in full isolation**
  (`go test -race ./internal/state -count=1` → FAIL). The plan DoD requires
  "scripts/verify-full.sh green at final HEAD" and "-race green on state/sandbox/harness"
  (plan Global Constraints + DoD lines 310-311); the ledger's closing line 62 says
  "all final gates green incl real gate PASS" — there is no verify-full artifact in
  `.scratch/sdd/final-*` and no record that verify-full was ever run to completion at final HEAD.
- **Mitigation:** this failure was honestly *disclosed* earlier — the Task 4 report proved the
  same step-4 lock-timeout (and a step-12 p2_sections 14-vs-15 mismatch) pre-existing on clean
  BASE — so it is not a regression of this branch. But "disclosed, then silently dropped from the
  DoD accounting" is exactly the pattern the plan's honesty rules exist to prevent. The failure
  mode itself is fail-loud lock behavior under race-inflated latency (the test's own worker
  exceeds its 5 s flock budget), i.e. test-infrastructure fragility, not demonstrated production
  data loss — but the DoD checkbox cannot be checked and step 12's status (the second disclosed
  pre-existing failure) is *unknown* because the run never reaches it.
- **Fix:** deflake the r13 harness for `-race` (derive the lock budget from an env knob, or
  serialize worker startup so contention is bounded; do not skip under `-race` — that would be
  gate-weakening), then run verify-full to completion at final HEAD, archive the log as
  `final-verifyfull.txt`, and either fix the step-12 mismatch or get an operator ruling recorded
  in the ledger. Correct ledger line 62 to name the gates actually run.

### F2 — IMPORTANT — independent-review evidence not persisted for Tasks 1, 2, 3, 4, 8, 14, 15

- **Evidence:** `.scratch/sdd/` contains real review artifacts for Tasks 5, 6, 7 (+fix1), 9
  (+fix1), 10-12 (+fixes), 13A, 16 — and these reviews are demonstrably substantive (Task 9's
  reviewer found two real Medium regex/precedence defects; Task 10's reviewer ruled spec
  PARTIAL on "brief shows it"; both closed with re-reviews). But for Tasks 1, 2, 3, 4 only
  one-line ledger verdicts exist ("review APPROVED spec YES") with review *packages* but no
  review *reports*; **Task 8 has no review recorded at all** (ledger line 45 records completion
  with finisher verification only); Tasks 14/15 (SECURITY.md, docs) have no independent
  claim-check despite the plan's Task 14 explicitly requiring "Reviewer checks every claim
  against the cited file/line".
- **Why it matters:** review integrity is one of the branch's core claims; for those tasks it is
  unverifiable, and Task 8 appears to have skipped the plan-mandated independent review entirely.
- **Fix:** persist (or re-run and persist) the review reports for 1/2/3/4 and 14/15, and run the
  missed Task 8 review now (it is a small, self-contained diff). Route per current operator
  routing (b-ai/glm-5.3-flash).

### F3 — IMPORTANT — the plan-mandated final whole-branch review never produced an artifact

- **Evidence:** plan §Execution order: "Final whole-branch review: union-alpha over
  MERGE_BASE..HEAD, pointed at the ledger's deferred minors; ONE fix wave then one scoped
  re-review." The fix wave happened (fabc7d18, 4fa0aef0, 0f881e55, 16b3bc3a) but was driven by
  the Phase C review and docs residuals; no whole-branch review report exists in `.scratch/sdd/`.
  The critic loop (this document) is the first MERGE_BASE..HEAD sweep.
- **Fix:** either accept this critic round as that sweep (record the ruling in the ledger) or run
  the promised dedicated review; do not leave the plan text claiming a step that has no artifact.

### F4 — MINOR — durable SDD ledger and review evidence are untracked

- **Evidence:** all of `.scratch/sdd/` (ledger, reports, gate logs, my own artifacts) is untracked;
  worktree cleanup erases the branch's audit trail, including the red/green evidence the reviews
  relied on.
- **Fix:** commit the ledger + review reports under a docs/evidence path, or record in
  IMPROVEMENTS.md that the SDD trail is ephemeral by design.

### F5 — MINOR — Task 12 double-counts an open question naming two components of one row

- **Evidence:** `internal/planner/queue.go` `scoreRow` adds `openQ[ref]` per component, so one
  question naming two components of the same row contributes W3 twice (noted by the Phase C
  review, accepted without a pin). Direction is conservative (ranks higher, never lower).
- **Fix:** count distinct questions per row, or pin the current semantics with a named test.

### F6 — MINOR — disclosed residuals correctly parked, listed for the record

- YAML alias traversal is unbounded (`internal/validation/yaml.go`) — the Task 16 review's
  disclosure ("do not claim general YAML safety") is honest; YAML input is operator-authored, so
  exposure is local-only. Suggest an alias/ratio cap as follow-up.
- `shellAbsentRe` colon-widening (`broadcast: not found` → ENVIRONMENT) pre-exists the branch and
  is disclosed in `task-9-fix1-review.md`; it slightly contradicts the runbook's tool-absent law.
- govulncheck PASS means "nothing CALLED is known-vulnerable" (uncalled advisories remain in the
  graph) — SECURITY.md documents this correctly; keep the wording in release notes.

## Honest-limits verification (dimension d)

- Task 5's premise-fabrication trap was **avoided**: the implementation was already correct, the
  commit (`1e6412e5`) says so explicitly, the ledger says "test-only pin … Do not claim a
  production bug was fixed", and the counterfactual (route the verb through `RegisterArtifact`)
  is pinned red. This is the single best honesty signal in the wave.
- SECURITY.md is exemplary: every claim I tested (cross-compile, attestation semantics, PASS
  semantics, host-profile disclosure) checks out against code; no overstatement found.
- The plan's DoD checkboxes were left **unchecked** in the plan file — consistent with reality
  (verify-full is red), no checkbox theater.

## What I could NOT verify (weighed as limitations, not assumed away)

- Live network behavior against real targets, chain deployments, Windows/macOS runtime
  (verified *unbuildable*, which matches SECURITY.md's claim), multi-operator concurrency on real
  mounts, and govulncheck advisory-DB freshness beyond this machine's snapshot.
- Step 12 of verify-full (never reached due to F1).

## WHAT-WOULD-MAKE-IT-TEN

### (i) Fixable in this branch

1. **F1 (the big one):** deflake the `-race` lock-budget harness in
   `internal/state/processlock_r13_test.go`, get `scripts/verify-full.sh` green through all 13
   steps at final HEAD (including the previously-disclosed step-12 p2_sections mismatch), archive
   `final-verifyfull.txt`, and correct the ledger's "all final gates green" line to match.
2. **F2:** persist review reports for Tasks 1/2/3/4 and 14/15; run the missed Task 8 review.
3. **F3:** record the final whole-branch review (or an explicit ruling that this critic round is it).
4. **F4:** commit the SDD ledger/reports or document their ephemerality.
5. **F5/F6:** distinct-question counting or a semantics pin in `queue.go`; optional alias cap in
   `yaml.go`.

### (ii) Fixable with operator action

1. Approve the branch (push/merge) once F1-F3 close — that approval is by design pending.
2. Adjudicate the r13 race-test environment sensitivity on a non-sandboxed machine (if it passes
   there, the finding downgrades to "gate is machine-fragile" with a CI requirement rather than
   "gate red").
3. Rule on govulncheck acceptance: one machine's advisory snapshot satisfies release, or require
   a fresh scan at release time on the release host.

### (iii) Out of scope by design (do not count against the score)

1. Discovery performance (the evaluation-era 0/2 gold results) — hardening-only scope;
   requires held-out measurement, honestly not claimed fixed.
2. Windows/macOS runtime support (declared Linux-only, truthfully).
3. Live network scanning of real targets; exploit development; autonomous hunting.
4. Container/VM escape hardening beyond honest labeling (upstream's boundary).
5. Multi-operator concurrency on real shared mounts (one-writer law is documented, not lifted).

## Score rationale in one paragraph

Dimensions: (a) task delivery — 16/16 landed, spot-checked honest, Task 5's fabrication trap
handled exactly right; (b) review integrity — excellent where artifacts exist, unverifiable for
~40% of tasks (F2), one task apparently unreviewed; (c) gate truth — every gate I could rerun is
genuinely green including the real govulncheck PASS, but the branch's own comprehensive gate
(verify-full) is red at HEAD and the ledger's final line papers over it (F1); (d) evidence
honesty — exemplary (SECURITY.md, unchecked DoD boxes, disclosed residuals, uncalled-advisory
wording); (e) residual risk — well surfaced (alias traversal, shellAbsent widening, PASS
semantics), with the one blind spot being F1's own status. Strong 7: a 9 is reachable this wave
by fixing F1-F3 alone.
