# Task 5 review — Morph gold re-run protocol (`99e7e906`)

Reviewer: independent read-only review. Inputs: task-5-brief.md, task-5-report.md,
`docs/eval/morph-rerun-protocol.md` @ `99e7e906`, plus source/benchmark cross-checks and
scratch-campaign reproduction runs (no tracked changes; scratch dirs removed afterward).

## Verdicts

- **Spec compliance: YES** — all six mandatory sections present, no placeholders; fresh
  `release.sh` REQUIRED on the pinned-target checkout with the archived log demoted to
  script-works evidence; contamination re-check FIRST with the machine-global caveat and the
  CI persistent-home note; the three expected gate firings quoted from source; the eval-gold
  invocation pinned (with an explicit, documented path-base deviation — see V-8); honesty
  rules and out-of-scope as briefed.
- **Task quality: APPROVED WITH FINDINGS** — one real defect (F-1, empirically confirmed)
  plus one clarifying observation (F-2). Neither invalidates the protocol's structure, but
  F-1 should be fixed in the doc before an operator session follows §3.1 verbatim.
- **Cannot verify:** the operator-side items the plan itself defers to execution time (C-1..C-3).

## Verified (evidence checked, not taken from the report)

- **V-1 Commit shape.** `git show --stat 99e7e906`: exactly `docs/eval/morph-rerun-protocol.md`,
  240 insertions; committed content byte-identical to the working file (`git show … | diff`).
  Placeholder scan (TODO/TBD/FIXME/XXX/<name>): none.
- **V-2 Six sections / no placeholders.** §1 pinned target, §2 contamination (FIRST), §3 campaign
  protocol, §4 scoring, §5 honesty, §6 out of scope — all substantive, none stubbed.
- **V-3 Fresh-release requirement.** §1 requires `bash scripts/release.sh` on THIS checkout, must
  end `RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean`;
  the string matches `scripts/release.sh:164` verbatim (script is `-rwxr-xr-x`). §1 and §6 both
  demote `docs/sdd/release-final.log` to "proves the script works … never a substitute". The log
  is committed at `10182b5c` and carries that `RELEASE OK` line (line 36) — as cited.
- **V-4 Contamination FIRST.** §2 orders the check "before any campaign work", states the store is
  machine-global (`~/.webv2/shared-memory`), quotes the benchmark keyword list verbatim (checked
  against `web3sec-final/targets/gold-findings.json` → `contamination_check.result`:
  "Sherlock morphl2 audit, ScaBench, prevStateRoot/commitBatch/finalizeBatch, or onDropMessage" —
  verbatim), and carries the CI note ("a runner with a persistent home dir will fail this check by
  design … one reason the protocol does not run in CI (§6)"). The memory.json-vs-manifest grep
  refinement is correct and documented. `WEBV2_GLOBAL_MEMORY_DIR` is a real knob (used by
  `internal/ingest`, `internal/cli` tests); the strict-A/B description matches the benchmark's
  `contamination_check.strict_ab_option` text.
- **V-5 Gate firing 1 — per-machine liveness refusal (text verbatim).** Doc:
  `protocol model: state machine(s) <names> have no liveness invariant (one per machine — stage 37)`.
  Source `internal/invariants/invariants.go:498-502` (format string split across two lines,
  concatenates to exactly this text, `%s` = uncovered machines); pinned by
  `TestPartialLivenessCoverageRefused` (`internal/invariants/invariants_test.go:913`). "Refused at
  load, before any write" matches the source comment (no registry mutation, no template event).
- **V-6 Gate firing 2 — cold-probe nag (text verbatim).** Doc quotes "cold probe surface —
  DISCOVERY is running with no probe emit on record, so the mechanical surface is unprobed" and
  the command `webv2 probes <C-id> run --emit`. Source `internal/briefing/briefing.go` (comment
  block 2201-2210, action 2211-2215): same command string, same advisory text, "It gates nothing"
  = the doc's "it gates nothing; it stands until the emit is on record". Verbatim match.
- **V-7 Gate firing 3 — exec-relevance refusal (from `55be2c2e`).** `git log` confirms `55be2c2e`
  ("fix(invariants): exec-relevance gate for invariant-verify (defect 6)") introduced
  `invariants.ExecTouchesInvariant`. Doc format
  `invariant verify failed: cited exec EXEC-… does not target any applies_to contract of INV-… (<reason>)`
  matches `internal/cli/cmd_invariant_verify.go` (Fprintf inside the gate, exit 2) and the three
  reasons `no-exec-record` / `no-command-record` / `no-target-match` match
  `internal/invariants/invariants.go:958-992`. Verbatim.
- **V-8 Scoring invocation.** `scripts/eval-gold.py --help` shows exactly the pinned shape
  (`--gold`, `--campaign`, `--confirm G-ID`; "advisory; never changes pass/bonus/verdict" matches
  §4). The report's drift fix is legitimate: the brief's relative `--gold web3sec-final/…` does not
  resolve from the repo root; the doc states the `$WEB3SEC2` path base explicitly and why.
  Reproduced live: `python3 scripts/eval-gold.py --gold $WEB3SEC2/web3sec-final/targets/gold-findings.json
  --campaign $WEB3SEC2/morph/campaigns/C-7f1005ecd5` → exit 0 and exactly the doc's baseline JSON
  `{"found": [], "missed": ["G-01", "G-02"], "false_positives": 0, … "verdict": "FAIL"}`.
  Benchmark `scoring.pass`/`bonus`/`false_positive_budget` quoted verbatim in §4 (string-compared
  against the JSON). Both scorer-gate invocations green from the repo root (25 tests at this
  commit; 26 at HEAD after `e28efeed` added one — see F-3 note).
- **V-9 Honesty rules.** §5 covers all four briefed items: no score pressure, miss-as-miss with the
  0/2 eval (`$WEB3SEC2/morph/FRAMEWORK_EVALUATION.md` — exists, 10.9K) as template, provenance
  rubric in `docs/eval-methodology.md` (file exists) with the `{claim, source_url, checked_date,
  verdict, tier}` row shape, record-what-happened.
- **V-10 Out of scope.** §6 covers all three briefed exclusions plus two sensible additions
  (frozen fixture, no release substitution) consistent with §1.
- **V-11 Pinned target facts.** Morph fixture HEAD is `8e8b6c5…` (doc says so); `git cat-file -t
  22ca805e` → `commit` with subject "add gas-oracle&procer ci (#500)" — doc quotes
  "add gas-oracle&prover ci (#500)" (matches; the repo subject reads "prover"). The scratch-worktree
  instead-of-move instruction protects the fixture.
- **V-12 Command resolution reproduced.** Fresh-campaign `webv2 probes <C-id> run --emit` exits 2
  with "no structural index … run 'webv2 index …' first" — exactly as the report logged; the doc
  orders `index` before `emit`, so the refusal is a correct fresh-state, not drift.

## Findings

- **F-1 (major, fix in doc): §3.1's "minimal shape" is not schema-valid — an operator following
  the doc verbatim hits a schema error, not the expected liveness refusal.** The doc presents a
  bare `{"state_machines": […]}` as `model.json` and cites `assets/schema/protocol_model.schema.json`,
  whose top level requires `protocol_id`, `name`, `contracts`, `actors`, `assets`, `relations`;
  `webv2 model` → `protocolgraph.LoadModel` (`internal/protocolgraph/protocolgraph.go:191-201`)
  runs `validation.Validate(model, "protocol_model", 25)` BEFORE any side effect. Reproduced in a
  scratch campaign with the doc's exact snippet: exit 2,
  `model load failed: protocol_model validation failed at <root>: 'protocol_id' is a required property`
  (plus the other five). The report's claim "minimal schema-valid shape" is therefore false.
  Expected firing 1 cannot be observed at this step as scripted. Fix: embed the
  `rollup_finalization` fragment inside a minimal schema-valid skeleton (the six required keys,
  empty arrays are fine — verified such a skeleton loads).
- **F-2 (minor, clarify): the §3.1→§3.2-1 sequence as written produces zero-coverage synthesis,
  not the refusal.** The per-machine refusal fires only under PARTIAL coverage
  (`invariants.go:493-502`: `len(uncovered) < len(machines)`); zero coverage takes the synthesis
  path ("Zero coverage: the synthesis path below", line ~505) and mints a LIVENESS invariant per
  machine. Reproduced: the same skeleton plus the `rollup_finalization` machine and no invariants
  loads exit 0 with `WARNING: … the invariant registry was seeded with NOTHING`. The doc's §3.1
  sentence ("refuses a model whose liveness coverage is partial") is correct as far as it goes, but
  the operator reading §3.2-1 will expect the refusal right after loading the §3.1 shape. One
  clarifying line (the refusal names `rollup_finalization` only once other machines have liveness
  coverage and it does not) removes the trap. The quoted refusal text itself is correct (V-5).
- **F-3 (note, not a Task 5 defect): "25 tests" was true at this commit; HEAD now runs 26** —
  `e28efeed` ("pin FP-budget boundary and bonus short-circuit") landed after `99e7e906` and added a
  test. No doc change required; flagging only so the count isn't read as drift.

## Cannot verify

- **C-1** The operator's fresh `bash scripts/release.sh` on the pinned-target checkout and its
  `RELEASE OK` — execution-time by design (the plan says so; the brief forbids Task 5 from running
  it). The script's exit-string and the archived green log are verified (V-3).
- **C-2** `git worktree add "$SCRATCH/morph-22ca805e" 22ca805e` was not executed by the implementer
  (it writes into the fixture repo's admin dir) and was not re-run here for the same reason. The
  commit object exists (V-11) and the command form is stock git; the report already flags the
  operator's first-run path sanity check.
- **C-3** The campaign itself, the recorded firings, and any re-run score — the protocol exists
  precisely so these happen in the operator's session; nothing in this review pre-executes them.
