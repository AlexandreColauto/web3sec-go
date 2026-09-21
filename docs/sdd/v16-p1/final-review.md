# Final whole-branch review — v1.6 P1/P2 record-and-evidence

**Range:** `528b6ae9..9ff35798` (11 commits, 90 files, +11,036/−312)
**Reviewed at:** HEAD `9ff35798`, working tree clean apart from untracked `.scratch/` probes
**Method:** full diff read for every non-test source file; focused packages re-run
(`GOCACHE=$PWD/.scratch/gocache`); an end-to-end CLI campaign built from scratch; the golden
gate re-run; the legacy Python-era fixture re-audited. No whole-suite run (the controller holds
`go test ./... -count=1` green; I ran `internal/audit/...`, `internal/feed`, `internal/boundary`,
`internal/reviewsession`, `internal/risk`, `internal/findings`, and the focused `internal/cli`
set — all `ok`).

---

## Verdict

**fix-then-merge.** No Critical finding. Two Important findings: one is a record-completeness
gap on the branch's own headline transport (fixable in three lines *or* by an explicit
documented decision that the field is harness-only), the other is a one-line correction to the
gate record's own review history. All 28 deferred Minors are triaged below: **0 must-fix** —
none is load-bearing for Phase 2/4/5, though three are worth taking opportunistically.

The Phase 1 exit criteria (a), (b), (c) are genuinely met, and I reproduced each of them on the
shipped binary rather than reading them off the gate record. Grandfathering holds: the legacy
Python-written campaign still `verify`s clean and its `v16_coverage` section is clean.

---

## Findings

### Critical (must fix)

**None.** I looked specifically for the classes that would qualify — a corrupted or unrecorded
ledger mutation, a re-validation of history turning red, a field written outside its schema, an
unreachable refusal, a wrong count in a gate script — and found none.

### Important (should fix)

**I-1 — The file-drop transport validates the declared input artifact set and then throws it
away: no `model.request` event is ever written on the only in-repo model-stage path, so
`v16_coverage.coverage.model_requests` / `requests_declared` can never move on a CLI-driven
campaign.**
`internal/feed/feed.go:88-121` (`invocationRequest`) validates the drop's request with
`boundary.ValidateRequest` and derives `context_artifacts`, then `internal/feed/feed.go:75-76`
hands the *output* to `findings.IngestHypothesis` — which writes no `model.request`
(`internal/findings/ingest.go:53-56`, `:107-108`). The ledger's only `model.request` writer is
`internal/boundary/ingest.go:82` (`logHypothesisRequest`), reachable only from
`boundary.IngestModelHypothesis`, which has **no non-test caller anywhere in the tree**
(`rg -n IngestModelHypothesis --glob '*.go'` → `internal/boundary/ingest.go` + tests only;
`boundary.BuildRequest` likewise has no non-test caller).

Evidence, run against the shipped binary:

* probe (`.scratch/fr-probe`, package-level, valid declaring drop): ingest succeeds,
  `fid=F-fd2ce7488f7f`, events = `{campaign.created:1, finding.ingested:1,
  finding.intake_warnings:1}` — **no `model.request`**.
* end-to-end CLI campaign (`init` → `run --feed` → `fork-dependence` → `fact-read` →
  `impact --replayable` → `review-session start` → `audit --json`): the drop declared
  `input_artifacts=[{kind:artifact,id:ART-aaaa1111}]`, was accepted (exit 0), and the coverage
  block read `model_requests: 0, requests_declared: 0` while six of the other seven fields read 1
  each (`fork_dependence_set, origin_stage, contributing_stages, deployment_facts, replay_recorded,
  review_sessions`; the two PoC tiers need a mint, which needs an exec).

Why it matters. (i) Task 9 exists so that a field which "silently stops being written" shows as
a visible `0`; for this field the counter is a permanent `0` on every campaign the CLI produces,
so it cannot distinguish "no model stage yet" from "the writer is gone" — the exact failure the
section was built to catch. (ii) The plan's Task 9 premise ("the input-artifact declaration is
an *event* (`model.request`)") holds only for an out-of-repo library caller. (iii) The gate
record's `requests_declared: 3` (`docs/gates/v16-P1.md:269-270`, and the prose at `:285-290`:
"Every one of the eight new fields has a non-zero count … `requests_declared` 3 (ledger
`model.request` events, whose declaration is real)") came from a scratch Go program calling
`boundary.BuildRequest` + `boundary.IngestModelHypothesis` — the record discloses the method, but
a reader takes that number as production-populated, and it is not reproducible through the CLI.

Provenance and scope, stated fairly: the plan's own Task 3 sketch (`plan:1000-1090`) omits the
log too, so this is **plan-level**, not implementer error, and the gate record §8.5 concedes the
harness is out of repo. But the branch *made the feed the sanctioned transport* (criterion c) and
the branch's own coverage section counts the field, so the two halves disagree with each other.

Fix (either): log the validated request on the feed's success path — one
`c.Log("model.request", nil, &request)` in `ingestDiscovery` (or a small exported
`boundary.LogRequest` helper so the "one event per mutation" shape stays in one place); **or**
decide explicitly that the field is harness-only and say so in `docs/gates/v16-P1.md` §5, the
RUNBOOK's §3 drop-file paragraph, and the `v16coverage.go` header, so the permanent zero is a
documented contract rather than a silent gap.

**I-2 — The shipped gate record asserts a review file does not exist that does exist, and
reports Task 9 as unreviewed when it was reviewed and fixed in the same commit range.**
`docs/gates/v16-P1.md:438-441` (§8.2) and `:453-459` (§8.7) state
"`task-9-review.md` does not exist … Task 9 has no review file … this document does not invent
one". The file exists (`.superpowers/sdd/2026-09-21-v16-p1-p2-record-and-evidence/task-9-review.md`,
mtime 18:26) and was already present when `9ff35798` was committed (18:36); `progress.md:30-34`
itself records the Task 9 review and its fix round. The record is also pinned at `f854a599`
while shipping inside `9ff35798`, so §5's audit object and §2's "residual" predate the I1/I2
fixes that the same commit landed.

Why it matters: this branch's deliverable *is* its honesty record. A later phase (the P2 spike,
Task 10) reads `v16-P1.md` as the Phase 1 evidence, and this passage tells it a task was never
reviewed — while the ledger and the review file say otherwise. Fix: one line in each of §8.2 and
§8.7 (Task 9: ❌ I1 chain-materialized population, I2 `p2-docker-e2e.sh` count → both fixed in
`9ff35798`, re-review `task-9-rereview.md` clean), plus a sentence in §5 noting the numbers were
produced at `f854a599`.

### Minor (mine, in addition to the deferred ones)

**N-1 — `stageOf` is dead code, and its comment describes a refinement that cannot happen.**
`internal/feed/feed.go:179-184` prefers a `stage` key on the request record, but
`model_request.schema.json` (and the `trajectory.schema.json` mirror) is
`additionalProperties: false` with no `stage` property, so a drop carrying one is refused by
`ValidateRequest` before `stageOf` ever runs. The fallback (the drop's stem) is therefore the
only reachable value — which is what the controller's ledger resolution (`progress.md:19-20`)
already says. Consequence: task-34-review Minor 5 ("a `discovery.json` carrying
`stage:"learning"` records `origin_stage=learning`") is **unreachable**; the residual is a
misleading comment and a branch that cannot be tested. Fix: drop the branch (or keep it and say
in the comment that it is currently unreachable under the schema).

**N-2 — `scripts/check-golden.py:14` and `:216` still say "all 15 rendered sections".** With
`EXPECTED_SECTIONS` = 16 names and `price_table` optional, the golden campaign renders **16** at
its priced step — which the gate itself prints: `step 164 audit-json-final: 16 audit sections`,
`step 07/194: 15`. Functionally correct (the core set is 15 and the docstring's count is stale);
task-9 M1.

**N-3 — Stale rendered-count prose in `README.md:132` ("all 14 rendered sections … 16
registered") and `scripts/legacy/README.md:23` ("all 14 rendered sections").** The live numbers
are 15 rendered / 17 registered (`verify-full.sh:21` was updated in this branch; these two were
not). `scripts/legacy/README.md:37-39` also claims "the auditors follow campaign-relative
files", which is not true of the `artifacts` section — see N-4.

**N-4 — `scripts/verify-full.sh` step 9 is red in this checkout for a PRE-EXISTING reason that
this branch did not cause (and cannot fix from here).** The committed Python-era fixture
`scripts/legacy/campaigns/C-45488bdaf5/campaign_state.json:59-61` registers `REP-adc3248d` at the
absolute path `.scratch/verify-p1/fixtures/note.md` with `sha256 771036afe171…`; the `artifacts`
section resolves absolute paths and re-hashes them
(`internal/audit/sections/artifacts.go:35-43,60-68`), and step 9 asserts `ok is True`
(`verify-full.sh:357-358`). Measured: with the file absent → `missing file`; with the file the
script writes (`verify-full.sh:428`, sha `0f5200f5a4cd…`) → `content hash mismatch`. Neither the
fixture, the `artifacts` section, nor `internal/validation` is touched by this branch
(`git diff --stat 528b6ae9..9ff35798 -- internal/audit/sections/artifacts.go internal/validation
scripts/legacy` → empty), so the failure is byte-identical at the base commit. **The branch's own
addition is clean there**: on that fixture `verify` is `ok` (54 events, chained) and
`v16_coverage` is `{checked: 2, problems: [], ok: true}` with 15 sections rendered. Flagging it
because the gate record says the full suite was not re-run and a future runner will hit it.

**N-5 — `impact --replayable` prints `extractable $None` in its summary line** when
`--extractable` is not also given (`internal/cli/cmd_impact.go:96-101`). Pre-existing shape for a
max-loss-only impact, and the two labeled replay lines the plan pins are printed correctly above
it; cosmetic, but a record-trust branch may want `—` rather than `$None`.

---

## Deferred-minor triage (28 findings, 0 must-fix)

Rulings: **leave** = acceptable to leave as-is; **leave + rec** = acceptable, but take it
opportunistically (cheap, or it removes a future trap). "Basis" is what I checked, not what the
task review asserted.

| Source | Finding | Ruling | Basis (what I checked) |
|---|---|---|---|
| t1 M1 | `check6ExploitContract`'s FAIL branch and blocker text executed by no test | **leave + rec** | Read `internal/bounty/gate_evidence.go:100-121`: the loop falls through to the fail row when no `foundry-test`/`fork-test` item exists, so the refusal is reachable and correct. The binding is pinned in all three directions (`policy_gate_bindings_test.go:88-97`, incl. "no row when the boolean is OFF", which rules out "the check always runs"). Test gap, not a defect; disclosed in the gate record §2 residual. Cheapest high-value fix in the branch (one case), and worth taking before Phase 4 consumes the boolean. |
| t1 M2 | Clause matches the evidence TYPE only, not a SUCCEEDED exec trace | **leave** | The ingest gate refuses E4+ items that do not trace to a real exit-0 EXEC (`internal/findings/ingest_evidence_gate.go`), `exec_ref` is documented as such in the schema, and `amend` only copies verified items. The clause is the brief's snippet verbatim. |
| t1 M3 | Schema walker hard-scoped to `poc_requirements` | **leave** | Enumerated every `"type":"boolean"` in `bounty_policy.schema.json` outside `poc_requirements` (`exclusions[].case_sensitive`, `accepted_risks[].case_sensitive`, …) — none names an evidence tier. A future boolean elsewhere is a Phase 4 problem, and the walker is 20 lines. |
| t1 M4 | Brief misnames the 4th gate parameter (`dryRun` vs save) | **leave** | `internal/bounty/gate_evidence.go` call sites pass `true` = save; cosmetic comment. |
| t2 M1 | `strValues` re-implements `validation.StrArr` | **leave** | Explicitly sanctioned by the plan's Global Constraints ("small helpers are duplicated on purpose"). No behaviour difference. |
| t2 M2 | `RecordInputSetRefusal` does not validate its own event against `model_rejected` | **leave** | Both call sites are gated before it: `logHypothesisRequest` by `InputSetRecordable` (which validates the derived event), the feed's bare-drop path by construction (`refusalRequest` fixes role/response_schema/context_hash). Verified live: the out-of-set refusal produced one schema-legal `model.rejected` and `verify` stayed `ok`. |
| t2 M3 | The refusal test does not assert the event payload | **leave** | `verify_trajectory` conformance plus the schema are asserted elsewhere; payload fields were reproduced by hand (below). |
| t2 M4 | No test pins the derivation's key scope / id shapes | **leave (largely closed)** | The fix round added `TestBundleArtifactsReachesRealMintedIDs` (`internal/boundary/input_artifacts_test.go:170`) and `TestInSetRealIDsPass` (`:202`), plus the prose/key-scoping cases — the C1 regression class is now covered. |
| t34 #2 | Drive-by rewrite of the shared parser's option lookup (`valNamed`/`flagNamed`) | **leave** | Reviewer proved token-set equivalence with `splitFlag`; `--feed` works under both forms; the golden run (196 steps, every P1-P3 verb) is GREEN, which exercises that parser broadly. |
| t34 #3 | `run`'s argparse precedence moved for missing-campaign + unknown token | **leave + rec** | Reproduced: `run --bogus` → `unrecognized arguments: --bogus` (exit 2) while the sibling `sequence run --bogus` still reports the missing-argument error first; `run` with no args still reports `the following arguments are required: campaign`. Exit codes unchanged, no test pins `run`'s text — a moved surface, so pin it if the new precedence is intended. |
| t34 #4 | `feed.FeedStage.Note` is written but never read | **leave** | `internal/feed/feed.go:38,47`; plan-mandated field; harmless. |
| t34 #5 | `request.stage` overrides the drop stem for attribution | **leave (refuted as unreachable)** | See N-1: `model_request` is `additionalProperties:false` with no `stage` key, so such a drop is refused, not mis-attributed. Residual is dead code. |
| t34 #6 | `reviewsession.Open` swallows a `State()` error | **leave** | Reproduced on a corrupt `campaign_state.json`: `review-session end` → exit 2, "no open review session in campaign …". Fail-closed, no write; only the diagnostic is wrong. Plan-mandated interface (`Open(c) (Value, bool)`). |
| t5678 M-1 | Task 5's ledger half (`finding.fact_read`) untested | **leave** | The writer is `findings.SaveThenLog` (`internal/findings/fact_read.go:57-66`), the same door the replay test proves unwinds; the audit section counts the field and is covered by `v16coverage_test.go`. |
| t5678 M-2 | Attestation refusal asserted loosely | **leave** | Behaviour verified by reading `factReadChecked` (`fact_read.go:74-92`); the write path is fail-closed. |
| t5678 M-3 | `--command`'s schema `minLength: 10` is not enforced on the write path | **leave** | `factReadChecked` refuses only the empty command, so a 5-char command fails later inside `SaveFinding` as a generic schema error. No bad record can land; only the exit code/message differ from the other refusals. |
| t5678 M-4 | Prefix matching accepts near-miss options (`--gas-costX 1`) | **leave + rec** | Reproduced by reading `internal/cli/cmd_impact.go:404-419` + `impactOptValue`; no cross-flag capture (`--extractable-per-round` is dispatched before `--extractable`), so a typo can only mis-name the flag it already carries. Still the one place a typo silently records rather than refusing. |
| t5678 M-5 | The two printed replay lines are not asserted byte-exactly | **leave** | Printed output verified live: `demonstrated: 2 rounds x $500.00 = $1000.00 extracted` / `computed: 2000 rounds to exhaustion, ceiling $1000000.00, attack cost $3000.00` — matches the plan's shape and the values the schema pins. |
| t5678 M-6 | A declared `--poc-tier` is discarded on the idempotent no-op path | **leave + rec** | `internal/cli/cmd_mint.go:80` runs `mintIdempotentNoop` (`:268-297`) before `mintPocTierRefusal`; it exits 0 saying "already minted … idempotent no-op" without naming the dropped tier, and the later `mint --poc-tier maximized` then refuses with "requires an existence-tier PoC first". Not load-bearing (the first mint on a fresh exec lands the tier; pre-existing for `--tier`), but this is the one Minor that can waste a Phase 2 spike run — a one-line notice would close it. |
| t5678 M-7 | Stale doc comment above `remediationFlags["mint"]` | **leave** | Cosmetic; the guard only requires coverage of catalog-named verbs. |
| t5678 M-8 | Replay lines print before the pre-existing impact summary | **leave** | Cosmetic ordering; the brief fixed no order. |
| t9 M1 | `check-golden.py` / `golden.sh` stale rendered-count comments | **leave** | See N-2; the gate is GREEN with the real numbers (15/16/15). |
| t9 M2 | Ledger parsed twice per audit | **leave** | Performance only; the golden run (196 steps) completes fine. |
| t9 M3 | "Refused by construction" is 2/3 airtight | **leave + rec** | Confirmed by reading: `findings.AddEvidence` (`internal/findings/ingest_evidence.go:13-80`) has no `ValidatePocTierOrder`, and `fork-dependence --set` can flip a finding to fork-dependent after a legal fork-independent maximized mint. But `poc_tier` has exactly one writer (`internal/findings/exec_evidence.go:215`, reached only through `MintReproEvidence`, which enforces the law — `reproduction_mint.go:87`), so no bypass is reachable today; the flip case is correctly *flagged* by the audit. A comment fix, not a code fix. |
| t9 M4 | RUNBOOK wording stricter than the code on the maximized refusal | **leave** | Doc-only; the RUNBOOK's §4 line omits the fork-dependence qualifier that `ValidatePocTierOrder` applies. |
| t9 M5 | ~200-line unrelated refactor of `check-golden.py` | **leave** | I ran the gate end to end: `GOLDEN GREEN: Go run validates (exit codes, tree + event chain, audit surface)`, 196 steps, `step 164: 16 audit sections`. The refactor's output-preservation was independently measured three ways by the Task 9 review. |
| t9 M6 | `contributing_stages` cannot rot independently | **leave** | By design (it is seeded from `origin_stage`); the section counts it anyway. |
| t9 M7 | Stale rendered-count prose in README / legacy README | **leave** | See N-3; docs only. |

**Which minors I checked against the "load-bearing for a later phase" test, and how:** M-6 (tier
no-op) against Task 10's spike sequence — `scripts/v16-spike.sh` mints `existence` on a *fresh*
exec, so the trap needs a pre-minted exec or a re-run; the mechanism still works. t9 M3 against
Phase 5's maximization loop — the loop's only route to a tiered item is `MintReproEvidence`,
which enforces the law. t1 M1 against Phase 4's policy consumption — the binding (what the
criterion demands) is pinned; only the fail-branch verdict is untested. t34 #5 against Task 8's
`origin_stage` attribution — refuted as unreachable under the schema. None met the bar.

---

## Cross-task checks (the classes a scoped review cannot see)

**1. Do the pieces agree on the eight field names? — YES, all eight.**
Writer → reader → schema, checked one by one:

| Field | Writer (production path) | Reader in `v16_coverage` | Schema |
|---|---|---|---|
| `input_artifacts`/`context_artifacts` | `boundary.BuildRequest` / feed derivation → `model.request` event | `v16coverage.go:183-194` (event `data.input_artifacts`) | `model_request.schema.json` + `trajectory.schema.json#model_request` (mirror pinned by test) |
| `review_sessions[]` | `reviewsession.Start/End` → `campaign_state` + event | `v16coverage.go:163-176` (`State()`) | `campaign_state.schema.json:219-238` |
| `deployment_facts[]` | `findings.RecordFactRead` | `v16coverage.go:108-109,154` | `finding.schema.json` (items required `command,value,chain,block,read_at`) |
| `poc_tier` (on evidence) | `MintedExecEvidenceItem` (only writer) | `v16coverage.go:113-118` via `findings.PocTierOf` | `finding.schema.json` evidence item enum |
| `replay` | `risk.RecordReplay` | `v16coverage.go` `replay_recorded` | `finding.schema.json` `replay` object |
| `fork_dependence` | `findings.SetForkDependence` | `v16coverage.go:94-95` | `finding.schema.json` enum |
| `origin_stage` | `ingestBuildPayload` (`ingest.go:140-142`) | `v16coverage.go:97-98` | `finding.schema.json` |
| `contributing_stages` | same, seeded from the stage | `v16coverage.go:100-101` | `finding.schema.json` |

Spelling, key order and registration order all agree; the section's `v16CoverageKeys` order
matches the order the fields were introduced. The one disagreement is reachability, not naming
(I-1).

**2. Refusal text on both transports — IDENTICAL.** Both transports call the same clause
(`boundary.ValidateRequest`): `internal/boundary/ingest.go:66-80` (library path) and
`internal/feed/feed.go:88-121` (feed). Live feed run: stderr
`… model request cites artifact ART-aaaa1111 outside its declared input set`, exit 1, and the
recorded `model.rejected` carries the same `error` string plus `declared:["POL-171165a6"]`,
`outside:["ART-aaaa1111"]`, `context_hash`, `payload_sha256`, `action` — and `verify` stayed
`ok` (10 events, chained). The RUNBOOK quotes both messages verbatim and both match the code.

**3. Section-count pins across Go, Python and shell — CONSISTENT (with stale prose, N-2/N-3).**
Registry = 17 (`register.go:26-48`, `v16_coverage` last); only `eval` and `price_table` return
`ErrSkip`, so a non-priced campaign renders 15 and a priced one 16. Pins:
`internal/audit/audit_test.go:85,106` (17/15), `internal/cli/cli_test.go:159` (15),
`internal/audit/p1_sections_test.go:214-224,269-292` (14 ported + `eval` + `price_table` +
`v16_coverage`, with the Go-only section stripped from the Python oracle by name — the strip is
explicit and fails if the token is absent, so the oracle is not weakened),
`scripts/verify-full.sh:261-290` (14 base + `v16_coverage` + gated tail, order-checked),
`scripts/check-golden.py:42-64` (16 names, `price_table` optional),
`scripts/p2-docker-e2e.sh:331` (15). Golden run confirms all three: 15 / 16 / 15.

**4. RUNBOOK against the CLI — CONSISTENT.** Every new surface is documented and every
documented surface exists: `run --feed` (0/1/2 exit contract, stem-names-stage, inbox rule,
unwired-by-name list of exactly the nine `feed.FeedUnwired` keys), `fact-read` (`--block`
required, mutating-verb denylist, `--read-only` attestation, `--chain`/`--actor` defaults),
`ingest --stage` → `origin_stage`/`contributing_stages`, `mint --poc-tier`, `impact --replayable`
cheat-sheet line, `fork-dependence`, `review-session`, and the `v16_coverage` audit section.
Dumped help for all six verbs and compared against the RUNBOOK text — they agree, including the
optional campaign positional on `review-session`. `TestRunbookDocumentsEveryRegisteredVerb`
passes and `runbookDocExempt` is still empty.

**5. Is every new field's write path reachable in production? — SEVEN OF EIGHT YES; one is not
(I-1).** Proven by building a campaign through the shipped CLI only (`init`, `run --feed`,
`fork-dependence`, `fact-read`, `impact --replayable`, `review-session start`), then
`audit --json`: `fork_dependence_set 1, origin_stage 1, contributing_stages 1, deployment_facts 1,
replay_recorded 1, review_sessions 1`; `poc_tier` needs an exec/mint (the CLI path is
`mint --poc-tier`, single writer verified). `model_requests`/`requests_declared` stayed 0 —
see I-1.

**6. Grandfathering (refuse-new, grandfather-old) — HOLDS.** No `required` array on any
pre-existing object gained a key (schema diff: the only new `required` lists are inside brand-new
nested objects — `review_sessions[]`, `deployment_facts[]`, `replay`, `input_artifacts[]` items).
`model_request`'s five required keys are unchanged; `model_rejected`'s new `context_hash`/
`declared`/`outside` are optional, so pre-v1.6 rejection events still validate. Re-validation of
history, measured on the Python-era fixture: `verify` → `ok: true`, 54 events, chain intact;
`audit --json` → 15 sections, `v16_coverage` `{checked: 2, problems: [], ok: true}`. The audit's
three impossible-state checks flag 0 of those 2 findings.

**7. Ledger discipline across the branch — CLEAN.** One event per mutation for every new writer:
`review_session.started`/`.ended` (one row + one event, `reviewsession.go:144-158`), one
`finding.fact_read`, one `finding.replay_recorded`, one `finding.fork_dependence_set`, one
`model.rejected` per refusal. Unwind-on-log-failure is real, not nominal: the three finding
writers go through `findings.SaveThenLog` (`storage.go:170-190`, byte restore + a named
double-failure error) and the session writer through `UnwindState(priorRaw, hadRaw)`. No
`time.Now()` and no raw UUID anywhere in the diff (`rg '^\+.*time\.Now\(\)|uuid|rand\.'` over the
Go diff → empty); new records use `state.NowIso()` / `state.NewID`. Event types need no registry
entry (the events schema leaves `type` free; `trajectory` validates only `model.*` + `outcome`),
and `verify` accepted all five new types.

**8. Byte-pinned surfaces that moved — each moved WITH its test.** `internal/cli/cli_test.go`
(14→15 sections), `internal/audit/audit_test.go` (16→17 registry, section list),
`internal/audit/p1_sections_test.go` (explicit strip + order), `internal/report/report_test.go`
and the reproduction/sequencepoc/trajectory call sites (the trailing `pocTier` argument),
`internal/orchestrator/testdata/oracles.json` (3 lines re-recorded, replay-proven by the golden
gate), `internal/cli/cmd_t23_shared.go` help/usage + RUNBOOK cheat-sheet. `sync-asset-manifest.py
--check` → "asset manifest is current". The one unpinned movement is t34 #3 (`run`'s argparse
precedence), triaged above.

**9. Would `scripts/verify-full.sh` go red? — the branch's own changes do not make it red; one
step has a pre-existing red.** Step 7 (golden) I re-ran end to end: `GOLDEN GREEN`, 196 steps,
196 commands, chain intact, `step 07: 15`, `step 164: 16`, `step 194: 15`. Step 9's failure is
N-4 (fixture + `artifacts` section untouched by this branch, byte-identical at base). Steps
10-12's section gate accepts 15 and their campaigns never price; step 12 prices and expects 16 —
consistent with the registry math.

**10. Task 10 honesty — the branch says so, in the right places.** `docs/gates/v16-P1.md:7-11`
splits the Phase 2 criterion into "arithmetic half TEST-PROVEN" and "extraction half
SPIKE-PROVEN **and the spike has NOT been run**", §7b repeats it, and `progress.md:32` records
`Task 10: NOT RUN — operator-run spike`. The plan (`plan:3044-3100`) also states the split. No
file claims the extraction half is proven; `scripts/v16-spike.sh` and `docs/gates/v16-P2-spike.md`
are correctly absent from the tree.

**11. The Part 4 quarantine (P0a) — a real guard, not a comment.** `part4Allow`
(`internal/audit/part4_guard_test.go:28-49`) lists the exact importers of `wilson`, `backtest`,
`classweights` and asserts equality **in both directions**; the three packages carry
"DEPRECATED — DO NOT BUILD ON THIS" headers; `internal/audit` tests pass. No new file in this
branch imports any of them.

**12. Signature ripples checked for silent behaviour change.** The new trailing `pocTier`
parameter (30 call sites) lands only when non-empty (`exec_evidence.go:214-218`), so pre-existing
evidence items keep their exact bytes; the `sigOpt` `fieldAt` change is behaviour-preserving
(`!ok` and `Kind != Str` both return `""`). The golden gate's byte-level tree/state oracles
confirm no drift.

---

## What I could not verify

1. **`scripts/verify-full.sh` end to end.** Steps 1-6 and 10-13 were not run (the controller
   holds the suite green; Task 11 was scoped not to re-run it). I ran step 7's golden suite
   standalone (GREEN) and reproduced step 9's audit by hand (pre-existing red, N-4).
2. **Task 10 / the Phase 2 extraction half.** Needs Docker, a fork RPC and a confirmed finding.
   By design; the branch states this honestly (cross-task check 10).
3. **Whether the out-of-repo harness calls `boundary.IngestModelHypothesis` or only writes drop
   files.** This decides whether I-1 is a code gap or a documentation gap; it is not decidable
   in-tree, and the gate record §8.5 concedes the same limit.
4. **`scripts/p2-docker-e2e.sh`** (Docker). Its `want 15` matches the registry math and the
   golden run's 15/16, but the script itself was not executed.
5. **`go test ./...`, `-race`, and the two-run determinism step** — the controller's claim; I
   re-ran the focused packages and the golden gate only.
6. **The gate record's §5 campaign** (the exact `.scratch` campaign and its pasted numbers). I did
   not reproduce that scratch program; I built an independent CLI-only campaign and report its
   numbers above. The Python-twin provenance of the three re-recorded `oracles.json` lines also
   remains unverifiable in-tree (the twin is gone) — but the golden gate, which replays them, is
   GREEN.

---

## Strengths (worth keeping)

- The three Phase 1 exit criteria are each backed by a test that would fail if the behaviour
  regressed, and criterion (a)'s binding test is genuinely three-directional — the "no row when
  the boolean is OFF" assertion is what makes it a gate rather than a label.
- The out-of-set refusal is reachable and recorded on the real transport, with a schema-legal
  event that keeps `verify_trajectory` green — the failure mode the plan named ("a refusal that
  is only returned is an orphan") is closed, including for the malformed-drop case.
- Refusals live in the write path, not the CLI: `ValidatePocTierOrder` in `MintReproEvidence`,
  `ValidateReplayProfitability` before any byte, `refuseDeclaredFields` at ingest — so the ladder,
  the ingest path and the CLI cannot disagree.
- Ledger/projection discipline is uniform and the unwind paths name their own double failure.
- Grandfathering was designed, not lucked into: optional keys everywhere, an explicit RUNBOOK
  paragraph, and a legacy fixture that still verifies.
- The gate record's split of the Phase 2 criterion into its two halves is exactly the honesty the
  plan asked for.

## Assessment

**Ready to merge?** With fixes — I-2 is a one-line documentation correction; I-1 needs a decision
(three lines of code, or an explicit "harness-only" statement in the gate record and RUNBOOK).
Neither invalidates a Phase 1 exit criterion, and nothing in the branch is unsafe to merge.

**Reasoning:** The branch does what the plan says, the pieces agree with one another on names,
text, counts and order, history still validates, and the ledger law holds throughout. The single
substantive gap is that the sanctioned model-stage transport validates a declaration it never
records, which leaves one of the eight fields Task 9 counts with no production writer — a
plan-level omission the branch inherited, but one this review exists to surface.
