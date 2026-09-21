# C7 Adjudication — v1.6 gap report

Recon of `websec` (module `websec`, Go 1.26) against framework-plan-v1.6.md Part C7
(§C7.1 dual-arm hostile critic, §C7.2 external corpus dedup + excluded-disclosure
probe, §C7.3 bypass analysis), Part 3 stage 12 (line 216), Part 7 Phase 4 row
(line 432), Part 5 tripwires (lines 396–405), and Part C9 last paragraph (line 317).

## Conventions

- **Verb file to copy from:** `internal/cli/cmd_dedup_signature.go` — the house
  pattern for a Go-only argparse-style verb: `argSpec{prog, usage, vals []*valOpt,
  pos []*posOpt}` parse (cmd_dedup_signature.go:60-68), help block as a const,
  `dedupSignatureCmd` body, then `register(command{ord: 76, name: "dedup-signature",
  line: "...", run: runDedupSignature})` in `init()` (cmd_dedup_signature.go:124-129).
  The dispatcher is `internal/cli/cli.go`; verbs live in `internal/cli/cmd_*.go`.
  For a verb with hand-rolled flag loops (mandatory flags, `=` forms), copy
  `internal/cli/cmd_adversarial.go:72-170` (`adversarialParseArgs` /
  `adversarialCheckArgs`).
- **Domain logic goes in a package, not the CLI:** `internal/dedup/dedup_signatures.go`
  (setters + `SaveThenLog` + one ledger event per mutation, lines 47-52) is the model.
- **Test file to copy from:** `internal/cli/cmd_dedup_signature_test.go` (plain Go,
  table-free, per-case funcs: `TestDedupSignatureHelpAndArgparse` :49,
  `TestDedupSignatureRootCauseComputesTheHash` :96). Campaigns come from
  `t15Campaign(t, program)` / `t15Finding(...)` fixtures in
  `internal/cli/cmd_dedup_test.go:17-40` (they wrap `t.TempDir()`); no Docker,
  no network, no model.
- **Exact invocations:**
  - `go test ./internal/cli -run 'TestDedupSignature'`
  - `go test ./internal/dedup`
  - `go test ./internal/findings -run 'Adversarial'`
  - `go test ./internal/corpus` (pure; the sweep degrades when the corpus root is
    absent — corpus_test.go:476-478 pins that)
- **Deterministic pins to respect:** 16-hex signature = `sha256(...)[:16]`
  (`internal/findings/signatures.go:64-67`, `signatureHex16`); Python-exact
  lower/strip/fields (`pyLower` signatures.go:22, `TextSignature` :40). Any new
  signature variant must stay byte-stable or version the key.

## Requirement-by-requirement table

| v1.6 requirement (spec line) | Status | Evidence | What a task must touch |
|---|---|---|---|
| §C7.2, line 300: `dedup-signature <C> F-xxx --root-cause --external rekt-2025.json,code4rena-corpus.json` | **PARTIAL** — verb + signatures exist; `--external` ABSENT | `internal/cli/cmd_dedup_signature.go:125-128` registers `dedup-signature` (ord 76); flags are exactly `--root-cause`, `--economic`, `--cwe` (cmd_dedup_signature.go:63); `plainPositionals`-style spec has no `--external`. `rg -n -- "--external" internal assets cmd docs` matches only MiniCertora docs (`docs/MINICERTORA_ARCHITECTURE.md:201`), never dedup. Signature computed: tier-2 `dedup.root_cause_signature` (internal/dedup/dedup_signatures.go:40, `SetRootCauseSignature` :30) and tier-3 `dedup.economic_signature` (:68, `SetEconomicSignature` :58), both = `findings.TextSignature(normalizedSentence)` (internal/findings/signatures.go:40); tier-1 `TechnicalSignature(class\|path\|function\|invariant)` (signatures.go:30). | Add `--external FILE[,FILE...]` to `cmd_dedup_signature.go` (or a new `dedup-check` verb) + a corpus-file loader in `internal/dedup`; match `TextSignature`/`TechnicalSignature` values against signatures extracted from the external JSON. |
| §C7.2, line 303: external corpus loader (rekt-style incident archive, audit-disclosure corpus); "A match halts the pipeline and flags DUPLICATE-KNOWN/PATCHED-KNOWN before E5 fork-runner budget is spent" | **PARTIAL** (loader: partial-but-wrong-shape; halt + flags: ABSENT) | Existing corpus machinery is class-frequency + PoC-shape, not signature matching, and explicitly advisory: `internal/corpus/corpus.go:1-15` ("do not … block the pipeline — they tell the proposer what the corpus says"), CLI `webv2 corpus-surface` (internal/cli/cmd_corpus_surface.go:3-5 "Advisory: it never sets status … or blocks the pipeline"). Data sources are the DeFiHackLabs PoC clone (`corpus.PocRoot = "data/datasets/DeFiHackLabs"`, corpus.go:102; loader `datasets.defihacklabs.LoadPocRecords`, internal/datasets/defihacklabs.go:76), shared-memory + eval-store class inventory (`ClassInventory`, corpus.go:108) and aderyn/slither tool outputs (internal/datasets/{aderyn,slither}). `rg -ni "rekt\|code4rena" internal assets` → 0 hits in Go code. `DUPLICATE-KNOWN`/`PATCHED-KNOWN` strings: 0 hits anywhere. Closest existing statuses: `DUPLICATE` terminal status (internal/findings/levels.go:37, transitions levels.go:112) set only by internal sweep auto-merge (`dedup.SetMarkDuplicate(findings.MarkDuplicate)`, internal/cli/cmd_dedup.go:257). No pre-fork budget gate reads any duplicate signal (`rg -ni duplicate internal/findings/gate*.go internal/bounty internal/orchestrator` → only status filters, orchestrator/chain.go:41-43). | New loader package (e.g. `internal/dedup/externalcorpus.go` or extend `internal/datasets`) for rekt/c4rena JSON; a `DUPLICATE-KNOWN`/`PATCHED-KNOWN` flag on the finding; a gate clause (copy `internal/bounty/bounty.go` gate pattern) that fires before stage 12/E5 spend. |
| §C7.2, line 305: excluded-disclosure mode — corpus check with the target's own disclosure excluded; pre-submission duplicate-risk rate (Phase 4); D8 (line 21) names it | **ABSENT** | Patterns tried: `rg -ni "excluded" internal assets` → only source-scope exclusion (`internal/solscope/solscope.go:16-21` `excludedDirs`) and held-out exclusion (RUNBOOK.md:748); `rg -ni "disclosure" internal assets` → only `webv2 publish --disclosure FILE` bundle (internal/cli/cmd_publish*.go, RUNBOOK.md:1305,1341 — an operator-attached artifact, not a corpus filter); `rg -ni "duplicate risk\|dup_rate\|duplicate-risk" internal assets` → 0 hits. No corpus file carries contest/provenance metadata to exclude by (datasets loaders have no contest field). | Corpus schema needs a per-entry source/contest discriminator + an `--exclude-contest <name>` flag on the external check + a duplicate-risk-rate counter (new telemetry row, cf. `internal/metrics`). |
| §C7.1, line 293: two critic arms (theft-first, liveness-first), mandatory adversarial liveness template; DISPROVED only if both arms agree; disagreement → promote to POSSIBLE + mandatory obligation | **PARTIAL** (single-arm critic exists; both-arm machinery ABSENT; the liveness template exists but is a different mechanism) | Single critic context: `roles.BuildCriticContext` (internal/roles/context_critic.go:163) with `task.response_schema: "critic_verdict"` (:226-229) — one arm, no arm parameter. `rg -ni "theft-first\|theft_first\|liveness-first\|dual-arm\|dualarm" internal assets cmd` → 0 hits. Statuses POSSIBLE/DISPROVED exist as transition states (internal/findings/levels.go:99-108); critic prompt teaches "when torn between `disproved` and `possible`, emit …" (assets/prompts/48_critic_system.md:152) — a soft tie-break, not a two-arm AND. No promotion-on-disagreement code, no mandatory-obligation open on disagreement (`rg -ni "obligation" internal/findings internal/roles` → 0 hits in non-test Go). The mandatory adversarial liveness template DOES exist, but as the adversarial-game clause, not a critic arm: `AdversarialGameFields` (internal/findings/adversarial.go:33-34), min-20-runes setter (`SetAdversarialGame` adversarial.go:117), gate `check15` (internal/bounty/bounty.go:355-389, trigger `IsLivenessFinding` adversarial.go:49), CLI `webv2 adversarial-game` (internal/cli/cmd_adversarial.go:212-215). | Add an arm dimension to the critic: two context builds (theft-first/liveness-first prompt variants — new assets/prompts file + `BuildCriticContext` param), a merge rule (DISPROVED iff both), promotion transition on disagreement, and an obligation record (new finding sub-object or ledger row) discharged via the §C5.2 EXEC rule. |
| §C7.1, line 295 + Part 5 line 399: directional measurement (theft-kills-liveness vs liveness-kills-theft), ~30% tripwire, feeds standing vouchers | **ABSENT** | Patterns tried: `rg -ni "directional\|theft-kills\|kills-liveness\|liveness-kills" internal assets` → 0 hits; `rg -ni "disagree" internal --glob '!*_test.go'` → only model↔ledger status drift (`internal/invariants/status_drift.go:24`), invariant-normalize vectors, and probe family-divergence rows — none critic-arm related; `rg -ni "voucher" internal` → 0 hits; no ~30% / 0.30 threshold constant anywhere. | New telemetry counter keyed (arm_that_kills, arm_killed) recorded at the disagreement merge point; tripwire check in `internal/metrics`/`internal/doctor`; wiring hook for §3.1 standing vouchers (voucher code itself also absent). |
| §C7.3, line 309: every confirmed finding carries an explicit adversary-adaptation (bypass) statement, built into the report template | **PARTIAL** | Closest existing things, neither mandatory nor on every confirmed finding: (1) the immunize patch-verification bypass — `internal/immunize/immunize.go:157-207` records optional `bypass` + `boundary_bypass_found` (patch-blocks-PoC check verdict), rendered in the finding section as a patch-verify verdict line `"bypass": "**BYPASS FOUND**"` (internal/report/report_finding_section.go:469-475) and schema-keyed at assets/schema/finding.schema.json:740 (`bypass` under patch_verification) — this is "did OUR patch hold", not "how an adversary adapts around the intended fix"; (2) the adversarial-game clause rendered for liveness findings only (report_finding_section.go:150-155, report_results.go:327-345). `rg -ni "bypass_statement\|bypass statement" internal assets` → 0 hits. Immunefi report sections are `immunefiSummary/Impact/Severity/PoC/Recommendation/Related` (internal/report/immunefi.go:218-370) — no bypass section; emission gate keys on CONFIRMED + severity pass but not on any bypass field. | New mandatory `bypass_statement` field (schema + setter + CONFIRMED gate clause), a report-template section in `report_finding_section.go` + `immunefi.go`, and backfill logic from immunize `bypass` rows where present. |
| C9 line 317: cluster confirmed findings by root-cause signature (reusing `dedup-signature`) before choosing bundle-vs-split per submission | **PARTIAL** | Clustering exists: tier-2 sweep groups live findings by `dedup.root_cause_signature` into `tier2Cluster{lineageID, members, autoMerged}` (internal/dedup/dedup_sweep.go:19-23, `tier2Sweep` :142) with deterministic `LineageIDFor` ("LIN-"+8hex, dedup_signatures.go:82-90). "One report per root cause; do not spray variants" is prompt prose (assets/prompts/43_report_and_submission.md:47). The bundle-vs-split *decision* is ABSENT: `rg -ni "bundle" internal/report internal/bounty internal/economics internal/risk` → only publish disclosure bundles and report block plumbing; no submission-packaging code weighs platform payout (per-root-cause vs per-report) at all. | Reuse `tier2Sweep`/`LineageIDFor` for the cluster step; add a submission-bundling chooser (new package or `internal/report` extension) reading the platform rubric's payout model. |

## Existing APIs a plan may reuse

- `dedup.SetRootCauseSignature(c *state.Campaign, findingID, normalizedSentence string, cwe *string) (validation.Value, error)` — internal/dedup/dedup_signatures.go:30
- `dedup.SetEconomicSignature(c *state.Campaign, findingID, normalizedEffect string) (validation.Value, error)` — dedup_signatures.go:58
- `dedup.LineageIDFor(signature string, memberIDs []string) string` — dedup_signatures.go:82
- `dedup.RunDedup(campaign *state.Campaign, autoMerge bool) (validation.Value, error)` — internal/dedup/dedup_sweep.go:44 (tier1 merge / cross-snapshot flag / tier2 cluster / tier3 flag; skips non-duplicatable statuses)
- `dedup.SetMarkDuplicate / SetFlagPossibleDuplicate / SetFoldIntoLineage` seams — cmd_dedup.go:257-259
- `findings.TechnicalSignature(bugClass, path, function, invariantID string) string`, `findings.TextSignature(text string) string` — internal/findings/signatures.go:30,40
- `findings.IsLivenessFinding(f validation.Value) bool` — internal/findings/adversarial.go:49; `findings.SetAdversarialGame(...)` :117; `findings.AdversarialGameDeficits(f)` :98
- `roles.BuildCriticContext(campaign *state.Campaign, findingID string) (validation.Value, error)` — internal/roles/context_critic.go:163 (single-arm; `game_audit` block :148 already feeds the adversarial clause to the critic)
- `findings.Transition(c, fid, "POSSIBLE"/"DISPROVED"/"DUPLICATE", actor, reason, ...)` — internal/findings/levels.go transition table :99-112
- `corpus.ClassInventory(c *state.Campaign)`, `corpus.LoadPocRecords(...)`, `corpus.ActiveSnapshotRoot(c)` — internal/corpus/corpus.go:108, internal/datasets/defihacklabs.go:76
- CLI verbs: `webv2 dedup <campaign>` (ord 5), `webv2 dedup-signature <C> <F> --root-cause|--economic [--cwe]` (ord 76), `webv2 corpus-surface <C> [--backtest --top --baseline]`, `webv2 adversarial-game <C> <F> --who-profit --mechanism --interplay --strongest-attacker` (ord 71), `webv2 adjudicate <C> [F] --verdict --basis --actor --reason`
- Schema keys: `dedup.root_cause_signature`, `dedup.economic_signature`, `dedup_meta.root_cause_sentence`, `dedup_meta.economic_effect_sentence`, `root_cause.cwe`, `adversarial_game.{who_profits,profit_mechanism,challenge_interplay,strongest_attacker}`, patch-verification `bypass` / `boundary_bypass_found` (finding.schema.json:721,740)

## Traps

- **Signature hashes are byte-exact Python-parity contracts.** `TextSignature` /
  `TechnicalSignature` pin CPython `str.lower().strip().split()` semantics via
  x/text (`pyLower`, signatures.go:16-22) and sha256-truncate-16. Tests pin
  re-runs (`dedup_regression_test.go`, `dedup_keepside_regression_test.go`); do
  not "improve" normalization, and never hand-write a hex (that's the bug
  cmd_dedup_signature.go:8-15 documents).
- **Dedup sweep idempotence + keep-side law.** `RunDedup` excludes
  non-duplicatable statuses (dedup_sweep.go:57-63) and keeps the earliest-created
  finding (:69-73); re-runs must reproduce, not add. `sigLiveGuard`
  (dedup_signatures.go:21-28) refuses signatures on terminal rows.
- **corpus-surface is advisory by design** ("never sets status … or blocks the
  pipeline", cmd_corpus_surface.go:3-5; corpus.go:11-15). Wiring a §C7.2 halt
  must go through a new gate clause, not by mutating this package's contract —
  `internal/corpus/e2e_test.go` and `corpus_test.go:509-576` pin the advisory
  surface and the `corpus_surface_block = None when empty` behavior.
- **DUPLICATE is a terminal status** with a fixed transition table
  (levels.go:37,112); auto-merging an illegal status aborts the sweep
  (dedup_sweep.go:53-56 comment) — external-corpus matches must use a new flag
  (DUPLICATE-KNOWN/PATCHED-KNOWN), not a `Transition` to DUPLICATE, or they will
  fight the sweep and the ALLOWED_TRANSITIONS tests.
- **adversarial-game ≠ dual-arm critic.** `check15` (bounty.go:355, gate list
  :409) and `report_results.go:327-345` pin the clause as DATA + presence-gated
  report line; its four fields have a 20-rune floor and re-validation. Don't
  repurpose `adversarial_game` for arm verdicts — add a separate object.
- **Deterministic pins:** findings/id pins via `WEBV2_NOW`/`WEBV2_UUID` env
  wiring in cmd/webv2/main.go:144-195; `LineageIDFor` must stay
  sorted-membership-deterministic or lineage ids churn across runs (the exact
  regression its comment documents, dedup_signatures.go:79-81).
- **Report golden surfaces:** `internal/report/report_test.go` (37KB) and
  `immunefi_test.go` pin section output; the patch-verify `"**BYPASS FOUND**"`
  string (report_finding_section.go:475) is part of a pinned rendering — a new
  mandatory bypass_statement section must be added alongside, not into, that
  verdict line.
- **Audit/ledger discipline:** every finding mutation goes through
  `SaveThenLog` with one named event (`dedup.root_cause_set`,
  `dedup.economic_set`, `finding.adversarial_game_set`); an unstamped mutation
  is a r18-P2 audit violation. `audit` flags engine-failed magnitudes and
  provisional-without-final rows (Part 5 line 404) — keep that path untouched
  when adding gate clauses.

---

## P1 update (post-merge)

**Refreshed 2026-09-21 · HEAD `7a131e90` · re-read range `528b6ae9..HEAD`.**

P1 did not touch this area; the statuses below are unchanged as of 2026-09-21, last verified at the recon run (commit `4b06c114`, 2026-09-21). The C7 rows were re-run: `--external` still absent (`internal/cli/cmd_dedup_signature.go:63` flags remain `--root-cause/--economic/--cwe`; ord 76 unchanged at `:125`), `DUPLICATE-KNOWN`/`PATCHED-KNOWN`, dual-arm critic (`theft-first`/`liveness-first`), directional measurement, and `bypass_statement` all still return zero code hits (`rg -n "theft-first|dual-arm|liveness-first|DUPLICATE-KNOWN|bypass_statement" internal --glob '!*_test.go'` → 0; the only `--external` matches are MiniCertora testdata). Re-checked anchors still hold: `internal/dedup/dedup_signatures.go:40`, `internal/roles/context_critic.go:163` (`BuildCriticContext`, still single-arm), `internal/findings/adversarial.go:33` (`AdversarialGameFields`), `internal/bounty/bounty.go:355` (`check15`).

P1 added no new signature, no new corpus loader, no report section in `internal/report/`, and no new audit section that reads a C7 artifact; the `v16_coverage` section P1 appended (`internal/audit/sections/register.go:47`) counts the eight C1/C2/C3/C8 record fields and touches none of this report's claims.
