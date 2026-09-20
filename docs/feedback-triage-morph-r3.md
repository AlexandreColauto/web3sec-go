# Triage: webv2 framework feedback — Morph round 3 (C-e0fc3ecd17)

**Input**

- `../morph/FINAL_REPORT.md` — operator's L2 bug-bounty campaign report +
  framework evaluation (12 findings-of-record claims collapsed into the
  9-item ranked-defect list + recommendations).
- Ground for verification: HEAD `0201f237` (post morph-round-2 wave).

**Method.** Same as rounds 1–2: every claim re-verified against Go source at
HEAD by 5 parallel read-only fact-check agents (glm-5.3-flash), each told to
produce file:line evidence and the laziest fix seam. Verdicts below say which
claims are already closed, which are real, and which the report got wrong —
"fix or not" depends on it.

## TL;DR disposition

| # | report claim | verdict at HEAD | disposition |
|---|---|---|---|
| 1 | fork-runner cannot reach any host RPC ⇒ E5/E6/T4 unobtainable | **REAL (4 parts)** | R3-1a loopback rewrite in `BuildContainerArgv`; R3-1c driver surfaces cast stderr; R3-1d loader refuses ignored assertion keys; R3-1b light: doctor prints the container-facing URL |
| 2 | `scope --policy` unregistered and uneventful | **REAL** | R3-2a: `RegisterOrRefresh("policy", …)` — kind already exists in the artifact enum; audit section 2 then re-hashes the policy for free |
| 3 | `move` does not enforce status floors | **REAL** | R3-3: `EvidenceDeficit` guard in the single shared `transition()` (skip CONFIRMED, already gated); fixture ripple budgeted |
| 4 | `assumptions[].status` write-once (no CLI verb) | **PARTIAL** — library mutator (`AssumptionTransition`) exists, operator verb does not | R3-4: thin `webv2 assume` CLI wrapping the existing API, `resolveEvidenceRef` is the `--ref` validator |
| 5 | falsifiability is token-based, not semantic | **REAL (2 interlocks), 1 premise wrong** | R3-5: stderr WARN when a linked finding's mechanism names no row symbol; `--finding` (or the exec's own `finding_id`) required when an EXEC ref escapes the anchor check. Report's arm-1 story (tier-1 gap-4 row escaped the quote rule) is **FALSE** — `HighRiskRow` is tier 0 OR gap>=3 |
| 6 | diagnostic execs share the reproduction ledger | **REAL** | R3-6: best-outcome (max-rank) status in `RecordAttempt`; failures stay recorded in `attempts[]` |
| 7 | mid-campaign surface rebuild orphans plan rows, no discharge | **REAL** | R3-7: audit skips CLOSED orphan priorities, so `answered Q-xxx blocked --reason …` becomes the discharge verb |
| 8 | policy reload silently rewinds the phase | **REAL** | R3-8: `Scope()` skips the phase write past SCOPE + CLI stderr notice (fresh-campaign bytes unchanged ⇒ no oracle re-record for this half) |
| 9 | ordering traps & papercuts | **MIXED** | 9a PARTIAL (amend re-stales the **critic verdict**, not recalls — recalls are row_digest-keyed): note printed. 9b **REFUTED** (no per-axis clamp exists; quotas are announced). 9c REAL: `verdict --actor`. 9d PARTIAL (`sequence_poc` IS listed — verified live; fix is a taxonomy pointer line). 9e REAL: `audit --deep` refusal gets the heal line to `brief --deep`. 9f PARTIAL: add optional `evidence` to trust_boundaries. 9g by-design: weights flat 1.0 with the G3-graduation gate — **fix nothing in code** |

## Report claims corrected in place

- §"Diagnostic execs … unqualifying" — confirmed, but the fix keeps failed
  attempts recorded (the framework's honesty law); only the *status
  projection* changes to best-outcome.
- §"amend silently re-stales a recorded recall" — the recall half is false
  (memory checks key on row digests); the critic-verdict half is real.
- §"`webv2 schema` omits `sequence_poc`" — false; `schema --list` prints it
  at HEAD. The reachable half is that the 23-class taxonomy lives in
  `assets/taxonomy/class_weights.json` and `schema` serves only schema docs.
- §"`--per-axis 20` cannot lift a `--total 40` clamp recorded in
  `probe_surface.json`" — refuted; `applyQuota` keeps per-axis and the run
  announces both quotas + missing[] reasons on stderr.

## Out of scope for this repo

The report's "For the eval file" recommendations target the held-out gold set
(`../web3sec-final/targets/gold-findings.json`) and the external scorer — not
the webv2 harness. They are a separate deliverable in the eval workspace
(arm declaration, per-finding reporter counts, tripwire field, gate-relative
`pass`, real status names, FP definition, path normalization).
`9g` (class weights) stays data-side: run the G3 backtest to populate
`assets/taxonomy/class_weights.json`; the graduation gate is already pinned.

## Process notes (carried from round-2, unchanged)

Each item lands with its own commit + Go regression test (fixed behavior gets
a test, not a golden step); assets edits regen via
`python3 scripts/sync-asset-manifest.py` **per commit** (bisect gate: no
intermediate commit may fail TestAssetPackManifest); event/state text changes
ripple into `internal/orchestrator/testdata/oracles.json` and must be
re-recorded through the replay harness, never hand-patched; new/changed CLI
refusal text must be checked against `scripts/golden-run.py` captures
(`python3 scripts/check-golden.py`); runbook wiring ships with every new verb
("never cut"). Green bar per merge: `go test ./...` (GOCACHE=/tmp/gocache) +
`go run ./cmd/webv2 selftest --full`.

## Plan

`docs/superpowers/plans/2026-09-19-morph-r3-fork-ladder-and-record-trust.md`

## Resolution (2026-09-19)

All 14 plan tasks shipped; every wave passed a glm-5.3-flash review gate
(must_fix empty after fix rounds). The table maps each ranked defect to
its disposition commits (`docs/superpowers/plans/2026-09-19-morph-r3-fork-ladder-and-record-trust.md`).

| Defect | Task | Shipped in |
| --- | --- | --- |
| 1a loopback fork RPC invisible to containers | R3-1a | `c72a2004` (+ rebuild-not-replace tail `0de0b4ad`) |
| 1b host/container URL confusion in diagnosis | R3-1b | `0a3bd00b` (provider stamp: recorded limitation — pin is free-form JSON) |
| 1c silent cast stderr on the fork probe | R3-1c | `5ce49411` |
| 2 bounty policy never reaches the store | R3-2a | `be27db00` |
| 3 `move` ignores the status's evidence floor | R3-3 | `30130560` (fixture ripple: `64c00e9c`) |
| 4 assumption status has no operator verb | R3-4 | `06f65f70` |
| 5 answered closures uncross-checked + anonymous EXEC escape | R3-5 | `8ae29f14` (+ review round `d736cc65`) |
| 6 reproduction status tracks latest, not best | R3-6 | `b05ec5fa` |
| 7 closed orphan still burns the audit | R3-7 | `f5c00687` |
| 8 scope reload rewinds the phase | R3-8 | `be27db00` |
| 9a amend re-stales the verdict silently | R3-9a | `a6003ffc` |
| 9c verdict carries no actor | R3-9c | `6ea8e83a` |
| 9d schema help ↔ taxonomy pointer | R3-9d | `c291f1d0` |
| 9e audit --deep is a parse error | R3-9e | `c291f1d0` |
| 9f trust boundary cannot cite its evidence | R3-9f | `aa38ff2c` |
| 9b / 9g | REFUTED / by design | no code, per the dispositions above |

Review polish: `d736cc65` (wave D), `ad75e352` (wave E). Wave A/B/C gates:
see the plan's task sections and the review records cited there.
