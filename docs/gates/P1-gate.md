# P1 Gate — Findings and Gates (Python → Go)

**Verdict: ALL EIGHT ITEMS PASS — the P1 gate is OPEN (2026-09-09).**

Spec gate (GO_REWRITE_SPEC.md §14, P1): *"deterministic walkthrough
(ported) reproduces Python's artifact bytes; gate dry-run outputs
identical."* — plus the §1.5 definition-of-done items that apply at
P1 scope (cross-golden byte-identity, cross-audit both directions,
ported suite green).

Reference state: web3sec-final HEAD `4fcf779` (1378 test functions,
pytest: 1446 passed / 1 skipped incl. parametrize).

| # | item | verdict |
|---|------|---------|
| 1 | Deterministic walkthrough reproduces Python's artifact bytes | **PASS** |
| 2 | Gate dry-run outputs identical | **PASS** |
| 3 | Cross-audit: Python-written campaign audits clean in Go | **PASS** |
| 4 | Cross-audit: Go-written campaign passes the live Python audit | **PASS** |
| 5 | Ported suite green (incl. -race and determinism double-run) | **PASS** |
| 6 | Python reference baseline still green | **PASS** |
| 7 | testmap.json function-level accounting reconciles | **PASS** |
| 8 | P1 CLI smoke (21 commands) + CONFIRMED reachable via CLI | **PASS** |

---

## 1. Deterministic walkthrough reproduces Python's artifact bytes — PASS

Command: `scripts/golden.sh` = `scripts/golden-run.py` +
`scripts/check-golden.py` (golden suite v2, recipe in
`docs/gates/golden-v2.md`).

Evidence (2026-09-09 settled run): `GOLDEN GREEN` — **59 recipe
commands × 2 twins** (the 8 P0 steps verbatim, then model/plan/scope/
ingest ×5/dedup/resolve-candidate ×2/prioritize/repro-queue/floors
×4/answered ×2/plan --rebuild/verdict ×2/recall ×3/gate ×5/prove
×3/waive/artifact ×3/move ×2/invariant ×2/budget ×2/hint/final
status/audit/audit --json/log/verify), **19 campaign tree files
byte-MATCH** (normalized per KNOWN_DIVERGENCES D2/D3/D4/D16), the two
`audit --json` reports agree on all 13 shared sections + `ok` +
`campaign_id` (Python-only token: `sequence_coverage`, D2). Pinned:
clock (`WEBV2_NOW`, +1s/step), id stream (`WEBV2_UUID`), finding-id
minter (D16). Deterministic across two full runs (run1 == run2
normalized). A mutation test (injected output change) turns the gate
RED, so it has teeth.

The walkthrough ends with finding `h5` at **CONFIRMED** (steps 46–47,
`move`): `F-102ea483d0c3: POSSIBLE (evidence level E7)` →
`F-102ea483d0c3: CONFIRMED (evidence level E7)` in *both* twins, with
the 3 history rows and the closing status/audit/log/verify picking up
the new state byte-for-byte.

On-disk: `.scratch/golden-v2/` (captures, report.json).

## 2. Gate dry-run outputs identical — PASS

Evidence: golden steps 31–35 and 45 — `gate <cid>` (all-finding
dry-run, exit 0 with the checklist), `gate <cid> <f>` single-finding
dry-run for two failing findings (**exit 1** with the failing clauses +
fix line + delta against the last recorded attempt), `gate --explain
evidence-floor`, and `gate <cid> <f5>` passing dry-run (**exit 0**,
`all checks pass (6 clause(s))`). Every one of these is byte-identical
across twins in the settled run, and the clause collector
(`findings.ConfirmationGateClauses`) is the single source for both the
dry-run checklist and the transition error (port of the Wave-B
`confirmation_gate_clauses` refactor, subject-qualified invariant
clauses, claim-drift clause, sequence clause behind the P2 seam).
verify-full step 13 re-asserts the documented exit codes (gate
dry-run = 1 while checks fail) against both twins.

## 3. Cross-audit: Python-written campaign audits clean in Go — PASS

Command: `scripts/verify-full.sh` step 11.

Evidence: a campaign built entirely with the LIVE Python CLI
(init/model/plan/ingest ×2/verdict confirmed/dedup/answered/gate
dry-run/artifact-register/invariant-verify, pinned clock + id stream)
audits clean in the Go binary: `audit` exit 0, `audit --json`
`ok: true`, `verify` exit 0. No Go audit complaint of any kind about
Python-written bytes. On-disk: `.scratch/verify-p1/`.

## 4. Cross-audit: Go-written campaign passes the live Python audit — PASS

Command: `scripts/verify-full.sh` step 12.

Evidence: the same campaign shape built with the Go binary under the
same pins — campaign id **byte-identical** across twins — passes the
LIVE Python `audit` (plain + `--json`) and `verify`: the Go writer
emits no bytes the Python auditor rejects (schema, hash chain, event
log). On-disk: `.scratch/verify-p1/`.

## 5. Ported suite green — PASS

Commands: `go vet ./...`; `go test ./... -count=1`;
`go test -race ./... -count=1`; the determinism double-run
(verify-full step 5).

Evidence (2026-09-09): full suite **1.35s warm** (23 packages),
`-race` **10.3s** — the warm run is under the 2s budget set by the
user directive ("I don't wanna super slow tests"); -race grew with the
21 new CLI commands but stays a ~10s one-shot. Two consecutive
`-count=1` runs byte-identical (durations stripped). `go vet` clean,
`gofmt -l internal cmd` empty.

## 6. Python reference baseline still green — PASS

Command: `scripts/verify-full.sh` step 7
(`cd web3sec-final && PYTHONPATH=src python3 -m pytest tests -q`).

Evidence (2026-09-09): `1446 passed, 1 skipped` (~217s — retained as
the reference baseline despite exceeding the 90s soft guidance; it is
the one slow step in verify-full, which totals ≈4min wall). The port
did not regress the reference.

## 7. testmap.json reconciles — PASS

Commands: `python3 scripts/check-testmap.py`;
`python3 scripts/count-python-tests.py`.

Evidence (2026-09-09):

```
rows total           : 1378 (matches count-python-tests.py grand total 1378)
real rows (P0 slice) : 340  [1:1=330, merged=10]
deferred stubs       : 1038  deferred-P1=233  deferred-P2=186  deferred-P3=507  deferred-P4=112
distinct py funcs    : 1378
P0 10-file slice     : fully real (no deferred stubs)
go_file/go_func refs  : all exist in the Go test tree
```

The P1 CLI wave flipped 71 rows this phase (T14/T15 suites, the gate
checklist, ingest discoverability/legend, invariant-verify --exec,
move, the WorkOrderKey vectors). The 233 remaining deferred-P1 rows
are the P2-owned slice of the P1-tagged files (exec/mint/reproduction
driven tests, model-boundary internals) plus the unported
`move`-adjacent internals noted per row.

## 8. P1 CLI smoke + CONFIRMED reachable — PASS

Command: `scripts/verify-full.sh` step 13.

Evidence: all 21 P1 commands (init, model, plan, ingest, verdict,
dedup, resolve-candidate, prioritize, repro-queue, answered, scope,
floors, budget, hint, recall, artifact-register, artifact-list,
invariant-verify, invariant-contradict, gate, prove, waive) exercised
once each in a valid shape against a scratch Go campaign, exit codes as
documented (all 0 except the failing single-finding gate dry-run = 1),
and the Python twin returns the identical exit-code sequence (23
invocations). Finding status CONFIRMED is reachable through the CLI
(`move`, item 1, steps 46–47).

---

## Known divergences added by this phase

`KNOWN_DIVERGENCES.md` D11–D16: usage block lists implemented
commands only (D11); non-object ingest payload wording (D12);
`Infinity`/`NaN` literals (D13); `resolve-candidate --note` reference
bug faithfully reproduced (D14); `WEBV2_GLOBAL_MEMORY_DIR` Python-only
(D15); finding-id pin mechanism (D16). Open rows carried forward:
D2 (`sequence_coverage` audit section — closes with the P2
sequence-poc port), D10 (P3 seams).

## Latent bug found and fixed by the walkthrough

`budget --json` printed `spent_usd: 0` (int) where Python prints
`0.0` (float) once any finding is CONFIRMED: `yield_report` builds a
trajectory row per CONFIRMED finding as well as per cost entry, so the
sum is a float from then on. `t14TotalCost` now counts cost-ledger AND
CONFIRMED-finding trajectories (filtered to `COST_KINDS`), int-0
preserved for the empty case. Recorded in `docs/gates/golden-v2.md`
§3.3 with a regression test. This is the class of bug the gate exists
to catch — it was invisible to every unit test until a CONFIRMED
finding existed in a campaign.

## Residuals (out of P1 scope)

- `exec`/`mint` and the sandbox evidence route: the walkthrough's
  passing gate reaches the evidence clause via the E7 ingest route;
  the E4 route (sandbox run → exec ledger → minted evidence) is P2's
  docker e2e gate.
- `sequence_coverage` audit section + the sequence clause's real
  coverage check: P2 (D2, D10 seam).
- The reference bug behind D14 awaits an upstream Python fix; the
  `--note` path is then ported back and the row deleted.
