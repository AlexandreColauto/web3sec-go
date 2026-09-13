# Wave N — operator friction (plan, 2026-09-13)

Source: `../morph/campaigns/C-16148b932c/FRAMEWORK_EVAL.md` (full operator review,
post-G-01). Controller triage done against code; every claim verified. Rulings here
are final for the wave; reviewers police implementation, not design.

Shared laws: `GOCACHE=$PWD/.gocache`; no `git add -A`; tests never exec child tools;
presence-gated schema additions; one-writer per file; controller commits — agents
leave the worktree dirty and report. After all tasks: manifest resync, full
`go test ./...`, walkthrough, GOLDEN once.

## T1 — stale remediation hints + a pin-vs-reality guard
**Defect (verified):** `internal/findings/gate.go:48` `GATE_REMEDIATION["critic-verdict"]`
= `webv2 verdict <fid> confirmed '<reasoning>' --actor <you>`, but the real CLI is
`webv2 verdict <C> F-xxx --verdict confirmed --reason "..."` (RUNBOOK:715). Same stale
shape in `internal/risk/acceptance.go` (security-confirmed remediation),
`internal/findings/transitions_test.go` (byte-pin of the wrong string),
`internal/bounty/bounty_test.go` fixtures (5), `internal/orchestrator/testdata/oracles.json` (1).
**Controller ruling:** the oracle fixture documents a command that CANNOT run — fixing
it is an authorized golden-fixture edit; golden reruns this wave. First read
`internal/cli/cmd_verdict.go` and derive the hint from the flags the parser actually
accepts (does it take `--actor`? does it take `<C>` positionally? the hint must match
the accepted argv EXACTLY including the campaign argument).
**Accept:** hints everywhere carry the real shape; all byte-pins updated in lockstep;
NEW guard test in `internal/findings` asserting every `GATE_REMEDIATION` entry that
starts `webv2 <verb>` names a verb present in the CLI dispatch registry and contains
`--verdict` where the verb requires it (registry-read, no source-grepping).

## T2 — ingest happy path: evidence items may cite an existing EXEC
**Defect:** PoC-bearing payloads must be split ("static items now, mint later"); when
both exist, the E4-gate error masks schema errors.
**Ruling:** an evidence item may carry `"exec_ref": "EXEC-…"` (schema: optional,
pattern-matched EXEC id) ONLY when the campaign ledger already holds that EXEC with
SUCCEEDED status; ingest then attaches the item through the SAME validation function
`mint` uses (single source of truth — extract or reuse; never fork the
meaningfulness/E4 logic). Failure modes: unknown exec_ref → refuse naming it; not
SUCCEEDED → refuse; ref'd exec bound to another finding → refuse (exec-finding
binding stays, operator re-runs under the survivor — that is their own lesson).
Error ORDER: full schema validation of the whole payload first, then ledger checks,
then gate math — a schema typo must surface even alongside a missing-evidence error.
**Accept:** one-shot payload with exec_ref ingests to E4 where the same content via
mint does (parity test); masking order fixed (test: bad-schema + E4-claim → schema
error reported); refusal trio tests; no mint behavior change.

## T3 — model.json vs ledger: reconcile reports invariant-status drift
**Defect:** cheap agents wrote `CONTRADICTED` into model.json while the gate reads the
ledger (UNVERIFIED). Reconciler hashes artifacts but never compares statuses.
**Ruling:** detect-and-name ONLY — the ledger is authoritative; reconcile NEVER writes
model.json statuses (one-writer law). Report lines `invariant INV-xxx: model.json
says X, ledger says Y — ledger governs`. Clean model files print nothing new.
**Accept:** drift row on a constructed fixture; silence when agreed; no state writes
(diff-check the model file bytes).

## T4 — `webv2 ingest --lint`
Validate the payload through the EXACT same pipeline T2 established (schema → ledger
checks → gate math) and print what ingest would print, but write nothing: no state
change, no events, no files. Exit 0 accepted / 2 refused, like the dry-run preflight
spirit. Shares files with T2 — strictly after it, same chain.
**Accept:** byte-equal refusal output vs real ingest on the same dirty payload; no
writes (test asserts state/events file hashes unchanged).

## T5 — dedup/supersede discoverability (NO basis change — ruling below)
**Operator pain:** self-duplicate resolved only via FP adjudication (poisons
precision); `supersede` existed but was never found.
**Controller ruling:** do NOT add adjudication basis `duplicate` — it would create a
second path to hide double-booked rows from precision when the honest fix (removing a
row from the live set via SUPERSEDED/DUPLICATE status) already exists; double
exclusion paths would silently inflate scores. Instead: (a) `dedup`'s report gains one
discovery line when it touched nothing ("manual self-duplicates: webv2 supersede <C>
F-new --of F-old retires a copy WITH evidence copied — adjudicating it false-positive
costs you precision instead"); (b) RUNBOOK: cross-reference supersede from the
adjudication section and the dedup section; (c) FP-adjudication acceptance path checks
whether the target duplicates another LIVE finding (same class + same affected path)
and prints a stderr nudge to consider supersede — nudge only, never refuses.
**Accept:** the three surfaces; tests for each; precision math untouched (proven by
existing scorecard tests passing).

## T6 — class→floor advisory at ingest + re-file support
**Defect (double-confirmed):** known class silently sets the floor; G-02 sat
E4-saturated at an E6 floor because of an ingest-time taxonomy choice.
**Ruling:** (a) the `ingested …` line ALWAYS names the resulting CONFIRMED floor
(`class bridge-message — CONFIRMED floor E6`) — pure information, zero false
positives; (b) `ClassAdvisory` for KNOWN classes adds a warning when the chosen
class's floor is STRICTER than the loosest known class: name the count + two examples
(sorted deterministically by (floor, name)); (c) re-file support = `amend --class`
already exists — VERIFY (test) that changing class recomputes the floor for the next
gate read (no retroactive promotion, no stale blessing) and that a floor-relaxing
re-file still requires the evidence the NEW class demands at CONFIRMED; add a
RUNBOOK sentence: re-file by true root cause, attest the match in `--note`.
**Accept:** advisory lines + tests (unknown-class behavior unchanged — its existing
pins must pass untouched); ingest-line floor present (walkthrough may need updating if
it byte-matches the ingested line — controller handles); parity test for amend/class.

## Order & grouping
WF1: T1 ∥ T2 (disjoint files). WF2: T4 → T3 (T4 must follow T2; T3 disjoint).
WF3: T6 ∥ T5. Controller verifies + commits each task; wave ends with full battery.
